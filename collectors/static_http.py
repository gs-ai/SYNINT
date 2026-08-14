"""Native lightweight HTTP collector with bounded crawl support."""

from __future__ import annotations

import os
import random
import time
from collections import deque
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests

from core.redaction import redact_url_credentials
from .base import BaseCollector, CollectionResult, CollectorCapabilities
from .utils import (
    create_safe_session,
    detect_cloudflare_challenge,
    normalize_url,
    parse_html_summary,
    same_domain,
    write_collection_artifacts,
    DEFAULT_BROWSER_USER_AGENTS,
)


class StaticHttpCollector(BaseCollector):
    """Low-noise HTTP collector using requests with deterministic fallbacks."""

    engine_name = "static_http"
    capabilities = CollectorCapabilities(
        supports_javascript=False,
        supports_browser_automation=False,
        supports_session_state=True,
        supports_screenshot=False,
        supports_crawl=True,
        supports_html_extraction=True,
        supports_file_download=True,
        supports_form_detection=True,
    )
    _CF_FALLBACK_MODES = {"balanced", "stealth", "deep_browser"}

    def __init__(self, config=None) -> None:
        super().__init__(config=config)
        self._session = create_safe_session(
            user_agent=self.config.user_agent,
            allow_env_network_config=self.config.allow_env_network_config,
        )
        self._apply_optional_cloudflare_cookie()
        if self.config.proxy_url:
            self._session.proxies.update({"http": self.config.proxy_url, "https": self.config.proxy_url})
        elif self.config.tor_socks_proxy:
            socks = self.config.tor_socks_proxy
            self._session.proxies.update({"http": socks, "https": socks})

    def _apply_optional_cloudflare_cookie(self) -> None:
        if not self.config.allow_env_cookies:
            return
        cf_clearance = str(os.getenv("SYNINT_CF_CLEARANCE", "")).strip()
        if not cf_clearance:
            return
        existing_cookie = str(self._session.headers.get("Cookie", "")).strip()
        cookie_parts = [part for part in [existing_cookie, f"cf_clearance={cf_clearance}"] if part]
        self._session.headers["Cookie"] = "; ".join(cookie_parts)

    def _rotate_user_agent(self) -> None:
        if self.config.user_agent:
            return
        self._session.headers["User-Agent"] = random.choice(DEFAULT_BROWSER_USER_AGENTS)

    def _pace(self) -> None:
        delay = random.uniform(self.config.min_delay_seconds, self.config.max_delay_seconds)
        if delay > 0:
            time.sleep(delay)

    def _request(self, method: str, url: str, *, allow_redirects: bool = True) -> requests.Response:
        timeout = max(1, int(self.config.timeout_seconds))
        last_exc: Exception | None = None
        for attempt in range(self.config.retries + 1):
            try:
                self._pace()
                response = self._session.request(method, url, timeout=timeout, allow_redirects=allow_redirects)
                cf_signal = detect_cloudflare_challenge(
                    status_code=response.status_code,
                    headers={k: v for k, v in response.headers.items()},
                    content=response.text or "",
                )
                if cf_signal.get("challenge_detected") and attempt < self.config.retries:
                    self._rotate_user_agent()
                    time.sleep(0.75 + (attempt * 0.5))
                    continue
                return response
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.config.retries:
                    time.sleep(min(2 ** attempt, 4))
        raise last_exc or RuntimeError("request failed")

    def _attempt_browser_fallback(self, url: str) -> CollectionResult | None:
        if self.config.mode not in self._CF_FALLBACK_MODES:
            return None
        try:
            from .camoufox_collector import CamoufoxCollector

            if not CamoufoxCollector.is_available():
                return None
            browser_result = CamoufoxCollector(config=self.config).fetch(url, need_render=True)
            if browser_result.error:
                return None
            return browser_result
        except Exception:
            return None

    def fetch(self, url: str, *, need_render: bool = False) -> CollectionResult:
        normalized = normalize_url(url)
        headers: Dict[str, str] = {}
        content = ""
        body_bytes: bytes = b""
        status_code = None
        final_url = normalized
        redirects: List[str] = []
        error = None

        try:
            response = self._request("GET", normalized, allow_redirects=True)
            status_code = response.status_code
            headers = {k: v for k, v in response.headers.items()}
            content = response.text or ""
            body_bytes = response.content or b""
            final_url = str(response.url)
            redirects = [str(hist.url) for hist in response.history] + [final_url]
        except Exception as exc:
            error = redact_url_credentials(exc)

        cf_signal = detect_cloudflare_challenge(status_code=status_code, headers=headers, content=content)
        fallback_used = False
        if cf_signal.get("challenge_detected"):
            browser_result = self._attempt_browser_fallback(normalized)
            if browser_result is not None:
                fallback_cf_signal = detect_cloudflare_challenge(
                    status_code=browser_result.status_code,
                    headers=browser_result.headers,
                    content=browser_result.content,
                )
                fallback_summary = browser_result.response_summary if isinstance(browser_result.response_summary, dict) else {}
                fallback_summary["cloudflare"] = {
                    **cf_signal,
                    "fallback_attempted": True,
                    "fallback_engine": browser_result.collector_engine,
                    "fallback_challenge_detected": fallback_cf_signal.get("challenge_detected", False),
                }
                browser_result.response_summary = fallback_summary
                fallback_used = True
                if not fallback_cf_signal.get("challenge_detected"):
                    return browser_result

        artifact_paths: Dict[str, str] = {}
        if self.config.save_artifacts:
            artifact_paths = write_collection_artifacts(
                artifact_root=self.config.artifact_root,
                url=normalized,
                collector_engine=self.engine_name,
                collection_mode=self.config.mode,
                status_code=status_code,
                content=content,
                rendered=False,
                headers=headers,
                body_bytes=body_bytes,
                final_url=final_url,
                content_type=headers.get("Content-Type", ""),
                content_disposition=headers.get("Content-Disposition", ""),
            )

        summary = parse_html_summary(final_url, content) if content else {}
        if artifact_paths.get("download"):
            summary["downloaded_file"] = artifact_paths.get("download")
        summary["cloudflare"] = {**cf_signal, "fallback_attempted": fallback_used}
        return CollectionResult(
            url=normalized,
            final_url=final_url,
            status_code=status_code,
            content=content,
            headers=headers,
            redirect_chain=redirects,
            error=error,
            collector_engine=self.engine_name,
            collection_mode=self.config.mode,
            rendered=False,
            proxy_used=bool(self.config.proxy_url or self.config.tor_socks_proxy),
            artifact_paths=artifact_paths,
            fetch_attempts=self.config.retries + 1,
            response_summary=summary,
        )

    def detect_forms(self, html: str) -> List[Dict[str, Any]]:
        return parse_html_summary("https://placeholder.local/", html).get("forms", [])

    def crawl(self, url: str, *, max_depth: int | None = None, max_pages: int | None = None) -> Dict[str, Any]:
        start_url = normalize_url(url)
        root_host = (urlparse(start_url).hostname or "").lower()
        depth_limit = max_depth if max_depth is not None else self.config.max_depth
        page_limit = max_pages if max_pages is not None else self.config.max_pages

        visited: Set[str] = set()
        queue = deque([(start_url, 0)])
        pages: List[Dict[str, Any]] = []
        internal_links: Set[str] = set()
        external_links: Set[str] = set()

        while queue and len(visited) < page_limit:
            current_url, depth = queue.popleft()
            if current_url in visited or depth > depth_limit:
                continue

            result = self.fetch(current_url)
            visited.add(current_url)
            summary = result.response_summary
            links = summary.get("links", []) if isinstance(summary, dict) else []

            page_record = {
                "url": current_url,
                "depth": depth,
                "status_code": result.status_code,
                "title": summary.get("title", "") if isinstance(summary, dict) else "",
                "meta_description": summary.get("meta_description", "") if isinstance(summary, dict) else "",
                "forms": summary.get("forms", []) if isinstance(summary, dict) else [],
                "file_links": summary.get("file_links", []) if isinstance(summary, dict) else [],
                "artifact_paths": result.artifact_paths,
                "collector_engine": result.collector_engine,
            }
            pages.append(page_record)

            for link in links:
                link_host = (urlparse(link).hostname or "").lower()
                if link_host == root_host:
                    internal_links.add(link)
                    if link not in visited and depth + 1 <= depth_limit:
                        queue.append((link, depth + 1))
                else:
                    external_links.add(link)

        robots_url = urljoin(start_url, "/robots.txt")
        sitemap_url = urljoin(start_url, "/sitemap.xml")
        robots = self.fetch(robots_url)
        sitemap = self.fetch(sitemap_url)

        return {
            "status": "ok",
            "visited": sorted(visited),
            "pages": pages,
            "visited_count": len(visited),
            "internal_links": sorted(internal_links),
            "external_links": sorted(external_links),
            "crawl_summary": {
                "max_depth": depth_limit,
                "max_pages": page_limit,
                "root_host": root_host,
            },
            "robots": {
                "url": robots_url,
                "status_code": robots.status_code,
                "available": bool(robots.content),
                "artifact_paths": robots.artifact_paths,
            },
            "sitemap": {
                "url": sitemap_url,
                "status_code": sitemap.status_code,
                "available": bool(sitemap.content),
                "artifact_paths": sitemap.artifact_paths,
            },
        }
