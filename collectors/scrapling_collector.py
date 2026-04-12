"""Optional Scrapling-powered structured extraction collector."""

from __future__ import annotations

import importlib
import random
import time
from typing import Any, Dict

from .base import BaseCollector, CollectionResult, CollectorCapabilities
from .utils import (
    create_safe_session,
    detect_cloudflare_challenge,
    normalize_url,
    parse_html_summary,
    write_collection_artifacts,
)


class ScraplingCollector(BaseCollector):
    """Structured HTML extraction adapter backed by Scrapling when installed."""

    engine_name = "scrapling"
    capabilities = CollectorCapabilities(
        supports_javascript=False,
        supports_browser_automation=False,
        supports_session_state=True,
        supports_screenshot=False,
        supports_crawl=False,
        supports_html_extraction=True,
        supports_file_download=True,
        supports_form_detection=True,
    )

    @classmethod
    def is_available(cls) -> bool:
        try:
            importlib.import_module("scrapling")
            return True
        except Exception:
            return False

    @classmethod
    def availability_reason(cls) -> str | None:
        if cls.is_available():
            return None
        return "scrapling package not installed"

    def fetch(self, url: str, *, need_render: bool = False) -> CollectionResult:
        normalized = normalize_url(url)
        html_content = ""
        headers: Dict[str, str] = {}
        status_code = None
        final_url = normalized
        error = None
        summary: Dict[str, Any] = {}
        body_bytes: bytes = b""

        try:
            session = create_safe_session(
                user_agent=self.config.user_agent,
                allow_env_network_config=self.config.allow_env_network_config,
            )
            if self.config.proxy_url:
                session.proxies.update({"http": self.config.proxy_url, "https": self.config.proxy_url})
            elif self.config.tor_socks_proxy:
                socks = self.config.tor_socks_proxy
                session.proxies.update({"http": socks, "https": socks})
            if self.config.max_delay_seconds > 0:
                time.sleep(random.uniform(self.config.min_delay_seconds, self.config.max_delay_seconds))
            response = session.get(normalized, timeout=self.config.timeout_seconds, allow_redirects=True)
            status_code = response.status_code
            final_url = str(response.url)
            html_content = response.text or ""
            body_bytes = response.content or b""
            headers = {k: v for k, v in response.headers.items()}

            summary = parse_html_summary(final_url, html_content)
            if self.is_available():
                scrapling = importlib.import_module("scrapling")
                parser_cls = getattr(scrapling, "Parser", None)
                if parser_cls is not None:
                    parsed = parser_cls(html_content)
                    title = getattr(parsed, "title", None)
                    if isinstance(title, str) and title.strip():
                        summary["title"] = title.strip()
        except Exception as exc:
            error = str(exc)

        summary = summary if isinstance(summary, dict) else {}
        summary["cloudflare"] = detect_cloudflare_challenge(
            status_code=status_code,
            headers=headers,
            content=html_content,
        )

        artifact_paths = {}
        if self.config.save_artifacts:
            artifact_paths = write_collection_artifacts(
                artifact_root=self.config.artifact_root,
                url=normalized,
                collector_engine=self.engine_name,
                collection_mode=self.config.mode,
                status_code=status_code,
                content=html_content,
                rendered=False,
                headers=headers,
                body_bytes=body_bytes,
                final_url=final_url,
                content_type=headers.get("Content-Type", ""),
                content_disposition=headers.get("Content-Disposition", ""),
            )
        if artifact_paths.get("download"):
            summary["downloaded_file"] = artifact_paths.get("download")

        return CollectionResult(
            url=normalized,
            final_url=final_url,
            status_code=status_code,
            content=html_content,
            headers=headers,
            error=error,
            collector_engine=self.engine_name,
            collection_mode=self.config.mode,
            rendered=False,
            proxy_used=bool(self.config.proxy_url or self.config.tor_socks_proxy),
            artifact_paths=artifact_paths,
            response_summary=summary,
        )
