"""Optional Camoufox-backed browser collector.

This adapter degrades gracefully when Camoufox is unavailable.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict

from .base import BaseCollector, CollectionResult, CollectorCapabilities
from .utils import detect_cloudflare_challenge, normalize_url, parse_html_summary, write_collection_artifacts


class CamoufoxCollector(BaseCollector):
    """Stealth-capable browser collector when Camoufox runtime is present."""

    engine_name = "camoufox"
    capabilities = CollectorCapabilities(
        supports_javascript=True,
        supports_browser_automation=True,
        supports_session_state=True,
        supports_screenshot=True,
        supports_crawl=False,
        supports_html_extraction=True,
        supports_file_download=True,
        supports_form_detection=True,
    )

    @classmethod
    def is_available(cls) -> bool:
        try:
            importlib.import_module("camoufox")
            return True
        except Exception:
            return False

    @classmethod
    def availability_reason(cls) -> str | None:
        if cls.is_available():
            return None
        return "camoufox package not installed"

    def fetch(self, url: str, *, need_render: bool = False) -> CollectionResult:
        normalized = normalize_url(url)
        if not self.is_available():
            return CollectionResult(
                url=normalized,
                final_url=normalized,
                status_code=None,
                content="",
                headers={},
                error=self.availability_reason(),
                collector_engine=self.engine_name,
                collection_mode=self.config.mode,
                rendered=True,
                proxy_used=bool(self.config.proxy_url or self.config.tor_socks_proxy),
                response_summary={},
            )

        html_content = ""
        final_url = normalized
        status_code = None
        headers: Dict[str, str] = {}
        screenshot_bytes = None
        body_bytes: bytes = b""
        error = None

        try:
            sync_api = importlib.import_module("camoufox.sync_api")
            camoufox_ctx = getattr(sync_api, "Camoufox", None)
            if camoufox_ctx is None:
                raise RuntimeError("camoufox sync API is unavailable")

            with camoufox_ctx(headless=True) as browser:
                context_kwargs: Dict[str, Any] = {}
                if self.config.proxy_url:
                    context_kwargs["proxy"] = {"server": self.config.proxy_url}
                if self.config.user_agent:
                    context_kwargs["user_agent"] = self.config.user_agent
                context = browser.new_context(**context_kwargs)
                page = context.new_page()
                response = page.goto(normalized, wait_until="networkidle", timeout=self.config.timeout_seconds * 1000)
                html_content = page.content()
                final_url = page.url
                if response:
                    status_code = response.status
                    headers = response.headers
                    try:
                        body_bytes = response.body() or b""
                    except Exception:
                        body_bytes = b""
                if self.capabilities.supports_screenshot:
                    screenshot_bytes = page.screenshot(full_page=True)
                context.close()
        except Exception as exc:
            error = str(exc)

        artifact_paths = {}
        if self.config.save_artifacts:
            artifact_paths = write_collection_artifacts(
                artifact_root=self.config.artifact_root,
                url=normalized,
                collector_engine=self.engine_name,
                collection_mode=self.config.mode,
                status_code=status_code,
                content=html_content,
                rendered=True,
                headers=headers,
                screenshot_bytes=screenshot_bytes,
                body_bytes=body_bytes,
                final_url=final_url,
                content_type=headers.get("content-type", ""),
                content_disposition=headers.get("content-disposition", ""),
            )

        return CollectionResult(
            url=normalized,
            final_url=final_url,
            status_code=status_code,
            content=html_content,
            headers=headers,
            error=error,
            collector_engine=self.engine_name,
            collection_mode=self.config.mode,
            rendered=True,
            proxy_used=bool(self.config.proxy_url or self.config.tor_socks_proxy),
            screenshot_path=artifact_paths.get("screenshot"),
            artifact_paths=artifact_paths,
            response_summary=(
                {
                    **parse_html_summary(final_url, html_content),
                    **({"downloaded_file": artifact_paths.get("download")} if artifact_paths.get("download") else {}),
                    "cloudflare": detect_cloudflare_challenge(
                        status_code=status_code,
                        headers=headers,
                        content=html_content,
                    ),
                }
                if html_content
                else {
                    "cloudflare": detect_cloudflare_challenge(
                        status_code=status_code,
                        headers=headers,
                        content=html_content,
                    )
                }
            ),
        )
