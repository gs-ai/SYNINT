"""Optional Scrapy-compatible collector adapter.

When Scrapy is unavailable, this adapter reports unavailability and allows orchestrator fallback.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict

from .base import BaseCollector, CollectionResult, CollectorCapabilities
from .static_http import StaticHttpCollector
from .utils import normalize_url


class ScrapyCollector(BaseCollector):
    """Bounded crawler adapter with Scrapy capability detection."""

    engine_name = "scrapy"
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

    @classmethod
    def is_available(cls) -> bool:
        try:
            importlib.import_module("scrapy")
            return True
        except Exception:
            return False

    @classmethod
    def availability_reason(cls) -> str | None:
        if cls.is_available():
            return None
        return "scrapy package not installed"

    def fetch(self, url: str, *, need_render: bool = False) -> CollectionResult:
        if not self.is_available():
            return CollectionResult(
                url=normalize_url(url),
                final_url=normalize_url(url),
                status_code=None,
                content="",
                headers={},
                error=self.availability_reason(),
                collector_engine=self.engine_name,
                collection_mode=self.config.mode,
                rendered=False,
                proxy_used=bool(self.config.proxy_url or self.config.tor_socks_proxy),
                response_summary={},
            )

        # For local bounded operation, delegate fetch behavior to static collector.
        delegate = StaticHttpCollector(config=self.config)
        result = delegate.fetch(url)
        result.collector_engine = self.engine_name
        return result

    def crawl(self, url: str, *, max_depth: int | None = None, max_pages: int | None = None) -> Dict[str, Any]:
        if not self.is_available():
            return {
                "status": "skipped",
                "reason": self.availability_reason(),
                "visited": [],
                "collector_engine": self.engine_name,
            }

        delegate = StaticHttpCollector(config=self.config)
        data = delegate.crawl(url, max_depth=max_depth, max_pages=max_pages)
        data["collector_engine"] = self.engine_name
        data["scrapy_compatible"] = True
        data["dedupe_enabled"] = True
        data["domain_scoped"] = True
        return data
