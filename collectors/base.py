"""Collector abstraction layer for pluggable web collection engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from synint_paths import COLLECTION_ARTIFACTS_DIR


@dataclass(frozen=True)
class CollectorCapabilities:
    supports_javascript: bool = False
    supports_browser_automation: bool = False
    supports_session_state: bool = False
    supports_screenshot: bool = False
    supports_crawl: bool = False
    supports_html_extraction: bool = True
    supports_file_download: bool = True
    supports_form_detection: bool = False


@dataclass
class CollectionConfig:
    mode: str = "balanced"
    timeout_seconds: int = 8
    retries: int = 1
    min_delay_seconds: float = 0.2
    max_delay_seconds: float = 1.0
    max_pages: int = 20
    max_depth: int = 2
    proxy_url: str | None = None
    tor_socks_proxy: str | None = None
    user_agent: str | None = None
    allow_env_network_config: bool = False
    allow_env_cookies: bool = False
    save_artifacts: bool = True
    artifact_root: Path = COLLECTION_ARTIFACTS_DIR
    session_state_path: str | None = None


@dataclass
class CollectionResult:
    url: str
    final_url: str
    status_code: int | None
    content: str
    headers: Dict[str, str]
    redirect_chain: List[str] = field(default_factory=list)
    error: str | None = None
    collector_engine: str = "unknown"
    collection_mode: str = "balanced"
    rendered: bool = False
    proxy_used: bool = False
    screenshot_path: str | None = None
    artifact_paths: Dict[str, str] = field(default_factory=dict)
    fetch_attempts: int = 1
    response_summary: Dict[str, Any] = field(default_factory=dict)


class BaseCollector:
    """Base contract for collection adapters."""

    engine_name = "base"
    capabilities = CollectorCapabilities()

    def __init__(self, config: CollectionConfig | None = None) -> None:
        self.config = config or CollectionConfig()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def availability_reason(cls) -> str | None:
        return None

    def fetch(self, url: str, *, need_render: bool = False) -> CollectionResult:
        raise NotImplementedError

    def crawl(self, url: str, *, max_depth: int | None = None, max_pages: int | None = None) -> Dict[str, Any]:
        return {
            "status": "skipped",
            "reason": f"collector {self.engine_name} does not implement crawl",
            "visited": [],
        }

    def detect_forms(self, html: str) -> List[Dict[str, Any]]:
        return []

    def take_screenshot(self, url: str) -> Optional[str]:
        return None
