"""Probe likely exposed archive and backup files with bounded requests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from agents.base_agent import OSINTAgent
from collectors import CollectionConfig, select_collector
from collectors.utils import create_safe_session
from synint_paths import COLLECTION_ARTIFACTS_DIR
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class ArchiveFileDiscoveryAgent(OSINTAgent):
    """Check curated sensitive file paths with low-noise probing."""

    name = "ArchiveFileDiscoveryAgent"
    supported_target_types = ("domain", "url", "text")
    requires_context = True

    CANDIDATES = [
        "backup.zip",
        "db.sql",
        "export.csv",
        ".env",
        "archive.tar.gz",
        "old.zip",
        "dump.sql",
        "logs.txt",
        "backup.tar",
        "database.sql.gz",
        "site-backup.zip",
    ]

    LISTING_MARKERS = ["Index of /", "Parent Directory", "Directory listing", "Last modified"]

    def _normalize_base(self, target: str) -> str:
        return target if "://" in target else f"https://{target}"

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        mode = str(context.get("collection_mode", "balanced")) if context else "balanced"
        reports_dir = str(context.get("reports_dir", "")).strip() if context else ""
        artifact_root = Path(reports_dir) / "collection_artifacts" if reports_dir else COLLECTION_ARTIFACTS_DIR
        if not target:
            return skipped(self.name, indicator, "missing target")

        base_url = self._normalize_base(target).rstrip("/") + "/"
        host = (urlparse(base_url).hostname or "").strip()
        if not host:
            return skipped(self.name, target, "invalid web target")

        try:
            collector, attempts = select_collector(
                mode=mode,
                need_render=False,
                need_crawl=False,
                config=CollectionConfig(mode=mode, artifact_root=artifact_root),
            )
            head_session = create_safe_session()
            checked: List[Dict[str, Any]] = []
            reachable: List[Dict[str, Any]] = []
            downloaded_files: List[str] = []
            suspicious_extensions: List[str] = []
            listing_signals: List[Dict[str, Any]] = []
            severity_notes: List[str] = []

            for name in self.CANDIDATES:
                url = urljoin(base_url, name)
                status_code = None
                method_used = "HEAD"
                detail = ""
                downloaded_path = ""
                get_result = None

                try:
                    head_resp = head_session.head(url, timeout=6, allow_redirects=True)
                    status_code = head_resp.status_code
                    if status_code in {405, 403} or status_code is None:
                        get_result = collector.fetch(url)
                        method_used = "GET"
                        status_code = get_result.status_code
                        detail = get_result.error or ""
                        body_sample = (get_result.content or "")[:1000]
                        if any(marker.lower() in body_sample.lower() for marker in self.LISTING_MARKERS):
                            listing_signals.append({"url": get_result.final_url, "signal": "directory_listing_marker"})
                except Exception as exc:
                    detail = str(exc)

                if status_code is not None and status_code < 400 and get_result is None:
                    get_result = collector.fetch(url)
                    method_used = "HEAD+GET"
                    if get_result.status_code is not None:
                        status_code = get_result.status_code
                    detail = detail or get_result.error or ""

                if get_result is not None:
                    local_download = str(get_result.artifact_paths.get("download", "")).strip()
                    if local_download and Path(local_download).exists() and Path(local_download).is_file():
                        downloaded_path = str(Path(local_download).resolve())
                        downloaded_files.append(downloaded_path)

                entry = {
                    "url": url,
                    "status_code": status_code,
                    "method": method_used,
                    "detail": detail,
                    "download_path": downloaded_path,
                }
                checked.append(entry)

                if status_code is not None and status_code < 400:
                    reachable.append(entry)
                    ext = "." + name.split(".")[-1] if "." in name else ""
                    if ext:
                        suspicious_extensions.append(ext.lower())

            if any(item.get("url", "").endswith(".env") for item in reachable):
                severity_notes.append("Potential environment file exposure detected.")
            if any(item.get("url", "").endswith(".sql") for item in reachable):
                severity_notes.append("Database dump-style file exposure detected.")
            if listing_signals:
                severity_notes.append("Directory listing indicators detected.")

            findings = {
                "collector_engine": collector.engine_name,
                "collection_mode": mode,
                "collector_attempts": attempts,
                "candidate_urls_checked": checked,
                "reachable_sensitive_files": reachable,
                "downloaded_files": sorted(set(downloaded_files)),
                "suspicious_extensions": sorted(set(suspicious_extensions)),
                "directory_listing_signals": listing_signals,
                "severity_notes": severity_notes,
                "fetch_attempts": len(checked),
            }
            risk = min(0.04 + len(reachable) * 0.08 + len(listing_signals) * 0.1, 0.95)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=len(reachable),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
