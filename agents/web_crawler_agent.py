"""Bounded website crawler with collector-engine abstraction and provenance."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from agents.base_agent import OSINTAgent
from collectors import CollectionConfig, select_collector
from core.entity_utils import extract_entities_from_text
from synint_paths import COLLECTION_ARTIFACTS_DIR
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class WebCrawlerAgent(OSINTAgent):
    """Crawl a target website safely and collect structured page intelligence."""

    name = "WebCrawlerAgent"
    supported_target_types = ("domain", "url", "text")
    requires_context = True

    SENSITIVE_TOKENS = {
        "admin",
        "login",
        "upload",
        "backup",
        "export",
        "archive",
        "staging",
        "dev",
        "dashboard",
        "config",
        "old",
        "test",
    }

    def _is_web_target(self, target: str) -> bool:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return bool(parsed.netloc)

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        mode = str(context.get("collection_mode", "balanced")) if context else "balanced"
        reports_dir = str(context.get("reports_dir", "")).strip() if context else ""
        artifact_root = Path(reports_dir) / "collection_artifacts" if reports_dir else COLLECTION_ARTIFACTS_DIR
        if not target:
            return skipped(self.name, indicator, "missing target")
        if not self._is_web_target(target):
            return skipped(self.name, target, "target is not web-addressable")

        try:
            collector, attempts = select_collector(
                mode=mode,
                # Crawl requires a collector with crawl capability; rendering can be
                # layered by downstream fetches when available.
                need_render=False,
                need_crawl=True,
                config=CollectionConfig(
                    mode=mode,
                    max_pages=25 if mode == "deep_browser" else 15,
                    max_depth=3 if mode == "deep_browser" else 2,
                    artifact_root=artifact_root,
                ),
            )
            crawl = collector.crawl(target)
            if crawl.get("status") != "ok":
                return skipped(self.name, target, crawl.get("reason", "crawl unavailable"), findings={"collector_attempts": attempts})

            pages = crawl.get("pages", [])
            discovered_urls = crawl.get("visited", [])
            internal_links = crawl.get("internal_links", [])
            external_links = crawl.get("external_links", [])

            forms_detected: List[Dict[str, Any]] = []
            file_links: List[str] = []
            downloaded_files: List[str] = []
            download_attempts: List[Dict[str, Any]] = []
            contact_emails: List[str] = []
            contact_phones: List[str] = []
            sensitive_paths: List[str] = []
            per_page: List[Dict[str, Any]] = []

            seen_hashes = set()
            for page in pages:
                url = str(page.get("url", ""))
                path = (urlparse(url).path or "/").lower()
                if any(token in path for token in self.SENSITIVE_TOKENS):
                    sensitive_paths.append(url)

                forms = page.get("forms", []) if isinstance(page.get("forms"), list) else []
                files = page.get("file_links", []) if isinstance(page.get("file_links"), list) else []
                forms_detected.extend(forms)
                file_links.extend(str(item) for item in files)

                text_source = " ".join([str(page.get("title", "")), str(page.get("meta_description", "")), url])
                fingerprint = sha256(text_source.encode("utf-8", errors="ignore")).hexdigest()
                if fingerprint in seen_hashes:
                    continue
                seen_hashes.add(fingerprint)

                entities = extract_entities_from_text(text_source)
                contact_emails.extend(entities.get("emails", []))
                contact_phones.extend(entities.get("phones", []))

                per_page.append(
                    {
                        "url": url,
                        "status_code": page.get("status_code"),
                        "title": page.get("title"),
                        "meta_description": page.get("meta_description"),
                        "form_count": len(forms),
                        "file_link_count": len(files),
                        "content_fingerprint": fingerprint,
                        "collector_engine": page.get("collector_engine", collector.engine_name),
                        "artifact_paths": page.get("artifact_paths", {}),
                    }
                )

            file_link_candidates = sorted(set(file_links))
            max_file_downloads = 20 if mode == "deep_browser" else 10
            if mode == "low_noise":
                max_file_downloads = 5
            for file_url in file_link_candidates[:max_file_downloads]:
                download_result = collector.fetch(file_url)
                local_path = str(download_result.artifact_paths.get("download", "")).strip()
                resolved_local = ""
                if local_path and Path(local_path).exists() and Path(local_path).is_file():
                    resolved_local = str(Path(local_path).resolve())
                    downloaded_files.append(resolved_local)

                download_attempts.append(
                    {
                        "url": file_url,
                        "status_code": download_result.status_code,
                        "collector_engine": download_result.collector_engine,
                        "downloaded": bool(resolved_local),
                        "download_path": resolved_local,
                    }
                )

            findings = {
                "collector_engine": crawl.get("collector_engine", collector.engine_name),
                "collection_mode": mode,
                "collector_attempts": attempts,
                "discovered_urls": sorted(set(discovered_urls)),
                "visited_count": int(crawl.get("visited_count", len(discovered_urls))),
                "internal_links": sorted(set(internal_links)),
                "external_links": sorted(set(external_links)),
                "forms_detected": forms_detected,
                "file_links": file_link_candidates,
                "downloaded_files": sorted(set(downloaded_files)),
                "download_attempts": download_attempts,
                "contact_artifacts": {
                    "emails": sorted(set(contact_emails)),
                    "phones": sorted(set(contact_phones)),
                },
                "sensitive_paths": sorted(set(sensitive_paths)),
                "crawl_summary": crawl.get("crawl_summary", {}),
                "page_summaries": per_page,
                "artifact_paths": {
                    "robots": crawl.get("robots", {}).get("artifact_paths", {}),
                    "sitemap": crawl.get("sitemap", {}).get("artifact_paths", {}),
                },
            }

            evidence_count = len(findings["discovered_urls"]) + len(findings["forms_detected"]) + len(findings["downloaded_files"])
            risk = min(0.05 + len(findings["sensitive_paths"]) * 0.03 + len(findings["file_links"]) * 0.02, 0.8)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
