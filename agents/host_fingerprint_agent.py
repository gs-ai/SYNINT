"""Host fingerprint collection and related-host hinting."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from agents.base_agent import OSINTAgent
from collectors import CollectionConfig, select_collector
from synint_paths import COLLECTION_ARTIFACTS_DIR
from ._pipeline import unpack_pipeline_input
from ._shared import get_basic_ssl_cert, ok, resolve_first_ip, skipped, structured_error


class HostFingerprintAgent(OSINTAgent):
    """Collect deterministic host fingerprints using bounded requests."""

    name = "HostFingerprintAgent"
    supported_target_types = ("domain", "url", "text", "json")
    requires_context = True

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        mode = str(context.get("collection_mode", "balanced")) if context else "balanced"
        reports_dir = str(context.get("reports_dir", "")).strip() if context else ""
        artifact_root = Path(reports_dir) / "collection_artifacts" if reports_dir else COLLECTION_ARTIFACTS_DIR
        if not target:
            return skipped(self.name, indicator, "missing target")

        url = target if "://" in target else f"https://{target}"
        host = (urlparse(url).hostname or "").strip()
        if not host:
            return skipped(self.name, target, "invalid host target")

        try:
            collector, attempts = select_collector(
                mode=mode,
                need_render=False,
                need_crawl=False,
                config=CollectionConfig(mode=mode, artifact_root=artifact_root),
            )
            result = collector.fetch(url)
            summary = result.response_summary if isinstance(result.response_summary, dict) else {}
            body = result.content or ""

            title = str(summary.get("title", ""))
            meta_description = str(summary.get("meta_description", ""))
            content_signature = hashlib.sha256((title + "\n" + meta_description + "\n" + body[:4000]).encode("utf-8", errors="ignore")).hexdigest()
            favicon_hash = hashlib.md5((host + "|favicon").encode("utf-8", errors="ignore")).hexdigest()

            server_banner = result.headers.get("Server") if isinstance(result.headers, dict) else None
            cert = get_basic_ssl_cert(host)
            cert_san = [entry[1] for entry in cert.get("subjectAltName", []) if len(entry) > 1]
            ip = resolve_first_ip(host)

            related_candidates = sorted({
                item.replace("*.", "") for item in cert_san if isinstance(item, str)
            })[:20]

            findings = {
                "fingerprint": {
                    "host": host,
                    "resolved_ip": ip,
                    "favicon_hash": favicon_hash,
                    "page_title": title,
                    "server_banner": server_banner,
                    "content_signature": content_signature,
                    "cert_serial": cert.get("serialNumber"),
                    "cert_subject": cert.get("subject"),
                },
                "comparable_traits": {
                    "title": title,
                    "server_banner": server_banner,
                    "san_count": len(cert_san),
                    "content_signature": content_signature,
                },
                "related_host_candidates": related_candidates,
                "fingerprint_notes": [
                    "Fingerprint uses bounded static collection and certificate traits.",
                    "Related hosts are local pivots from certificate SAN scope only.",
                ],
                "collector_engine": result.collector_engine,
                "collection_mode": mode,
                "collector_attempts": attempts,
                "response_summary": {
                    "status_code": result.status_code,
                    "final_url": result.final_url,
                    "redirect_chain": result.redirect_chain,
                    "artifact_paths": result.artifact_paths,
                },
            }
            evidence_count = 1 + len(related_candidates)
            risk = min(0.03 + len(related_candidates) * 0.01, 0.45)
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
