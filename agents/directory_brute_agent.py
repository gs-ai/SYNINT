"""Curated high-value path probing with low-noise HTTP classification."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from agents.base_agent import OSINTAgent
from collectors import CollectionConfig, select_collector
from synint_paths import COLLECTION_ARTIFACTS_DIR
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class DirectoryBruteAgent(OSINTAgent):
    """Probe a small curated directory list for notable reachable paths."""

    name = "DirectoryBruteAgent"
    supported_target_types = ("domain", "url", "text")
    requires_context = True

    WORDLIST = [
        "admin",
        "login",
        "dashboard",
        "upload",
        "backup",
        "old",
        "test",
        "dev",
        "staging",
        "docs",
        "api",
        "config",
    ]

    @staticmethod
    def _normalize_path(path: str) -> str:
        raw = str(path or "").strip()
        if not raw:
            return "/"
        if not raw.startswith("/"):
            raw = "/" + raw
        if len(raw) > 1 and raw.endswith("/"):
            raw = raw[:-1]
        return raw

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        mode = str(context.get("collection_mode", "balanced")) if context else "balanced"
        reports_dir = str(context.get("reports_dir", "")).strip() if context else ""
        artifact_root = Path(reports_dir) / "collection_artifacts" if reports_dir else COLLECTION_ARTIFACTS_DIR
        if not target:
            return skipped(self.name, indicator, "missing target")

        base_url = target if "://" in target else f"https://{target}"
        base_url = base_url.rstrip("/") + "/"

        try:
            collector, attempts = select_collector(
                mode=mode,
                need_render=False,
                need_crawl=False,
                config=CollectionConfig(mode=mode, artifact_root=artifact_root),
            )
            checked_paths: List[Dict[str, Any]] = []
            reachable_paths: List[Dict[str, Any]] = []
            auth_gates: List[Dict[str, Any]] = []
            redirects: List[Dict[str, Any]] = []
            notable_findings: List[str] = []

            for word in self.WORDLIST:
                url = urljoin(base_url, word)
                result = collector.fetch(url)
                status = int(result.status_code or 0)
                final_url = result.final_url or url
                requested_path = self._normalize_path(urlparse(url).path)
                final_path = self._normalize_path(urlparse(final_url).path)
                redirected = bool(status in range(300, 400) or requested_path != final_path)
                if result.redirect_chain and len(result.redirect_chain) > 1:
                    redirected = True

                entry = {
                    "path": f"/{word}",
                    "url": final_url,
                    "requested_url": url,
                    "status_code": result.status_code,
                    "collector_engine": result.collector_engine,
                    "redirect_chain": result.redirect_chain,
                    "requested_path": requested_path,
                    "final_path": final_path,
                    "redirected": redirected,
                }
                checked_paths.append(entry)

                # Count only direct path hits as reachable. Redirected 2xx targets are
                # tracked separately to avoid inflating real exposure findings.
                if 200 <= status < 300 and not redirected:
                    reachable_paths.append(entry)
                if status in {401, 403}:
                    auth_gates.append(entry)
                if redirected:
                    redirects.append(entry)

            if reachable_paths:
                notable_findings.append(f"{len(reachable_paths)} curated path(s) returned 2xx responses.")
            if auth_gates:
                notable_findings.append(f"{len(auth_gates)} path(s) appear auth-gated (401/403).")
            if redirects:
                notable_findings.append(f"{len(redirects)} path(s) redirected.")

            findings = {
                "collector_engine": collector.engine_name,
                "collection_mode": mode,
                "collector_attempts": attempts,
                "checked_paths": checked_paths,
                "reachable_paths": reachable_paths,
                "auth_gates": auth_gates,
                "redirects": redirects,
                "notable_findings": notable_findings,
            }

            risk = min(0.03 + len(reachable_paths) * 0.03 + len(auth_gates) * 0.02, 0.7)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=len(reachable_paths) + len(auth_gates),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
