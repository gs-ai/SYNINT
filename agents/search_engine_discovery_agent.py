"""Parse local search exports or cached corpora for discovery signals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.document_utils import extract_text_from_file
from core.entity_utils import URL_RE, extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class SearchEngineDiscoveryAgent(OSINTAgent):
    """Derive indexed-document and mention signals from local search-result artifacts."""

    name = "SearchEngineDiscoveryAgent"
    supported_target_types = ("text", "file", "json")
    requires_context = True

    QUERY_HINTS = ["site:", "filetype:", "intitle:", "inurl:"]
    ADMIN_PATH_MARKERS = ["/admin", "/login", "/dashboard", "/wp-admin", "/config", "/backup"]

    def _candidate_sources(self, target: str, context: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        if target and Path(target).exists() and Path(target).is_file():
            candidates.append(target)
        for path in context.get("collected_files", []) if isinstance(context, dict) else []:
            candidate = str(path)
            if Path(candidate).exists() and Path(candidate).is_file():
                candidates.append(candidate)
        return unique_sorted(candidates)

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            sources = self._candidate_sources(target, context)
            if not sources:
                return skipped(self.name, target, "no local search exports available")

            matched_queries: List[str] = []
            indexed_documents: List[str] = []
            profile_mentions: List[str] = []
            leak_signals: List[str] = []
            administrative_paths: List[str] = []
            source_map: Dict[str, Dict[str, Any]] = {}

            for source in sources:
                extracted = extract_text_from_file(source)
                if extracted.get("status") != "ok":
                    source_map[source] = {"status": "error", "error": extracted.get("error")}
                    continue

                text = str(extracted.get("text", ""))
                entities = extract_entities_from_text(text)
                urls = entities.get("urls", [])
                indexed_documents.extend(urls)

                for line in text.splitlines():
                    lowered = line.lower()
                    if any(hint in lowered for hint in self.QUERY_HINTS):
                        matched_queries.append(line.strip())
                    if "linkedin.com/in/" in lowered or "x.com/" in lowered or "github.com/" in lowered:
                        profile_mentions.append(line.strip())
                    if any(marker in lowered for marker in ["exposed", "leak", "credential", "password", "dump"]):
                        leak_signals.append(line.strip())

                for url in urls:
                    l = url.lower()
                    if any(marker in l for marker in self.ADMIN_PATH_MARKERS):
                        administrative_paths.append(url)

                source_map[source] = {
                    "status": "ok",
                    "extractor": extracted.get("extractor"),
                    "char_count": extracted.get("char_count", 0),
                    "url_count": len(urls),
                }

            findings = {
                "matched_queries": unique_sorted(matched_queries),
                "indexed_documents": unique_sorted(indexed_documents),
                "profile_mentions": unique_sorted(profile_mentions),
                "leak_signals": unique_sorted(leak_signals),
                "administrative_paths": unique_sorted(administrative_paths),
                "sources": source_map,
            }

            evidence_count = len(findings["indexed_documents"]) + len(findings["leak_signals"]) + len(findings["administrative_paths"])
            risk = min(0.03 + len(findings["leak_signals"]) * 0.08 + len(findings["administrative_paths"]) * 0.05, 0.85)
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
