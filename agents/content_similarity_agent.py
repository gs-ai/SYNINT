"""Content similarity analysis across collected page/text artifacts."""

from __future__ import annotations

from difflib import SequenceMatcher
from hashlib import sha256
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class ContentSimilarityAgent(OSINTAgent):
    """Compare collected textual content for reuse/template overlap patterns."""

    name = "ContentSimilarityAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        try:
            web_findings = agent_results.get("WebCrawlerAgent", {}).get("result", {}).get("findings", {})
            page_summaries = web_findings.get("page_summaries", []) if isinstance(web_findings, dict) else []
            texts: List[Dict[str, str]] = []

            for page in page_summaries:
                if not isinstance(page, dict):
                    continue
                source = str(page.get("url", ""))
                title = str(page.get("title", ""))
                meta = str(page.get("meta_description", ""))
                blob = (title + " " + meta).strip()
                if source and blob:
                    texts.append({"source": source, "text": blob})

            if len(texts) < 2:
                return skipped(self.name, target, "insufficient page corpus for similarity comparison")

            pairs: List[Dict[str, Any]] = []
            reused_markers: List[str] = []
            for i in range(len(texts)):
                for j in range(i + 1, len(texts)):
                    a = texts[i]
                    b = texts[j]
                    ratio = SequenceMatcher(None, a["text"].lower(), b["text"].lower()).ratio()
                    if ratio >= 0.65:
                        pairs.append(
                            {
                                "source_a": a["source"],
                                "source_b": b["source"],
                                "similarity": round(ratio, 4),
                            }
                        )
                        if ratio >= 0.85:
                            reused_markers.append("high_text_reuse")

            cluster_groups: List[Dict[str, Any]] = []
            if pairs:
                cluster_groups.append(
                    {
                        "cluster_id": "similarity_cluster_1",
                        "members": unique_sorted([item["source_a"] for item in pairs] + [item["source_b"] for item in pairs]),
                    }
                )

            fingerprints = {
                item["source"]: sha256(item["text"].encode("utf-8", errors="ignore")).hexdigest()
                for item in texts
            }

            findings = {
                "similarity_pairs": pairs,
                "cluster_groups": cluster_groups,
                "reused_markers": unique_sorted(reused_markers),
                "content_fingerprint_summary": fingerprints,
            }

            if not pairs:
                return skipped(self.name, target, "no significant similarity pairs detected", findings=findings)

            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(pairs) * 0.02, 0.7),
                evidence_mode="derived",
                evidence_count=len(pairs),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
