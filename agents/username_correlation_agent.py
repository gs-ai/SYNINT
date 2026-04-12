"""Username variant generation and local corpus correlation."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import collect_all_text, unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class UsernameCorrelationAgent(OSINTAgent):
    """Generate username variants and match them against collected local evidence."""

    name = "UsernameCorrelationAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def _seed(self, target: str, context: Dict[str, Any]) -> str:
        if target.startswith("@"):
            return target[1:]
        if "@" in target and "://" not in target:
            return target.split("@", 1)[0]
        if "://" in target:
            return target.rstrip("/").split("/")[-1].lstrip("@") or context.get("normalized_target", "")
        if "." in target and " " not in target:
            return target.split(".", 1)[0]
        return target

    def _variants(self, seed: str) -> List[str]:
        base = re.sub(r"[^A-Za-z0-9._-]", "", seed.strip().lower())
        if not base:
            return []
        parts = re.split(r"[._-]+", base)
        variants = {
            base,
            base.replace(".", ""),
            base.replace("_", ""),
            base.replace("-", ""),
        }
        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]
            variants.update({
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}{last}",
                f"{first[0]}{last}" if first else last,
                f"{last}{first[0]}" if first else last,
            })
        return unique_sorted(variants)

    def run(self, indicator: Any):
        target, context, agent_results = unpack_pipeline_input(indicator)
        seed = self._seed(target, context)
        if not seed:
            return skipped(self.name, target, "could not derive seed username")

        try:
            variants = self._variants(seed)
            if not variants:
                return skipped(self.name, target, "no valid username variants generated")

            corpus_lines = collect_all_text(agent_results)
            corpus_lower = "\n".join(corpus_lines).lower()
            matched = [variant for variant in variants if variant.lower() in corpus_lower]

            clusters = []
            if matched:
                clusters.append(
                    {
                        "cluster_id": "reuse_cluster_1",
                        "variants": matched,
                        "sources": [
                            "local_collected_corpus",
                        ],
                    }
                )

            confidence_notes = [
                "Matches are based on local collected corpus only.",
                "No live platform claim is made without explicit platform fetch evidence.",
            ]

            findings = {
                "seed": seed,
                "generated_variants": variants,
                "matched_variants": unique_sorted(matched),
                "probable_reuse_clusters": clusters,
                "confidence_notes": confidence_notes,
            }
            evidence_count = len(findings["matched_variants"])
            risk = min(0.02 + evidence_count * 0.04, 0.5)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="derived" if evidence_count else "heuristic",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
