"""Classify and score evidence by evidentiary tier."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class EvidenceScoringAgent(OSINTAgent):
    """Prevent heuristic-only outputs from dominating the investigation narrative."""

    name = "EvidenceScoringAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def _tier(self, evidence_mode: str, status: str) -> str:
        mode = evidence_mode.lower()
        if status == "error":
            return "hypothesis"
        if mode in {"collected", "active", "fused"}:
            return "direct evidence"
        if mode in {"derived", "passive"}:
            return "derived evidence"
        if mode in {"heuristic"}:
            return "inferred evidence"
        if mode in {"scaffold", "none"}:
            return "enrichment only"
        return "hypothesis"

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no results available to score")

        try:
            scored: List[Dict[str, Any]] = []
            tier_counts: Dict[str, int] = {}
            confidence_distribution: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}

            for agent_name, entry in sorted(agent_results.items()):
                result = entry.get("result") if isinstance(entry, dict) else entry
                if not isinstance(result, dict):
                    continue

                status = str(result.get("status", "unknown"))
                if status.lower() == "skipped":
                    continue
                mode = str(result.get("evidence_mode", "none"))
                evidence_count = int(result.get("evidence_count", 0) or 0)
                risk = float(result.get("risk_score", 0.0) or 0.0)
                tier = self._tier(mode, status)
                if tier == "direct evidence" and evidence_count <= 0:
                    tier = "enrichment only"

                confidence = min(1.0, 0.35 + evidence_count * 0.05 + risk * 0.35)
                if tier == "enrichment only":
                    confidence = min(confidence, 0.45)
                if tier == "direct evidence":
                    confidence = max(confidence, 0.55)

                band = "high" if confidence >= 0.75 else "medium" if confidence >= 0.45 else "low"
                confidence_distribution[band] += 1
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

                scored.append(
                    {
                        "agent": agent_name,
                        "tier": tier,
                        "confidence": round(confidence, 4),
                        "status": status,
                        "risk_score": round(risk, 4),
                        "evidence_count": evidence_count,
                        "evidence_mode": mode,
                    }
                )

            scored.sort(key=lambda item: (item["confidence"], item["evidence_count"], item["risk_score"]), reverse=True)
            strongest = scored[:10]

            findings = {
                "scored_findings": scored,
                "evidence_tiers": tier_counts,
                "confidence_distribution": confidence_distribution,
                "strongest_evidence": strongest,
            }
            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(strongest) * 0.02, 0.7),
                evidence_mode="derived",
                evidence_count=len(scored),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
