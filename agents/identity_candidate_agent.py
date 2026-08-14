"""Optional candidate-only identity resolution agent."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.identity_resolution import IdentityResolver
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class IdentityCandidateAgent(OSINTAgent):
    """Create explainable identity links without confirming or merging records."""

    name = "IdentityCandidateAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    @staticmethod
    def _entities(context: Dict[str, Any], agent_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = context.get("identity_entities")
        if isinstance(candidates, list):
            return [item for item in candidates if isinstance(item, dict)]
        entity_result = agent_results.get("EntityResolutionAgent", {})
        result = entity_result.get("result", {}) if isinstance(entity_result, dict) else {}
        findings = result.get("findings", {}) if isinstance(result, dict) else {}
        resolved = findings.get("resolved_entities", []) if isinstance(findings, dict) else []
        return [item for item in resolved if isinstance(item, dict)] if isinstance(resolved, list) else []

    def run(self, indicator: Any):
        target, context, agent_results = unpack_pipeline_input(indicator)
        entities = self._entities(context, agent_results)
        if len(entities) < 2:
            return skipped(self.name, target, "identity resolution requires at least two entity observations")
        try:
            candidates = IdentityResolver.create_candidates(entities)
            findings = {
                "identity_candidates": [candidate.to_dict() for candidate in candidates],
                "candidate_count": len(candidates),
                "automatic_confirmation_count": 0,
                "original_entities_mutated": False,
                "confirmation_policy": "explicit operator decision required",
                "llm_direct_confirmation": False,
            }
            if not candidates:
                return skipped(self.name, target, "no deterministic identity candidate signals found", findings=findings)
            return ok(
                self.name,
                target,
                findings,
                min(0.02 + len(candidates) * 0.005, 0.25),
                evidence_mode="derived",
                evidence_count=len(candidates),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
