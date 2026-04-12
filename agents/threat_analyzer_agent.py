#!/usr/bin/env python3
"""Threat fusion agent that consolidates cross-stage investigative signals."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._shared import ok, skipped, structured_error


class ThreatAnalyzerAgent(OSINTAgent):
    """Build a consolidated risk/threat picture from pipeline artifacts."""

    name = "ThreatAnalyzerAgent"
    supported_target_types = ("fusion_bundle", "json", "multiline", "text")
    consume_all_results = True

    def _payload(self, indicator: Any) -> Dict[str, Any]:
        if isinstance(indicator, dict):
            return indicator
        if indicator is None:
            return {}
        text = str(indicator).strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _build(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = payload.get("target", "")
        agent_results = payload.get("agent_results") if isinstance(payload.get("agent_results"), dict) else {}
        evidence_registry = payload.get("evidence_registry") if isinstance(payload.get("evidence_registry"), list) else []
        entity_registry = payload.get("entity_registry") if isinstance(payload.get("entity_registry"), list) else []
        if not agent_results:
            return skipped(self.name, target, "no agent results provided for threat fusion", findings={"source_agents": []})

        evidence_findings = agent_results.get("EvidenceScoringAgent", {}).get("result", {}).get("findings", {})
        contradiction_findings = agent_results.get("ContradictionDetectionAgent", {}).get("result", {}).get("findings", {})
        lead_findings = agent_results.get("LeadGenerationAgent", {}).get("result", {}).get("findings", {})
        infra_findings = agent_results.get("InfrastructureClusterAgent", {}).get("result", {}).get("findings", {})
        timeline_findings = agent_results.get("TimelineReconstructionAgent", {}).get("result", {}).get("findings", {})
        entity_findings = agent_results.get("EntityResolutionAgent", {}).get("result", {}).get("findings", {})

        scored = evidence_findings.get("scored_findings", []) if isinstance(evidence_findings, dict) else []
        strongest = evidence_findings.get("strongest_evidence", []) if isinstance(evidence_findings, dict) else []
        contradictions = contradiction_findings.get("contradictions", []) if isinstance(contradiction_findings, dict) else []
        leads = lead_findings.get("prioritized_leads", []) if isinstance(lead_findings, dict) else []
        clusters = infra_findings.get("clusters", []) if isinstance(infra_findings, dict) else []
        timeline_events = timeline_findings.get("timeline", []) if isinstance(timeline_findings, dict) else []
        timeline_gaps = timeline_findings.get("missing_time_gaps", []) if isinstance(timeline_findings, dict) else []
        resolved_entities = entity_findings.get("resolved_entities", []) if isinstance(entity_findings, dict) else []
        if not resolved_entities:
            resolved_entities = [item for item in entity_registry if isinstance(item, dict)]

        direct_count = sum(1 for item in scored if item.get("tier") == "direct evidence")
        derived_count = sum(1 for item in scored if item.get("tier") == "derived evidence")
        inferred_count = sum(1 for item in scored if item.get("tier") == "inferred evidence")
        registry_direct = sum(
            1 for item in evidence_registry if str(item.get("evidence_tier", "")).lower().startswith("direct")
        )

        risk_components = {
            "direct_evidence_weight": min(direct_count * 0.06, 0.35),
            "derived_evidence_weight": min(derived_count * 0.03, 0.2),
            "registry_direct_weight": min(registry_direct * 0.02, 0.2),
            "contradiction_weight": min(len(contradictions) * 0.07, 0.21),
            "infrastructure_cluster_weight": min(len(clusters) * 0.08, 0.24),
            "timeline_gap_weight": min(len(timeline_gaps) * 0.04, 0.12),
            "lead_priority_weight": min(sum(1 for item in leads if int(item.get("priority", 99)) <= 2) * 0.05, 0.15),
        }
        fused_risk = min(sum(risk_components.values()), 1.0)

        threat_picture = {
            "target": target,
            "source_agents_considered": sorted(agent_results.keys()),
            "evidence_summary": {
                "total_scored_findings": len(scored),
                "registry_evidence_count": len(evidence_registry),
                "direct_evidence_count": direct_count,
                "derived_evidence_count": derived_count,
                "inferred_evidence_count": inferred_count,
            },
            "entity_summary": {
                "entity_registry_count": len(entity_registry),
                "resolved_entity_count": len(resolved_entities),
            },
            "infrastructure_summary": {
                "cluster_count": len(clusters),
            },
            "timeline_summary": {
                "event_count": len(timeline_events),
                "gap_count": len(timeline_gaps),
            },
            "contradiction_count": len(contradictions),
            "lead_count": len(leads),
            "risk_components": risk_components,
        }

        findings = {
            "threat_picture": threat_picture,
            "strongest_evidence": strongest,
            "registry_evidence_snapshot": evidence_registry[:20],
            "registry_entity_snapshot": entity_registry[:20],
            "infrastructure_clusters": clusters,
            "contradictions": contradictions,
            "prioritized_leads": leads[:10],
            "timeline_significance": {
                "events": len(timeline_events),
                "gaps": timeline_gaps,
            },
        }

        return ok(
            self.name,
            target,
            findings,
            fused_risk,
            evidence_mode="fused",
            evidence_count=len(strongest) + len(contradictions) + len(clusters),
        )

    def run(self, indicator: Any = None) -> Dict[str, Any]:
        try:
            payload = self._payload(indicator)
            if not payload:
                return skipped(self.name, "", "threat fusion expects manager payload or valid json input")
            return self._build(payload)
        except Exception as exc:
            return structured_error(self.name, indicator, exc)


if __name__ == "__main__":
    import sys

    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(ThreatAnalyzerAgent().run(arg), indent=2))
