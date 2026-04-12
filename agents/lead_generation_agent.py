"""Generate prioritized investigative leads from collected findings."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class LeadGenerationAgent(OSINTAgent):
    """Turn results into concrete ranked pivot actions."""

    name = "LeadGenerationAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no upstream results for lead generation")

        try:
            leads: List[Dict[str, Any]] = []

            archive = agent_results.get("ArchiveFileDiscoveryAgent", {}).get("result", {}).get("findings", {})
            for item in archive.get("reachable_sensitive_files", []) if isinstance(archive, dict) else []:
                leads.append(
                    {
                        "priority": 1,
                        "title": f"Inspect reachable sensitive file: {item.get('url', '')}",
                        "rationale": "Potential direct data exposure from reachable sensitive path.",
                        "required_inputs": [item.get("url", "")],
                        "recommended_pivots": ["DocumentIngestAgent", "MetadataExtractionAgent"],
                    }
                )

            contradictions = agent_results.get("ContradictionDetectionAgent", {}).get("result", {}).get("findings", {})
            for item in contradictions.get("contradictions", []) if isinstance(contradictions, dict) else []:
                leads.append(
                    {
                        "priority": 2,
                        "title": "Resolve contradiction across sources",
                        "rationale": item.get("message", "Cross-source conflict requires validation."),
                        "required_inputs": item.get("sources", []),
                        "recommended_pivots": ["WhoisAgent", "SSLCertAnalysisAgent", "HistoricalDNSAgent"],
                    }
                )

            infra = agent_results.get("InfrastructureClusterAgent", {}).get("result", {}).get("findings", {})
            for cluster in infra.get("clusters", []) if isinstance(infra, dict) else []:
                leads.append(
                    {
                        "priority": 3,
                        "title": f"Pivot infrastructure cluster: {cluster.get('cluster_id', '')}",
                        "rationale": "Shared indicators suggest same-operator infrastructure candidates.",
                        "required_inputs": cluster.get("members", []),
                        "recommended_pivots": ["HostFingerprintAgent", "CertificatePivotAgent", "ServiceBannerAgent"],
                    }
                )

            timeline = agent_results.get("TimelineReconstructionAgent", {}).get("result", {}).get("findings", {})
            for gap in timeline.get("missing_time_gaps", []) if isinstance(timeline, dict) else []:
                leads.append(
                    {
                        "priority": 4,
                        "title": "Fill timeline gap",
                        "rationale": f"Gap detected: {gap}",
                        "required_inputs": [gap],
                        "recommended_pivots": ["HistoricalDNSAgent", "SearchEngineDiscoveryAgent", "DocumentIngestAgent"],
                    }
                )

            if not leads:
                return skipped(self.name, target, "no actionable leads generated")

            deduped = {}
            for lead in leads:
                key = f"{lead.get('title')}|{lead.get('rationale')}"
                if key not in deduped or int(lead.get("priority", 999)) < int(deduped[key].get("priority", 999)):
                    deduped[key] = lead

            prioritized = sorted(deduped.values(), key=lambda item: int(item.get("priority", 999)))
            findings = {
                "prioritized_leads": prioritized,
                "recommended_pivots": sorted({pivot for lead in prioritized for pivot in lead.get("recommended_pivots", [])}),
                "rationale": [lead.get("rationale") for lead in prioritized],
                "required_inputs": [lead.get("required_inputs", []) for lead in prioritized],
            }
            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(prioritized) * 0.04, 0.75),
                evidence_mode="derived",
                evidence_count=len(prioritized),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
