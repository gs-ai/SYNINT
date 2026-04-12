"""Cross-agent contradiction detection with source citations."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import iter_findings, unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class ContradictionDetectionAgent(OSINTAgent):
    """Detect conflicts across ownership/location/hostname/timeline related findings."""

    name = "ContradictionDetectionAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no results available for contradiction analysis")

        try:
            contradictions: List[Dict[str, Any]] = []
            source_comparisons: List[Dict[str, Any]] = []

            registrar_values: Dict[str, List[str]] = {}
            cert_hosts: Dict[str, List[str]] = {}
            location_values: Dict[str, List[str]] = {}

            for agent_name, findings in iter_findings(agent_results):
                registrar = findings.get("registrar")
                if registrar:
                    registrar_values.setdefault(str(registrar).strip().lower(), []).append(agent_name)

                host = findings.get("host")
                if host:
                    cert_hosts.setdefault(str(host).strip().lower(), []).append(agent_name)

                for key in ["locations", "location", "country", "region"]:
                    value = findings.get(key)
                    if isinstance(value, list):
                        for item in value:
                            location_values.setdefault(str(item).strip().lower(), []).append(agent_name)
                    elif isinstance(value, str) and value.strip():
                        location_values.setdefault(value.strip().lower(), []).append(agent_name)

            if len(registrar_values) > 1:
                contradictions.append(
                    {
                        "message": "Conflicting registrar values detected across sources.",
                        "sources": sorted({agent for agents in registrar_values.values() for agent in agents}),
                        "details": registrar_values,
                    }
                )

            if len(cert_hosts) > 1:
                contradictions.append(
                    {
                        "message": "Hostname mismatch observed across certificate/domain findings.",
                        "sources": sorted({agent for agents in cert_hosts.values() for agent in agents}),
                        "details": cert_hosts,
                    }
                )

            if len(location_values) > 2:
                contradictions.append(
                    {
                        "message": "Multiple conflicting location indicators detected.",
                        "sources": sorted({agent for agents in location_values.values() for agent in agents}),
                        "details": location_values,
                    }
                )

            source_comparisons.append({"registrar_values": registrar_values, "cert_hosts": cert_hosts, "location_values": location_values})

            findings = {
                "contradictions": contradictions,
                "conflict_groups": [{"group": idx + 1, "message": item["message"]} for idx, item in enumerate(contradictions)],
                "source_comparisons": source_comparisons,
                "significance": "high" if contradictions else "low",
            }

            if not contradictions:
                return skipped(self.name, target, "no significant contradictions detected", findings=findings)

            return ok(
                self.name,
                target,
                findings,
                min(0.05 + len(contradictions) * 0.1, 0.8),
                evidence_mode="derived",
                evidence_count=len(contradictions),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
