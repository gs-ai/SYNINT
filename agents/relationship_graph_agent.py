"""Build graph-ready relationship edges from resolved entities and findings."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import iter_findings, unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class RelationshipGraphAgent(OSINTAgent):
    """Produce stable graph nodes/edges with evidence references."""

    name = "RelationshipGraphAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior results for relationship graph")

        try:
            entity_payload = agent_results.get("EntityResolutionAgent", {}).get("result", {}).get("findings", {})
            resolved = entity_payload.get("resolved_entities", []) if isinstance(entity_payload, dict) else []
            if not resolved and isinstance(indicator, dict):
                entity_registry = indicator.get("entity_registry")
                if isinstance(entity_registry, list):
                    resolved = [item for item in entity_registry if isinstance(item, dict)]
            if not resolved:
                return skipped(self.name, target, "resolved entities unavailable")

            nodes = [
                {
                    "id": item.get("entity_id"),
                    "label": item.get("canonical_name"),
                    "entity_type": item.get("entity_type"),
                    "confidence": item.get("confidence", 0.0),
                }
                for item in resolved
                if isinstance(item, dict)
            ]

            by_value = {str(node.get("label", "")).lower(): str(node.get("id", "")) for node in nodes}
            edges: List[Dict[str, Any]] = []

            for agent_name, findings in iter_findings(agent_results):
                values: List[str] = []
                for val in findings.values():
                    if isinstance(val, str):
                        values.append(val)
                    elif isinstance(val, list):
                        values.extend(str(item) for item in val if isinstance(item, str))

                matched_nodes = [by_value[v.lower()] for v in values if v.lower() in by_value]
                matched_nodes = unique_sorted(matched_nodes)
                for idx, source in enumerate(matched_nodes):
                    for target_node in matched_nodes[idx + 1 :]:
                        edge_id = f"{source}->{target_node}:{agent_name}"
                        edges.append(
                            {
                                "id": edge_id,
                                "source": source,
                                "target": target_node,
                                "edge_type": "co_observed",
                                "weight": 0.6,
                                "source_agent": agent_name,
                                "source_evidence": [f"{agent_name}:findings"],
                            }
                        )

            # deterministic dedupe
            edge_map: Dict[str, Dict[str, Any]] = {}
            for edge in edges:
                key = f"{edge['source']}|{edge['target']}|{edge['source_agent']}"
                edge_map[key] = edge

            deduped_edges = list(edge_map.values())
            findings = {
                "nodes": nodes,
                "edges": deduped_edges,
                "edge_types": unique_sorted(edge.get("edge_type", "") for edge in deduped_edges),
                "edge_weights": {edge.get("id"): edge.get("weight", 0.0) for edge in deduped_edges},
                "graph_summary": {
                    "node_count": len(nodes),
                    "edge_count": len(deduped_edges),
                },
            }

            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(deduped_edges) * 0.01, 0.6),
                evidence_mode="derived",
                evidence_count=len(deduped_edges),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
