"""Build provenance-backed relationship graph analytics from SYNINT entities."""

from __future__ import annotations

from hashlib import sha1
from itertools import combinations
from typing import Any, Dict, Iterable, List, Tuple

import networkx as nx

from agents.base_agent import OSINTAgent
from ._pipeline import iter_findings, unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class RelationshipGraphAgent(OSINTAgent):
    """Produce stable graph nodes/edges with evidence references."""

    name = "RelationshipGraphAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True
    MAX_ENTITIES_PER_OBSERVATION = 50
    CO_OCCURRENCE_CONTAINER_KEYS = {
        "detected_entities",
        "entities",
        "entity_observation",
        "observation",
        "record",
    }

    @staticmethod
    def _observation_id(agent_name: str, reference: str, values: Iterable[str]) -> str:
        payload = f"{agent_name}|{reference}|{'|'.join(sorted(values))}"
        return "obs_" + sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]

    @classmethod
    def _observation_groups(cls, value: Any, path: str = "findings") -> Iterable[Tuple[str, List[str]]]:
        """Yield logical records instead of treating an entire agent result as co-occurring."""
        if isinstance(value, dict):
            direct: List[str] = []
            for key, nested in value.items():
                child_path = f"{path}.{key}"
                if isinstance(nested, str) and nested.strip():
                    direct.append(nested.strip())
                elif isinstance(nested, list) and all(isinstance(item, str) for item in nested):
                    direct.extend(item.strip() for item in nested if item.strip())
                elif isinstance(nested, (dict, list)):
                    yield from cls._observation_groups(nested, child_path)
            container_key = path.rsplit(".", 1)[-1].lower()
            is_logical_record = "[" in path or container_key in cls.CO_OCCURRENCE_CONTAINER_KEYS
            if direct and is_logical_record:
                yield path, direct
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, (dict, list)):
                    yield from cls._observation_groups(item, f"{path}[{index}]")

    @staticmethod
    def _analytics(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        graph = nx.Graph()
        graph.add_nodes_from((str(node["id"]), node) for node in nodes if node.get("id"))
        graph.add_edges_from(
            (str(edge["source"]), str(edge["target"]), {"edge_type": edge["edge_type"]})
            for edge in edges
        )
        degree = nx.degree_centrality(graph) if graph.number_of_nodes() > 1 else {
            node: 0.0 for node in graph.nodes
        }
        components = sorted(
            (sorted(component) for component in nx.connected_components(graph)),
            key=lambda component: (-len(component), component),
        )
        central_nodes = sorted(
            (
                {
                    "entity_id": node,
                    "degree": int(graph.degree(node)),
                    "degree_centrality": round(float(degree.get(node, 0.0)), 6),
                }
                for node in graph.nodes
            ),
            key=lambda item: (-item["degree"], item["entity_id"]),
        )
        return {
            "density": round(float(nx.density(graph)), 6) if graph.number_of_nodes() > 1 else 0.0,
            "connected_components": components,
            "component_count": len(components),
            "isolates": sorted(nx.isolates(graph)),
            "central_nodes": central_nodes,
        }

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
                    "aliases": item.get("aliases", []),
                    "source_evidence_ids": item.get("source_evidence_ids", []),
                }
                for item in resolved
                if isinstance(item, dict)
            ]

            by_value: Dict[str, str] = {}
            for node in nodes:
                entity_id = str(node.get("id", ""))
                for value in [node.get("label"), *(node.get("aliases") or [])]:
                    if value:
                        by_value[str(value).strip().lower()] = entity_id

            edge_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
            truncated_groups = 0
            for agent_name, findings in iter_findings(agent_results):
                entry = agent_results.get(agent_name, {})
                result = entry.get("result", {}) if isinstance(entry, dict) else {}
                timestamp = result.get("timestamp") if isinstance(result, dict) else None
                for reference, values in self._observation_groups(findings):
                    matched_nodes = unique_sorted(
                        by_value[value.strip().lower()]
                        for value in values
                        if value.strip().lower() in by_value
                    )
                    if len(matched_nodes) > self.MAX_ENTITIES_PER_OBSERVATION:
                        matched_nodes = matched_nodes[: self.MAX_ENTITIES_PER_OBSERVATION]
                        truncated_groups += 1
                    if len(matched_nodes) < 2:
                        continue
                    observation_id = self._observation_id(agent_name, reference, matched_nodes)
                    provenance = {
                        "source_agent": agent_name,
                        "source_reference": reference,
                        "observation_id": observation_id,
                        "timestamp": timestamp,
                    }
                    for source, target_node in combinations(matched_nodes, 2):
                        pair = tuple(sorted((source, target_node)))
                        current = edge_map.get(pair)
                        if current is None:
                            edge_id = "edge_" + sha1(
                                f"{pair[0]}|{pair[1]}|CO_OCCURS_WITH".encode("utf-8")
                            ).hexdigest()[:16]
                            current = {
                                "id": edge_id,
                                "source": pair[0],
                                "target": pair[1],
                                "edge_type": "CO_OCCURS_WITH",
                                "relationship_status": "CANDIDATE",
                                "confirmed": False,
                                "weight": 0.0,
                                "source_agent": agent_name,
                                "source_evidence": [],
                                "supporting_observation_ids": [],
                                "provenance": [],
                                "timestamp": timestamp,
                            }
                            edge_map[pair] = current
                        current["supporting_observation_ids"].append(observation_id)
                        current["source_evidence"].append(f"{agent_name}:{reference}")
                        current["provenance"].append(provenance)

            deduped_edges = []
            for edge in edge_map.values():
                edge["supporting_observation_ids"] = unique_sorted(edge["supporting_observation_ids"])
                edge["source_evidence"] = unique_sorted(edge["source_evidence"])
                unique_provenance = {
                    (item["source_agent"], item["source_reference"], item["observation_id"]): item
                    for item in edge["provenance"]
                }
                edge["provenance"] = [unique_provenance[key] for key in sorted(unique_provenance)]
                edge["weight"] = round(min(len(edge["supporting_observation_ids"]) / 5.0, 1.0), 4)
                deduped_edges.append(edge)
            deduped_edges.sort(key=lambda edge: edge["id"])
            findings = {
                "nodes": nodes,
                "edges": deduped_edges,
                "edge_types": unique_sorted(edge.get("edge_type", "") for edge in deduped_edges),
                "edge_weights": {edge.get("id"): edge.get("weight", 0.0) for edge in deduped_edges},
                "graph_summary": {
                    "node_count": len(nodes),
                    "edge_count": len(deduped_edges),
                    "truncated_observation_groups": truncated_groups,
                },
                "analytics": self._analytics(nodes, deduped_edges),
                "semantics": {
                    "co_occurrence_is_confirmation": False,
                    "confirmed_relationship_count": 0,
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
