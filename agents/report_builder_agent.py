"""Polished report/export generation agent for SYNINT investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, List
import re

from agents.base_agent import OSINTAgent
from core.exporter import write_export_bundle
from synint_paths import INVESTIGATIONS_DIR
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class ReportBuilderAgent(OSINTAgent):
    """Create summary.json, evidence register CSV, graph/timeline/lead JSON, and report.md."""

    name = "ReportBuilderAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    @staticmethod
    def _entity_key(payload: Dict[str, Any]) -> str:
        entity_id = str(payload.get("entity_id", "")).strip()
        if entity_id:
            return entity_id
        canonical = str(payload.get("canonical_name", "")).strip().lower()
        entity_type = str(payload.get("entity_type", "unknown")).strip().lower()
        digest = sha1(f"{entity_type}|{canonical}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"ent_{digest}"

    def _merge_entities(self, entity_registry: List[Dict[str, Any]], resolved_entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for raw in list(entity_registry) + list(resolved_entities):
            if not isinstance(raw, dict):
                continue
            key = self._entity_key(raw)
            current = merged.get(key)
            aliases = [str(v) for v in raw.get("aliases", []) if str(v).strip()] if isinstance(raw.get("aliases"), list) else []
            evidence_ids = (
                [str(v) for v in raw.get("source_evidence_ids", []) if str(v).strip()]
                if isinstance(raw.get("source_evidence_ids"), list)
                else []
            )
            candidate = {
                "entity_id": key,
                "entity_type": str(raw.get("entity_type", "unknown")),
                "canonical_name": str(raw.get("canonical_name", "")),
                "aliases": sorted(set(aliases)),
                "attributes": raw.get("attributes", {}) if isinstance(raw.get("attributes"), dict) else {},
                "source_evidence_ids": sorted(set(evidence_ids)),
                "confidence": float(raw.get("confidence", 0.5) or 0.5),
            }
            if current is None:
                merged[key] = candidate
                continue
            current["aliases"] = sorted(set(current.get("aliases", [])) | set(candidate["aliases"]))
            current["source_evidence_ids"] = sorted(set(current.get("source_evidence_ids", [])) | set(candidate["source_evidence_ids"]))
            attrs = current.get("attributes", {}) if isinstance(current.get("attributes"), dict) else {}
            attrs.update(candidate["attributes"])
            current["attributes"] = attrs
            current["confidence"] = max(float(current.get("confidence", 0.0) or 0.0), candidate["confidence"])
            if not str(current.get("canonical_name", "")).strip() and candidate["canonical_name"]:
                current["canonical_name"] = candidate["canonical_name"]
            if str(current.get("entity_type", "")).strip().lower() in {"", "unknown"} and candidate["entity_type"]:
                current["entity_type"] = candidate["entity_type"]
        return [merged[key] for key in sorted(merged)]

    def _project_scored_findings(self, scored: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        projected: List[Dict[str, Any]] = []
        for item in scored:
            if not isinstance(item, dict):
                continue
            agent = str(item.get("agent", "unknown")).strip() or "unknown"
            tier = str(item.get("tier", "derived evidence")).strip() or "derived evidence"
            mode = str(item.get("evidence_mode", "derived")).strip() or "derived"
            status = str(item.get("status", "unknown")).strip() or "unknown"
            confidence = float(item.get("confidence", 0.5) or 0.5)
            risk_score = float(item.get("risk_score", 0.0) or 0.0)
            evidence_count = int(item.get("evidence_count", 0) or 0)
            normalized = f"{agent.lower()}:{tier.lower()}:{mode.lower()}:{status.lower()}"
            digest = sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]
            projected.append(
                {
                    "id": f"score_{digest}",
                    "source_agent": agent,
                    "evidence_type": "agent_score",
                    "value": f"{tier}; status={status}; evidence_count={evidence_count}; risk={risk_score:.4f}",
                    "normalized_value": normalized,
                    "confidence": round(confidence, 4),
                    "severity": "high" if confidence >= 0.8 else "medium" if confidence >= 0.5 else "low",
                    "evidence_tier": tier,
                    "timestamp": "",
                    "source_reference": "EvidenceScoringAgent",
                }
            )
        return projected

    def _merge_evidence(self, evidence_registry: List[Dict[str, Any]], scored: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        projected = self._project_scored_findings(scored)
        merged: Dict[str, Dict[str, Any]] = {}
        for raw in list(evidence_registry) + projected:
            if not isinstance(raw, dict):
                continue
            evidence_id = str(raw.get("id", "")).strip()
            if not evidence_id:
                source = str(raw.get("source_agent", "unknown")).strip().lower()
                e_type = str(raw.get("evidence_type", "unknown")).strip().lower()
                normalized = str(raw.get("normalized_value") or raw.get("value") or "").strip().lower()
                evidence_id = f"ev_{sha1(f'{source}|{e_type}|{normalized}'.encode('utf-8', errors='ignore')).hexdigest()[:16]}"
            merged[evidence_id] = {
                "id": evidence_id,
                "source_agent": str(raw.get("source_agent", "")),
                "evidence_type": str(raw.get("evidence_type", "")),
                "value": str(raw.get("value", "")),
                "normalized_value": str(raw.get("normalized_value", "")),
                "confidence": float(raw.get("confidence", 0.0) or 0.0),
                "severity": str(raw.get("severity", "medium")),
                "evidence_tier": str(raw.get("evidence_tier", "derived evidence")),
                "timestamp": str(raw.get("timestamp", "")),
                "source_reference": raw.get("source_reference"),
            }
        return [merged[key] for key in sorted(merged)]

    def _extract_registry_payloads(
        self,
        agent_results: Dict[str, Any],
        evidence_registry: List[Dict[str, Any]],
        entity_registry: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        entity_findings = agent_results.get("EntityResolutionAgent", {}).get("result", {}).get("findings", {})
        graph_findings = agent_results.get("RelationshipGraphAgent", {}).get("result", {}).get("findings", {})
        timeline_findings = agent_results.get("TimelineReconstructionAgent", {}).get("result", {}).get("findings", {})
        lead_findings = agent_results.get("LeadGenerationAgent", {}).get("result", {}).get("findings", {})
        contradiction_findings = agent_results.get("ContradictionDetectionAgent", {}).get("result", {}).get("findings", {})
        evidence_findings = agent_results.get("EvidenceScoringAgent", {}).get("result", {}).get("findings", {})

        resolved_entities = entity_findings.get("resolved_entities", []) if isinstance(entity_findings, dict) else []
        scored = evidence_findings.get("scored_findings", []) if isinstance(evidence_findings, dict) else []
        merged_entities = self._merge_entities(entity_registry, resolved_entities)
        merged_evidence = self._merge_evidence(evidence_registry, scored)
        graph_nodes = graph_findings.get("nodes", []) if isinstance(graph_findings, dict) else []
        if not graph_nodes and merged_entities:
            graph_nodes = [
                {
                    "id": item.get("entity_id"),
                    "label": item.get("canonical_name"),
                    "entity_type": item.get("entity_type"),
                    "confidence": item.get("confidence", 0.0),
                }
                for item in merged_entities
                if isinstance(item, dict)
            ]

        return {
            "entities": merged_entities,
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_findings.get("edges", []) if isinstance(graph_findings, dict) else [],
                "labels": [node.get("entity_type") for node in graph_nodes],
                "weights": [edge.get("weight", 0.0) for edge in graph_findings.get("edges", [])] if isinstance(graph_findings, dict) else [],
            },
            "timeline": timeline_findings.get("timeline", []) if isinstance(timeline_findings, dict) else [],
            "leads": lead_findings.get("prioritized_leads", []) if isinstance(lead_findings, dict) else [],
            "contradictions": contradiction_findings.get("contradictions", []) if isinstance(contradiction_findings, dict) else [],
            "evidence": merged_evidence,
        }

    def run(self, indicator: Any):
        target, context, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior results available for report building")

        try:
            evidence_registry = indicator.get("evidence_registry", []) if isinstance(indicator, dict) else []
            entity_registry = indicator.get("entity_registry", []) if isinstance(indicator, dict) else []
            if not isinstance(evidence_registry, list):
                evidence_registry = []
            if not isinstance(entity_registry, list):
                entity_registry = []

            data = self._extract_registry_payloads(agent_results, evidence_registry, entity_registry)
            reports_dir = str(context.get("reports_dir") or "").strip()
            if reports_dir:
                output_dir = Path(reports_dir)
            else:
                output_root = INVESTIGATIONS_DIR
                case_base = str(context.get("normalized_target") or context.get("original_target") or target or "target")
                case_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", case_base).strip("._")[:80] or "target"
                case_name = str(context.get("case_name") or f"{case_slug}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
                output_dir = output_root / case_name

            summary = {
                "target": target,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "agent_count": len(agent_results) + (0 if self.name in agent_results else 1),
                "evidence_count": len(data["evidence"]),
                "entity_count": len(data["entities"]),
                "timeline_count": len(data["timeline"]),
                "lead_count": len(data["leads"]),
                "contradiction_count": len(data["contradictions"]),
                "collection_mode": context.get("collection_mode", "standard"),
            }

            exported = write_export_bundle(
                base_output_dir=output_dir,
                context={
                    "original_target": context.get("original_target", target),
                    "normalized_target": context.get("normalized_target", target),
                    "collection_mode": context.get("collection_mode", "standard"),
                },
                summary=summary,
                evidence=data["evidence"],
                entities=data["entities"],
                timeline=data["timeline"],
                graph=data["graph"],
                leads=data["leads"],
                contradictions=data["contradictions"],
                agent_results=agent_results,
            )

            findings = {
                "markdown_report": exported.get("report_md"),
                "json_report": exported.get("summary_json"),
                "csv_evidence_register": exported.get("evidence_register_csv"),
                "graph_json": exported.get("graph_json"),
                "exported_files": exported,
            }
            return ok(
                self.name,
                target,
                findings,
                0.02,
                evidence_mode="collected",
                evidence_count=len(exported),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
