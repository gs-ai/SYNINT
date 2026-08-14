"""Export layer for SYNINT v5 investigation artifacts."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from synint_version import SYNINT_RELEASE, SYNINT_VERSION


def _safe_json_dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _build_markdown_report(
    *,
    context: Dict[str, Any],
    summary: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    entities: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    graph: Dict[str, Any],
    leads: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    agent_results: Dict[str, Any],
) -> str:
    lines: List[str] = []

    lines.append(f"# {SYNINT_RELEASE} INVESTIGATION REPORT")
    lines.append(f"- Product Version: `{SYNINT_VERSION}`")
    lines.append("")

    lines.append("# CASE / TARGET OVERVIEW")
    lines.append(f"- Target: `{context.get('original_target', '')}`")
    lines.append(f"- Normalized Target: `{context.get('normalized_target', '')}`")
    lines.append(f"- Collection Mode: `{context.get('collection_mode', 'standard')}`")
    lines.append("")

    lines.append("# EXECUTIVE SUMMARY")
    lines.append(f"- Agents Executed: {summary.get('agent_count', 0)}")
    lines.append(f"- Evidence Items: {summary.get('evidence_count', 0)}")
    lines.append(f"- Resolved Entities: {summary.get('entity_count', 0)}")
    lines.append(f"- Timeline Events: {summary.get('timeline_count', 0)}")
    lines.append(f"- Leads Generated: {summary.get('lead_count', 0)}")
    lines.append("")

    lines.append("# KEY FINDINGS")
    lines.append("| Finding | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total Evidence | {summary.get('evidence_count', 0)} |")
    lines.append(f"| High Confidence Evidence (>=0.8) | {sum(1 for ev in evidence if float(ev.get('confidence', 0.0)) >= 0.8)} |")
    lines.append(f"| Contradictions | {len(contradictions)} |")
    lines.append("")

    lines.append("# EVIDENCE REGISTER SUMMARY")
    lines.append("| ID | TYPE | SOURCE | TIER | CONFIDENCE |")
    lines.append("|---|---|---|---|---|")
    for ev in evidence[:20]:
        lines.append(
            f"| {ev.get('id','')} | {ev.get('evidence_type','')} | {ev.get('source_agent','')} | {ev.get('evidence_tier','')} | {ev.get('confidence',0):.2f} |"
        )
    if len(evidence) > 20:
        lines.append(f"- ... {len(evidence) - 20} more evidence items in `evidence_register.csv`.")
    lines.append("")

    lines.append("# ENTITY SUMMARY")
    lines.append("| ENTITY ID | TYPE | CANONICAL NAME | CONFIDENCE |")
    lines.append("|---|---|---|---|")
    for entity in entities[:20]:
        lines.append(
            f"| {entity.get('entity_id','')} | {entity.get('entity_type','')} | {entity.get('canonical_name','')} | {float(entity.get('confidence', 0.0)):.2f} |"
        )
    lines.append("")

    lines.append("# INFRASTRUCTURE SUMMARY")
    lines.append(f"- Graph Nodes: {len(graph.get('nodes', []))}")
    lines.append(f"- Graph Edges: {len(graph.get('edges', []))}")
    lines.append("")

    lines.append("# TIMELINE SUMMARY")
    lines.append("| EVENT TYPE | RAW TIMESTAMP | NORMALIZED TIMESTAMP | SOURCE |")
    lines.append("|---|---|---|---|")
    for event in timeline[:20]:
        lines.append(
            f"| {event.get('event_type','')} | {event.get('raw_timestamp','')} | {event.get('normalized_timestamp','')} | {event.get('source_agent','')} |"
        )
    lines.append("")

    lines.append("# CONTRADICTIONS / GAPS")
    if contradictions:
        for item in contradictions[:20]:
            lines.append(f"- {item.get('message', 'unspecified contradiction')} (sources: {', '.join(item.get('sources', []))})")
    else:
        lines.append("- No explicit contradictions detected.")
    lines.append("")

    lines.append("# PRIORITIZED LEADS")
    lines.append("| PRIORITY | LEAD | RATIONALE |")
    lines.append("|---|---|---|")
    for lead in sorted(leads, key=lambda item: int(item.get("priority", 999)))[:20]:
        lines.append(
            f"| {lead.get('priority', '')} | {lead.get('title', '')} | {lead.get('rationale', '')} |"
        )
    lines.append("")

    lines.append("# AGENT EXECUTION SUMMARY")
    lines.append("| AGENT | STATUS | RISK | EVIDENCE MODE | EVIDENCE COUNT |")
    lines.append("|---|---|---|---|---|")
    for agent_name in sorted(agent_results):
        entry = agent_results[agent_name]
        result = entry.get("result", {}) if isinstance(entry, dict) else {}
        lines.append(
            "| {agent} | {status} | {risk:.2f} | {mode} | {count} |".format(
                agent=agent_name,
                status=result.get("status", "unknown"),
                risk=float(result.get("risk_score", 0.0) or 0.0),
                mode=result.get("evidence_mode", "none"),
                count=result.get("evidence_count", 0),
            )
        )
    lines.append("")

    lines.append("# APPENDIX")
    lines.append("- Export files: `summary.json`, `evidence_register.csv`, `timeline.json`, `entities.json`, `graph.json`, `leads.json`, `report.md`.")
    if context.get("run_id"):
        lines.append(f"- Run ID: `{context.get('run_id')}`")
    if context.get("forensic_ledger_path"):
        lines.append(f"- Chain-of-custody ledger: `{context.get('forensic_ledger_path')}`")
    if context.get("checkpoint_path"):
        lines.append(f"- Checkpoint: `{context.get('checkpoint_path')}`")
    if context.get("investigation_db_path"):
        lines.append(f"- Investigation DB: `{context.get('investigation_db_path')}`")
    lines.append(f"- Generated UTC: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    return "\n".join(lines)


def write_export_bundle(
    *,
    base_output_dir: Path,
    context: Dict[str, Any],
    summary: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    entities: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    graph: Dict[str, Any],
    leads: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    agent_results: Dict[str, Any],
) -> Dict[str, str]:
    """Write structured investigation exports to disk."""
    output_dir = base_output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_path = output_dir / "summary.json"
    evidence_csv_path = output_dir / "evidence_register.csv"
    timeline_path = output_dir / "timeline.json"
    entities_path = output_dir / "entities.json"
    graph_path = output_dir / "graph.json"
    leads_path = output_dir / "leads.json"
    report_md_path = output_dir / "report.md"

    _safe_json_dump(summary_path, summary)
    _safe_json_dump(timeline_path, timeline)
    _safe_json_dump(entities_path, entities)
    _safe_json_dump(graph_path, graph)
    _safe_json_dump(leads_path, leads)

    with evidence_csv_path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "id",
            "source_agent",
            "evidence_type",
            "value",
            "normalized_value",
            "confidence",
            "severity",
            "evidence_tier",
            "timestamp",
            "source_reference",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in evidence:
            writer.writerow({key: row.get(key) for key in fieldnames})

    markdown = _build_markdown_report(
        context=context,
        summary=summary,
        evidence=evidence,
        entities=entities,
        timeline=timeline,
        graph=graph,
        leads=leads,
        contradictions=contradictions,
        agent_results=agent_results,
    )
    report_md_path.write_text(markdown + "\n", encoding="utf-8")

    return {
        "output_dir": str(output_dir),
        "summary_json": str(summary_path),
        "evidence_register_csv": str(evidence_csv_path),
        "timeline_json": str(timeline_path),
        "entities_json": str(entities_path),
        "graph_json": str(graph_path),
        "leads_json": str(leads_path),
        "report_md": str(report_md_path),
    }
