"""Shared helpers for pipeline-capable SYNINT agents."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def unpack_pipeline_input(indicator: Any) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """Return target, context, and all prior agent results from a payload or raw input."""
    if isinstance(indicator, dict):
        target = str(indicator.get("target") or indicator.get("original_target") or "").strip()
        context = indicator.get("investigation_context") if isinstance(indicator.get("investigation_context"), dict) else {}
        all_results = indicator.get("agent_results") if isinstance(indicator.get("agent_results"), dict) else {}
        if not target:
            target = str(context.get("normalized_target") or context.get("original_target") or "").strip()
        return target, context, all_results
    target = str(indicator).strip()
    return target, {}, {}


def iter_findings(agent_results: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for agent_name, entry in (agent_results or {}).items():
        result = entry.get("result") if isinstance(entry, dict) else entry
        if isinstance(result, dict):
            findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
            yield str(agent_name), findings


def gather_strings_from_findings(agent_results: Dict[str, Any], keys: Iterable[str]) -> List[str]:
    out: List[str] = []
    key_set = set(keys)
    for _, findings in iter_findings(agent_results):
        for key, value in findings.items():
            if key_set and key not in key_set:
                continue
            if isinstance(value, str):
                text = value.strip()
                if text:
                    out.append(text)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        out.append(item.strip())
    return out


def collect_all_text(agent_results: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for _, findings in iter_findings(agent_results):
        for value in findings.values():
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        out.append(item.strip())
            elif isinstance(value, dict):
                for nested in value.values():
                    if isinstance(nested, str) and nested.strip():
                        out.append(nested.strip())
    return out


def unique_sorted(values: Iterable[str]) -> List[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})
