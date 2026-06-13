"""Deterministic entity resolution across agent outputs."""

from __future__ import annotations

from hashlib import sha1
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.entity_utils import EMAIL_RE, URL_RE, normalize_phone
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import is_ip, ok, skipped, structured_error


def _entity_key(entity_type: str, value: str) -> str:
    raw = f"{entity_type}|{value.strip().lower()}"
    return "ent_" + sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


class EntityResolutionAgent(OSINTAgent):
    """Merge duplicate entities with deterministic, evidence-weighted rules."""

    name = "EntityResolutionAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def _extract_candidate_values(self, findings: Dict[str, Any]) -> List[str]:
        values: List[str] = []
        direct_keys = [
            "emails",
            "phones",
            "urls",
            "domains",
            "ips",
            "handles",
            "pivot_domains",
            "related_host_candidates",
            "discovered_urls",
            "live_lookalikes",
            "subject_alt_names",
        ]
        for key in direct_keys:
            raw = findings.get(key)
            if isinstance(raw, str):
                values.append(raw)
            elif isinstance(raw, list):
                values.extend(str(item) for item in raw if isinstance(item, str))

        structured_contacts = findings.get("structured_contacts")
        if isinstance(structured_contacts, list):
            for item in structured_contacts:
                if isinstance(item, dict) and isinstance(item.get("value"), str):
                    values.append(item["value"])

        profiles = findings.get("profiles")
        if isinstance(profiles, list):
            for item in profiles:
                if isinstance(item, dict):
                    for field in ("url", "final_url"):
                        value = item.get(field)
                        if isinstance(value, str) and value.strip():
                            values.append(value)

        related_assets = findings.get("related_assets")
        if isinstance(related_assets, list):
            for item in related_assets:
                if isinstance(item, dict):
                    host = item.get("host")
                    if isinstance(host, str) and host.strip():
                        values.append(host)
                    ips = item.get("ips")
                    if isinstance(ips, list):
                        values.extend(str(ip) for ip in ips if isinstance(ip, str))

        subdomain_hits = findings.get("subdomain_hits")
        if isinstance(subdomain_hits, list):
            for item in subdomain_hits:
                if isinstance(item, dict):
                    host = item.get("host")
                    if isinstance(host, str) and host.strip():
                        values.append(host)

        base_records = findings.get("base_records")
        if isinstance(base_records, dict):
            a_aaaa = base_records.get("A_AAAA")
            if isinstance(a_aaaa, dict):
                for ip in a_aaaa.get("A", []):
                    if isinstance(ip, str):
                        values.append(ip)
                for ip in a_aaaa.get("AAAA", []):
                    if isinstance(ip, str):
                        values.append(ip)

        return values

    def _classify_value(self, value: str) -> tuple[str, str] | None:
        val = value.strip()
        lower = val.lower()
        if not val:
            return None
        if EMAIL_RE.fullmatch(val):
            return "email", lower
        if lower.startswith("http://") or lower.startswith("https://"):
            return "url", lower
        if is_ip(val):
            return "ip", val
        if "." in lower and " " not in lower and "/" not in lower and "@" not in lower:
            return "domain", lower
        if val.startswith("+") and len(val) >= 8:
            return "phone", normalize_phone(val)
        if val.startswith("@") and len(val) >= 3:
            return "handle", lower
        if len(val) >= 26 and val.startswith(("1", "3", "bc1", "0x")):
            return "wallet", val
        if "/" in val and " " not in val and len(val.split("/")) == 2:
            return "repo", lower
        return None

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior results to resolve")

        try:
            entity_map: Dict[str, Dict[str, Any]] = {}
            merge_candidates: List[Dict[str, Any]] = []

            for agent_name, entry in sorted(agent_results.items()):
                result = entry.get("result") if isinstance(entry, dict) else entry
                if not isinstance(result, dict):
                    continue
                if str(result.get("status", "")).lower() != "ok":
                    continue

                findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
                if not findings:
                    continue
                reason = str(result.get("reason") or "").lower()
                mode = str(result.get("evidence_mode", "none")).lower()
                evidence_count = int(result.get("evidence_count", 0) or 0)
                hypothesis_only = bool(findings.get("email_hypothesis_only"))
                if mode in {"none", "scaffold"}:
                    continue
                if evidence_count <= 0 and (hypothesis_only or "generated addresses" in reason):
                    continue
                if evidence_count <= 0 and "lookalike" in reason and int(findings.get("live_lookalike_count", 0) or 0) == 0:
                    continue

                values = self._extract_candidate_values(findings)

                for val in values:
                    classified = self._classify_value(val)
                    if not classified:
                        continue
                    entity_type, normalized = classified
                    entity_id = _entity_key(entity_type, normalized)

                    current = entity_map.get(entity_id)
                    if current is None:
                        entity_map[entity_id] = {
                            "entity_id": entity_id,
                            "entity_type": entity_type,
                            "canonical_name": normalized,
                            "aliases": [val],
                            "attributes": {"first_seen_agent": agent_name},
                            "source_evidence_ids": [],
                            "confidence": 0.65,
                            "supporting_evidence": [f"{agent_name}:{val}"],
                        }
                    else:
                        current["aliases"].append(val)
                        current["supporting_evidence"].append(f"{agent_name}:{val}")
                        current["confidence"] = min(0.95, float(current["confidence"]) + 0.05)
                        merge_candidates.append(
                            {
                                "entity_id": entity_id,
                                "normalized_value": normalized,
                                "sources": unique_sorted(current["supporting_evidence"]),
                            }
                        )

            resolved_entities = []
            confidence_scores = {}
            supporting_evidence = {}
            for entity_id, payload in sorted(entity_map.items()):
                payload["aliases"] = unique_sorted(payload["aliases"])
                payload["supporting_evidence"] = unique_sorted(payload["supporting_evidence"])
                resolved_entities.append(payload)
                confidence_scores[entity_id] = round(float(payload.get("confidence", 0.0)), 4)
                supporting_evidence[entity_id] = payload["supporting_evidence"]

            if not resolved_entities:
                return skipped(self.name, target, "no mergeable entities found")

            findings = {
                "resolved_entities": resolved_entities,
                "merge_candidates": merge_candidates,
                "confidence_scores": confidence_scores,
                "supporting_evidence": supporting_evidence,
            }
            return ok(
                self.name,
                target,
                findings,
                min(0.05 + len(resolved_entities) * 0.01, 0.65),
                evidence_mode="derived",
                evidence_count=len(resolved_entities),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
