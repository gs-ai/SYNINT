"""Compare current DNS findings against optional local historical snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class HistoricalDNSAgent(OSINTAgent):
    """Optional historical DNS diffing using locally supplied snapshot data."""

    name = "HistoricalDNSAgent"
    supported_target_types = ("domain", "url", "json", "text", "file")
    consume_all_results = True

    def _load_historical_records(self, context: Dict[str, Any]) -> Dict[str, Any]:
        for path in context.get("collected_files", []) if isinstance(context, dict) else []:
            candidate = Path(str(path))
            if not candidate.exists() or not candidate.is_file() or candidate.suffix.lower() != ".json":
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            if isinstance(data, dict) and "historical_dns" in data:
                return data.get("historical_dns", {}) if isinstance(data.get("historical_dns"), dict) else {}
            if isinstance(data, dict) and "records" in data and "domain" in data:
                return data
        return {}

    def run(self, indicator: Any):
        target, context, agent_results = unpack_pipeline_input(indicator)
        try:
            dns_findings = agent_results.get("DNSEnumAgent", {}).get("result", {}).get("findings", {})
            current_records = dns_findings.get("base_records", {}) if isinstance(dns_findings, dict) else {}
            if not current_records:
                return skipped(self.name, target, "current DNS records unavailable")

            historical = self._load_historical_records(context)
            historical_records = historical.get("records", {}) if isinstance(historical, dict) else {}

            changes: List[Dict[str, Any]] = []
            nameserver_changes: List[Dict[str, Any]] = []
            hosting_changes: List[Dict[str, Any]] = []
            added_hosts: List[str] = []
            removed_hosts: List[str] = []

            for rtype, current in current_records.items():
                current_set = set(current if isinstance(current, list) else [])
                hist_set = set(historical_records.get(rtype, []) if isinstance(historical_records, dict) else [])
                added = sorted(current_set - hist_set)
                removed = sorted(hist_set - current_set)
                if added or removed:
                    changes.append({"record_type": rtype, "added": added, "removed": removed})
                if rtype == "NS" and (added or removed):
                    nameserver_changes.append({"added": added, "removed": removed})
                if rtype in {"A_AAAA", "A", "AAAA"} and (added or removed):
                    hosting_changes.append({"record_type": rtype, "added": added, "removed": removed})
                added_hosts.extend(added)
                removed_hosts.extend(removed)

            findings = {
                "current_records": current_records,
                "historical_records": historical_records,
                "changes": changes,
                "nameserver_changes": nameserver_changes,
                "hosting_changes": hosting_changes,
                "added_hosts": sorted(set(added_hosts)),
                "removed_hosts": sorted(set(removed_hosts)),
            }

            if not historical_records:
                return ok(
                    self.name,
                    target,
                    findings,
                    0.02,
                    evidence_mode="derived",
                    evidence_count=len(changes),
                    reason="historical snapshot not provided; returned current-only view",
                )

            risk = min(0.03 + len(changes) * 0.04, 0.65)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="derived",
                evidence_count=len(changes),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
