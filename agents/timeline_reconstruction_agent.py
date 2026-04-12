"""Normalize and correlate temporal signals into an investigation timeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.entity_utils import DATE_TOKEN_RE, normalize_date_to_iso
from ._pipeline import collect_all_text, iter_findings, unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class TimelineReconstructionAgent(OSINTAgent):
    """Build ISO-normalized chronology from multi-agent outputs."""

    name = "TimelineReconstructionAgent"
    supported_target_types = ("text", "json", "domain", "url", "file")
    consume_all_results = True

    def _add_event(
        self,
        events: List[Dict[str, Any]],
        *,
        event_type: str,
        raw_timestamp: str,
        normalized_timestamp: str | None,
        source_agent: str,
        source_reference: str | None = None,
        observed: bool = True,
    ) -> None:
        events.append(
            {
                "event_type": event_type,
                "raw_timestamp": raw_timestamp,
                "normalized_timestamp": normalized_timestamp,
                "source_agent": source_agent,
                "source_reference": source_reference,
                "observed": observed,
            }
        )

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior results for timeline")

        try:
            events: List[Dict[str, Any]] = []
            for agent_name, findings in iter_findings(agent_results):
                for key in ["created_ts", "modified_ts", "not_before", "not_after", "expires_at_utc", "generated_at", "created_at_utc"]:
                    value = findings.get(key)
                    if value is None:
                        continue
                    raw = str(value)
                    normalized = normalize_date_to_iso(raw)
                    if normalized is None:
                        try:
                            normalized = datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
                        except Exception:
                            normalized = None
                    self._add_event(
                        events,
                        event_type=key,
                        raw_timestamp=raw,
                        normalized_timestamp=normalized,
                        source_agent=agent_name,
                        source_reference=key,
                        observed=True,
                    )

            corpus = "\n".join(collect_all_text(agent_results))
            for match in DATE_TOKEN_RE.finditer(corpus):
                raw = match.group(0)
                normalized = normalize_date_to_iso(raw)
                self._add_event(
                    events,
                    event_type="text_date_token",
                    raw_timestamp=raw,
                    normalized_timestamp=normalized,
                    source_agent="text_corpus",
                    source_reference="regex_date_token",
                    observed=False,
                )

            normalized_events = [item for item in events if item.get("normalized_timestamp")]
            normalized_events.sort(key=lambda item: str(item.get("normalized_timestamp")))
            timeline = normalized_events

            earliest = timeline[0] if timeline else None
            latest = timeline[-1] if timeline else None

            clusters: Dict[str, int] = {}
            for item in timeline:
                key = str(item.get("normalized_timestamp", ""))[:10]
                if key:
                    clusters[key] = clusters.get(key, 0) + 1

            missing_gaps: List[str] = []
            dates = sorted(clusters)
            for idx in range(len(dates) - 1):
                if dates[idx][:4].isdigit() and dates[idx + 1][:4].isdigit():
                    year_gap = int(dates[idx + 1][:4]) - int(dates[idx][:4])
                    if year_gap >= 2:
                        missing_gaps.append(f"{dates[idx]} -> {dates[idx + 1]} ({year_gap}y gap)")

            findings = {
                "normalized_events": normalized_events,
                "timeline": timeline,
                "earliest_event": earliest,
                "latest_event": latest,
                "event_clusters": [{"date": key, "count": value} for key, value in sorted(clusters.items())],
                "missing_time_gaps": missing_gaps,
            }

            if not timeline:
                return skipped(self.name, target, "no timeline-normalizable events found", findings=findings)

            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(timeline) * 0.005, 0.55),
                evidence_mode="derived",
                evidence_count=len(timeline),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
