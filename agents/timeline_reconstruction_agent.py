"""Normalize and correlate temporal signals into an investigation timeline."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Tuple

from agents.base_agent import OSINTAgent
from core.entity_utils import DATE_TOKEN_RE, normalize_date_to_iso
from ._pipeline import collect_all_text, iter_findings, unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class TimelineReconstructionAgent(OSINTAgent):
    """Build ISO-normalized chronology from multi-agent outputs."""

    name = "TimelineReconstructionAgent"
    supported_target_types = ("text", "json", "domain", "url", "file")
    consume_all_results = True

    ROLE_BY_FIELD = {
        "analysis_timestamp": "COLLECTION_TIME",
        "collection_time": "COLLECTION_TIME",
        "collected_at": "COLLECTION_TIME",
        "generated_at": "COLLECTION_TIME",
        "publication_time": "PUBLICATION_TIME",
        "published_at": "PUBLICATION_TIME",
        "pubdate": "PUBLICATION_TIME",
        "archive_time": "ARCHIVE_TIME",
        "archive_timestamp": "ARCHIVE_TIME",
        "capture_timestamp": "ARCHIVE_TIME",
        "timestamp": "SOURCE_TIME",
        "source_time": "SOURCE_TIME",
        "first_seen": "OBSERVATION_TIME",
        "last_seen": "OBSERVATION_TIME",
        "observed_at": "OBSERVATION_TIME",
        "created": "DOCUMENT_CREATED",
        "document_created": "DOCUMENT_CREATED",
        "created_ts": "DOCUMENT_CREATED",
        "modified": "DOCUMENT_MODIFIED",
        "document_modified": "DOCUMENT_MODIFIED",
        "modified_ts": "DOCUMENT_MODIFIED",
    }

    @classmethod
    def _role_for(cls, field_path: str, source_agent: str) -> str:
        key = field_path.rsplit(".", 1)[-1].lower()
        lowered_path = field_path.lower()
        if source_agent == "CommonCrawlIngestAgent" and key == "timestamp":
            return "ARCHIVE_TIME"
        for field, role in cls.ROLE_BY_FIELD.items():
            if key == field or lowered_path.endswith(f".{field}"):
                return role
        return "SOURCE_TIME"

    @staticmethod
    def _timezone_offset(raw: str) -> str | None:
        text = raw.strip()
        if text.endswith("Z"):
            return "Z"
        match = re.search(r"([+-]\d{2}:\d{2})$", text)
        return match.group(1) if match else None

    @staticmethod
    def _normalize_timestamp(raw: str) -> str | None:
        normalized = normalize_date_to_iso(raw)
        if normalized is not None:
            return normalized
        if re.fullmatch(r"\d{14}", raw):
            try:
                return datetime.strptime(raw, "%Y%m%d%H%M%S").isoformat()
            except ValueError:
                return None
        try:
            numeric = float(raw)
            if 0 < numeric < 100_000_000_000:
                return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
        except (TypeError, ValueError):
            return None

    @classmethod
    def _timestamp_fields(cls, value: Any, path: str = "") -> Iterable[Tuple[str, str]]:
        if isinstance(value, dict):
            for key, nested in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if isinstance(nested, (str, int, float)):
                    lowered = str(key).lower()
                    if any(
                        token in lowered
                        for token in (
                            "time", "date", "created", "modified", "seen",
                            "published", "generated", "expires", "expiry",
                            "not_before", "not_after",
                        )
                    ):
                        yield child_path, str(nested)
                elif isinstance(nested, (dict, list)):
                    yield from cls._timestamp_fields(nested, child_path)
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                if isinstance(nested, (dict, list)):
                    yield from cls._timestamp_fields(nested, f"{path}[{index}]")

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
        role: str = "SOURCE_TIME",
        timezone_offset: str | None = None,
    ) -> None:
        events.append(
            {
                "event_type": event_type,
                "raw_timestamp": raw_timestamp,
                "original_timestamp": raw_timestamp,
                "normalized_timestamp": normalized_timestamp,
                "timezone_offset": timezone_offset,
                "role": role,
                "source_agent": source_agent,
                "source_reference": source_reference,
                "provenance": {
                    "source_agent": source_agent,
                    "source_reference": source_reference,
                },
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
                for key, raw in self._timestamp_fields(findings):
                    normalized = self._normalize_timestamp(raw)
                    self._add_event(
                        events,
                        event_type=key,
                        raw_timestamp=raw,
                        normalized_timestamp=normalized,
                        source_agent=agent_name,
                        source_reference=key,
                        observed=True,
                        role=self._role_for(key, agent_name),
                        timezone_offset=self._timezone_offset(raw),
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
                    role="DERIVED_EVENT",
                    timezone_offset=self._timezone_offset(raw),
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
