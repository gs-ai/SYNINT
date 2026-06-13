"""Shared schema objects for SYNINT pipeline outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha1
from typing import Any, Dict, Iterable, List, Literal

AgentStatus = Literal["ok", "skipped", "error"]
EvidenceMode = Literal["collected", "derived", "heuristic", "scaffold", "fused", "active", "passive", "none"]


def _stable_id(prefix: str, payload: str) -> str:
    digest = sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique_strings(values: Iterable[Any], *, lower: bool = False) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if lower:
            text = text.lower()
        if text not in seen:
            seen.add(text)
            out.append(text)
    return sorted(out)


@dataclass
class EvidenceItem:
    source_agent: str
    evidence_type: str
    value: str
    normalized_value: str
    confidence: float = 0.5
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    source_reference: str | None = None
    supporting_context: Dict[str, Any] = field(default_factory=dict)
    timestamp: str | None = None
    evidence_tier: str = "derived"
    id: str = ""

    def __post_init__(self) -> None:
        self.source_agent = str(self.source_agent).strip()
        self.evidence_type = str(self.evidence_type).strip().lower()
        self.value = str(self.value).strip()
        self.normalized_value = str(self.normalized_value or self.value).strip().lower()
        self.confidence = max(0.0, min(float(self.confidence), 1.0))
        self.severity = str(self.severity or "medium").strip().lower() or "medium"
        self.tags = _unique_strings(self.tags)
        self.source_reference = str(self.source_reference).strip() if self.source_reference else None
        if not isinstance(self.supporting_context, dict):
            self.supporting_context = {}
        self.evidence_tier = str(self.evidence_tier or "derived").strip().lower() or "derived"
        if not self.id:
            self.id = _stable_id(
                "ev",
                f"{self.source_agent}|{self.evidence_type}|{self.normalized_value}|{self.source_reference or ''}",
            )
        if not self.timestamp:
            self.timestamp = utc_now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_agent": self.source_agent,
            "evidence_type": self.evidence_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "tags": self.tags,
            "source_reference": self.source_reference,
            "supporting_context": self.supporting_context,
            "timestamp": self.timestamp,
            "evidence_tier": self.evidence_tier,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "EvidenceItem":
        return cls(**payload)

    def merge(self, other: "EvidenceItem") -> "EvidenceItem":
        if self.id != other.id:
            raise ValueError("cannot merge evidence items with different ids")
        merged_context = dict(self.supporting_context)
        for key, value in other.supporting_context.items():
            current = merged_context.get(key)
            if isinstance(current, list) and isinstance(value, list):
                merged_context[key] = _unique_strings([*current, *value])
            elif isinstance(current, dict) and isinstance(value, dict):
                nested = dict(current)
                nested.update(value)
                merged_context[key] = nested
            else:
                merged_context[key] = value
        return EvidenceItem(
            source_agent=self.source_agent or other.source_agent,
            evidence_type=self.evidence_type or other.evidence_type,
            value=self.value if len(self.value) >= len(other.value) else other.value,
            normalized_value=self.normalized_value or other.normalized_value,
            confidence=max(self.confidence, other.confidence),
            severity=self._higher_severity(self.severity, other.severity),
            tags=_unique_strings([*self.tags, *other.tags]),
            source_reference=self.source_reference or other.source_reference,
            supporting_context=merged_context,
            timestamp=min(str(self.timestamp or ""), str(other.timestamp or "")) or (self.timestamp or other.timestamp),
            evidence_tier=self._higher_tier(self.evidence_tier, other.evidence_tier),
            id=self.id,
        )

    @staticmethod
    def _higher_severity(left: str, right: str) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return left if order.get(left, 1) >= order.get(right, 1) else right

    @staticmethod
    def _higher_tier(left: str, right: str) -> str:
        order = {
            "none": 0,
            "scaffold": 1,
            "heuristic": 2,
            "derived": 3,
            "passive": 4,
            "active": 5,
            "fused": 6,
            "collected": 7,
        }
        return left if order.get(left, 0) >= order.get(right, 0) else right


@dataclass
class Entity:
    entity_type: str
    canonical_name: str
    aliases: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    entity_id: str = ""

    def __post_init__(self) -> None:
        self.entity_type = str(self.entity_type or "unknown").strip().lower() or "unknown"
        self.canonical_name = str(self.canonical_name).strip()
        self.aliases = _unique_strings([self.canonical_name, *self.aliases])
        self.source_evidence_ids = _unique_strings(self.source_evidence_ids)
        if not isinstance(self.attributes, dict):
            self.attributes = {}
        self.confidence = max(0.0, min(float(self.confidence), 1.0))
        if not self.entity_id:
            self.entity_id = _stable_id(
                "ent",
                f"{self.entity_type}|{self.canonical_name.strip().lower()}",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "canonical_name": self.canonical_name,
            "aliases": sorted(set(self.aliases)),
            "attributes": self.attributes,
            "source_evidence_ids": sorted(set(self.source_evidence_ids)),
            "confidence": round(self.confidence, 4),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Entity":
        return cls(**payload)

    def merge(self, other: "Entity") -> "Entity":
        if self.entity_id != other.entity_id:
            raise ValueError("cannot merge entities with different ids")
        merged_attributes = dict(self.attributes)
        for key, value in other.attributes.items():
            current = merged_attributes.get(key)
            if isinstance(current, list) and isinstance(value, list):
                merged_attributes[key] = _unique_strings([*current, *value])
            elif isinstance(current, dict) and isinstance(value, dict):
                nested = dict(current)
                nested.update(value)
                merged_attributes[key] = nested
            else:
                merged_attributes[key] = value
        canonical = self.canonical_name if len(self.canonical_name) >= len(other.canonical_name) else other.canonical_name
        return Entity(
            entity_type=self.entity_type or other.entity_type,
            canonical_name=canonical,
            aliases=_unique_strings([*self.aliases, *other.aliases]),
            attributes=merged_attributes,
            source_evidence_ids=_unique_strings([*self.source_evidence_ids, *other.source_evidence_ids]),
            confidence=max(self.confidence, other.confidence),
            entity_id=self.entity_id,
        )


@dataclass
class RelationshipEdge:
    source_entity_id: str
    target_entity_id: str
    edge_type: str
    weight: float = 0.5
    source_evidence_ids: List[str] = field(default_factory=list)
    source_agent: str | None = None

    def __post_init__(self) -> None:
        self.weight = max(0.0, min(float(self.weight), 1.0))
        self.source_evidence_ids = _unique_strings(self.source_evidence_ids)
        self.source_agent = str(self.source_agent).strip() if self.source_agent else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_entity_id,
            "target": self.target_entity_id,
            "edge_type": self.edge_type,
            "weight": round(self.weight, 4),
            "source_evidence_ids": sorted(set(self.source_evidence_ids)),
            "source_agent": self.source_agent,
        }


@dataclass
class TimelineEvent:
    event_type: str
    raw_timestamp: str
    normalized_timestamp: str | None
    source_agent: str
    source_reference: str | None = None
    observed: bool = True
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event_type = str(self.event_type or "").strip()
        self.raw_timestamp = str(self.raw_timestamp or "").strip()
        self.normalized_timestamp = str(self.normalized_timestamp).strip() if self.normalized_timestamp else None
        self.source_agent = str(self.source_agent or "").strip()
        self.source_reference = str(self.source_reference).strip() if self.source_reference else None
        if not isinstance(self.details, dict):
            self.details = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "raw_timestamp": self.raw_timestamp,
            "normalized_timestamp": self.normalized_timestamp,
            "source_agent": self.source_agent,
            "source_reference": self.source_reference,
            "observed": self.observed,
            "details": self.details,
        }


@dataclass
class LeadItem:
    title: str
    rationale: str
    priority: int
    required_inputs: List[str] = field(default_factory=list)
    recommended_pivots: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.title = str(self.title or "").strip()
        self.rationale = str(self.rationale or "").strip()
        self.priority = int(self.priority)
        self.required_inputs = _unique_strings(self.required_inputs)
        self.recommended_pivots = _unique_strings(self.recommended_pivots)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "rationale": self.rationale,
            "priority": int(self.priority),
            "required_inputs": self.required_inputs,
            "recommended_pivots": self.recommended_pivots,
        }


@dataclass
class AgentEnvelope:
    status: AgentStatus
    agent: str
    target: Any
    findings: Dict[str, Any]
    risk_score: float = 0.0
    error: str | None = None
    reason: str | None = None
    evidence_mode: EvidenceMode = "none"
    evidence_count: int = 0
    execution_time: float = 0.0

    def __post_init__(self) -> None:
        self.status = str(self.status).strip().lower()  # type: ignore[assignment]
        self.agent = str(self.agent or "").strip()
        if not isinstance(self.findings, dict):
            self.findings = {}
        self.risk_score = max(0.0, min(float(self.risk_score), 1.0))
        self.error = str(self.error).strip() if self.error else None
        self.reason = str(self.reason).strip() if self.reason else None
        self.evidence_mode = str(self.evidence_mode or "none").strip().lower()  # type: ignore[assignment]
        self.evidence_count = max(0, int(self.evidence_count))
        self.execution_time = round(max(0.0, float(self.execution_time)), 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "agent": self.agent,
            "target": self.target,
            "findings": self.findings,
            "risk_score": round(max(0.0, min(float(self.risk_score), 1.0)), 4),
            "error": self.error,
            "reason": self.reason,
            "evidence_mode": self.evidence_mode,
            "evidence_count": max(0, int(self.evidence_count)),
            "execution_time": round(max(0.0, float(self.execution_time)), 4),
        }
