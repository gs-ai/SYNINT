"""Shared schema objects for SYNINT pipeline outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha1
from typing import Any, Dict, List, Literal

AgentStatus = Literal["ok", "skipped", "error"]
EvidenceMode = Literal["collected", "derived", "heuristic", "scaffold", "fused", "active", "passive", "none"]


def _stable_id(prefix: str, payload: str) -> str:
    digest = sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        self.confidence = max(0.0, min(float(self.confidence), 1.0))
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
            "tags": list(dict.fromkeys(self.tags)),
            "source_reference": self.source_reference,
            "supporting_context": self.supporting_context,
            "timestamp": self.timestamp,
            "evidence_tier": self.evidence_tier,
        }


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
