"""Reversible, provenance-backed identity candidate workflow.

Candidate generation never mutates or merges input entities. Every state change
requires an explicit human/operator decision; model actors cannot confirm or
reject candidates.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from hashlib import sha1
from itertools import combinations
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Literal

from core.entity_utils import normalize_phone
from core.schemas import utc_now_iso

IdentityStatus = Literal["CANDIDATE", "REVIEWED", "CONFIRMED", "REJECTED", "CONTRADICTED"]
DecisionAction = Literal["CONFIRM", "REJECT", "REVERSE"]


def _unique(values: Iterable[Any]) -> List[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _as_strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _attributes(entity: Dict[str, Any]) -> Dict[str, Any]:
    value = entity.get("attributes")
    return value if isinstance(value, dict) else {}


def _normalized_name(entity: Dict[str, Any]) -> str:
    value = str(entity.get("canonical_name") or entity.get("name") or "")
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def _identifiers(entity: Dict[str, Any], key: str, normalizer=lambda value: value.lower()) -> set[str]:
    values = [*_as_strings(entity.get(key)), *_as_strings(_attributes(entity).get(key))]
    return {normalizer(value.strip()) for value in values if value.strip()}


def _mapping(entity: Dict[str, Any], key: str) -> Dict[str, str]:
    value = entity.get(key)
    if not isinstance(value, dict):
        value = _attributes(entity).get(key)
    if not isinstance(value, dict):
        return {}
    return {
        str(namespace).strip().lower(): str(identifier).strip().lower()
        for namespace, identifier in value.items()
        if str(namespace).strip() and str(identifier).strip()
    }


def _observation_ids(entity: Dict[str, Any]) -> List[str]:
    return _unique(
        [
            *_as_strings(entity.get("source_evidence_ids")),
            *_as_strings(entity.get("supporting_observation_ids")),
            *_as_strings(_attributes(entity).get("supporting_observation_ids")),
        ]
    )


def _provenance(entity: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = entity.get("provenance") or _attributes(entity).get("provenance") or []
    if isinstance(value, dict):
        return [deepcopy(value)]
    return [deepcopy(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


@dataclass
class IdentitySignal:
    signal_type: str
    strength: str
    values: List[str]
    explanation: str
    observation_ids: List[str] = field(default_factory=list)
    provenance: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IdentityCandidate:
    candidate_id: str
    entity_a: str
    entity_b: str
    supporting_observations: List[str]
    contradicting_observations: List[str]
    supporting_signals: List[IdentitySignal]
    contradicting_signals: List[IdentitySignal]
    source_provenance: List[Dict[str, Any]]
    created_at: str
    method: str = "synint-deterministic-signals-v1"
    score: None = None
    status: IdentityStatus = "CANDIDATE"
    review_state: str = "PENDING"
    reviewer_decision: Dict[str, Any] | None = None
    decision_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["supporting_signals"] = [signal.to_dict() for signal in self.supporting_signals]
        payload["contradicting_signals"] = [signal.to_dict() for signal in self.contradicting_signals]
        payload["why_candidate_exists"] = [signal.explanation for signal in self.supporting_signals]
        payload["what_contradicts_it"] = [signal.explanation for signal in self.contradicting_signals]
        payload["what_would_increase_confidence"] = (
            []
            if any(signal.strength == "strong" for signal in self.supporting_signals)
            else [
                "verified public cross-reference",
                "same verified email or phone",
                "same source-native stable identifier",
                "explicit source declaration",
            ]
        )
        payload["automatic_confirmation_allowed"] = False
        payload["llm_confirmation_allowed"] = False
        return payload

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "IdentityCandidate":
        data = dict(payload)
        for derived in (
            "why_candidate_exists",
            "what_contradicts_it",
            "what_would_increase_confidence",
            "automatic_confirmation_allowed",
            "llm_confirmation_allowed",
        ):
            data.pop(derived, None)
        data["supporting_signals"] = [IdentitySignal(**item) for item in data.get("supporting_signals", [])]
        data["contradicting_signals"] = [IdentitySignal(**item) for item in data.get("contradicting_signals", [])]
        return cls(**data)


class IdentityResolver:
    """Create candidates from transparent exact/declared signals only."""

    @staticmethod
    def _signal(
        signal_type: str,
        strength: str,
        values: Iterable[str],
        explanation: str,
        a: Dict[str, Any],
        b: Dict[str, Any],
    ) -> IdentitySignal:
        return IdentitySignal(
            signal_type=signal_type,
            strength=strength,
            values=_unique(values),
            explanation=explanation,
            observation_ids=_unique([*_observation_ids(a), *_observation_ids(b)]),
            provenance=[*_provenance(a), *_provenance(b)],
        )

    @classmethod
    def _supporting_signals(cls, a: Dict[str, Any], b: Dict[str, Any]) -> List[IdentitySignal]:
        signals: List[IdentitySignal] = []
        emails = _identifiers(a, "emails") & _identifiers(b, "emails")
        if emails:
            signals.append(cls._signal("EXACT_NORMALIZED_EMAIL", "strong", emails, "same normalized email", a, b))
        phones = _identifiers(a, "phones", normalize_phone) & _identifiers(b, "phones", normalize_phone)
        if phones:
            signals.append(cls._signal("EXACT_VERIFIED_PHONE", "strong", phones, "same normalized phone", a, b))

        stable_a = _mapping(a, "source_native_ids")
        stable_b = _mapping(b, "source_native_ids")
        stable = [f"{namespace}:{identifier}" for namespace, identifier in stable_a.items() if stable_b.get(namespace) == identifier]
        if stable:
            signals.append(cls._signal("EXACT_SOURCE_NATIVE_ID", "strong", stable, "same source-native stable identifier", a, b))

        a_id = str(a.get("entity_id") or "")
        b_id = str(b.get("entity_id") or "")
        links_a = set(_as_strings(a.get("explicit_links") or _attributes(a).get("explicit_links")))
        links_b = set(_as_strings(b.get("explicit_links") or _attributes(b).get("explicit_links")))
        if b_id in links_a or a_id in links_b:
            signals.append(cls._signal("EXPLICIT_SOURCE_LINK", "strong", [a_id, b_id], "one source explicitly links the two records", a, b))

        name_a, name_b = _normalized_name(a), _normalized_name(b)
        if name_a and name_a == name_b:
            signals.append(cls._signal("SAME_NORMALIZED_NAME", "weak", [name_a], "same normalized name; candidate evidence only", a, b))

        usernames_a = _mapping(a, "usernames")
        usernames_b = _mapping(b, "usernames")
        username_overlap = sorted(set(usernames_a.values()) & set(usernames_b.values()))
        if username_overlap:
            signals.append(
                cls._signal(
                    "SAME_USERNAME_CROSS_SERVICE",
                    "weak",
                    username_overlap,
                    "same username across services; ambiguous candidate evidence only",
                    a,
                    b,
                )
            )
        return signals

    @classmethod
    def _contradicting_signals(cls, a: Dict[str, Any], b: Dict[str, Any]) -> List[IdentitySignal]:
        signals: List[IdentitySignal] = []
        exclusive_a = _mapping(a, "verified_identifiers")
        exclusive_b = _mapping(b, "verified_identifiers")
        conflicts = [
            f"{namespace}:{exclusive_a[namespace]}!={exclusive_b[namespace]}"
            for namespace in sorted(set(exclusive_a) & set(exclusive_b))
            if exclusive_a[namespace] != exclusive_b[namespace]
        ]
        if conflicts:
            signals.append(
                cls._signal(
                    "CONFLICTING_VERIFIED_IDENTIFIER",
                    "strong",
                    conflicts,
                    "different verified identifiers in the same exclusive namespace",
                    a,
                    b,
                )
            )

        locations_a = _mapping(a, "locations_by_time")
        locations_b = _mapping(b, "locations_by_time")
        location_conflicts = [
            f"{timestamp}:{locations_a[timestamp]}!={locations_b[timestamp]}"
            for timestamp in sorted(set(locations_a) & set(locations_b))
            if locations_a[timestamp] != locations_b[timestamp]
        ]
        if location_conflicts:
            signals.append(
                cls._signal(
                    "CONFLICTING_LOCATION_AT_TIME",
                    "strong",
                    location_conflicts,
                    "incompatible locations at the same source timestamp",
                    a,
                    b,
                )
            )

        a_id = str(a.get("entity_id") or "")
        b_id = str(b.get("entity_id") or "")
        excluded_a = set(_as_strings(a.get("explicitly_not_same_as") or _attributes(a).get("explicitly_not_same_as")))
        excluded_b = set(_as_strings(b.get("explicitly_not_same_as") or _attributes(b).get("explicitly_not_same_as")))
        if b_id in excluded_a or a_id in excluded_b:
            signals.append(
                cls._signal(
                    "EXPLICIT_DIFFERENT_IDENTITY",
                    "strong",
                    [a_id, b_id],
                    "a source explicitly declares the records are different identities",
                    a,
                    b,
                )
            )
        return signals

    @classmethod
    def create_candidates(cls, entities: Iterable[Dict[str, Any]]) -> List[IdentityCandidate]:
        records = [deepcopy(entity) for entity in entities if isinstance(entity, dict) and entity.get("entity_id")]
        records.sort(key=lambda entity: str(entity["entity_id"]))
        by_id = {str(entity["entity_id"]): entity for entity in records}
        inverted: Dict[str, set[str]] = {}

        def index(entity_id: str, namespace: str, values: Iterable[str]) -> None:
            for value in values:
                token = f"{namespace}|{value}"
                inverted.setdefault(token, set()).add(entity_id)

        for record in records:
            entity_id = str(record["entity_id"])
            index(entity_id, "email", _identifiers(record, "emails"))
            index(entity_id, "phone", _identifiers(record, "phones", normalize_phone))
            index(
                entity_id,
                "stable",
                (f"{key}:{value}" for key, value in _mapping(record, "source_native_ids").items()),
            )
            name = _normalized_name(record)
            if name:
                index(entity_id, "name", [name])
            index(entity_id, "username", _mapping(record, "usernames").values())

        candidate_pairs: set[tuple[str, str]] = set()
        for entity_ids in inverted.values():
            for entity_a, entity_b in combinations(sorted(entity_ids), 2):
                candidate_pairs.add((entity_a, entity_b))
        for record in records:
            entity_a = str(record["entity_id"])
            links = _as_strings(record.get("explicit_links") or _attributes(record).get("explicit_links"))
            for entity_b in links:
                if entity_b in by_id and entity_b != entity_a:
                    candidate_pairs.add(tuple(sorted((entity_a, entity_b))))

        candidates: List[IdentityCandidate] = []
        for entity_a, entity_b in sorted(candidate_pairs):
            a, b = by_id[entity_a], by_id[entity_b]
            support = cls._supporting_signals(a, b)
            if not support:
                continue
            contradictions = cls._contradicting_signals(a, b)
            candidate_id = "idc_" + sha1(
                f"{entity_a}|{entity_b}|synint-deterministic-signals-v1".encode("utf-8")
            ).hexdigest()[:16]
            candidates.append(
                IdentityCandidate(
                    candidate_id=candidate_id,
                    entity_a=entity_a,
                    entity_b=entity_b,
                    supporting_observations=_unique(
                        observation
                        for signal in support
                        for observation in signal.observation_ids
                    ),
                    contradicting_observations=_unique(
                        observation
                        for signal in contradictions
                        for observation in signal.observation_ids
                    ),
                    supporting_signals=support,
                    contradicting_signals=contradictions,
                    source_provenance=[*_provenance(a), *_provenance(b)],
                    created_at=utc_now_iso(),
                    status="CONTRADICTED" if contradictions else "CANDIDATE",
                )
            )
        return candidates


class IdentityDecisionStore:
    """Atomic optional store for candidate links and reversible decisions."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._candidates: Dict[str, IdentityCandidate] = {}
        if self.path and self.path.exists():
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            for item in payload.get("candidates", []) if isinstance(payload, dict) else []:
                candidate = IdentityCandidate.from_dict(item)
                self._candidates[candidate.candidate_id] = candidate

    def add_candidates(self, candidates: Iterable[IdentityCandidate]) -> None:
        for candidate in candidates:
            self._candidates.setdefault(candidate.candidate_id, deepcopy(candidate))
        self._persist()

    def get(self, candidate_id: str) -> IdentityCandidate | None:
        candidate = self._candidates.get(candidate_id)
        return deepcopy(candidate) if candidate else None

    def list(self) -> List[IdentityCandidate]:
        return [deepcopy(self._candidates[key]) for key in sorted(self._candidates)]

    def decide(
        self,
        candidate_id: str,
        *,
        action: DecisionAction,
        reviewer: str,
        rationale: str,
        actor_type: str = "operator",
    ) -> IdentityCandidate:
        candidate = self._candidates.get(candidate_id)
        if candidate is None:
            raise KeyError(f"unknown identity candidate: {candidate_id}")
        reviewer = reviewer.strip()
        rationale = rationale.strip()
        if not reviewer or not rationale:
            raise ValueError("reviewer and rationale are required")
        if actor_type.strip().lower() in {"llm", "model", "ai"}:
            raise PermissionError("LLM/model actors cannot change identity candidate state")

        previous = candidate.status
        if action == "CONFIRM":
            candidate.status = "CONFIRMED"
            candidate.review_state = "REVIEWED"
        elif action == "REJECT":
            candidate.status = "REJECTED"
            candidate.review_state = "REVIEWED"
        elif action == "REVERSE":
            if candidate.status not in {"CONFIRMED", "REJECTED"}:
                raise ValueError("only a confirmed or rejected decision can be reversed")
            candidate.status = "CONTRADICTED" if candidate.contradicting_signals else "CANDIDATE"
            candidate.review_state = "PENDING"
        else:
            raise ValueError(f"unsupported identity decision action: {action}")

        decision = {
            "action": action,
            "reviewer": reviewer,
            "actor_type": actor_type,
            "rationale": rationale,
            "previous_status": previous,
            "new_status": candidate.status,
            "timestamp": utc_now_iso(),
        }
        candidate.reviewer_decision = decision
        candidate.decision_history.append(decision)
        self._persist()
        return deepcopy(candidate)

    def _persist(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"schema_version": 1, "candidates": [item.to_dict() for item in self.list()]}, indent=2),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
