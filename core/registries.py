"""Central evidence and entity registries for SYNINT pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from .schemas import Entity, EvidenceItem


@dataclass
class EvidenceRegistry:
    """Deduplicating evidence registry with deterministic keying."""

    _items: Dict[str, EvidenceItem] = field(default_factory=dict)

    def add(self, item: EvidenceItem | Dict[str, Any]) -> str:
        if isinstance(item, dict):
            ev = EvidenceItem(**item)
        else:
            ev = item
        self._items[ev.id] = ev
        return ev.id

    def extend(self, items: Iterable[EvidenceItem | Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for item in items:
            ids.append(self.add(item))
        return ids

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def to_list(self) -> List[Dict[str, Any]]:
        return [self._items[key].to_dict() for key in sorted(self._items)]

    def summary(self) -> Dict[str, Any]:
        tiers: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        for item in self._items.values():
            tiers[item.evidence_tier] = tiers.get(item.evidence_tier, 0) + 1
            by_agent[item.source_agent] = by_agent.get(item.source_agent, 0) + 1
        return {
            "total_evidence": len(self._items),
            "evidence_tiers": tiers,
            "by_agent": dict(sorted(by_agent.items())),
        }


@dataclass
class EntityRegistry:
    """Entity registry keyed by deterministic entity IDs."""

    _entities: Dict[str, Entity] = field(default_factory=dict)

    def add(self, item: Entity | Dict[str, Any]) -> str:
        if isinstance(item, dict):
            entity = Entity(**item)
        else:
            entity = item

        existing = self._entities.get(entity.entity_id)
        if existing is None:
            self._entities[entity.entity_id] = entity
            return entity.entity_id

        merged_aliases = sorted(set(existing.aliases) | set(entity.aliases))
        merged_evidence = sorted(set(existing.source_evidence_ids) | set(entity.source_evidence_ids))
        merged_attributes = dict(existing.attributes)
        merged_attributes.update(entity.attributes)

        existing.aliases = merged_aliases
        existing.source_evidence_ids = merged_evidence
        existing.attributes = merged_attributes
        existing.confidence = max(existing.confidence, entity.confidence)
        return existing.entity_id

    def extend(self, items: Iterable[Entity | Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for item in items:
            ids.append(self.add(item))
        return ids

    def to_list(self) -> List[Dict[str, Any]]:
        return [self._entities[key].to_dict() for key in sorted(self._entities)]

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for item in self._entities.values():
            counts[item.entity_type] = counts.get(item.entity_type, 0) + 1
        return {"total_entities": len(self._entities), "by_type": dict(sorted(counts.items()))}
