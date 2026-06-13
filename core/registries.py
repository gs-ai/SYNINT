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
        ev = EvidenceItem.from_dict(item) if isinstance(item, dict) else item
        existing = self._items.get(ev.id)
        self._items[ev.id] = ev if existing is None else existing.merge(ev)
        return ev.id

    def extend(self, items: Iterable[EvidenceItem | Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for item in items:
            ids.append(self.add(item))
        return ids

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def __contains__(self, evidence_id: str) -> bool:
        return evidence_id in self._items

    def __len__(self) -> int:
        return len(self._items)

    def items(self) -> List[EvidenceItem]:
        return [self._items[key] for key in sorted(self._items)]

    def to_list(self) -> List[Dict[str, Any]]:
        return [item.to_dict() for item in self.items()]

    def summary(self) -> Dict[str, Any]:
        tiers: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for item in self._items.values():
            tiers[item.evidence_tier] = tiers.get(item.evidence_tier, 0) + 1
            by_agent[item.source_agent] = by_agent.get(item.source_agent, 0) + 1
            by_type[item.evidence_type] = by_type.get(item.evidence_type, 0) + 1
        return {
            "total_evidence": len(self._items),
            "evidence_tiers": dict(sorted(tiers.items())),
            "by_agent": dict(sorted(by_agent.items())),
            "by_type": dict(sorted(by_type.items())),
        }


@dataclass
class EntityRegistry:
    """Entity registry keyed by deterministic entity IDs."""

    _entities: Dict[str, Entity] = field(default_factory=dict)

    def add(self, item: Entity | Dict[str, Any]) -> str:
        entity = Entity.from_dict(item) if isinstance(item, dict) else item

        existing = self._entities.get(entity.entity_id)
        if existing is None:
            self._entities[entity.entity_id] = entity
            return entity.entity_id

        self._entities[entity.entity_id] = existing.merge(entity)
        return entity.entity_id

    def extend(self, items: Iterable[Entity | Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for item in items:
            ids.append(self.add(item))
        return ids

    def to_list(self) -> List[Dict[str, Any]]:
        return [self._entities[key].to_dict() for key in sorted(self._entities)]

    def get(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def __contains__(self, entity_id: str) -> bool:
        return entity_id in self._entities

    def __len__(self) -> int:
        return len(self._entities)

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        for item in self._entities.values():
            counts[item.entity_type] = counts.get(item.entity_type, 0) + 1
            source_agent = str(item.attributes.get("source_agent", "")).strip()
            if source_agent:
                by_agent[source_agent] = by_agent.get(source_agent, 0) + 1
        return {
            "total_entities": len(self._entities),
            "by_type": dict(sorted(counts.items())),
            "by_agent": dict(sorted(by_agent.items())),
        }
