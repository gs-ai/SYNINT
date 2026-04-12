"""Investigation context object shared by orchestrator and agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from agents._shared import infer_target_types, normalize_target


@dataclass
class InvestigationContext:
    original_target: str
    normalized_target: str
    target_type: str
    resolved_ips: List[str] = field(default_factory=list)
    resolved_domains: List[str] = field(default_factory=list)
    collected_urls: List[str] = field(default_factory=list)
    collected_files: List[str] = field(default_factory=list)
    collected_entities: List[Dict[str, Any]] = field(default_factory=list)
    collected_evidence: List[Dict[str, Any]] = field(default_factory=list)
    runtime_notes: List[str] = field(default_factory=list)
    collection_mode: str = "standard"

    @classmethod
    def from_target(cls, target: str, collection_mode: str = "standard") -> "InvestigationContext":
        normalized = normalize_target(target)
        target_types = sorted(infer_target_types(target))
        primary_type = target_types[0] if target_types else "text"
        return cls(
            original_target=target,
            normalized_target=normalized,
            target_type=primary_type,
            collection_mode=collection_mode,
        )

    def add_url(self, url: str) -> None:
        if url and url not in self.collected_urls:
            self.collected_urls.append(url)

    def add_file(self, path: str) -> None:
        if path and path not in self.collected_files:
            self.collected_files.append(path)

    def add_runtime_note(self, note: str) -> None:
        if note:
            self.runtime_notes.append(note)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_target": self.original_target,
            "normalized_target": self.normalized_target,
            "target_type": self.target_type,
            "resolved_ips": sorted(set(self.resolved_ips)),
            "resolved_domains": sorted(set(self.resolved_domains)),
            "collected_urls": sorted(set(self.collected_urls)),
            "collected_files": sorted(set(self.collected_files)),
            "collected_entities": self.collected_entities,
            "collected_evidence": self.collected_evidence,
            "runtime_notes": self.runtime_notes,
            "collection_mode": self.collection_mode,
        }
