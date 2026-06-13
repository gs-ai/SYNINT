"""Checkpoint persistence for resumable SYNINT runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Set


class CheckpointStore:
    """Atomic JSON checkpoint manager."""

    def __init__(self, checkpoint_path: str | Path):
        self.path = Path(checkpoint_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, payload: Dict[str, Any]) -> None:
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp_path.replace(self.path)

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def completed_agents(self) -> Set[str]:
        payload = self.load()
        results = payload.get("results", {})
        if not isinstance(results, dict):
            return set()
        return {str(name) for name in results}
