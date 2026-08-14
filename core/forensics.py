"""Forensic ledger helpers for SYNINT v5 artifact integrity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def sha256_file(path: str | Path) -> str:
    """Return a streaming SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    run_id: str
    timestamp_utc: str
    event_type: str
    artifact_path: str
    artifact_sha256: str
    source_agent: str | None = None
    evidence_id: str | None = None
    source_reference: str | None = None
    previous_entry_hash: str | None = None
    entry_hash: str | None = None


class EvidenceLedger:
    """Append-only JSONL ledger with hash-chained entries."""

    def __init__(self, ledger_path: str | Path):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str | None:
        if not self.ledger_path.exists():
            return None
        lines = [line for line in self.ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return None
        try:
            return json.loads(lines[-1]).get("entry_hash")
        except Exception:
            return None

    @staticmethod
    def _hash_payload(payload: Dict[str, Any]) -> str:
        clean = dict(payload)
        clean.pop("entry_hash", None)
        encoded = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def append_artifact(
        self,
        *,
        run_id: str,
        event_type: str,
        artifact_path: str | Path,
        source_agent: str | None = None,
        evidence_id: str | None = None,
        source_reference: str | None = None,
    ) -> LedgerEntry | None:
        path = Path(artifact_path).expanduser().resolve()
        if not path.exists() or not path.is_file():
            return None

        entry = LedgerEntry(
            run_id=run_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            artifact_path=str(path),
            artifact_sha256=sha256_file(path),
            source_agent=source_agent,
            evidence_id=evidence_id,
            source_reference=source_reference,
            previous_entry_hash=self._last_hash(),
        )
        payload = asdict(entry)
        payload["entry_hash"] = self._hash_payload(payload)
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return LedgerEntry(**payload)

    def entry_count(self) -> int:
        if not self.ledger_path.exists():
            return 0
        return sum(1 for line in self.ledger_path.read_text(encoding="utf-8").splitlines() if line.strip())
