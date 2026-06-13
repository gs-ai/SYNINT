Outlined is the plan to beef up SYNINT by hardening the **core investigative engine**.

Right now it already has a good chassis: staged pipelines, concurrent execution, target gating, context propagation, evidence/entity registries, progress snapshots, JSON/HTML reports, and runtime fingerprinting. The manager already supports quick/standard/deep stage plans , concurrent execution through `ThreadPoolExecutor` , normalized result envelopes , deterministic evidence/entity registries , and report snapshots during execution .

The next upgrades should make it more **forensic, resumable, stable, and court/report ready**.

## Highest-value upgrades

### 1. Add a forensic chain-of-custody ledger

Every run should produce a tamper-evident ledger:

```text
run_id
target
timestamp
artifact path
sha256 hash
agent name
evidence id
source reference
parent hash
```

The current `EvidenceItem` already creates stable IDs and timestamps , but I would add a separate immutable ledger using SHA-256 for artifact integrity.

```python
#!/usr/bin/env python3
"""
SYNINT Evidence Ledger
----------------------
Creates append-only, hash-linked records for collected files, reports, and evidence.
This strengthens forensic traceability without changing any agent logic.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    """Return SHA-256 hash for a file."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
    """Append-only JSONL ledger with chained entry hashes."""

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
    def _hash_payload(payload: dict[str, Any]) -> str:
        clean = dict(payload)
        clean.pop("entry_hash", None)
        encoded = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def append_file(
        self,
        *,
        run_id: str,
        event_type: str,
        artifact_path: str | Path,
        source_agent: str | None = None,
        evidence_id: str | None = None,
        source_reference: str | None = None,
    ) -> LedgerEntry:
        artifact_path = Path(artifact_path).resolve()

        entry = LedgerEntry(
            run_id=run_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            artifact_path=str(artifact_path),
            artifact_sha256=sha256_file(artifact_path),
            source_agent=source_agent,
            evidence_id=evidence_id,
            source_reference=source_reference,
            previous_entry_hash=self._last_hash(),
        )

        payload = asdict(entry)
        payload["entry_hash"] = self._hash_payload(payload)

        with self.ledger_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True) + "\n")

        return LedgerEntry(**payload)
```

### 2. Add checkpoint/resume

If a deep run crashes at agent 33 of 46, SYNINT should resume instead of restarting everything.

The current pipeline keeps `pipeline_state` with context, evidence registry, and entity registry at the end of a run . Expand that into periodic checkpoints after every agent.

```python
#!/usr/bin/env python3
"""
SYNINT Checkpoint Store
-----------------------
Persists resumable run state after each completed agent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CheckpointStore:
    """Simple JSON checkpoint manager for interrupted SYNINT runs."""

    def __init__(self, checkpoint_path: str | Path):
        self.path = Path(checkpoint_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, payload: dict[str, Any]) -> None:
        temp_path = self.path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self.path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def completed_agents(self) -> set[str]:
        payload = self.load()
        results = payload.get("results", {})
        return set(results.keys()) if isinstance(results, dict) else set()
```

### 3. Add a local SQLite investigation database

Reports are good, but a local database makes SYNINT much stronger over time.

Tables:

```text
runs
targets
agent_results
evidence_items
entities
relationships
timeline_events
artifacts
errors
```

This turns SYNINT from a run-and-report tool into a searchable investigative memory system.

### 4. Add strict result validation

The current normalizer is already solid because it forces standard keys like `status`, `agent`, `target`, `findings`, `risk_score`, `error`, `reason`, `evidence_mode`, and `evidence_count` . I would add schema validation after normalization so bad outputs are caught immediately.

Use Pydantic or JSON Schema.

```python
#!/usr/bin/env python3
"""
SYNINT Result Validator
-----------------------
Validates normalized agent output before reporting or registry ingestion.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError


class SynintResultEnvelope(BaseModel):
    status: Literal["ok", "skipped", "error"]
    agent: str
    target: Any
    findings: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(ge=0.0, le=1.0)
    error: str | None = None
    reason: str | None = None
    evidence_mode: str = "none"
    evidence_count: int = Field(default=0, ge=0)


def validate_result(payload: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
    """Return validation status, cleaned payload, and optional error."""
    try:
        model = SynintResultEnvelope(**payload)
        return True, model.model_dump(), None
    except ValidationError as exc:
        return False, payload, str(exc)
```

### 5. Add process isolation for unstable/heavy tasks

Threading is already present for normal runs . For heavier document/media/browser work, use a process pool or subprocess isolation so one bad OCR/browser/parser crash does not poison the whole run.

Best setup:

```text
normal lightweight agents -> threads
heavy file/browser/media tasks -> subprocess
dangerous experimental tasks -> lab-only subprocess
```

### 6. Add a global timeout/retry/circuit breaker layer

Each agent should not individually decide timeout discipline. The manager should enforce:

```text
max runtime per agent
max retries
failure quarantine
network timeout profile
skip-on-repeat-failure
```

That makes deep runs more stable.

### 7. Pin dependencies and add lock files

The current requirements are broad and unpinned, including `requests`, `numpy`, `scipy`, `scikit-learn`, `networkx`, document/media packages, and collector packages .

Upgrade to:

```text
requirements.in
requirements.lock
pyproject.toml
```

Then build with:

```bash
pip-compile requirements.in -o requirements.lock
pip install -r requirements.lock
```

This makes results more reproducible.

### 8. Add run profiles

Instead of only CLI flags, create YAML profiles:

```yaml
name: civil_background_standard
pipeline_mode: standard
collection_mode: balanced
max_workers: 12
agent_timeout_seconds: 90
report_formats:
  - json
  - html
  - markdown
evidence:
  hash_artifacts: true
  write_ledger: true
  preserve_raw: true
```

The CLI already supports pipeline mode and collection mode . Profiles would make repeatable case-type runs much cleaner.

### 9. Add report bundling

Every run should export a final package:

```text
synint_report.html
synint_report.json
synint_report.md
evidence_ledger.jsonl
runtime_fingerprint.json
pip_freeze.txt
raw_artifacts/
screenshots/
documents/
logs/
```

The runtime fingerprint already captures `run_id`, UTC timestamp, git commit hash, Python version, platform, and pip freeze snapshot . Bundle that with the final report.

### 10. Add health checks

Before a run starts, SYNINT should verify:

```text
Python version
dependency availability
Tesseract installed
Camoufox/browser available
disk write access
reports directory writable
network available if online mode
Git commit hash captured
```

The path structure is centralized already through `synint_paths.py` , so this is easy to add.

## Best next build order

```text
1. Evidence ledger
2. Checkpoint/resume
3. SQLite investigation database
4. Strict schema validation
5. Timeout/retry/circuit breaker
6. Dependency lock files
7. Run profiles
8. Report bundle exporter
9. Health check command
10. Benchmark/test suite
```

## Bottom line

The biggest upgrade is turning SYNINT from a strong multi-agent runner into a **forensic investigation operating system**.

Not more agents.

A stronger chassis:

```text
hash everything
checkpoint everything
validate everything
store everything
resume everything
bundle everything
reproduce everything
```

That is what makes it substantially more robust without touching the agentic module layer.
