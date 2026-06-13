"""Local SQLite storage for SYNINT v4 investigations."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List


class InvestigationDatabase:
    """SQLite-backed investigation memory for a run."""

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    execution_model TEXT,
                    pipeline_mode TEXT,
                    collection_mode TEXT,
                    status TEXT,
                    created_at_utc TEXT,
                    updated_at_utc TEXT,
                    metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS agent_results (
                    run_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    stage_name TEXT,
                    status TEXT,
                    execution_time REAL,
                    result_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, agent_name)
                );
                CREATE TABLE IF NOT EXISTS evidence_items (
                    run_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS entities (
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, entity_id)
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    run_id TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    artifact_sha256 TEXT,
                    event_type TEXT,
                    source_agent TEXT,
                    source_reference TEXT,
                    PRIMARY KEY (run_id, artifact_path, event_type)
                );
                CREATE TABLE IF NOT EXISTS errors (
                    run_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    error_text TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                """
            )

    def upsert_run(
        self,
        *,
        run_id: str,
        target: str,
        execution_model: str | None,
        pipeline_mode: str | None,
        collection_mode: str | None,
        status: str,
        created_at_utc: str,
        updated_at_utc: str,
        metadata: Dict[str, Any],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, target, execution_model, pipeline_mode, collection_mode,
                    status, created_at_utc, updated_at_utc, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    target=excluded.target,
                    execution_model=excluded.execution_model,
                    pipeline_mode=excluded.pipeline_mode,
                    collection_mode=excluded.collection_mode,
                    status=excluded.status,
                    updated_at_utc=excluded.updated_at_utc,
                    metadata_json=excluded.metadata_json
                """,
                (
                    run_id,
                    target,
                    execution_model,
                    pipeline_mode,
                    collection_mode,
                    status,
                    created_at_utc,
                    updated_at_utc,
                    json.dumps(metadata, sort_keys=True),
                ),
            )

    def upsert_agent_result(self, run_id: str, agent_name: str, entry: Dict[str, Any], stage_name: str | None = None) -> None:
        result = entry.get("result", {}) if isinstance(entry, dict) else {}
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_results (run_id, agent_name, stage_name, status, execution_time, result_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, agent_name) DO UPDATE SET
                    stage_name=excluded.stage_name,
                    status=excluded.status,
                    execution_time=excluded.execution_time,
                    result_json=excluded.result_json
                """,
                (
                    run_id,
                    agent_name,
                    stage_name,
                    result.get("status"),
                    float(entry.get("execution_time", 0.0) or 0.0),
                    json.dumps(entry, sort_keys=True),
                ),
            )

    def replace_evidence(self, run_id: str, evidence_rows: Iterable[Dict[str, Any]]) -> None:
        rows = [(run_id, str(row.get("id", "")), json.dumps(row, sort_keys=True)) for row in evidence_rows if str(row.get("id", "")).strip()]
        with self._connect() as connection:
            connection.execute("DELETE FROM evidence_items WHERE run_id = ?", (run_id,))
            if rows:
                connection.executemany(
                    "INSERT INTO evidence_items (run_id, evidence_id, payload_json) VALUES (?, ?, ?)",
                    rows,
                )

    def replace_entities(self, run_id: str, entity_rows: Iterable[Dict[str, Any]]) -> None:
        rows = [(run_id, str(row.get("entity_id", "")), json.dumps(row, sort_keys=True)) for row in entity_rows if str(row.get("entity_id", "")).strip()]
        with self._connect() as connection:
            connection.execute("DELETE FROM entities WHERE run_id = ?", (run_id,))
            if rows:
                connection.executemany(
                    "INSERT INTO entities (run_id, entity_id, payload_json) VALUES (?, ?, ?)",
                    rows,
                )

    def record_artifact(self, run_id: str, entry: Dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    run_id, artifact_path, artifact_sha256, event_type, source_agent, source_reference
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(entry.get("artifact_path", "")),
                    str(entry.get("artifact_sha256", "")),
                    str(entry.get("event_type", "")),
                    entry.get("source_agent"),
                    entry.get("source_reference"),
                ),
            )

    def record_error(self, run_id: str, agent_name: str, error_text: str, created_at_utc: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO errors (run_id, agent_name, error_text, created_at_utc) VALUES (?, ?, ?, ?)",
                (run_id, agent_name, error_text, created_at_utc),
            )
