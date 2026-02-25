#!/usr/bin/env python3
"""Utilities for collecting runtime metadata for SYNINT reports."""

from __future__ import annotations

import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4


def _run_command(command: list[str], timeout: int = 10) -> str:
    """Run a command and return stdout text; return empty string on failure."""
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.stdout.strip()
    except Exception:
        return ""


def build_run_metadata(
    dependency_snapshot_file: Optional[str] = "reports/runtime_pip_freeze.txt",
) -> Dict[str, Any]:
    """Build a runtime metadata payload for report stamping."""
    metadata: Dict[str, Any] = {
        "run_id": str(uuid4()),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit_hash": _run_command(["git", "rev-parse", "HEAD"]) or "unknown",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
    }

    if dependency_snapshot_file:
        freeze_output = _run_command([sys.executable, "-m", "pip", "freeze"], timeout=30)
        if freeze_output:
            snapshot_path = Path(dependency_snapshot_file)
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot_path.write_text(freeze_output + "\n", encoding="utf-8")
            metadata["dependency_snapshot_file"] = str(snapshot_path)
            metadata["dependency_count"] = len(freeze_output.splitlines())
        else:
            metadata["dependency_snapshot_file"] = None
            metadata["dependency_snapshot_error"] = "Unable to capture pip freeze output"

    return metadata
