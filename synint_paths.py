"""Shared filesystem paths for SYNINT runtime outputs and assets."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"
COLLECTION_ARTIFACTS_DIR = REPORTS_DIR / "collection_artifacts"
INVESTIGATIONS_DIR = REPORTS_DIR / "investigations"
DOCS_DIR = PROJECT_ROOT / "docs"
DOCS_ASSETS_DIR = DOCS_DIR / "assets"

