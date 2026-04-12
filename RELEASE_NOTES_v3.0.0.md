# SYNINT v3.0.0

Release date: April 12, 2026

## Highlights

- Introduces SYNINT v3 architecture with both concurrent run-all execution and staged pipeline execution.
- Expands platform coverage to a 46-agent suite across OSINT collection, enrichment, correlation, and reporting.
- Adds pluggable collector-engine abstraction with capability-aware fallback.
- Delivers structured per-run reporting plus investigation export bundles.

## What's New

- Execution modes:
  - Default concurrent run-all across selected agents.
  - Staged pipeline orchestration with `quick`, `standard`, and `deep` profiles.
- Collection modes:
  - `low_noise`, `balanced`, `stealth`, `deep_browser`.
- Collector framework:
  - `StaticHttpCollector` (default baseline).
  - `ScraplingCollector` (optional).
  - `ScrapyCollector` (optional).
  - `CamoufoxCollector` (optional stealth/browser path).
- Reporting and artifacts:
  - Run-scoped outputs under `reports/<target-mm.dd.yy-HHMM>/`.
  - JSON and HTML summary reports.
  - Collection artifact tree (`raw_html`, `rendered_html`, `screenshots`, `headers`, `response_meta`, `extracted_text`, `downloads`).
  - Investigation export bundle from `ReportBuilderAgent`.

## Agent Coverage

- Total agents in canonical order: 46.
- Includes collection, entity/contact, timeline/history, file/media, infrastructure/pivot, and synthesis/export groups.
- Full catalog is documented in `README.md` under **Agent Catalog (46 Total)**.

## Operational Improvements

- Path handling is now project-root anchored via `synint_paths.py` for more predictable runtime outputs.
- Optional dependency behavior is graceful: unavailable optional collectors/tools do not hard-fail full runs.

## Validation

- Unit test suite: `python3 -m unittest discover -s tests -p 'test_*.py'`
- Current verification status at release prep: passing.

## Upgrade Notes

- Run from project root for expected relative CLI ergonomics.
- Install/update dependencies before first v3 run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- Default behavior is already run-all; `--legacy-run-all` remains available for compatibility.

## Legal

Only run SYNINT against targets you are authorized to investigate.
