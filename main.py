#!/usr/bin/env python3
"""CLI entrypoint for SYNINT v4 pipeline execution and reporting."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime
from html import escape
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Sequence
from urllib.parse import urlparse

from agent_manager import AgentManager
from agent_manager import RuntimePolicy
from agents import AGENT_ORDER, available_agent_names, load_agent_classes
from core import CheckpointStore, EvidenceLedger, InvestigationDatabase
from runtime_fingerprint import build_run_metadata
from synint_paths import REPORTS_DIR

REPORTS_ROOT = REPORTS_DIR
REPORT_JSON_NAME = "synint_report.json"
REPORT_HTML_NAME = "synint_report.html"
LOG_FILE_NAME = "synint.log"
CHECKPOINT_FILE_NAME = "synint_checkpoint.json"
LEDGER_FILE_NAME = "chain_of_custody.jsonl"
INVESTIGATION_DB_NAME = "investigation.sqlite"


def _configure_logging(log_file: Path | None = None) -> None:
    file_path = log_file or (REPORTS_ROOT / LOG_FILE_NAME)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        file_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(), file_handler],
        force=True,
    )


# Configure logging.
_configure_logging()
logger = logging.getLogger(__name__)


def _target_slug(target: str) -> str:
    raw = str(target).strip().lower()
    if not raw:
        return "target"

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or parsed.netloc or raw).strip().lower()
    if host.startswith("www."):
        host = host[4:]
    host_parts = [part for part in host.split(".") if part]
    host_base = ".".join(host_parts[:-1]) if len(host_parts) >= 2 else host
    slug = re.sub(r"[^a-z0-9]+", "", host_base)
    if slug:
        return slug[:80]

    fallback = re.sub(r"[^a-z0-9]+", "", raw)
    return (fallback[:80] or "target")


def _create_run_reports_dir(target: str) -> Path:
    now = datetime.now()
    timestamp = f"{now.month}.{now.day}.{str(now.year)[-2:]}-{now.strftime('%H%M')}"
    base_name = f"{_target_slug(target)}-{timestamp}"
    run_dir = REPORTS_ROOT / base_name
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = REPORTS_ROOT / f"{base_name}-{suffix:02d}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def _result_from_entry(agent_entry: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(agent_entry, dict):
        return {}
    result = agent_entry.get("result")
    if isinstance(result, dict):
        return result
    return {}


def _status_from_entry(agent_entry: Dict[str, Any]) -> str:
    result = _result_from_entry(agent_entry)
    status = result.get("status")
    if isinstance(status, str) and status.strip():
        return status.lower()
    if "error" in result:
        return "error"
    if result:
        return "ok"
    return "unknown"


def _risk_from_entry(agent_entry: Dict[str, Any]) -> float | None:
    result = _result_from_entry(agent_entry)
    raw = result.get("risk_score")
    if isinstance(raw, (int, float)):
        return max(0.0, min(float(raw), 1.0))
    return None


def build_report_payload(
    results: Dict[str, Dict[str, Any]],
    overall_time: float,
    target: str,
    run_metadata: Dict[str, Any],
    *,
    execution_model: str,
    pipeline_mode: str | None = None,
    collection_mode: str | None = None,
    pipeline_state: Dict[str, Any] | None = None,
    expected_total_agents: int | None = None,
    report_phase: str | None = None,
) -> Dict[str, Any]:
    """Build one canonical report payload used by all outputs."""
    total_agents = len(results)
    selected_total = int(expected_total_agents) if isinstance(expected_total_agents, int) and expected_total_agents > 0 else total_agents
    pending_agents = max(selected_total - total_agents, 0)
    status_counts: Dict[str, int] = {"ok": 0, "skipped": 0, "error": 0, "unknown": 0}

    risk_scores: Dict[str, float] = {}
    for agent_name, entry in results.items():
        status = _status_from_entry(entry)
        status_counts[status] = status_counts.get(status, 0) + 1

        risk = _risk_from_entry(entry)
        if risk is not None:
            risk_scores[agent_name] = round(risk, 4)

    average_risk = round(sum(risk_scores.values()) / len(risk_scores), 4) if risk_scores else 0.0
    max_risk = round(max(risk_scores.values()), 4) if risk_scores else 0.0
    top_risk_agents = [
        {"agent": name, "risk_score": score}
        for name, score in sorted(risk_scores.items(), key=lambda item: item[1], reverse=True)[:5]
    ]
    pipeline_snapshot = pipeline_state or {}
    forensic_summary = {
        "ledger_path": pipeline_snapshot.get("forensic_ledger_path", ""),
        "checkpoint_path": pipeline_snapshot.get("checkpoint_path", ""),
        "investigation_db_path": pipeline_snapshot.get("investigation_db_path", ""),
    }

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "execution_model": execution_model,
        "pipeline_mode": pipeline_mode,
        "collection_mode": collection_mode,
        "report_phase": report_phase or ("complete" if pending_agents == 0 else "in_progress"),
        "total_execution_time": overall_time,
        "total_agents_executed": total_agents,
        "total_agents_selected": selected_total,
        "pending_agents": pending_agents,
        "error_count": status_counts.get("error", 0),
        "status_summary": status_counts,
        "risk_summary": {
            "scored_agents": len(risk_scores),
            "average_risk_score": average_risk,
            "max_risk_score": max_risk,
            "top_risk_agents": top_risk_agents,
        },
        "forensic_summary": forensic_summary,
        "run_metadata": run_metadata,
        "pipeline_state": pipeline_snapshot,
        "results": results,
    }


def generate_json_report(report: Dict[str, Any], filename: Path = REPORTS_ROOT / REPORT_JSON_NAME) -> None:
    """Generate a JSON report from the aggregated results including metadata."""
    try:
        filename.parent.mkdir(parents=True, exist_ok=True)
        with filename.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4)
        logger.info("JSON report successfully saved to %s", filename)
    except Exception as exc:
        logger.exception("Failed to generate JSON report: %s", exc)


def generate_html_report(report: Dict[str, Any], filename: Path = REPORTS_ROOT / REPORT_HTML_NAME) -> None:
    """Generate an HTML report from the aggregated results including metadata."""
    try:
        filename.parent.mkdir(parents=True, exist_ok=True)
        results = report.get("results", {})
        html_parts = [
            """<!DOCTYPE html>
<html>
<head>
    <title>SYNINT Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
        th { background-color: #f2f2f2; text-align: left; }
        pre { background-color: #f8f8f8; padding: 10px; border: 1px solid #ddd; }
        .error { background-color: #ffdddd; }
        .collapsible {
            background-color: #f2f2f2;
            color: #444;
            cursor: pointer;
            padding: 10px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
        }
        .active, .collapsible:hover {
            background-color: #ddd;
        }
        .content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <h1>SYNINT Report</h1>
"""
        ]

        html_parts.append(f"    <p><strong>Target:</strong> {escape(str(report.get('target', '')))}</p>\n")
        html_parts.append(f"    <p><strong>Report Generated:</strong> {escape(str(report.get('generated_at', '')))}</p>\n")
        html_parts.append(f"    <p><strong>Report Status:</strong> {escape(str(report.get('report_phase', 'unknown')))}</p>\n")
        html_parts.append(
            f"    <p><strong>Total Agents Selected:</strong> {int(report.get('total_agents_selected', report.get('total_agents_executed', len(results))))}</p>\n"
        )
        html_parts.append(
            f"    <p><strong>Agents Completed:</strong> {int(report.get('total_agents_executed', len(results)))}</p>\n"
        )
        html_parts.append(
            f"    <p><strong>Pending Agents:</strong> {int(report.get('pending_agents', 0))}</p>\n"
        )
        html_parts.append(
            f"    <p><strong>Total Execution Time:</strong> {float(report.get('total_execution_time', 0.0)):.2f} seconds</p>\n"
        )
        html_parts.append(f"    <p><strong>Error Count:</strong> {int(report.get('error_count', 0))}</p>\n")

        status_summary = report.get("status_summary", {})
        risk_summary = report.get("risk_summary", {})
        html_parts.append(
            "    <p><strong>Status Summary:</strong> "
            + escape(json.dumps(status_summary, sort_keys=True))
            + "</p>\n"
        )
        html_parts.append(
            "    <p><strong>Risk Summary:</strong> "
            + escape(json.dumps(risk_summary, sort_keys=True))
            + "</p>\n"
        )
        html_parts.append(
            "    <p><strong>Forensic Summary:</strong> "
            + escape(json.dumps(report.get("forensic_summary", {}), sort_keys=True))
            + "</p>\n"
        )

        html_parts.append("    <button onclick=\"downloadJSON()\">Download JSON Report</button>\n")
        html_parts.append("    <h2>RUN_METADATA</h2>\n")
        html_parts.append(
            "    <pre>" + escape(json.dumps(report.get("run_metadata", {}), indent=2)) + "</pre>\n"
        )
        html_parts.append(
            """    <br/><br/>
    <table>
        <tr>
            <th>Agent</th>
            <th>Status</th>
            <th>Risk Score</th>
            <th>Execution Time (seconds)</th>
            <th>Result</th>
        </tr>
"""
        )

        for agent, data in results.items():
            status = _status_from_entry(data)
            risk_value = _risk_from_entry(data)
            error_class = "error" if status == "error" else ""
            execution_time = float(data.get("execution_time", 0.0))
            result_json = escape(json.dumps(data.get("result", {}), indent=2))
            display_risk = "n/a" if risk_value is None else f"{risk_value:.4f}"

            html_parts.append(
                f"""        <tr class="{error_class}">
            <td>{escape(str(agent))}</td>
            <td>{escape(status)}</td>
            <td>{display_risk}</td>
            <td>{execution_time:.2f}</td>
            <td>
                <button class="collapsible">View Details</button>
                <div class="content">
                    <pre>{result_json}</pre>
                </div>
            </td>
        </tr>
"""
            )

        report_json = escape(json.dumps(report, indent=4))
        html_parts.append(
            """    </table>
    <script>
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
        }
        function downloadJSON() {
            var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(document.getElementById("jsonData").textContent);
            var downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", "synint_report.json");
            document.body.appendChild(downloadAnchorNode);
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        }
    </script>
"""
        )
        html_parts.append(f"    <pre id=\"jsonData\" style=\"display:none;\">{report_json}</pre>\n")
        html_parts.append("</body>\n</html>\n")

        with filename.open("w", encoding="utf-8") as report_file:
            report_file.write("".join(html_parts))
        logger.info("HTML report successfully saved to %s", filename)
    except Exception as exc:
        logger.exception("Failed to generate HTML report: %s", exc)


def _record_runtime_artifact(
    *,
    ledger: EvidenceLedger | None,
    database: InvestigationDatabase | None,
    run_id: str,
    event_type: str,
    artifact_path: Path,
    source_reference: str,
) -> None:
    if ledger is None or not run_id:
        return
    entry = ledger.append_artifact(
        run_id=run_id,
        event_type=event_type,
        artifact_path=artifact_path,
        source_agent="main",
        source_reference=source_reference,
    )
    if entry is not None and database is not None:
        database.record_artifact(run_id, entry.__dict__)


def _parse_agent_name_csv(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def _select_agent_names(include_names: set[str], exclude_names: set[str]) -> Sequence[str]:
    available = set(available_agent_names())
    unknown = sorted((include_names | exclude_names) - available)
    if unknown:
        raise ValueError(f"Unknown agent class name(s): {', '.join(unknown)}")

    selected: list[str] = []
    for name in AGENT_ORDER:
        if include_names and name not in include_names:
            continue
        if name in exclude_names:
            continue
        selected.append(name)

    if not selected:
        raise ValueError("No agents selected after applying include/exclude filters.")
    return selected


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run SYNINT across selected agents.")
    parser.add_argument("target", nargs="?", help="Target indicator to analyze")
    parser.add_argument(
        "--agents",
        default="",
        help="Comma-separated agent class names to run (default: all)",
    )
    parser.add_argument(
        "--exclude-agents",
        default="",
        help="Comma-separated agent class names to skip",
    )
    parser.add_argument(
        "--list-agents",
        action="store_true",
        help="List available agents and exit (unless target is also provided)",
    )
    parser.add_argument(
        "--pipeline-mode",
        choices=("quick", "standard", "deep"),
        default="standard",
        help="Pipeline depth profile for staged orchestration (used only with --pipeline)",
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Use staged pipeline orchestration (default behavior runs all selected agents)",
    )
    parser.add_argument(
        "--collection-mode",
        choices=("low_noise", "balanced", "stealth", "deep_browser"),
        default="",
        help="Override automatic collection mode mapping",
    )
    parser.add_argument(
        "--legacy-run-all",
        action="store_true",
        help="Deprecated compatibility flag; default already runs all selected agents",
    )
    parser.add_argument(
        "--resume-checkpoint",
        default="",
        help="Resume a prior run from the given checkpoint JSON path",
    )
    parser.add_argument(
        "--agent-timeout",
        type=float,
        default=0.0,
        help="Per-agent timeout in seconds (0 disables timeout enforcement)",
    )
    parser.add_argument(
        "--agent-retries",
        type=int,
        default=0,
        help="Per-agent retry count after a failure or timeout",
    )
    return parser


def _print_available_agents() -> None:
    print("Available agents:")
    for name in AGENT_ORDER:
        print(f"- {name}")


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()
    logger.info(
        "SYNINT invoked (target=%s, list_agents=%s, include=%s, exclude=%s, pipeline=%s, pipeline_mode=%s, legacy=%s, resume=%s)",
        args.target,
        args.list_agents,
        bool(str(args.agents).strip()),
        bool(str(args.exclude_agents).strip()),
        args.pipeline,
        args.pipeline_mode,
        args.legacy_run_all,
        bool(str(args.resume_checkpoint).strip()),
    )

    if args.list_agents:
        _print_available_agents()
        if not args.target:
            logger.info("Listed agents and exited without running analysis.")
            return

    if not args.target:
        parser.print_usage()
        logger.error("No target provided.")
        sys.exit(1)

    target = args.target
    resume_checkpoint = Path(str(args.resume_checkpoint).strip()).expanduser() if str(args.resume_checkpoint).strip() else None
    if resume_checkpoint is not None:
        if not resume_checkpoint.exists():
            logger.error("Resume checkpoint not found: %s", resume_checkpoint)
            sys.exit(1)
        run_reports_dir = resume_checkpoint.resolve().parent
    else:
        run_reports_dir = _create_run_reports_dir(target)
    log_file = run_reports_dir / LOG_FILE_NAME
    _configure_logging(log_file)
    logger.info("Run reports directory initialized at %s", run_reports_dir)

    include_names = _parse_agent_name_csv(args.agents)
    exclude_names = _parse_agent_name_csv(args.exclude_agents)

    try:
        selected_agent_names = _select_agent_names(include_names, exclude_names)
    except ValueError as exc:
        logger.error(str(exc))
        sys.exit(1)

    logger.info("Starting SYNINT analysis for target: %s", target)
    logger.info("Selected %d agents.", len(selected_agent_names))
    start_time = time.time()
    report_json_path = run_reports_dir / REPORT_JSON_NAME
    report_html_path = run_reports_dir / REPORT_HTML_NAME
    results: Dict[str, Dict[str, Any]] = {}

    try:
        checkpoint_store = CheckpointStore(resume_checkpoint or (run_reports_dir / CHECKPOINT_FILE_NAME))
        resume_payload = checkpoint_store.load() if resume_checkpoint is not None else {}
        run_metadata = build_run_metadata(dependency_snapshot_file=run_reports_dir / "runtime_pip_freeze.txt")
        if isinstance(resume_payload, dict) and str(resume_payload.get("run_id", "")).strip():
            run_metadata["run_id"] = str(resume_payload.get("run_id"))
        evidence_ledger = EvidenceLedger(run_reports_dir / LEDGER_FILE_NAME)
        investigation_db = InvestigationDatabase(run_reports_dir / INVESTIGATION_DB_NAME)
        manager = AgentManager(
            run_id=str(run_metadata.get("run_id", "")),
            checkpoint_store=checkpoint_store,
            evidence_ledger=evidence_ledger,
            investigation_db=investigation_db,
            runtime_policy=RuntimePolicy(
                timeout_seconds=max(0.0, float(args.agent_timeout or 0.0)),
                max_retries=max(0, int(args.agent_retries or 0)),
            ),
        )
        selected_agent_classes = load_agent_classes(selected_agent_names)
        for agent_cls in selected_agent_classes:
            manager.register_agent(agent_cls())

        logger.info("All selected agents registered successfully.")

        use_pipeline = bool(args.pipeline) and not bool(args.legacy_run_all)
        execution_model = "pipeline" if use_pipeline else "legacy_run_all"
        collection_mode_override = str(args.collection_mode).strip() or None
        run_collection_mode = collection_mode_override or "balanced"
        run_metadata["checkpoint_path"] = str(checkpoint_store.path.resolve())
        run_metadata["forensic_ledger_path"] = str(evidence_ledger.ledger_path.resolve())
        run_metadata["investigation_db_path"] = str(investigation_db.path.resolve())
        run_metadata["agent_timeout_seconds"] = max(0.0, float(args.agent_timeout or 0.0))
        run_metadata["agent_retries"] = max(0, int(args.agent_retries or 0))
        run_metadata["resumed_from_checkpoint"] = str(resume_checkpoint.resolve()) if resume_checkpoint is not None else None
        last_progress_report = 0.0
        progress_interval_seconds = 20.0

        def _write_report_snapshot(current_results: Dict[str, Dict[str, Any]], progress: Dict[str, Any] | None = None) -> None:
            nonlocal last_progress_report
            payload = progress or {}
            now = time.time()
            force = bool(payload.get("force"))
            if not force and (now - last_progress_report) < progress_interval_seconds:
                return

            snapshot = build_report_payload(
                current_results,
                now - start_time,
                target,
                run_metadata,
                execution_model=execution_model,
                pipeline_mode=args.pipeline_mode if use_pipeline else None,
                collection_mode=(manager.pipeline_state or {}).get("collection_mode") or run_collection_mode,
                pipeline_state=manager.pipeline_state or None,
                expected_total_agents=len(selected_agent_names),
                report_phase="complete" if str(payload.get("phase")) == "complete" else "in_progress",
            )
            generate_json_report(snapshot, report_json_path)
            generate_html_report(snapshot, report_html_path)
            _record_runtime_artifact(
                ledger=evidence_ledger,
                database=investigation_db,
                run_id=str(run_metadata.get("run_id", "")),
                event_type="report_snapshot_json",
                artifact_path=report_json_path,
                source_reference="synint_report.json",
            )
            _record_runtime_artifact(
                ledger=evidence_ledger,
                database=investigation_db,
                run_id=str(run_metadata.get("run_id", "")),
                event_type="report_snapshot_html",
                artifact_path=report_html_path,
                source_reference="synint_report.html",
            )
            last_progress_report = now
            logger.info(
                "Progress report snapshot saved (agents=%d, stage=%s, phase=%s).",
                len(current_results),
                payload.get("stage", "n/a"),
                payload.get("phase", "update"),
            )

        if use_pipeline:
            logger.info(
                "Running staged pipeline mode=%s collection_override=%s",
                args.pipeline_mode,
                collection_mode_override or "auto",
            )
            logger.warning(
                "Pipeline mode runs only stage-planned agents; use default mode (without --pipeline) to run all selected agents."
            )
            results = manager.run_pipeline(
                target,
                pipeline_mode=args.pipeline_mode,
                collection_mode_override=collection_mode_override,
                run_reports_dir=run_reports_dir,
                progress_callback=_write_report_snapshot,
            )
        else:
            logger.info("Running all selected agents concurrently.")
            results = manager.run_all(
                target,
                run_reports_dir=run_reports_dir,
                progress_callback=_write_report_snapshot,
                collection_mode=run_collection_mode,
            )

        overall_time = time.time() - start_time
        logger.info("Total execution time: %.2f seconds", overall_time)

        report = build_report_payload(
            results,
            overall_time,
            target,
            run_metadata,
            execution_model=execution_model,
            pipeline_mode=args.pipeline_mode if use_pipeline else None,
            collection_mode=(manager.pipeline_state or {}).get("collection_mode") or run_collection_mode,
            pipeline_state=manager.pipeline_state or None,
            expected_total_agents=len(selected_agent_names),
            report_phase="complete",
        )

        print(json.dumps(results, indent=4))
        generate_json_report(report, report_json_path)
        generate_html_report(report, report_html_path)
        _record_runtime_artifact(
            ledger=evidence_ledger,
            database=investigation_db,
            run_id=str(run_metadata.get("run_id", "")),
            event_type="final_report_json",
            artifact_path=report_json_path,
            source_reference="synint_report.json",
        )
        _record_runtime_artifact(
            ledger=evidence_ledger,
            database=investigation_db,
            run_id=str(run_metadata.get("run_id", "")),
            event_type="final_report_html",
            artifact_path=report_html_path,
            source_reference="synint_report.html",
        )
        logger.info("Execution log persisted to %s", log_file)

        report_builder_result = results.get("ReportBuilderAgent", {}).get("result", {})
        if isinstance(report_builder_result, dict):
            findings = report_builder_result.get("findings", {})
            if isinstance(findings, dict) and isinstance(findings.get("exported_files"), dict):
                logger.info("Investigation export bundle: %s", findings.get("exported_files"))

    except Exception as exc:
        try:
            if results:
                failure_report = build_report_payload(
                    results,
                    time.time() - start_time,
                    target,
                    run_metadata if "run_metadata" in locals() else {},
                    execution_model="pipeline" if (bool(args.pipeline) and not bool(args.legacy_run_all)) else "legacy_run_all",
                    pipeline_mode=args.pipeline_mode if (bool(args.pipeline) and not bool(args.legacy_run_all)) else None,
                    collection_mode=run_collection_mode if "run_collection_mode" in locals() else None,
                    pipeline_state={},
                    expected_total_agents=len(selected_agent_names),
                    report_phase="failed",
                )
                generate_json_report(failure_report, report_json_path)
                generate_html_report(failure_report, report_html_path)
                logger.info("Partial failure report persisted to %s and %s", report_json_path, report_html_path)
        except Exception as report_exc:
            logger.exception("Failed to persist partial failure report: %s", report_exc)
        logger.exception("An error occurred during SYNINT execution: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
