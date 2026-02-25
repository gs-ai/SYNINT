#!/usr/bin/env python3
"""
Main script for SYNINT OSINT Framework.

Registers all available agents with AgentManager, executes them concurrently
on a specified target, and exports JSON/HTML reports.
"""

import json
import logging
import sys
import time
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict

from agent_manager import AgentManager
from agents.cybint_agent import CybintAgent
from agents.ids_agent import IDSAgent
from agents.mitm_agent import MITMAgent
from agents.siem_agent import SIEMAgent
from agents.social_media_agent import SocialMediaAgent
from agents.techint_agent import TechIntAgent
from agents.threat_analyzer_agent import ThreatAnalyzerAgent
from agents.whois_agent import WhoisAgent
from runtime_fingerprint import build_run_metadata

# Configure logging.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

REPORTS_DIR = Path("reports")
REPORT_JSON = REPORTS_DIR / "synint_report.json"
REPORT_HTML = REPORTS_DIR / "synint_report.html"


def _has_error(agent_entry: Dict[str, Any]) -> bool:
    """Return True when an agent entry contains an error-shaped result."""
    result = agent_entry.get("result") if isinstance(agent_entry, dict) else None
    return isinstance(result, dict) and "error" in result


def build_report_payload(
    results: Dict[str, Dict[str, Any]],
    overall_time: float,
    target: str,
    run_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Build one canonical report payload used by all outputs."""
    total_agents = len(results)
    error_count = sum(1 for entry in results.values() if _has_error(entry))

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "total_execution_time": overall_time,
        "total_agents_executed": total_agents,
        "error_count": error_count,
        "run_metadata": run_metadata,
        "results": results,
    }


def generate_json_report(report: Dict[str, Any], filename: Path = REPORT_JSON) -> None:
    """Generate a JSON report from the aggregated results including metadata."""
    try:
        filename.parent.mkdir(parents=True, exist_ok=True)
        with filename.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4)
        logger.info("JSON report successfully saved to %s", filename)
    except Exception as exc:
        logger.exception("Failed to generate JSON report: %s", exc)


def generate_html_report(report: Dict[str, Any], filename: Path = REPORT_HTML) -> None:
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
        html_parts.append(
            f"    <p><strong>Total Agents Executed:</strong> {int(report.get('total_agents_executed', len(results)))}</p>\n"
        )
        html_parts.append(
            f"    <p><strong>Total Execution Time:</strong> {float(report.get('total_execution_time', 0.0)):.2f} seconds</p>\n"
        )
        html_parts.append(f"    <p><strong>Error Count:</strong> {int(report.get('error_count', 0))}</p>\n")
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
            <th>Execution Time (seconds)</th>
            <th>Result</th>
        </tr>
"""
        )

        for agent, data in results.items():
            error_class = "error" if _has_error(data) else ""
            execution_time = float(data.get("execution_time", 0.0))
            result_json = escape(json.dumps(data.get("result", {}), indent=2))
            html_parts.append(
                f"""        <tr class="{error_class}">
            <td>{escape(str(agent))}</td>
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


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    logger.info("Starting SYNINT analysis for target: %s", target)
    start_time = time.time()

    try:
        manager = AgentManager()
        manager.register_agent(CybintAgent())
        manager.register_agent(SocialMediaAgent())
        manager.register_agent(WhoisAgent())
        manager.register_agent(IDSAgent())
        manager.register_agent(MITMAgent())
        manager.register_agent(SIEMAgent())
        manager.register_agent(TechIntAgent())
        manager.register_agent(ThreatAnalyzerAgent())

        logger.info("All agents registered successfully.")

        results = manager.run_all(target)
        overall_time = time.time() - start_time
        logger.info("Total execution time: %.2f seconds", overall_time)

        run_metadata = build_run_metadata()
        report = build_report_payload(results, overall_time, target, run_metadata)

        print(json.dumps(results, indent=4))
        generate_json_report(report)
        generate_html_report(report)

    except Exception as exc:
        logger.exception("An error occurred during SYNINT execution: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
