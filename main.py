#!/usr/bin/env python3
"""
Main script for SYNINT OSINT Framework

This script registers all available agents with the AgentManager and executes them concurrently
on a specified target. Aggregated results are output in JSON format to the console and exported
to both a JSON report and an HTML report. The reports include metadata such as generation date/time,
target, total execution time, and error counts.
"""

import json
import sys
import logging
import time
from datetime import datetime

from agent_manager import AgentManager
from agents.cybint_agent import CybintAgent
from agents.social_media_agent import SocialMediaAgent
from agents.whois_agent import WhoisAgent
from agents.ids_agent import IDSAgent
from agents.mitm_agent import MITMAgent
from agents.siem_agent import SIEMAgent
from agents.techint_agent import TechIntAgent
from agents.threat_analyzer_agent import ThreatAnalyzerAgent

# Configure logging.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def generate_json_report(results, overall_time, target, filename="synint_report.json"):
    """Generate a JSON report from the aggregated results including metadata."""
    try:
        report = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "total_execution_time": overall_time,
            "results": results
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        logger.info(f"JSON report successfully saved to {filename}")
    except Exception as e:
        logger.exception(f"Failed to generate JSON report: {e}")

def generate_html_report(results, overall_time, target, filename="synint_report.html"):
    """Generate an enhanced HTML report from the aggregated results including metadata."""
    try:
        total_agents = len(results)
        error_count = sum(1 for r in results.values() if "error" in r["result"])
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SYNINT Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
        th {{ background-color: #f2f2f2; text-align: left; }}
        pre {{ background-color: #f8f8f8; padding: 10px; border: 1px solid #ddd; }}
        .error {{ background-color: #ffdddd; }}
        .collapsible {{
            background-color: #f2f2f2;
            color: #444;
            cursor: pointer;
            padding: 10px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
        }}
        .active, .collapsible:hover {{
            background-color: #ddd;
        }}
        .content {{
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <h1>SYNINT Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Report Generated:</strong> {gen_time}</p>
    <p><strong>Total Agents Executed:</strong> {total_agents}</p>
    <p><strong>Total Execution Time:</strong> {overall_time:.2f} seconds</p>
    <p><strong>Error Count:</strong> {error_count}</p>
    <button onclick="downloadJSON()">Download JSON Report</button>
    <br/><br/>
    <table>
        <tr>
            <th>Agent</th>
            <th>Execution Time (seconds)</th>
            <th>Result</th>
        </tr>
"""
        for agent, data in results.items():
            error_class = "error" if "error" in data["result"] else ""
            result_json = json.dumps(data["result"], indent=2)
            html += f"""        <tr class="{error_class}">
            <td>{agent}</td>
            <td>{data["execution_time"]:.2f}</td>
            <td>
                <button class="collapsible">View Details</button>
                <div class="content">
                    <pre>{result_json}</pre>
                </div>
            </td>
        </tr>
"""
        html += """    </table>
    <script>
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {{
            coll[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "block";
                }}
            }});
        }}
        function downloadJSON() {{
            var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(document.getElementById("jsonData").textContent);
            var downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", "synint_report.json");
            document.body.appendChild(downloadAnchorNode);
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        }}
    </script>
    <pre id="jsonData" style="display:none;">""" + json.dumps(results, indent=4) + """</pre>
</body>
</html>"""
        with open(filename, "w") as f:
            f.write(html)
        logger.info(f"HTML report successfully saved to {filename}")
    except Exception as e:
        logger.exception(f"Failed to generate HTML report: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    logger.info(f"Starting SYNINT analysis for target: {target}")
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
        logger.info(f"Total execution time: {overall_time:.2f} seconds")
        
        print(json.dumps(results, indent=4))
        
        generate_json_report(results, overall_time, target)
        generate_html_report(results, overall_time, target)
        
        # Optional: Uncomment if PDF export is required and WeasyPrint is installed.
        # from weasyprint import HTML
        # HTML(filename="synint_report.html").write_pdf("synint_report.pdf")
        # logger.info("PDF report successfully saved to synint_report.pdf")
        
    except Exception as e:
        logger.exception(f"An error occurred during SYNINT execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
