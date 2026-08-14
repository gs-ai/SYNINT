import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from agents.wayback_analysis import WaybackAnalysisAgent
from agent_manager import AgentManager


class WaybackWaymoreAgentTests(unittest.TestCase):
    def test_discovers_waymore_next_to_active_python_when_path_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_python_dir = Path(tmp) / "bin"
            fake_python_dir.mkdir(parents=True, exist_ok=True)
            fake_python = fake_python_dir / "python"
            fake_waymore = fake_python_dir / "waymore"
            fake_python.write_text("", encoding="utf-8")
            fake_waymore.write_text("", encoding="utf-8")

            with (
                patch("agents.wayback_analysis.shutil.which", return_value=""),
                patch("agents.wayback_analysis.sys.executable", str(fake_python)),
            ):
                binary = WaybackAnalysisAgent()._waymore_binary()

        self.assertEqual(Path(binary).resolve(), fake_waymore.resolve())

    def test_uses_archive_fallback_when_waymore_unavailable(self) -> None:
        payload = {
            "target": "https://example.com",
            "investigation_context": {},
        }
        fake_response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: [["original", "statuscode", "mimetype", "timestamp"], ["https://example.com/archive", "200", "text/html", "20240101"]],
        )
        with (
            # Mock the agent boundary so an installed sibling venv executable
            # can never turn this unit test into a live external invocation.
            patch.object(WaybackAnalysisAgent, "_waymore_binary", return_value=""),
            patch("agents.wayback_analysis.requests.get", return_value=fake_response),
        ):
            result = WaybackAnalysisAgent().run(payload)

        self.assertEqual(result.get("status"), "ok")
        self.assertEqual(result.get("findings", {}).get("collection_backend"), "archive_cdx_fallback")
        self.assertEqual(result.get("findings", {}).get("archived_url_count"), 1)

    def test_runs_waymore_without_api_key_dependent_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "target": "https://example.com/path?q=1#frag",
                "investigation_context": {
                    "reports_dir": tmp,
                    "collection_mode": "balanced",
                },
            }

            def _fake_run(cmd, check, capture_output, text, timeout):
                self.assertIn("-mode", cmd)
                self.assertIn("U", cmd)
                self.assertIn("-xvt", cmd)
                self.assertIn("-xix", cmd)
                self.assertNotIn("-xav", cmd)
                self.assertNotIn("-xus", cmd)
                self.assertNotIn("-xga", cmd)
                out_path = Path(cmd[cmd.index("-oU") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    "\n".join(
                        [
                            "https://example.com/",
                            "https://example.com/admin",
                            "https://cdn.example.com/backup.zip",
                        ]
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

            with (
                patch("agents.wayback_analysis.shutil.which", return_value="/usr/local/bin/waymore"),
                patch("agents.wayback_analysis.subprocess.run", side_effect=_fake_run),
            ):
                result = WaybackAnalysisAgent().run(payload)

            self.assertEqual(result.get("status"), "ok")
            findings = result.get("findings", {})
            self.assertEqual(findings.get("archived_url_count"), 3)
            self.assertIn("virustotal", findings.get("provider_exclusions", []))
            self.assertIn("intelx", findings.get("provider_exclusions", []))
            self.assertGreaterEqual(len(findings.get("sensitive_archived_urls", [])), 1)
            self.assertGreaterEqual(len(findings.get("archive_file_candidates", [])), 1)

    def test_wayback_access_denied_triggers_commoncrawl_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "target": "https://example.com",
                "investigation_context": {
                    "reports_dir": tmp,
                    "collection_mode": "balanced",
                },
            }
            calls = {"n": 0}

            def _fake_run(cmd, check, capture_output, text, timeout):
                calls["n"] += 1
                out_path = Path(cmd[cmd.index("-oU") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                if calls["n"] == 1:
                    out_path.write_text("", encoding="utf-8")
                    return subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout="",
                        stderr="Wayback - [ ERR ] Unable to get links from Wayback Machine (archive.org): Access Denied.",
                    )
                self.assertIn("-xwm", cmd)
                out_path.write_text("https://example.com/archive/page\n", encoding="utf-8")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            with (
                patch("agents.wayback_analysis.shutil.which", return_value="/usr/local/bin/waymore"),
                patch("agents.wayback_analysis.subprocess.run", side_effect=_fake_run),
            ):
                result = WaybackAnalysisAgent().run(payload)

            self.assertEqual(result.get("status"), "ok")
            findings = result.get("findings", {})
            self.assertEqual(findings.get("archived_url_count"), 1)
            execution = findings.get("execution", {})
            self.assertTrue(execution.get("fallback_attempted"))
            self.assertEqual(calls["n"], 2)


class PipelineStageCoverageTests(unittest.TestCase):
    def test_wayback_analysis_present_in_all_pipeline_modes(self) -> None:
        manager = AgentManager()
        for mode in ["quick", "standard", "deep"]:
            stages = manager._stage_plan(mode)
            flat = [agent for _, group in stages for agent in group]
            self.assertIn("WaybackAnalysisAgent", flat)


if __name__ == "__main__":
    unittest.main()
