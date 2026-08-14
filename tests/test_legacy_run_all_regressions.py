import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

from agent_manager import AgentManager
from agents.base_agent import OSINTAgent
from agents.directory_brute_agent import DirectoryBruteAgent
from agents.report_builder_agent import ReportBuilderAgent


class ContextEchoAgent(OSINTAgent):
    requires_context = True

    def run(self, indicator):
        ctx = indicator.get("investigation_context", {}) if isinstance(indicator, dict) else {}
        return {
            "status": "ok",
            "findings": {"collection_mode_seen": ctx.get("collection_mode")},
            "risk_score": 0.0,
            "evidence_mode": "collected",
            "evidence_count": 0,
        }


class FusionSeedAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"fusion_seed": True},
            "risk_score": 0.0,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class FusionConsumerAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        results = indicator.get("agent_results", {}) if isinstance(indicator, dict) else {}
        seed = results.get("FusionSeedAgent", {}).get("result", {}).get("findings", {})
        saw_seed = bool(seed.get("fusion_seed"))
        return {
            "status": "ok",
            "findings": {"saw_fusion_seed": saw_seed},
            "risk_score": 0.0,
            "evidence_mode": "derived",
            "evidence_count": 1 if saw_seed else 0,
        }


class EvidenceScoringAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"score_ready": True},
            "risk_score": 0.0,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class ThreatAnalyzerAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        results = indicator.get("agent_results", {}) if isinstance(indicator, dict) else {}
        score_ready = results.get("EvidenceScoringAgent", {}).get("result", {}).get("findings", {}).get("score_ready", False)
        return {
            "status": "ok",
            "findings": {"saw_score_ready": bool(score_ready)},
            "risk_score": 0.0,
            "evidence_mode": "fused",
            "evidence_count": 1 if score_ready else 0,
        }


class _FakeCollector:
    engine_name = "fake"

    def fetch(self, url):
        path = (urlparse(url).path.rstrip("/") or "/").lower()
        if path == "/admin":
            return SimpleNamespace(
                status_code=200,
                final_url="https://example.com/news/story",
                collector_engine=self.engine_name,
                redirect_chain=[url, "https://example.com/news/story"],
            )
        if path == "/login":
            return SimpleNamespace(
                status_code=200,
                final_url="https://example.com/login",
                collector_engine=self.engine_name,
                redirect_chain=[url],
            )
        if path == "/dashboard":
            return SimpleNamespace(
                status_code=403,
                final_url="https://example.com/dashboard",
                collector_engine=self.engine_name,
                redirect_chain=[url],
            )
        return SimpleNamespace(
            status_code=404,
            final_url=url,
            collector_engine=self.engine_name,
            redirect_chain=[url],
        )


class LegacyRunAllRegressionTests(unittest.TestCase):
    def test_legacy_run_all_propagates_context_and_refreshes_fusion_payload(self) -> None:
        manager = AgentManager()
        for cls in [ContextEchoAgent, FusionSeedAgent, FusionConsumerAgent]:
            manager.register_agent(cls())

        results = manager.run_all("https://example.com", collection_mode="stealth")

        context_findings = results["ContextEchoAgent"]["result"]["findings"]
        consumer_findings = results["FusionConsumerAgent"]["result"]["findings"]
        self.assertEqual(context_findings.get("collection_mode_seen"), "stealth")
        self.assertTrue(consumer_findings.get("saw_fusion_seed"))
        self.assertEqual(manager.pipeline_state.get("collection_mode"), "stealth")

    def test_directory_brute_does_not_count_redirected_2xx_as_reachable(self) -> None:
        payload = {
            "target": "example.com",
            "investigation_context": {"collection_mode": "balanced"},
        }
        with patch("agents.directory_brute_agent.select_collector", return_value=(_FakeCollector(), [{"collector_engine": "fake"}])):
            result = DirectoryBruteAgent().run(payload)

        self.assertEqual(result.get("status"), "ok")
        findings = result.get("findings", {})
        reachable_paths = {item.get("path") for item in findings.get("reachable_paths", [])}
        redirects = {item.get("path") for item in findings.get("redirects", [])}

        self.assertIn("/login", reachable_paths)
        self.assertIn("/admin", redirects)
        self.assertNotIn("/admin", reachable_paths)

    def test_fusion_agents_follow_pipeline_dependency_order(self) -> None:
        manager = AgentManager()
        # Register in reverse dependency order to verify manager reorders fusion execution.
        manager.register_agent(ThreatAnalyzerAgent())
        manager.register_agent(EvidenceScoringAgent())

        results = manager.run_all("example.com", collection_mode="balanced")
        threat_findings = results["ThreatAnalyzerAgent"]["result"]["findings"]
        self.assertTrue(threat_findings.get("saw_score_ready"))

    def test_report_builder_merges_sparse_registry_with_fusion_outputs(self) -> None:
        agent = ReportBuilderAgent()
        agent_results = {
            "EntityResolutionAgent": {
                "result": {
                    "findings": {
                        "resolved_entities": [
                            {
                                "entity_id": "ent_1",
                                "entity_type": "email",
                                "canonical_name": "ops@example.com",
                                "aliases": ["ops@example.com"],
                                "confidence": 0.9,
                            }
                        ]
                    }
                }
            },
            "EvidenceScoringAgent": {
                "result": {
                    "findings": {
                        "scored_findings": [
                            {
                                "agent": "WebCrawlerAgent",
                                "tier": "direct evidence",
                                "confidence": 0.88,
                                "status": "ok",
                                "risk_score": 0.4,
                                "evidence_count": 3,
                                "evidence_mode": "collected",
                            },
                            {
                                "agent": "ContactDiscoveryAgent",
                                "tier": "derived evidence",
                                "confidence": 0.66,
                                "status": "ok",
                                "risk_score": 0.2,
                                "evidence_count": 2,
                                "evidence_mode": "derived",
                            },
                        ]
                    }
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "target": "example.com",
                "investigation_context": {"reports_dir": tmp, "collection_mode": "balanced"},
                "agent_results": agent_results,
                "evidence_registry": [
                    {
                        "id": "ev_1",
                        "source_agent": "WhoisAgent",
                        "evidence_type": "domain",
                        "value": "example.com",
                        "normalized_value": "example.com",
                        "confidence": 0.55,
                        "severity": "low",
                        "evidence_tier": "derived evidence",
                        "timestamp": "",
                        "source_reference": "whois",
                    }
                ],
                "entity_registry": [],
            }
            result = agent.run(payload)
            self.assertEqual(result.get("status"), "ok")

            exported = result.get("findings", {}).get("exported_files", {})
            evidence_csv = Path(exported.get("evidence_register_csv", ""))
            entities_json = Path(exported.get("entities_json", ""))
            summary_json = Path(exported.get("summary_json", ""))
            self.assertTrue(evidence_csv.exists())
            self.assertTrue(entities_json.exists())
            self.assertTrue(summary_json.exists())

            evidence_lines = evidence_csv.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(evidence_lines), 4)  # header + merged evidence rows
            entities_text = entities_json.read_text(encoding="utf-8")
            self.assertIn("ops@example.com", entities_text)
            summary_payload = __import__("json").loads(summary_json.read_text(encoding="utf-8"))
            self.assertEqual(summary_payload.get("product"), "SYNINT v5")
            self.assertEqual(summary_payload.get("synint_version"), "5.0.0")
            self.assertEqual(summary_payload.get("agent_count"), len(agent_results) + 1)


if __name__ == "__main__":
    unittest.main()
