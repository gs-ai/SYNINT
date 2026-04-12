import tempfile
import unittest
from pathlib import Path

from agents.contradiction_detection_agent import ContradictionDetectionAgent
from agents.entity_resolution_agent import EntityResolutionAgent
from agents.evidence_scoring_agent import EvidenceScoringAgent
from agents.lead_generation_agent import LeadGenerationAgent
from agents.timeline_reconstruction_agent import TimelineReconstructionAgent
from core.exporter import write_export_bundle


class AnalysisAndExportTests(unittest.TestCase):
    def test_entity_resolution_merges_duplicate_values(self) -> None:
        payload = {
            "target": "example.com",
            "agent_results": {
                "AgentA": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "collected",
                        "evidence_count": 2,
                        "findings": {"emails": ["ops@example.com"], "urls": ["https://example.com"]},
                    }
                },
                "AgentB": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "collected",
                        "evidence_count": 2,
                        "findings": {"emails": ["ops@example.com"], "urls": ["https://example.com"]},
                    }
                },
            },
        }
        result = EntityResolutionAgent().run(payload)
        self.assertEqual(result["status"], "ok")
        resolved = result["findings"]["resolved_entities"]
        email_entities = [item for item in resolved if item["entity_type"] == "email"]
        self.assertEqual(len(email_entities), 1)

    def test_entity_resolution_classifies_ip_values_as_ip(self) -> None:
        payload = {
            "target": "example.com",
            "agent_results": {
                "DNSAgent": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "active",
                        "evidence_count": 2,
                        "findings": {
                            "base_records": {
                                "A_AAAA": {
                                    "A": ["104.21.67.75", "172.67.218.108"],
                                    "AAAA": [],
                                }
                            }
                        },
                    }
                },
            },
        }
        result = EntityResolutionAgent().run(payload)
        self.assertEqual(result["status"], "ok")
        types = {item["entity_type"] for item in result["findings"]["resolved_entities"]}
        self.assertIn("ip", types)

    def test_timeline_reconstruction_normalizes_date_tokens(self) -> None:
        payload = {
            "target": "example.com",
            "agent_results": {
                "WhoisAgent": {"result": {"findings": {"created_ts": "2024-01-01"}}},
                "DocAgent": {"result": {"findings": {"note": "Observed activity on Jan 10, 2024."}}},
            },
        }
        result = TimelineReconstructionAgent().run(payload)
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(len(result["findings"]["timeline"]), 1)
        self.assertIsNotNone(result["findings"]["earliest_event"])

    def test_contradiction_then_lead_generation_prioritizes_sensitive_files(self) -> None:
        contradiction_payload = {
            "target": "example.com",
            "agent_results": {
                "WhoisAgent": {"result": {"findings": {"registrar": "RegistrarA"}}},
                "OtherAgent": {"result": {"findings": {"registrar": "RegistrarB"}}},
            },
        }
        contradiction_result = ContradictionDetectionAgent().run(contradiction_payload)
        self.assertEqual(contradiction_result["status"], "ok")
        self.assertGreaterEqual(len(contradiction_result["findings"]["contradictions"]), 1)

        leads_payload = {
            "target": "example.com",
            "agent_results": {
                "ArchiveFileDiscoveryAgent": {
                    "result": {
                        "findings": {
                            "reachable_sensitive_files": [
                                {"url": "https://example.com/backup.zip"},
                            ]
                        }
                    }
                },
                "ContradictionDetectionAgent": {"result": contradiction_result},
            },
        }
        lead_result = LeadGenerationAgent().run(leads_payload)
        self.assertEqual(lead_result["status"], "ok")
        prioritized = lead_result["findings"]["prioritized_leads"]
        self.assertGreaterEqual(len(prioritized), 1)
        self.assertEqual(min(item["priority"] for item in prioritized), 1)

    def test_evidence_scoring_distinguishes_scaffold_vs_collected(self) -> None:
        payload = {
            "target": "example.com",
            "agent_results": {
                "CollectedAgent": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "collected",
                        "evidence_count": 4,
                        "risk_score": 0.4,
                    }
                },
                "ScaffoldAgent": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "scaffold",
                        "evidence_count": 0,
                        "risk_score": 0.1,
                    }
                },
                "EmptyCollectedAgent": {
                    "result": {
                        "status": "ok",
                        "evidence_mode": "collected",
                        "evidence_count": 0,
                        "risk_score": 0.1,
                    }
                },
                "SkippedAgent": {
                    "result": {
                        "status": "skipped",
                        "evidence_mode": "none",
                        "evidence_count": 0,
                        "risk_score": 0.0,
                    }
                },
            },
        }
        result = EvidenceScoringAgent().run(payload)
        self.assertEqual(result["status"], "ok")
        tiers = {row["agent"]: row["tier"] for row in result["findings"]["scored_findings"]}
        self.assertEqual(tiers["CollectedAgent"], "direct evidence")
        self.assertEqual(tiers["ScaffoldAgent"], "enrichment only")
        self.assertEqual(tiers["EmptyCollectedAgent"], "enrichment only")
        self.assertNotIn("SkippedAgent", tiers)

    def test_export_bundle_creates_required_files_and_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = write_export_bundle(
                base_output_dir=Path(tmp),
                context={"original_target": "example.com", "normalized_target": "example.com", "collection_mode": "balanced"},
                summary={"agent_count": 3, "evidence_count": 1, "entity_count": 1, "timeline_count": 1, "lead_count": 1},
                evidence=[
                    {
                        "id": "ev_1",
                        "source_agent": "WebCrawlerAgent",
                        "evidence_type": "url",
                        "value": "https://example.com",
                        "normalized_value": "https://example.com",
                        "confidence": 0.9,
                        "severity": "medium",
                        "evidence_tier": "direct evidence",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "source_reference": "crawl",
                    }
                ],
                entities=[{"entity_id": "ent_1", "entity_type": "domain", "canonical_name": "example.com", "confidence": 0.9}],
                timeline=[
                    {
                        "event_type": "created",
                        "raw_timestamp": "2024-01-01",
                        "normalized_timestamp": "2024-01-01T00:00:00",
                        "source_agent": "WhoisAgent",
                    }
                ],
                graph={"nodes": [{"id": "ent_1"}], "edges": [], "labels": ["domain"], "weights": []},
                leads=[{"priority": 1, "title": "Inspect backup.zip", "rationale": "Sensitive file exposure"}],
                contradictions=[],
                agent_results={"WebCrawlerAgent": {"result": {"status": "ok", "risk_score": 0.2, "evidence_mode": "collected", "evidence_count": 1}}},
            )

            required = [
                "summary_json",
                "evidence_register_csv",
                "timeline_json",
                "entities_json",
                "graph_json",
                "leads_json",
                "report_md",
            ]
            for key in required:
                self.assertTrue(Path(out[key]).exists(), f"{key} missing")

            report_text = Path(out["report_md"]).read_text(encoding="utf-8")
            self.assertIn("CASE / TARGET OVERVIEW", report_text)
            self.assertIn("EXECUTIVE SUMMARY", report_text)
            self.assertIn("AGENT EXECUTION SUMMARY", report_text)


if __name__ == "__main__":
    unittest.main()
