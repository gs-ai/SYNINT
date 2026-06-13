import unittest
import tempfile
from pathlib import Path

from agent_manager import AgentManager
from agents.base_agent import OSINTAgent
from core import CheckpointStore, EvidenceLedger, InvestigationDatabase


class WebCrawlerAgent(OSINTAgent):
    requires_context = True

    def run(self, target):
        return {
            "status": "ok",
            "findings": {
                "discovered_urls": ["https://example.com", "https://example.com/contact"],
                "emails": ["intel@example.com"],
                "phones": ["+13125551212"],
                "file_links": [],
            },
            "risk_score": 0.2,
            "evidence_mode": "collected",
            "evidence_count": 3,
        }


class ContactDiscoveryAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"emails": ["intel@example.com"], "phones": ["+13125551212"]},
            "risk_score": 0.1,
            "evidence_mode": "collected",
            "evidence_count": 2,
        }


class EntityResolutionAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {
                "resolved_entities": [
                    {
                        "entity_type": "email",
                        "canonical_name": "intel@example.com",
                        "aliases": ["intel@example.com"],
                        "attributes": {"source": "test"},
                        "source_evidence_ids": [],
                        "confidence": 0.9,
                    }
                ]
            },
            "risk_score": 0.1,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class RelationshipGraphAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {
                "nodes": [{"id": "ent_1", "label": "intel@example.com", "entity_type": "email"}],
                "edges": [],
            },
            "risk_score": 0.05,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class TimelineReconstructionAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {
                "timeline": [
                    {
                        "event_type": "created",
                        "raw_timestamp": "2024-01-01",
                        "normalized_timestamp": "2024-01-01T00:00:00",
                        "source_agent": "stub",
                    }
                ]
            },
            "risk_score": 0.05,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class EvidenceScoringAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"scored_findings": [{"agent": "WebCrawlerAgent", "tier": "direct evidence", "confidence": 0.9}]},
            "risk_score": 0.2,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class ContradictionDetectionAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"contradictions": []},
            "risk_score": 0.01,
            "evidence_mode": "derived",
            "evidence_count": 0,
        }


class LeadGenerationAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"prioritized_leads": [{"priority": 1, "title": "Inspect contact endpoint", "rationale": "Direct contact artifact"}]},
            "risk_score": 0.05,
            "evidence_mode": "derived",
            "evidence_count": 1,
        }


class ThreatAnalyzerAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"threat_picture": {"summary": "stub"}},
            "risk_score": 0.3,
            "evidence_mode": "fused",
            "evidence_count": 1,
        }


class ReportBuilderAgent(OSINTAgent):
    consume_all_results = True

    def run(self, indicator):
        return {
            "status": "ok",
            "findings": {"exported_files": {"report_md": "reports/investigations/test/report.md"}},
            "risk_score": 0.01,
            "evidence_mode": "collected",
            "evidence_count": 1,
        }


class FileProducingAgent(OSINTAgent):
    requires_context = True

    def run(self, indicator):
        ctx = indicator.get("investigation_context", {}) if isinstance(indicator, dict) else {}
        reports_dir = Path(str(ctx.get("reports_dir", "")))
        artifact = reports_dir / "collected.txt"
        artifact.write_text("artifact", encoding="utf-8")
        return {
            "status": "ok",
            "findings": {"downloaded_files": [str(artifact)]},
            "risk_score": 0.0,
            "evidence_mode": "collected",
            "evidence_count": 1,
        }


class PipelineOrchestrationTests(unittest.TestCase):
    def test_quick_pipeline_populates_registries_and_state(self) -> None:
        manager = AgentManager()
        for cls in [
            WebCrawlerAgent,
            ContactDiscoveryAgent,
            EntityResolutionAgent,
            RelationshipGraphAgent,
            TimelineReconstructionAgent,
            EvidenceScoringAgent,
            ContradictionDetectionAgent,
            LeadGenerationAgent,
            ThreatAnalyzerAgent,
            ReportBuilderAgent,
        ]:
            manager.register_agent(cls())

        results = manager.run_pipeline("example.com", pipeline_mode="quick")
        self.assertIn("WebCrawlerAgent", results)
        self.assertIn("ReportBuilderAgent", results)
        self.assertGreater(len(manager.evidence_registry.to_list()), 0)
        self.assertGreater(len(manager.entity_registry.to_list()), 0)
        self.assertEqual(manager.pipeline_state.get("pipeline_mode"), "quick")
        self.assertEqual(manager.pipeline_state.get("collection_mode"), "low_noise")

    def test_pipeline_persists_checkpoint_ledger_and_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = AgentManager(
                run_id="run-test-1",
                checkpoint_store=CheckpointStore(Path(tmp) / "synint_checkpoint.json"),
                evidence_ledger=EvidenceLedger(Path(tmp) / "chain_of_custody.jsonl"),
                investigation_db=InvestigationDatabase(Path(tmp) / "investigation.sqlite"),
            )
            for cls in [
                FileProducingAgent,
                WebCrawlerAgent,
                ContactDiscoveryAgent,
                EntityResolutionAgent,
                RelationshipGraphAgent,
                TimelineReconstructionAgent,
                EvidenceScoringAgent,
                ContradictionDetectionAgent,
                LeadGenerationAgent,
                ThreatAnalyzerAgent,
                ReportBuilderAgent,
            ]:
                manager.register_agent(cls())

            results = manager.run_all("example.com", run_reports_dir=tmp, collection_mode="balanced")
            self.assertIn("FileProducingAgent", results)
            self.assertTrue((Path(tmp) / "synint_checkpoint.json").exists())
            self.assertTrue((Path(tmp) / "investigation.sqlite").exists())
            self.assertTrue((Path(tmp) / "chain_of_custody.jsonl").exists())
            ledger_text = (Path(tmp) / "chain_of_custody.jsonl").read_text(encoding="utf-8")
            self.assertIn("collected_file", ledger_text)


if __name__ == "__main__":
    unittest.main()
