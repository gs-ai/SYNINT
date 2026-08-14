import tempfile
import unittest
import zipfile
from pathlib import Path

from agents.document_ingest_agent import DocumentIngestAgent
from agents.metadata_extraction import MetadataExtractionAgent
from agents.relationship_graph_agent import RelationshipGraphAgent
from agents.timeline_reconstruction_agent import TimelineReconstructionAgent


class RelationshipGraphAnalyticsTests(unittest.TestCase):
    def test_cooccurrence_is_provenance_backed_and_never_confirmed(self) -> None:
        entities = [
            {
                "entity_id": "ent_email",
                "entity_type": "email",
                "canonical_name": "ops@example.com",
                "aliases": ["ops@example.com"],
                "source_evidence_ids": ["ev_email"],
                "confidence": 0.9,
            },
            {
                "entity_id": "ent_example",
                "entity_type": "domain",
                "canonical_name": "example.com",
                "aliases": ["example.com"],
                "source_evidence_ids": ["ev_domain"],
                "confidence": 0.8,
            },
            {
                "entity_id": "ent_other",
                "entity_type": "domain",
                "canonical_name": "other.example",
                "aliases": ["other.example"],
                "source_evidence_ids": [],
                "confidence": 0.7,
            },
        ]
        payload = {
            "target": "example.com",
            "agent_results": {
                "EntityResolutionAgent": {
                    "result": {"findings": {"resolved_entities": entities}}
                },
                "ObservationAgent": {
                    "result": {
                        "timestamp": "2026-08-12T10:00:00-05:00",
                        "findings": {
                            "records": [
                                {"email": "ops@example.com", "domain": "example.com"},
                                {"email": "ops@example.com", "domain": "other.example"},
                            ]
                        },
                    }
                },
            },
        }

        result = RelationshipGraphAgent().run(payload)

        self.assertEqual(result["status"], "ok")
        edges = result["findings"]["edges"]
        self.assertEqual(len(edges), 2)
        self.assertFalse(any(edge["confirmed"] for edge in edges))
        self.assertEqual({edge["edge_type"] for edge in edges}, {"CO_OCCURS_WITH"})
        self.assertEqual({edge["relationship_status"] for edge in edges}, {"CANDIDATE"})
        self.assertTrue(all(edge["supporting_observation_ids"] for edge in edges))
        self.assertTrue(all(len(edge["supporting_observation_ids"]) == 1 for edge in edges))
        self.assertTrue(all(edge["provenance"] for edge in edges))
        # Separate logical records must not manufacture a domain-to-domain edge.
        pairs = {frozenset((edge["source"], edge["target"])) for edge in edges}
        self.assertNotIn(frozenset(("ent_example", "ent_other")), pairs)
        self.assertEqual(result["findings"]["semantics"]["confirmed_relationship_count"], 0)
        self.assertEqual(result["findings"]["analytics"]["component_count"], 1)


class DocumentForensicsTests(unittest.TestCase):
    def _make_docx_fixture(self, path: Path) -> None:
        core = """<?xml version="1.0" encoding="UTF-8"?>
        <cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc" xmlns:dcterms="urn:dcterms">
          <dc:creator>meta@example.org</dc:creator>
          <dcterms:created>2024-01-02T03:04:05-05:00</dcterms:created>
          <dcterms:modified>2024-02-03T04:05:06-05:00</dcterms:modified>
        </cp:coreProperties>"""
        document = """<w:document xmlns:w="urn:w"><w:body><w:p>
        Contact ops@example.com at https://example.com/report
        </w:p></w:body></w:document>"""
        relationships = """<Relationships><Relationship
        Target="https://evidence.example/source" TargetMode="External"/></Relationships>"""
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("docProps/core.xml", core)
            archive.writestr("word/document.xml", document)
            archive.writestr("word/_rels/document.xml.rels", relationships)

    def test_document_analysis_is_read_only_and_provenance_backed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.docx"
            self._make_docx_fixture(path)
            before = path.read_bytes()
            before_stat = path.stat()

            result = MetadataExtractionAgent().run(str(path))

            self.assertEqual(result["status"], "ok")
            findings = result["findings"]
            forensic = findings["document_forensics"]
            self.assertEqual(forensic["document_type"], "docx")
            self.assertTrue(forensic["read_only"])
            self.assertEqual(forensic["source_sha256"], findings["sha256"])
            self.assertEqual(forensic["metadata"]["author"], "meta@example.org")
            self.assertIn("https://evidence.example/source", forensic["metadata"]["external_targets"])
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mtime_ns, before_stat.st_mtime_ns)

    def test_document_ingest_keeps_enhanced_entities_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.docx"
            self._make_docx_fixture(path)

            result = DocumentIngestAgent().run(str(path))

            self.assertEqual(result["status"], "ok")
            summary = result["findings"]["extracted_text_summary"][0]
            self.assertIn("ops@example.com", result["findings"]["detected_entities"]["emails"])
            self.assertIn("meta@example.org", summary["forensic_entities"]["emails"])
            self.assertNotIn("meta@example.org", result["findings"]["detected_entities"]["emails"])
            relationships = result["findings"]["document_relationships"]
            self.assertEqual(relationships[0]["relationship_type"], "DOCUMENT_LINKS_TO")
            self.assertEqual(relationships[0]["source_sha256"], summary["source_sha256"])


class TimelineRoleTests(unittest.TestCase):
    def test_roles_offsets_and_archive_timestamps_are_preserved(self) -> None:
        payload = {
            "target": "example.com",
            "agent_results": {
                "DocumentIngestAgent": {
                    "result": {
                        "findings": {
                            "document_forensics": {
                                "metadata": {"created": "2024-01-02T03:04:05-05:00"},
                                "analysis_timestamp": "2026-08-12T15:00:00Z",
                            }
                        }
                    }
                },
                "PublisherAgent": {
                    "result": {"findings": {"published_at": "2025-03-04T12:30:00+02:00"}}
                },
                "CommonCrawlIngestAgent": {
                    "result": {"findings": {"captures": [{"timestamp": "20240105112233"}]}}
                },
            },
        }

        result = TimelineReconstructionAgent().run(payload)

        self.assertEqual(result["status"], "ok")
        timeline = result["findings"]["timeline"]
        roles = {item["role"] for item in timeline}
        self.assertTrue(
            {"DOCUMENT_CREATED", "COLLECTION_TIME", "PUBLICATION_TIME", "ARCHIVE_TIME"}.issubset(roles)
        )
        published = next(item for item in timeline if item["role"] == "PUBLICATION_TIME")
        self.assertEqual(published["timezone_offset"], "+02:00")
        self.assertEqual(published["original_timestamp"], "2025-03-04T12:30:00+02:00")
        archive = next(item for item in timeline if item["role"] == "ARCHIVE_TIME")
        self.assertIsNone(archive["timezone_offset"])
        self.assertEqual(archive["normalized_timestamp"], "2024-01-05T11:22:33")


if __name__ == "__main__":
    unittest.main()
