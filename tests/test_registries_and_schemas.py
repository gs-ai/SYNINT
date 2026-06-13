import unittest

from core.registries import EntityRegistry, EvidenceRegistry
from core.schemas import AgentEnvelope, Entity, EvidenceItem


class RegistriesAndSchemasTests(unittest.TestCase):
    def test_evidence_registry_merges_duplicate_evidence(self) -> None:
        registry = EvidenceRegistry()
        evidence_id = registry.add(
            EvidenceItem(
                source_agent="AgentA",
                evidence_type="domain",
                value="Example.com",
                normalized_value="example.com",
                confidence=0.4,
                tags=["seed"],
                supporting_context={"sources": ["a"]},
            )
        )
        registry.add(
            EvidenceItem(
                source_agent="AgentA",
                evidence_type="domain",
                value="example.com",
                normalized_value="example.com",
                confidence=0.8,
                tags=["pivot"],
                supporting_context={"sources": ["b"]},
                id=evidence_id,
            )
        )

        merged = registry.get(evidence_id)
        assert merged is not None
        self.assertEqual(merged.confidence, 0.8)
        self.assertEqual(merged.tags, ["pivot", "seed"])
        self.assertEqual(merged.supporting_context["sources"], ["a", "b"])

    def test_entity_registry_merges_aliases_evidence_and_attributes(self) -> None:
        registry = EntityRegistry()
        entity_id = registry.add(
            Entity(
                entity_type="domain",
                canonical_name="example.com",
                aliases=["www.example.com"],
                attributes={"source_agent": "AgentA", "notes": ["seed"]},
                source_evidence_ids=["ev_1"],
                confidence=0.5,
            )
        )
        registry.add(
            Entity(
                entity_type="domain",
                canonical_name="example.com",
                aliases=["portal.example.com"],
                attributes={"notes": ["pivot"], "category": "target"},
                source_evidence_ids=["ev_2"],
                confidence=0.9,
                entity_id=entity_id,
            )
        )

        merged = registry.get(entity_id)
        assert merged is not None
        self.assertEqual(merged.confidence, 0.9)
        self.assertIn("www.example.com", merged.aliases)
        self.assertIn("portal.example.com", merged.aliases)
        self.assertEqual(merged.source_evidence_ids, ["ev_1", "ev_2"])
        self.assertEqual(merged.attributes["notes"], ["pivot", "seed"])

    def test_agent_envelope_normalizes_runtime_fields(self) -> None:
        envelope = AgentEnvelope(
            status="OK",
            agent=" TestAgent ",
            target="example.com",
            findings={"x": 1},
            risk_score=5,
            evidence_mode="Collected",
            evidence_count=-3,
            execution_time=-1,
        )
        payload = envelope.to_dict()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["agent"], "TestAgent")
        self.assertEqual(payload["risk_score"], 1.0)
        self.assertEqual(payload["evidence_mode"], "collected")
        self.assertEqual(payload["evidence_count"], 0)
        self.assertEqual(payload["execution_time"], 0.0)


if __name__ == "__main__":
    unittest.main()
