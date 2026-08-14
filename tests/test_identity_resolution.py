import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from agents import AGENT_ORDER, OPTIONAL_AGENT_ORDER
from agents.identity_candidate_agent import IdentityCandidateAgent
from core.identity_resolution import IdentityDecisionStore, IdentityResolver


def entity(entity_id: str, name: str, **attributes):
    return {
        "entity_id": entity_id,
        "entity_type": "person",
        "canonical_name": name,
        "attributes": attributes,
        "source_evidence_ids": [f"obs_{entity_id}"],
        "provenance": [{"source_agent": "FixtureAgent", "source_reference": entity_id}],
    }


class IdentityCandidateGenerationTests(unittest.TestCase):
    def test_optional_agent_never_changes_default_order(self) -> None:
        self.assertNotIn("IdentityCandidateAgent", AGENT_ORDER)
        self.assertIn("IdentityCandidateAgent", OPTIONAL_AGENT_ORDER)
        self.assertEqual(len(AGENT_ORDER), 46)

    def test_strong_exact_signal_creates_candidate_not_confirmation(self) -> None:
        records = [
            entity("a", "Alice Example", emails=["Alice@Example.com"]),
            entity("b", "A. Example", emails=["alice@example.com"]),
        ]
        before = deepcopy(records)

        candidates = IdentityResolver.create_candidates(records)

        self.assertEqual(records, before)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.status, "CANDIDATE")
        self.assertIsNone(candidate.score)
        self.assertEqual(candidate.supporting_signals[0].signal_type, "EXACT_NORMALIZED_EMAIL")
        self.assertTrue(candidate.supporting_observations)
        self.assertTrue(candidate.source_provenance)
        payload = candidate.to_dict()
        self.assertFalse(payload["automatic_confirmation_allowed"])
        self.assertFalse(payload["llm_confirmation_allowed"])

    def test_unrelated_entities_do_not_create_false_candidate(self) -> None:
        candidates = IdentityResolver.create_candidates(
            [
                entity("a", "Alice Example", emails=["alice@example.com"]),
                entity("b", "Bob Different", emails=["bob@different.example"]),
            ]
        )
        self.assertEqual(candidates, [])

    def test_same_name_different_people_stays_ambiguous_candidate(self) -> None:
        candidate = IdentityResolver.create_candidates(
            [
                entity("a", "Jordan Smith", verified_identifiers={"passport": "A100"}),
                entity("b", "Jordan Smith", verified_identifiers={"passport": "B200"}),
            ]
        )[0]
        self.assertEqual(candidate.status, "CONTRADICTED")
        self.assertEqual(candidate.supporting_signals[0].strength, "weak")
        self.assertEqual(candidate.contradicting_signals[0].signal_type, "CONFLICTING_VERIFIED_IDENTIFIER")

    def test_same_username_different_service_is_candidate_only(self) -> None:
        candidate = IdentityResolver.create_candidates(
            [
                entity("a", "Alpha", usernames={"github": "sharedname"}),
                entity("b", "Beta", usernames={"x": "sharedname"}),
            ]
        )[0]
        self.assertEqual(candidate.status, "CANDIDATE")
        self.assertEqual(candidate.supporting_signals[0].signal_type, "SAME_USERNAME_CROSS_SERVICE")
        self.assertEqual(candidate.supporting_signals[0].strength, "weak")

    def test_explicit_link_is_explainable_but_not_auto_confirmed(self) -> None:
        candidate = IdentityResolver.create_candidates(
            [entity("a", "Alpha", explicit_links=["b"]), entity("b", "Beta")]
        )[0]
        self.assertEqual(candidate.status, "CANDIDATE")
        self.assertEqual(candidate.supporting_signals[0].signal_type, "EXPLICIT_SOURCE_LINK")

    def test_agent_emits_candidates_without_merge(self) -> None:
        payload = {
            "target": "case-fixture",
            "investigation_context": {
                "identity_entities": [
                    entity("a", "Alice", phones=["+1 (312) 555-1212"]),
                    entity("b", "Alicia", phones=["+13125551212"]),
                ]
            },
        }
        result = IdentityCandidateAgent().run(payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"]["candidate_count"], 1)
        self.assertEqual(result["findings"]["automatic_confirmation_count"], 0)
        self.assertFalse(result["findings"]["original_entities_mutated"])


class IdentityDecisionWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = IdentityResolver.create_candidates(
            [entity("a", "Alice", emails=["alice@example.com"]), entity("b", "A", emails=["alice@example.com"])]
        )[0]

    def test_confirm_reject_and_reversal_are_explicit_and_reversible(self) -> None:
        store = IdentityDecisionStore()
        store.add_candidates([self.candidate])
        confirmed = store.decide(
            self.candidate.candidate_id,
            action="CONFIRM",
            reviewer="analyst-1",
            rationale="verified public cross-reference reviewed",
        )
        self.assertEqual(confirmed.status, "CONFIRMED")
        reversed_candidate = store.decide(
            self.candidate.candidate_id,
            action="REVERSE",
            reviewer="analyst-1",
            rationale="source retracted the cross-reference",
        )
        self.assertEqual(reversed_candidate.status, "CANDIDATE")
        self.assertEqual(len(reversed_candidate.decision_history), 2)
        rejected = store.decide(
            self.candidate.candidate_id,
            action="REJECT",
            reviewer="analyst-2",
            rationale="verified identifiers belong to different people",
        )
        self.assertEqual(rejected.status, "REJECTED")
        self.assertEqual(rejected.entity_a, "a")
        self.assertEqual(rejected.entity_b, "b")

    def test_llm_cannot_change_candidate_state(self) -> None:
        store = IdentityDecisionStore()
        store.add_candidates([self.candidate])
        with self.assertRaises(PermissionError):
            store.decide(
                self.candidate.candidate_id,
                action="CONFIRM",
                reviewer="model-output",
                rationale="model guessed same person",
                actor_type="llm",
            )
        self.assertEqual(store.get(self.candidate.candidate_id).status, "CANDIDATE")

    def test_atomic_store_round_trip_preserves_original_candidate_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity_candidates.json"
            store = IdentityDecisionStore(path)
            store.add_candidates([self.candidate])
            store.decide(
                self.candidate.candidate_id,
                action="CONFIRM",
                reviewer="operator",
                rationale="explicit reviewed evidence",
            )
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["schema_version"], 1)
            restored = IdentityDecisionStore(path).get(self.candidate.candidate_id)
            self.assertEqual(restored.status, "CONFIRMED")
            self.assertEqual(restored.entity_a, self.candidate.entity_a)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_reviewer_and_rationale_are_mandatory(self) -> None:
        store = IdentityDecisionStore()
        store.add_candidates([self.candidate])
        with self.assertRaises(ValueError):
            store.decide(
                self.candidate.candidate_id,
                action="CONFIRM",
                reviewer="",
                rationale="",
            )


class IdentityCalibrationTests(unittest.TestCase):
    def test_controlled_fixture_calibration_has_zero_auto_confirmations(self) -> None:
        fixtures = [
            ("positive", [entity("p1", "Person One", emails=["p@example.com"]), entity("p2", "P One", emails=["p@example.com"])], True),
            ("negative", [entity("n1", "North", emails=["n@example.com"]), entity("n2", "South", emails=["s@example.com"])], False),
            ("ambiguous", [entity("u1", "User A", usernames={"x": "same"}), entity("u2", "User B", usernames={"github": "same"})], True),
            ("contradictory", [entity("c1", "Case", emails=["c@example.com"], locations_by_time={"2026-01-01": "US"}), entity("c2", "Case", emails=["c@example.com"], locations_by_time={"2026-01-01": "AU"})], True),
            ("same-name", [entity("s1", "Sam Lee"), entity("s2", "Sam Lee")], True),
            ("explicit-link", [entity("e1", "One", explicit_links=["e2"]), entity("e2", "Two")], True),
        ]
        expected_candidates = 0
        observed_candidates = 0
        automatic_confirmations = 0
        false_candidates = 0
        for _, records, expected in fixtures:
            candidates = IdentityResolver.create_candidates(records)
            expected_candidates += int(expected)
            observed_candidates += int(bool(candidates))
            if candidates and not expected:
                false_candidates += 1
            automatic_confirmations += sum(candidate.status == "CONFIRMED" for candidate in candidates)
        self.assertEqual(observed_candidates, expected_candidates)
        self.assertEqual(false_candidates, 0)
        self.assertEqual(automatic_confirmations, 0)


if __name__ == "__main__":
    unittest.main()
