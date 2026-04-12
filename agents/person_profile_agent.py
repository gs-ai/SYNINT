"""Person-centric profile consolidation with direct-vs-inferred separation."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.entity_utils import extract_entities_from_text
from ._pipeline import collect_all_text, iter_findings, unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class PersonProfileAgent(OSINTAgent):
    """Consolidate people-oriented findings from prior agents."""

    name = "PersonProfileAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior results for profile consolidation")

        try:
            aliases: List[str] = []
            usernames: List[str] = []
            locations: List[str] = []
            organizations: List[str] = []
            contact_points: List[str] = []
            associated_entities: List[str] = []
            direct_evidence: List[str] = []
            inferred_evidence: List[str] = []

            for _, findings in iter_findings(agent_results):
                for key in ["suspected_people", "aliases"]:
                    value = findings.get(key)
                    if isinstance(value, list):
                        aliases.extend(str(v) for v in value)
                for key in ["generated_variants", "matched_variants", "usernames"]:
                    value = findings.get(key)
                    if isinstance(value, list):
                        usernames.extend(str(v) for v in value)
                for key in ["suspected_orgs", "organizations"]:
                    value = findings.get(key)
                    if isinstance(value, list):
                        organizations.extend(str(v) for v in value)
                for key in ["emails", "phones"]:
                    value = findings.get(key)
                    if isinstance(value, list):
                        contact_points.extend(str(v) for v in value)
                if isinstance(findings.get("profile_mentions"), list):
                    direct_evidence.extend(str(v) for v in findings["profile_mentions"])

            corpus = "\n".join(collect_all_text(agent_results))
            extracted = extract_entities_from_text(corpus)
            aliases.extend(extracted.get("suspected_people", []))
            organizations.extend(extracted.get("suspected_orgs", []))
            locations.extend([item for item in extracted.get("addresses", [])])
            associated_entities.extend(extracted.get("urls", []))
            contact_points.extend(extracted.get("emails", []))
            contact_points.extend(extracted.get("phones", []))

            if aliases and not direct_evidence:
                inferred_evidence.append("Person-like names inferred from collected text patterns.")
            if usernames:
                inferred_evidence.append("Username variants inferred from observed handles and naming patterns.")

            profile_summary = {
                "alias_count": len(unique_sorted(aliases)),
                "username_count": len(unique_sorted(usernames)),
                "organization_count": len(unique_sorted(organizations)),
                "contact_point_count": len(unique_sorted(contact_points)),
                "direct_evidence_count": len(direct_evidence),
                "inferred_evidence_count": len(inferred_evidence),
            }

            findings = {
                "profile_summary": profile_summary,
                "aliases": unique_sorted(aliases),
                "usernames": unique_sorted(usernames),
                "locations": unique_sorted(locations),
                "organizations": unique_sorted(organizations),
                "contact_points": unique_sorted(contact_points),
                "associated_entities": unique_sorted(associated_entities),
                "direct_evidence": unique_sorted(direct_evidence),
                "inferred_evidence": unique_sorted(inferred_evidence),
            }

            evidence_count = len(findings["direct_evidence"]) + len(findings["contact_points"])
            risk = min(0.02 + len(findings["associated_entities"]) * 0.01 + len(findings["direct_evidence"]) * 0.03, 0.55)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="derived" if evidence_count else "heuristic",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
