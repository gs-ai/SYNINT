"""Aggregate and normalize contact artifacts with source attribution."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.entity_utils import extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class ContactDiscoveryAgent(OSINTAgent):
    """Harvest contact intelligence from collected pages/documents and prior findings."""

    name = "ContactDiscoveryAgent"
    supported_target_types = ("text", "json", "domain", "url")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not agent_results:
            return skipped(self.name, target, "no prior agent results to aggregate")

        try:
            emails: List[str] = []
            phones: List[str] = []
            addresses: List[str] = []
            domains: List[str] = []
            handles: List[str] = []
            contact_pages: List[str] = []
            source_map: Dict[str, Dict[str, List[str]]] = {}
            corpus_chunks: List[str] = []

            for agent_name, entry in sorted(agent_results.items()):
                result = entry.get("result") if isinstance(entry, dict) else entry
                if not isinstance(result, dict):
                    continue
                if str(result.get("status", "")).lower() != "ok":
                    continue

                findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
                if not findings:
                    continue

                reason = str(result.get("reason") or "").lower()
                if bool(findings.get("email_hypothesis_only")) or "generated addresses" in reason:
                    # Skip hypothesis-only generated mailbox lists.
                    continue

                agent_emails: List[str] = []
                agent_phones: List[str] = []
                agent_addresses: List[str] = []
                agent_domains: List[str] = []
                agent_handles: List[str] = []

                for key in ["emails", "contact_emails"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        agent_emails.extend(str(v).lower() for v in values)

                for key in ["phones", "contact_phones"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        agent_phones.extend(str(v) for v in values)

                values = findings.get("addresses")
                if isinstance(values, list):
                    agent_addresses.extend(str(v) for v in values)
                values = findings.get("domains")
                if isinstance(values, list):
                    agent_domains.extend(str(v).lower() for v in values)
                values = findings.get("handles")
                if isinstance(values, list):
                    agent_handles.extend(str(v) for v in values)

                if isinstance(findings.get("contact_artifacts"), dict):
                    artifacts = findings.get("contact_artifacts", {})
                    if isinstance(artifacts.get("emails"), list):
                        agent_emails.extend(str(v).lower() for v in artifacts["emails"])
                    if isinstance(artifacts.get("phones"), list):
                        agent_phones.extend(str(v) for v in artifacts["phones"])
                    if isinstance(artifacts.get("domains"), list):
                        agent_domains.extend(str(v).lower() for v in artifacts["domains"])
                    if isinstance(artifacts.get("handles"), list):
                        agent_handles.extend(str(v) for v in artifacts["handles"])

                pages = findings.get("discovered_urls")
                if isinstance(pages, list):
                    for url in pages:
                        lurl = str(url).lower()
                        if "contact" in lurl or "about" in lurl or "support" in lurl:
                            contact_pages.append(str(url))

                if agent_emails or agent_phones or agent_addresses:
                    source_map[agent_name] = {
                        "emails": unique_sorted(agent_emails),
                        "phones": unique_sorted(agent_phones),
                        "addresses": unique_sorted(agent_addresses),
                        "domains": unique_sorted(agent_domains),
                        "handles": unique_sorted(agent_handles),
                    }

                emails.extend(agent_emails)
                phones.extend(agent_phones)
                addresses.extend(agent_addresses)
                domains.extend(agent_domains)
                handles.extend(agent_handles)

                evidence_mode = str(result.get("evidence_mode", "none")).lower()
                if evidence_mode in {"collected", "active", "fused"}:
                    for key, value in findings.items():
                        if key.startswith("generated_"):
                            continue
                        if key in {"content_fingerprint_summary", "whois_data"}:
                            continue
                        if isinstance(value, str):
                            text = value.strip()
                            if text and len(text) <= 20000:
                                corpus_chunks.append(text)
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, str):
                                    text = item.strip()
                                    if text and len(text) <= 500:
                                        corpus_chunks.append(text)

            corpus = "\n".join(corpus_chunks)
            entities = extract_entities_from_text(corpus) if corpus else {}
            emails.extend(entities.get("emails", []))
            phones.extend(entities.get("phones", []))
            addresses.extend(entities.get("addresses", []))
            domains.extend(entities.get("domains", []))
            handles.extend(entities.get("handles", []))

            structured_contacts = [
                {"type": "email", "value": value} for value in unique_sorted(emails)
            ] + [
                {"type": "phone", "value": value} for value in unique_sorted(phones)
            ] + [
                {"type": "address", "value": value} for value in unique_sorted(addresses)
            ] + [
                {"type": "domain", "value": value} for value in unique_sorted(domains)
            ] + [
                {"type": "handle", "value": value} for value in unique_sorted(handles)
            ]

            findings = {
                "emails": unique_sorted(emails),
                "phones": unique_sorted(phones),
                "addresses": unique_sorted(addresses),
                "domains": unique_sorted(domains),
                "handles": unique_sorted(handles),
                "contact_pages": unique_sorted(contact_pages),
                "structured_contacts": structured_contacts,
                "source_map": source_map,
            }
            evidence_count = len(findings["structured_contacts"])
            risk = min(0.03 + evidence_count * 0.01, 0.45)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
