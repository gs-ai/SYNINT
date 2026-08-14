"""Document ingestion and entity extraction for local evidence files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.document_utils import extract_text_from_file
from core.entity_utils import extract_entities_enhanced, extract_entities_from_text
from core.schemas import utc_now_iso
from ._pipeline import unpack_pipeline_input, unique_sorted
from .metadata_extraction import MetadataExtractionAgent
from ._shared import ok, skipped, structured_error


class DocumentIngestAgent(OSINTAgent):
    """Ingest local documents and extract structured text entities."""

    name = "DocumentIngestAgent"
    supported_target_types = ("file", "text", "json")
    requires_context = True

    SUPPORTED_HINTS = {".txt", ".csv", ".json", ".html", ".htm", ".pdf", ".docx", ".xlsx", ".pptx"}

    @staticmethod
    def _append_if_local_file(candidates: List[str], raw_path: Any) -> None:
        path = str(raw_path).strip()
        if not path:
            return
        candidate = Path(path).expanduser()
        try:
            if candidate.exists() and candidate.is_file():
                candidates.append(str(candidate.resolve()))
        except Exception:
            return

    def _candidate_files(self, target: str, context: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        self._append_if_local_file(candidates, target)

        for item in context.get("collected_files", []) if isinstance(context, dict) else []:
            self._append_if_local_file(candidates, item)

        if isinstance(context, dict):
            for agent_entry in (context.get("agent_results") or {}).values():
                result = agent_entry.get("result") if isinstance(agent_entry, dict) else None
                findings = result.get("findings") if isinstance(result, dict) else None
                if isinstance(findings, dict):
                    for key in ("downloaded_files", "files", "candidate_files", "file_links"):
                        values = findings.get(key, [])
                        if isinstance(values, list):
                            for value in values:
                                if isinstance(value, dict):
                                    for field in ("download_path", "path", "downloaded_file", "file_path"):
                                        if field in value:
                                            self._append_if_local_file(candidates, value.get(field))
                                else:
                                    self._append_if_local_file(candidates, value)

        return unique_sorted(candidates)

    def run(self, indicator: Any):
        target, context, all_results = unpack_pipeline_input(indicator)
        local_context = dict(context)
        local_context["agent_results"] = all_results

        try:
            files = self._candidate_files(target, local_context)
            if not files:
                return skipped(self.name, target, "no local files available for ingestion")

            extracted: List[Dict[str, Any]] = []
            all_emails: List[str] = []
            all_phones: List[str] = []
            all_urls: List[str] = []
            all_domains: List[str] = []
            all_ips: List[str] = []
            all_handles: List[str] = []
            all_dates: List[str] = []
            all_people: List[str] = []
            all_orgs: List[str] = []
            document_relationships: List[Dict[str, Any]] = []
            enhanced_enabled = bool(context.get("enhanced_extraction"))
            enhanced_results: List[Dict[str, Any]] = []

            metadata_agent = MetadataExtractionAgent()
            for path in files:
                file_data = extract_text_from_file(path)
                if file_data.get("status") != "ok":
                    extracted.append({"path": path, "status": "error", "error": file_data.get("error")})
                    continue

                text = str(file_data.get("text", ""))
                entities = extract_entities_from_text(text)
                if enhanced_enabled:
                    enhanced = extract_entities_enhanced(text)
                    enhanced_results.append(
                        {
                            "path": path,
                            "bitcoin_wallets": enhanced["bitcoin_wallets"],
                            "ethereum_wallets": enhanced["ethereum_wallets"],
                            "uuids": enhanced["uuids"],
                            "ssn_like_redacted": enhanced["ssn_like_redacted"],
                        }
                    )
                metadata_result = metadata_agent.run(path)
                metadata_findings = metadata_result.get("findings", {}) if isinstance(metadata_result, dict) else {}
                forensics = metadata_findings.get("document_forensics", {}) if isinstance(metadata_findings, dict) else {}
                forensic_text = "\n".join(
                    str(value)
                    for value in [
                        forensics.get("embedded_urls", []),
                        forensics.get("metadata", {}),
                    ]
                )
                forensic_entities = extract_entities_from_text(forensic_text)
                for url in forensics.get("embedded_urls", []) if isinstance(forensics, dict) else []:
                    document_relationships.append(
                        {
                            "source_path": path,
                            "target": url,
                            "relationship_type": "DOCUMENT_LINKS_TO",
                            "source_sha256": metadata_findings.get("sha256"),
                        }
                    )

                extracted.append(
                    {
                        "path": path,
                        "status": "ok",
                        "extractor": file_data.get("extractor"),
                        "char_count": file_data.get("char_count", 0),
                        "entity_counts": {k: len(v) for k, v in entities.items() if isinstance(v, list)},
                        "file_intel": metadata_findings,
                        "source_path": path,
                        "source_sha256": metadata_findings.get("sha256"),
                        "analysis_timestamp": forensics.get("analysis_timestamp") or utc_now_iso(),
                        "provenance": metadata_findings.get("provenance", {}),
                        "document_forensics": forensics,
                        # Enhanced metadata extraction is separate so established
                        # detected_entities output remains backward compatible.
                        "forensic_entities": forensic_entities,
                    }
                )

                all_emails.extend(entities.get("emails", []))
                all_phones.extend(entities.get("phones", []))
                all_urls.extend(entities.get("urls", []))
                all_domains.extend(entities.get("domains", []))
                all_ips.extend(entities.get("ips", []))
                all_handles.extend(entities.get("handles", []))
                all_dates.extend(entities.get("dates", []))
                all_people.extend(entities.get("suspected_people", []))
                all_orgs.extend(entities.get("suspected_orgs", []))

            findings = {
                "extracted_text_summary": extracted,
                "detected_entities": {
                    "emails": unique_sorted(all_emails),
                    "phones": unique_sorted(all_phones),
                    "urls": unique_sorted(all_urls),
                    "domains": unique_sorted(all_domains),
                    "ips": unique_sorted(all_ips),
                    "handles": unique_sorted(all_handles),
                    "dates": unique_sorted(all_dates),
                    "suspected_people": unique_sorted(all_people),
                    "suspected_orgs": unique_sorted(all_orgs),
                },
                "emails": unique_sorted(all_emails),
                "phones": unique_sorted(all_phones),
                "urls": unique_sorted(all_urls),
                "domains": unique_sorted(all_domains),
                "ips": unique_sorted(all_ips),
                "handles": unique_sorted(all_handles),
                "dates": unique_sorted(all_dates),
                "suspected_people": unique_sorted(all_people),
                "suspected_orgs": unique_sorted(all_orgs),
                "file_intel": extracted,
                "document_relationships": document_relationships,
                "enhanced_extraction": {
                    "enabled": enhanced_enabled,
                    "results": enhanced_results,
                    "legacy_entities_unchanged": True,
                },
                "files_processed": len(extracted),
            }

            evidence_count = (
                len(findings["emails"])
                + len(findings["phones"])
                + len(findings["urls"])
                + len(findings["domains"])
                + len(findings["ips"])
                + len(findings["handles"])
            )
            risk = min(0.03 + evidence_count * 0.01, 0.55)
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
