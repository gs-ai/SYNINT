"""Correlate files by hash, metadata, naming, and embedded indicators."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.document_utils import extract_text_from_file
from core.entity_utils import extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, safe_hash_file, skipped, structured_error


class FileRelationshipAgent(OSINTAgent):
    """Build file relationship clusters for evidence bundles."""

    name = "FileRelationshipAgent"
    supported_target_types = ("file", "text", "json")
    requires_context = True

    def _files(self, target: str, context: Dict[str, Any]) -> List[str]:
        files: List[str] = []
        if target and Path(target).exists() and Path(target).is_file():
            files.append(target)
        for p in context.get("collected_files", []) if isinstance(context, dict) else []:
            path = str(p)
            if Path(path).exists() and Path(path).is_file():
                files.append(path)
        return unique_sorted(files)

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            files = self._files(target, context)
            if len(files) < 2:
                return skipped(self.name, target, "need at least two files for relationship analysis")

            file_profiles: Dict[str, Dict[str, Any]] = {}
            for path in files:
                text_payload = extract_text_from_file(path)
                text = str(text_payload.get("text", ""))
                entities = extract_entities_from_text(text)
                profile = {
                    "path": path,
                    "sha256": safe_hash_file(path, "sha256"),
                    "md5": safe_hash_file(path, "md5"),
                    "name": Path(path).name.lower(),
                    "emails": entities.get("emails", []),
                    "urls": entities.get("urls", []),
                    "domains": entities.get("domains", []),
                    "phones": entities.get("phones", []),
                }
                file_profiles[path] = profile

            related_files: List[Dict[str, Any]] = []
            relationship_types: List[str] = []
            supporting_evidence: List[Dict[str, Any]] = []

            file_list = sorted(file_profiles)
            for i in range(len(file_list)):
                for j in range(i + 1, len(file_list)):
                    a = file_profiles[file_list[i]]
                    b = file_profiles[file_list[j]]
                    reasons: List[str] = []

                    if a["sha256"] == b["sha256"]:
                        reasons.append("same_sha256")
                    if a["md5"] == b["md5"]:
                        reasons.append("same_md5")

                    name_tokens_a = set(a["name"].replace(".", " ").replace("_", " ").replace("-", " ").split())
                    name_tokens_b = set(b["name"].replace(".", " ").replace("_", " ").replace("-", " ").split())
                    overlap_tokens = sorted(name_tokens_a & name_tokens_b)
                    if overlap_tokens:
                        reasons.append("name_token_overlap")

                    shared_emails = sorted(set(a["emails"]) & set(b["emails"]))
                    shared_urls = sorted(set(a["urls"]) & set(b["urls"]))
                    shared_domains = sorted(set(a["domains"]) & set(b["domains"]))
                    if shared_emails:
                        reasons.append("shared_email")
                    if shared_urls:
                        reasons.append("shared_url")
                    if shared_domains:
                        reasons.append("shared_domain")

                    if reasons:
                        related_files.append(
                            {
                                "file_a": a["path"],
                                "file_b": b["path"],
                                "relationship_types": reasons,
                            }
                        )
                        relationship_types.extend(reasons)
                        supporting_evidence.append(
                            {
                                "pair": [a["path"], b["path"]],
                                "shared_emails": shared_emails,
                                "shared_urls": shared_urls,
                                "shared_domains": shared_domains,
                                "name_token_overlap": overlap_tokens,
                            }
                        )

            findings = {
                "related_files": related_files,
                "relationship_types": unique_sorted(relationship_types),
                "cluster_summary": {
                    "input_file_count": len(files),
                    "related_pair_count": len(related_files),
                },
                "supporting_evidence": supporting_evidence,
            }

            if not related_files:
                return skipped(self.name, target, "no meaningful file relationships detected", findings=findings)

            return ok(
                self.name,
                target,
                findings,
                min(0.03 + len(related_files) * 0.02, 0.6),
                evidence_mode="derived",
                evidence_count=len(related_files),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
