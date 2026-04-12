from pathlib import Path
from agents.base_agent import OSINTAgent
from ._shared import cheap_file_type, ok, safe_hash_file, skipped, structured_error

class MetadataExtractionAgent(OSINTAgent):
    """
    File metadata and leakage triage agent.

    Capabilities:
    - file stats
    - sha256/md5 hashes
    - extension/type inference
    - suspicious filename token detection
    - basic metadata risk triage
    """
    name = "MetadataExtractionAgent"
    supported_target_types = ("file",)

    SUSPICIOUS_TOKENS = [
        "secret", "password", "credential", "confidential", "internal",
        "private", "backup", "export", "dump", "leak"
    ]

    def run(self, target):
        try:
            p = Path(target)
            if not p.exists() or not p.is_file():
                return skipped(
                    self.name,
                    target,
                    "target is not a local file",
                    findings={"exists": False},
                )

            st = p.stat()
            lowered = p.name.lower()
            hit_tokens = [t for t in self.SUSPICIOUS_TOKENS if t in lowered]
            ftype = cheap_file_type(str(p))

            findings = {
                "exists": True,
                "path": str(p.resolve()),
                "name": p.name,
                "suffix": p.suffix.lower(),
                "file_type": ftype,
                "size_bytes": st.st_size,
                "created_ts": getattr(st, "st_ctime", None),
                "modified_ts": getattr(st, "st_mtime", None),
                "sha256": safe_hash_file(str(p), "sha256"),
                "md5": safe_hash_file(str(p), "md5"),
                "suspicious_filename_tokens": hit_tokens,
            }

            risk = 0.05
            if hit_tokens:
                risk += min(len(hit_tokens) * 0.1, 0.4)
            if st.st_size > 25 * 1024 * 1024:
                risk += 0.1
            if ftype in {"pdf", "docx", "xlsx", "pptx"}:
                risk += 0.1

            findings["enrichment_hooks"] = {
                "exif_ready": ftype == "image",
                "pdf_metadata_ready": ftype == "pdf",
                "office_metadata_ready": ftype in {"docx", "xlsx", "pptx"},
            }

            return ok(self.name, target, findings, risk)
        except Exception as e:
            return structured_error(self.name, target, e)
