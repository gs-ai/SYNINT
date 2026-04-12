import os
import tempfile
import unittest
from pathlib import Path

from agents.document_ingest_agent import DocumentIngestAgent
from collectors.utils import write_collection_artifacts


class DownloadPipelineTests(unittest.TestCase):
    def test_write_collection_artifacts_persists_download_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = write_collection_artifacts(
                artifact_root=Path(tmp) / "collection_artifacts",
                url="https://example.com/files/report.pdf",
                final_url="https://example.com/files/report.pdf",
                collector_engine="static_http",
                collection_mode="stealth",
                status_code=200,
                content="%PDF-1.4",
                body_bytes=b"%PDF-1.4\nmock",
                content_type="application/pdf",
                content_disposition='attachment; filename="report.pdf"',
                rendered=False,
                headers={"Content-Type": "application/pdf"},
            )
            self.assertIn("download", out)
            self.assertTrue(Path(out["download"]).exists())
            self.assertIn("/downloads/", out["download"])

    def test_document_ingest_accepts_relative_downloaded_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = Path.cwd()
            os.chdir(tmp)
            try:
                data_dir = Path("data")
                data_dir.mkdir(parents=True, exist_ok=True)
                sample = data_dir / "sample.txt"
                sample.write_text("Contact: ops@example.com", encoding="utf-8")

                payload = {
                    "target": "example.com",
                    "investigation_context": {},
                    "agent_results": {
                        "WebCrawlerAgent": {
                            "result": {
                                "findings": {
                                    "downloaded_files": [str(sample)],
                                }
                            }
                        }
                    },
                }
                result = DocumentIngestAgent().run(payload)
                self.assertEqual(result.get("status"), "ok")
                self.assertGreaterEqual(result.get("findings", {}).get("files_processed", 0), 1)
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
