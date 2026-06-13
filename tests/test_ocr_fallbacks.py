import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.ocr_ingest_agent import OCRIngestAgent


class OCRFallbackTests(unittest.TestCase):
    def test_discovers_images_from_report_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            screenshot_dir = Path(tmp) / "collection_artifacts" / "screenshots"
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            image_path = screenshot_dir / "capture.png"
            image_path.write_bytes(b"not-a-real-png")

            payload = {
                "target": "example.com",
                "investigation_context": {
                    "reports_dir": tmp,
                    "collected_files": [],
                },
            }
            agent = OCRIngestAgent()
            candidates = agent._candidate_images(payload["target"], payload["investigation_context"])
            self.assertIn(str(image_path), candidates)

    def test_returns_ok_when_no_ocr_backend_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "capture.png"
            image_path.write_bytes(b"not-a-real-png")

            payload = {
                "target": str(image_path),
                "investigation_context": {},
            }

            with patch("agents.ocr_ingest_agent.shutil.which", return_value=""):
                result = OCRIngestAgent().run(payload)

            self.assertEqual(result.get("status"), "ok")
            findings = result.get("findings", {})
            self.assertFalse(findings.get("ocr_available"))
            self.assertEqual(findings.get("ocr_backend"), "none")


if __name__ == "__main__":
    unittest.main()
