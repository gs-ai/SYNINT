"""OCR text extraction for images with graceful dependency handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.entity_utils import extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class OCRIngestAgent(OSINTAgent):
    """Extract OCR text from image files when local OCR tooling is available."""

    name = "OCRIngestAgent"
    supported_target_types = ("file", "text", "json")
    requires_context = True

    IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}

    def _candidate_images(self, target: str, context: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        if target and Path(target).exists() and Path(target).is_file():
            candidates.append(target)
        for item in context.get("collected_files", []) if isinstance(context, dict) else []:
            path = str(item)
            if Path(path).exists() and Path(path).is_file():
                candidates.append(path)
        return unique_sorted([c for c in candidates if Path(c).suffix.lower() in self.IMAGE_SUFFIXES])

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            images = self._candidate_images(target, context)
            if not images:
                return skipped(self.name, target, "no candidate image files for OCR")

            try:
                import pytesseract  # type: ignore
                from PIL import Image  # type: ignore
            except Exception as exc:
                return skipped(
                    self.name,
                    target,
                    f"OCR dependencies unavailable: {exc}",
                    findings={"images_seen": images, "ocr_available": False},
                )

            extracted_text: List[Dict[str, Any]] = []
            probable_entities: Dict[str, List[str]] = {
                "emails": [],
                "phones": [],
                "urls": [],
                "dates": [],
            }

            for image_path in images:
                text = pytesseract.image_to_string(Image.open(image_path))
                entities = extract_entities_from_text(text)
                extracted_text.append(
                    {
                        "path": image_path,
                        "char_count": len(text),
                        "preview": text[:200],
                    }
                )
                for key in probable_entities:
                    probable_entities[key].extend(entities.get(key, []))

            findings = {
                "extracted_text": extracted_text,
                "text_blocks": extracted_text,
                "probable_entities": {key: unique_sorted(values) for key, values in probable_entities.items()},
                "confidence_notes": [
                    "OCR confidence can vary by image quality and language support.",
                    "Text extraction executed only where OCR dependencies were available.",
                ],
            }
            evidence_count = sum(len(values) for values in findings["probable_entities"].values())
            return ok(
                self.name,
                target,
                findings,
                min(0.03 + evidence_count * 0.01, 0.5),
                evidence_mode="collected",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
