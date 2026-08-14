"""OCR text extraction for images with graceful dependency handling."""

from __future__ import annotations

import shutil
import subprocess
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
        reports_dir = str(context.get("reports_dir", "")).strip() if isinstance(context, dict) else ""
        if reports_dir:
            artifact_root = Path(reports_dir) / "collection_artifacts"
            for folder in ("downloads", "screenshots"):
                base = artifact_root / folder
                if base.exists() and base.is_dir():
                    for path in base.rglob("*"):
                        if path.is_file():
                            candidates.append(str(path))
        return unique_sorted([c for c in candidates if Path(c).suffix.lower() in self.IMAGE_SUFFIXES])

    @staticmethod
    def _ocr_via_tesseract_cli(image_path: str) -> str:
        binary = shutil.which("tesseract")
        if not binary:
            return ""
        completed = subprocess.run(
            [binary, image_path, "stdout"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return completed.stdout or ""

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            images = self._candidate_images(target, context)
            if not images:
                return skipped(self.name, target, "no candidate image files for OCR")

            pytesseract_module = None
            image_module = None
            backend = "none"
            # pytesseract is only a Python wrapper; the system executable is
            # still required. Resolve it first so an installed wrapper is not
            # reported as a working OCR backend on its own.
            tesseract_binary = shutil.which("tesseract")
            if tesseract_binary:
                try:
                    import pytesseract as pytesseract_module  # type: ignore
                    from PIL import Image as image_module  # type: ignore
                    backend = "pytesseract"
                except Exception:
                    pytesseract_module = None
                    image_module = None
                    backend = "tesseract_cli"

            extracted_text: List[Dict[str, Any]] = []
            probable_entities: Dict[str, List[str]] = {
                "emails": [],
                "phones": [],
                "urls": [],
                "domains": [],
                "ips": [],
                "handles": [],
                "dates": [],
            }
            unreadable_images: List[str] = []
            image_errors: List[Dict[str, str]] = []

            for image_path in images:
                text = ""
                try:
                    if backend == "pytesseract" and pytesseract_module is not None and image_module is not None:
                        # Close image resources deterministically, including
                        # when decoding or OCR fails for an individual file.
                        with image_module.open(image_path) as image:
                            text = pytesseract_module.image_to_string(image)
                    elif backend == "tesseract_cli":
                        text = self._ocr_via_tesseract_cli(image_path)
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    image_errors.append({"path": image_path, "error": str(exc)})

                entities = extract_entities_from_text(text)
                if not text.strip():
                    unreadable_images.append(image_path)
                extracted_text.append(
                    {
                        "path": image_path,
                        "char_count": len(text),
                        "preview": text[:200],
                        "ocr_backend": backend,
                    }
                )
                for key in probable_entities:
                    probable_entities[key].extend(entities.get(key, []))

            findings = {
                "extracted_text": extracted_text,
                "text_blocks": extracted_text,
                "images_seen": images,
                "probable_entities": {key: unique_sorted(values) for key, values in probable_entities.items()},
                "ocr_backend": backend,
                "ocr_available": backend != "none",
                "unreadable_images": unique_sorted(unreadable_images),
                "image_errors": image_errors,
                "confidence_notes": [
                    "OCR confidence can vary by image quality and language support.",
                    "Image discovery includes downloaded files and collector screenshots when available.",
                    "If pytesseract is unavailable, the agent attempts the system tesseract CLI before degrading.",
                ],
            }
            evidence_count = sum(len(values) for values in findings["probable_entities"].values())
            risk = min(0.03 + evidence_count * 0.01, 0.5)
            reason = None
            if backend == "none":
                reason = "no OCR backend available; inspected image candidates and returned empty OCR findings"
            elif unreadable_images and len(unreadable_images) == len(images):
                reason = "OCR backend available but no readable text was extracted from image candidates"
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
                reason=reason,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
