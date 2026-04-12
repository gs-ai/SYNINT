"""Lightweight deterministic image forensics."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

import cv2
import numpy as np

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, safe_hash_file, skipped, structured_error


class ImageForensicsAgent(OSINTAgent):
    """Compute image profile, hashes, and lightweight forensic flags."""

    name = "ImageForensicsAgent"
    supported_target_types = ("file", "text", "json")
    requires_context = True

    IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}

    def _candidate_images(self, target: str, context: Dict[str, Any]) -> List[str]:
        items: List[str] = []
        if target and Path(target).exists() and Path(target).is_file():
            items.append(target)
        for path in context.get("collected_files", []) if isinstance(context, dict) else []:
            p = str(path)
            if Path(p).exists() and Path(p).is_file():
                items.append(p)
        return unique_sorted([p for p in items if Path(p).suffix.lower() in self.IMAGE_SUFFIXES])

    def _perceptual_hash(self, image: np.ndarray) -> str:
        resized = cv2.resize(image, (32, 32), interpolation=cv2.INTER_AREA)
        dct = cv2.dct(np.float32(resized))
        low = dct[:8, :8]
        median = np.median(low)
        bits = (low > median).astype(np.uint8).flatten()
        binary = "".join(str(int(x)) for x in bits)
        return f"{int(binary, 2):016x}"

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            images = self._candidate_images(target, context)
            if not images:
                return skipped(self.name, target, "no image files available")

            image_profiles: List[Dict[str, Any]] = []
            hash_index: Dict[str, List[str]] = {}
            forensic_flags: List[str] = []

            for path in images:
                img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
                if img is None:
                    image_profiles.append({"path": path, "status": "error", "error": "unable to load image"})
                    continue

                phash = self._perceptual_hash(img)
                sha256 = safe_hash_file(path, "sha256")
                md5 = safe_hash_file(path, "md5")
                size = Path(path).stat().st_size
                height, width = img.shape
                variance = float(np.var(img))

                profile = {
                    "path": path,
                    "width": int(width),
                    "height": int(height),
                    "size_bytes": int(size),
                    "pixel_variance": round(variance, 4),
                }

                exif: Dict[str, Any] = {}
                try:
                    from PIL import Image  # type: ignore

                    pil_img = Image.open(path)
                    raw_exif = pil_img.getexif() or {}
                    exif = {str(k): str(v) for k, v in raw_exif.items()}
                except Exception:
                    exif = {}

                image_profiles.append(
                    {
                        "path": path,
                        "status": "ok",
                        "image_profile": profile,
                        "exif": exif,
                        "hashes": {
                            "sha256": sha256,
                            "md5": md5,
                            "perceptual_hash": phash,
                        },
                    }
                )

                hash_index.setdefault(phash, []).append(path)
                if size < 5 * 1024:
                    forensic_flags.append(f"Very small file size for image: {path}")
                if variance < 10.0:
                    forensic_flags.append(f"Low-variance image (possible flat/blank asset): {path}")

            duplicate_hooks = [
                {"perceptual_hash": key, "paths": value}
                for key, value in sorted(hash_index.items())
                if len(value) > 1
            ]

            findings = {
                "image_profile": image_profiles,
                "exif": [{"path": item.get("path"), "exif": item.get("exif", {})} for item in image_profiles if item.get("status") == "ok"],
                "hashes": [{"path": item.get("path"), "hashes": item.get("hashes", {})} for item in image_profiles if item.get("status") == "ok"],
                "duplicate_matching_hooks": duplicate_hooks,
                "forensic_flags": unique_sorted(forensic_flags),
            }

            evidence_count = len([item for item in image_profiles if item.get("status") == "ok"])
            risk = min(0.02 + len(findings["forensic_flags"]) * 0.05, 0.45)
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
