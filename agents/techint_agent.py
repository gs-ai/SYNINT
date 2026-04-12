#!/usr/bin/env python3
"""Technical intelligence agent for real host/service observations."""

from __future__ import annotations

import argparse
import json
import logging
import socket
from pathlib import Path
from typing import Dict, List

from agents.base_agent import OSINTAgent
from collectors.utils import create_safe_session
from ._shared import normalize_target, ok, structured_error

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def analyze_tech_services(indicator: str, timeout: int = 3) -> Dict[str, object]:
    """Collect observable service metadata for a host or IP."""
    target = normalize_target(str(indicator).strip())
    observations: List[str] = []

    try:
        ip_address = socket.gethostbyname(target)
    except Exception as exc:
        return {"module": "TECHINT", "status": "error", "indicator": target, "error": str(exc)}

    open_ports: List[int] = []
    for port in (22, 53, 80, 443):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip_address, port)) == 0:
                    open_ports.append(port)
            except Exception:
                continue

    http_info: Dict[str, object] = {}
    try:
        session = create_safe_session()
        response = session.get(f"https://{target}", timeout=timeout, allow_redirects=True)
        server = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")
        http_info = {
            "url": response.url,
            "http_status": response.status_code,
            "server": server,
            "x_powered_by": powered_by,
        }
        if server:
            observations.append(f"Server header exposed: {server}")
        if powered_by:
            observations.append(f"X-Powered-By header exposed: {powered_by}")
    except Exception as exc:
        http_info = {"error": str(exc)}

    return {
        "module": "TECHINT",
        "status": "ok",
        "indicator": target,
        "resolved_address": ip_address,
        "open_ports": open_ports,
        "http": http_info,
        "observations": observations,
    }


def analyze_surveillance_data(indicator: str) -> Dict[str, object]:
    """Analyze a real image file using frequency-domain metrics."""
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except Exception:
        return {
            "module": "SURVEILLANCE",
            "status": "error",
            "indicator": str(indicator),
            "error": "opencv-python and numpy are required for surveillance mode",
        }

    image_path = Path(indicator)
    if not image_path.exists():
        return {
            "module": "SURVEILLANCE",
            "status": "error",
            "indicator": str(image_path),
            "error": "Image path does not exist",
        }

    image = cv2.imread(str(image_path), cv2.IMREAD_GRAYSCALE)
    if image is None:
        return {
            "module": "SURVEILLANCE",
            "status": "error",
            "indicator": str(image_path),
            "error": "Unable to load image as grayscale",
        }

    dft = np.fft.fft2(np.float32(image))
    dft_shift = np.fft.fftshift(dft)
    magnitude_spectrum = 20 * np.log(np.abs(dft_shift) + 1)

    height, width = image.shape
    dominant_feature = float(np.mean(magnitude_spectrum))
    spectral_std_dev = float(np.std(magnitude_spectrum))

    return {
        "module": "SURVEILLANCE",
        "status": "ok",
        "indicator": str(image_path),
        "image_dimensions": {"width": width, "height": height},
        "dominant_feature": dominant_feature,
        "spectral_std_dev": spectral_std_dev,
    }


class TechIntAgent(OSINTAgent):
    """Technical intelligence agent with host and surveillance analysis modes."""
    name = "TechIntAgent"
    supported_target_types = ("domain", "ip")

    def run(self, indicator: str, mode: str = "tech") -> Dict[str, object]:
        try:
            normalized_indicator = normalize_target(indicator) if mode == "tech" else indicator
            if mode == "surveillance":
                raw = analyze_surveillance_data(indicator)
            else:
                raw = analyze_tech_services(normalized_indicator)
            if raw.get("status") == "error":
                return structured_error(self.name, indicator, raw.get("error", "techint failure"))

            findings = {k: v for k, v in raw.items() if k not in {"module", "status", "indicator"}}
            evidence_count = 0
            if isinstance(findings.get("open_ports"), list):
                evidence_count += len(findings.get("open_ports", []))
            if isinstance(findings.get("observations"), list):
                evidence_count += len(findings.get("observations", []))
            risk = min(0.03 + evidence_count * 0.02, 0.4)
            result = ok(
                self.name,
                normalized_indicator if mode == "tech" else indicator,
                findings,
                risk,
                evidence_mode="active" if evidence_count else "passive",
                evidence_count=evidence_count,
            )
            self.results = result
            return result
        except Exception as exc:
            logger.exception("Error during TECHINT analysis: %s", exc)
            return structured_error(self.name, indicator, exc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TECHINT Module - host/service intelligence")
    parser.add_argument("indicator", type=str, help="Host, IP, or image path")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["tech", "surveillance"],
        default="tech",
        help="Select mode: 'tech' for host/service analysis, 'surveillance' for image analysis",
    )
    args = parser.parse_args()

    print(json.dumps(TechIntAgent().run(args.indicator, mode=args.mode), indent=4))
