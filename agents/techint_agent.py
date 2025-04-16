#!/usr/bin/env python3
"""
TECHINT Module - Technical Intelligence
-----------------------------------------
Advanced version with mathematically optimized risk scoring and feature extraction.
"""

import argparse
import json
import logging
import cv2
import numpy as np
import scipy.special  # for the sigmoid (expit) function
from math import sqrt
from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def advanced_techint(indicator: str) -> dict:
    logger.info("Performing advanced TECHINT analysis with optimization...")
    try:
        # Convert indicator to a numerical value via its hash
        indicator_val = abs(hash(indicator)) % 1000
        # Compute a risk score using a sigmoid function; adjust parameters as needed
        risk_score = float(scipy.special.expit((indicator_val - 500) / 50.0))
        # Compute a complementary metric: the “risk dispersion”
        dispersion = sqrt(indicator_val) / 50.0
        return {
            "module": "TECHINT",
            "status": "optimized",
            "indicator": indicator,
            "risk_score": risk_score,
            "dispersion": dispersion
        }
    except Exception as e:
        logger.error(f"Error in TECHINT analysis: {e}")
        return {"error": str(e)}

def advanced_surveillance_data(indicator: str) -> dict:
    logger.info("Performing advanced surveillance analysis using Fourier transforms...")
    try:
        # Load grayscale image for robust intensity analysis
        image = cv2.imread(indicator, cv2.IMREAD_GRAYSCALE)
        if image is None:
            error_msg = f"Unable to load image: {indicator}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Compute the 2D DFT and shift the zero frequency component to the center
        dft = np.fft.fft2(np.float32(image))
        dft_shift = np.fft.fftshift(dft)
        # Compute the magnitude spectrum and normalize
        magnitude_spectrum = 20 * np.log(np.abs(dft_shift) + 1)
        # Extract a dominant feature as the mean of the spectrum
        dominant_feature = float(np.mean(magnitude_spectrum))
        # Adjust risk based on deviation from the median using sigmoid scaling
        median_val = float(np.median(magnitude_spectrum))
        std_val = float(np.std(magnitude_spectrum)) + 1e-6  # prevent division by zero
        risk_score = float(scipy.special.expit((dominant_feature - median_val) / std_val))
        
        # Additionally, simulate a spatial coherence metric using the image's dimensions
        height, width = image.shape
        spatial_coherence = sqrt(width * height) / (width + height)
        
        return {
            "module": "SURVEILLANCE",
            "status": "optimized",
            "indicator": indicator,
            "image_dimensions": {"width": width, "height": height},
            "dominant_feature": dominant_feature,
            "risk_score": risk_score,
            "spatial_coherence": spatial_coherence
        }
    except Exception as e:
        logger.error(f"Error in surveillance analysis: {e}")
        return {"error": str(e)}

class TechIntAgent(OSINTAgent):
    """
    TechIntAgent - An agent for performing technical intelligence analysis.
    Supports two modes:
      - "tech": for textual technical indicator analysis.
      - "surveillance": for image analysis.
    """
    def run(self, indicator: str, mode: str = "tech") -> dict:
        try:
            if mode == "surveillance":
                result = advanced_surveillance_data(indicator)
            else:
                result = advanced_techint(indicator)
            self.results = result
            return result
        except Exception as e:
            logger.exception(f"Error during TECHINT analysis: {e}")
            return {"error": str(e)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TECHINT Module - Optimized and secure.")
    parser.add_argument("indicator", type=str, help="Technical indicator or image file path")
    parser.add_argument("--mode", type=str, choices=["tech", "surveillance"], default="tech",
                        help="Select mode: 'tech' for technical analysis, 'surveillance' for image analysis")
    args = parser.parse_args()
    
    agent = TechIntAgent()
    result = agent.run(args.indicator, mode=args.mode)
    print(json.dumps(result, indent=4))
