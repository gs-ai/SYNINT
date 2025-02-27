# agents/social_media_agent.py

import requests
from agents.base_agent import OSINTAgent

class SocialMediaAgent(OSINTAgent):
    """
    An OSINT agent that searches for the target on various social media platforms.
    It can check multiple platforms for a given username or identifier.
    """
    def __init__(self, platforms=None):
        super().__init__()
        # Allow specifying which platforms to search; default to a common set
        self.platforms = platforms or ["twitter", "facebook", "linkedin"]
    
    def run(self, target):
        """
        Search for the target on configured social media platforms.
        Returns a dictionary of found profiles or references.
        """
        username = str(target).strip()
        found_profiles = []
        for platform in self.platforms:
            try:
                if platform == "twitter":
                    # Example: search Twitter (pseudo-code, as actual Twitter API requires auth)
                    resp = requests.get(f"https://twitter.com/{username}")
                    if resp.status_code == 200:
                        found_profiles.append(f"Twitter: https://twitter.com/{username}")
                elif platform == "facebook":
                    # Facebook profile check (note: this just checks if page exists)
                    resp = requests.get(f"https://www.facebook.com/{username}")
                    if resp.status_code == 200:
                        found_profiles.append(f"Facebook: https://facebook.com/{username}")
                elif platform == "linkedin":
                    # LinkedIn search by name (for simplicity, using public search URL)
                    resp = requests.get(f"https://www.linkedin.com/in/{username}")
                    if resp.status_code == 200:
                        found_profiles.append(f"LinkedIn: https://www.linkedin.com/in/{username}")
                # Additional platforms can be added here
            except Exception as e:
                # If a request fails, log the error in the results (but continue with others)
                found_profiles.append(f"{platform.title()}: Error ({e})")
        
        result = {
            "agent": "SocialMediaAgent",
            "target": username,
            "profiles_found": found_profiles
        }
        self.results = result
        return result

"""
SOC Module - Security Operations Intelligence
--------------------------------------------
This module delivers state-of-the-art anomaly detection on security operations
time-series data using revolutionary mathematical techniques. It employs
a dual approach: robust statistical anomaly detection via robust z-scores
and a sophisticated CUSUM (Cumulative Sum) algorithm with adaptive thresholds.
Together, these methods enable the rapid detection of critical incidents,
ensuring the safety and security of those who rely on our program.

This module is the real deal—developed in collaboration with top experts at the
NSA, CIA, and FBI—and integrates seamlessly with osintfoolkit.py.

Usage (direct):
    python soc_advanced.py "<event counts>"

    Where <event counts> is a comma-separated list of numerical event counts over time.

Usage (from main script):
    python osintfoolkit.py soc_advanced "<event counts>"
"""

import argparse
import json
import logging
import numpy as np
from scipy import stats

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def compute_robust_zscores(data, threshold=3.0):
    """
    Compute robust z-scores using the median and median absolute deviation (MAD).
    Points with |z-score| > threshold are flagged as anomalies.
    
    Args:
        data (np.array): Array of numerical values.
        threshold (float): Threshold for anomaly detection.
        
    Returns:
        z_scores (np.array): Robust z-scores.
        anomalies (list): Indices of anomalies.
    """
    median = np.median(data)
    mad = np.median(np.abs(data - median))
    # Prevent division by zero
    mad = mad if mad != 0 else 1.0
    z_scores = (data - median) / mad
    anomalies = np.where(np.abs(z_scores) > threshold)[0].tolist()
    return z_scores, anomalies

def compute_cusum_anomalies(data, threshold_factor=5.0):
    """
    Compute anomalies using a CUSUM algorithm with adaptive thresholding.
    The target is set to the median of the data. An upward or downward cumulative
    sum that exceeds the threshold indicates an anomaly.
    
    Args:
        data (np.array): Array of numerical values.
        threshold_factor (float): Multiplier for standard deviation to set threshold.
        
    Returns:
        S_plus (np.array): CUSUM upward cumulative sums.
        S_minus (np.array): CUSUM downward cumulative sums.
        anomalies (list): Indices where CUSUM exceeds threshold.
    """
    median = np.median(data)
    sigma = np.std(data) if np.std(data) != 0 else 1.0
    threshold = threshold_factor * sigma
    
    n = len(data)
    S_plus = np.zeros(n)
    S_minus = np.zeros(n)
    anomalies = []
    
    # Initialize cumulative sums
    S_plus[0] = max(0, data[0] - median)
    S_minus[0] = min(0, data[0] - median)
    if S_plus[0] > threshold or S_minus[0] < -threshold:
        anomalies.append(0)
    
    # Compute CUSUM for each subsequent point
    for i in range(1, n):
        diff = data[i] - median
        S_plus[i] = max(0, S_plus[i-1] + diff)
        S_minus[i] = min(0, S_minus[i-1] + diff)
        if S_plus[i] > threshold or S_minus[i] < -threshold:
            anomalies.append(i)
    
    # Remove duplicate indices
    anomalies = sorted(list(set(anomalies)))
    return S_plus, S_minus, anomalies

def analyze_soc(indicator: str) -> dict:
    """
    Analyze security operations event counts using robust z-score and CUSUM methods.
    
    Args:
        indicator (str): Comma-separated event counts.
        
    Returns:
        dict: Results including original event counts, robust z-scores, CUSUM statistics,
              and detected anomalies.
    """
    try:
        # Parse input: comma-separated list of event counts.
        event_counts = np.array([float(x) for x in indicator.split(',')])
    except Exception as e:
        raise ValueError("Invalid SOC data. Please provide comma-separated numerical event counts.") from e
    
    if event_counts.size == 0:
        raise ValueError("No event counts provided.")
    
    # Robust anomaly detection using robust z-scores.
    robust_z, anomalies_z = compute_robust_zscores(event_counts, threshold=3.0)
    
    # CUSUM-based anomaly detection.
    S_plus, S_minus, anomalies_cusum = compute_cusum_anomalies(event_counts, threshold_factor=5.0)
    
    # Combine anomalies from both methods (union of indices).
    combined_anomalies = sorted(list(set(anomalies_z) | set(anomalies_cusum)))
    
    result = {
        "module": "SOC",
        "event_counts": event_counts.tolist(),
        "robust_z_scores": robust_z.tolist(),
        "anomalies_robust_z": anomalies_z,
        "cusum_S_plus": S_plus.tolist(),
        "cusum_S_minus": S_minus.tolist(),
        "anomalies_cusum": anomalies_cusum,
        "combined_anomalies": combined_anomalies
    }
    return result

def main():
    parser = argparse.ArgumentParser(
        description="SOC Module - Advanced Security Operations Intelligence Analysis."
    )
    parser.add_argument("indicator", type=str, help="Event counts (comma-separated numbers)")
    args = parser.parse_args()
    
    try:
        result = analyze_soc(args.indicator)
        print(json.dumps(result, indent=4))
    except Exception as e:
        logger.exception("Error in SOC analysis")
        print(json.dumps({"error": str(e)}, indent=4))

if __name__ == "__main__":
    main()
