#!/usr/bin/env python3
"""
SIEM Module - Security Information and Event Management Intelligence
--------------------------------------------------------------------
Correlates SIEM log events via:
  - TF-IDF feature extraction
  - Truncated SVD (latent semantics)
  - Agglomerative clustering

Behavior:
  - If fewer than 2 events are provided, returns a structured "skipped" response
    instead of raising exceptions.
"""

import json
import logging
import warnings
from typing import Any, Dict, List

import numpy as np
from sklearn.cluster import AgglomerativeClustering
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _estimate_optimal_clusters(
    svd: TruncatedSVD, threshold: float = 0.90, min_clusters: int = 2
) -> int:
    ratios = getattr(svd, "explained_variance_ratio_", None)
    if ratios is None or len(ratios) == 0 or np.any(np.isnan(ratios)):
        return min_clusters
    cumulative = np.cumsum(ratios)
    k = int(np.searchsorted(cumulative, threshold) + 1)
    return max(k, min_clusters)


class SIEMAgent(OSINTAgent):
    """
    SIEMAgent - clusters newline-separated SIEM events.

    Input contract:
      indicator: newline-separated SIEM log lines (strings)

    If the framework is invoked with a domain as indicator, this agent will return
    a "skipped" result because clustering requires event lines.
    """

    def analyze_siem(self, indicator: str) -> Dict[str, Any]:
        try:
            events = [line.strip() for line in str(indicator).splitlines() if line.strip()]
            if len(events) < 2:
                return {
                    "module": "SIEM",
                    "status": "skipped",
                    "reason": "Insufficient SIEM events for clustering. Provide at least 2 newline-separated log lines.",
                    "n_events": len(events),
                }

            vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
            X = vectorizer.fit_transform(events)

            # Guard: SVD requires at least 2 features to be meaningful.
            n_features = X.shape[1]
            if n_features < 2:
                return {
                    "module": "SIEM",
                    "status": "skipped",
                    "reason": "Insufficient feature space for semantic clustering (too few unique tokens).",
                    "n_events": len(events),
                    "n_features": int(n_features),
                }

            n_components = min(100, n_features - 1)
            svd = TruncatedSVD(n_components=n_components, random_state=42)
            # Tiny or near-identical datasets can trigger harmless variance warnings.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message="invalid value encountered in divide",
                    category=RuntimeWarning,
                )
                X_reduced = svd.fit_transform(X)

            # Agglomerative requires at least 2 samples.
            if X_reduced.shape[0] < 2:
                return {
                    "module": "SIEM",
                    "status": "skipped",
                    "reason": "Insufficient samples after reduction.",
                    "n_events": len(events),
                }

            k = _estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2)
            k = min(k, len(events))  # cannot have more clusters than samples

            clustering = AgglomerativeClustering(n_clusters=k)
            labels = clustering.fit_predict(X_reduced)

            clusters: Dict[str, List[str]] = {}
            for label, event in zip(labels, events):
                clusters.setdefault(str(int(label)), []).append(event)

            return {
                "module": "SIEM",
                "status": "ok",
                "n_events": len(events),
                "n_clusters": int(k),
                "clusters": clusters,
            }

        except Exception as exc:
            logger.exception("SIEM analysis error")
            return {"module": "SIEM", "status": "error", "error": str(exc)}

    def run(self, indicator: str) -> Dict[str, Any]:
        return self.analyze_siem(indicator)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SIEM Module - clustering for SIEM event lines.")
    parser.add_argument("indicator", type=str, help="SIEM log events (newline-separated)")
    args = parser.parse_args()

    print(json.dumps(SIEMAgent().run(args.indicator), indent=4))
