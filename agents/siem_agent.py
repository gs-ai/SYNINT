#!/usr/bin/env python3
"""
SIEM Module - Security Information and Event Management Intelligence
--------------------------------------------------------------------
This module performs revolutionary correlation of SIEM log events using advanced mathematical
techniques. It converts newline-separated SIEM logs into a TF‑IDF feature space, reduces the
dimensionality using Truncated Singular Value Decomposition (SVD) to capture latent semantics,
and automatically estimates the optimal number of clusters based on cumulative explained variance.
Agglomerative clustering is then applied to reveal underlying threat patterns in security logs.
"""

import json
import logging
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.cluster import AgglomerativeClustering
from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2):
    """
    Estimate the optimal number of clusters based on cumulative explained variance from SVD.
    
    Args:
        svd (TruncatedSVD): A fitted TruncatedSVD object.
        threshold (float): Cumulative explained variance ratio threshold.
        min_clusters (int): Minimum number of clusters.
    
    Returns:
        int: Estimated optimal number of clusters.
    """
    cumulative_variance = np.cumsum(svd.explained_variance_ratio_)
    optimal_clusters = np.searchsorted(cumulative_variance, threshold) + 1
    optimal_clusters = max(optimal_clusters, min_clusters)
    logger.info(f"Estimated optimal clusters: {optimal_clusters} (threshold: {threshold})")
    return optimal_clusters

def analyze_siem(indicator: str) -> dict:
    # Parse SIEM log events.
    events = [line.strip() for line in indicator.splitlines() if line.strip()]
    if len(events) < 2:
        logger.info("SIEM analysis skipped: Insufficient SIEM log data.")
        return {"skipped": "SIEM analysis skipped: At least 2 SIEM log events are required for clustering."}
    # Convert log events into TF‑IDF features.
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(events)
    
    # Reduce dimensionality using Truncated SVD (LSA) to capture latent semantics.
    n_components = min(100, X.shape[1] - 1) if X.shape[1] > 1 else 1
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    X_reduced = svd.fit_transform(X)
    
    # Estimate the optimal number of clusters based on cumulative explained variance.
    optimal_clusters = estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2)
    
    # Apply Agglomerative Clustering with the estimated number of clusters.
    clustering = AgglomerativeClustering(n_clusters=optimal_clusters)
    labels = clustering.fit_predict(X_reduced)
    
    # Organize events into clusters.
    clusters = {}
    for label, event in zip(labels, events):
        clusters.setdefault(str(label), []).append(event)
    
    return {
        "module": "SIEM",
        "n_clusters": optimal_clusters,
        "clusters": clusters
    }

    """
    Args:
        indicator (str): Newline-separated SIEM log events.
    
    Returns:
        dict: A dictionary with the SIEM module analysis results, including clusters.
    """
    # Parse SIEM log events.
    events = [line.strip() for line in indicator.splitlines() if line.strip()]
    if not events:
        raise ValueError("No SIEM log events provided.")
    
    # Convert log events into TF‑IDF features.
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(events)
    
    # Reduce dimensionality using Truncated SVD (LSA) to capture latent semantics.
    n_components = min(100, X.shape[1] - 1) if X.shape[1] > 1 else 1
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    X_reduced = svd.fit_transform(X)
    
    # Estimate the optimal number of clusters based on cumulative explained variance.
    optimal_clusters = estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2)
    
    # Apply Agglomerative Clustering with the estimated number of clusters.
    clustering = AgglomerativeClustering(n_clusters=optimal_clusters)
    labels = clustering.fit_predict(X_reduced)
    
    # Organize events into clusters.
    clusters = {}
    for label, event in zip(labels, events):
        clusters.setdefault(str(label), []).append(event)
    
    return {
        "module": "SIEM",
        "n_clusters": optimal_clusters,
        "clusters": clusters
    }

class SIEMAgent(OSINTAgent):
    """
    SIEMAgent - An agent for analyzing SIEM log events through advanced vector space modeling and clustering.
    """
    def run(self, indicator: str) -> dict:
        return analyze_siem(indicator)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SIEM Module - Advanced Security Information and Event Management Analysis.")
    parser.add_argument("indicator", type=str, help="SIEM log events (newline-separated)")
    args = parser.parse_args()
    
    result = SIEMAgent().run(args.indicator)
    print(json.dumps(result, indent=4))
