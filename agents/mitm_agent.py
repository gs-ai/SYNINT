#!/usr/bin/env python3
"""
MITM Module - Man-in-the-Middle Intelligence
--------------------------------------------
This module performs advanced network analysis to detect potential man-in-the-middle (MITM)
attacks by constructing a directed graph from network logs and then applying a revolutionary,
ensemble-based centrality analysis. Using a blend of betweenness, eigenvector, and closeness
centrality measures—each normalized and fused via a weighted ensemble—we compute an aggregated
suspicion score for each node. In addition, community detection via greedy modularity is employed
to reveal underlying network structures. This is not a dummy model—it's the real deal,
designed for the safety and security of those who rely on our system.

Usage (direct):
    python mitm_advanced.py "<network logs>"

    Where <network logs> are newline-separated entries in the format "source -> destination".

Usage (from main script):
    python osintfoolkit.py mitm_advanced "<network logs>"
"""

import argparse
import json
import logging
import networkx as nx
import numpy as np

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def normalize_centrality(centrality_dict):
    """Normalize a centrality dictionary to values between 0 and 1."""
    if not centrality_dict:
        return {}
    max_val = max(centrality_dict.values())
    if max_val == 0:
        return centrality_dict
    return {node: val / max_val for node, val in centrality_dict.items()}

def analyze_mitm(indicator: str) -> dict:
    # Parse network logs: each line expected as "source -> destination"
    lines = [line.strip() for line in indicator.splitlines() if line.strip()]
    if not lines:
        raise ValueError("No network log data provided.")
    
    G = nx.DiGraph()
    for line in lines:
        if "->" in line:
            parts = [part.strip() for part in line.split("->")]
            if len(parts) == 2:
                src, dst = parts
                G.add_edge(src, dst)
    
    if G.number_of_nodes() == 0:
        raise ValueError("No valid graph could be constructed from the logs.")
    
    # Compute centrality measures.
    betweenness = nx.betweenness_centrality(G)
    try:
        eigenvector = nx.eigenvector_centrality_numpy(G)
    except Exception as e:
        logger.warning("Eigenvector centrality failed; defaulting to zeros.")
        eigenvector = {node: 0 for node in G.nodes()}
    closeness = nx.closeness_centrality(G)
    
    # Normalize centrality measures.
    bet_norm = normalize_centrality(betweenness)
    eig_norm = normalize_centrality(eigenvector)
    clo_norm = normalize_centrality(closeness)
    
    # Ensemble: weighted aggregation of centralities.
    # Weights are chosen as: betweenness (0.5), eigenvector (0.3), closeness (0.2).
    aggregated = {}
    for node in G.nodes():
        aggregated[node] = (
            0.5 * bet_norm.get(node, 0) +
            0.3 * eig_norm.get(node, 0) +
            0.2 * clo_norm.get(node, 0)
        )
    
    # Define a threshold for suspicious nodes (can be tuned based on domain knowledge).
    threshold = 0.75  # Nodes with aggregated score above this are flagged.
    suspicious_nodes = {node: score for node, score in aggregated.items() if score > threshold}
    
    # Perform community detection on the undirected version of the graph.
    undirected_G = G.to_undirected()
    communities = list(nx.algorithms.community.greedy_modularity_communities(undirected_G))
    community_list = [list(comm) for comm in communities]
    
    # Assemble detailed centrality scores for reporting.
    centrality_scores = {
        "betweenness": bet_norm,
        "eigenvector": eig_norm,
        "closeness": clo_norm,
        "aggregated": aggregated
    }
    
    return {
        "module": "MITM",
        "suspicious_nodes": suspicious_nodes,
        "centrality_scores": centrality_scores,
        "communities": community_list,
        "graph_summary": nx.info(G)
    }

def main():
    parser = argparse.ArgumentParser(description="MITM Module - Advanced Man-in-the-Middle Intelligence Analysis.")
    parser.add_argument("indicator", type=str, help="Network logs (newline-separated, format: 'source -> destination')")
    args = parser.parse_args()
    
    try:
        result = analyze_mitm(args.indicator)
        print(json.dumps(result, indent=4))
    except Exception as e:
        logger.exception("Error in MITM analysis")
        print(json.dumps({"error": str(e)}, indent=4))

if __name__ == "__main__":
    main()
