# base_agent.py – Abstract base class for all agents
from abc import ABC, abstractmethod

class OSINTAgent(ABC):
    """Abstract base class for OSINT agents in SYNINT."""
    def __init__(self):
        self.results = None  # to store results after run
    @abstractmethod
    def run(self, target):
        """Each subclass implements this method to gather/analysis data on the target."""
        pass

# agent_manager.py – Manages registration and execution of agents
from concurrent.futures import ThreadPoolExecutor, as_completed

class AgentManager:
    """Orchestrates multiple OSINT agents and manages their execution."""
    def __init__(self):
        self.agents = []
    def register_agent(self, agent: OSINTAgent):
        """Register an agent instance to be managed."""
        self.agents.append(agent)
    def remove_agent(self, agent: OSINTAgent):
        """Deregister an agent."""
        if agent in self.agents:
            self.agents.remove(agent)
    def run_all(self, target):
        """
        Run all registered agents against the given target in parallel.
        Returns a dictionary mapping agent class names to their result.
        """
        results = {}
        if not self.agents:
            return results
        # Execute each agent's run() in parallel threads
        with ThreadPoolExecutor(max_workers=len(self.agents)) as executor:
            future_to_agent = {executor.submit(agent.run, target): agent for agent in self.agents}
            for future in as_completed(future_to_agent):
                agent = future_to_agent[future]
                agent_name = type(agent).__name__
                try:
                    result = future.result()
                except Exception as e:
                    result = {"error": str(e)}
                results[agent_name] = result
        return results
    def run_agent(self, agent_name: str, target):
        """
        Run a specific registered agent by class name on the target.
        Returns that agent's result (or None if no such agent is registered).
        """
        for agent in self.agents:
            if type(agent).__name__ == agent_name:
                try:
                    return agent.run(target)
                except Exception as e:
                    return {"error": str(e)}
        return None

# social_media_agent.py – Searches social media platforms for the target username
import requests

class SocialMediaAgent(OSINTAgent):
    """Searches for the target on configured social media platforms via direct HTTP requests."""
    def __init__(self, platforms=None):
        super().__init__()
        # Default platforms to check; can be customized
        self.platforms = platforms or ["twitter", "facebook", "linkedin"]
    def run(self, target):
        username = str(target).strip()
        found_profiles = []
        # Use a common browser User-Agent to avoid blocking or detection
        headers = {"User-Agent": "Mozilla/5.0"}
        for platform in self.platforms:
            try:
                if platform == "twitter":
                    resp = requests.get(f"https://twitter.com/{username}", headers=headers, timeout=5)
                    if resp.status_code == 200:
                        found_profiles.append(f"Twitter: https://twitter.com/{username}")
                elif platform == "facebook":
                    resp = requests.get(f"https://www.facebook.com/{username}", headers=headers, timeout=5)
                    if resp.status_code == 200:
                        found_profiles.append(f"Facebook: https://facebook.com/{username}")
                elif platform == "linkedin":
                    resp = requests.get(f"https://www.linkedin.com/in/{username}", headers=headers, timeout=5)
                    if resp.status_code == 200:
                        found_profiles.append(f"LinkedIn: https://www.linkedin.com/in/{username}")
                # Additional platforms can be added similarly...
            except Exception as e:
                # If any request fails (network issue, etc.), record the error (stealth: do not halt entirely)
                found_profiles.append(f"{platform.title()}: Error ({e})")
        result = {
            "agent": "SocialMediaAgent",
            "target": username,
            "profiles_found": found_profiles
        }
        self.results = result
        return result

# whois_agent.py – Performs a WHOIS lookup on the target domain
import subprocess

class WhoisAgent(OSINTAgent):
    """Performs a WHOIS lookup on a domain or IP by calling the system 'whois' command."""
    def run(self, target):
        target_str = str(target).strip()
        try:
            output = subprocess.check_output(["whois", target_str], timeout=5)
            data = output.decode('utf-8', errors='ignore')
        except Exception as e:
            data = f"Error during whois lookup: {e}"
        result = {
            "agent": "WhoisAgent",
            "target": target_str,
            "whois_data": data
        }
        self.results = result
        return result

# cybint_agent.py – Cyber Intelligence scanning agent (no external APIs, uses math heuristics)
import socket, math, random

def transform_target(target: str):
    """
    Resolve domain to IP (if possible) and compute a hash-based intelligence score for the target.
    """
    try:
        ip_addr = socket.gethostbyname(target)
    except Exception:
        ip_addr = target  # if resolution fails, use the original target string
    # Compute a pseudo-random intelligence score (0 to 1) based on the target string
    prime_mod = 101111
    accum = 0
    for ch in target:
        accum = (accum * 31 + ord(ch)) % prime_mod
    score = accum / prime_mod
    return {"original": target, "transformed_ip": ip_addr, "intelligence_score": score}

def advanced_vuln_analysis(preprocessed: dict):
    """
    Simulate an advanced vulnerability analysis using heuristic probabilities.
    Returns a list of vulnerabilities with assigned severity if they're "detected."
    """
    int_score = preprocessed.get("intelligence_score", 0)
    # Example vulnerability database
    vulnerabilities_db = [
        {"vulnerability": "Potential RCE (Remote Code Execution)", "base_severity": 9.3},
        {"vulnerability": "Weak TLS/SSL Cipher", "base_severity": 7.1},
        {"vulnerability": "Directory Traversal", "base_severity": 6.3},
        {"vulnerability": "Open Redirect", "base_severity": 5.0}
    ]
    results = []
    for vuln in vulnerabilities_db:
        # The chance of detecting each vulnerability increases with int_score and the base severity
        probability = (vuln["base_severity"] / 10.0) * (1 + int_score)
        if random.random() < probability:
            # Assign a severity level label based on base_severity
            if vuln["base_severity"] >= 9.0:
                severity = "Critical"
            elif vuln["base_severity"] >= 7.0:
                severity = "High"
            elif vuln["base_severity"] >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
            results.append({
                "vulnerability": vuln["vulnerability"],
                "severity": severity
            })
    if not results:
        # If none meet the probability threshold, report no vulnerabilities found
        results.append({
            "vulnerability": "No vulnerabilities detected with current heuristics",
            "severity": "Info"
        })
    return results

def real_vulnerability_scan(target: str):
    """
    Perform the complete cyber-intelligence scan on the target:
    returns a dict with resolved address, score, and potential vulnerabilities.
    """
    info = transform_target(target)
    vulns = advanced_vuln_analysis(info)
    return {
        "module": "CYBINT",
        "target": target,
        "resolved_address": info.get("transformed_ip"),
        "intelligence_score": info.get("intelligence_score"),
        "vulnerabilities": vulns
    }

class CybintAgent(OSINTAgent):
    """Analyzes a target IP/domain for vulnerabilities (cyber intelligence)."""
    def run(self, target):
        target_str = str(target).strip()
        try:
            result = real_vulnerability_scan(target_str)
        except Exception as e:
            result = {"error": str(e)}
        self.results = result
        return result

# ids_agent.py – IDS log anomaly detection agent using machine learning
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

def compute_adaptive_contamination(X_reduced, random_state=42):
    """
    Estimate an appropriate contamination (outlier proportion) for anomaly detection based on data distribution.
    Uses an initial IsolationForest to gauge anomaly scores.
    """
    iso = IsolationForest(random_state=random_state)
    iso.fit(X_reduced)
    scores = iso.decision_function(X_reduced)
    median_score = float(np.median(scores))
    mad = float(np.median(np.abs(scores - median_score)))  # median absolute deviation
    threshold = median_score - 1.5 * mad
    contamination = float(np.mean(scores < threshold))
    # Clamp the contamination between 0.01 and 0.5 for realism
    if contamination < 0.01: contamination = 0.01
    if contamination > 0.5: contamination = 0.5
    return contamination

def analyze_ids(log_data: str):
    """
    Perform ensemble anomaly detection on IDS logs.
    Returns a dict with anomalies and detector outputs.
    """
    logs = [line.strip() for line in log_data.splitlines() if line.strip()]
    if not logs:
        raise ValueError("No IDS log data provided.")
    # Feature extraction: TF-IDF on log lines
    vectorizer = TfidfVectorizer(stop_words='english', max_features=500)
    X = vectorizer.fit_transform(logs)  # sparse matrix
    X_dense = X.toarray()
    # Dimensionality reduction for efficiency
    n_components = min(100, X_dense.shape[1] - 1) if X_dense.shape[1] > 1 else 1
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    X_reduced = svd.fit_transform(X_dense)
    # Adaptive contamination estimation
    contamination = compute_adaptive_contamination(X_reduced)
    # Initialize detectors with the estimated contamination
    iso_forest = IsolationForest(contamination=contamination, random_state=42)
    iso_forest.fit(X_reduced)
    preds_if = iso_forest.predict(X_reduced)        # 1 for normal, -1 for anomaly
    lof = LocalOutlierFactor(n_neighbors=20, contamination=contamination)
    preds_lof = lof.fit_predict(X_reduced)          # 1 for normal, -1 for anomaly
    oc_svm = OneClassSVM(nu=contamination, kernel="rbf", gamma='scale')
    oc_svm.fit(X_reduced)
    preds_svm = oc_svm.predict(X_reduced)           # 1 for normal, -1 for anomaly
    # Combine predictions: mark anomaly if any detector flags -1
    combined = []
    for p1, p2, p3 in zip(preds_if, preds_lof, preds_svm):
        combined.append(-1 if (p1 == -1 or p2 == -1 or p3 == -1) else 1)
    # Prepare results
    anomaly_results = [
        {"log": log, "anomaly": (combined[i] == -1)}
        for i, log in enumerate(logs)
    ]
    total_anomalies = sum(1 for p in combined if p == -1)
    return {
        "module": "IDS",
        "estimated_contamination": contamination,
        "total_events": len(logs),
        "anomalies_detected": total_anomalies,
        "results": anomaly_results,
        "detector_outputs": {
            "IsolationForest": preds_if.tolist(),
            "LocalOutlierFactor": preds_lof.tolist(),
            "OneClassSVM": preds_svm.tolist()
        }
    }

class IDSAgent(OSINTAgent):
    """Detects anomalies in IDS logs using an ensemble of anomaly detection algorithms."""
    def run(self, target):
        target_str = str(target)
        try:
            result = analyze_ids(target_str)
        except Exception as e:
            result = {"error": str(e)}
        self.results = result
        return result

# mitm_agent.py – Network traffic analysis agent for MITM detection
import networkx as nx

def normalize_centrality(cent_dict: dict):
    """Normalize centrality values to [0,1] range (if max is 0, leave values unchanged)."""
    if not cent_dict:
        return {}
    max_val = max(cent_dict.values())
    if max_val == 0:
        return cent_dict
    return {node: val / max_val for node, val in cent_dict.items()}

def analyze_mitm(log_data: str):
    """
    Analyze network connections to identify nodes that could be MITM (high centrality).
    Expects log_data with lines "Source -> Destination".
    """
    lines = [line.strip() for line in log_data.splitlines() if line.strip()]
    if not lines:
        raise ValueError("No network log data provided.")
    G = nx.DiGraph()
    for line in lines:
        if "->" in line:
            parts = [part.strip() for part in line.split("->", 1)]
            if len(parts) == 2:
                src, dst = parts
                G.add_edge(src, dst)
    if G.number_of_nodes() == 0:
        raise ValueError("No valid graph could be constructed from the logs.")
    # Calculate centrality measures
    betweenness = nx.betweenness_centrality(G)
    try:
        eigenvector = nx.eigenvector_centrality_numpy(G)
    except Exception:
        # If eigenvector centrality fails (e.g., networkx might not converge for some graphs),
        # default to zero for all nodes for that measure.
        eigenvector = {node: 0 for node in G.nodes()}
    closeness = nx.closeness_centrality(G)
    # Normalize the centralities
    bet_norm = normalize_centrality(betweenness)
    eig_norm = normalize_centrality(eigenvector)
    clo_norm = normalize_centrality(closeness)
    # Ensemble score: weighted sum of centralities (weights: betweenness 0.5, eigenvector 0.3, closeness 0.2)
    aggregated = {}
    for node in G.nodes():
        aggregated[node] = (0.5 * bet_norm.get(node, 0) +
                            0.3 * eig_norm.get(node, 0) +
                            0.2 * clo_norm.get(node, 0))
    # Identify suspicious nodes above threshold
    threshold = 0.75
    suspicious_nodes = {node: score for node, score in aggregated.items() if score > threshold}
    # Community detection in the (undirected) network
    undirected_G = G.to_undirected()
    communities = list(nx.algorithms.community.greedy_modularity_communities(undirected_G))
    community_list = [list(comm) for comm in communities]
    return {
        "module": "MITM",
        "suspicious_nodes": suspicious_nodes,
        "centrality_scores": {
            "betweenness": bet_norm,
            "eigenvector": eig_norm,
            "closeness": clo_norm,
            "aggregated": aggregated
        },
        "communities": community_list,
        "graph_summary": nx.info(G)
    }

class MITMAgent(OSINTAgent):
    """Analyzes network traffic logs to detect potential Man-in-the-Middle nodes."""
    def run(self, target):
        target_str = str(target)
        try:
            result = analyze_mitm(target_str)
        except Exception as e:
            result = {"error": str(e)}
        self.results = result
        return result

# siem_agent.py – SIEM log clustering agent
from sklearn.cluster import AgglomerativeClustering

def estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2):
    """
    Estimate number of clusters based on cumulative explained variance of SVD components.
    Ensures at least min_clusters.
    """
    cum_variance = np.cumsum(svd.explained_variance_ratio_)
    # Find the smallest number of components that reach the threshold variance
    optimal = int(np.searchsorted(cum_variance, threshold) + 1)
    if optimal < min_clusters:
        optimal = min_clusters
    return optimal

def analyze_siem(log_data: str):
    """
    Cluster SIEM log events to find related groups.
    Returns a dict with the number of clusters and the events grouped.
    """
    events = [line.strip() for line in log_data.splitlines() if line.strip()]
    if not events:
        raise ValueError("No SIEM log events provided.")
    # Feature extraction
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(events)
    # Reduce dimensionality with SVD (LSA)
    n_components = min(100, X.shape[1] - 1) if X.shape[1] > 1 else 1
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    X_reduced = svd.fit_transform(X)
    # Determine clusters
    n_clusters = estimate_optimal_clusters(svd, threshold=0.90, min_clusters=2)
    clustering = AgglomerativeClustering(n_clusters=n_clusters)
    labels = clustering.fit_predict(X_reduced)
    # Group events by cluster label
    clusters = {}
    for label, event in zip(labels, events):
        clusters.setdefault(str(label), []).append(event)
    return {
        "module": "SIEM",
        "n_clusters": n_clusters,
        "clusters": clusters
    }

class SIEMAgent(OSINTAgent):
    """Clusters SIEM log events to reveal patterns or incidents."""
    def run(self, target):
        target_str = str(target)
        try:
            result = analyze_siem(target_str)
        except Exception as e:
            result = {"error": str(e)}
        self.results = result
        return result

# techint_agent.py – Technical intelligence agent (handles text indicators and images)
import cv2, scipy.special
import json

def advanced_techint(indicator: str):
    """
    Compute a risk score for a technical indicator string using a sigmoid function on its hash value.
    Also compute a dispersion metric as an additional feature.
    """
    try:
        # Hash the indicator to a number (for consistency across runs, we don't salt the hash here)
        val = abs(hash(indicator)) % 1000
        # Risk score between 0 and 1
        risk_score = float(scipy.special.expit((val - 500) / 50.0))
        dispersion = math.sqrt(val) / 50.0
        return {
            "module": "TECHINT",
            "indicator": indicator,
            "risk_score": risk_score,
            "dispersion": dispersion
        }
    except Exception as e:
        return {"error": str(e)}

def advanced_surveillance_data(image_path: str):
    """
    Analyze an image file for surveillance intelligence.
    Computes frequency domain features and a risk score based on anomalies in the image.
    """
    try:
        image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if image is None:
            # Could not load image (file not found or unsupported)
            return {"error": f"Unable to load image: {image_path}"}
        # Perform frequency analysis (FFT)
        dft = np.fft.fft2(image.astype(np.float32))
        dft_shift = np.fft.fftshift(dft)
        magnitude = 20 * np.log(np.abs(dft_shift) + 1)
        dominant_feature = float(np.mean(magnitude))
        # Calculate risk as sigmoid of (dominant_feature deviation from median)
        median_val = float(np.median(magnitude))
        std_val = float(np.std(magnitude)) + 1e-6  # add a tiny value to avoid division by zero
        risk_score = float(scipy.special.expit((dominant_feature - median_val) / std_val))
        # Spatial coherence as a simple metric of image complexity
        height, width = image.shape
        spatial_coherence = math.sqrt(width * height) / (width + height)
        return {
            "module": "SURVEILLANCE",
            "indicator": image_path,
            "image_dimensions": {"width": width, "height": height},
            "dominant_feature": dominant_feature,
            "risk_score": risk_score,
            "spatial_coherence": spatial_coherence
        }
    except Exception as e:
        return {"error": str(e)}

class TechIntAgent(OSINTAgent):
    """Analyzes technical indicators or images to produce a risk assessment."""
    def run(self, target):
        target_str = str(target).strip()
        # Try image analysis first
        result = advanced_surveillance_data(target_str)
        if result.get("error"):
            # If image analysis failed (not an image), fallback to tech indicator analysis
            result = advanced_techint(target_str)
        self.results = result
        return result

# threat_analyzer_agent.py – Aggregates threat indicators to compute overall risk
from dataclasses import dataclass
from typing import List

@dataclass
class ThreatIndicator:
    type: str
    value: str
    confidence: float

class ThreatAnalyzer:
    """Aggregates threat indicators and computes a composite risk score."""
    def __init__(self):
        self.risk_threshold = 0.7
        self.indicators: List[ThreatIndicator] = []
    def add_indicator(self, indicator_type: str, value: str, confidence: float):
        ind = ThreatIndicator(type=indicator_type, value=value, confidence=confidence)
        self.indicators.append(ind)
    def calculate_risk_score(self) -> float:
        if not self.indicators:
            return 0.0
        total_confidence = sum(ind.confidence for ind in self.indicators)
        return total_confidence / len(self.indicators)
    def get_high_risk_indicators(self) -> List[ThreatIndicator]:
        return [ind for ind in self.indicators if ind.confidence > self.risk_threshold]
    def to_dict(self):
        return {
            "risk_score": self.calculate_risk_score(),
            "indicators": [
                {"type": ind.type, "value": ind.value, "confidence": ind.confidence}
                for ind in self.indicators
            ]
        }

class ThreatAnalyzerAgent(OSINTAgent):
    """
    Analyzes multiple threat indicators provided as input and outputs overall risk.
    Accepts input as JSON or comma-separated lines (type,value,confidence).
    """
    def run(self, target):
        ta = ThreatAnalyzer()
        data_str = str(target).strip()
        if data_str:
            # Determine input format (JSON vs lines)
            try:
                loaded = json.loads(data_str)
                if isinstance(loaded, dict) and "indicators" in loaded:
                    indicators_list = loaded["indicators"]
                elif isinstance(loaded, list):
                    indicators_list = loaded
                else:
                    # If JSON is not in expected format, treat as plain text lines
                    raise ValueError("JSON format not recognized, falling back to text parsing.")
            except Exception:
                # Parse as lines "type,value,confidence"
                indicators_list = []
                for line in data_str.splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 3:
                        itype, val, conf = parts[0], parts[1], parts[2]
                        try:
                            conf_val = float(conf)
                        except:
                            continue  # skip if confidence is not a number
                        indicators_list.append({"type": itype, "value": val, "confidence": conf_val})
            # Add each parsed indicator to the ThreatAnalyzer
            for ind in indicators_list:
                try:
                    itype = ind.get("type") or ind.get("indicator_type") or ""
                    val = ind.get("value") or ""
                    conf = float(ind.get("confidence", 0.0))
                except:
                    continue  # skip any indicator that is missing fields or has invalid confidence
                if itype and val:
                    ta.add_indicator(itype, val, conf)
        # Build result
        result = {"module": "ThreatAnalyzer", **ta.to_dict()}
        # Include high-risk indicators (confidence > 0.7)
        high_risk_list = [
            {"type": ind.type, "value": ind.value, "confidence": ind.confidence}
            for ind in ta.get_high_risk_indicators()
        ]
        result["high_risk_indicators"] = high_risk_list
        self.results = result
        return result
