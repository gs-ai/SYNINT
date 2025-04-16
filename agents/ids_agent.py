#!/usr/bin/env python3
"""
IDS Module - Intrusion Detection Systems Intelligence
-----------------------------------------------------
This module performs advanced, real‑world anomaly detection on IDS log events using a revolutionary ensemble approach.
It leverages TF‑IDF, dimensionality reduction via Truncated SVD, and an ensemble of IsolationForest, Local Outlier Factor,
and One-Class SVM to detect anomalies in log data.
"""

import argparse
import json
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

class IDSAgent(OSINTAgent):
    """
    IDSAgent - An agent for performing advanced intrusion detection analysis on IDS log events.
    Uses an ensemble of IsolationForest, Local Outlier Factor, and One-Class SVM for anomaly detection.
    """
    def compute_adaptive_contamination(self, X_reduced, random_state=42):
        """
        Compute an adaptive contamination parameter based on the distribution of decision scores
        from a preliminary Isolation Forest.
        """
        initial_clf = IsolationForest(random_state=random_state)
        initial_clf.fit(X_reduced)
        scores = initial_clf.decision_function(X_reduced)
        median_score = np.median(scores)
        mad = np.median(np.abs(scores - median_score))
        threshold = median_score - 1.5 * mad
        estimated_contamination = np.mean(scores < threshold)
        # Constrain contamination to a realistic range: [0.01, 0.5]
        estimated_contamination = min(max(estimated_contamination, 0.01), 0.5)
        logger.info(f"Adaptive contamination estimated: {estimated_contamination:.3f}")
        return estimated_contamination

    def analyze_ids(self, indicator: str) -> dict:
        """
        Analyze IDS log events using an ensemble anomaly detection approach.
        If there are fewer than 2 log entries, return a 'skipped' result.
        """
        try:
            logs = [line.strip() for line in indicator.splitlines() if line.strip()]
            if len(logs) < 2:
                logger.info("IDS analysis skipped: Insufficient log data.")
                return {"skipped": "IDS analysis skipped: Insufficient log data. At least 2 log entries are required."}
            
            logger.info(f"Number of log entries: {len(logs)}")
            
            # Feature Extraction: TF‑IDF vectorization.
            vectorizer = TfidfVectorizer(stop_words='english', max_features=500)
            X = vectorizer.fit_transform(logs).toarray()
            logger.info(f"TF‑IDF feature matrix shape: {X.shape}")
            
            # Dimensionality Reduction: Truncated SVD.
            n_components = min(100, X.shape[1] - 1) if X.shape[1] > 1 else 1
            svd = TruncatedSVD(n_components=n_components, random_state=42)
            X_reduced = svd.fit_transform(X)
            logger.info(f"Reduced feature matrix shape: {X_reduced.shape}")
            
            # Adaptive Contamination Estimation.
            contamination = self.compute_adaptive_contamination(X_reduced)
            
            # Ensemble Anomaly Detection:
            iso_forest = IsolationForest(contamination=contamination, random_state=42)
            iso_forest.fit(X_reduced)
            predictions_if = iso_forest.predict(X_reduced)
            
            lof = LocalOutlierFactor(n_neighbors=20, contamination=contamination)
            predictions_lof = lof.fit_predict(X_reduced)
            
            oc_svm = OneClassSVM(nu=contamination, kernel="rbf", gamma='scale')
            oc_svm.fit(X_reduced)
            predictions_ocsvm = oc_svm.predict(X_reduced)
            
            ensemble_predictions = [
                -1 if (p_if == -1 or p_lof == -1 or p_ocsvm == -1) else 1
                for p_if, p_lof, p_ocsvm in zip(predictions_if, predictions_lof, predictions_ocsvm)
            ]
            
            anomaly_results = [
                {"log": log, "anomaly": (pred == -1)}
                for log, pred in zip(logs, ensemble_predictions)
            ]
            
            total_anomalies = sum(1 for pred in ensemble_predictions if pred == -1)
            logger.info(f"Detected {total_anomalies} anomalies out of {len(logs)} log entries.")
            
            return {
                "module": "IDS",
                "estimated_contamination": contamination,
                "results": anomaly_results,
                "detector_outputs": {
                    "IsolationForest": predictions_if.tolist(),
                    "LocalOutlierFactor": predictions_lof.tolist(),
                    "OneClassSVM": predictions_ocsvm.tolist()
                }
            }
        except Exception as e:
            logger.error(f"Error in IDS analysis: {e}")
            return {"error": str(e)}

    def run(self, indicator: str) -> dict:
        """
        Execute the IDS analysis on the provided log data.
        """
        return self.analyze_ids(indicator)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Module - Advanced Intrusion Detection Analysis.")
    parser.add_argument("indicator", type=str, help="IDS log data (newline-separated)")
    args = parser.parse_args()
    result = IDSAgent().run(args.indicator)
    print(json.dumps(result, indent=4))
