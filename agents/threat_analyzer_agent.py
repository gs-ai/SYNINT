#!/usr/bin/env python3
"""
Threat Analyzer Module - Aggregates threat indicators to compute overall risk.
"""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List
from agents.base_agent import OSINTAgent

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@dataclass
class ThreatIndicator:
    type: str
    value: str
    confidence: float
    mitre_techniques: List[str] = None

class ThreatAnalyzer:
    def __init__(self):
        self.risk_threshold = 0.7
        self.indicators: List[ThreatIndicator] = []

    def add_indicator(self, indicator_type: str, value: str, confidence: float) -> None:
        indicator = ThreatIndicator(
            type=indicator_type,
            value=value,
            confidence=confidence
        )
        self.indicators.append(indicator)
        logger.info(f"Added new {indicator_type} indicator: {value}")

    def calculate_risk_score(self) -> float:
        if not self.indicators:
            return 0.0
        total_confidence = sum(ind.confidence for ind in self.indicators)
        return total_confidence / len(self.indicators)

    def get_high_risk_indicators(self) -> List[ThreatIndicator]:
        return [ind for ind in self.indicators if ind.confidence > self.risk_threshold]

    def to_json(self) -> Dict:
        return {
            "risk_score": self.calculate_risk_score(),
            "indicators": [
                {"type": ind.type, "value": ind.value, "confidence": ind.confidence}
                for ind in self.indicators
            ]
        }

class ThreatAnalyzerAgent(OSINTAgent):
    """
    ThreatAnalyzerAgent - An agent that aggregates threat indicators and computes an overall risk score.
    Accepts input either as:
      - A JSON string with an "indicators" field, or
      - Newline-separated lines in the format "type,value,confidence"
    If no input is provided, default sample data is used.
    """
    def run(self, indicator: str = None) -> dict:
        analyzer = ThreatAnalyzer()
        
        if indicator:
            data_str = indicator.strip()
            # Try to parse as JSON
            try:
                loaded = json.loads(data_str)
                if isinstance(loaded, dict) and "indicators" in loaded:
                    indicators_list = loaded["indicators"]
                elif isinstance(loaded, list):
                    indicators_list = loaded
                else:
                    raise ValueError("JSON format not recognized")
            except Exception:
                # Parse as newline-separated text: each line "type,value,confidence"
                indicators_list = []
                for line in data_str.splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 3:
                        itype, val, conf = parts[0], parts[1], parts[2]
                        try:
                            conf_val = float(conf)
                        except:
                            continue
                        indicators_list.append({"type": itype, "value": val, "confidence": conf_val})
            
            for ind in indicators_list:
                try:
                    itype = ind.get("type", "")
                    val = ind.get("value", "")
                    conf = float(ind.get("confidence", 0.0))
                    if itype and val:
                        analyzer.add_indicator(itype, val, conf)
                except Exception as e:
                    logger.error(f"Skipping invalid indicator: {ind} due to error: {e}")
        else:
            # Use default sample data if no input provided
            analyzer.add_indicator("ip_address", "192.168.1.1", 0.8)
            analyzer.add_indicator("domain", "example.com", 0.6)
        
        self.results = analyzer.to_json()
        return self.results

if __name__ == "__main__":
    result = ThreatAnalyzerAgent().run()
    print(json.dumps(result, indent=4))
