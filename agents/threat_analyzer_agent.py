#!/usr/bin/env python3

import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

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
                {
                    "type": ind.type,
                    "value": ind.value,
                    "confidence": ind.confidence
                } for ind in self.indicators
            ]
        }

def main():
    analyzer = ThreatAnalyzer()
    
    # Example usage
    analyzer.add_indicator("ip_address", "192.168.1.1", 0.8)
    analyzer.add_indicator("domain", "example.com", 0.6)
    
    print(json.dumps(analyzer.to_json(), indent=4))

if __name__ == "__main__":
    main()
