#!/usr/bin/env python3
"""Threat Analyzer Module - Aggregates threat indicators to compute overall risk."""

from __future__ import annotations

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


class ThreatAnalyzer:
    def __init__(self) -> None:
        self.risk_threshold = 0.7
        self.indicators: List[ThreatIndicator] = []

    def add_indicator(self, indicator_type: str, value: str, confidence: float) -> None:
        self.indicators.append(ThreatIndicator(type=indicator_type, value=value, confidence=confidence))

    def calculate_risk_score(self) -> float:
        if not self.indicators:
            return 0.0
        return sum(ind.confidence for ind in self.indicators) / len(self.indicators)

    def get_high_risk_indicators(self) -> List[ThreatIndicator]:
        return [ind for ind in self.indicators if ind.confidence > self.risk_threshold]

    def to_json(self) -> Dict[str, object]:
        return {
            "risk_score": self.calculate_risk_score(),
            "indicators": [
                {"type": ind.type, "value": ind.value, "confidence": ind.confidence}
                for ind in self.indicators
            ],
        }


class ThreatAnalyzerAgent(OSINTAgent):
    """Aggregates threat indicators from JSON or CSV-like input."""

    def run(self, indicator: str | None = None) -> Dict[str, object]:
        analyzer = ThreatAnalyzer()
        if not indicator or not str(indicator).strip():
            result: Dict[str, object] = {
                "module": "ThreatAnalyzer",
                "status": "skipped",
                "reason": "No indicators provided. Supply JSON with 'indicators' or newline rows: type,value,confidence.",
                "risk_score": 0.0,
                "indicators": [],
            }
            self.results = result
            return result

        data_str = str(indicator).strip()
        try:
            loaded = json.loads(data_str)
            if isinstance(loaded, dict) and "indicators" in loaded:
                indicators_list = loaded["indicators"]
            elif isinstance(loaded, list):
                indicators_list = loaded
            else:
                raise ValueError("JSON format not recognized")
        except Exception:
            indicators_list = []
            for line in data_str.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    continue
                try:
                    indicators_list.append(
                        {"type": parts[0], "value": parts[1], "confidence": float(parts[2])}
                    )
                except ValueError:
                    continue

        for ind in indicators_list:
            try:
                indicator_type = str(ind.get("type", "")).strip()
                value = str(ind.get("value", "")).strip()
                confidence = float(ind.get("confidence", 0.0))
            except Exception:
                continue

            if indicator_type and value:
                analyzer.add_indicator(indicator_type, value, confidence)

        payload = analyzer.to_json()
        result = {
            "module": "ThreatAnalyzer",
            "status": "ok",
            **payload,
            "high_risk_indicators": [
                {"type": ind.type, "value": ind.value, "confidence": ind.confidence}
                for ind in analyzer.get_high_risk_indicators()
            ],
        }
        self.results = result
        return result


if __name__ == "__main__":
    import sys

    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(ThreatAnalyzerAgent().run(arg), indent=4))
