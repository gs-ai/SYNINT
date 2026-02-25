#!/usr/bin/env python3
"""Shared abstract base class for all SYNINT agents."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class OSINTAgent(ABC):
    """Abstract base class for all OSINT agents in SYNINT."""

    def __init__(self) -> None:
        self.results: Dict[str, Any] | None = None

    @abstractmethod
    def run(self, target: str) -> Dict[str, Any]:
        """Execute agent analysis for a target and return a structured result."""
        raise NotImplementedError
