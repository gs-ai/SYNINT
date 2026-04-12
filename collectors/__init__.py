"""Collector adapters and selection utilities."""

from .base import BaseCollector, CollectionConfig, CollectionResult, CollectorCapabilities
from .factory import collector_capability_matrix, select_collector

__all__ = [
    "BaseCollector",
    "CollectorCapabilities",
    "CollectionConfig",
    "CollectionResult",
    "collector_capability_matrix",
    "select_collector",
]
