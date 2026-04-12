"""Collector engine selection and graceful fallback logic."""

from __future__ import annotations

from dataclasses import asdict
import os
from typing import Any, Dict, List, Tuple, Type

from .base import BaseCollector, CollectionConfig
from .camoufox_collector import CamoufoxCollector
from .scrapling_collector import ScraplingCollector
from .scrapy_collector import ScrapyCollector
from .static_http import StaticHttpCollector


COLLECTOR_CLASSES: Dict[str, Type[BaseCollector]] = {
    "static_http": StaticHttpCollector,
    "scrapling": ScraplingCollector,
    "scrapy": ScrapyCollector,
    "camoufox": CamoufoxCollector,
}


def collector_capability_matrix() -> Dict[str, Dict[str, Any]]:
    matrix: Dict[str, Dict[str, Any]] = {}
    for name, cls in COLLECTOR_CLASSES.items():
        matrix[name] = {
            "available": cls.is_available(),
            "availability_reason": cls.availability_reason(),
            "capabilities": asdict(cls.capabilities),
        }
    return matrix


def _selection_order(
    *,
    mode: str,
    need_render: bool,
    need_crawl: bool,
    prefer_engine: str | None,
) -> List[str]:
    if prefer_engine and prefer_engine in COLLECTOR_CLASSES:
        return [prefer_engine] + [name for name in ["static_http", "scrapling", "scrapy", "camoufox"] if name != prefer_engine]

    if need_render:
        return ["camoufox", "static_http", "scrapling", "scrapy"]
    if need_crawl:
        return ["static_http", "scrapy", "scrapling", "camoufox"]
    if mode == "deep_browser":
        return ["camoufox", "scrapling", "static_http", "scrapy"]
    if mode == "stealth":
        return ["camoufox", "static_http", "scrapling", "scrapy"]
    if mode == "low_noise":
        return ["static_http", "scrapling", "scrapy", "camoufox"]
    return ["static_http", "scrapling", "scrapy", "camoufox"]


def select_collector(
    *,
    mode: str,
    need_render: bool = False,
    need_crawl: bool = False,
    prefer_engine: str | None = None,
    config: CollectionConfig | None = None,
) -> Tuple[BaseCollector, List[Dict[str, Any]]]:
    """Select the best collector using capability-aware fallback ordering."""
    attempts: List[Dict[str, Any]] = []
    if not prefer_engine:
        env_prefer = str(os.getenv("SYNINT_PREFER_COLLECTOR", "")).strip().lower()
        if env_prefer in COLLECTOR_CLASSES:
            prefer_engine = env_prefer
    order = _selection_order(mode=mode, need_render=need_render, need_crawl=need_crawl, prefer_engine=prefer_engine)

    for engine_name in order:
        cls = COLLECTOR_CLASSES[engine_name]
        available = cls.is_available()
        reason = cls.availability_reason()
        attempts.append(
            {
                "collector_engine": engine_name,
                "available": available,
                "reason": reason,
            }
        )
        if available:
            return cls(config=config), attempts

    # guaranteed local fallback
    attempts.append(
        {
            "collector_engine": "static_http",
            "available": True,
            "reason": "forced fallback",
        }
    )
    return StaticHttpCollector(config=config), attempts
