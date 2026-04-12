#!/usr/bin/env python3
"""Agent orchestration manager with staged pipeline support."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlparse

from agents._shared import infer_target_types, normalize_agent_output, skipped, target_matches
from core import EntityRegistry, EvidenceRegistry, InvestigationContext
from core.schemas import Entity, EvidenceItem

logger = logging.getLogger(__name__)
ProgressCallback = Callable[[Dict[str, Dict[str, Any]], Dict[str, Any]], None]


PIPELINE_STAGE_PLAN: Dict[str, List[Tuple[str, List[str]]]] = {
    "quick": [
        (
            "normalization_and_collection",
            [
                "CybintAgent",
                "DNSEnumAgent",
                "WhoisAgent",
                "SSLCertAnalysisAgent",
                "IPReputationAgent",
                "WebCrawlerAgent",
                "WaybackAnalysisAgent",
            ],
        ),
        (
            "entity_and_timeline",
            [
                "ContactDiscoveryAgent",
                "EntityResolutionAgent",
                "RelationshipGraphAgent",
                "TimelineReconstructionAgent",
            ],
        ),
        (
            "synthesis",
            [
                "EvidenceScoringAgent",
                "ContradictionDetectionAgent",
                "LeadGenerationAgent",
                "ThreatAnalyzerAgent",
                "ReportBuilderAgent",
            ],
        ),
    ],
    "standard": [
        (
            "collection",
            [
                "WebCrawlerAgent",
                "DirectoryBruteAgent",
                "ArchiveFileDiscoveryAgent",
                "SearchEngineDiscoveryAgent",
                "WaybackAnalysisAgent",
                "DocumentIngestAgent",
                "ContactDiscoveryAgent",
                "HostFingerprintAgent",
                "ServiceBannerAgent",
                "CertificatePivotAgent",
                "ContentSimilarityAgent",
            ],
        ),
        (
            "entity_resolution",
            [
                "UsernameCorrelationAgent",
                "PersonProfileAgent",
                "EntityResolutionAgent",
                "RelationshipGraphAgent",
                "FileRelationshipAgent",
            ],
        ),
        (
            "history_and_infrastructure",
            [
                "TimelineReconstructionAgent",
                "HistoricalDNSAgent",
                "DomainRegistrationPatternAgent",
                "InfrastructureClusterAgent",
            ],
        ),
        (
            "synthesis_export",
            [
                "EvidenceScoringAgent",
                "ContradictionDetectionAgent",
                "LeadGenerationAgent",
                "ThreatAnalyzerAgent",
                "ReportBuilderAgent",
            ],
        ),
    ],
    "deep": [
        (
            "collection",
            [
                "WebCrawlerAgent",
                "DirectoryBruteAgent",
                "ArchiveFileDiscoveryAgent",
                "SearchEngineDiscoveryAgent",
                "WaybackAnalysisAgent",
                "DocumentIngestAgent",
                "OCRIngestAgent",
                "ImageForensicsAgent",
                "TranscriptExtractionAgent",
                "ContactDiscoveryAgent",
                "HostFingerprintAgent",
                "ServiceBannerAgent",
                "CertificatePivotAgent",
                "ContentSimilarityAgent",
            ],
        ),
        (
            "entity_resolution",
            [
                "UsernameCorrelationAgent",
                "PersonProfileAgent",
                "EntityResolutionAgent",
                "RelationshipGraphAgent",
                "FileRelationshipAgent",
            ],
        ),
        (
            "history_and_correlation",
            [
                "TimelineReconstructionAgent",
                "HistoricalDNSAgent",
                "DomainRegistrationPatternAgent",
                "InfrastructureClusterAgent",
            ],
        ),
        (
            "synthesis_export",
            [
                "EvidenceScoringAgent",
                "ContradictionDetectionAgent",
                "LeadGenerationAgent",
                "ThreatAnalyzerAgent",
                "ReportBuilderAgent",
            ],
        ),
    ],
}


class AgentManager:
    """Manages registration, concurrent execution, and staged pipelines."""

    def __init__(self):
        self.agents: List[Any] = []
        self._agent_names: set[str] = set()
        self.evidence_registry = EvidenceRegistry()
        self.entity_registry = EntityRegistry()
        self.pipeline_state: Dict[str, Any] = {}
        self._run_reports_dir: str = ""

    def register_agent(self, agent):
        agent_name = type(agent).__name__
        if agent_name not in self._agent_names:
            self.agents.append(agent)
            self._agent_names.add(agent_name)
            logger.info("Registered agent: %s", agent_name)
        else:
            logger.warning("Agent %s is already registered. Skipping duplicate instance.", agent_name)

    def remove_agent(self, agent):
        agent_name = type(agent).__name__
        if agent in self.agents:
            self.agents.remove(agent)
            self._agent_names.discard(agent_name)
            logger.info("Removed agent: %s", agent_name)
        else:
            logger.warning("Agent %s is not registered.", agent_name)

    def list_agents(self) -> list:
        return [type(agent).__name__ for agent in self.agents]

    def _preflight_skip_result(self, agent: Any, target: Any, detected_types: set[str]) -> Dict[str, Any] | None:
        agent_name = type(agent).__name__
        supported_types = tuple(getattr(agent, "supported_target_types", ("any",)))
        if target_matches(supported_types, detected_types):
            return None
        reason = f"unsupported target type(s): {sorted(detected_types)}; supported: {sorted(set(supported_types))}"
        return skipped(agent_name, target, reason)

    @staticmethod
    def _attach_execution_time(result: Dict[str, Any], execution_time: float) -> Dict[str, Any]:
        payload = dict(result)
        payload["execution_time"] = round(max(0.0, execution_time), 4)
        return payload

    def _agent_lookup(self) -> Dict[str, Any]:
        return {type(agent).__name__: agent for agent in self.agents}

    @staticmethod
    def _maybe_add_context_file(context: InvestigationContext, raw_value: Any) -> None:
        path_value = ""
        if isinstance(raw_value, str):
            path_value = raw_value.strip()
        elif isinstance(raw_value, dict):
            for key in ("path", "downloaded_file", "download_path", "file_path"):
                candidate = raw_value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    path_value = candidate.strip()
                    break
        if not path_value:
            return

        candidate_path = Path(path_value).expanduser()
        try:
            if candidate_path.exists() and candidate_path.is_file():
                context.add_file(str(candidate_path.resolve()))
        except Exception:
            return

    @staticmethod
    def _emit_progress(
        progress_callback: ProgressCallback | None,
        results: Dict[str, Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> None:
        if progress_callback is None:
            return
        try:
            progress_callback(dict(results), dict(metadata))
        except Exception as exc:
            logger.exception("Progress callback failed: %s", exc)

    def _ingest_evidence_and_entities(self, agent_name: str, result: Dict[str, Any]) -> None:
        if not isinstance(result, dict):
            return
        findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
        if not findings:
            return

        evidence_items: List[EvidenceItem] = []
        entity_items: List[Entity] = []

        key_to_entity_type = {
            "emails": "email",
            "phones": "phone",
            "urls": "url",
            "domains": "domain",
            "pivot_domains": "domain",
            "related_host_candidates": "domain",
            "suspected_people": "person",
            "suspected_orgs": "organization",
            "wallets": "wallet",
        }

        for key, entity_type in key_to_entity_type.items():
            values = findings.get(key)
            if not isinstance(values, list):
                continue
            for raw in values:
                value = str(raw).strip()
                if not value:
                    continue
                ev = EvidenceItem(
                    source_agent=agent_name,
                    evidence_type=entity_type,
                    value=value,
                    normalized_value=value.lower(),
                    confidence=0.6,
                    severity="medium",
                    tags=["pipeline_collected", key],
                    source_reference=key,
                    supporting_context={"agent": agent_name},
                    evidence_tier="derived" if result.get("evidence_mode") != "collected" else "direct evidence",
                )
                evidence_items.append(ev)

        resolved = findings.get("resolved_entities")
        if isinstance(resolved, list):
            for item in resolved:
                if not isinstance(item, dict):
                    continue
                entity_items.append(
                    Entity(
                        entity_type=str(item.get("entity_type", "unknown")),
                        canonical_name=str(item.get("canonical_name", "")),
                        aliases=[str(v) for v in item.get("aliases", []) if str(v).strip()],
                        attributes=item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {},
                        source_evidence_ids=item.get("source_evidence_ids", []) if isinstance(item.get("source_evidence_ids"), list) else [],
                        confidence=float(item.get("confidence", 0.5) or 0.5),
                    )
                )

        for ev in evidence_items:
            ev_id = self.evidence_registry.add(ev)
            entity_type = ev.evidence_type
            if entity_type in {"email", "phone", "url", "domain", "wallet", "person", "organization"}:
                entity_items.append(
                    Entity(
                        entity_type=entity_type,
                        canonical_name=ev.normalized_value,
                        aliases=[ev.value],
                        attributes={"source_agent": agent_name},
                        source_evidence_ids=[ev_id],
                        confidence=ev.confidence,
                    )
                )

        self.entity_registry.extend(entity_items)

    def run_all(
        self,
        target,
        run_reports_dir: str | Path | None = None,
        progress_callback: ProgressCallback | None = None,
        collection_mode: str = "balanced",
    ) -> Dict[str, Dict[str, Any]]:
        results = {}
        if not self.agents:
            logger.warning("No agents registered to run.")
            return results

        self.evidence_registry = EvidenceRegistry()
        self.entity_registry = EntityRegistry()
        self._run_reports_dir = str(run_reports_dir or "").strip()
        mode = str(collection_mode or "balanced").strip() or "balanced"
        context = InvestigationContext.from_target(str(target), collection_mode=mode)
        self._seed_context(context)
        context.add_runtime_note("execution_model=legacy_run_all")
        context.add_runtime_note(f"collection_mode={mode}")

        detected_types = infer_target_types(target)
        fusion_agents = [a for a in self.agents if bool(getattr(a, "consume_all_results", False))]
        fusion_agents = self._ordered_fusion_agents(fusion_agents)
        regular_agents = [a for a in self.agents if a not in fusion_agents]

        logger.info("Executing %d agents on target: %s", len(self.agents), target)
        max_workers = min(max(len(regular_agents), 1), 32)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_agent = {}
            for agent in regular_agents:
                preflight = self._preflight_skip_result(agent, target, detected_types)
                if preflight is not None:
                    agent_name = type(agent).__name__
                    preflight = self._attach_execution_time(preflight, 0.0)
                    results[agent_name] = {"result": preflight, "execution_time": 0.0}
                    logger.info("Agent %s skipped by target gating.", agent_name)
                    context.add_runtime_note(f"{agent_name}:skipped")
                    self._emit_progress(
                        progress_callback,
                        results,
                        {"execution_model": "legacy_run_all", "agent": agent_name, "status": "skipped"},
                    )
                    continue
                start_time = perf_counter()
                if bool(getattr(agent, "requires_context", False)):
                    input_payload = self._payload_for_agent(str(target), context, results)
                else:
                    input_payload = target
                future = executor.submit(agent.run, input_payload)
                future_to_agent[future] = (agent, start_time)

            for future in as_completed(future_to_agent):
                agent, start_time = future_to_agent[future]
                elapsed = perf_counter() - start_time
                agent_name = type(agent).__name__
                try:
                    raw_result = future.result()
                    result = normalize_agent_output(agent_name, target, raw_result)
                    logger.info("Agent %s completed in %.2f seconds.", agent_name, elapsed)
                except Exception as exc:
                    logger.exception("Error executing agent %s: %s", agent_name, exc)
                    result = normalize_agent_output(
                        agent_name,
                        target,
                        {"status": "error", "error": str(exc), "reason": "agent execution failure"},
                    )
                result = self._attach_execution_time(result, elapsed)
                results[agent_name] = {
                    "result": result,
                    "execution_time": round(elapsed, 4),
                }
                self._ingest_evidence_and_entities(agent_name, result)
                findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
                for key in ["discovered_urls", "internal_links", "external_links"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            context.add_url(str(value))
                for key in ["files", "file_links", "candidate_files", "downloaded_files"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            self._maybe_add_context_file(context, value)
                context.collected_evidence = self.evidence_registry.to_list()
                context.collected_entities = self.entity_registry.to_list()
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._emit_progress(
                    progress_callback,
                    results,
                    {"execution_model": "legacy_run_all", "agent": agent_name, "status": result.get("status", "unknown")},
                )

        if fusion_agents:
            for fusion_agent in fusion_agents:
                agent_name = type(fusion_agent).__name__
                start_time = perf_counter()
                try:
                    fusion_payload = self._payload_for_agent(str(target), context, results)
                    fusion_payload["target_types"] = sorted(detected_types)
                    raw = fusion_agent.run(fusion_payload)
                    result = normalize_agent_output(agent_name, target, raw)
                except Exception as exc:
                    logger.exception("Error executing fusion agent %s: %s", agent_name, exc)
                    result = normalize_agent_output(
                        agent_name,
                        target,
                        {"status": "error", "error": str(exc), "reason": "fusion execution failure"},
                    )
                elapsed = perf_counter() - start_time
                result = self._attach_execution_time(result, elapsed)
                results[agent_name] = {
                    "result": result,
                    "execution_time": round(elapsed, 4),
                }
                self._ingest_evidence_and_entities(agent_name, result)
                findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
                for key in ["discovered_urls", "internal_links", "external_links"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            context.add_url(str(value))
                for key in ["files", "file_links", "candidate_files", "downloaded_files"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            self._maybe_add_context_file(context, value)
                context.collected_evidence = self.evidence_registry.to_list()
                context.collected_entities = self.entity_registry.to_list()
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._emit_progress(
                    progress_callback,
                    results,
                    {"execution_model": "legacy_run_all", "agent": agent_name, "status": result.get("status", "unknown")},
                )

        self.pipeline_state = {
            "pipeline_mode": None,
            "collection_mode": mode,
            "investigation_context": context.to_dict(),
            "evidence_registry": self.evidence_registry.to_list(),
            "entity_registry": self.entity_registry.to_list(),
        }

        ordered = {name: results[name] for name in sorted(results)}
        self._emit_progress(
            progress_callback,
            ordered,
            {"execution_model": "legacy_run_all", "phase": "complete", "force": True},
        )
        return ordered

    def _pipeline_collection_mode(self, pipeline_mode: str) -> str:
        if pipeline_mode == "quick":
            return "low_noise"
        if pipeline_mode == "deep":
            return "deep_browser"
        return "balanced"

    def _seed_context(self, context: InvestigationContext) -> None:
        target = str(context.normalized_target or context.original_target).strip()
        if not target:
            return

        if "://" in target:
            parsed = urlparse(target)
            host = (parsed.hostname or "").strip().lower()
            if host:
                context.resolved_domains.append(host)
        elif "." in target:
            context.resolved_domains.append(target.lower())

        if target.replace(".", "").isdigit():
            context.resolved_ips.append(target)

    def _stage_plan(self, pipeline_mode: str) -> List[Tuple[str, List[str]]]:
        return PIPELINE_STAGE_PLAN.get(pipeline_mode, PIPELINE_STAGE_PLAN["standard"])

    def _ordered_fusion_agents(self, agents: List[Any]) -> List[Any]:
        """Order fusion agents according to standard pipeline dependencies."""
        stage_order: List[str] = []
        for _, names in self._stage_plan("standard"):
            stage_order.extend(names)
        priority = {name: idx for idx, name in enumerate(stage_order)}
        original_index = {id(agent): idx for idx, agent in enumerate(self.agents)}
        return sorted(
            agents,
            key=lambda agent: (
                priority.get(type(agent).__name__, len(priority)),
                original_index.get(id(agent), len(self.agents)),
            ),
        )

    def _payload_for_agent(self, target: str, context: InvestigationContext, results: Dict[str, Any]) -> Dict[str, Any]:
        context_dict = context.to_dict()
        if self._run_reports_dir:
            context_dict["reports_dir"] = self._run_reports_dir
        return {
            "target": target,
            "investigation_context": context_dict,
            "agent_results": results,
            "evidence_registry": self.evidence_registry.to_list(),
            "entity_registry": self.entity_registry.to_list(),
        }

    def run_pipeline(
        self,
        target: str,
        pipeline_mode: str = "standard",
        collection_mode_override: str | None = None,
        run_reports_dir: str | Path | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Run a staged pipeline with dependencies and context propagation."""
        if not self.agents:
            logger.warning("No agents registered to run.")
            return {}

        self.evidence_registry = EvidenceRegistry()
        self.entity_registry = EntityRegistry()
        self._run_reports_dir = str(run_reports_dir or "").strip()

        collection_mode = str(collection_mode_override or self._pipeline_collection_mode(pipeline_mode))
        context = InvestigationContext.from_target(target, collection_mode=collection_mode)
        self._seed_context(context)
        context.add_runtime_note(f"pipeline_mode={pipeline_mode}")
        context.add_runtime_note(f"collection_mode={collection_mode}")
        agent_map = self._agent_lookup()
        detected_types = infer_target_types(target)
        results: Dict[str, Dict[str, Any]] = {}

        plan = self._stage_plan(pipeline_mode)
        logger.info("Running %s pipeline with %d stage(s)", pipeline_mode, len(plan))

        for stage_name, stage_agents in plan:
            logger.info("Starting pipeline stage: %s", stage_name)
            for agent_name in stage_agents:
                agent = agent_map.get(agent_name)
                if agent is None:
                    continue

                use_payload = bool(getattr(agent, "consume_all_results", False) or getattr(agent, "requires_context", False))
                needs_gate = not bool(getattr(agent, "consume_all_results", False))
                if needs_gate:
                    preflight = self._preflight_skip_result(agent, target, detected_types)
                    if preflight is not None:
                        preflight = self._attach_execution_time(preflight, 0.0)
                        results[agent_name] = {
                            "result": preflight,
                            "execution_time": 0.0,
                            "stage": stage_name,
                        }
                        self._emit_progress(
                            progress_callback,
                            results,
                            {
                                "execution_model": "pipeline",
                                "pipeline_mode": pipeline_mode,
                                "stage": stage_name,
                                "agent": agent_name,
                                "status": "skipped",
                            },
                        )
                        continue

                input_payload = self._payload_for_agent(target, context, results) if use_payload else target
                start_time = perf_counter()
                try:
                    raw = agent.run(input_payload)
                    result = normalize_agent_output(agent_name, target, raw)
                except Exception as exc:
                    logger.exception("Error executing pipeline agent %s: %s", agent_name, exc)
                    result = normalize_agent_output(
                        agent_name,
                        target,
                        {"status": "error", "error": str(exc), "reason": "pipeline execution failure"},
                    )

                elapsed = perf_counter() - start_time
                result = self._attach_execution_time(result, elapsed)
                results[agent_name] = {
                    "result": result,
                    "execution_time": round(elapsed, 4),
                    "stage": stage_name,
                }

                findings = result.get("findings") if isinstance(result.get("findings"), dict) else {}
                for key in ["discovered_urls", "internal_links", "external_links"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            context.add_url(str(value))
                for key in ["files", "file_links", "candidate_files", "downloaded_files"]:
                    values = findings.get(key)
                    if isinstance(values, list):
                        for value in values:
                            self._maybe_add_context_file(context, value)

                self._ingest_evidence_and_entities(agent_name, result)
                context.collected_evidence = self.evidence_registry.to_list()
                context.collected_entities = self.entity_registry.to_list()
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._emit_progress(
                    progress_callback,
                    results,
                    {
                        "execution_model": "pipeline",
                        "pipeline_mode": pipeline_mode,
                        "stage": stage_name,
                        "agent": agent_name,
                        "status": result.get("status", "unknown"),
                    },
                )

            self._emit_progress(
                progress_callback,
                results,
                {
                    "execution_model": "pipeline",
                    "pipeline_mode": pipeline_mode,
                    "stage": stage_name,
                    "phase": "stage_complete",
                    "force": True,
                },
            )

        self.pipeline_state = {
            "pipeline_mode": pipeline_mode,
            "collection_mode": collection_mode,
            "investigation_context": context.to_dict(),
            "evidence_registry": self.evidence_registry.to_list(),
            "entity_registry": self.entity_registry.to_list(),
        }
        self._emit_progress(
            progress_callback,
            results,
            {"execution_model": "pipeline", "pipeline_mode": pipeline_mode, "phase": "complete", "force": True},
        )
        return results

    def run_agent(self, agent_name, target) -> dict:
        for agent in self.agents:
            if type(agent).__name__ == agent_name:
                logger.info("Running agent: %s", agent_name)
                try:
                    detected_types = infer_target_types(target)
                    preflight = self._preflight_skip_result(agent, target, detected_types)
                    if preflight is not None:
                        preflight = self._attach_execution_time(preflight, 0.0)
                        return {"result": preflight, "execution_time": 0.0}
                    start_time = perf_counter()
                    if bool(getattr(agent, "requires_context", False) or getattr(agent, "consume_all_results", False)):
                        context = InvestigationContext.from_target(str(target), collection_mode="balanced")
                        self._seed_context(context)
                        if self._run_reports_dir:
                            context_dict = context.to_dict()
                            context_dict["reports_dir"] = self._run_reports_dir
                        else:
                            context_dict = context.to_dict()
                        input_payload = {
                            "target": target,
                            "investigation_context": context_dict,
                            "agent_results": {},
                            "evidence_registry": self.evidence_registry.to_list(),
                            "entity_registry": self.entity_registry.to_list(),
                        }
                    else:
                        input_payload = target
                    raw_result = agent.run(input_payload)
                    result = normalize_agent_output(agent_name, target, raw_result)
                    elapsed = perf_counter() - start_time
                    result = self._attach_execution_time(result, elapsed)
                    logger.info("Agent %s completed in %.2f seconds.", agent_name, elapsed)
                    self._ingest_evidence_and_entities(agent_name, result)
                    return {"result": result, "execution_time": round(elapsed, 4)}
                except Exception as exc:
                    logger.exception("Error running agent %s: %s", agent_name, exc)
                    fallback = normalize_agent_output(
                        agent_name,
                        target,
                        {"status": "error", "error": str(exc), "reason": "agent execution failure"},
                    )
                    fallback = self._attach_execution_time(fallback, 0.0)
                    return {"result": fallback, "execution_time": 0.0}
        error_msg = f"No agent found with name: {agent_name}"
        logger.error(error_msg)
        fallback = normalize_agent_output(
            agent_name,
            target,
            {"status": "error", "error": error_msg, "reason": "unregistered agent"},
        )
        fallback = self._attach_execution_time(fallback, 0.0)
        return {"result": fallback, "execution_time": 0.0}


if __name__ == "__main__":
    print("AgentManager is part of the SYNINT framework and is not intended to be run standalone.")
