#!/usr/bin/env python3
"""Agent orchestration manager with staged pipeline support."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlparse

from agents._shared import infer_target_types, normalize_agent_output, skipped, target_matches
from core import (
    CheckpointStore,
    EntityRegistry,
    EvidenceLedger,
    EvidenceRegistry,
    InvestigationContext,
    InvestigationDatabase,
    validate_result,
)
from core.schemas import Entity, EvidenceItem

logger = logging.getLogger(__name__)
ProgressCallback = Callable[[Dict[str, Dict[str, Any]], Dict[str, Any]], None]


@dataclass(frozen=True)
class RuntimePolicy:
    timeout_seconds: float = 0.0
    max_retries: int = 0


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

    def __init__(
        self,
        *,
        run_id: str = "",
        checkpoint_store: CheckpointStore | None = None,
        evidence_ledger: EvidenceLedger | None = None,
        investigation_db: InvestigationDatabase | None = None,
        runtime_policy: RuntimePolicy | None = None,
    ):
        self.agents: List[Any] = []
        self._agent_names: set[str] = set()
        self.evidence_registry = EvidenceRegistry()
        self.entity_registry = EntityRegistry()
        self.pipeline_state: Dict[str, Any] = {}
        self._run_reports_dir: str = ""
        self.run_id = str(run_id or "")
        self.checkpoint_store = checkpoint_store
        self.evidence_ledger = evidence_ledger
        self.investigation_db = investigation_db
        self.runtime_policy = runtime_policy or RuntimePolicy()

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

    def _normalize_validated_result(self, agent_name: str, target: Any, raw_result: Any) -> Dict[str, Any]:
        normalized = normalize_agent_output(agent_name, target, raw_result)
        valid, cleaned, error = validate_result(normalized)
        if valid:
            return cleaned
        logger.error("Result validation failed for %s: %s", agent_name, error)
        return normalize_agent_output(
            agent_name,
            target,
            {"status": "error", "error": error or "result validation failed", "reason": "result validation failure"},
        )

    def _invoke_agent(self, agent: Any, input_payload: Any, agent_name: str, target: Any) -> Dict[str, Any]:
        attempts = max(0, int(self.runtime_policy.max_retries)) + 1
        timeout_seconds = max(0.0, float(self.runtime_policy.timeout_seconds))
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                if timeout_seconds > 0.0:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(agent.run, input_payload)
                        raw_result = future.result(timeout=timeout_seconds)
                else:
                    raw_result = agent.run(input_payload)
                result = self._normalize_validated_result(agent_name, target, raw_result)
                if attempt > 1:
                    result["reason"] = f"completed after retry {attempt - 1}"
                return result
            except Exception as exc:
                last_error = exc
                logger.warning("Agent %s attempt %d/%d failed: %s", agent_name, attempt, attempts, exc)

        assert last_error is not None
        return self._normalize_validated_result(
            agent_name,
            target,
            {"status": "error", "error": str(last_error), "reason": "agent execution failure"},
        )

    def _restore_registries(self, checkpoint: Dict[str, Any]) -> None:
        self.evidence_registry = EvidenceRegistry()
        self.entity_registry = EntityRegistry()
        pipeline_state = checkpoint.get("pipeline_state", {}) if isinstance(checkpoint, dict) else {}
        for item in pipeline_state.get("evidence_registry", []):
            if isinstance(item, dict):
                self.evidence_registry.add(item)
        for item in pipeline_state.get("entity_registry", []):
            if isinstance(item, dict):
                self.entity_registry.add(item)

    def _restore_context(self, checkpoint: Dict[str, Any], target: str, collection_mode: str) -> InvestigationContext:
        pipeline_state = checkpoint.get("pipeline_state", {}) if isinstance(checkpoint, dict) else {}
        context_payload = pipeline_state.get("investigation_context", {})
        if isinstance(context_payload, dict) and context_payload:
            context = InvestigationContext.from_dict(context_payload)
        else:
            context = InvestigationContext.from_target(target, collection_mode=collection_mode)
            self._seed_context(context)
        return context

    def _sync_runtime_state(self, context: InvestigationContext) -> None:
        context.collected_evidence = self.evidence_registry.to_list()
        context.collected_entities = self.entity_registry.to_list()

    def _record_artifact(self, *, event_type: str, artifact_path: str | Path, source_agent: str | None = None, source_reference: str | None = None) -> None:
        if self.evidence_ledger is None or not self.run_id:
            return
        entry = self.evidence_ledger.append_artifact(
            run_id=self.run_id,
            event_type=event_type,
            artifact_path=artifact_path,
            source_agent=source_agent,
            source_reference=source_reference,
        )
        if entry is not None and self.investigation_db is not None:
            self.investigation_db.record_artifact(self.run_id, entry.__dict__)

    def _record_context_artifacts(self, agent_name: str, findings: Dict[str, Any]) -> None:
        file_keys = ("files", "file_links", "candidate_files", "downloaded_files")
        for key in file_keys:
            values = findings.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                path_value = ""
                if isinstance(value, str):
                    path_value = value
                elif isinstance(value, dict):
                    for candidate_key in ("path", "download", "downloaded_file", "download_path", "file_path"):
                        candidate = value.get(candidate_key)
                        if isinstance(candidate, str) and candidate.strip():
                            path_value = candidate
                            break
                if path_value:
                    self._record_artifact(
                        event_type="collected_file",
                        artifact_path=path_value,
                        source_agent=agent_name,
                        source_reference=key,
                    )
        exported_files = findings.get("exported_files")
        if isinstance(exported_files, dict):
            for key, path_value in exported_files.items():
                if isinstance(path_value, str) and path_value.strip():
                    self._record_artifact(
                        event_type="exported_artifact",
                        artifact_path=path_value,
                        source_agent=agent_name,
                        source_reference=key,
                    )

    def _persist_runtime_state(
        self,
        *,
        target: str,
        results: Dict[str, Dict[str, Any]],
        context: InvestigationContext,
        execution_model: str,
        pipeline_mode: str | None,
        collection_mode: str,
        stage_name: str | None = None,
        status: str = "running",
    ) -> None:
        self.pipeline_state = {
            "pipeline_mode": pipeline_mode,
            "collection_mode": collection_mode,
            "investigation_context": context.to_dict(),
            "evidence_registry": self.evidence_registry.to_list(),
            "entity_registry": self.entity_registry.to_list(),
            "forensic_ledger_path": str(self.evidence_ledger.ledger_path) if self.evidence_ledger is not None else "",
            "checkpoint_path": str(self.checkpoint_store.path) if self.checkpoint_store is not None else "",
            "investigation_db_path": str(self.investigation_db.path) if self.investigation_db is not None else "",
        }

        if self.checkpoint_store is not None:
            self.checkpoint_store.save(
                {
                    "run_id": self.run_id,
                    "target": target,
                    "execution_model": execution_model,
                    "pipeline_mode": pipeline_mode,
                    "collection_mode": collection_mode,
                    "stage_name": stage_name,
                    "status": status,
                    "results": results,
                    "pipeline_state": self.pipeline_state,
                    "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                }
            )

        if self.investigation_db is not None and self.run_id:
            now = datetime.now(timezone.utc).isoformat()
            self.investigation_db.upsert_run(
                run_id=self.run_id,
                target=target,
                execution_model=execution_model,
                pipeline_mode=pipeline_mode,
                collection_mode=collection_mode,
                status=status,
                created_at_utc=now,
                updated_at_utc=now,
                metadata={"stage_name": stage_name, "result_count": len(results)},
            )
            for agent_name, entry in results.items():
                self.investigation_db.upsert_agent_result(self.run_id, agent_name, entry, stage_name=entry.get("stage"))
                result = entry.get("result", {}) if isinstance(entry, dict) else {}
                if str(result.get("status")) == "error" and result.get("error"):
                    self.investigation_db.record_error(self.run_id, agent_name, str(result.get("error")), now)
            self.investigation_db.replace_evidence(self.run_id, self.evidence_registry.to_list())
            self.investigation_db.replace_entities(self.run_id, self.entity_registry.to_list())

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
            "ips": "ip",
            "handles": "handle",
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

    def _update_context_from_findings(self, context: InvestigationContext, findings: Dict[str, Any]) -> None:
        for key in ("discovered_urls", "internal_links", "external_links"):
            values = findings.get(key)
            if isinstance(values, list):
                for value in values:
                    context.add_url(str(value))
        for key in ("files", "file_links", "candidate_files", "downloaded_files"):
            values = findings.get(key)
            if isinstance(values, list):
                for value in values:
                    self._maybe_add_context_file(context, value)

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

        self._run_reports_dir = str(run_reports_dir or "").strip()
        mode = str(collection_mode or "balanced").strip() or "balanced"
        checkpoint = self.checkpoint_store.load() if self.checkpoint_store is not None else {}
        if checkpoint and str(checkpoint.get("target")) == str(target):
            self._restore_registries(checkpoint)
            results = dict(checkpoint.get("results", {})) if isinstance(checkpoint.get("results"), dict) else {}
            context = self._restore_context(checkpoint, str(target), mode)
            context.add_runtime_note("resume=true")
        else:
            self.evidence_registry = EvidenceRegistry()
            self.entity_registry = EntityRegistry()
            context = InvestigationContext.from_target(str(target), collection_mode=mode)
            self._seed_context(context)
        context.collection_mode = mode
        context.run_id = self.run_id or context.run_id
        context.case_name = Path(self._run_reports_dir).name if self._run_reports_dir else context.case_name
        context.add_runtime_note("execution_model=legacy_run_all")
        context.add_runtime_note(f"collection_mode={mode}")
        self._sync_runtime_state(context)

        detected_types = infer_target_types(target)
        fusion_agents = [a for a in self.agents if bool(getattr(a, "consume_all_results", False))]
        fusion_agents = self._ordered_fusion_agents(fusion_agents)
        regular_agents = [a for a in self.agents if a not in fusion_agents]
        completed_agents = set(results)

        logger.info("Executing %d agents on target: %s", len(self.agents), target)
        max_workers = min(max(len(regular_agents), 1), 32)
        self._persist_runtime_state(
            target=str(target),
            results=results,
            context=context,
            execution_model="legacy_run_all",
            pipeline_mode=None,
            collection_mode=mode,
            status="running",
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_agent = {}
            for agent in regular_agents:
                agent_name = type(agent).__name__
                if agent_name in completed_agents:
                    continue
                preflight = self._preflight_skip_result(agent, target, detected_types)
                if preflight is not None:
                    preflight = self._attach_execution_time(preflight, 0.0)
                    results[agent_name] = {"result": preflight, "execution_time": 0.0}
                    logger.info("Agent %s skipped by target gating.", agent_name)
                    context.add_runtime_note(f"{agent_name}:skipped")
                    self._persist_runtime_state(
                        target=str(target),
                        results=results,
                        context=context,
                        execution_model="legacy_run_all",
                        pipeline_mode=None,
                        collection_mode=mode,
                        stage_name=None,
                        status="running",
                    )
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
                future = executor.submit(self._invoke_agent, agent, input_payload, agent_name, target)
                future_to_agent[future] = (agent, start_time)

            for future in as_completed(future_to_agent):
                agent, start_time = future_to_agent[future]
                elapsed = perf_counter() - start_time
                agent_name = type(agent).__name__
                try:
                    result = future.result()
                    logger.info("Agent %s completed in %.2f seconds.", agent_name, elapsed)
                except Exception as exc:
                    logger.exception("Error executing agent %s: %s", agent_name, exc)
                    result = self._normalize_validated_result(
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
                self._update_context_from_findings(context, findings)
                self._record_context_artifacts(agent_name, findings)
                self._sync_runtime_state(context)
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._persist_runtime_state(
                    target=str(target),
                    results=results,
                    context=context,
                    execution_model="legacy_run_all",
                    pipeline_mode=None,
                    collection_mode=mode,
                    status="running",
                )
                self._emit_progress(
                    progress_callback,
                    results,
                    {"execution_model": "legacy_run_all", "agent": agent_name, "status": result.get("status", "unknown")},
                )

        if fusion_agents:
            for fusion_agent in fusion_agents:
                agent_name = type(fusion_agent).__name__
                if agent_name in results:
                    continue
                start_time = perf_counter()
                try:
                    fusion_payload = self._payload_for_agent(str(target), context, results)
                    fusion_payload["target_types"] = sorted(detected_types)
                    result = self._invoke_agent(fusion_agent, fusion_payload, agent_name, target)
                except Exception as exc:
                    logger.exception("Error executing fusion agent %s: %s", agent_name, exc)
                    result = self._normalize_validated_result(
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
                self._update_context_from_findings(context, findings)
                self._record_context_artifacts(agent_name, findings)
                self._sync_runtime_state(context)
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._persist_runtime_state(
                    target=str(target),
                    results=results,
                    context=context,
                    execution_model="legacy_run_all",
                    pipeline_mode=None,
                    collection_mode=mode,
                    status="running",
                )
                self._emit_progress(
                    progress_callback,
                    results,
                    {"execution_model": "legacy_run_all", "agent": agent_name, "status": result.get("status", "unknown")},
                )

        self._persist_runtime_state(
            target=str(target),
            results=results,
            context=context,
            execution_model="legacy_run_all",
            pipeline_mode=None,
            collection_mode=mode,
            status="complete",
        )

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
        if self.evidence_ledger is not None:
            context_dict["forensic_ledger_path"] = str(self.evidence_ledger.ledger_path)
        if self.checkpoint_store is not None:
            context_dict["checkpoint_path"] = str(self.checkpoint_store.path)
        if self.investigation_db is not None:
            context_dict["investigation_db_path"] = str(self.investigation_db.path)
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

        self._run_reports_dir = str(run_reports_dir or "").strip()
        collection_mode = str(collection_mode_override or self._pipeline_collection_mode(pipeline_mode))
        checkpoint = self.checkpoint_store.load() if self.checkpoint_store is not None else {}
        if checkpoint and str(checkpoint.get("target")) == str(target) and str(checkpoint.get("pipeline_mode") or pipeline_mode) == pipeline_mode:
            self._restore_registries(checkpoint)
            context = self._restore_context(checkpoint, target, collection_mode)
            results: Dict[str, Dict[str, Any]] = dict(checkpoint.get("results", {})) if isinstance(checkpoint.get("results"), dict) else {}
            context.add_runtime_note("resume=true")
        else:
            self.evidence_registry = EvidenceRegistry()
            self.entity_registry = EntityRegistry()
            context = InvestigationContext.from_target(target, collection_mode=collection_mode)
            self._seed_context(context)
            results = {}
        context.collection_mode = collection_mode
        context.run_id = self.run_id or context.run_id
        context.case_name = Path(self._run_reports_dir).name if self._run_reports_dir else context.case_name
        context.add_runtime_note(f"pipeline_mode={pipeline_mode}")
        context.add_runtime_note(f"collection_mode={collection_mode}")
        self._sync_runtime_state(context)
        agent_map = self._agent_lookup()
        detected_types = infer_target_types(target)

        plan = self._stage_plan(pipeline_mode)
        logger.info("Running %s pipeline with %d stage(s)", pipeline_mode, len(plan))
        self._persist_runtime_state(
            target=target,
            results=results,
            context=context,
            execution_model="pipeline",
            pipeline_mode=pipeline_mode,
            collection_mode=collection_mode,
            status="running",
        )

        for stage_name, stage_agents in plan:
            logger.info("Starting pipeline stage: %s", stage_name)
            for agent_name in stage_agents:
                if agent_name in results:
                    continue
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
                        self._persist_runtime_state(
                            target=target,
                            results=results,
                            context=context,
                            execution_model="pipeline",
                            pipeline_mode=pipeline_mode,
                            collection_mode=collection_mode,
                            stage_name=stage_name,
                            status="running",
                        )
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
                    result = self._invoke_agent(agent, input_payload, agent_name, target)
                except Exception as exc:
                    logger.exception("Error executing pipeline agent %s: %s", agent_name, exc)
                    result = self._normalize_validated_result(
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
                self._update_context_from_findings(context, findings)
                self._record_context_artifacts(agent_name, findings)
                self._ingest_evidence_and_entities(agent_name, result)
                self._sync_runtime_state(context)
                context.add_runtime_note(f"{agent_name}:{result.get('status', 'unknown')}")
                self._persist_runtime_state(
                    target=target,
                    results=results,
                    context=context,
                    execution_model="pipeline",
                    pipeline_mode=pipeline_mode,
                    collection_mode=collection_mode,
                    stage_name=stage_name,
                    status="running",
                )
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

        self._persist_runtime_state(
            target=target,
            results=results,
            context=context,
            execution_model="pipeline",
            pipeline_mode=pipeline_mode,
            collection_mode=collection_mode,
            status="complete",
        )
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
                        context.run_id = self.run_id or context.run_id
                        if self._run_reports_dir:
                            context_dict = context.to_dict()
                            context_dict["reports_dir"] = self._run_reports_dir
                        else:
                            context_dict = context.to_dict()
                        if self.evidence_ledger is not None:
                            context_dict["forensic_ledger_path"] = str(self.evidence_ledger.ledger_path)
                        if self.checkpoint_store is not None:
                            context_dict["checkpoint_path"] = str(self.checkpoint_store.path)
                        if self.investigation_db is not None:
                            context_dict["investigation_db_path"] = str(self.investigation_db.path)
                        input_payload = {
                            "target": target,
                            "investigation_context": context_dict,
                            "agent_results": {},
                            "evidence_registry": self.evidence_registry.to_list(),
                            "entity_registry": self.entity_registry.to_list(),
                        }
                    else:
                        input_payload = target
                    result = self._invoke_agent(agent, input_payload, agent_name, target)
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
