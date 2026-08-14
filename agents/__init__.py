#!/usr/bin/env python3
"""Canonical exports and lazy registration helpers for SYNINT agents."""

from __future__ import annotations

from importlib import import_module
from typing import Dict, List, Sequence, Type

from .base_agent import OSINTAgent

AGENT_IMPORT_PATHS: Dict[str, str] = {
    "CybintAgent": ".cybint_agent",
    "SocialMediaAgent": ".social_media_agent",
    "WhoisAgent": ".whois_agent",
    "IDSAgent": ".ids_agent",
    "MITMAgent": ".mitm_agent",
    "SIEMAgent": ".siem_agent",
    "TechIntAgent": ".techint_agent",
    "ThreatAnalyzerAgent": ".threat_analyzer_agent",
    "DNSEnumAgent": ".dns_enum",
    "EmailHarvestAgent": ".email_harvest",
    "MetadataExtractionAgent": ".metadata_extraction",
    "GitHubIntelAgent": ".github_intel",
    "SSLCertAnalysisAgent": ".ssl_cert_analysis",
    "IPReputationAgent": ".ip_reputation",
    "DarkWebMonitorAgent": ".darkweb_monitor",
    "WaybackAnalysisAgent": ".wayback_analysis",
    "JobPostingIntelAgent": ".job_posting_intel",
    "PortfolioMappingAgent": ".portfolio_mapping",
    "BlockchainIntelAgent": ".blockchain_intel",
    "PhishingDetectionAgent": ".phishing_detection",
    "WebCrawlerAgent": ".web_crawler_agent",
    "DocumentIngestAgent": ".document_ingest_agent",
    "ArchiveFileDiscoveryAgent": ".archive_file_discovery_agent",
    "DirectoryBruteAgent": ".directory_brute_agent",
    "SearchEngineDiscoveryAgent": ".search_engine_discovery_agent",
    "ContactDiscoveryAgent": ".contact_discovery_agent",
    "UsernameCorrelationAgent": ".username_correlation_agent",
    "PersonProfileAgent": ".person_profile_agent",
    "EntityResolutionAgent": ".entity_resolution_agent",
    "RelationshipGraphAgent": ".relationship_graph_agent",
    "TimelineReconstructionAgent": ".timeline_reconstruction_agent",
    "HistoricalDNSAgent": ".historical_dns_agent",
    "DomainRegistrationPatternAgent": ".domain_registration_pattern_agent",
    "OCRIngestAgent": ".ocr_ingest_agent",
    "ImageForensicsAgent": ".image_forensics_agent",
    "TranscriptExtractionAgent": ".transcript_extraction_agent",
    "FileRelationshipAgent": ".file_relationship_agent",
    "HostFingerprintAgent": ".host_fingerprint_agent",
    "ServiceBannerAgent": ".service_banner_agent",
    "CertificatePivotAgent": ".certificate_pivot_agent",
    "ContentSimilarityAgent": ".content_similarity_agent",
    "InfrastructureClusterAgent": ".infrastructure_cluster_agent",
    "EvidenceScoringAgent": ".evidence_scoring_agent",
    "ContradictionDetectionAgent": ".contradiction_detection_agent",
    "LeadGenerationAgent": ".lead_generation_agent",
    "ReportBuilderAgent": ".report_builder_agent",
    "CommonCrawlIngestAgent": ".commoncrawl_ingest_agent",
    "MachineDiscoveryAgent": ".machine_discovery_agent",
    "IdentityCandidateAgent": ".identity_candidate_agent",
}

AGENT_ORDER: Sequence[str] = (
    "CybintAgent",
    "SocialMediaAgent",
    "WhoisAgent",
    "IDSAgent",
    "MITMAgent",
    "SIEMAgent",
    "TechIntAgent",
    "ThreatAnalyzerAgent",
    "DNSEnumAgent",
    "EmailHarvestAgent",
    "MetadataExtractionAgent",
    "GitHubIntelAgent",
    "SSLCertAnalysisAgent",
    "IPReputationAgent",
    "DarkWebMonitorAgent",
    "WaybackAnalysisAgent",
    "JobPostingIntelAgent",
    "PortfolioMappingAgent",
    "BlockchainIntelAgent",
    "PhishingDetectionAgent",
    "WebCrawlerAgent",
    "DocumentIngestAgent",
    "ArchiveFileDiscoveryAgent",
    "DirectoryBruteAgent",
    "SearchEngineDiscoveryAgent",
    "ContactDiscoveryAgent",
    "UsernameCorrelationAgent",
    "PersonProfileAgent",
    "EntityResolutionAgent",
    "RelationshipGraphAgent",
    "TimelineReconstructionAgent",
    "HistoricalDNSAgent",
    "DomainRegistrationPatternAgent",
    "OCRIngestAgent",
    "ImageForensicsAgent",
    "TranscriptExtractionAgent",
    "FileRelationshipAgent",
    "HostFingerprintAgent",
    "ServiceBannerAgent",
    "CertificatePivotAgent",
    "ContentSimilarityAgent",
    "InfrastructureClusterAgent",
    "EvidenceScoringAgent",
    "ContradictionDetectionAgent",
    "LeadGenerationAgent",
    "ReportBuilderAgent",
)

# Agents that are fully selectable via --agents but never run as part of the
# default run-all/pipeline set. Operators opt in explicitly, for example with
# `--agents CommonCrawlIngestAgent`.
OPTIONAL_AGENT_ORDER: Sequence[str] = (
    "CommonCrawlIngestAgent",
    "MachineDiscoveryAgent",
    "IdentityCandidateAgent",
)


def available_agent_names() -> Sequence[str]:
    """Return all known agent class names (default + optional), without
    importing heavy dependencies."""
    return tuple(AGENT_ORDER) + tuple(OPTIONAL_AGENT_ORDER)


def load_agent_class(agent_name: str) -> Type[OSINTAgent]:
    """Resolve and import one agent class by name."""
    module_path = AGENT_IMPORT_PATHS.get(agent_name)
    if not module_path:
        raise KeyError(f"Unknown agent class name: {agent_name}")

    module = import_module(module_path, package=__name__)
    cls = getattr(module, agent_name)
    if not issubclass(cls, OSINTAgent):
        raise TypeError(f"{agent_name} is not an OSINTAgent subclass")
    return cls


def load_agent_classes(agent_names: Sequence[str] | None = None) -> List[Type[OSINTAgent]]:
    """Resolve a list of agent classes in deterministic order."""
    selected = list(agent_names) if agent_names is not None else list(AGENT_ORDER)
    return [load_agent_class(name) for name in selected]


def build_default_agents() -> List[OSINTAgent]:
    """Create the framework's default agent instances in deterministic order."""
    return [cls() for cls in load_agent_classes()]


def __getattr__(name: str):
    """Support lazy class exports like `from agents import WhoisAgent`."""
    if name in AGENT_IMPORT_PATHS:
        return load_agent_class(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> List[str]:
    return sorted(set(globals()) | set(AGENT_IMPORT_PATHS))


__all__ = [
    "AGENT_IMPORT_PATHS",
    "AGENT_ORDER",
    "OPTIONAL_AGENT_ORDER",
    "available_agent_names",
    "load_agent_class",
    "load_agent_classes",
    "build_default_agents",
    "OSINTAgent",
    *AGENT_ORDER,
    *OPTIONAL_AGENT_ORDER,
]
