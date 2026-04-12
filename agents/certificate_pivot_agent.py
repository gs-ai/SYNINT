"""Certificate-based pivoting from existing TLS findings."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class CertificatePivotAgent(OSINTAgent):
    """Pivot across SAN/CN/wildcard scope from locally known certificate data."""

    name = "CertificatePivotAgent"
    supported_target_types = ("domain", "url", "text", "json")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        try:
            ssl_findings = agent_results.get("SSLCertAnalysisAgent", {}).get("result", {}).get("findings", {})
            if not isinstance(ssl_findings, dict) or not ssl_findings:
                return skipped(self.name, target, "ssl certificate findings unavailable")

            sans = ssl_findings.get("subject_alt_names", []) if isinstance(ssl_findings.get("subject_alt_names"), list) else []
            wildcard_scope = sorted(set(item for item in sans if isinstance(item, str) and item.startswith("*.")))
            pivot_domains = sorted(set(item.replace("*.", "") for item in sans if isinstance(item, str)))

            san_relationships = [
                {
                    "source": ssl_findings.get("host", target),
                    "related_domain": domain,
                    "relationship": "certificate_san",
                }
                for domain in pivot_domains
            ]

            cert_cluster_hints: List[str] = []
            if wildcard_scope:
                cert_cluster_hints.append("Wildcard SAN scope can imply broad certificate reuse.")
            if len(pivot_domains) > 5:
                cert_cluster_hints.append("High SAN cardinality may indicate shared infrastructure.")

            findings = {
                "pivot_domains": pivot_domains,
                "san_relationships": san_relationships,
                "wildcard_scope": wildcard_scope,
                "cert_cluster_hints": cert_cluster_hints,
            }
            risk = min(0.03 + len(pivot_domains) * 0.02, 0.6)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="derived",
                evidence_count=len(pivot_domains),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
