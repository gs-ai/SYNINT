"""Evidence-based infrastructure clustering from multi-agent signals."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class InfrastructureClusterAgent(OSINTAgent):
    """Cluster likely related infrastructure using explicit reason codes."""

    name = "InfrastructureClusterAgent"
    supported_target_types = ("domain", "url", "text", "json")
    consume_all_results = True

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        try:
            host_fp = agent_results.get("HostFingerprintAgent", {}).get("result", {}).get("findings", {})
            cert_pivot = agent_results.get("CertificatePivotAgent", {}).get("result", {}).get("findings", {})
            dns_enum = agent_results.get("DNSEnumAgent", {}).get("result", {}).get("findings", {})
            similarity = agent_results.get("ContentSimilarityAgent", {}).get("result", {}).get("findings", {})
            banners = agent_results.get("ServiceBannerAgent", {}).get("result", {}).get("findings", {})

            if not any(isinstance(item, dict) and item for item in [host_fp, cert_pivot, dns_enum, similarity, banners]):
                return skipped(self.name, target, "insufficient infrastructure signals")

            shared_indicators: List[str] = []
            cluster_reasons: List[Dict[str, Any]] = []

            pivot_domains = cert_pivot.get("pivot_domains", []) if isinstance(cert_pivot, dict) else []
            if pivot_domains:
                shared_indicators.extend(str(d) for d in pivot_domains)
                cluster_reasons.append({"reason_code": "CERT_SAN_REUSE", "detail": f"{len(pivot_domains)} SAN pivot domain(s)"})

            subdomains = dns_enum.get("subdomain_hits", []) if isinstance(dns_enum, dict) else []
            if subdomains:
                shared_indicators.extend(str(item.get("host")) for item in subdomains if isinstance(item, dict))
                cluster_reasons.append({"reason_code": "DNS_ASSET_OVERLAP", "detail": f"{len(subdomains)} discovered subdomain(s)"})

            pairs = similarity.get("similarity_pairs", []) if isinstance(similarity, dict) else []
            if pairs:
                cluster_reasons.append({"reason_code": "CONTENT_REUSE", "detail": f"{len(pairs)} high-similarity content pair(s)"})

            exposed_admin = banners.get("exposed_admin_services", []) if isinstance(banners, dict) else []
            if exposed_admin:
                cluster_reasons.append({"reason_code": "ADMIN_SERVICE_EXPOSURE", "detail": ", ".join(exposed_admin)})

            primary_cluster = {
                "cluster_id": "infra_cluster_1",
                "members": unique_sorted(shared_indicators),
                "reason_codes": [item["reason_code"] for item in cluster_reasons],
            }

            confidence = min(0.2 + len(cluster_reasons) * 0.15, 0.95)
            findings = {
                "clusters": [primary_cluster],
                "cluster_reasons": cluster_reasons,
                "shared_indicators": unique_sorted(shared_indicators),
                "confidence": round(confidence, 4),
            }

            return ok(
                self.name,
                target,
                findings,
                min(0.03 + confidence * 0.6, 0.9),
                evidence_mode="derived",
                evidence_count=len(unique_sorted(shared_indicators)),
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
