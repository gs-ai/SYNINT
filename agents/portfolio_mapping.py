import socket
from typing import Dict, List

from agents.base_agent import OSINTAgent
from ._shared import is_domain, normalize_target, ok, skipped, structured_error


class PortfolioMappingAgent(OSINTAgent):
    """Asset discovery with scoring based only on observed resolvable assets."""

    name = "PortfolioMappingAgent"
    supported_target_types = ("domain", "url")

    PREFIXES = [
        "www", "mail", "api", "app", "portal", "vpn", "auth", "cdn", "docs",
        "blog", "dev", "test", "staging", "status", "files", "download",
    ]

    SENSITIVE_PREFIXES = {"admin", "vpn", "auth", "dev", "staging", "portal"}

    def _resolve(self, host: str) -> List[str]:
        try:
            return sorted(set(socket.gethostbyname_ex(host)[2]))
        except Exception:
            return []

    def run(self, target):
        try:
            domain = normalize_target(target)
            if not is_domain(domain):
                return skipped(self.name, target, "target is not a domain")

            assets = []
            for prefix in self.PREFIXES:
                host = f"{prefix}.{domain}"
                ips = self._resolve(host)
                if not ips:
                    continue
                assets.append({"host": host, "prefix": prefix, "ips": ips})

            unique_ips = sorted({ip for asset in assets for ip in asset["ips"]})
            sensitive_assets = [a for a in assets if a["prefix"] in self.SENSITIVE_PREFIXES]

            evidence_count = len(assets)
            risk = 0.01
            risk += min(len(assets) / 25.0, 0.2)
            risk += min(len(unique_ips) / 40.0, 0.15)
            risk += min(len(sensitive_assets) * 0.03, 0.12)

            findings: Dict[str, object] = {
                "domain": domain,
                "related_assets": assets,
                "asset_count": len(assets),
                "unique_ip_count": len(unique_ips),
                "unique_ips": unique_ips,
                "sensitive_asset_count": len(sensitive_assets),
            }
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="active" if evidence_count else "none",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
