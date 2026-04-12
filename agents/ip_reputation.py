import ipaddress
from typing import Any, Dict

from agents.base_agent import OSINTAgent
from ._shared import is_domain, normalize_target, ok, resolve_first_ip, skipped, structured_error


class IPReputationAgent(OSINTAgent):
    """IP triage and reputation heuristic agent."""

    name = "IPReputationAgent"
    supported_target_types = ("ip", "domain", "url")

    def _summarize_ip(self, ip_obj: ipaddress._BaseAddress) -> Dict[str, Any]:
        return {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_reserved": ip_obj.is_reserved,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
            "is_link_local": ip_obj.is_link_local,
            "reverse_pointer": ip_obj.reverse_pointer,
        }

    def run(self, target):
        try:
            original = str(target).strip()
            target_value = original
            resolved_from = None

            try:
                ip_obj = ipaddress.ip_address(target_value)
            except ValueError:
                normalized = normalize_target(target_value)
                if is_domain(normalized):
                    resolved = resolve_first_ip(normalized)
                    if not resolved:
                        return skipped(self.name, target, "domain did not resolve to an IP")
                    target_value = resolved
                    resolved_from = normalized
                    ip_obj = ipaddress.ip_address(target_value)
                else:
                    return skipped(self.name, target, "target is neither IP nor resolvable domain")

            findings = self._summarize_ip(ip_obj)
            if resolved_from:
                findings["resolved_from"] = resolved_from

            risk = 0.02
            if ip_obj.is_global:
                risk += 0.08
            if ip_obj.is_reserved or ip_obj.is_multicast:
                risk += 0.03

            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="active" if ip_obj.is_global else "passive",
                evidence_count=1,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
