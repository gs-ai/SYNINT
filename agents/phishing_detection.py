import socket
from typing import List

from agents.base_agent import OSINTAgent
from ._shared import (
    domain_permutations,
    is_domain,
    lexical_domain_score,
    normalize_target,
    ok,
    skipped,
    structured_error,
)


class PhishingDetectionAgent(OSINTAgent):
    """Phishing and impersonation detection with conservative lexical scoring."""

    name = "PhishingDetectionAgent"
    supported_target_types = ("domain", "url")

    def _resolves(self, host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return True
        except Exception:
            return False

    def run(self, target):
        try:
            domain = normalize_target(target)
            if not is_domain(domain):
                return skipped(self.name, target, "target is not a domain")

            generated = domain_permutations(domain)
            lexical_score, lexical_details = lexical_domain_score(domain)

            live_lookalikes: List[str] = [candidate for candidate in generated if self._resolves(candidate)]
            live_count = len(live_lookalikes)

            # Lexical-only suspicion remains low-to-moderate.
            lexical_component = min(lexical_score * 0.2, 0.2)
            live_component = min(live_count * 0.2, 0.8)
            risk = 0.05 + lexical_component + live_component

            findings = {
                "domain": domain,
                "generated_lookalikes": generated,
                "lookalike_count": len(generated),
                "live_lookalikes": live_lookalikes,
                "live_lookalike_count": live_count,
                "lexical_analysis": lexical_details,
            }

            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="active" if live_count > 0 else "derived",
                evidence_count=live_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
