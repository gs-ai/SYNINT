import re

from agents.base_agent import OSINTAgent
from ._shared import is_domain, normalize_target, ok, skipped, structured_error


class EmailHarvestAgent(OSINTAgent):
    """Generate likely mailbox patterns as enrichment hints."""

    name = "EmailHarvestAgent"
    supported_target_types = ("domain", "url")

    ROLE_ACCOUNTS = [
        "admin", "info", "support", "sales", "billing", "accounts", "security",
        "helpdesk", "contact", "press", "legal", "privacy", "abuse", "noc",
    ]

    PERSON_PATTERNS = [
        "{first}.{last}",
        "{first}{last}",
        "{f}{last}",
        "{first}",
        "{last}.{first}",
        "{first}_{last}",
    ]

    EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

    def run(self, target):
        try:
            domain = normalize_target(target)
            if not is_domain(domain):
                return skipped(self.name, target, "target is not a domain")

            first = "john"
            last = "doe"
            candidates = []

            for local in self.ROLE_ACCOUNTS:
                candidates.append(f"{local}@{domain}")

            for pattern in self.PERSON_PATTERNS:
                local = pattern.format(first=first, last=last, f=first[0])
                candidates.append(f"{local}@{domain}")

            generated = [addr for addr in dict.fromkeys(candidates) if self.EMAIL_RE.match(addr)]
            findings = {
                "domain": domain,
                "generated_addresses": generated,
                "generated_count": len(generated),
                "email_hypothesis_only": True,
                "security_policy_hooks": {
                    "spf_check_ready": True,
                    "dmarc_check_ready": True,
                    "dkim_selector_scan_ready": True,
                },
            }

            # Address generation is hypothesis-only and should remain low risk without corroboration.
            return ok(
                self.name,
                target,
                findings,
                0.03,
                evidence_mode="derived",
                evidence_count=0,
                reason="generated addresses are not direct evidence",
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
