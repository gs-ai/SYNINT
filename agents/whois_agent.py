#!/usr/bin/env python3
"""WHOIS lookup agent."""

import logging
import re
import subprocess

from agents.base_agent import OSINTAgent
from ._shared import normalize_target, ok, skipped, structured_error

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class WhoisAgent(OSINTAgent):
    name = "WhoisAgent"
    supported_target_types = ("domain", "ip")

    def validate_target(self, target: str) -> bool:
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ipv4_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        ipv6_regex = r"^(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+$"
        return bool(re.match(domain_regex, target) or re.match(ipv4_regex, target) or re.match(ipv6_regex, target))

    def run(self, target) -> dict:
        target_str = normalize_target(str(target).strip())
        logger.info("Starting WHOIS lookup for target: %s", target_str)

        if not self.validate_target(target_str):
            return skipped(self.name, target, "invalid target format for whois")

        try:
            output = subprocess.check_output(["whois", target_str], timeout=12)
            data = output.decode("utf-8", errors="ignore")
            findings = {
                "whois_data": data,
                "raw_length": len(data),
                "has_registrar": "registrar" in data.lower(),
            }
            evidence_count = 1 if data.strip() else 0
            return ok(
                self.name,
                target,
                findings,
                0.02,
                evidence_mode="active" if evidence_count else "none",
                evidence_count=evidence_count,
            )
        except subprocess.TimeoutExpired:
            return structured_error(self.name, target, "WHOIS lookup timed out")
        except FileNotFoundError:
            return structured_error(self.name, target, "WHOIS command not found")
        except Exception as exc:
            return structured_error(self.name, target, exc)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python whois_agent.py <target>")
    else:
        print(WhoisAgent().run(sys.argv[1]))
