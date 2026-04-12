from agents.base_agent import OSINTAgent
from ._shared import ok, structured_error, shannon_entropy

class DarkWebMonitorAgent(OSINTAgent):
    """
    Dark web monitoring scaffold agent.

    Local-first by design.
    Intended to search local breach corpora, onion indexes, marketplace dumps, or paste archives.

    Capabilities:
    - target normalization
    - token complexity profiling
    - corpus adapter readiness
    """
    name = "DarkWebMonitorAgent"
    supported_target_types = ("text", "domain", "url", "ip")

    def run(self, target):
        try:
            entropy = shannon_entropy(target)
            findings = {
                "search_target": target,
                "target_entropy": round(entropy, 4),
                "agent_classification": "enrichment_scaffold",
                "local_sources_supported": [
                    "breach corpus",
                    "paste dumps",
                    "onion index snapshots",
                    "forum scrape archives",
                    "credential sets"
                ],
                "matching_hooks": {
                    "exact_match": True,
                    "fuzzy_match": True,
                    "domain_match": True,
                    "email_match": True,
                    "username_match": True
                }
            }
            evidence_count = 0
            risk = 0.0 if evidence_count == 0 else min(entropy / 8.0, 0.25)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="scaffold",
                evidence_count=evidence_count,
            )
        except Exception as e:
            return structured_error(self.name, target, e)
