import re
from agents.base_agent import OSINTAgent
from ._shared import ok, structured_error

class GitHubIntelAgent(OSINTAgent):
    """
    GitHub intelligence agent.

    This version is local-first and non-API-dependent by default.
    It prepares clean parsing and repo triage logic without pretending to enumerate remote GitHub itself.

    Capabilities:
    - recognize user/org/repo targets
    - score likely intel value
    - expose hooks for local repo mirror scanning and secret scanning
    """
    name = "GitHubIntelAgent"
    supported_target_types = ("text", "domain", "url")

    USER_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
    REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")

    def run(self, target):
        try:
            mode = "generic"
            normalized = target.strip()

            if self.REPO_RE.match(normalized):
                mode = "repo"
            elif self.USER_RE.match(normalized):
                mode = "user_or_org"

            findings = {
                "target": normalized,
                "mode": mode,
                "agent_classification": "enrichment_scaffold",
                "capabilities": {
                    "local_repo_mirror_scan": True,
                    "secret_pattern_scan": True,
                    "commit_timeline_scan": True,
                    "contributor_graph_ready": True,
                    "language_fingerprint_ready": True
                },
                "recommended_inputs": [
                    "cloned repo path",
                    "commit log export",
                    "contributors export",
                    "code search corpus"
                ]
            }
            evidence_count = 0
            risk = 0.0 if evidence_count == 0 else 0.05
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
