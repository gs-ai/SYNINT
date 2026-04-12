from agents.base_agent import OSINTAgent
from ._shared import classify_wallet, ok, structured_error

class BlockchainIntelAgent(OSINTAgent):
    """
    Blockchain intelligence triage agent.

    Capabilities:
    - wallet pattern detection
    - chain-family likelihood
    - enrichment readiness for local transaction datasets
    """
    name = "BlockchainIntelAgent"
    supported_target_types = ("text",)

    def run(self, target):
        try:
            classes = classify_wallet(target)
            likely = [k for k, v in classes.items() if v]
            findings = {
                "target": target,
                "wallet_classification": classes,
                "likely_matches": likely,
                "enrichment_hooks": {
                    "transaction_graph_ready": True,
                    "cluster_analysis_ready": True,
                    "exchange_label_join_ready": True
                }
            }
            risk = 0.2 if likely else 0.0
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="derived" if likely else "none",
                evidence_count=len(likely),
            )
        except Exception as e:
            return structured_error(self.name, target, e)
