from datetime import datetime, timezone

from agents.base_agent import OSINTAgent
from ._shared import get_basic_ssl_cert, is_domain, normalize_target, ok, skipped, structured_error


class SSLCertAnalysisAgent(OSINTAgent):
    """Conservative SSL/TLS certificate analysis with richer context."""

    name = "SSLCertAnalysisAgent"
    supported_target_types = ("domain", "url")

    @staticmethod
    def _parse_not_after(not_after: str | None) -> int | None:
        if not not_after:
            return None
        try:
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return int((dt - datetime.now(timezone.utc)).days)
        except Exception:
            return None

    def run(self, target):
        try:
            host = normalize_target(target)
            if not is_domain(host):
                return skipped(self.name, target, "target is not a domain")

            cert = get_basic_ssl_cert(host)
            san = [entry[1] for entry in cert.get("subjectAltName", []) if len(entry) > 1]
            issuer = cert.get("issuer")
            subject = cert.get("subject")
            days_until_expiration = self._parse_not_after(cert.get("notAfter"))

            is_expired = days_until_expiration is not None and days_until_expiration < 0
            near_expiry = days_until_expiration is not None and days_until_expiration < 14
            wildcard_count = sum(1 for item in san if "*." in item)

            findings = {
                "host": host,
                "issuer": issuer,
                "subject": subject,
                "serial_number": cert.get("serialNumber"),
                "version": cert.get("version"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "days_until_expiration": days_until_expiration,
                "is_expired": is_expired,
                "near_expiry": near_expiry,
                "subject_alt_names": san,
                "san_count": len(san),
                "wildcard_san_count": wildcard_count,
                "ocsp_endpoints": cert.get("OCSP", []),
                "ca_issuers": cert.get("caIssuers", []),
                "crl_distribution_points": cert.get("crlDistributionPoints", []),
            }

            risk = 0.03
            risk += 0.1 if is_expired else 0.0
            risk += 0.05 if near_expiry else 0.0
            risk += 0.04 if len(san) == 0 else 0.0
            risk += 0.03 if wildcard_count > 0 else 0.0

            evidence_count = len(san) + (1 if cert.get("serialNumber") else 0)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="active",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
