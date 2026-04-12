import socket
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._shared import (
    is_domain,
    normalize_target,
    ok,
    query_dns_records,
    skipped,
    structured_error,
)


class DNSEnumAgent(OSINTAgent):
    """DNS and mail-security posture reconnaissance."""

    name = "DNSEnumAgent"
    supported_target_types = ("domain", "url")

    COMMON_SUBDOMAINS = [
        "www", "mail", "webmail", "vpn", "remote", "portal", "admin", "dev",
        "test", "staging", "api", "cdn", "app", "auth", "m", "blog", "docs",
        "files", "ftp", "ns1", "ns2", "mx", "smtp", "imap", "pop", "citrix",
    ]

    DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"]

    def _resolve(self, hostname: str) -> Dict[str, List[str]]:
        out = {"A": [], "AAAA": []}
        try:
            infos = socket.getaddrinfo(hostname, None)
            for item in infos:
                family = item[0]
                ip = item[4][0]
                if family == socket.AF_INET and ip not in out["A"]:
                    out["A"].append(ip)
                elif family == socket.AF_INET6 and ip not in out["AAAA"]:
                    out["AAAA"].append(ip)
        except Exception:
            pass
        return out

    def _wildcard_heuristic(self, domain: str) -> bool:
        fake = f"nonexistent-wildcard-check-9x7q.{domain}"
        return any(self._resolve(fake).values())

    def _collect_mail_security(self, domain: str) -> Dict[str, Any]:
        txt_records = query_dns_records("TXT", domain)
        dmarc_records = query_dns_records("TXT", f"_dmarc.{domain}")

        dkim_hits: List[Dict[str, Any]] = []
        for selector in self.DKIM_SELECTORS:
            host = f"{selector}._domainkey.{domain}"
            records = query_dns_records("TXT", host)
            if records:
                dkim_hits.append({"selector": selector, "records": records})

        spf_present = any("v=spf1" in rec.lower() for rec in txt_records)
        dmarc_present = any("v=dmarc1" in rec.lower() for rec in dmarc_records)

        return {
            "txt": txt_records,
            "spf_present": spf_present,
            "dmarc_records": dmarc_records,
            "dmarc_present": dmarc_present,
            "dkim_selectors_found": dkim_hits,
            "dkim_selector_count": len(dkim_hits),
        }

    def run(self, target: str):
        try:
            domain = normalize_target(target)
            if not is_domain(domain):
                return skipped(self.name, target, "target is not a domain")

            base_records = {
                "A_AAAA": self._resolve(domain),
                "MX": query_dns_records("MX", domain),
                "NS": query_dns_records("NS", domain),
                "TXT": query_dns_records("TXT", domain),
                "CNAME": query_dns_records("CNAME", domain),
            }

            discovered = []
            for sub in self.COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{domain}"
                recs = self._resolve(fqdn)
                cname = query_dns_records("CNAME", fqdn)
                if recs["A"] or recs["AAAA"] or cname:
                    discovered.append({"host": fqdn, "records": {**recs, "CNAME": cname}})

            wildcard = self._wildcard_heuristic(domain)
            mail_security = self._collect_mail_security(domain)

            evidence_count = (
                len(discovered)
                + len(base_records["MX"])
                + len(base_records["NS"])
                + len(base_records["TXT"])
                + len(mail_security["dmarc_records"])
                + mail_security["dkim_selector_count"]
            )

            risk = 0.02
            risk += min(len(discovered) / 30.0, 0.25)
            risk += 0.05 if wildcard else 0.0
            risk += 0.05 if not mail_security["dmarc_present"] else 0.0
            risk += 0.03 if not mail_security["spf_present"] else 0.0

            findings = {
                "domain": domain,
                "base_records": base_records,
                "subdomain_hits": discovered,
                "subdomain_hit_count": len(discovered),
                "wildcard_dns_suspected": wildcard,
                "mail_security": mail_security,
            }

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
