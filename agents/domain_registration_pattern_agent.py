"""Domain registration and naming pattern heuristics for campaign clustering support."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error


class DomainRegistrationPatternAgent(OSINTAgent):
    """Analyze registrar/age/TLD/naming signals from available WHOIS context."""

    name = "DomainRegistrationPatternAgent"
    supported_target_types = ("domain", "url", "text", "json")
    consume_all_results = True

    def _domain_bits(self, target: str) -> Dict[str, str]:
        raw = target.replace("https://", "").replace("http://", "").split("/", 1)[0]
        parts = [part for part in raw.split(".") if part]
        if len(parts) < 2:
            return {"domain": raw, "sld": raw, "tld": ""}
        return {
            "domain": raw,
            "sld": ".".join(parts[:-1]),
            "tld": parts[-1],
        }

    def _extract_whois_lines(self, whois_data: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in whois_data.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key_norm = key.strip().lower()
            value_norm = value.strip()
            if not value_norm:
                continue
            if key_norm in {"creation date", "created", "created on", "registration time"} and "creation_date" not in out:
                out["creation_date"] = value_norm
            elif key_norm in {"updated date", "last updated", "updated on"} and "updated_date" not in out:
                out["updated_date"] = value_norm
            elif key_norm in {"registry expiry date", "expiration date", "expires on", "expiry date"} and "expiry_date" not in out:
                out["expiry_date"] = value_norm
            elif key_norm in {"registrar", "sponsoring registrar"} and "registrar" not in out:
                out["registrar"] = value_norm
        return out

    def run(self, indicator: Any):
        target, _, agent_results = unpack_pipeline_input(indicator)
        if not target:
            return skipped(self.name, indicator, "missing target")

        try:
            bits = self._domain_bits(target)
            whois_findings = agent_results.get("WhoisAgent", {}).get("result", {}).get("findings", {})
            whois_data = str(whois_findings.get("whois_data", "")) if isinstance(whois_findings, dict) else ""
            parsed = self._extract_whois_lines(whois_data)

            creation_date = parsed.get("creation_date")
            age_days = None
            if creation_date:
                try:
                    created = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                    age_days = int((datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days)
                except Exception:
                    age_days = None

            naming_pattern = {
                "length": len(bits.get("sld", "")),
                "has_hyphen": "-" in bits.get("sld", ""),
                "has_digits": any(ch.isdigit() for ch in bits.get("sld", "")),
                "token_count": len(bits.get("sld", "").split("-")),
            }

            tld_pattern = {
                "tld": bits.get("tld", ""),
                "is_common_tld": bits.get("tld", "") in {"com", "org", "net", "io", "co"},
            }

            registrar_signals = {
                "registrar": parsed.get("registrar"),
                "creation_date": creation_date,
                "updated_date": parsed.get("updated_date"),
                "expiry_date": parsed.get("expiry_date"),
                "domain_age_days": age_days,
            }

            registration_profile = {
                "domain": bits.get("domain"),
                "sld": bits.get("sld"),
                "tld": bits.get("tld"),
                "registrar_present": bool(parsed.get("registrar")),
                "age_known": age_days is not None,
            }

            campaign_hooks = {
                "cluster_with_same_tld": True,
                "cluster_with_similar_sld_shape": True,
                "cluster_with_registrar_reuse": bool(parsed.get("registrar")),
            }

            findings = {
                "registration_profile": registration_profile,
                "naming_pattern": naming_pattern,
                "tld_pattern": tld_pattern,
                "registrar_signals": registrar_signals,
                "campaign_similarity_hooks": campaign_hooks,
            }

            risk = 0.02
            if naming_pattern["has_hyphen"] and naming_pattern["has_digits"]:
                risk += 0.08
            if age_days is not None and age_days < 60:
                risk += 0.12

            return ok(
                self.name,
                target,
                findings,
                min(risk, 0.5),
                evidence_mode="heuristic",
                evidence_count=1 if parsed else 0,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
