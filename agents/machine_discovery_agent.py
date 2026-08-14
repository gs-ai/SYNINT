"""Experimental, opt-in public camera/ALPR/FLIR source discovery.

This agent searches a fixed public metadata API. It never contacts discovered
devices, retrieves streams, bypasses authentication, or performs control
operations. Raw search banners are transient and are never returned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1
import ipaddress
import json
import os
import re
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

from agents.base_agent import OSINTAgent
from core.redaction import redact_values
from ._pipeline import unpack_pipeline_input
from ._shared import ok, skipped, structured_error

REDACTED_PLATE = "[REDACTED-PLATE]"
SHODAN_SEARCH_ENDPOINT = "https://api.shodan.io/shodan/host/search"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_PLATE_VALUE_RE = re.compile(
    r"((?:license[_ -]?plate|plate(?:[_ -]?number)?|registration)"
    r"\s*[:=]\s*[\"']?)([A-Z0-9][A-Z0-9 -]{3,9})",
    re.IGNORECASE,
)
_PLATE_KEY_RE = re.compile(r"(?:license[_ -]?plate|plate(?:[_ -]?number)?)", re.IGNORECASE)

QUERY_DEFINITIONS: Tuple[Tuple[str, str], ...] = (
    ("camera", "screenshot.label:webcam"),
    ("alpr", 'http.title:"ALPR"'),
    ("flir", 'http.title:"FLIR"'),
)


def _bounded_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name, default)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def is_public_ip(value: str) -> bool:
    """Return true only for globally routable IP literals."""
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def _public_hostname(value: str) -> bool:
    hostname = value.strip().lower().rstrip(".")
    if not hostname or hostname == "localhost" or hostname.endswith((".local", ".internal")):
        return False
    if is_public_ip(hostname):
        return True
    return bool(_DOMAIN_RE.fullmatch(hostname))


def _redact_text(value: Any) -> Tuple[str, bool]:
    text = str(value or "")
    redacted, count = _PLATE_VALUE_RE.subn(lambda match: match.group(1) + REDACTED_PLATE, text)
    return redacted, count > 0


def _plate_indicators(value: Any, path: str = "") -> Tuple[set[str], bool]:
    fields: set[str] = set()
    value_found = False
    if isinstance(value, dict):
        for key, nested in value.items():
            child = f"{path}.{key}" if path else str(key)
            if _PLATE_KEY_RE.search(str(key)):
                fields.add(child)
                if nested not in (None, "", [], {}):
                    value_found = True
            nested_fields, nested_value = _plate_indicators(nested, child)
            fields.update(nested_fields)
            value_found = value_found or nested_value
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            nested_fields, nested_value = _plate_indicators(nested, f"{path}[{index}]")
            fields.update(nested_fields)
            value_found = value_found or nested_value
    elif isinstance(value, str):
        _, found = _redact_text(value)
        value_found = value_found or found
    return fields, value_found


@dataclass
class DiscoveryBudget:
    max_requests: int
    max_pages: int
    max_records: int
    max_runtime_seconds: int
    max_concurrency: int = 1
    started_monotonic: float = field(default_factory=time.monotonic)
    requests_spent: int = 0
    pages_spent: int = 0
    records_seen: int = 0

    @classmethod
    def from_environment(cls) -> "DiscoveryBudget":
        return cls(
            max_requests=_bounded_env("SYNINT_MACHINE_MAX_REQUESTS", 3, 1, 10),
            max_pages=_bounded_env("SYNINT_MACHINE_MAX_PAGES", 3, 1, 5),
            max_records=_bounded_env("SYNINT_MACHINE_MAX_RECORDS", 30, 1, 100),
            max_runtime_seconds=_bounded_env("SYNINT_MACHINE_MAX_RUNTIME", 30, 1, 120),
        )

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)

    @property
    def exhausted(self) -> bool:
        return (
            self.requests_spent >= self.max_requests
            or self.pages_spent >= self.max_pages
            or self.records_seen >= self.max_records
            or self.elapsed_seconds >= self.max_runtime_seconds
        )

    def note_request(self) -> None:
        if self.exhausted:
            raise RuntimeError("Machine discovery budget exhausted")
        self.requests_spent += 1
        self.pages_spent += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests": {"limit": self.max_requests, "spent": self.requests_spent},
            "pages": {"limit": self.max_pages, "spent": self.pages_spent},
            "records": {"limit": self.max_records, "seen": self.records_seen},
            "runtime_seconds": {
                "limit": self.max_runtime_seconds,
                "elapsed": round(self.elapsed_seconds, 4),
            },
            "concurrency": {"limit": self.max_concurrency, "used": 1},
            "exhausted": self.exhausted,
        }


class MachineDiscoveryAgent(OSINTAgent):
    """Discover public source metadata under an explicit experimental gate."""

    name = "MachineDiscoveryAgent"
    supported_target_types = ("domain", "url", "ip")

    @staticmethod
    def _scope_for_target(target: str) -> str | None:
        raw = target.strip()
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        hostname = (parsed.hostname or raw).strip().lower().rstrip(".")
        if is_public_ip(hostname):
            return f"net:{hostname}/32"
        if _public_hostname(hostname) and not is_public_ip(hostname):
            return f'hostname:"{hostname}"'
        return None

    @staticmethod
    def _validate_api_endpoint() -> None:
        parsed = urlparse(SHODAN_SEARCH_ENDPOINT)
        if parsed.scheme != "https" or parsed.hostname != "api.shodan.io":
            raise RuntimeError("Machine discovery API endpoint is outside the fixed allowlist")

    def _search_page(
        self,
        *,
        api_key: str,
        query: str,
        page: int,
        timeout: int,
    ) -> Dict[str, Any]:
        self._validate_api_endpoint()
        response = requests.get(
            SHODAN_SEARCH_ENDPOINT,
            params={"key": api_key, "query": query, "page": page},
            timeout=timeout,
            stream=True,
            allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise requests.RequestException("redirect refused by Machine discovery allowlist")
        response.raise_for_status()
        chunks: List[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError("Machine discovery response exceeds 5 MiB bound")
            chunks.append(chunk)
        payload = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
        if not isinstance(payload, dict):
            raise ValueError("Machine discovery response is not an object")
        return payload

    @staticmethod
    def _safe_record(match: Dict[str, Any], service_type: str, query_name: str) -> Dict[str, Any] | None:
        ip = str(match.get("ip_str") or "").strip()
        if not is_public_ip(ip):
            return None
        try:
            port = int(match.get("port"))
        except (TypeError, ValueError):
            return None
        if not 1 <= port <= 65535:
            return None

        http = match.get("http") if isinstance(match.get("http"), dict) else {}
        fields, plate_value_found = _plate_indicators(match)
        product, product_redacted = _redact_text(match.get("product"))
        title, title_redacted = _redact_text(http.get("title"))
        org, org_redacted = _redact_text(match.get("org"))
        plate_value_found = plate_value_found or product_redacted or title_redacted or org_redacted
        location = match.get("location") if isinstance(match.get("location"), dict) else {}
        scheme = "https" if port in {443, 8443} else "http"
        hostnames = sorted(
            {
                str(hostname).strip().lower()
                for hostname in (match.get("hostnames") or [])
                if _public_hostname(str(hostname))
            }
        )[:20]
        source_id = "machine_" + sha1(f"{ip}|{port}".encode("utf-8")).hexdigest()[:16]
        return {
            "source_id": source_id,
            "service_type": service_type,
            "classification": "CANDIDATE",
            "source_url": f"{scheme}://{ip}:{port}/",
            "ip": ip,
            "port": port,
            "transport": str(match.get("transport") or "tcp"),
            "product_candidate": product or None,
            "title": title or None,
            "organization": org or None,
            "country": str(location.get("country_name") or "") or None,
            "city": str(location.get("city") or "") or None,
            "location_is_approximate": True,
            "hostnames": hostnames,
            "query_name": query_name,
            "plate_data_indicator": bool(fields or plate_value_found),
            "plate_values_redacted": bool(plate_value_found),
            "plate_field_names": sorted(fields),
            "raw_banner_persisted": False,
            "screenshot_persisted": False,
        }

    def run(self, indicator: Any):
        target, _, _ = unpack_pipeline_input(indicator)
        if not target:
            target = str(indicator or "").strip()
        api_key = str(os.getenv("SHODAN_API_KEY", "")).strip()
        if not api_key:
            return skipped(
                self.name,
                target,
                "SHODAN_API_KEY not configured; experimental Machine discovery unavailable",
            )
        scope = self._scope_for_target(target)
        if not scope:
            return skipped(
                self.name,
                target,
                "Machine discovery requires a public-routable IP or public hostname target",
            )

        budget = DiscoveryBudget.from_environment()
        pages_per_query = _bounded_env("SYNINT_MACHINE_PAGES_PER_QUERY", 1, 1, 2)
        timeout = _bounded_env("SYNINT_MACHINE_TIMEOUT", 10, 1, 30)
        sources: Dict[str, Dict[str, Any]] = {}
        query_ledger: List[Dict[str, Any]] = []

        try:
            for service_type, base_query in QUERY_DEFINITIONS:
                if budget.exhausted:
                    break
                query = f"{base_query} {scope}"
                for page in range(1, pages_per_query + 1):
                    if budget.exhausted:
                        break
                    budget.note_request()
                    payload = self._search_page(
                        api_key=api_key,
                        query=query,
                        page=page,
                        timeout=timeout,
                    )
                    matches = payload.get("matches") if isinstance(payload.get("matches"), list) else []
                    accepted = 0
                    for match in matches:
                        if budget.records_seen >= budget.max_records:
                            break
                        budget.records_seen += 1
                        if not isinstance(match, dict):
                            continue
                        record = self._safe_record(match, service_type, service_type)
                        if record is None:
                            continue
                        existing = sources.get(record["source_id"])
                        if existing is None:
                            record["service_types"] = [service_type]
                            sources[record["source_id"]] = record
                        elif service_type not in existing["service_types"]:
                            existing["service_types"].append(service_type)
                            if record["plate_data_indicator"]:
                                existing["plate_data_indicator"] = True
                                existing["plate_values_redacted"] = record["plate_values_redacted"]
                                existing["plate_field_names"] = sorted(
                                    set(existing["plate_field_names"]) | set(record["plate_field_names"])
                                )
                        accepted += 1
                    query_ledger.append(
                        {
                            "service_type": service_type,
                            "page": page,
                            "records_returned": len(matches),
                            "records_accepted": accepted,
                        }
                    )
                    total = int(payload.get("total", 0) or 0)
                    if not matches or page * 100 >= total:
                        break

            ordered_sources = sorted(sources.values(), key=lambda item: item["source_id"])
            counts = {
                service_type: sum(service_type in item["service_types"] for item in ordered_sources)
                for service_type, _ in QUERY_DEFINITIONS
            }
            findings = {
                "classification": "EXPERIMENTAL",
                "activation": "explicit --agents MachineDiscoveryAgent selection",
                "sources": ordered_sources,
                "counts": {**counts, "unique_sources": len(ordered_sources)},
                "query_ledger": query_ledger,
                "budget": budget.to_dict(),
                "safety": {
                    "read_only": True,
                    "direct_device_requests": 0,
                    "device_control_operations": [],
                    "authentication_bypass": False,
                    "fixed_api_allowlist": ["api.shodan.io"],
                    "private_network_results_blocked": True,
                    "redirects_followed": False,
                    "plate_redaction_before_persistence": True,
                    "raw_banners_persisted": False,
                    "screenshots_persisted": False,
                },
            }
            return ok(
                self.name,
                target,
                findings,
                min(0.02 + len(ordered_sources) * 0.005, 0.35),
                evidence_mode="passive",
                evidence_count=len(ordered_sources),
            )
        except (requests.RequestException, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            safe_error = redact_values(exc, [api_key])
            return structured_error(self.name, target, f"Machine discovery unavailable: {safe_error}")
