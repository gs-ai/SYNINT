"""Entity extraction and normalization helpers."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
PHONE_RE = re.compile(r"(?:(?:tel|phone|mobile|cell|fax)\s*:\s*)?(?:\+?\d[\d\s().-]{6,}\d)(?:\s*(?:x|ext\.?|extension)\s*\d{1,8})?", re.I)
URL_RE = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
HANDLE_RE = re.compile(r"(?<![\w@.])@[A-Za-z0-9_](?:[A-Za-z0-9_.-]{1,31})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
DATE_TOKEN_RE = re.compile(
    r"\b(?:"
    r"\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?"
    r"|\d{4}/\d{2}/\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{2,4}"
    r"|\d{1,2}-\d{1,2}-\d{2,4}"
    r"|(?:\d{1,2}\s+)?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}"
    r"|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{4}"
    r")\b",
    re.I,
)
PERSON_LIKE_RE = re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b")
ORG_HINT_RE = re.compile(r"\b[A-Z][A-Za-z0-9&.-]{1,40}\s+(?:Inc|LLC|Ltd|Corp|Company|Group|Labs|Technologies)\b")
ADDRESS_RE = re.compile(r"\b\d{1,6}\s+[A-Za-z0-9 .'-]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b", re.I)
_TRAILING_PUNCTUATION = ".,;:!?)]}>\"'"
_LEADING_PUNCTUATION = "([<{\"'"


def unobfuscate_text(text: str) -> str:
    value = str(text or "")
    replacements = [
        (r"\bhxxps://", "https://"),
        (r"\bhxxp://", "http://"),
        (r"\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+", "@"),
        (r"\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+", "."),
        (r"\[\.\]", "."),
        (r"\(\.\)", "."),
        (r"\[\s*:\s*\]", ":"),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value, flags=re.I)
    value = re.sub(r"([A-Za-z0-9-])\s*\.\s*([A-Za-z0-9-])", r"\1.\2", value)
    value = re.sub(r"([A-Za-z0-9._%+-]+)\s*@\s*((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})", r"\1@\2", value)
    return value


def _clean_token(value: str) -> str:
    return str(value or "").strip().strip(_TRAILING_PUNCTUATION).lstrip(_LEADING_PUNCTUATION)


def _normalize_url(raw: str) -> str:
    value = _clean_token(raw)
    if value.lower().startswith("www."):
        value = f"https://{value}"
    return value


def _is_valid_domain(value: str) -> bool:
    candidate = _clean_token(value).rstrip(".").lower()
    if not candidate or " " in candidate or "@" in candidate:
        return False
    if candidate.count(".") < 1:
        return False
    if candidate.startswith(("-", ".")) or candidate.endswith(("-", ".")):
        return False
    return bool(DOMAIN_RE.fullmatch(candidate))


def _extract_domains(body: str, urls: List[str], emails: List[str]) -> List[str]:
    values = set()
    email_domains = {item.split("@", 1)[1] for item in emails if "@" in item}

    def _add(candidate: str) -> None:
        if _is_valid_domain(candidate):
            values.add(candidate)
            if candidate.startswith("www.") and _is_valid_domain(candidate[4:]):
                values.add(candidate[4:])

    for raw in DOMAIN_RE.findall(body):
        candidate = _clean_token(raw).rstrip(".").lower()
        _add(candidate)
    for raw_url in urls:
        host = (urlparse(raw_url).hostname or "").strip().lower()
        if host:
            _add(host)
    return sorted(values - email_domains)


def _extract_ips(body: str) -> List[str]:
    values = set()
    for regex in (IPV4_RE, IPV6_RE):
        for match in regex.finditer(body):
            candidate = _clean_token(match.group(0))
            try:
                values.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
    return sorted(values)


def _extract_handles(body: str, emails: List[str]) -> List[str]:
    values = set()
    email_locals = {item.split("@", 1)[0].lower() for item in emails if "@" in item}
    for match in HANDLE_RE.finditer(body):
        handle = _clean_token(match.group(0))
        if not handle or handle == "@":
            continue
        if handle[1:].lower() in email_locals:
            continue
        values.add(handle)
    return sorted(values)


def normalize_phone(raw: str) -> str:
    token = _clean_token(raw)
    if not token or "/" in token:
        return raw.strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 7 or len(digits) > 15:
        return raw.strip()
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    if len(digits) >= 8:
        return f"+{digits}"
    return raw.strip()


def _extract_phones(body: str) -> List[str]:
    values = set()
    for match in PHONE_RE.finditer(body):
        raw = _clean_token(match.group(0))
        normalized = normalize_phone(raw)
        if not normalized.startswith("+"):
            continue
        digits = re.sub(r"\D", "", normalized)
        if len(digits) < 8 or len(digits) > 15:
            continue
        if digits in {"0" * len(digits), "1" * len(digits)}:
            continue
        values.add(normalized)
    return sorted(values)


def extract_entities_from_text(text: str) -> Dict[str, List[str]]:
    body = unobfuscate_text(text)
    emails = sorted(set(_clean_token(m.group(0)).lower() for m in EMAIL_RE.finditer(body)))
    urls = sorted(set(_normalize_url(m.group(0)) for m in URL_RE.finditer(body)))
    domains = _extract_domains(body, urls, emails)
    ips = _extract_ips(body)
    handles = _extract_handles(body, emails)
    phones = _extract_phones(body)
    dates = sorted(set(_clean_token(m.group(0)) for m in DATE_TOKEN_RE.finditer(body)))
    people = sorted(set(m.group(0).strip() for m in PERSON_LIKE_RE.finditer(body)))
    orgs = sorted(set(m.group(0).strip() for m in ORG_HINT_RE.finditer(body)))
    addresses = sorted(set(m.group(0).strip() for m in ADDRESS_RE.finditer(body)))
    return {
        "emails": emails,
        "phones": phones,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "handles": handles,
        "dates": dates,
        "suspected_people": people,
        "suspected_orgs": orgs,
        "addresses": addresses,
    }


def normalize_date_to_iso(raw: str) -> str | None:
    value = str(raw).strip()
    if not value:
        return None
    value = value.replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(value).isoformat()
    except Exception:
        pass

    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%m-%d-%Y",
        "%m-%d-%y",
        "%d %b %Y",
        "%d %B %Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%b %Y",
        "%B %Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).isoformat()
        except Exception:
            continue
    return None


def content_hash(content: str) -> str:
    import hashlib

    return hashlib.sha256((content or "").encode("utf-8", errors="ignore")).hexdigest()


def flatten_strings(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            out.append(text)
    return out
