"""Entity extraction and normalization helpers."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}")
URL_RE = re.compile(r"https?://[^\s<>'\"]+")
DATE_TOKEN_RE = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2},\s*\d{4})\b",
    re.I,
)
PERSON_LIKE_RE = re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b")
ORG_HINT_RE = re.compile(r"\b[A-Z][A-Za-z0-9&.-]{1,40}\s+(?:Inc|LLC|Ltd|Corp|Company|Group|Labs|Technologies)\b")
ADDRESS_RE = re.compile(r"\b\d{1,6}\s+[A-Za-z0-9 .'-]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b", re.I)


def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    if len(digits) > 0:
        return f"+{digits}"
    return raw.strip()


def extract_entities_from_text(text: str) -> Dict[str, List[str]]:
    body = str(text or "")
    emails = sorted(set(m.group(0).strip().lower() for m in EMAIL_RE.finditer(body)))
    phones = sorted(set(normalize_phone(m.group(0)) for m in PHONE_RE.finditer(body)))
    urls = sorted(set(m.group(0).strip() for m in URL_RE.finditer(body)))
    dates = sorted(set(m.group(0).strip() for m in DATE_TOKEN_RE.finditer(body)))
    people = sorted(set(m.group(0).strip() for m in PERSON_LIKE_RE.finditer(body)))
    orgs = sorted(set(m.group(0).strip() for m in ORG_HINT_RE.finditer(body)))
    addresses = sorted(set(m.group(0).strip() for m in ADDRESS_RE.finditer(body)))
    return {
        "emails": emails,
        "phones": phones,
        "urls": urls,
        "dates": dates,
        "suspected_people": people,
        "suspected_orgs": orgs,
        "addresses": addresses,
    }


def normalize_date_to_iso(raw: str) -> str | None:
    value = str(raw).strip()
    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%b %d, %Y",
        "%B %d, %Y",
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
