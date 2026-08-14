"""Small, deterministic helpers for removing credentials from persisted text."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import quote, quote_plus


_URL_CREDENTIALS_RE = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]*)?@",
    flags=re.IGNORECASE,
)


def redact_url_credentials(value: object) -> str:
    """Redact user information embedded in URLs within arbitrary text."""
    return _URL_CREDENTIALS_RE.sub(r"\g<scheme>[REDACTED]@", str(value))


def redact_values(value: object, secrets: Iterable[object]) -> str:
    """Redact raw and URL-encoded forms of explicitly supplied secrets."""
    text = redact_url_credentials(value)
    candidates: set[str] = set()
    for raw_secret in secrets:
        secret = str(raw_secret or "")
        if not secret:
            continue
        candidates.update({secret, quote(secret, safe=""), quote_plus(secret)})
    for candidate in sorted(candidates, key=len, reverse=True):
        text = text.replace(candidate, "[REDACTED]")
    return text


__all__ = ["redact_url_credentials", "redact_values"]
