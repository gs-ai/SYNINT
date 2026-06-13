"""Strict validation for normalized SYNINT agent envelopes."""

from __future__ import annotations

from typing import Any, Dict, Tuple

_VALID_STATUSES = {"ok", "skipped", "error"}


def validate_result(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str | None]:
    """Validate the normalized agent output envelope."""
    if not isinstance(payload, dict):
        return False, {}, "normalized payload must be a dictionary"

    cleaned = dict(payload)
    status = str(cleaned.get("status", "")).strip().lower()
    if status not in _VALID_STATUSES:
        return False, cleaned, f"invalid status '{cleaned.get('status')}'"
    cleaned["status"] = status

    for key in ("agent",):
        value = cleaned.get(key)
        if not isinstance(value, str) or not value.strip():
            return False, cleaned, f"missing required string field '{key}'"
        cleaned[key] = value.strip()

    if "findings" not in cleaned or not isinstance(cleaned.get("findings"), dict):
        return False, cleaned, "findings must be a dictionary"

    try:
        cleaned["risk_score"] = max(0.0, min(float(cleaned.get("risk_score", 0.0) or 0.0), 1.0))
    except (TypeError, ValueError):
        return False, cleaned, "risk_score must be numeric"

    cleaned["error"] = None if cleaned.get("error") in ("", None) else str(cleaned.get("error"))
    cleaned["reason"] = None if cleaned.get("reason") in ("", None) else str(cleaned.get("reason"))
    cleaned["evidence_mode"] = str(cleaned.get("evidence_mode", "none") or "none")

    try:
        cleaned["evidence_count"] = max(0, int(cleaned.get("evidence_count", 0) or 0))
    except (TypeError, ValueError):
        return False, cleaned, "evidence_count must be an integer"

    try:
        cleaned["execution_time"] = round(max(0.0, float(cleaned.get("execution_time", 0.0) or 0.0)), 4)
    except (TypeError, ValueError):
        return False, cleaned, "execution_time must be numeric"

    return True, cleaned, None
