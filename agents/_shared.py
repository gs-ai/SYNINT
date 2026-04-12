import re
import ssl
import json
import math
import socket
import shutil
import subprocess
import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, Any, List, Tuple, Iterable

STANDARD_RESULT_KEYS = (
    "status",
    "agent",
    "target",
    "findings",
    "risk_score",
    "error",
    "reason",
    "evidence_mode",
    "evidence_count",
)

def normalize_target(target: str) -> str:
    target = str(target).strip()
    if not target:
        return ""
    if re.match(r"^https?://", target, re.I):
        parsed = urlparse(target)
        host = (parsed.hostname or parsed.netloc or target).strip()
        return host.lower()
    parsed = urlparse(f"//{target}")
    host = (parsed.hostname or "").strip()
    if host:
        return host.lower()
    return target

def looks_like_url(value: str) -> bool:
    try:
        parsed = urlparse(str(value))
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False

def is_domain(value: str) -> bool:
    value = normalize_target(value)
    if len(value) > 253:
        return False
    return bool(re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$", value))

def infer_target_types(target: Any) -> set[str]:
    if isinstance(target, dict):
        return {"fusion_bundle", "json", "object"}

    target_str = str(target).strip()
    types: set[str] = set()

    if not target_str:
        return {"text"}

    if "\n" in target_str:
        types.add("multiline")

    if looks_like_url(target_str):
        types.add("url")

    if is_ip(target_str):
        types.add("ip")

    if is_domain(target_str):
        types.add("domain")

    try:
        if Path(target_str).exists() and Path(target_str).is_file():
            types.add("file")
    except Exception:
        pass

    try:
        loaded = json.loads(target_str)
        if isinstance(loaded, (dict, list)):
            types.add("json")
    except Exception:
        pass

    types.add("text")
    return types

def target_matches(supported_target_types: Iterable[str], detected_target_types: set[str]) -> bool:
    supported = set(supported_target_types)
    if not supported or "any" in supported:
        return True
    return bool(supported & detected_target_types)

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy

def safe_hash_file(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _clamp_risk(score: float) -> float:
    return round(max(0.0, min(float(score), 1.0)), 4)

def _coerce_evidence_count(raw: Any, findings: Dict[str, Any] | None) -> int:
    if isinstance(raw, int) and raw >= 0:
        return raw
    if isinstance(findings, dict):
        explicit = findings.get("evidence_count")
        if isinstance(explicit, int) and explicit >= 0:
            return explicit
    return 0

def build_result(
    *,
    status: str,
    agent: str,
    target: Any,
    findings: Dict[str, Any] | None = None,
    risk_score: float = 0.0,
    error: str | None = None,
    reason: str | None = None,
    evidence_mode: str = "none",
    evidence_count: int = 0,
) -> Dict[str, Any]:
    findings_dict = findings if isinstance(findings, dict) else {}
    return {
        "status": status,
        "agent": agent,
        "target": target,
        "findings": findings_dict,
        "risk_score": _clamp_risk(risk_score),
        "error": error,
        "reason": reason,
        "evidence_mode": evidence_mode,
        "evidence_count": max(0, int(evidence_count)),
    }

def structured_error(
    agent: str,
    target: Any,
    exc: Exception | str,
    *,
    reason: str | None = None,
) -> Dict[str, Any]:
    return {
        **build_result(
            status="error",
            agent=agent,
            target=target,
            findings={},
            risk_score=0.0,
            error=str(exc),
            reason=reason or "agent execution error",
            evidence_mode="none",
            evidence_count=0,
        )
    }

def skipped(
    agent: str,
    target: Any,
    reason: str,
    *,
    findings: Dict[str, Any] | None = None,
    evidence_mode: str = "none",
    evidence_count: int = 0,
) -> Dict[str, Any]:
    return build_result(
        status="skipped",
        agent=agent,
        target=target,
        findings=findings or {},
        risk_score=0.0,
        error=None,
        reason=reason,
        evidence_mode=evidence_mode,
        evidence_count=evidence_count,
    )

def ok(
    agent: str,
    target: Any,
    findings: Dict[str, Any],
    risk_score: float,
    *,
    evidence_mode: str = "active",
    evidence_count: int | None = None,
    reason: str | None = None,
) -> Dict[str, Any]:
    count = _coerce_evidence_count(evidence_count, findings)
    return build_result(
        status="ok",
        agent=agent,
        target=target,
        findings=findings,
        risk_score=risk_score,
        error=None,
        reason=reason,
        evidence_mode=evidence_mode,
        evidence_count=count,
    )

def normalize_agent_output(agent: str, target: Any, output: Any) -> Dict[str, Any]:
    if not isinstance(output, dict):
        return structured_error(agent, target, "agent returned non-dict output")

    if all(key in output for key in STANDARD_RESULT_KEYS):
        return build_result(
            status=str(output.get("status", "unknown")),
            agent=str(output.get("agent", agent)),
            target=output.get("target", target),
            findings=output.get("findings") if isinstance(output.get("findings"), dict) else {},
            risk_score=float(output.get("risk_score", 0.0) or 0.0),
            error=output.get("error"),
            reason=output.get("reason"),
            evidence_mode=str(output.get("evidence_mode", "none")),
            evidence_count=int(output.get("evidence_count", 0) or 0),
        )

    status = str(output.get("status", "")).lower().strip()
    if not status:
        if output.get("error"):
            status = "error"
        elif output.get("skipped") or output.get("reason"):
            status = "skipped"
        else:
            status = "ok"

    reason = output.get("reason")
    if not reason and "skipped" in output:
        reason = str(output.get("skipped"))

    error = output.get("error")

    findings = output.get("findings")
    if not isinstance(findings, dict):
        reserved = {"status", "agent", "target", "risk_score", "error", "reason", "skipped"}
        findings = {k: v for k, v in output.items() if k not in reserved}

    risk_score = float(output.get("risk_score", 0.0) or 0.0)
    evidence_count = output.get("evidence_count")
    if not isinstance(evidence_count, int):
        evidence_count = findings.get("evidence_count", 0) if isinstance(findings, dict) else 0
        if not isinstance(evidence_count, int):
            evidence_count = 0

    evidence_mode = str(output.get("evidence_mode", "active" if evidence_count > 0 else "none"))
    return build_result(
        status=status,
        agent=agent,
        target=output.get("target", target),
        findings=findings,
        risk_score=risk_score,
        error=error,
        reason=reason,
        evidence_mode=evidence_mode,
        evidence_count=evidence_count,
    )

def domain_permutations(domain: str) -> List[str]:
    base = normalize_target(domain).lower()
    core = base.split(".")[0]
    tld = ".".join(base.split(".")[1:]) if "." in base else ""
    perms = set()
    substitutions = {
        "o": "0",
        "l": "1",
        "i": "1",
        "e": "3",
        "a": "4",
        "s": "5",
    }
    perms.add(base + "-login")
    perms.add(base + "-secure")
    perms.add("secure-" + base)
    perms.add("login-" + base)
    for k, v in substitutions.items():
        if k in core:
            perms.add(core.replace(k, v) + (("." + tld) if tld else ""))
    if len(core) > 3:
        perms.add(core[:-1] + (("." + tld) if tld else ""))
        perms.add(core + core[-1] + (("." + tld) if tld else ""))
    return sorted(x for x in perms if x and x != base)

def lexical_domain_score(domain: str) -> Tuple[float, Dict[str, Any]]:
    d = normalize_target(domain).lower()
    parts = d.split(".")
    label = parts[0] if parts else d
    entropy = shannon_entropy(label)
    digit_ratio = sum(ch.isdigit() for ch in label) / max(1, len(label))
    hyphen_count = label.count("-")
    suspicious_tokens = [t for t in ["secure", "login", "verify", "update", "account", "auth"] if t in d]
    score = 0.0
    score += min(entropy / 5.0, 0.4)
    score += min(digit_ratio, 0.2)
    score += min(hyphen_count * 0.05, 0.15)
    score += min(len(suspicious_tokens) * 0.1, 0.25)
    return min(score, 1.0), {
        "entropy": round(entropy, 4),
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_count": hyphen_count,
        "suspicious_tokens": suspicious_tokens
    }

def get_basic_ssl_cert(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    return cert

def resolve_first_ip(host_or_target: str, timeout: float = 2.0) -> str | None:
    host = normalize_target(host_or_target)
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)

def query_dns_records(rrtype: str, name: str, timeout_s: int = 4) -> List[str]:
    rr = rrtype.upper().strip()
    query_name = str(name).strip()
    dig_path = shutil.which("dig")
    if dig_path:
        try:
            out = subprocess.check_output(
                [dig_path, "+short", rr, query_name],
                timeout=timeout_s,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            pass

    nslookup_path = shutil.which("nslookup")
    if nslookup_path:
        try:
            out = subprocess.check_output(
                [nslookup_path, "-type=" + rr, query_name],
                timeout=timeout_s,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            cleaned: List[str] = []
            for line in out.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                lowered = stripped.lower()
                if lowered.startswith(("server:", "address:", "non-authoritative", "***")):
                    continue
                cleaned.append(stripped)
            return cleaned
        except Exception:
            pass

    return []

def classify_wallet(target: str) -> Dict[str, Any]:
    target = target.strip()
    return {
        "bitcoin_legacy": bool(re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", target)),
        "bitcoin_bech32": bool(re.match(r"^bc1[ac-hj-np-z02-9]{11,71}$", target)),
        "ethereum": bool(re.match(r"^0x[a-fA-F0-9]{40}$", target)),
        "monero_like": bool(re.match(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", target)),
        "solana_like": bool(re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", target)),
    }

def cheap_file_type(path: str) -> str:
    ext = Path(path).suffix.lower()
    mapping = {
        ".jpg": "image",
        ".jpeg": "image",
        ".png": "image",
        ".gif": "image",
        ".tif": "image",
        ".tiff": "image",
        ".bmp": "image",
        ".webp": "image",
        ".pdf": "pdf",
        ".docx": "docx",
        ".xlsx": "xlsx",
        ".pptx": "pptx",
        ".txt": "text",
        ".csv": "csv",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
    }
    return mapping.get(ext, "unknown")
