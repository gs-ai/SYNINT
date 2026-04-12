#!/usr/bin/env python3
"""Social media discovery agent with network-backed profile checks."""

from __future__ import annotations

import copy
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Sequence
from urllib.parse import urlparse

import requests

from agents.base_agent import OSINTAgent
from collectors.utils import create_safe_session
from ._shared import ok, skipped, structured_error


@dataclass(frozen=True)
class PlatformRule:
    name: str
    profile_url_template: str
    not_found_markers: tuple[str, ...] = ()
    blocked_markers: tuple[str, ...] = ()
    login_path_markers: tuple[str, ...] = ("/login", "/signin", "/checkpoint", "/challenge")
    retryable_statuses: tuple[int, ...] = (429, 500, 502, 503, 504)
    hard_not_found_statuses: tuple[int, ...] = (404, 410)
    hard_blocked_statuses: tuple[int, ...] = (401, 403, 451, 999)


DEFAULT_PLATFORM_RULES: Dict[str, PlatformRule] = {
    "twitter": PlatformRule(
        name="twitter",
        profile_url_template="https://x.com/{username}",
        not_found_markers=(
            "this account doesn’t exist",
            "this account doesn't exist",
            "try searching for another",
            "account doesn’t exist",
        ),
        blocked_markers=("rate limit exceeded", "are you a robot", "captcha"),
        login_path_markers=("/i/flow/login", "/login", "/account/access"),
    ),
    "facebook": PlatformRule(
        name="facebook",
        profile_url_template="https://www.facebook.com/{username}",
        not_found_markers=(
            "this page isn't available",
            "this content isn't available",
            "the link may be broken",
            "page isn't available",
        ),
        blocked_markers=("temporarily blocked", "unusual traffic", "security check"),
    ),
    "linkedin": PlatformRule(
        name="linkedin",
        profile_url_template="https://www.linkedin.com/in/{username}",
        not_found_markers=(
            "profile unavailable",
            "an exact match for",
            "page not found",
            "this page doesn’t exist",
            "this page doesn't exist",
        ),
        blocked_markers=("join linkedin", "verify you're human", "captcha"),
        hard_blocked_statuses=(401, 403, 451, 999),
    ),
}

GENERIC_BLOCKED_TEXT_MARKERS = (
    "captcha",
    "verify you're human",
    "verify you are human",
    "robot check",
    "access denied",
    "temporarily blocked",
    "unusual traffic",
    "security check",
)

GENERIC_LOGIN_TEXT_MARKERS = (
    "sign in",
    "log in",
    "join linkedin",
    "login to continue",
    "please log in",
    "continue with facebook",
)


class SocialMediaAgent(OSINTAgent):
    """Searches common platforms for reachable public profile URLs."""

    name = "SocialMediaAgent"
    supported_target_types = ("text", "domain")

    _CANDIDATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,59}$")
    _RESERVED_PATH_SEGMENTS = {
        "home",
        "login",
        "signin",
        "signup",
        "explore",
        "search",
        "about",
        "help",
        "privacy",
        "terms",
        "status",
        "settings",
        "messages",
        "notifications",
        "company",
        "in",
        "u",
        "i",
        "flow",
    }

    def __init__(
        self,
        platforms: List[str] | None = None,
        timeout: int = 8,
        *,
        platform_rules: Mapping[str, PlatformRule] | None = None,
        max_retries: int = 2,
        backoff_base_seconds: float = 0.5,
        backoff_max_seconds: float = 8.0,
        backoff_jitter: float = 0.2,
        cache_ttl_seconds: int = 600,
        connect_timeout: float | None = None,
        read_timeout: float | None = None,
        min_interval_per_host_seconds: float = 0.5,
        max_concurrency: int = 3,
        max_username_candidates: int = 4,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__()
        normalized_platforms = [p.strip().lower() for p in (platforms or ["twitter", "facebook", "linkedin"]) if p.strip()]
        self.platforms = list(dict.fromkeys(normalized_platforms))

        self.platform_rules = dict(platform_rules or DEFAULT_PLATFORM_RULES)
        self.max_retries = max(0, int(max_retries))
        self.backoff_base_seconds = max(0.0, float(backoff_base_seconds))
        self.backoff_max_seconds = max(self.backoff_base_seconds, float(backoff_max_seconds))
        self.backoff_jitter = max(0.0, min(float(backoff_jitter), 1.0))
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds))
        self.min_interval_per_host_seconds = max(0.0, float(min_interval_per_host_seconds))
        self.max_concurrency = max(1, int(max_concurrency))
        self.max_username_candidates = max(1, int(max_username_candidates))
        self.sleep_fn = sleep_fn

        timeout_float = max(1.0, float(timeout))
        self.connect_timeout = float(connect_timeout) if connect_timeout is not None else min(4.0, timeout_float)
        self.read_timeout = float(read_timeout) if read_timeout is not None else timeout_float

        self._thread_local = threading.local()
        self._cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()
        self._cache_hits = 0
        self._cache_misses = 0
        self._host_last_request_at: Dict[str, float] = {}
        self._host_lock_map: Dict[str, threading.Lock] = {}
        self._host_lock_map_guard = threading.Lock()

    def _get_session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = create_safe_session()
            self._thread_local.session = session
        return session

    def _sanitize_candidate(self, value: str) -> str | None:
        candidate = str(value).strip().lstrip("@").strip("/")
        candidate = candidate.split("?", 1)[0].split("#", 1)[0].strip().strip(".")
        if not candidate:
            return None
        if not self._CANDIDATE_RE.match(candidate):
            return None
        return candidate

    def _derive_candidate_usernames(self, target: str) -> List[str]:
        raw = str(target).strip()
        if not raw:
            return []

        candidates: List[str] = []

        def add(value: str | None) -> None:
            if value is None:
                return
            candidate = self._sanitize_candidate(value)
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        add(raw)

        lowered = raw.lower()
        if "@" in raw and "://" not in lowered:
            local_part, _, domain_part = raw.partition("@")
            add(local_part)
            if "." in domain_part:
                add(domain_part.split(".", 1)[0])

        if "." in raw and "/" not in raw and " " not in raw and "@" not in raw:
            add(raw.split(".", 1)[0])

        if "://" in lowered:
            parsed = urlparse(raw)
            hostname = (parsed.hostname or "").lower()
            if hostname:
                host_label = hostname.split(".")[0]
                if host_label not in {"www", "m", "mobile"}:
                    add(host_label)
            for segment in reversed([s for s in parsed.path.split("/") if s]):
                clean_segment = segment.strip().lower()
                if clean_segment in self._RESERVED_PATH_SEGMENTS:
                    continue
                add(segment)

        if raw.startswith("@"):
            add(raw[1:])

        return candidates[: self.max_username_candidates]

    def _platform_url(self, platform: str, username: str) -> str | None:
        rule = self.platform_rules.get(platform.lower())
        if not rule:
            return None
        return rule.profile_url_template.format(username=username)

    def _get_host_lock(self, host: str) -> threading.Lock:
        with self._host_lock_map_guard:
            if host not in self._host_lock_map:
                self._host_lock_map[host] = threading.Lock()
            return self._host_lock_map[host]

    def _respect_host_rate_limit(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host or self.min_interval_per_host_seconds <= 0:
            return

        host_lock = self._get_host_lock(host)
        with host_lock:
            last_at = self._host_last_request_at.get(host, 0.0)
            now = time.monotonic()
            wait_seconds = self.min_interval_per_host_seconds - (now - last_at)
            if wait_seconds > 0:
                self.sleep_fn(wait_seconds)
            self._host_last_request_at[host] = time.monotonic()

    def _cache_get(self, url: str) -> Dict[str, Any] | None:
        if self.cache_ttl_seconds <= 0:
            return None
        with self._cache_lock:
            entry = self._cache.get(url)
            if not entry:
                self._cache_misses += 1
                return None

            cached_at, payload = entry
            if (time.monotonic() - cached_at) > self.cache_ttl_seconds:
                self._cache.pop(url, None)
                self._cache_misses += 1
                return None

            self._cache_hits += 1
            return copy.deepcopy(payload)

    def _cache_set(self, url: str, payload: Dict[str, Any]) -> None:
        if self.cache_ttl_seconds <= 0:
            return
        with self._cache_lock:
            self._cache[url] = (time.monotonic(), copy.deepcopy(payload))

    def _http_get(self, url: str) -> requests.Response:
        return self._get_session().get(
            url,
            timeout=(self.connect_timeout, self.read_timeout),
            allow_redirects=True,
        )

    def _retry_delay(self, attempt_number: int) -> float:
        delay = self.backoff_base_seconds * (2 ** max(0, attempt_number - 1))
        if self.backoff_jitter > 0:
            delay += random.uniform(0.0, delay * self.backoff_jitter)
        return min(delay, self.backoff_max_seconds)

    @staticmethod
    def _matching_markers(text: str, markers: Sequence[str]) -> List[str]:
        if not text:
            return []
        found = [m for m in markers if m in text]
        return found[:5]

    def _classify_response(
        self,
        *,
        rule: PlatformRule,
        username: str,
        url: str,
        response: requests.Response,
        attempts: int,
        from_cache: bool,
    ) -> Dict[str, Any]:
        status_code = int(getattr(response, "status_code", 0) or 0)
        final_url = str(getattr(response, "url", url))
        final_path = (urlparse(final_url).path or "").lower()
        final_url_lower = final_url.lower()
        body_text = str(getattr(response, "text", "") or "")[:12000].lower()
        redirect_chain = [
            {"status": int(getattr(h, "status_code", 0) or 0), "url": str(getattr(h, "url", ""))}
            for h in list(getattr(response, "history", []))
        ]

        not_found_hits = self._matching_markers(body_text, rule.not_found_markers)
        blocked_hits = self._matching_markers(body_text, rule.blocked_markers + GENERIC_BLOCKED_TEXT_MARKERS)
        login_hits = self._matching_markers(body_text, GENERIC_LOGIN_TEXT_MARKERS)
        username_in_final_url = username.lower() in final_url_lower

        classification: Dict[str, Any] = {
            "platform": rule.name,
            "username": username,
            "url": url,
            "final_url": final_url,
            "http_status": status_code,
            "attempts": attempts,
            "from_cache": from_cache,
            "redirect_chain": redirect_chain,
            "status": "unknown",
            "status_reason": "unclassified",
            "confidence": 0.2,
            "matched_markers": {
                "not_found": not_found_hits,
                "blocked": blocked_hits,
                "login": login_hits,
            },
            "retryable": status_code in set(rule.retryable_statuses),
        }

        if status_code in set(rule.hard_not_found_statuses):
            classification.update({"status": "not_found", "status_reason": "hard_not_found_status", "confidence": 0.98})
            return classification

        if not_found_hits:
            classification.update({"status": "not_found", "status_reason": "not_found_marker", "confidence": 0.92})
            return classification

        has_login_path = any(marker in final_path for marker in rule.login_path_markers)
        if status_code in set(rule.hard_blocked_statuses):
            classification.update({"status": "blocked", "status_reason": "hard_blocked_status", "confidence": 0.78})
            return classification

        if blocked_hits or has_login_path or login_hits:
            classification.update({"status": "blocked", "status_reason": "access_challenge_or_login_gate", "confidence": 0.7})
            return classification

        if status_code == 429:
            classification.update({"status": "error", "status_reason": "rate_limited", "confidence": 0.15})
            return classification

        if status_code in set(rule.retryable_statuses):
            classification.update({"status": "error", "status_reason": f"transient_http_{status_code}", "confidence": 0.15})
            return classification

        if 200 <= status_code < 400:
            if username_in_final_url:
                classification.update({"status": "reachable", "status_reason": "username_in_final_url", "confidence": 0.88})
            else:
                classification.update({"status": "probably_exists", "status_reason": "successful_http_without_negative_markers", "confidence": 0.64})
            return classification

        classification.update({"status": "error", "status_reason": f"unexpected_http_{status_code}", "confidence": 0.1})
        return classification

    def _is_retryable_exception(self, exc: Exception) -> bool:
        return isinstance(exc, (requests.Timeout, requests.ConnectionError))

    def _check_profile(self, rule: PlatformRule, url: str, username: str) -> Dict[str, Any]:
        cached = self._cache_get(url)
        if cached is not None:
            cached["from_cache"] = True
            return cached

        max_attempts = self.max_retries + 1
        for attempt_number in range(1, max_attempts + 1):
            try:
                self._respect_host_rate_limit(url)
                response = self._http_get(url)
                classified = self._classify_response(
                    rule=rule,
                    username=username,
                    url=url,
                    response=response,
                    attempts=attempt_number,
                    from_cache=False,
                )

                if classified.get("retryable") and attempt_number < max_attempts:
                    self.sleep_fn(self._retry_delay(attempt_number))
                    continue

                self._cache_set(url, classified)
                return classified
            except requests.RequestException as exc:
                retryable_exception = self._is_retryable_exception(exc)
                if retryable_exception and attempt_number < max_attempts:
                    self.sleep_fn(self._retry_delay(attempt_number))
                    continue

                failure = {
                    "platform": rule.name,
                    "username": username,
                    "url": url,
                    "final_url": url,
                    "http_status": None,
                    "attempts": attempt_number,
                    "from_cache": False,
                    "redirect_chain": [],
                    "status": "error",
                    "status_reason": "request_exception",
                    "detail": str(exc),
                    "confidence": 0.1,
                    "matched_markers": {"not_found": [], "blocked": [], "login": []},
                    "retryable": retryable_exception,
                }
                self._cache_set(url, failure)
                return failure

        # Defensive fallback: should not be reached.
        return {
            "platform": rule.name,
            "username": username,
            "url": url,
            "final_url": url,
            "http_status": None,
            "attempts": max_attempts,
            "from_cache": False,
            "redirect_chain": [],
            "status": "error",
            "status_reason": "unexpected_fallthrough",
            "detail": "request loop exited unexpectedly",
            "confidence": 0.1,
            "matched_markers": {"not_found": [], "blocked": [], "login": []},
            "retryable": False,
        }

    @staticmethod
    def _pick_best_attempt(attempts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        priority = {
            "reachable": 6,
            "probably_exists": 5,
            "blocked": 4,
            "unknown": 3,
            "not_found": 2,
            "error": 1,
            "unsupported": 0,
        }
        if not attempts:
            return {"status": "unknown", "status_reason": "no_attempts", "confidence": 0.0}
        return max(attempts, key=lambda item: (priority.get(str(item.get("status")), -1), float(item.get("confidence", 0.0))))

    def _analyze_platform(self, platform: str, candidates: Sequence[str]) -> Dict[str, Any]:
        rule = self.platform_rules.get(platform)
        if not rule:
            return {
                "platform": platform,
                "status": "unsupported",
                "status_reason": "platform_not_configured",
                "confidence": 0.0,
                "attempted_usernames": [],
                "attempt_log": [],
            }

        attempts: List[Dict[str, Any]] = []
        for candidate in candidates:
            url = self._platform_url(platform, candidate)
            if not url:
                continue
            profile_result = self._check_profile(rule, url, candidate)
            attempts.append(profile_result)

            # Stop after high-signal outcomes to reduce unnecessary network traffic.
            if profile_result.get("status") in {"reachable", "probably_exists"}:
                break
            if profile_result.get("status") == "blocked" and float(profile_result.get("confidence", 0.0)) >= 0.7:
                break

        best = copy.deepcopy(self._pick_best_attempt(attempts))
        best["platform"] = platform
        best["attempted_usernames"] = [str(item.get("username", "")) for item in attempts]
        best["attempt_log"] = [
            {
                "username": item.get("username"),
                "status": item.get("status"),
                "status_reason": item.get("status_reason"),
                "http_status": item.get("http_status"),
                "final_url": item.get("final_url"),
                "attempts": item.get("attempts"),
                "from_cache": item.get("from_cache"),
            }
            for item in attempts
        ]
        return best

    @staticmethod
    def _count_statuses(profiles: Sequence[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in profiles:
            status = str(entry.get("status", "unknown"))
            counts[status] = counts.get(status, 0) + 1
        return counts

    @staticmethod
    def _risk_from_profiles(profiles: Sequence[Dict[str, Any]]) -> float:
        confirmed = [p for p in profiles if p.get("status") in {"reachable", "probably_exists"}]
        blocked = [p for p in profiles if p.get("status") == "blocked"]
        if not confirmed:
            return 0.0

        confidence_sum = sum(float(p.get("confidence", 0.0)) for p in confirmed)
        platform_diversity = len({str(p.get("platform", "")) for p in confirmed})
        blocked_bonus = min(0.03, len(blocked) * 0.01)
        raw_score = (confidence_sum * 0.08) + (platform_diversity * 0.01) + blocked_bonus
        return min(round(raw_score, 4), 0.35)

    def run(self, target: str) -> Dict[str, object]:
        original_target = str(target).strip()
        candidates = self._derive_candidate_usernames(original_target)

        if not original_target:
            return skipped(
                self.name,
                original_target,
                reason="empty target",
                findings={"profiles": [], "username_candidates": []},
            )
        if not candidates:
            return skipped(
                self.name,
                original_target,
                reason="could not derive valid username candidates from target",
                findings={"profiles": [], "username_candidates": []},
            )

        try:
            if self.max_concurrency > 1 and len(self.platforms) > 1:
                with ThreadPoolExecutor(max_workers=min(self.max_concurrency, len(self.platforms))) as pool:
                    profiles = list(pool.map(lambda p: self._analyze_platform(p, candidates), self.platforms))
            else:
                profiles = [self._analyze_platform(platform, candidates) for platform in self.platforms]

            status_breakdown = self._count_statuses(profiles)
            confirmed = [p for p in profiles if p.get("status") in {"reachable", "probably_exists"}]
            findings: Dict[str, Any] = {
                "profiles": profiles,
                "username_candidates": candidates,
                "platforms_checked": list(self.platforms),
                "status_breakdown": status_breakdown,
                "reachable_count": status_breakdown.get("reachable", 0),
                "probable_count": status_breakdown.get("probably_exists", 0),
                "blocked_count": status_breakdown.get("blocked", 0),
                "not_found_count": status_breakdown.get("not_found", 0),
                "error_count": status_breakdown.get("error", 0),
                "unsupported_count": status_breakdown.get("unsupported", 0),
                "cache_stats": {
                    "hits": self._cache_hits,
                    "misses": self._cache_misses,
                    "ttl_seconds": self.cache_ttl_seconds,
                },
            }
            result = ok(
                self.name,
                original_target,
                findings,
                risk_score=self._risk_from_profiles(profiles),
                evidence_mode="active" if confirmed else "none",
                evidence_count=len(confirmed),
            )
            self.results = result
            return result
        except Exception as exc:
            return structured_error(self.name, original_target, exc)
