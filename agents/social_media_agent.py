#!/usr/bin/env python3
"""Social media discovery agent with network-backed profile checks."""

from __future__ import annotations

from typing import Dict, List

import requests

from agents.base_agent import OSINTAgent


class SocialMediaAgent(OSINTAgent):
    """Searches common platforms for reachable public profile URLs."""

    def __init__(self, platforms: List[str] | None = None, timeout: int = 8) -> None:
        super().__init__()
        self.platforms = platforms or ["twitter", "facebook", "linkedin"]
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (SYNINT/1.0)"})

    def _platform_url(self, platform: str, username: str) -> str | None:
        if platform == "twitter":
            return f"https://x.com/{username}"
        if platform == "facebook":
            return f"https://www.facebook.com/{username}"
        if platform == "linkedin":
            return f"https://www.linkedin.com/in/{username}"
        return None

    def _check_profile(self, url: str) -> Dict[str, str]:
        try:
            response = self._session.get(url, timeout=self.timeout, allow_redirects=True)
            status_code = response.status_code
            # Treat explicit not-found/blocked statuses as non-existent profile.
            if status_code in (404, 410):
                return {"url": url, "status": "not_found"}
            if status_code >= 500:
                return {"url": url, "status": "error", "detail": f"HTTP {status_code}"}
            return {"url": response.url, "status": "reachable", "http_status": str(status_code)}
        except requests.RequestException as exc:
            return {"url": url, "status": "error", "detail": str(exc)}

    def run(self, target: str) -> Dict[str, object]:
        username = str(target).strip()
        profiles: List[Dict[str, str]] = []

        for platform in self.platforms:
            url = self._platform_url(platform, username)
            if not url:
                profiles.append({"platform": platform, "status": "unsupported"})
                continue

            profile_result = self._check_profile(url)
            profile_result["platform"] = platform
            profiles.append(profile_result)

        result: Dict[str, object] = {
            "agent": "SocialMediaAgent",
            "target": username,
            "profiles": profiles,
        }
        self.results = result
        return result
