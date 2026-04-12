"""Safe small-scope service banner collection agent."""

from __future__ import annotations

import socket
from typing import Any, Dict, List
from urllib.parse import urlparse

from agents.base_agent import OSINTAgent
from ._pipeline import unpack_pipeline_input
from ._shared import ok, resolve_first_ip, skipped, structured_error


class ServiceBannerAgent(OSINTAgent):
    """Collect banners from a curated small set of service ports."""

    name = "ServiceBannerAgent"
    supported_target_types = ("domain", "url", "ip", "text", "json")
    requires_context = True

    PORTS = [21, 22, 25, 80, 443, 3389]

    def _resolve_host(self, target: str) -> str | None:
        if "://" in target:
            host = (urlparse(target).hostname or "").strip()
            return host or None
        if target.count(".") >= 1:
            return target.strip()
        return None

    def _grab_banner(self, ip: str, port: int, timeout: int = 2) -> Dict[str, Any]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((ip, port))
            if code != 0:
                return {"port": port, "open": False}
            try:
                if port in {80, 443}:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = sock.recv(512)
                text = banner.decode("utf-8", errors="ignore").strip()
            except Exception:
                text = ""
            return {"port": port, "open": True, "banner": text[:200]}

    def run(self, indicator: Any):
        target, _, _ = unpack_pipeline_input(indicator)
        host = self._resolve_host(target)
        if not host:
            return skipped(self.name, target, "invalid host target")

        try:
            ip = resolve_first_ip(host) or host
            banners: List[Dict[str, Any]] = []
            likely_services: List[str] = []
            version_hints: List[str] = []
            exposed_admin_services: List[str] = []

            for port in self.PORTS:
                entry = self._grab_banner(ip, port)
                banners.append(entry)
                if not entry.get("open"):
                    continue

                banner_text = str(entry.get("banner", "")).lower()
                if "ssh" in banner_text or port == 22:
                    likely_services.append("ssh")
                if "smtp" in banner_text or port == 25:
                    likely_services.append("smtp")
                if "http" in banner_text or port in {80, 443}:
                    likely_services.append("http")
                if "rdp" in banner_text or port == 3389:
                    likely_services.append("rdp")
                if "vsftpd" in banner_text:
                    version_hints.append("vsftpd")
                if "apache" in banner_text:
                    version_hints.append("apache")
                if port in {22, 3389}:
                    exposed_admin_services.append(f"port_{port}")

            findings = {
                "banners": banners,
                "likely_services": sorted(set(likely_services)),
                "version_hints": sorted(set(version_hints)),
                "exposed_admin_services": sorted(set(exposed_admin_services)),
            }
            evidence_count = len([b for b in banners if b.get("open")])
            risk = min(0.03 + len(exposed_admin_services) * 0.12 + evidence_count * 0.02, 0.85)
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
