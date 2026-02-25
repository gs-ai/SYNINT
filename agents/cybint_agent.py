#!/usr/bin/env python3
"""Cyber intelligence agent that reports observable network security signals."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List

import requests

from agents.base_agent import OSINTAgent


class CybintAgent(OSINTAgent):
    """Performs lightweight, real network checks for a target."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]

    def __init__(self, timeout: int = 3) -> None:
        super().__init__()
        self.timeout = timeout

    def _resolve_target(self, target: str) -> Dict[str, str | None]:
        try:
            ip_address = socket.gethostbyname(target)
            return {"resolved_address": ip_address, "error": None}
        except Exception as exc:
            return {"resolved_address": None, "error": str(exc)}

    def _check_open_ports(self, host: str) -> List[int]:
        open_ports: List[int] = []
        for port in self.COMMON_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                except Exception:
                    continue
        return open_ports

    def _tls_certificate(self, host: str) -> Dict[str, str | int | bool | None]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    cert = secure_sock.getpeercert()

            not_after = cert.get("notAfter")
            if not not_after:
                return {"status": "unknown", "error": "Certificate expiration unavailable"}

            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiration = int((expires_at - datetime.now(timezone.utc)).days)
            return {
                "status": "ok",
                "expires_at_utc": expires_at.isoformat(),
                "days_until_expiration": days_until_expiration,
                "expired": days_until_expiration < 0,
            }
        except Exception as exc:
            return {"status": "unavailable", "error": str(exc)}

    def _http_security_headers(self, target: str) -> Dict[str, object]:
        findings: List[str] = []
        headers_seen: Dict[str, str] = {}
        url = f"https://{target}"

        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            for header_name in [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
            ]:
                header_value = headers.get(header_name)
                if header_value:
                    headers_seen[header_name] = header_value
                else:
                    findings.append(f"Missing HTTP security header: {header_name}")

            return {
                "url": response.url,
                "http_status": response.status_code,
                "security_headers": headers_seen,
                "findings": findings,
            }
        except Exception as exc:
            return {"url": url, "error": str(exc), "findings": findings}

    def run(self, target: str) -> Dict[str, object]:
        target_str = str(target).strip()
        resolution = self._resolve_target(target_str)
        if resolution["error"]:
            result: Dict[str, object] = {
                "agent": "CybintAgent",
                "target": target_str,
                "status": "error",
                "error": f"Target resolution failed: {resolution['error']}",
            }
            self.results = result
            return result

        resolved_address = str(resolution["resolved_address"])
        open_ports = self._check_open_ports(resolved_address)
        tls_data = self._tls_certificate(target_str)
        http_data = self._http_security_headers(target_str)

        findings: List[str] = []
        if 21 in open_ports:
            findings.append("FTP port 21 is open")
        if 23 in open_ports:
            findings.append("Telnet port 23 is open")
        if 3389 in open_ports:
            findings.append("RDP port 3389 is open")
        if isinstance(tls_data, dict) and tls_data.get("expired") is True:
            findings.append("TLS certificate appears expired")
        findings.extend(http_data.get("findings", []))

        result = {
            "agent": "CybintAgent",
            "target": target_str,
            "status": "ok",
            "resolved_address": resolved_address,
            "open_ports": open_ports,
            "tls": tls_data,
            "http": http_data,
            "findings": findings,
        }
        self.results = result
        return result
