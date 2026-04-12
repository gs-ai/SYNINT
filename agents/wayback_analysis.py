"""Historical archive discovery via optional waymore CLI integration."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from agents.base_agent import OSINTAgent
from synint_paths import COLLECTION_ARTIFACTS_DIR
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error

class WaybackAnalysisAgent(OSINTAgent):
    """Run waymore (if installed) to gather archived URL intelligence."""

    name = "WaybackAnalysisAgent"
    supported_target_types = ("domain", "url", "text")
    requires_context = True

    SENSITIVE_PATH_TOKENS = [
        "admin",
        "backup",
        "export",
        "old",
        "private",
        "test",
        "dev",
        "staging",
        "config",
        "login",
    ]
    FILE_EXTENSIONS = (".zip", ".tar", ".gz", ".7z", ".sql", ".bak", ".env", ".csv", ".log", ".json", ".xml")

    def _waymore_binary(self) -> str:
        found = shutil.which("waymore")
        if found:
            return found
        # When running with an explicit venv python path, PATH may not include
        # the sibling bin directory where console scripts are installed.
        py_dir = Path(sys.executable).parent
        resolved_py_dir = Path(sys.executable).resolve().parent
        candidates = [
            py_dir / "waymore",
            py_dir / "waymore.exe",
            resolved_py_dir / "waymore",
            resolved_py_dir / "waymore.exe",
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return str(candidate)
        return ""

    def _waymore_input(self, target: str) -> str:
        raw = str(target or "").strip()
        if not raw:
            return ""
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or parsed.netloc or "").strip().lower()
        if not host:
            return raw
        path = (parsed.path or "").strip()
        if path and path != "/":
            return f"{host}{path}"
        return host

    def _artifact_paths(self, context: Dict[str, Any]) -> Tuple[Path, Path]:
        reports_dir = str(context.get("reports_dir", "")).strip() if isinstance(context, dict) else ""
        if reports_dir:
            base = Path(reports_dir) / "collection_artifacts" / "waymore"
        else:
            base = COLLECTION_ARTIFACTS_DIR / "waymore"
        base.mkdir(parents=True, exist_ok=True)
        return base, base / "waymore_urls.txt"

    def _limit_requests(self) -> str:
        raw = str(os.getenv("SYNINT_WAYMORE_LIMIT_REQUESTS", "40")).strip()
        return raw if raw.isdigit() else "40"

    def _timeout_seconds(self) -> int:
        raw = str(os.getenv("SYNINT_WAYMORE_TIMEOUT", "240")).strip()
        return int(raw) if raw.isdigit() else 240

    def _build_command(self, binary: str, target_input: str, output_file: Path) -> List[str]:
        # Exclude provider sources that are commonly API-key dependent.
        return [
            binary,
            "-i",
            target_input,
            "-mode",
            "U",
            "-oU",
            str(output_file),
            "-xvt",
            "-xix",
            "-lcc",
            "1",
            "-lr",
            self._limit_requests(),
            "-r",
            "1",
        ]

    def _load_urls(self, path: Path) -> List[str]:
        if not path.exists() or not path.is_file():
            return []
        urls: List[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = str(line).strip()
            if value.startswith("http://") or value.startswith("https://"):
                urls.append(value)
        return unique_sorted(urls)

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            if not target:
                return skipped(self.name, indicator, "missing target")

            binary = self._waymore_binary()
            if not binary:
                return skipped(self.name, target, "waymore CLI not found in PATH")

            target_input = self._waymore_input(target)
            if not target_input:
                return skipped(self.name, target, "unable to normalize target for waymore")

            artifact_dir, urls_output = self._artifact_paths(context)
            command = self._build_command(binary, target_input, urls_output)
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds(),
            )

            archived_urls = self._load_urls(urls_output)
            fallback_attempted = False
            fallback_command: List[str] = []
            fallback_completed: subprocess.CompletedProcess[str] | None = None
            stderr_text = completed.stderr or ""
            wayback_blocked = "access denied" in stderr_text.lower() and "wayback" in stderr_text.lower()
            if not archived_urls and wayback_blocked:
                # Retry with Wayback excluded so Common Crawl can still contribute.
                fallback_attempted = True
                fallback_command = [part for part in command if part != "-xwm"]
                fallback_command.append("-xwm")
                fallback_completed = subprocess.run(
                    fallback_command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds(),
                )
                archived_urls = self._load_urls(urls_output)

            sensitive_urls = [
                url
                for url in archived_urls
                if any(token in url.lower() for token in self.SENSITIVE_PATH_TOKENS)
            ]
            archive_file_candidates = [
                url
                for url in archived_urls
                if any(url.lower().split("?", 1)[0].endswith(ext) for ext in self.FILE_EXTENSIONS)
            ]
            hostnames = unique_sorted(
                (urlparse(url).hostname or "").strip().lower()
                for url in archived_urls
                if (urlparse(url).hostname or "").strip()
            )

            if not archived_urls and completed.returncode != 0:
                stderr = (completed.stderr or "").strip()
                return structured_error(self.name, target, stderr or f"waymore exited with code {completed.returncode}")

            findings = {
                "waymore_input": target_input,
                "waymore_command": command,
                "provider_exclusions": ["virustotal", "intelx"],
                "archived_urls": archived_urls,
                "archived_url_count": len(archived_urls),
                "sensitive_archived_urls": sensitive_urls,
                "archive_file_candidates": archive_file_candidates,
                "archived_hostnames": hostnames,
                "output_urls_file": str(urls_output),
                "artifact_dir": str(artifact_dir),
                "discovered_urls": archived_urls,
                "execution": {
                    "return_code": completed.returncode,
                    "stderr_excerpt": (completed.stderr or "")[-1200:],
                    "stdout_excerpt": (completed.stdout or "")[-1200:],
                    "wayback_blocked": wayback_blocked,
                    "fallback_attempted": fallback_attempted,
                    "fallback_command": fallback_command,
                    "fallback_return_code": fallback_completed.returncode if fallback_completed is not None else None,
                    "fallback_stderr_excerpt": (fallback_completed.stderr or "")[-1200:] if fallback_completed is not None else "",
                    "fallback_stdout_excerpt": (fallback_completed.stdout or "")[-1200:] if fallback_completed is not None else "",
                },
            }

            if not archived_urls:
                return skipped(
                    self.name,
                    target,
                    "waymore completed with no archived URLs",
                    findings=findings,
                    evidence_mode="none",
                    evidence_count=0,
                )

            evidence_count = len(archived_urls)
            risk = min(
                0.03
                + len(sensitive_urls) * 0.03
                + len(archive_file_candidates) * 0.02
                + min(len(archived_urls), 500) * 0.0005,
                0.85,
            )
            reason = None
            if completed.returncode != 0:
                reason = f"waymore exited with code {completed.returncode}; parsed partial URL output"
            elif wayback_blocked and fallback_attempted:
                reason = "wayback access blocked; parsed URLs using non-wayback fallback"
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
                reason=reason,
            )
        except subprocess.TimeoutExpired:
            return structured_error(self.name, target, "waymore execution timed out")
        except Exception as exc:
            return structured_error(self.name, target, exc)
