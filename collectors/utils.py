"""Shared helpers for collectors (URL normalization, HTML parsing, artifacts)."""

from __future__ import annotations

import json
import mimetypes
import random
import re
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote, urljoin, urlparse, urlunparse

import requests

DEFAULT_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]

CLOUDFLARE_MARKERS = [
    "cf-challenge",
    "cdn-cgi/challenge-platform",
    "attention required",
    "checking your browser",
    "just a moment",
    "cf-turnstile",
    "turnstile",
    "why do i have to complete a captcha",
]

DOWNLOADABLE_SUFFIXES = {
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".sql",
    ".csv",
    ".txt",
    ".env",
    ".bak",
    ".old",
    ".log",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".json",
    ".xml",
    ".png",
    ".jpg",
    ".jpeg",
    ".tif",
    ".tiff",
    ".bmp",
    ".webp",
    ".mp4",
    ".mp3",
}


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    scheme = parsed.scheme or "https"
    host = (parsed.hostname or "").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        netloc = f"{host}:{port}"
    else:
        netloc = host or parsed.netloc.lower().split("@")[-1]
    path = parsed.path or "/"
    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, fragment="")
    return urlunparse(normalized)


def same_domain(url_a: str, url_b: str) -> bool:
    return (urlparse(url_a).hostname or "").lower() == (urlparse(url_b).hostname or "").lower()


def default_browser_headers(user_agent: str | None = None) -> Dict[str, str]:
    ua = user_agent or random.choice(DEFAULT_BROWSER_USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }


def create_safe_session(
    *,
    user_agent: str | None = None,
    allow_env_network_config: bool = False,
    headers: Dict[str, str] | None = None,
) -> requests.Session:
    """Create a requests session that avoids leaking local environment/network context."""
    session = requests.Session()
    session.trust_env = bool(allow_env_network_config)
    session.headers.clear()
    session.headers.update(default_browser_headers(user_agent))
    if headers:
        session.headers.update({str(k): str(v) for k, v in headers.items()})
    session.cookies.clear()
    return session


def detect_cloudflare_challenge(
    *,
    status_code: int | None,
    headers: Dict[str, Any] | None,
    content: str,
) -> Dict[str, Any]:
    lowered_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    server = lowered_headers.get("server", "").lower()
    has_cf_headers = bool(
        lowered_headers.get("cf-ray")
        or lowered_headers.get("cf-cache-status")
        or lowered_headers.get("cf-mitigated")
        or "cloudflare" in server
    )

    body = (content or "").lower()
    matched_markers = [marker for marker in CLOUDFLARE_MARKERS if marker in body]
    blocked_status = int(status_code or 0) in {403, 409, 429, 503}
    challenge_detected = bool(matched_markers) or (has_cf_headers and blocked_status)

    return {
        "detected": bool(has_cf_headers or matched_markers),
        "challenge_detected": challenge_detected,
        "blocked_status": blocked_status,
        "status_code": status_code,
        "matched_markers": matched_markers,
        "has_cf_headers": has_cf_headers,
        "has_turnstile": any("turnstile" in marker for marker in matched_markers),
    }


class _HTMLCollectorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.file_links: List[str] = []
        self._in_title = False
        self._title_parts: List[str] = []
        self._meta_description = ""
        self.text_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
                if re.search(r"\.(?:zip|tar|gz|7z|sql|csv|txt|env|bak|old|log|pdf|docx|xlsx|pptx)$", href, re.I):
                    self.file_links.append(href)
        elif tag.lower() == "form":
            self.forms.append(
                {
                    "action": attr_map.get("action", ""),
                    "method": (attr_map.get("method", "get") or "get").lower(),
                    "id": attr_map.get("id", ""),
                    "name": attr_map.get("name", ""),
                }
            )
        elif tag.lower() == "meta":
            if attr_map.get("name", "").lower() == "description":
                self._meta_description = attr_map.get("content", "")
        elif tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if not data:
            return
        text = data.strip()
        if not text:
            return
        self.text_chunks.append(text)
        if self._in_title:
            self._title_parts.append(text)

    @property
    def title(self) -> str:
        return " ".join(self._title_parts).strip()

    @property
    def meta_description(self) -> str:
        return self._meta_description.strip()


def parse_html_summary(base_url: str, html: str) -> Dict[str, Any]:
    parser = _HTMLCollectorParser()
    parser.feed(html or "")

    normalized_links = []
    for href in parser.links:
        absolute = urljoin(base_url, href)
        if absolute.startswith("http://") or absolute.startswith("https://"):
            normalized_links.append(normalize_url(absolute))

    files = []
    for href in parser.file_links:
        absolute = urljoin(base_url, href)
        if absolute.startswith("http://") or absolute.startswith("https://"):
            files.append(normalize_url(absolute))

    text_content = " ".join(parser.text_chunks)
    return {
        "title": parser.title,
        "meta_description": parser.meta_description,
        "links": sorted(set(normalized_links)),
        "forms": parser.forms,
        "file_links": sorted(set(files)),
        "text": text_content,
    }


def _artifact_file_name(url: str, suffix: str) -> str:
    digest = sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{digest}.{suffix}"


def _coerce_download_file_name(
    *,
    final_url: str,
    content_disposition: str,
    content_type: str,
) -> str:
    candidate = ""
    cd = content_disposition or ""

    # RFC 5987 / basic filename extraction.
    ext_name = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd, flags=re.I)
    if ext_name:
        candidate = unquote(ext_name.group(1).strip().strip('"'))
    if not candidate:
        plain_name = re.search(r'filename\s*=\s*"?([^\";]+)"?', cd, flags=re.I)
        if plain_name:
            candidate = plain_name.group(1).strip()

    if not candidate:
        candidate = Path(urlparse(final_url).path).name or "download"

    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._-") or "download"
    if "." not in candidate:
        guessed = mimetypes.guess_extension((content_type or "").split(";")[0].strip().lower())
        if guessed:
            candidate = f"{candidate}{guessed}"
        else:
            candidate = f"{candidate}.bin"
    return candidate[:120]


def _looks_like_download(
    *,
    final_url: str,
    status_code: int | None,
    content_type: str,
    content_disposition: str,
    body_bytes: bytes | None,
) -> bool:
    if int(status_code or 0) < 200 or int(status_code or 0) >= 300:
        return False
    if not body_bytes:
        return False

    cd = (content_disposition or "").lower()
    ct = (content_type or "").split(";")[0].strip().lower()
    suffix = Path(urlparse(final_url).path).suffix.lower()

    if "attachment" in cd or "filename=" in cd:
        return True
    if suffix in DOWNLOADABLE_SUFFIXES:
        return True
    if ct and not any(token in ct for token in ("text/html", "application/xhtml", "application/xml")):
        return True
    return False


def write_collection_artifacts(
    *,
    artifact_root: Path,
    url: str,
    collector_engine: str,
    collection_mode: str,
    status_code: int | None,
    content: str,
    rendered: bool,
    headers: Dict[str, Any] | None = None,
    screenshot_bytes: bytes | None = None,
    body_bytes: bytes | None = None,
    final_url: str | None = None,
    content_type: str | None = None,
    content_disposition: str | None = None,
) -> Dict[str, str]:
    artifact_root.mkdir(parents=True, exist_ok=True)

    directories = {
        "raw_html": artifact_root / "raw_html",
        "rendered_html": artifact_root / "rendered_html",
        "screenshots": artifact_root / "screenshots",
        "headers": artifact_root / "headers",
        "response_meta": artifact_root / "response_meta",
        "extracted_text": artifact_root / "extracted_text",
        "downloads": artifact_root / "downloads",
    }
    for path in directories.values():
        path.mkdir(parents=True, exist_ok=True)

    output: Dict[str, str] = {}
    html_dir = directories["rendered_html"] if rendered else directories["raw_html"]
    html_path = html_dir / _artifact_file_name(url, "html")
    html_path.write_text(content or "", encoding="utf-8", errors="ignore")
    output["html"] = str(html_path)

    text_path = directories["extracted_text"] / _artifact_file_name(url, "txt")
    stripped_text = re.sub(r"<[^>]+>", " ", content or "")
    text_path.write_text(re.sub(r"\s+", " ", stripped_text).strip() + "\n", encoding="utf-8")
    output["text"] = str(text_path)

    headers_path = directories["headers"] / _artifact_file_name(url, "json")
    headers_path.write_text(json.dumps(headers or {}, indent=2), encoding="utf-8")
    output["headers"] = str(headers_path)

    content_hash = sha256((content or "").encode("utf-8", errors="ignore")).hexdigest()
    meta = {
        "source_url": url,
        "collector_engine": collector_engine,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status_code": status_code,
        "content_hash": content_hash,
        "capture_mode": collection_mode,
        "rendered": rendered,
    }
    meta_path = directories["response_meta"] / _artifact_file_name(url, "json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    output["meta"] = str(meta_path)

    if screenshot_bytes:
        shot_path = directories["screenshots"] / _artifact_file_name(url, "png")
        shot_path.write_bytes(screenshot_bytes)
        output["screenshot"] = str(shot_path)

    resolved_final_url = final_url or url
    resolved_content_type = content_type or ""
    resolved_content_disposition = content_disposition or ""
    if _looks_like_download(
        final_url=resolved_final_url,
        status_code=status_code,
        content_type=resolved_content_type,
        content_disposition=resolved_content_disposition,
        body_bytes=body_bytes,
    ):
        digest = sha256(resolved_final_url.encode("utf-8", errors="ignore")).hexdigest()[:12]
        file_name = _coerce_download_file_name(
            final_url=resolved_final_url,
            content_disposition=resolved_content_disposition,
            content_type=resolved_content_type,
        )
        download_path = directories["downloads"] / f"{digest}-{file_name}"
        download_path.write_bytes(body_bytes or b"")
        output["download"] = str(download_path)

    return output
