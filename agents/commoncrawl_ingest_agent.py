"""Bounded, streaming Common Crawl archive acquisition (optional, opt-in).

Never runs by default (see agents.OPTIONAL_AGENT_ORDER / main.py agent
selection) and never downloads a full WARC segment: it queries the Common
Crawl CDX index for existing captures, then issues a single ranged HTTP
request per matched record to fetch just that one WARC entry.
"""

from __future__ import annotations

import io
import json
import os
from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

from agents.base_agent import OSINTAgent
from core.entity_utils import extract_entities_enhanced, extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error

try:
    from warcio.archiveiterator import ArchiveIterator
    _WARCIO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via availability tests
    ArchiveIterator = None  # type: ignore[assignment]
    _WARCIO_AVAILABLE = False


class _StdlibTextExtractor(HTMLParser):
    """Minimal stdlib HTML-to-text extractor (no bs4/lxml dependency added)."""

    _SKIP_TAGS = {"script", "style", "noscript", "svg", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._chunks.append(data.strip())

    def text(self) -> str:
        return "\n".join(self._chunks)


def html_to_text(html: str) -> str:
    parser = _StdlibTextExtractor()
    try:
        parser.feed(html)
    except Exception:
        return html
    return parser.text()


class CommonCrawlIngestAgent(OSINTAgent):
    """Optional Common Crawl acquisition: CDX lookup + single-record range fetch.

    Not part of AGENT_ORDER; must be explicitly selected via --agents.
    """

    name = "CommonCrawlIngestAgent"
    supported_target_types = ("domain", "url", "text")
    requires_context = True

    CDX_ENDPOINT_TEMPLATE = "https://index.commoncrawl.org/{index}-index"
    DATA_ENDPOINT_TEMPLATE = "https://data.commoncrawl.org/{filename}"
    COLLINFO_ENDPOINT = "https://index.commoncrawl.org/collinfo.json"
    MAX_RANGE_BYTES = 20 * 1024 * 1024
    MAX_TEXT_CHARS = 200_000

    @staticmethod
    def dependency_available() -> bool:
        return _WARCIO_AVAILABLE

    def _max_records(self) -> int:
        raw = str(os.getenv("SYNINT_COMMONCRAWL_MAX_RECORDS", "5")).strip()
        if not raw.isdigit():
            return 5
        return max(1, min(int(raw), 50))

    def _timeout_seconds(self) -> int:
        raw = str(os.getenv("SYNINT_COMMONCRAWL_TIMEOUT", "30")).strip()
        return int(raw) if raw.isdigit() else 30

    def _resolve_index(self) -> Tuple[str, Dict[str, Any]]:
        override = str(os.getenv("SYNINT_COMMONCRAWL_INDEX", "")).strip()
        if override:
            return override, {"source": "env_override"}
        response = requests.get(self.COLLINFO_ENDPOINT, timeout=self._timeout_seconds())
        response.raise_for_status()
        collections = response.json()
        if not isinstance(collections, list) or not collections:
            raise ValueError("collinfo.json returned no collections")
        latest = collections[0]
        if not isinstance(latest, dict):
            raise ValueError("collinfo.json entry malformed")
        index_id = str(latest.get("id", "")).strip()
        if not index_id:
            raise ValueError("collinfo.json entry missing id")
        return index_id, {"source": "collinfo_latest", "name": latest.get("name")}

    @staticmethod
    def build_cdx_pattern(target: str) -> str:
        raw = str(target or "").strip()
        if not raw:
            return ""
        if "://" in raw:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").strip().lower()
            path = parsed.path or ""
            if not host:
                return ""
            return f"{host}{path}" if path and path != "/" else f"{host}/*"
        host = raw.strip().lower()
        return f"{host}/*" if host else ""

    def _query_cdx(self, index_id: str, pattern: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        endpoint = self.CDX_ENDPOINT_TEMPLATE.format(index=index_id)
        params = {
            "url": pattern,
            "output": "json",
            "matchType": "prefix" if pattern.endswith("*") else "exact",
            "filter": "status:200",
            "collapse": "urlkey",
            "limit": str(self._max_records()),
        }
        response = requests.get(endpoint, params=params, timeout=self._timeout_seconds(), stream=True)
        if response.status_code == 404:
            return [], {"endpoint": endpoint, "params": params, "status_code": 404}
        response.raise_for_status()
        records: List[Dict[str, Any]] = []
        for line in response.iter_lines(decode_unicode=True):
            if not line or not str(line).strip():
                continue
            try:
                parsed = json.loads(line)
            except Exception:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        return records, {"endpoint": endpoint, "params": params, "status_code": response.status_code}

    def _fetch_record_payload(self, record: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        filename = str(record.get("filename", "")).strip()
        offset_raw = record.get("offset")
        length_raw = record.get("length")
        if not filename or offset_raw is None or length_raw is None:
            return "", {"error": "record missing filename/offset/length"}
        try:
            offset = int(offset_raw)
            length = int(length_raw)
        except (TypeError, ValueError):
            return "", {"error": "record offset/length not integers"}
        if length <= 0:
            return "", {"error": "record length non-positive"}
        if length > self.MAX_RANGE_BYTES:
            return "", {"error": f"record length {length} exceeds bound {self.MAX_RANGE_BYTES}"}

        url = self.DATA_ENDPOINT_TEMPLATE.format(filename=filename)
        range_header = f"bytes={offset}-{offset + length - 1}"
        response = requests.get(url, headers={"Range": range_header}, timeout=self._timeout_seconds())
        response.raise_for_status()

        if not _WARCIO_AVAILABLE:
            return "", {"error": "warcio not installed"}

        text = ""
        for warc_record in ArchiveIterator(io.BytesIO(response.content)):
            if warc_record.rec_type == "response":
                payload = warc_record.content_stream().read()
                text = payload.decode("utf-8", errors="replace")
                break
        return text, {"data_url": url, "range": range_header, "bytes_fetched": len(response.content)}

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            if not target:
                return skipped(self.name, indicator, "missing target")

            if not _WARCIO_AVAILABLE:
                return skipped(
                    self.name,
                    target,
                    "warcio not installed; Common Crawl ingestion unavailable (optional dependency)",
                )

            pattern = self.build_cdx_pattern(target)
            if not pattern:
                return skipped(self.name, target, "unable to build Common Crawl URL pattern for target")

            try:
                index_id, index_meta = self._resolve_index()
            except Exception as exc:
                return structured_error(self.name, target, f"failed to resolve Common Crawl index: {exc}")

            try:
                records, cdx_meta = self._query_cdx(index_id, pattern)
            except requests.RequestException as exc:
                return structured_error(self.name, target, f"Common Crawl CDX query failed: {exc}")

            if not records:
                return skipped(
                    self.name,
                    target,
                    "no Common Crawl captures found for target",
                    findings={
                        "index_id": index_id,
                        "index_meta": index_meta,
                        "cdx_meta": cdx_meta,
                        "pattern": pattern,
                    },
                )

            captures: List[Dict[str, Any]] = []
            aggregate_entities: Dict[str, List[str]] = {}
            aggregate_enhanced: Dict[str, List[str]] = {}
            enhanced_enabled = bool(context.get("enhanced_extraction"))
            fetch_errors: List[Dict[str, Any]] = []

            for record in records[: self._max_records()]:
                try:
                    text, fetch_meta = self._fetch_record_payload(record)
                except requests.RequestException as exc:
                    fetch_errors.append({"record": record.get("url"), "error": str(exc)})
                    continue
                if not text:
                    fetch_errors.append({"record": record.get("url"), **fetch_meta})
                    continue

                lowered = text[:2048].lower()
                page_text = html_to_text(text) if ("<html" in lowered or "<!doctype" in lowered) else text
                page_text = page_text[: self.MAX_TEXT_CHARS]
                entities = extract_entities_from_text(page_text)
                for key, values in entities.items():
                    bucket = aggregate_entities.setdefault(key, [])
                    for value in values:
                        if value not in bucket:
                            bucket.append(value)
                if enhanced_enabled:
                    enhanced = extract_entities_enhanced(page_text)
                    for key in ("bitcoin_wallets", "ethereum_wallets", "uuids", "ssn_like_redacted"):
                        bucket = aggregate_enhanced.setdefault(key, [])
                        for value in enhanced.get(key, []):
                            if value not in bucket:
                                bucket.append(value)

                captures.append(
                    {
                        "url": record.get("url"),
                        "timestamp": record.get("timestamp"),
                        "mime": record.get("mime"),
                        "status": record.get("status"),
                        "digest": record.get("digest"),
                        "filename": record.get("filename"),
                        "offset": record.get("offset"),
                        "length": record.get("length"),
                        "fetch_meta": fetch_meta,
                        "text_excerpt": page_text[:500],
                        "entities": entities,
                    }
                )

            findings = {
                "index_id": index_id,
                "index_meta": index_meta,
                "cdx_meta": cdx_meta,
                "pattern": pattern,
                "records_found": len(records),
                "records_fetched": len(captures),
                "fetch_errors": fetch_errors,
                "captures": captures,
                **{key: unique_sorted(values) for key, values in aggregate_entities.items()},
                "discovered_urls": unique_sorted(aggregate_entities.get("urls", [])),
                "enhanced_extraction": {
                    "enabled": enhanced_enabled,
                    "detected_identifiers": {
                        key: unique_sorted(values) for key, values in aggregate_enhanced.items()
                    },
                    "legacy_entities_unchanged": True,
                },
            }

            if not captures:
                return skipped(
                    self.name,
                    target,
                    "Common Crawl captures found but no record payloads were retrievable",
                    findings=findings,
                )

            evidence_count = sum(len(v) for v in aggregate_entities.values()) + len(captures)
            risk = min(0.05 + len(captures) * 0.01, 0.4)
            reason = f"fetched {len(captures)}/{len(records)} matched record(s) via bounded range request" if fetch_errors else None
            return ok(
                self.name,
                target,
                findings,
                risk,
                evidence_mode="collected",
                evidence_count=evidence_count,
                reason=reason,
            )
        except Exception as exc:
            return structured_error(self.name, target, exc)
