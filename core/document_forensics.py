"""Read-only, bounded document metadata and structure extraction."""

from __future__ import annotations

import mimetypes
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable
from xml.etree import ElementTree

from core.schemas import utc_now_iso

MAX_METADATA_SCAN_BYTES = 25 * 1024 * 1024
MAX_EMBEDDED_ITEMS = 100

_PDF_INFO_RE = re.compile(
    rb"/(Author|Title|Subject|Keywords|Creator|Producer|CreationDate|ModDate)\s*"
    rb"\(((?:[^()\\]|\\.)*)\)"
)
_URL_RE = re.compile(rb"https?://[A-Za-z0-9.\-/_%?=&#+~:,]{4,500}")
_XML_NAMESPACE_RE = re.compile(r"^\{[^}]+\}")
_CORE_FIELDS = {
    "creator": "author",
    "lastModifiedBy": "last_modified_by",
    "created": "created",
    "modified": "modified",
    "revision": "revision",
    "title": "title",
    "subject": "subject",
    "keywords": "keywords",
    "description": "description",
    "category": "category",
    "Application": "application",
    "Company": "company",
    "Manager": "manager",
    "TotalTime": "editing_minutes",
    "Pages": "pages",
    "Words": "words",
}
_PDF_FIELDS = {
    "author": "author",
    "title": "title",
    "subject": "subject",
    "keywords": "keywords",
    "creator": "application",
    "producer": "producer",
    "creationdate": "created",
    "moddate": "modified",
}


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value.strip().rstrip(".,)") for value in values if value.strip()})


def _decode_pdf_value(value: bytes) -> str:
    return (
        value.decode("utf-8", errors="ignore")
        .replace(r"\(", "(")
        .replace(r"\)", ")")
        .strip()
    )


def _pdf_metadata(data: bytes) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"format": "pdf"}
    for match in _PDF_INFO_RE.finditer(data):
        source_key = match.group(1).decode("ascii", errors="ignore").lower()
        value = _decode_pdf_value(match.group(2))
        if value:
            metadata.setdefault(_PDF_FIELDS.get(source_key, source_key), value)
    metadata["page_markers"] = data.count(b"/Type/Page") + data.count(b"/Type /Page")
    metadata["incremental_updates"] = max(data.count(b"%%EOF") - 1, 0)
    metadata["has_javascript"] = b"/JavaScript" in data or b"/JS" in data
    metadata["has_embedded_files"] = b"/EmbeddedFile" in data
    metadata["has_annotations"] = b"/Annot" in data
    metadata["has_acroform"] = b"/AcroForm" in data
    metadata["encrypted"] = b"/Encrypt" in data
    return metadata


def _container_format(names: list[str]) -> str:
    if "word/document.xml" in names:
        return "docx"
    if any(name.startswith("xl/") for name in names):
        return "xlsx"
    if any(name.startswith("ppt/") for name in names):
        return "pptx"
    if "mimetype" in names or "meta.xml" in names:
        return "opendocument"
    if any(name.endswith(".opf") for name in names):
        return "epub"
    return "zip-container"


def _zip_metadata(path: Path) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"format": "zip-container"}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            metadata["format"] = _container_format(names)
            metadata["part_count"] = len(names)
            metadata["embedded_parts"] = sorted(
                name
                for name in names
                if "/embeddings/" in name or "/media/" in name or name.startswith("Pictures/")
            )[:MAX_EMBEDDED_ITEMS]
            metadata["has_tracked_changes"] = any(
                "revisions" in name or name.endswith("people.xml") for name in names
            )

            for part in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
                if part not in names:
                    continue
                try:
                    root = ElementTree.fromstring(archive.read(part))
                except (ElementTree.ParseError, KeyError, OSError):
                    continue
                for node in root.iter():
                    field = _CORE_FIELDS.get(_XML_NAMESPACE_RE.sub("", node.tag))
                    if field and node.text and node.text.strip():
                        metadata.setdefault(field, node.text.strip())

            external_targets: list[str] = []
            for name in names:
                if not name.endswith(".rels"):
                    continue
                try:
                    body = archive.read(name).decode("utf-8", errors="ignore")
                except (KeyError, OSError):
                    continue
                external_targets.extend(
                    re.findall(r'Target="((?:file|https?)://[^"]+)"', body, flags=re.IGNORECASE)
                )
            metadata["external_targets"] = _unique(external_targets)[:MAX_EMBEDDED_ITEMS]
    except (zipfile.BadZipFile, OSError):
        metadata["parse_status"] = "unavailable"
    return metadata


def analyze_document(path_value: str | Path, *, source_sha256: str = "") -> Dict[str, Any]:
    """Analyze a local document without writing to or replacing the source file.

    The byte scan is capped; hashes are supplied by the caller's streaming hash
    path so the record still identifies the complete source file.
    """

    path = Path(path_value)
    result: Dict[str, Any] = {
        "source_path": str(path.resolve()),
        "source_sha256": source_sha256,
        "analysis_timestamp": utc_now_iso(),
        "extractor": "synint.core.document_forensics",
        "read_only": True,
    }
    if not path.exists() or not path.is_file():
        return {**result, "status": "error", "error": "source file does not exist"}

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_METADATA_SCAN_BYTES)
    except OSError as exc:
        return {**result, "status": "error", "error": str(exc)}

    suffix = path.suffix.lower()
    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    if data.startswith(b"%PDF"):
        mime_type = "application/pdf"
        metadata = _pdf_metadata(data)
    elif data.startswith(b"PK\x03\x04") or suffix in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"}:
        metadata = _zip_metadata(path)
    else:
        metadata = {"format": suffix.lstrip(".") or "unknown"}

    links = _unique(match.group(0).decode("utf-8", errors="ignore") for match in _URL_RE.finditer(data))
    return {
        **result,
        "status": "ok",
        "mime_type": mime_type,
        "document_type": metadata.get("format", suffix.lstrip(".") or "unknown"),
        "size_bytes": path.stat().st_size,
        "bytes_scanned": len(data),
        "scan_truncated": path.stat().st_size > len(data),
        "metadata": metadata,
        "embedded_urls": links[:MAX_EMBEDDED_ITEMS],
    }
