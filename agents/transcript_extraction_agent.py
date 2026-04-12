"""Transcript and conversation log parsing agent."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import OSINTAgent
from core.document_utils import extract_text_from_file
from core.entity_utils import extract_entities_from_text
from ._pipeline import unpack_pipeline_input, unique_sorted
from ._shared import ok, skipped, structured_error


class TranscriptExtractionAgent(OSINTAgent):
    """Extract speakers, entities, timeline cues, and contradiction hints from text transcripts."""

    name = "TranscriptExtractionAgent"
    supported_target_types = ("text", "file", "json")
    requires_context = True

    SPEAKER_RE = re.compile(r"^(?P<speaker>[A-Za-z][A-Za-z0-9 _.-]{0,40}):\s*(?P<content>.+)$")

    def _load_text(self, target: str, context: Dict[str, Any]) -> str:
        if target and Path(target).exists() and Path(target).is_file():
            result = extract_text_from_file(target)
            return str(result.get("text", ""))
        chunks: List[str] = []
        for path in context.get("collected_files", []) if isinstance(context, dict) else []:
            p = str(path)
            if Path(p).exists() and Path(p).is_file() and Path(p).suffix.lower() in {".txt", ".md", ".log", ".json"}:
                result = extract_text_from_file(p)
                text = str(result.get("text", ""))
                if text:
                    chunks.append(text)
        return "\n".join(chunks)

    def run(self, indicator: Any):
        target, context, _ = unpack_pipeline_input(indicator)
        try:
            text = self._load_text(target, context)
            if not text.strip() and isinstance(indicator, str):
                text = indicator
            if not text.strip():
                return skipped(self.name, target, "no transcript text available")

            speaker_segments: List[Dict[str, Any]] = []
            timeline_markers: List[Dict[str, Any]] = []
            contradictions: List[Dict[str, Any]] = []
            escalation_flags: List[str] = []

            last_assertions: Dict[str, str] = {}
            for idx, line in enumerate(text.splitlines()):
                stripped = line.strip()
                if not stripped:
                    continue

                match = self.SPEAKER_RE.match(stripped)
                if match:
                    speaker = match.group("speaker").strip()
                    content = match.group("content").strip()
                    speaker_segments.append({"line": idx + 1, "speaker": speaker, "content": content})

                    lower = content.lower()
                    if any(token in lower for token in ["urgent", "immediately", "escalate", "critical", "breach"]):
                        escalation_flags.append(f"line {idx + 1}: {content[:120]}")

                    topic_key = re.sub(r"[^a-z0-9]+", " ", lower).split(" ")[0] if lower else ""
                    stance = "affirm" if any(w in lower for w in ["yes", "confirmed", "true", "present"]) else "deny" if any(w in lower for w in ["no", "false", "not", "absent"]) else ""
                    if topic_key and stance:
                        prior = last_assertions.get(topic_key)
                        if prior and prior != stance:
                            contradictions.append(
                                {
                                    "topic": topic_key,
                                    "line": idx + 1,
                                    "message": f"Conflicting statements detected for topic '{topic_key}'.",
                                    "quote": content,
                                }
                            )
                        last_assertions[topic_key] = stance

                for date_match in re.finditer(r"\b\d{4}-\d{2}-\d{2}\b", stripped):
                    timeline_markers.append({"line": idx + 1, "raw": date_match.group(0)})

            entities = extract_entities_from_text(text)
            findings = {
                "speaker_segments": speaker_segments,
                "extracted_entities": entities,
                "timeline_markers": timeline_markers,
                "contradictions": contradictions,
                "escalation_flags": unique_sorted(escalation_flags),
            }
            evidence_count = len(speaker_segments) + len(timeline_markers)
            risk = min(0.03 + len(escalation_flags) * 0.05 + len(contradictions) * 0.06, 0.8)
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
