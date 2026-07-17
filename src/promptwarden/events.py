"""Security event emission: OCSF-aligned JSON + CEF, with pluggable sinks.

Events never contain Authorization headers, API keys, or full raw prompts —
only truncated/masked evidence produced by the detectors. That constraint is
part of the threat model (the event pipeline itself must not become the leak).
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import __version__
from .detectors.base import Direction
from .pipeline import Verdict

logger = logging.getLogger("promptwarden.events")

# OCSF severity_id scale: 1 Informational .. 5 Critical
_OCSF_SEVERITY = [(9, 5), (7, 4), (5, 3), (3, 2), (0, 1)]


def _ocsf_severity(score: int) -> int:
    for threshold, sev_id in _OCSF_SEVERITY:
        if score >= threshold:
            return sev_id
    return 1


def build_event(
    verdict: Verdict,
    direction: Direction,
    request_id: str | None = None,
    app_id: str = "default",
) -> dict:
    """Build an OCSF-aligned finding event (class: Detection Finding, 2004)."""
    return {
        "time": datetime.now(timezone.utc).isoformat(),
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "activity_name": f"llm_{direction}_inspection",
        "severity_id": _ocsf_severity(verdict.score),
        "status": verdict.action,
        "message": (
            f"PromptWarden {verdict.action}: {len(verdict.detections)} detection(s), "
            f"max severity {verdict.score}"
        ),
        "metadata": {
            "product": {"name": "PromptWarden", "version": __version__},
            "uid": request_id or str(uuid.uuid4()),
            "app_id": app_id,
        },
        "finding_info": [
            {
                "rule_id": d.rule_id,
                "detector": d.detector,
                "title": d.description,
                "severity": d.severity,
                "confidence": d.confidence,
                "evidence": d.evidence,
                "owasp_llm_top10": d.owasp_llm,
                "mitre_atlas": d.atlas,
            }
            for d in verdict.detections
        ],
    }


def to_cef(event: dict) -> str:
    """Render an event as a single CEF line for legacy SIEM ingestion."""
    first = event["finding_info"][0] if event["finding_info"] else {}
    ext = (
        f"act={event['status']} "
        f"cs1={first.get('owasp_llm_top10', '')} cs1Label=owaspLlmTop10 "
        f"cs2={first.get('mitre_atlas', '')} cs2Label=mitreAtlas "
        f"msg={event['message']}"
    )
    return (
        f"CEF:0|PromptWarden|gateway|{__version__}|"
        f"{first.get('rule_id', 'PW-NONE')}|{first.get('title', 'clean')}|"
        f"{event['severity_id']}|{ext}"
    )


class StdoutSink:
    def emit(self, event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False))  # noqa: T201


class FileSink:
    """Append JSONL events; thread-safe within a single process."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class HecSink:
    """Splunk HTTP Event Collector sink. Failures are logged, never raised:
    losing one event must not take down the traffic path."""

    def __init__(self, url: str, token: str):
        self.endpoint = url.rstrip("/") + "/services/collector/event"
        self._headers = {"Authorization": f"Splunk {token}"}

    def emit(self, event: dict) -> None:
        try:
            httpx.post(
                self.endpoint,
                headers=self._headers,
                json={"event": event, "sourcetype": "promptwarden"},
                timeout=3.0,
            )
        except httpx.HTTPError as exc:
            logger.warning("HEC emit failed: %s", exc)


class EventEmitter:
    def __init__(self, sinks: list):
        self.sinks = sinks

    def emit(
        self,
        verdict: Verdict,
        direction: Direction,
        request_id: str | None = None,
        app_id: str = "default",
    ) -> dict:
        event = build_event(verdict, direction, request_id=request_id, app_id=app_id)
        for sink in self.sinks:
            sink.emit(event)
        return event
