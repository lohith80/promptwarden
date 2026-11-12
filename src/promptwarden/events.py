"""Security event emission: OCSF-aligned JSON + CEF, with pluggable sinks.

Events never contain Authorization headers, API keys, or full raw prompts -
only truncated/masked evidence produced by the detectors. That constraint is
part of the threat model (the event pipeline itself must not become the leak).

Delivery is decoupled from the request path. EventEmitter.start() moves sink
I/O to a background thread fed by a bounded queue: a slow or dead SIEM can
cost events (counted, never silent) but cannot add latency to LLM traffic or
stall the event loop.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from . import __version__
from .detectors.base import Detection, Direction
from .pipeline import Verdict

logger = logging.getLogger("promptwarden.events")

SCHEMA_VERSION = "1.1"

# OCSF severity_id scale: 1 Informational .. 5 Critical
_OCSF_SEVERITY = [(9, 5), (7, 4), (5, 3), (3, 2), (0, 1)]


def _ocsf_severity(score: int) -> int:
    for threshold, sev_id in _OCSF_SEVERITY:
        if score >= threshold:
            return sev_id
    return 1


@dataclass
class RequestContext:
    """Who and what a verdict belongs to. Carried into every event."""

    request_id: str
    app_id: str = "default"
    endpoint: str = "/v1/chat/completions"
    model: str | None = None
    stream: bool = False
    src_ip: str | None = None
    user: str | None = None
    correlation_id: str | None = None
    policy_hash: str | None = None
    mode: str = "enforce"


def _finding(d: Detection) -> dict:
    finding = {
        "rule_id": d.rule_id,
        "detector": d.detector,
        "title": d.description,
        "severity": d.severity,
        "confidence": d.confidence,
        "evidence": d.evidence,
        "owasp_llm_top10": d.owasp_llm,
        "owasp_agentic_top10": d.owasp_agentic,
        "mitre_atlas": d.atlas,
        "disposition": d.disposition,
    }
    if d.source is not None:
        finding["source"] = d.source
    if d.index is not None:
        finding["index"] = d.index
    if d.tool_name:
        finding["tool_name"] = d.tool_name
    if d.tags:
        finding["tags"] = list(d.tags)
    return finding


def _context_fields(ctx: RequestContext | None) -> dict:
    if ctx is None:
        return {}
    fields: dict = {
        "actor": {"app_id": ctx.app_id},
        "llm": {"endpoint": ctx.endpoint, "model": ctx.model, "stream": ctx.stream},
    }
    if ctx.user:
        fields["actor"]["user"] = ctx.user
    if ctx.src_ip:
        fields["src_endpoint"] = {"ip": ctx.src_ip}
    return fields


def _metadata(request_id: str | None, app_id: str, ctx: RequestContext | None) -> dict:
    metadata = {
        "product": {"name": "PromptWarden", "version": __version__},
        "schema_version": SCHEMA_VERSION,
        "event_uid": str(uuid.uuid4()),
        "uid": request_id or str(uuid.uuid4()),
        "app_id": app_id,
    }
    if ctx is not None:
        metadata["policy_hash"] = ctx.policy_hash
        metadata["mode"] = ctx.mode
        if ctx.correlation_id:
            metadata["correlation_uid"] = ctx.correlation_id
    return metadata


def build_event(
    verdict: Verdict,
    direction: Direction,
    request_id: str | None = None,
    app_id: str = "default",
    ctx: RequestContext | None = None,
) -> dict:
    """Build an OCSF-aligned finding event (class: Detection Finding, 2004)."""
    if ctx is not None:
        request_id = request_id or ctx.request_id
        app_id = ctx.app_id
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "activity_name": f"llm_{direction}_inspection",
        "severity_id": _ocsf_severity(verdict.score),
        "status": verdict.action,
        "disposition": verdict.disposition,
        "message": (
            f"PromptWarden {verdict.disposition}: {len(verdict.detections)} detection(s), "
            f"max severity {verdict.score}"
        ),
        "metadata": _metadata(request_id, app_id, ctx),
        "finding_info": [_finding(d) for d in verdict.detections],
    }
    event.update(_context_fields(ctx))
    return event


def build_gateway_event(
    detection: Detection, status: str, disposition: str, ctx: RequestContext,
    suppressed: int = 0,
) -> dict:
    """Finding raised by the gateway itself (auth failure, rate limit, model
    policy) rather than by content inspection."""
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "activity_name": "llm_gateway_control",
        "severity_id": _ocsf_severity(detection.severity),
        "status": status,
        "disposition": disposition,
        "message": f"PromptWarden {disposition}: {detection.description}",
        "metadata": _metadata(ctx.request_id, ctx.app_id, ctx),
        "finding_info": [_finding(detection)],
    }
    if suppressed:
        event["suppressed_count"] = suppressed
    event.update(_context_fields(ctx))
    return event


def build_audit_event(
    ctx: RequestContext,
    *,
    status_code: int,
    outcome: str,
    duration_ms: float,
    upstream_ms: float | None,
    prompt_chars: int,
    completion_chars: int,
    usage: dict | None,
    rule_ids: list[str],
) -> dict:
    """One API Activity record per request (OCSF class 6003). Metadata only:
    sizes, timings, token usage, and which rules fired. Never content."""
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "activity_name": "llm_request",
        "severity_id": 1,
        "status": outcome,
        "message": f"LLM request {outcome} ({status_code})",
        "metadata": _metadata(ctx.request_id, ctx.app_id, ctx),
        "http_response": {"code": status_code},
        "duration_ms": round(duration_ms, 2),
        "upstream_ms": round(upstream_ms, 2) if upstream_ms is not None else None,
        "prompt_chars": prompt_chars,
        "completion_chars": completion_chars,
        "usage": usage or {},
        "rule_ids": rule_ids,
    }
    event.update(_context_fields(ctx))
    return event


def _cef_header(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\n", " ").replace("\r", " ")


def _cef_ext(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def to_cef(event: dict) -> str:
    """Render an event as a single CEF line for legacy SIEM ingestion.

    Header and extension values are escaped per the CEF spec so that operator
    text (denylist descriptions) or model text cannot forge fields.
    """
    findings = event.get("finding_info") or []
    first = findings[0] if findings else {}
    metadata = event.get("metadata", {})
    parts = [
        f"act={_cef_ext(event.get('status', ''))}",
        f"cs1={_cef_ext(first.get('owasp_llm_top10') or '')} cs1Label=owaspLlmTop10",
        f"cs2={_cef_ext(first.get('mitre_atlas') or '')} cs2Label=mitreAtlas",
        f"cs3={_cef_ext(metadata.get('app_id', ''))} cs3Label=appId",
        f"externalId={_cef_ext(metadata.get('uid', ''))}",
    ]
    src_ip = (event.get("src_endpoint") or {}).get("ip")
    if src_ip:
        parts.append(f"src={_cef_ext(src_ip)}")
    parts.append(f"msg={_cef_ext(event.get('message', ''))}")
    return (
        f"CEF:0|PromptWarden|gateway|{_cef_header(__version__)}|"
        f"{_cef_header(first.get('rule_id', 'PW-NONE'))}|"
        f"{_cef_header(first.get('title', event.get('activity_name', 'clean')))}|"
        f"{event.get('severity_id', 1)}|{' '.join(parts)}"
    )


# -- sinks ------------------------------------------------------------------


class StdoutSink:
    name = "stdout"

    def emit(self, event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), flush=True)  # noqa: T201


class FileSink:
    """Append JSONL events; thread-safe within a single process."""

    name = "file"

    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class _HttpSink:
    """Shared HTTP delivery: one pooled client, status checked, never raises."""

    name = "http"

    def __init__(self, endpoint: str, headers: dict, transport: httpx.BaseTransport | None = None):
        self.endpoint = endpoint
        self._client = httpx.Client(headers=headers, timeout=5.0, transport=transport)
        self.failures = 0

    def _post(self, *, content: bytes) -> None:
        try:
            response = self._client.post(
                self.endpoint, content=content, headers={"Content-Type": "application/json"}
            )
        except httpx.HTTPError as exc:
            self.failures += 1
            logger.warning("%s sink delivery failed: %s", self.name, type(exc).__name__)
            return
        if response.status_code >= 300:
            self.failures += 1
            logger.warning("%s sink rejected events: HTTP %s", self.name, response.status_code)

    def close(self) -> None:
        self._client.close()


class HecSink(_HttpSink):
    """Splunk HTTP Event Collector sink. Failures are logged and counted,
    never raised: losing one event must not take down the traffic path."""

    name = "splunk_hec"

    def __init__(self, url: str, token: str, transport: httpx.BaseTransport | None = None):
        super().__init__(
            url.rstrip("/") + "/services/collector/event",
            {"Authorization": f"Splunk {token}"},
            transport,
        )

    def emit(self, event: dict) -> None:
        self.emit_batch([event])

    def emit_batch(self, events: list[dict]) -> None:
        # HEC accepts several event objects concatenated in one request body.
        body = "\n".join(
            json.dumps({"event": event, "sourcetype": "promptwarden"}, ensure_ascii=False)
            for event in events
        )
        self._post(content=body.encode("utf-8"))


class WebhookSink(_HttpSink):
    """Generic HTTPS JSON sink: POSTs a JSON array of events with optional
    bearer auth. Fits Cribl, Elastic, Chronicle, or a Sentinel ingestion proxy."""

    name = "webhook"

    def __init__(self, url: str, token: str | None = None,
                 transport: httpx.BaseTransport | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        super().__init__(url, headers, transport)

    def emit(self, event: dict) -> None:
        self.emit_batch([event])

    def emit_batch(self, events: list[dict]) -> None:
        self._post(content=json.dumps(events, ensure_ascii=False).encode("utf-8"))


class SyslogCefSink:
    """CEF over syslog (RFC 3164 framing) for QRadar, ArcSight and similar.

    addr looks like udp://host:514 or tcp://host:601.
    """

    name = "syslog_cef"

    def __init__(self, addr: str):
        parts = urlsplit(addr)
        if parts.scheme not in {"udp", "tcp"} or not parts.hostname:
            raise ValueError("PW_SYSLOG_ADDR must look like udp://host:514 or tcp://host:601")
        self._tcp = parts.scheme == "tcp"
        self._target = (parts.hostname, parts.port or 514)
        self._sock: socket.socket | None = None
        self.failures = 0

    def _connect(self) -> socket.socket:
        if self._sock is None:
            if self._tcp:
                self._sock = socket.create_connection(self._target, timeout=3.0)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def emit(self, event: dict) -> None:
        # <134> = facility local0, severity informational.
        line = f"<134>promptwarden: {to_cef(event)}"
        try:
            sock = self._connect()
            if self._tcp:
                sock.sendall(line.encode("utf-8") + b"\n")
            else:
                sock.sendto(line.encode("utf-8")[:8192], self._target)
        except OSError as exc:
            self.failures += 1
            self._sock = None
            logger.warning("syslog sink delivery failed: %s", type(exc).__name__)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


# -- emitter ----------------------------------------------------------------

_STOP = object()


class EventThrottle:
    """Collapse repeats of the same gateway event (for example a client that
    hammers a rate limit) into one event per interval with a suppressed count,
    so an attacker cannot use the gateway to flood the SIEM."""

    def __init__(self, interval_seconds: float = 10.0, clock=None, max_keys: int = 10_000):
        self._interval = interval_seconds
        self._clock = clock or time.monotonic
        self._state: dict[str, tuple[float, int]] = {}
        self._max_keys = max_keys

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (emit_now, suppressed_since_last_emit)."""
        now = self._clock()
        last, suppressed = self._state.get(key, (None, 0))
        if last is None or now - last >= self._interval:
            if len(self._state) >= self._max_keys:
                self._state.clear()
            self._state[key] = (now, 0)
            return True, suppressed
        self._state[key] = (last, suppressed + 1)
        return False, 0


class EventEmitter:
    """Fan events out to sinks.

    Without start(), emission is synchronous (library and test use). After
    start(), events go through a bounded queue to a daemon thread; when the
    queue is full the event is dropped and counted.
    """

    def __init__(self, sinks: list, queue_size: int = 10_000, on_drop=None, on_emit=None):
        self.sinks = sinks
        self.dropped = 0
        self.emitted = 0
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._thread: threading.Thread | None = None
        self._on_drop = on_drop
        self._on_emit = on_emit

    # lifecycle

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._worker, name="promptwarden-events", daemon=True
            )
            self._thread.start()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def close(self, timeout: float = 5.0) -> None:
        if self._thread is not None:
            self._queue.put(_STOP)
            self._thread.join(timeout)
            self._thread = None
        for sink in self.sinks:
            closer = getattr(sink, "close", None)
            if closer is not None:
                closer()

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until queued events are delivered (best effort)."""
        if self._thread is None:
            return True
        done = threading.Event()
        self._queue.put(done)
        return done.wait(timeout)

    # emission

    def emit_event(self, event: dict) -> dict:
        if self._thread is None:
            self._deliver([event])
            return event
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            if self._on_drop is not None:
                self._on_drop()
        return event

    def emit(
        self,
        verdict: Verdict,
        direction: Direction,
        request_id: str | None = None,
        app_id: str = "default",
        ctx: RequestContext | None = None,
    ) -> dict:
        return self.emit_event(
            build_event(verdict, direction, request_id=request_id, app_id=app_id, ctx=ctx)
        )

    # internals

    def _deliver(self, events: list[dict]) -> None:
        for sink in self.sinks:
            try:
                batch = getattr(sink, "emit_batch", None)
                if batch is not None:
                    batch(events)
                else:
                    for event in events:
                        sink.emit(event)
            except Exception:  # a broken sink must not stop the others
                logger.exception("event sink %s failed", getattr(sink, "name", sink))
        self.emitted += len(events)
        if self._on_emit is not None:
            self._on_emit(len(events))

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            batch: list[dict] = []
            markers: list[threading.Event] = []
            stop = False
            while True:
                if item is _STOP:
                    stop = True
                elif isinstance(item, threading.Event):
                    markers.append(item)
                else:
                    batch.append(item)
                if stop or len(batch) >= 200:
                    break
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
            if batch:
                self._deliver(batch)
            for marker in markers:
                marker.set()
            if stop:
                return
