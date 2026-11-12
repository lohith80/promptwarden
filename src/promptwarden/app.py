"""PromptWarden gateway: OpenAI-compatible reverse proxy with inline detection.

Endpoints
  POST /v1/chat/completions   inspected both ways; streaming supported
  POST /v1/embeddings         inbound inspection (documents headed to a vector store)
  GET  /v1/models[/{id}]      authenticated passthrough
  GET  /healthz /readyz       liveness / readiness
  GET  /metrics               Prometheus

Anything else returns 404: a security gateway does not forward what it cannot
inspect.

Request path, in order: identify the app (gateway key) -> rate limit -> read
the body under a size cap -> model allowlist -> inbound inspection (with
optional secret redaction) -> upstream call with the right credential ->
outbound inspection (streamed or whole) -> audit record.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import logging
import re
import signal
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import __version__, gateway_rules
from .auth import AppIndex, AuthResult
from .config import EffectiveConfig, Policy, PolicyError, Settings, load_policy
from .detectors.base import Detection
from .detectors.tools import ToolRegistry
from .events import (
    EventEmitter,
    EventThrottle,
    FileSink,
    HecSink,
    RequestContext,
    StdoutSink,
    SyslogCefSink,
    WebhookSink,
    build_audit_event,
    build_gateway_event,
)
from .metrics import CONTENT_TYPE, Metrics
from .pipeline import Pipeline, Verdict
from .ratelimit import RateLimiter
from .segments import (
    InspectionInput,
    Uninspectable,
    chat_request_input,
    chat_response_input,
    embeddings_input,
)
from .streaming import StreamInspector

logger = logging.getLogger("promptwarden")

# Only these request headers are forwarded upstream. Everything else
# (cookies, tracing headers, client IPs, the gateway key) stops here.
# Authorization is handled separately: see auth.AppIndex.resolve.
_FORWARD_HEADERS = {"content-type", "openai-organization", "openai-project", "openai-beta"}

# Upstream response headers worth handing back: SDK retry logic reads them.
_RETURN_HEADERS = {
    "retry-after",
    "openai-processing-ms",
    "x-request-id",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
}

# Bodies at or above this size are inspected on a worker thread.
_OFFLOAD_BYTES = 32_768

_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WITHHELD = (
    "[PromptWarden] Response withheld: outbound content matched blocking policy "
    "(request_id {request_id})."
)


class _TooLarge(Exception):
    pass


@dataclass
class Runtime:
    """Everything derived from the policy file. Swapped atomically on reload."""

    policy: Policy
    policy_hash: str
    pipeline: Pipeline
    apps: AppIndex


@dataclass
class _Call:
    """Bookkeeping for one request, used for metrics and the audit record."""

    ctx: RequestContext
    started: float
    outcome: str = "allowed"
    status_code: int = 200
    upstream_ms: float | None = None
    prompt_chars: int = 0
    completion_chars: int = 0
    usage: dict | None = None
    rule_ids: list[str] = field(default_factory=list)
    finalized: bool = False
    body_bytes: int = 0


def build_runtime(settings: Settings, registry: ToolRegistry | None = None) -> Runtime:
    policy = load_policy(settings.policy_path)
    if settings.upstream_api_key and not policy.auth.required:
        logger.warning(
            "PW_UPSTREAM_API_KEY is set but auth.required is false: the key is only "
            "used for requests that present a valid gateway key"
        )
    return Runtime(
        policy=policy,
        policy_hash=policy.fingerprint(),
        pipeline=Pipeline(policy, registry),
        apps=AppIndex(policy, global_upstream_key=settings.upstream_api_key),
    )


def _build_sinks(settings: Settings) -> list:
    sinks: list = []
    if settings.stdout_events:
        sinks.append(StdoutSink())
    if settings.event_log_path:
        sinks.append(FileSink(settings.event_log_path))
    if settings.hec_url and settings.hec_token:
        sinks.append(HecSink(settings.hec_url, settings.hec_token))
    if settings.webhook_url:
        sinks.append(WebhookSink(settings.webhook_url, settings.webhook_token))
    if settings.syslog_addr:
        sinks.append(SyslogCefSink(settings.syslog_addr))
    return sinks


def _error(status: int, error_type: str, message: str, request_id: str | None = None,
           extra: dict | None = None, headers: dict | None = None) -> JSONResponse:
    error: dict = {"type": error_type, "message": message}
    if request_id:
        error["request_id"] = request_id
    if extra:
        error.update(extra)
    response_headers = dict(headers or {})
    if request_id:
        response_headers["x-promptwarden-request-id"] = request_id
    return JSONResponse(status_code=status, content={"error": error}, headers=response_headers)


def _detection_summaries(verdict: Verdict) -> list[dict]:
    return [
        {
            "rule_id": d.rule_id,
            "description": d.description,
            "severity": d.severity,
            "owasp_llm_top10": d.owasp_llm,
            "mitre_atlas": d.atlas,
        }
        for d in verdict.detections
    ]


class Gateway:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.metrics = Metrics()
        self.registry = ToolRegistry()
        self.runtime = build_runtime(settings, self.registry)
        self.metrics.set_policy(self.runtime.policy_hash, self.runtime.policy.gateway.mode)
        self.limiter = RateLimiter()
        self.throttle = EventThrottle()
        self.emitter = EventEmitter(
            _build_sinks(settings),
            queue_size=settings.event_queue_size,
            on_drop=self.metrics.events_dropped.inc,
            on_emit=self.metrics.events_emitted.inc,
        )
        timeout = self.runtime.policy.gateway.upstream_timeout_seconds
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=10.0),
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
            transport=transport,
        )
        self._policy_stamp = self._stamp()

    # -- lifecycle ----------------------------------------------------------

    def _stamp(self) -> tuple[float, int] | None:
        try:
            stat = Path(self.settings.policy_path).stat()
        except OSError:
            return None
        return (stat.st_mtime, stat.st_size)

    def reload(self) -> bool:
        """Re-read the policy file. An invalid file keeps the running policy."""
        try:
            runtime = build_runtime(self.settings, self.registry)
        except PolicyError as exc:
            logger.error("policy reload rejected, keeping current policy: %s", exc)
            self.metrics.policy_reloads.labels(result="rejected").inc()
            return False
        changed = runtime.policy_hash != self.runtime.policy_hash
        self.runtime = runtime
        self._policy_stamp = self._stamp()
        self.metrics.set_policy(runtime.policy_hash, runtime.policy.gateway.mode)
        self.metrics.policy_reloads.labels(result="applied" if changed else "unchanged").inc()
        logger.info("policy reloaded (hash %s, changed=%s)", runtime.policy_hash, changed)
        return True

    async def watch_policy(self, interval: int) -> None:
        while True:
            await asyncio.sleep(interval)
            stamp = self._stamp()
            if stamp != self._policy_stamp:
                self._policy_stamp = stamp
                self.reload()

    async def close(self) -> None:
        await self.client.aclose()
        self.emitter.close()

    # -- helpers ------------------------------------------------------------

    def _client_ip(self, request: Request) -> str | None:
        hops = self.settings.trusted_proxy_hops
        if hops > 0:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                parts = [part.strip() for part in forwarded.split(",") if part.strip()]
                if len(parts) >= hops:
                    return parts[-hops][:64]
        return request.client.host if request.client else None

    def _new_call(self, request: Request, endpoint: str, runtime: Runtime) -> _Call:
        correlation = request.headers.get("x-request-id")
        if correlation and not _CORRELATION_RE.match(correlation):
            correlation = None
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            endpoint=endpoint,
            src_ip=self._client_ip(request),
            correlation_id=correlation,
            policy_hash=runtime.policy_hash,
            mode=runtime.policy.gateway.mode,
        )
        return _Call(ctx=ctx, started=time.perf_counter())

    def _finalize(self, call: _Call, runtime: Runtime) -> None:
        if call.finalized:
            return
        call.finalized = True
        ctx = call.ctx
        self.metrics.requests.labels(
            app=ctx.app_id, endpoint=ctx.endpoint, outcome=call.outcome
        ).inc()
        if call.usage:
            for kind in ("prompt_tokens", "completion_tokens"):
                value = call.usage.get(kind)
                if isinstance(value, int) and value > 0:
                    self.metrics.tokens.labels(app=ctx.app_id, type=kind).inc(value)
        if runtime.policy.audit.enabled:
            self.emitter.emit_event(
                build_audit_event(
                    ctx,
                    status_code=call.status_code,
                    outcome=call.outcome,
                    duration_ms=(time.perf_counter() - call.started) * 1000,
                    upstream_ms=call.upstream_ms,
                    prompt_chars=call.prompt_chars,
                    completion_chars=call.completion_chars,
                    usage=call.usage,
                    rule_ids=sorted(set(call.rule_ids)),
                )
            )

    def _gateway_finding(self, call: _Call, detection: Detection, status: str,
                         disposition: str, throttle_key: str) -> None:
        self.metrics.detections.labels(
            rule_id=detection.rule_id, direction="inbound", disposition=disposition
        ).inc()
        call.rule_ids.append(detection.rule_id)
        emit, suppressed = self.throttle.allow(throttle_key)
        if emit:
            self.emitter.emit_event(
                build_gateway_event(detection, status, disposition, call.ctx, suppressed)
            )

    def _inspect(self, runtime: Runtime, payload: InspectionInput, direction: str,
                 eff: EffectiveConfig) -> Verdict:
        started = time.perf_counter()
        verdict = runtime.pipeline.inspect(payload, direction, eff)
        self.metrics.inspection_seconds.labels(direction=direction).observe(
            time.perf_counter() - started
        )
        return verdict

    async def _inspect_async(self, runtime: Runtime, payload: InspectionInput, direction: str,
                             eff: EffectiveConfig, size: int) -> Verdict:
        """Inspect, moving large payloads off the event loop.

        Inspection is CPU-bound. For a typical prompt it takes well under a
        millisecond and a thread hop would cost more than it saves. For a
        large body it can take long enough to stall every other connection
        on this worker, so it runs on a thread and the loop stays responsive.
        """
        if size < _OFFLOAD_BYTES:
            return self._inspect(runtime, payload, direction, eff)
        return await asyncio.to_thread(self._inspect, runtime, payload, direction, eff)

    def _record(self, call: _Call, verdict: Verdict, direction: str) -> None:
        """Count detections, emit the finding event, update the call outcome."""
        for detection in verdict.detections:
            disposition = (
                "redacted" if detection.disposition == "redacted" else verdict.disposition
            )
            self.metrics.detections.labels(
                rule_id=detection.rule_id, direction=direction, disposition=disposition
            ).inc()
            call.rule_ids.append(detection.rule_id)
        if verdict.action != "allow":
            self.emitter.emit(verdict, direction, ctx=call.ctx)
        if verdict.action == "block":
            call.outcome = f"blocked_{direction}"
        elif verdict.action == "flag" and call.outcome == "allowed":
            call.outcome = "flagged"

    async def _read_body(self, request: Request, limit: int) -> bytes:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise _TooLarge
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise _TooLarge
            chunks.append(chunk)
        return b"".join(chunks)

    def _reject(self, call: _Call, status: int, error_type: str, message: str, outcome: str,
                extra: dict | None = None, headers: dict | None = None) -> JSONResponse:
        call.outcome = outcome
        call.status_code = status
        return _error(status, error_type, message, call.ctx.request_id, extra, headers)

    def _authenticate(self, request: Request, call: _Call,
                      runtime: Runtime) -> tuple[AuthResult, JSONResponse | None]:
        auth = runtime.apps.resolve(request.headers)
        ctx = call.ctx
        ctx.app_id = auth.effective.app_id
        ctx.mode = auth.effective.mode
        if not auth.ok:
            if auth.error_status == 401:
                self._gateway_finding(
                    call, gateway_rules.auth_failed(auth.error_message), "block", "denied",
                    f"auth:{ctx.src_ip}",
                )
                outcome = "unauthorized"
            else:
                logger.error("app %s: %s", ctx.app_id, auth.error_message)
                outcome = "config_error"
            return auth, self._reject(
                call, auth.error_status, auth.error_type, auth.error_message, outcome
            )

        limits = auth.effective.limits
        allowed, retry_after = self.limiter.check(
            ctx.app_id, limits.requests_per_minute, limits.burst
        )
        if not allowed:
            self._gateway_finding(
                call, gateway_rules.rate_limited(ctx.app_id, limits.requests_per_minute),
                "block", "rate_limited", f"rate:{ctx.app_id}",
            )
            return auth, self._reject(
                call, 429, "promptwarden_rate_limited", "rate limit exceeded", "rate_limited",
                headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
            )
        return auth, None

    async def _admit(self, request: Request, call: _Call,
                     runtime: Runtime) -> tuple[AuthResult, dict | None, JSONResponse | None]:
        """Authenticate, rate limit, and parse the request body."""
        auth, rejection = self._authenticate(request, call, runtime)
        if rejection is not None:
            return auth, None, rejection

        try:
            raw = await self._read_body(request, runtime.policy.gateway.max_body_bytes)
        except _TooLarge:
            return auth, None, self._reject(
                call, 413, "promptwarden_limit", "request too large", "too_large"
            )
        call.body_bytes = len(raw)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return auth, None, self._reject(
                call, 400, "promptwarden_bad_request", "body must be a JSON object", "bad_request"
            )

        ctx = call.ctx
        model = body.get("model")
        ctx.model = model[:128] if isinstance(model, str) else None
        user = body.get("user") or body.get("safety_identifier")
        ctx.user = user[:128] if isinstance(user, str) else None

        allowed_models = auth.effective.limits.allowed_models
        if allowed_models and not any(
            fnmatch.fnmatchcase(ctx.model or "", pattern) for pattern in allowed_models
        ):
            self._gateway_finding(
                call, gateway_rules.model_denied(ctx.model or ""), "block", "denied",
                f"model:{ctx.app_id}:{ctx.model}",
            )
            return auth, None, self._reject(
                call, 403, "promptwarden_model_not_allowed",
                "this model is not allowed for this app", "model_denied",
            )
        return auth, body, None

    def _blocked_response(self, call: _Call, runtime: Runtime, verdict: Verdict) -> JSONResponse:
        call.status_code = 400
        extra = None
        if runtime.policy.gateway.expose_detections:
            extra = {"detections": _detection_summaries(verdict)}
        return _error(
            400, "promptwarden_blocked", "Request blocked by PromptWarden policy",
            call.ctx.request_id, extra,
        )

    def _upstream_headers(self, request: Request, auth: AuthResult) -> dict:
        headers = {k: v for k, v in request.headers.items() if k.lower() in _FORWARD_HEADERS}
        if auth.upstream_authorization:
            headers["authorization"] = auth.upstream_authorization
        return headers

    def _return_headers(self, upstream: httpx.Response, call: _Call) -> dict:
        headers = {k: v for k, v in upstream.headers.items() if k.lower() in _RETURN_HEADERS}
        headers["x-promptwarden-request-id"] = call.ctx.request_id
        return headers

    def _url(self, path: str) -> str:
        return self.settings.upstream_base_url.rstrip("/") + path

    # -- chat completions ---------------------------------------------------

    async def chat_completions(self, request: Request) -> Response:
        runtime = self.runtime
        call = self._new_call(request, "/v1/chat/completions", runtime)
        deferred = False
        try:
            response, deferred = await self._chat(request, call, runtime)
            return response
        finally:
            if not deferred:
                self._finalize(call, runtime)

    async def _chat(self, request: Request, call: _Call,
                    runtime: Runtime) -> tuple[Response, bool]:
        auth, body, rejection = await self._admit(request, call, runtime)
        if rejection is not None or body is None:
            return rejection, False  # type: ignore[return-value]
        eff = auth.effective
        policy = runtime.policy

        try:
            payload = chat_request_input(body, policy.inspection.trusted_roles)
        except ValueError as exc:
            return self._reject(call, 400, "promptwarden_bad_request", str(exc),
                                "bad_request"), False
        call.prompt_chars = payload.char_count
        if payload.uninspected_parts:
            self.metrics.uninspected_parts.labels(app=eff.app_id).inc(payload.uninspected_parts)

        inbound = await self._inspect_async(runtime, payload, "inbound", eff, call.body_bytes)
        self._record(call, inbound, "inbound")
        if inbound.action == "block":
            return self._blocked_response(call, runtime, inbound), False

        cap = eff.limits.max_output_tokens
        if cap:
            for key in ("max_completion_tokens", "max_tokens"):
                if isinstance(body.get(key), int) and body[key] > cap:
                    body[key] = cap

        headers = self._upstream_headers(request, auth)
        url = self._url("/v1/chat/completions")
        if body.get("stream") is True:
            call.ctx.stream = True
            return await self._chat_stream(call, runtime, eff, url, body, headers)

        started = time.perf_counter()
        try:
            upstream = await self.client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            logger.error("upstream error: %s", type(exc).__name__)
            return self._reject(call, 502, "promptwarden_upstream", "upstream unreachable",
                                "upstream_error"), False
        self._observe_upstream(call, started)
        return await self._finish_json(call, runtime, eff, upstream, upstream.content), False

    def _observe_upstream(self, call: _Call, started: float) -> None:
        elapsed = time.perf_counter() - started
        call.upstream_ms = elapsed * 1000
        self.metrics.upstream_seconds.observe(elapsed)

    async def _finish_json(self, call: _Call, runtime: Runtime, eff: EffectiveConfig,
                           upstream: httpx.Response, raw: bytes) -> Response:
        """Inspect a complete (non-streamed) upstream response and return it."""
        call.status_code = upstream.status_code
        headers = self._return_headers(upstream, call)
        try:
            response_body = json.loads(raw)
        except ValueError:
            call.outcome = "upstream_error"
            return _error(upstream.status_code, "promptwarden_upstream",
                          "non-JSON upstream response", call.ctx.request_id, headers=headers)
        if not isinstance(response_body, dict):
            return JSONResponse(status_code=upstream.status_code, content=response_body,
                                headers=headers)
        if upstream.status_code >= 400 and call.outcome == "allowed":
            call.outcome = "upstream_error"

        payload = chat_response_input(response_body)
        call.completion_chars = payload.char_count
        if isinstance(response_body.get("usage"), dict):
            call.usage = response_body["usage"]

        outbound = await self._inspect_async(runtime, payload, "outbound", eff, len(raw))
        self._record(call, outbound, "outbound")
        if outbound.action == "block":
            notice = _WITHHELD.format(request_id=call.ctx.request_id)
            for choice in response_body.get("choices") or []:
                message = choice.get("message") if isinstance(choice, dict) else None
                if isinstance(message, dict):
                    message["content"] = notice
                    # A blocked tool call must not reach the client: the
                    # client is what would execute it.
                    message.pop("tool_calls", None)
                    message.pop("function_call", None)
                    choice["finish_reason"] = "content_filter"
            info: dict = {"action": "block", "request_id": call.ctx.request_id}
            if runtime.policy.gateway.expose_detections:
                info["detections"] = _detection_summaries(outbound)
            response_body["promptwarden"] = info
        return JSONResponse(status_code=upstream.status_code, content=response_body,
                            headers=headers)

    async def _chat_stream(self, call: _Call, runtime: Runtime, eff: EffectiveConfig, url: str,
                           body: dict, headers: dict) -> tuple[Response, bool]:
        started = time.perf_counter()
        upstream_request = self.client.build_request("POST", url, json=body, headers=headers)
        try:
            upstream = await self.client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            logger.error("upstream error: %s", type(exc).__name__)
            return self._reject(call, 502, "promptwarden_upstream", "upstream unreachable",
                                "upstream_error"), False

        content_type = upstream.headers.get("content-type", "")
        if upstream.status_code != 200 or "text/event-stream" not in content_type:
            # Error body, or a provider that ignored stream=true. Either way
            # it is a complete document: inspect it as one.
            try:
                raw = await upstream.aread()
            except httpx.HTTPError:
                raw = b""
            finally:
                await upstream.aclose()
            self._observe_upstream(call, started)
            return await self._finish_json(call, runtime, eff, upstream, raw), False

        streaming = runtime.policy.streaming
        inspector = StreamInspector(
            lambda payload: self._inspect(runtime, payload, "outbound", eff),
            enforce=eff.mode == "enforce",
            holdback_chars=streaming.holdback_chars,
            buffer_all=streaming.mode == "buffer",
            request_id=call.ctx.request_id,
            expose_detections=runtime.policy.gateway.expose_detections,
        )

        async def relay():
            try:
                async for line in upstream.aiter_lines():
                    if not line:
                        continue
                    if line.startswith(":"):
                        yield line + "\n\n"  # keep-alive comment
                        continue
                    if not line.startswith("data:"):
                        continue
                    for out in inspector.feed(line[5:].strip()):
                        yield f"data: {out}\n\n"
                    if inspector.finished:
                        break
                if not inspector.finished:
                    for out in inspector.finish():
                        yield f"data: {out}\n\n"
            except httpx.HTTPError as exc:
                logger.error("upstream stream error: %s", type(exc).__name__)
                call.outcome = "upstream_error"
            finally:
                with contextlib.suppress(Exception):
                    await upstream.aclose()
                self._observe_upstream(call, started)
                call.completion_chars = inspector.completion_chars
                call.usage = inspector.usage
                if inspector.verdict is not None:
                    self._record(call, inspector.verdict, "outbound")
                elif call.outcome == "allowed":
                    call.outcome = "client_disconnect"
                self._finalize(call, runtime)

        response_headers = self._return_headers(upstream, call)
        response_headers["Cache-Control"] = "no-cache"
        response_headers["X-Accel-Buffering"] = "no"
        return StreamingResponse(relay(), media_type="text/event-stream",
                                 headers=response_headers), True

    # -- embeddings ---------------------------------------------------------

    async def embeddings(self, request: Request) -> Response:
        runtime = self.runtime
        call = self._new_call(request, "/v1/embeddings", runtime)
        try:
            return await self._embeddings(request, call, runtime)
        finally:
            self._finalize(call, runtime)

    async def _embeddings(self, request: Request, call: _Call, runtime: Runtime) -> Response:
        auth, body, rejection = await self._admit(request, call, runtime)
        if rejection is not None or body is None:
            return rejection  # type: ignore[return-value]
        eff = auth.effective
        try:
            payload = embeddings_input(body)
        except Uninspectable as exc:
            self._gateway_finding(
                call, gateway_rules.uninspectable(str(exc)), "block", "denied",
                f"uninspectable:{eff.app_id}",
            )
            return self._reject(call, 400, "promptwarden_uninspectable", str(exc), "bad_request")
        except ValueError as exc:
            return self._reject(call, 400, "promptwarden_bad_request", str(exc), "bad_request")
        call.prompt_chars = payload.char_count

        inbound = await self._inspect_async(runtime, payload, "inbound", eff, call.body_bytes)
        self._record(call, inbound, "inbound")
        if inbound.action == "block":
            return self._blocked_response(call, runtime, inbound)

        started = time.perf_counter()
        try:
            upstream = await self.client.post(
                self._url("/v1/embeddings"), json=body,
                headers=self._upstream_headers(request, auth),
            )
        except httpx.HTTPError as exc:
            logger.error("upstream error: %s", type(exc).__name__)
            return self._reject(call, 502, "promptwarden_upstream", "upstream unreachable",
                                "upstream_error")
        self._observe_upstream(call, started)
        call.status_code = upstream.status_code
        if upstream.status_code >= 400 and call.outcome == "allowed":
            call.outcome = "upstream_error"
        try:
            usage = upstream.json().get("usage")
            call.usage = usage if isinstance(usage, dict) else None
        except (ValueError, AttributeError):
            pass
        return Response(
            content=upstream.content, status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
            headers=self._return_headers(upstream, call),
        )

    # -- models -------------------------------------------------------------

    async def models(self, request: Request, model_id: str | None = None) -> Response:
        runtime = self.runtime
        call = self._new_call(request, "/v1/models", runtime)
        try:
            auth, rejection = self._authenticate(request, call, runtime)
            if rejection is not None:
                return rejection
            path = "/v1/models" + (f"/{model_id}" if model_id else "")
            try:
                upstream = await self.client.get(
                    self._url(path), headers=self._upstream_headers(request, auth)
                )
            except httpx.HTTPError as exc:
                logger.error("upstream error: %s", type(exc).__name__)
                return self._reject(call, 502, "promptwarden_upstream", "upstream unreachable",
                                    "upstream_error")
            call.status_code = upstream.status_code
            return Response(
                content=upstream.content, status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type", "application/json"),
                headers=self._return_headers(upstream, call),
            )
        finally:
            self._finalize(call, runtime)


def create_app(settings: Settings | None = None,
               transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    """Build the gateway. `transport` lets tests stand in for the upstream."""
    settings = settings or Settings.from_env()
    gateway = Gateway(settings, transport)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        if settings.event_async:
            gateway.emitter.start()
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError, AttributeError):
            loop.add_signal_handler(signal.SIGHUP, gateway.reload)
        watcher = None
        if settings.policy_reload_seconds > 0:
            watcher = asyncio.create_task(gateway.watch_policy(settings.policy_reload_seconds))
        try:
            yield
        finally:
            if watcher is not None:
                watcher.cancel()
            await gateway.close()

    app = FastAPI(title="PromptWarden", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway = gateway
    app.state.settings = settings

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    async def readyz() -> Response:
        runtime = gateway.runtime
        events_ok = (not settings.event_async) or gateway.emitter.running
        body = {
            "status": "ready" if events_ok else "degraded",
            "version": __version__,
            "policy_hash": runtime.policy_hash,
            "mode": runtime.policy.gateway.mode,
            "auth_required": runtime.policy.auth.required,
            "apps": len(runtime.policy.apps),
            "event_sinks": [getattr(sink, "name", "custom") for sink in gateway.emitter.sinks],
            "events_dropped": gateway.emitter.dropped,
        }
        return JSONResponse(status_code=200 if events_ok else 503, content=body)

    if settings.metrics_enabled:

        @app.get("/metrics")
        async def metrics() -> Response:
            return Response(content=gateway.metrics.render(), media_type=CONTENT_TYPE)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        return await gateway.chat_completions(request)

    @app.post("/v1/embeddings")
    async def embeddings(request: Request) -> Response:
        return await gateway.embeddings(request)

    @app.get("/v1/models")
    async def list_models(request: Request) -> Response:
        return await gateway.models(request)

    @app.get("/v1/models/{model_id:path}")
    async def get_model(request: Request, model_id: str) -> Response:
        return await gateway.models(request, model_id)

    return app


def __getattr__(name: str):
    # `uvicorn promptwarden.app:app` keeps working, but the app (and its
    # background thread) is only built when something actually asks for it.
    if name == "app":
        instance = create_app()
        globals()["app"] = instance
        return instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
