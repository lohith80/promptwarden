"""PromptWarden gateway: OpenAI-compatible reverse proxy with inline detection.

v0.1 scope (documented limitation): non-streaming chat completions only.
`stream: true` requests are downgraded to non-streaming so inspection always
sees the complete response before it reaches the client. Streaming inspection
and an Anthropic Messages adapter are on the roadmap.
"""

from __future__ import annotations

import logging
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .config import Settings, load_policy
from .events import EventEmitter, FileSink, HecSink, StdoutSink
from .pipeline import Pipeline, Verdict

logger = logging.getLogger("promptwarden")

# Only these request headers are forwarded upstream. Everything else
# (cookies, tracing headers, client IPs) stops at the gateway.
_FORWARD_HEADERS = {"authorization", "content-type", "openai-organization", "openai-project"}


def _extract_text(messages: list) -> str:
    """Concatenate textual content from an OpenAI-style messages array."""
    parts: list[str] = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for chunk in content:
                if isinstance(chunk, dict) and chunk.get("type") == "text":
                    parts.append(chunk.get("text", ""))
    return "\n".join(parts)


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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    policy = load_policy(settings.policy_path)
    pipeline = Pipeline(policy)

    sinks: list = [StdoutSink()]
    if settings.event_log_path:
        sinks.append(FileSink(settings.event_log_path))
    if settings.hec_url and settings.hec_token:
        sinks.append(HecSink(settings.hec_url, settings.hec_token))
    emitter = EventEmitter(sinks)

    app = FastAPI(title="PromptWarden", version=__version__)
    app.state.pipeline = pipeline
    app.state.emitter = emitter
    app.state.settings = settings

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body_bytes = await request.body()
        if len(body_bytes) > policy.gateway.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": {"type": "promptwarden_limit", "message": "request too large"}},
            )
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": {"type": "promptwarden_bad_request", "message": "invalid JSON"}},
            )

        request_id = str(uuid.uuid4())
        inbound_text = _extract_text(body.get("messages", []))
        inbound = pipeline.run(inbound_text, "inbound")
        if inbound.action != "allow":
            emitter.emit(inbound, "inbound", request_id=request_id)
        if inbound.action == "block":
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "type": "promptwarden_blocked",
                        "message": "Request blocked by PromptWarden policy",
                        "request_id": request_id,
                        "detections": _detection_summaries(inbound),
                    }
                },
            )

        # v0.1: force non-streaming so the full response is inspectable.
        body["stream"] = False
        headers = {
            k: v for k, v in request.headers.items() if k.lower() in _FORWARD_HEADERS
        }
        upstream_url = settings.upstream_base_url.rstrip("/") + "/v1/chat/completions"
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                upstream = await client.post(upstream_url, json=body, headers=headers)
            except httpx.HTTPError as exc:
                logger.error("upstream error: %s", exc)
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": {
                            "type": "promptwarden_upstream",
                            "message": "upstream unreachable",
                        }
                    },
                )

        try:
            response_body = upstream.json()
        except ValueError:
            return JSONResponse(status_code=upstream.status_code, content={"error": {
                "type": "promptwarden_upstream", "message": "non-JSON upstream response"}})

        outbound_text = "\n".join(
            choice.get("message", {}).get("content") or ""
            for choice in response_body.get("choices", [])
        )
        outbound = pipeline.run(outbound_text, "outbound")
        if outbound.action != "allow":
            emitter.emit(outbound, "outbound", request_id=request_id)
        if outbound.action == "block":
            for choice in response_body.get("choices", []):
                if "message" in choice:
                    choice["message"]["content"] = (
                        "[PromptWarden] Response withheld: outbound content matched "
                        f"blocking policy (request_id {request_id})."
                    )
            response_body["promptwarden"] = {
                "action": "block",
                "request_id": request_id,
                "detections": _detection_summaries(outbound),
            }

        return JSONResponse(status_code=upstream.status_code, content=response_body)

    return app


app = create_app()
