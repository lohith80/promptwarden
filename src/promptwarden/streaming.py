"""Inline inspection of streamed (SSE) chat completions.

The problem with streaming is that text already sent to the client cannot be
recalled. StreamInspector solves it with a holdback window: every chunk is
queued, and a chunk is released only once the text that follows it, up to
holdback_chars, has been inspected. The guarantee this buys:

    Any detection whose matched text is no longer than holdback_chars is made
    before a single character of that match reaches the client.

Secrets, canary tokens and injection phrases are all far shorter than the
default 256 characters. A match longer than the window (a very long beacon
URL) is still detected, but its first characters may already be out; that is
the documented residual risk of window mode. Buffer mode holds the entire
stream and has no such gap, at the cost of time to first token.

Tool calls are never released early: a client acts on a tool call only when
it is complete, so the deltas are held until the arguments have been
inspected. Streams with more than one choice fall back to full buffering.

In monitor mode nothing is held and nothing is scanned mid-stream: chunks
pass straight through and the full output is inspected once at the end, so
shadow mode adds no latency to a stream.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable

from .detectors.tools import ToolCall
from .pipeline import Verdict
from .segments import InspectionInput, stream_output_input

# Mid-stream scans run each time this many new characters have arrived.
SCAN_EVERY_CHARS = 48
# Extra context kept in front of the holdback window so a match that started
# earlier is still seen whole.
MIN_OVERLAP_CHARS = 256

DONE = "[DONE]"

InspectFn = Callable[[InspectionInput], Verdict]


class StreamInspector:
    """Feed SSE data payloads in, get releasable payloads out.

    feed() and finish() return the payloads (the text after "data: ") that
    may be sent to the client now. After a block, `blocked` is True and the
    caller should stop reading the upstream.
    """

    def __init__(
        self,
        inspect: InspectFn,
        *,
        enforce: bool,
        holdback_chars: int,
        buffer_all: bool,
        request_id: str,
        expose_detections: bool = True,
    ):
        self._inspect = inspect
        self._enforce = enforce
        self._holdback = holdback_chars
        self._overlap = max(holdback_chars, MIN_OVERLAP_CHARS)
        self._hold_all = buffer_all
        self._request_id = request_id
        self._expose = expose_detections

        self._pending: deque[tuple[str, int]] = deque()  # (payload, release_at)
        self._parts: dict[int, list[str]] = {}
        self._tool_calls: dict[tuple[int, int], dict[str, str]] = {}
        self._total = 0  # characters of choice-0 content seen
        self._scanned = 0  # characters of choice-0 content inspected
        self._window = ""  # unreleased tail plus overlap, for mid-stream scans
        self._meta: dict = {}

        self.verdict: Verdict | None = None
        self.blocked = False
        self.finished = False
        self.completion_chars = 0
        self.usage: dict | None = None

    # -- public -------------------------------------------------------------

    def feed(self, payload: str) -> list[str]:
        if self.finished:
            return []
        if payload.strip() == DONE:
            return self._finish(with_done=True)

        new_text = self._absorb(payload)
        self._pending.append((payload, self._total))

        if not self._enforce:
            return self._release_all()
        if self._hold_all:
            return []

        if new_text:
            self._window += new_text
            if self._total - self._scanned >= SCAN_EVERY_CHARS:
                verdict = self._inspect(stream_output_input({0: self._window}, []))
                if verdict.action == "block":
                    return self._block(verdict)
                self._scanned = self._total
                self._window = self._window[-(self._holdback + self._overlap):]
        return self._release_ready()

    def finish(self) -> list[str]:
        """Upstream ended (with or without a [DONE] marker)."""
        if self.finished:
            return []
        return self._finish(with_done=False)

    def tool_calls(self) -> list[ToolCall]:
        return [
            ToolCall(name=state["name"], arguments=state["arguments"], index=choice)
            for (choice, _), state in sorted(self._tool_calls.items())
        ]

    # -- internals ----------------------------------------------------------

    def _absorb(self, payload: str) -> str:
        """Parse one chunk, accumulate its content. Returns new choice-0 text."""
        try:
            chunk = json.loads(payload)
        except ValueError:
            return ""
        if not isinstance(chunk, dict):
            return ""
        if not self._meta:
            self._meta = {k: chunk[k] for k in ("id", "model", "created") if k in chunk}
        if isinstance(chunk.get("usage"), dict):
            self.usage = chunk["usage"]

        new_text = ""
        choices = chunk.get("choices")
        if not isinstance(choices, list):
            return ""
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            if not isinstance(index, int):
                index = 0
            if index != 0:
                self._hold_all = True
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            content = delta.get("content")
            if isinstance(content, str) and content:
                self._parts.setdefault(index, []).append(content)
                self.completion_chars += len(content)
                if index == 0:
                    self._total += len(content)
                    new_text += content

            calls = delta.get("tool_calls")
            raw_calls = list(calls) if isinstance(calls, list) else []
            if isinstance(delta.get("function_call"), dict):
                raw_calls.append({"index": 0, "function": delta["function_call"]})
            for call in raw_calls:
                if not isinstance(call, dict):
                    continue
                self._hold_all = True
                position = call.get("index", 0)
                if not isinstance(position, int):
                    position = 0
                state = self._tool_calls.setdefault(
                    (index, position), {"name": "", "arguments": ""}
                )
                fn = call.get("function")
                if isinstance(fn, dict):
                    if isinstance(fn.get("name"), str) and fn["name"]:
                        state["name"] = fn["name"]
                    if isinstance(fn.get("arguments"), str):
                        state["arguments"] += fn["arguments"]
        return new_text

    def _release_ready(self) -> list[str]:
        limit = self._scanned - self._holdback
        out: list[str] = []
        while self._pending and self._pending[0][1] <= limit:
            out.append(self._pending.popleft()[0])
        return out

    def _release_all(self) -> list[str]:
        out = [payload for payload, _ in self._pending]
        self._pending.clear()
        return out

    def _finish(self, *, with_done: bool) -> list[str]:
        texts = {index: "".join(parts) for index, parts in self._parts.items()}
        verdict = self._inspect(stream_output_input(texts, self.tool_calls()))
        if verdict.action == "block" and self._enforce:
            return self._block(verdict)
        self.verdict = verdict
        self.finished = True
        out = self._release_all()
        if with_done:
            out.append(DONE)
        return out

    def _block(self, verdict: Verdict) -> list[str]:
        self.verdict = verdict
        self.blocked = True
        self.finished = True
        self._pending.clear()
        notice = (
            "\n\n[PromptWarden] Response withheld: outbound content matched "
            f"blocking policy (request_id {self._request_id})."
        )
        chunk: dict = {
            "id": self._meta.get("id", f"chatcmpl-{self._request_id}"),
            "object": "chat.completion.chunk",
            "created": self._meta.get("created", 0),
            "model": self._meta.get("model", ""),
            "choices": [
                {"index": 0, "delta": {"content": notice}, "finish_reason": "content_filter"}
            ],
            "promptwarden": {"action": "block", "request_id": self._request_id},
        }
        if self._expose:
            chunk["promptwarden"]["detections"] = [
                {
                    "rule_id": d.rule_id,
                    "description": d.description,
                    "severity": d.severity,
                    "owasp_llm_top10": d.owasp_llm,
                    "mitre_atlas": d.atlas,
                }
                for d in verdict.detections
            ]
        return [json.dumps(chunk, ensure_ascii=False), DONE]
