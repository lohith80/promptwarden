import json
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from promptwarden.app import create_app
from promptwarden.config import Policy, Settings
from promptwarden.pipeline import Pipeline

CORPUS_DIR = Path(__file__).parent / "corpus"


def load_corpus(name: str):
    return yaml.safe_load((CORPUS_DIR / name).read_text(encoding="utf-8"))["samples"]


@pytest.fixture
def pipeline() -> Pipeline:
    return Pipeline(Policy())


def completion(text: str, **message_extra) -> dict:
    message = {"role": "assistant", "content": text, **message_extra}
    return {
        "id": "cmpl-1",
        "model": "gpt-test",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 9, "total_tokens": 16},
    }


def sse(chunks: list[dict], done: bool = True) -> bytes:
    lines = [f"data: {json.dumps(chunk)}\n\n" for chunk in chunks]
    if done:
        lines.append("data: [DONE]\n\n")
    return "".join(lines).encode("utf-8")


def text_chunks(text: str, size: int = 4) -> list[dict]:
    base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "m"}
    chunks = [{**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}]
    for i in range(0, len(text), size):
        chunks.append({**base, "choices": [{"index": 0, "delta": {"content": text[i:i + size]}}]})
    chunks.append({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    return chunks


def stream_text(body: str) -> str:
    """Reassemble the assistant text a client would see from an SSE body."""
    out = []
    for line in body.splitlines():
        if line.startswith("data: ") and line != "data: [DONE]":
            for choice in json.loads(line[6:]).get("choices", []):
                out.append(choice.get("delta", {}).get("content") or "")
    return "".join(out)


class ListSink:
    name = "list"

    def __init__(self):
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


class Harness:
    """A gateway wired to a scripted upstream, with events captured."""

    def __init__(self, tmp_path: Path, policy: dict | None = None, upstream=None, **settings):
        self.requests: list[httpx.Request] = []
        self.upstream = upstream or (lambda request: httpx.Response(200, json=completion("ok")))
        self.policy_path = tmp_path / "policy.yaml"
        if policy is not None:
            self.policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return self.upstream(request)

        self.app = create_app(
            Settings(policy_path=str(self.policy_path), stdout_events=False, event_async=False,
                     upstream_base_url="http://upstream.test", **settings),
            transport=httpx.MockTransport(handler),
        )
        self.gateway = self.app.state.gateway
        self.sink = ListSink()
        self.gateway.emitter.sinks.append(self.sink)
        self.client = TestClient(self.app)

    @property
    def events(self) -> list[dict]:
        return self.sink.events

    def findings(self) -> list[dict]:
        return [f for e in self.events if e["class_uid"] == 2004 for f in e["finding_info"]]

    def rule_ids(self) -> set[str]:
        return {f["rule_id"] for f in self.findings()}

    def last_upstream_json(self) -> dict:
        return json.loads(self.requests[-1].content)

    def chat(self, content="hello", headers=None, **body):
        payload = {"model": "gpt-test", "messages": [{"role": "user", "content": content}], **body}
        return self.client.post("/v1/chat/completions", json=payload, headers=headers or {})


@pytest.fixture
def harness(tmp_path):
    def make(policy: dict | None = None, upstream=None, **settings) -> Harness:
        return Harness(tmp_path, policy, upstream, **settings)

    return make
