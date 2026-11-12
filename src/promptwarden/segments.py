"""Turn API payloads into inspectable segments.

The gateway does not scan a request as one blob of text. Each piece is
extracted with its provenance (who wrote it) so the pipeline can apply the
right detectors and report exactly where a finding came from: a user turn,
a tool result, a tool definition, model output, or tool-call arguments.

Segments built from request bodies carry a setter so a detector can rewrite
the text in place (used for secret redaction).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from .detectors.tools import ToolCall

_TEXT_PART_TYPES = {"text", "input_text", "output_text"}


class Uninspectable(ValueError):
    """The payload carries content the gateway cannot read (for example
    pre-tokenized embedding input). Refused rather than passed blind."""


@dataclass
class Segment:
    text: str
    source: str
    index: int | None = None
    tool_name: str | None = None
    setter: Callable[[str], None] | None = None


@dataclass
class InspectionInput:
    segments: list[Segment] = field(default_factory=list)
    tool_definitions: list = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    # Content parts that were skipped because they are not text (images,
    # audio, files). Surfaced as a metric; see THREAT_MODEL.md.
    uninspected_parts: int = 0

    @property
    def char_count(self) -> int:
        return sum(len(segment.text) for segment in self.segments)


def _source_for_role(role: object, trusted_roles: list[str]) -> str:
    if not isinstance(role, str):
        return "user"
    if role in trusted_roles:
        return "system"
    if role == "assistant":
        return "assistant"
    if role in {"tool", "function"}:
        return "tool_result"
    return "user"


def _dict_setter(container: dict, key: str) -> Callable[[str], None]:
    def setter(value: str) -> None:
        container[key] = value

    return setter


def _list_setter(container: list, position: int) -> Callable[[str], None]:
    def setter(value: str) -> None:
        container[position] = value

    return setter


def chat_request_input(body: dict, trusted_roles: list[str]) -> InspectionInput:
    """Extract segments from an OpenAI-style chat completions request.

    Raises ValueError when the messages array is malformed.
    """
    messages = body.get("messages", [])
    if not isinstance(messages, list):
        raise ValueError("messages must be an array")
    result = InspectionInput()
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"messages[{index}] must be an object")
        source = _source_for_role(message.get("role"), trusted_roles)
        tool_name = message.get("name") if isinstance(message.get("name"), str) else None
        content = message.get("content")
        if isinstance(content, str):
            if content:
                result.segments.append(
                    Segment(content, source, index, tool_name, _dict_setter(message, "content"))
                )
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") in _TEXT_PART_TYPES and isinstance(part.get("text"), str):
                    if part["text"]:
                        result.segments.append(
                            Segment(part["text"], source, index, tool_name,
                                    _dict_setter(part, "text"))
                        )
                else:
                    result.uninspected_parts += 1

    tools = body.get("tools")
    if isinstance(tools, list):
        result.tool_definitions.extend(tools)
    functions = body.get("functions")  # legacy function-calling format
    if isinstance(functions, list):
        result.tool_definitions.extend(functions)
    return result


def _arguments_text(arguments: object) -> str:
    if isinstance(arguments, str):
        return arguments
    if arguments is None:
        return ""
    return json.dumps(arguments, ensure_ascii=False)


def chat_response_input(response_body: dict) -> InspectionInput:
    """Extract segments from an OpenAI-style chat completions response."""
    result = InspectionInput()
    choices = response_body.get("choices")
    if not isinstance(choices, list):
        return result
    for position, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        index = choice.get("index", position)
        if not isinstance(index, int):
            index = position
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content:
            result.segments.append(Segment(content, "model_output", index))
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str) and part["text"]:
                    result.segments.append(Segment(part["text"], "model_output", index))

        calls = message.get("tool_calls")
        raw_calls = list(calls) if isinstance(calls, list) else []
        if isinstance(message.get("function_call"), dict):
            raw_calls.append({"function": message["function_call"]})
        for call in raw_calls:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") if isinstance(call.get("function"), dict) else call
            name = fn.get("name") if isinstance(fn.get("name"), str) else ""
            arguments = _arguments_text(fn.get("arguments"))
            result.tool_calls.append(ToolCall(name=name, arguments=arguments, index=index))
            if arguments:
                result.segments.append(Segment(arguments, "tool_call", index, name or None))
    return result


def stream_output_input(texts: dict[int, str], tool_calls: list[ToolCall]) -> InspectionInput:
    """Build an outbound inspection input from accumulated stream state."""
    result = InspectionInput(tool_calls=list(tool_calls))
    for index in sorted(texts):
        if texts[index]:
            result.segments.append(Segment(texts[index], "model_output", index))
    for call in tool_calls:
        if call.arguments:
            result.segments.append(
                Segment(call.arguments, "tool_call", call.index, call.name or None)
            )
    return result


def embeddings_input(body: dict) -> InspectionInput:
    """Extract segments from an embeddings request.

    Text sent for embedding is treated as a document: third-party content on
    its way into a vector store. Pre-tokenized input cannot be inspected and
    is refused.
    """
    raw = body.get("input")
    result = InspectionInput()
    if isinstance(raw, str):
        if raw:
            result.segments.append(Segment(raw, "document", 0, None, _dict_setter(body, "input")))
        return result
    if isinstance(raw, list):
        for index, item in enumerate(raw):
            if isinstance(item, str):
                if item:
                    result.segments.append(
                        Segment(item, "document", index, None, _list_setter(raw, index))
                    )
            else:
                raise Uninspectable(
                    "embedding input must be text; token arrays cannot be inspected"
                )
        return result
    raise ValueError("input must be a string or an array of strings")
