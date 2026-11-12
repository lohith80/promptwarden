"""Agent tool security: tool poisoning, definition drift, and call policy.

Tools are the part of an LLM request nobody reads. A tool's description is
text the model treats as instructions, it usually comes from a third party
(an MCP server, a plugin), and it can change after it was approved. This
module gives the gateway three controls over that surface:

PW-T001  Tool-call policy. The model asked to call a tool that policy denies
         (or that is not on the allowlist). Blocks excessive agency at the
         last point before the client executes the call.
PW-T002  Tool poisoning. A tool definition contains hidden or instruction-like
         content: injection phrasing, invisible characters, "do not tell the
         user", references to credential files, parameter-stuffing requests.
PW-T003  Pinned definition mismatch. The definition does not hash to the value
         pinned in policy. Deterministic rug-pull detection.
PW-T004  Definition drift (trust on first use). The definition changed while
         the gateway was running. Works without pins; resets on restart.
PW-T005  Unpinned tool. Policy requires every tool to be pinned and this one
         is not.

Tool definitions are accepted in OpenAI function format and in MCP tools/list
format; both canonicalize to the same hash input.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass

from ..config import ToolsConfig
from . import heuristics
from .base import Detection

_CONCEALMENT = re.compile(
    r"(?i)\b(do\s+not|don'?t|never|without)\s+(tell(ing)?|mention(ing)?|inform(ing)?|"
    r"reveal(ing)?|notify(ing)?|show(ing)?|alert(ing)?|disclos(e|ing))\b[^.\n]{0,40}"
    r"\b(user|human|operator|anyone)\b"
)
_SENSITIVE_PATH = re.compile(
    r"(?i)(~|/home/[^/\s]+|/root|%userprofile%)[/\\]\.(ssh|aws|gnupg|kube|docker|config[/\\]gcloud)\b"
    r"|\bid_(rsa|ed25519|ecdsa)\b|/etc/(passwd|shadow)\b|\bmcp\.json\b"
    r"|\b(read|open|cat|load|send|upload|include|pass)\b[^.\n]{0,40}"
    r"(\.env\b|credentials(\.json)?\b|\bapi[_ ]keys?\b|\bsecrets?\b|\bprivate\s+keys?\b)"
)
# Windows are kept short on purpose: three chained windows multiply, and tool
# text is attacker-supplied. See tests/test_performance.py.
_PARAMETER_STUFFING = re.compile(
    r"(?i)\b(pass|put|place|include|send|add|copy|provide)\b[^.\n]{0,40}"
    r"\b(conversation|chat\s+history|system\s+prompt|previous\s+messages|file\s+contents?|"
    r"credentials|secrets?|api\s+keys?|tokens?|passwords?)\b[^.\n]{0,30}"
    r"\b(as|in|into|to|via|using)\s+(the\s+|an?\s+|this\s+|its\s+)?['\"`]?[a-z_]{0,20}['\"`]?\s?"
    r"(param(eter)?s?|arguments?|fields?|sidenote|notes?|metadata)\b"
)
_MARKUP_DIRECTIVE = re.compile(r"(?i)<\s*(important|system|instructions?|secret|hidden)\s*>")
_CROSS_TOOL = re.compile(
    r"(?i)\b(when(ever)?|before|after|instead\s+of|every\s+time)\b[^.\n]{0,40}"
    r"\b(using|calling|invoking|you\s+use|you\s+call)\b[^.\n]{0,30}"
    r"\b(other|another|any|the)\s+[a-z_]{0,30}\s?tools?\b[^.\n]{0,60}"
    r"\b(must|always|also|first|instead)\b"
)

_POISON_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (_CONCEALMENT, "asks the model to hide its actions from the user", 9),
    (_PARAMETER_STUFFING, "asks for conversation data or secrets in a tool parameter", 9),
    (_MARKUP_DIRECTIVE, "directive markup aimed at the model", 8),
    (_CROSS_TOOL, "tries to change how other tools are used (tool shadowing)", 8),
    (_SENSITIVE_PATH, "references credential files or secrets", 6),
]

_MAX_TOOLS = 256
_MAX_DEFINITION_TEXT = 20_000


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: str
    index: int = 0


def canonical_tool(tool: object) -> dict | None:
    """Reduce a tool definition to {name, description, parameters}.

    Accepts OpenAI chat format ({"type": "function", "function": {...}}),
    the flat function format, and MCP format ({"name", "description",
    "inputSchema"}). Returns None for anything that is not a function tool.
    """
    if not isinstance(tool, dict):
        return None
    fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
    name = fn.get("name")
    if not isinstance(name, str) or not name:
        return None
    parameters = fn.get("parameters")
    if parameters is None:
        parameters = fn.get("inputSchema", fn.get("input_schema"))
    description = fn.get("description")
    return {
        "name": name,
        "description": description if isinstance(description, str) else "",
        "parameters": parameters if isinstance(parameters, dict) else {},
    }


def tool_hash(tool: object) -> str | None:
    """sha256 over the canonical JSON of a tool definition."""
    canonical = canonical_tool(tool)
    if canonical is None:
        return None
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _schema_strings(node: object, out: list[str], depth: int = 0) -> None:
    """Collect every human-readable string in a JSON schema: descriptions,
    titles, enum values, defaults, examples. All of it reaches the model."""
    if depth > 12 or len(out) > 500:
        return
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key in {"type", "$schema", "format", "required"}:
                continue
            if key == "properties" and isinstance(value, dict):
                out.extend(str(prop) for prop in value)
            _schema_strings(value, out, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _schema_strings(item, out, depth + 1)


def definition_text(canonical: dict) -> str:
    parts = [canonical["name"], canonical["description"]]
    _schema_strings(canonical["parameters"], parts)
    return "\n".join(part for part in parts if part)[:_MAX_DEFINITION_TEXT]


class ToolRegistry:
    """First-seen tool definition hashes per app, for drift detection.

    In-memory and bounded. It resets on restart and is per replica, which is
    why pins in policy are the durable control and this is the early warning.
    """

    def __init__(self, max_entries: int = 10_000):
        self._seen: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._max = max_entries
        self._lock = threading.Lock()  # large inspections run on worker threads

    def observe(self, app_id: str, name: str, digest: str) -> str | None:
        """Record a definition. Returns the previous hash if it changed."""
        key = (app_id, name)
        with self._lock:
            previous = self._seen.get(key)
            self._seen[key] = digest
            self._seen.move_to_end(key)
            if len(self._seen) > self._max:
                self._seen.popitem(last=False)
        if previous is not None and previous != digest:
            return previous
        return None


def _supply_chain(rule_id: str, severity: int, confidence: float, description: str,
                  name: str, evidence: str) -> Detection:
    return Detection(
        detector="tools",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        owasp_llm="LLM03",
        owasp_agentic="ASI04",
        atlas="AML.T0010",
        source="tool_definition",
        tool_name=name[:64],
    )


def _poisoning(name: str, text: str) -> Detection | None:
    reasons: list[str] = []
    tags: list[str] = []
    severity = 0
    evidence = ""

    for hit in heuristics.scan(text, "inbound", source="tool_definition"):
        reasons.append(hit.description)
        tags.append(hit.rule_id)
        severity = max(severity, hit.severity, 8)
        evidence = evidence or hit.evidence

    for pattern, reason, pattern_severity in _POISON_PATTERNS:
        match = pattern.search(text)
        if match:
            reasons.append(reason)
            severity = max(severity, pattern_severity)
            evidence = evidence or match.group(0)

    if not reasons:
        return None
    return Detection(
        detector="tools",
        rule_id="PW-T002",
        severity=severity,
        confidence=0.85,
        description=f"Tool definition '{name[:40]}' looks poisoned: {reasons[0]}",
        evidence=evidence,
        owasp_llm="LLM01",
        owasp_agentic="ASI04",
        atlas="AML.T0051.001",
        tags=tags + ["tool_poisoning"],
        source="tool_definition",
        tool_name=name[:64],
    )


def scan_definitions(
    tools: list, config: ToolsConfig, app_id: str, registry: ToolRegistry | None
) -> list[Detection]:
    detections: list[Detection] = []
    for tool in tools[:_MAX_TOOLS]:
        canonical = canonical_tool(tool)
        if canonical is None:
            continue
        name = canonical["name"]
        digest = tool_hash(tool) or ""

        pinned = config.pinned.get(name)
        # A definition that matches its pin was reviewed and approved by
        # whoever pinned it, so it is not re-scanned. That is the supported
        # way to silence a PW-T002 finding on a tool you trust.
        if config.inspect_definitions and pinned != digest:
            poisoned = _poisoning(name, definition_text(canonical))
            if poisoned:
                detections.append(poisoned)

        if pinned is not None:
            if pinned != digest:
                detections.append(
                    _supply_chain(
                        "PW-T003", 9, 1.0,
                        f"Tool definition '{name[:40]}' does not match its pinned hash",
                        name, f"expected {pinned[:12]} got {digest[:12]}",
                    )
                )
        elif config.require_pinned:
            detections.append(
                _supply_chain(
                    "PW-T005", 8, 1.0,
                    f"Tool '{name[:40]}' is not pinned and policy requires pinned tools",
                    name, f"sha256 {digest[:12]}",
                )
            )

        if config.drift_detection and registry is not None and pinned is None:
            previous = registry.observe(app_id, name, digest)
            if previous is not None:
                detections.append(
                    _supply_chain(
                        "PW-T004", 6, 0.9,
                        f"Tool definition '{name[:40]}' changed since it was first seen",
                        name, f"was {previous[:12]} now {digest[:12]}",
                    )
                )
    return detections


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def scan_calls(calls: list[ToolCall], config: ToolsConfig) -> list[Detection]:
    detections: list[Detection] = []
    for call in calls:
        denied = _matches(call.name, config.denied)
        not_allowed = bool(config.allowed) and not _matches(call.name, config.allowed)
        if denied or not_allowed:
            reason = "is denied by policy" if denied else "is not on the tool allowlist"
            detections.append(
                Detection(
                    detector="tools",
                    rule_id="PW-T001",
                    severity=9,
                    confidence=1.0,
                    description=f"Model requested tool '{call.name[:40]}', which {reason}",
                    evidence=call.name,
                    owasp_llm="LLM06",
                    owasp_agentic="ASI02",
                    atlas="AML.T0053",
                    source="tool_call",
                    index=call.index,
                    tool_name=call.name[:64],
                )
            )
    return detections
