"""Heuristic prompt-injection and jailbreak detection.

Pattern rules are intentionally conservative: each requires a trigger verb or
phrase plus contextual anchors within a bounded window, which keeps the false
positive rate near zero on benign traffic (see tests/corpus/benign.yaml).
Functional rules cover payloads regexes handle poorly (encoding smuggling,
invisible-Unicode instruction hiding).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Detection, Direction


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    pattern: re.Pattern
    severity: int
    description: str
    owasp_llm: str
    atlas: str
    directions: tuple[Direction, ...] = ("inbound", "outbound")


PATTERN_RULES: list[PatternRule] = [
    PatternRule(
        rule_id="PW-H001",
        pattern=re.compile(
            r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(previous|prior|above|earlier|system)\b[^.\n]{0,40}"
            r"\b(instructions?|prompts?|rules?|directives?)\b"
        ),
        severity=8,
        description="Instruction override attempt (ignore/disregard prior instructions)",
        owasp_llm="LLM01",
        atlas="AML.T0051",
    ),
    PatternRule(
        rule_id="PW-H002",
        pattern=re.compile(
            r"(?i)\b(reveal|show|print|repeat|output|display|leak)\b[^.\n]{0,60}"
            r"\b(system|initial|hidden|original)\b[^.\n]{0,20}"
            r"\b(prompt|instructions?|message)\b"
        ),
        severity=8,
        description="System prompt exfiltration probe",
        owasp_llm="LLM07",
        atlas="AML.T0051",
    ),
    PatternRule(
        rule_id="PW-H003",
        pattern=re.compile(
            r"(?i)(\bact\s+as\s+(if\s+you\s+are\s+)?an?\s+(unrestricted|unfiltered|jailbroken)\b"
            r"|\bpretend\s+(you\s+are|to\s+be)\b[^.\n]{0,40}\bwithout\s+(any\s+)?"
            r"(rules|restrictions|filters|guidelines)\b"
            r"|\byou\s+are\s+now\s+(free\s+of|no\s+longer\s+bound|dan\b|in\s+developer\s+mode))"
        ),
        severity=7,
        description="Role/persona override toward an unrestricted assistant",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H004",
        pattern=re.compile(
            r"(?i)(\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bdeveloper\s+mode\s+enabled\b"
            r"|\bjailbreak(s|ing|en)?\b)"
        ),
        severity=7,
        description="Known jailbreak vocabulary (DAN / developer mode / jailbreak)",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H007",
        pattern=re.compile(
            r"(?i)(\bnever\s+(refuse|say\s+no|apologi[sz]e)\b"
            r"|\bwithout\s+(any\s+)?(warnings?|disclaimers?|refusals?)\b)"
        ),
        severity=6,
        description="Refusal-suppression instruction",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H009",
        pattern=re.compile(r"!\[[^\]]*\]\(https?://[^\s)]*[?&][^\s)]+\)"),
        severity=8,
        description="Markdown image beacon with query parameters (data exfiltration channel)",
        owasp_llm="LLM05",
        atlas="AML.T0057",
    ),
]

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{80,}")
_DECODE_HINT = re.compile(r"(?i)\b(decode|base64|rot13|hex)\b")

# Unicode tag block (U+E0000-U+E007F) is invisible in most UIs and a known
# instruction-smuggling channel; zero-width characters serve the same purpose.
_INVISIBLE = re.compile("[\U000e0000-\U000e007f\u200b\u200c\u200d\u2060\ufeff]")


def scan(text: str, direction: Direction) -> list[Detection]:
    detections: list[Detection] = []

    for rule in PATTERN_RULES:
        if direction not in rule.directions:
            continue
        match = rule.pattern.search(text)
        if match:
            detections.append(
                Detection(
                    detector="heuristics",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=0.8,
                    description=rule.description,
                    evidence=match.group(0),
                    owasp_llm=rule.owasp_llm,
                    atlas=rule.atlas,
                )
            )

    blob = _BASE64_BLOB.search(text)
    if blob and _DECODE_HINT.search(text):
        detections.append(
            Detection(
                detector="heuristics",
                rule_id="PW-H005",
                severity=7,
                confidence=0.7,
                description="Encoded payload with a decode instruction (encoding smuggling)",
                evidence=blob.group(0),
                owasp_llm="LLM01",
                atlas="AML.T0051",
            )
        )

    invisible = _INVISIBLE.findall(text)
    if len(invisible) >= 5:
        detections.append(
            Detection(
                detector="heuristics",
                rule_id="PW-H006",
                severity=9,
                confidence=0.9,
                description=(
                    f"{len(invisible)} invisible Unicode characters "
                    "(tag block / zero-width): hidden-instruction channel"
                ),
                evidence="",
                owasp_llm="LLM01",
                atlas="AML.T0051",
            )
        )

    return detections
