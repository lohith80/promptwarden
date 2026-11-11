"""Secret and PII egress detection.

Aimed primarily at outbound (model response) traffic, but applied in both
directions: a secret inside a prompt is still a secret leaving the app
boundary toward a third-party API. Evidence is always masked.

Two entry points:

- scan()   report what is present (one detection per rule).
- redact() replace every strong match with [REDACTED:<rule>] and report what
           was removed. Used when policy sets secrets.inbound_action: redact.

Known limitations (documented, not hidden): SSN matching is format-based
(###-##-####) and US-centric; entropy scoring is a weak signal, so it is
capped at flag-level severity and never used for redaction.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .base import Detection, Direction, mask


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    pattern: re.Pattern
    severity: int
    description: str


SECRET_RULES: list[SecretRule] = [
    SecretRule(
        rule_id="PW-S001",
        pattern=re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        severity=9,
        description="AWS access key ID",
    ),
    SecretRule(
        rule_id="PW-S002",
        pattern=re.compile(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"
        ),
        severity=10,
        description="Private key material",
    ),
    SecretRule(
        rule_id="PW-S003",
        pattern=re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        severity=9,
        description="API secret key (sk- prefix)",
    ),
    SecretRule(
        rule_id="PW-S004",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"
        ),
        severity=7,
        description="JSON Web Token",
    ),
    SecretRule(
        rule_id="PW-S005",
        # Area 000/666/9xx, group 00 and serial 0000 are never issued.
        pattern=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        severity=8,
        description="US Social Security Number (formatted)",
    ),
    SecretRule(
        rule_id="PW-S008",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"
        ),
        severity=9,
        description="GitHub access token",
    ),
    SecretRule(
        rule_id="PW-S009",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9]{8,}-[A-Za-z0-9-]{8,}\b"),
        severity=9,
        description="Slack token",
    ),
    SecretRule(
        rule_id="PW-S010",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity=8,
        description="Google API key",
    ),
    SecretRule(
        rule_id="PW-S011",
        pattern=re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"),
        severity=9,
        description="Stripe live secret key",
    ),
    SecretRule(
        rule_id="PW-S012",
        pattern=re.compile(r"\bAccountKey=[A-Za-z0-9+/]{60,}={0,2}"),
        severity=9,
        description="Azure storage account key",
    ),
]

_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+/_=-]{28,}\b")
_MAX_ENTROPY_TOKEN = 72


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _shannon_entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _card_spans(text: str) -> list[tuple[int, int, str]]:
    spans = []
    for candidate in _CARD_CANDIDATE.finditer(text):
        raw = candidate.group(0).rstrip(" -")
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            spans.append((candidate.start(), candidate.start() + len(raw), digits))
    return spans


def _detection(rule_id: str, severity: int, description: str, evidence: str,
               confidence: float = 0.9) -> Detection:
    return Detection(
        detector="secrets",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        owasp_llm="LLM02",
        atlas="AML.T0057",
    )


def scan(text: str, direction: Direction) -> list[Detection]:
    detections: list[Detection] = []

    for rule in SECRET_RULES:
        match = rule.pattern.search(text)
        if match:
            detections.append(
                _detection(rule.rule_id, rule.severity, rule.description, mask(match.group(0)))
            )

    cards = _card_spans(text)
    if cards:
        detections.append(
            _detection("PW-S006", 9, "Payment card number (Luhn-valid)", mask(cards[0][2]), 0.85)
        )

    for token_match in _ENTROPY_TOKEN.finditer(text):
        token = token_match.group(0)
        has_alpha = any(c.isalpha() for c in token)
        has_digit = any(c.isdigit() for c in token)
        # Credentials are short. A very long high-entropy run is encoded
        # data (an image, an archive), not a key.
        if len(token) > _MAX_ENTROPY_TOKEN:
            continue
        if has_alpha and has_digit and _shannon_entropy(token) >= 4.2:
            detections.append(
                _detection(
                    "PW-S007", 5, "High-entropy token (possible credential)", mask(token), 0.5
                )
            )
            break

    return detections


def redact(text: str) -> tuple[str, list[Detection]]:
    """Replace every strong secret match with a placeholder.

    Returns the rewritten text and one detection per rule that matched, with
    disposition "redacted". The entropy rule is deliberately excluded: it is
    too weak a signal to justify rewriting a prompt.
    """
    spans: list[tuple[int, int, str, int, str, str]] = []
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            spans.append(
                (match.start(), match.end(), rule.rule_id, rule.severity, rule.description,
                 mask(match.group(0)))
            )
    for start, end, digits in _card_spans(text):
        spans.append(
            (start, end, "PW-S006", 9, "Payment card number (Luhn-valid)", mask(digits))
        )
    if not spans:
        return text, []

    spans.sort(key=lambda span: (span[0], -span[1]))
    out: list[str] = []
    detections: dict[str, Detection] = {}
    cursor = 0
    for start, end, rule_id, severity, description, evidence in spans:
        if start < cursor:
            continue  # overlaps a span already redacted
        out.append(text[cursor:start])
        out.append(f"[REDACTED:{rule_id}]")
        cursor = end
        if rule_id not in detections:
            detection = _detection(rule_id, severity, description, evidence)
            detection.disposition = "redacted"
            detections[rule_id] = detection
    out.append(text[cursor:])
    return "".join(out), list(detections.values())
