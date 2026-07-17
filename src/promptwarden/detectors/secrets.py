"""Secret and PII egress detection.

Aimed primarily at outbound (model response) traffic, but applied in both
directions: a secret inside a prompt is still a secret leaving the app
boundary toward a third-party API. Evidence is always masked.

Known limitations (documented, not hidden): SSN matching is format-based
(###-##-####) and US-centric; entropy scoring is a weak signal and therefore
capped at flag-level severity.
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
        pattern=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
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
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        severity=8,
        description="US Social Security Number (formatted)",
    ),
]

_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+/_=-]{28,}\b")


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


def scan(text: str, direction: Direction) -> list[Detection]:
    detections: list[Detection] = []

    for rule in SECRET_RULES:
        match = rule.pattern.search(text)
        if match:
            detections.append(
                Detection(
                    detector="secrets",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=0.9,
                    description=rule.description,
                    evidence=mask(match.group(0)),
                    owasp_llm="LLM02",
                    atlas="AML.T0057",
                )
            )

    for candidate in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", candidate.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            detections.append(
                Detection(
                    detector="secrets",
                    rule_id="PW-S006",
                    severity=9,
                    confidence=0.85,
                    description="Payment card number (Luhn-valid)",
                    evidence=mask(digits),
                    owasp_llm="LLM02",
                    atlas="AML.T0057",
                )
            )
            break

    for token_match in _ENTROPY_TOKEN.finditer(text):
        token = token_match.group(0)
        has_alpha = any(c.isalpha() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if has_alpha and has_digit and _shannon_entropy(token) >= 4.2:
            detections.append(
                Detection(
                    detector="secrets",
                    rule_id="PW-S007",
                    severity=5,
                    confidence=0.5,
                    description="High-entropy token (possible credential)",
                    evidence=mask(token),
                    owasp_llm="LLM02",
                    atlas="AML.T0057",
                )
            )
            break

    return detections
