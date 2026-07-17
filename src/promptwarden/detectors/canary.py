"""Canary-token leak detection.

Operators plant canary tokens inside system prompts (see generate_canary and
the policy `detectors.canary.tokens` list). A canary appearing in outbound
model text is deterministic evidence of system prompt leakage: severity 10,
confidence 1.0 — no heuristics involved.
"""

from __future__ import annotations

import secrets as _secrets

from .base import Detection, Direction, mask

CANARY_PREFIX = "pw-canary-"


def generate_canary() -> str:
    """Generate a canary token to embed in a system prompt."""
    return CANARY_PREFIX + _secrets.token_hex(8)


def scan(text: str, direction: Direction, tokens: list[str]) -> list[Detection]:
    if direction != "outbound":
        return []
    detections: list[Detection] = []
    for token in tokens:
        if token and token in text:
            detections.append(
                Detection(
                    detector="canary",
                    rule_id="PW-C001",
                    severity=10,
                    confidence=1.0,
                    description="Canary token from the system prompt found in model output",
                    evidence=mask(token, keep=len(CANARY_PREFIX) + 2),
                    owasp_llm="LLM07",
                    atlas="AML.T0057",
                )
            )
    return detections
