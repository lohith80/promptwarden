"""Findings raised by the gateway itself rather than by content inspection."""

from __future__ import annotations

from .detectors.base import Detection


def rate_limited(app_id: str, requests_per_minute: int) -> Detection:
    return Detection(
        detector="gateway",
        rule_id="PW-G001",
        severity=5,
        confidence=1.0,
        description=f"Rate limit exceeded for app '{app_id}' ({requests_per_minute}/min)",
        owasp_llm="LLM10",
        atlas="AML.T0034",
    )


def auth_failed(reason: str) -> Detection:
    return Detection(
        detector="gateway",
        rule_id="PW-G002",
        severity=5,
        confidence=1.0,
        description=f"Gateway authentication failed: {reason}",
    )


def model_denied(model: str) -> Detection:
    return Detection(
        detector="gateway",
        rule_id="PW-G003",
        severity=6,
        confidence=1.0,
        description="Requested model is not on the app's model allowlist",
        evidence=model,
        owasp_llm="LLM10",
    )


def uninspectable(reason: str) -> Detection:
    return Detection(
        detector="gateway",
        rule_id="PW-G004",
        severity=6,
        confidence=1.0,
        description=f"Request refused because its content cannot be inspected: {reason}",
    )
