"""Operator-defined denylist patterns, loaded from policy YAML.

Lets a security team ship org-specific rules (classification markers,
project codenames, internal hostnames) without touching code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Detection, Direction


@dataclass(frozen=True)
class DenyRule:
    rule_id: str
    pattern: re.Pattern
    severity: int
    description: str
    directions: tuple[str, ...] = ("inbound", "outbound")


def compile_rules(raw_rules: list) -> list[DenyRule]:
    """Compile rules from policy. Accepts DenyRuleConfig models or plain dicts."""
    rules = []
    for raw in raw_rules:
        data = raw if isinstance(raw, dict) else raw.model_dump()
        rules.append(
            DenyRule(
                rule_id=str(data["id"]),
                pattern=re.compile(data["pattern"]),
                severity=int(data.get("severity", 6)),
                description=str(data.get("description", "Denylist pattern match")),
                directions=tuple(data.get("directions") or ("inbound", "outbound")),
            )
        )
    return rules


def scan(text: str, direction: Direction, rules: list[DenyRule]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in rules:
        if direction not in rule.directions:
            continue
        match = rule.pattern.search(text)
        if match:
            detections.append(
                Detection(
                    detector="denylist",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=0.9,
                    description=rule.description,
                    evidence=match.group(0),
                    owasp_llm="LLM02",
                    atlas=None,
                )
            )
    return detections
