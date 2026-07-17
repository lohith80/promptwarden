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


def compile_rules(raw_rules: list[dict]) -> list[DenyRule]:
    rules = []
    for raw in raw_rules:
        rules.append(
            DenyRule(
                rule_id=str(raw["id"]),
                pattern=re.compile(raw["pattern"]),
                severity=int(raw.get("severity", 6)),
                description=str(raw.get("description", "Denylist pattern match")),
            )
        )
    return rules


def scan(text: str, direction: Direction, rules: list[DenyRule]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in rules:
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
