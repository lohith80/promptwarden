"""Shared detection types.

Every detector returns a list of Detection objects. A Detection carries the
framework mappings (OWASP LLM Top 10 2025 + MITRE ATLAS) so downstream events
are SIEM-ready without any enrichment step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Direction = Literal["inbound", "outbound"]

MAX_EVIDENCE_LEN = 80


@dataclass
class Detection:
    detector: str
    rule_id: str
    severity: int  # 1-10, aligned with the policy block/flag thresholds
    confidence: float  # 0.0-1.0
    description: str
    evidence: str = ""
    owasp_llm: str | None = None
    atlas: str | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Evidence is stored truncated so raw prompts/secrets never land in
        # events at full length; secret detectors additionally mask values.
        if len(self.evidence) > MAX_EVIDENCE_LEN:
            self.evidence = self.evidence[:MAX_EVIDENCE_LEN] + "..."


def mask(value: str, keep: int = 4) -> str:
    """Mask a sensitive value, keeping a short identifying prefix."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 12)
