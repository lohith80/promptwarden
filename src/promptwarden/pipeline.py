"""Detection pipeline: run enabled detectors, aggregate into a verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .config import Policy
from .detectors import canary, denylist, heuristics, secrets
from .detectors.base import Detection, Direction

Action = Literal["allow", "flag", "block"]


@dataclass
class Verdict:
    action: Action
    score: int  # max severity across detections (0 when clean)
    detections: list[Detection] = field(default_factory=list)


class Pipeline:
    def __init__(self, policy: Policy):
        self.policy = policy
        self._deny_rules = (
            denylist.compile_rules(policy.detectors.denylist.patterns)
            if policy.detectors.denylist.enabled
            else []
        )

    def run(self, text: str, direction: Direction) -> Verdict:
        detections: list[Detection] = []
        cfg = self.policy.detectors

        if cfg.heuristics.enabled:
            detections.extend(heuristics.scan(text, direction))
        if cfg.secrets.enabled:
            detections.extend(secrets.scan(text, direction))
        if cfg.canary.enabled and cfg.canary.tokens:
            detections.extend(canary.scan(text, direction, cfg.canary.tokens))
        if self._deny_rules:
            detections.extend(denylist.scan(text, direction, self._deny_rules))

        score = max((d.severity for d in detections), default=0)
        gw = self.policy.gateway
        if score >= gw.block_at:
            action: Action = "block"
        elif score >= gw.flag_at:
            action = "flag"
        else:
            action = "allow"
        return Verdict(action=action, score=score, detections=detections)
