"""Detection pipeline: run detectors over segments, aggregate into a verdict."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from .config import EffectiveConfig, Policy
from .detectors import canary, denylist, exfil, heuristics, secrets, tools
from .detectors.base import INDIRECT_SOURCES, Detection, Direction
from .segments import InspectionInput, Segment

logger = logging.getLogger("promptwarden.pipeline")

Action = Literal["allow", "flag", "block"]

MAX_DETECTIONS = 100


@dataclass
class Verdict:
    action: Action
    score: int  # max severity across detections (0 when clean)
    detections: list[Detection] = field(default_factory=list)
    # True when the gateway is in monitor mode and this traffic would have
    # been blocked under enforce.
    would_block: bool = False
    mode: str = "enforce"
    # True when the inspection engine failed and on_error decided the action.
    error: bool = False

    @property
    def disposition(self) -> str:
        if self.action == "block":
            return "blocked"
        if self.would_block:
            return "would_block"
        if any(d.disposition == "redacted" for d in self.detections):
            return "redacted"
        return "flagged" if self.action == "flag" else "allowed"


class Pipeline:
    def __init__(self, policy: Policy, registry: tools.ToolRegistry | None = None):
        self.policy = policy
        self.registry = registry if registry is not None else tools.ToolRegistry()
        self._default = policy.effective()
        self._deny_rules = (
            denylist.compile_rules(policy.detectors.denylist.patterns)
            if policy.detectors.denylist.enabled
            else []
        )

    # -- public API ---------------------------------------------------------

    def run(
        self,
        text: str,
        direction: Direction,
        source: str | None = None,
        effective: EffectiveConfig | None = None,
    ) -> Verdict:
        """Inspect a single piece of text. Convenience wrapper over inspect()."""
        if source is None:
            source = "user" if direction == "inbound" else "model_output"
        return self.inspect(InspectionInput(segments=[Segment(text, source)]), direction, effective)

    def inspect(
        self,
        payload: InspectionInput,
        direction: Direction,
        effective: EffectiveConfig | None = None,
    ) -> Verdict:
        eff = effective or self._default
        try:
            detections = self._detect(payload, direction, eff)
        except Exception:  # the engine must never take the traffic path down
            logger.exception("inspection engine error")
            return self._error_verdict(eff)
        return self._decide(detections, eff)

    # -- internals ----------------------------------------------------------

    def _detect(
        self, payload: InspectionInput, direction: Direction, eff: EffectiveConfig
    ) -> list[Detection]:
        detections: list[Detection] = []
        cfg = self.policy.detectors
        # Monitor mode observes; it never changes traffic. A secret that would
        # be redacted under enforce is reported as would_block instead.
        redact = (
            direction == "inbound"
            and eff.mode == "enforce"
            and cfg.secrets.enabled
            and cfg.secrets.inbound_action == "redact"
        )

        for segment in payload.segments:
            found: list[Detection] = []
            if redact and segment.setter is not None:
                rewritten, redacted = secrets.redact(segment.text)
                if redacted:
                    segment.setter(rewritten)
                    segment.text = rewritten
                    found.extend(redacted)
            found.extend(self._scan_segment(segment, direction))
            self._annotate(found, segment)
            detections.extend(found)
            if len(detections) >= MAX_DETECTIONS:
                break

        if direction == "inbound" and payload.tool_definitions:
            detections.extend(
                tools.scan_definitions(payload.tool_definitions, eff.tools, eff.app_id,
                                       self.registry)
            )
        if direction == "outbound" and payload.tool_calls:
            detections.extend(tools.scan_calls(payload.tool_calls, eff.tools))
        return detections[:MAX_DETECTIONS]

    def _scan_segment(self, segment: Segment, direction: Direction) -> list[Detection]:
        cfg = self.policy.detectors
        text = segment.text
        # Operator-authored text is not scanned for injection phrasing, and
        # tool-call arguments are structured data, not prose.
        prose = segment.source not in {"system", "tool_call"}
        found: list[Detection] = []
        if cfg.heuristics.enabled and prose:
            found.extend(heuristics.scan(text, direction, segment.source))
        if cfg.exfil.enabled and prose:
            found.extend(exfil.scan(text, direction, cfg.exfil))
        if cfg.secrets.enabled:
            found.extend(secrets.scan(text, direction))
        if cfg.canary.enabled and cfg.canary.tokens:
            found.extend(canary.scan(text, direction, cfg.canary.tokens))
        if self._deny_rules:
            found.extend(denylist.scan(text, direction, self._deny_rules))
        return found

    @staticmethod
    def _annotate(found: list[Detection], segment: Segment) -> None:
        for detection in found:
            detection.source = segment.source
            detection.index = segment.index
            detection.tool_name = segment.tool_name
            if segment.source in INDIRECT_SOURCES and detection.atlas == "AML.T0051":
                detection.atlas = "AML.T0051.001"
                detection.owasp_agentic = detection.owasp_agentic or "ASI01"
                if "indirect" not in detection.tags:
                    detection.tags.append("indirect")
            if segment.source == "tool_call" and detection.detector in {"secrets", "canary"}:
                # Data leaving through a tool invocation rather than chat text.
                detection.atlas = "AML.T0086"
                detection.owasp_agentic = "ASI02"
                detection.tags.append("via_tool_call")

    def _decide(self, detections: list[Detection], eff: EffectiveConfig) -> Verdict:
        score = max((d.severity for d in detections), default=0)
        # A redacted secret has been dealt with: it is worth an event but must
        # not block the request it was just removed from.
        blocking = max(
            (d.severity for d in detections if d.disposition != "redacted"), default=0
        )
        would_block = False
        if blocking >= eff.block_at:
            if eff.mode == "monitor":
                action: Action = "flag"
                would_block = True
            else:
                action = "block"
        elif score >= eff.flag_at:
            action = "flag"
        else:
            action = "allow"
        return Verdict(
            action=action, score=score, detections=detections, would_block=would_block,
            mode=eff.mode,
        )

    def _error_verdict(self, eff: EffectiveConfig) -> Verdict:
        detection = Detection(
            detector="gateway",
            rule_id="PW-G900",
            severity=10,
            confidence=1.0,
            description="Inspection engine error; action decided by gateway.on_error",
        )
        fail_closed = self.policy.gateway.on_error == "fail_closed"
        if fail_closed and eff.mode == "enforce":
            return Verdict("block", 10, [detection], mode=eff.mode, error=True)
        return Verdict("flag", 10, [detection], would_block=fail_closed, mode=eff.mode, error=True)
