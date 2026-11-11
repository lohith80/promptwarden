"""Prometheus metrics.

Each gateway instance owns its registry (no process-global state), which keeps
tests isolated and lets several apps live in one process. Label cardinality is
bounded by design: app IDs come from policy, rule IDs from the rule catalog.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_INSPECT_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0)
_UPSTREAM_BUCKETS = (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "promptwarden_requests_total",
            "Requests handled, by app, endpoint and outcome.",
            ["app", "endpoint", "outcome"],
            registry=self.registry,
        )
        self.detections = Counter(
            "promptwarden_detections_total",
            "Detections, by rule, direction and disposition.",
            ["rule_id", "direction", "disposition"],
            registry=self.registry,
        )
        self.inspection_seconds = Histogram(
            "promptwarden_inspection_seconds",
            "Time spent in the detection pipeline.",
            ["direction"],
            buckets=_INSPECT_BUCKETS,
            registry=self.registry,
        )
        self.upstream_seconds = Histogram(
            "promptwarden_upstream_seconds",
            "Upstream LLM API latency (time to full response or end of stream).",
            buckets=_UPSTREAM_BUCKETS,
            registry=self.registry,
        )
        self.tokens = Counter(
            "promptwarden_tokens_total",
            "Tokens reported by the upstream API, by app and type.",
            ["app", "type"],
            registry=self.registry,
        )
        self.events_emitted = Counter(
            "promptwarden_events_emitted_total",
            "Security events delivered to sinks.",
            registry=self.registry,
        )
        self.events_dropped = Counter(
            "promptwarden_events_dropped_total",
            "Security events dropped because the event queue was full.",
            registry=self.registry,
        )
        self.uninspected_parts = Counter(
            "promptwarden_uninspected_parts_total",
            "Non-text content parts (images, audio, files) passed without inspection.",
            ["app"],
            registry=self.registry,
        )
        self.policy_reloads = Counter(
            "promptwarden_policy_reloads_total",
            "Policy reload attempts, by result.",
            ["result"],
            registry=self.registry,
        )
        self.policy_info = Gauge(
            "promptwarden_policy_info",
            "Currently loaded policy (value is always 1).",
            ["hash", "mode"],
            registry=self.registry,
        )

    def set_policy(self, policy_hash: str, mode: str) -> None:
        self.policy_info.clear()
        self.policy_info.labels(hash=policy_hash, mode=mode).set(1)

    def render(self) -> bytes:
        return generate_latest(self.registry)
