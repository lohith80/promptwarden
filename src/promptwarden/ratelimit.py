"""Per-app token-bucket rate limiting.

Guards against unbounded consumption (OWASP LLM10) and cost harvesting
(MITRE ATLAS AML.T0034): a runaway agent loop or a stolen gateway key should
hit a ceiling at the gateway, not on the provider invoice.

State is in-process. With N replicas the effective limit is N times the
configured value; a shared store is on the roadmap. Keys are app IDs from
policy, so the table is bounded.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        # key -> (tokens, last_refill)
        self._buckets: dict[str, tuple[float, float]] = {}

    def check(self, key: str, requests_per_minute: int, burst: int = 0) -> tuple[bool, float]:
        """Take one token. Returns (allowed, retry_after_seconds)."""
        if requests_per_minute <= 0:
            return True, 0.0
        capacity = float(burst or requests_per_minute)
        rate = requests_per_minute / 60.0
        now = self._clock()
        tokens, last = self._buckets.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * rate)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True, 0.0
        self._buckets[key] = (tokens, now)
        return False, (1.0 - tokens) / rate
