from promptwarden.events import EventThrottle
from promptwarden.ratelimit import RateLimiter


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_unlimited_when_zero():
    limiter = RateLimiter()
    assert all(limiter.check("a", 0)[0] for _ in range(1000))


def test_bucket_drains_and_refills():
    clock = Clock()
    limiter = RateLimiter(clock)
    assert [limiter.check("a", 60, burst=3)[0] for _ in range(4)] == [True, True, True, False]
    allowed, retry_after = limiter.check("a", 60, burst=3)
    assert not allowed and 0 < retry_after <= 1.0
    clock.now += 1.0  # 60/min = one token per second
    assert limiter.check("a", 60, burst=3)[0]
    assert not limiter.check("a", 60, burst=3)[0]


def test_keys_are_independent():
    limiter = RateLimiter(Clock())
    assert limiter.check("a", 60, burst=1)[0] and not limiter.check("a", 60, burst=1)[0]
    assert limiter.check("b", 60, burst=1)[0]


def test_gateway_returns_429_with_retry_after(harness):
    h = harness(policy={"limits": {"requests_per_minute": 2}})
    assert [h.chat("hi").status_code for _ in range(4)] == [200, 200, 429, 429]
    resp = h.chat("hi")
    assert resp.json()["error"]["type"] == "promptwarden_rate_limited"
    assert int(resp.headers["retry-after"]) >= 1
    assert len(h.requests) == 2
    # Three rejections, one event: the gateway must not flood the SIEM.
    rate_events = [e for e in h.events if e["finding_info"][0]["rule_id"] == "PW-G001"]
    assert len(rate_events) == 1
    assert rate_events[0]["finding_info"][0]["mitre_atlas"] == "AML.T0034"


def test_per_app_limits(harness, monkeypatch):
    from promptwarden import auth

    key = "pw_" + "k" * 43
    h = harness(policy={
        "limits": {"requests_per_minute": 1000},
        "apps": [{"id": "batch", "key_hashes": [auth.hash_key(key)],
                  "limits": {"requests_per_minute": 1}}],
    })
    headers = {"X-PromptWarden-Key": key, "Authorization": "Bearer sk-x"}
    assert h.chat("hi", headers=headers).status_code == 200
    assert h.chat("hi", headers=headers).status_code == 429
    assert h.chat("hi").status_code == 200, "other apps are unaffected"


def test_event_throttle_reports_suppressed_count():
    clock = Clock()
    throttle = EventThrottle(interval_seconds=10, clock=clock)
    assert throttle.allow("k") == (True, 0)
    assert throttle.allow("k") == (False, 0)
    assert throttle.allow("k") == (False, 0)
    assert throttle.allow("other") == (True, 0)
    clock.now += 11
    assert throttle.allow("k") == (True, 2)
