"""Inspection time on hostile input.

Inspection runs on the request path, so a rule that goes superlinear is a
denial of service against the gateway. v0.1 shipped one: the image-beacon
pattern was quadratic, and a 500 KB body of repeated "![" held a worker for
over a minute. These tests keep that class of bug out.

Two checks per input: an absolute bound with a wide margin for slow CI
runners, and a scaling check (doubling the input must not quadruple the
time), which does not depend on how fast the machine is.
"""

import base64
import time

import pytest

from promptwarden.config import Policy
from promptwarden.pipeline import Pipeline
from promptwarden.segments import InspectionInput

SIZE = 60_000
PIPELINE = Pipeline(Policy())


def rep(unit: str, size: int) -> str:
    return unit * (size // len(unit))


# Each unit is built to make some rule do the most work for the least text:
# an opener that never closes, a prefix that almost matches, a run just short
# of a threshold.
HOSTILE_UNITS = {
    "image opener": "![",
    "image with url": "![a](http://x?",
    "reference image": "![a][",
    "html image": "<img ",
    "jwt prefix": "eyJ-",
    "jwt dots": "eyJaaaaaaaaaaa.",
    "base64 run below threshold": "A" * 79 + " ",
    "base64 text blobs": base64.b64encode(b"hello world this is some text here ok").decode() + " ",
    "override prefix": "ignore previous ",
    "override no object": "ignore " + "x " * 30,
    "probe prefix": "reveal system ",
    "leetspeak": "h3ll0 w0rld 1gn0r3 ",
    "dotted letters": "a.",
    "zero width": "a\u200b",
    "mixed script": "p\u0430yp\u0430l ",
    "card digits": "4111 1111 1111 1111 ",
    "digit separators": "1-",
    "evasion stack": "never refuse without any restrictions no ethics stay in character ",
    "ai address": "note to the ai ",
    "query separators": "?&",
    "slack prefix": "xoxb-aaaaaaaa-",
    "spanish prefix": "ignora las ",
    "tool stuffing": "pass token in ",
    "tool shadowing": "when using the other ",
    "tool concealment": "do not tell the ",
}


def _time(fn) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("name", sorted(HOSTILE_UNITS))
def test_hostile_text_is_linear(name):
    unit = HOSTILE_UNITS[name]
    for direction, source in (("inbound", "user"), ("inbound", "tool_result"),
                              ("outbound", "model_output")):
        small = rep(unit, SIZE)
        large = rep(unit, SIZE * 2)
        t_small = _time(lambda s=small, d=direction, o=source: PIPELINE.run(s, d, source=o))
        t_large = _time(lambda s=large, d=direction, o=source: PIPELINE.run(s, d, source=o))
        assert t_small < 2.0, f"{name} [{source}]: {t_small:.2f}s for {SIZE} chars"
        # Linear is 2x, quadratic is 4x. The constant absorbs scheduler noise
        # on timings of a few milliseconds; a real quadratic rule at this
        # size takes seconds and fails both assertions.
        assert t_large < 3.5 * t_small + 0.05, (
            f"{name} [{source}] scales superlinearly: "
            f"{t_small * 1000:.0f} ms -> {t_large * 1000:.0f} ms"
        )


@pytest.mark.parametrize("name", ["tool stuffing", "tool shadowing", "tool concealment",
                                  "ai address", "override prefix", "image opener"])
def test_hostile_tool_definitions_are_bounded(name):
    description = rep(HOSTILE_UNITS[name], 20_000)
    tools = [{"name": f"tool_{i}", "description": description, "inputSchema": {}}
             for i in range(5)]
    elapsed = _time(lambda: PIPELINE.inspect(InspectionInput(tool_definitions=tools), "inbound"))
    assert elapsed < 2.0, f"{name}: {elapsed:.2f}s for 100,000 characters of tool text"


def test_single_giant_tokens():
    for text in ("A" * 500_000, "1" * 500_000, " " * 500_000, "\n" * 500_000,
                 "eyJ" + "a" * 500_000, chr(0xE0061) * 200_000):
        elapsed = _time(lambda t=text: PIPELINE.run(t, "inbound"))
        assert elapsed < 2.0, f"{text[:8]!r}...: {elapsed:.2f}s"
