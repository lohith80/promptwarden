"""Corpus benchmark: the numbers reported in the README come from here.

Read the numbers for what they are. The corpus is written by the same people
who write the rules, so it measures regression safety (nothing that used to
be caught slips, nothing benign starts firing), not real-world recall. For an
out-of-sample number see scripts/eval_public_dataset.py and the README.
"""

import statistics
import time
from pathlib import Path

import yaml

from conftest import CORPUS_DIR, load_corpus

ATTACK_SETS = ["injections.yaml", "obfuscated.yaml", "multilingual.yaml"]


def _detected(pipeline, samples, source="user"):
    return [s for s in samples if pipeline.run(s, "inbound", source=source).action != "allow"]


def test_injection_detection_rate(pipeline):
    samples = load_corpus("injections.yaml")
    detected = _detected(pipeline, samples)
    rate = len(detected) / len(samples)
    missed = [s[:60] for s in samples if s not in detected]
    assert rate >= 0.85, f"detection rate {rate:.0%}; missed: {missed}"


def test_obfuscated_detection_rate(pipeline):
    samples = load_corpus("obfuscated.yaml")
    detected = _detected(pipeline, samples)
    missed = [s[:60] for s in samples if s not in detected]
    assert len(detected) / len(samples) >= 0.85, f"missed: {missed}"


def test_multilingual_detection_rate(pipeline):
    samples = load_corpus("multilingual.yaml")
    detected = _detected(pipeline, samples)
    missed = [s[:60] for s in samples if s not in detected]
    assert len(detected) / len(samples) >= 0.85, f"missed: {missed}"


def test_benign_false_positive_rate(pipeline):
    samples = load_corpus("benign.yaml")
    false_positives = [
        (s[:60], [d.rule_id for d in v.detections])
        for s in samples
        if (v := pipeline.run(s, "inbound")).action != "allow"
    ]
    assert not false_positives, f"benign samples flagged: {false_positives}"


def test_indirect_injection_corpus(pipeline):
    """Tool results: every attack flagged or blocked, every benign one clean."""
    wrong = []
    for sample in load_corpus("indirect.yaml"):
        verdict = pipeline.run(sample["text"], "inbound", source="tool_result")
        hit = verdict.action != "allow"
        if hit != (sample["label"] == "attack"):
            wrong.append((sample["label"], sample["text"][:60],
                          [d.rule_id for d in verdict.detections]))
    assert not wrong, f"indirect corpus mismatches: {wrong}"


def test_secret_egress_detection(pipeline):
    samples = load_corpus("secrets.yaml")
    for sample in samples:
        verdict = pipeline.run(sample["text"], "outbound")
        rule_ids = {d.rule_id for d in verdict.detections}
        assert sample["expect_rule"] in rule_ids, (
            f"expected {sample['expect_rule']} on: {sample['text'][:50]}, got {rule_ids}"
        )


def _known_limits() -> dict:
    return yaml.safe_load((CORPUS_DIR / "known_limits.yaml").read_text(encoding="utf-8"))


def test_known_limits_are_still_accurate(pipeline):
    """known_limits.yaml documents what the engine gets wrong. If a sample in
    it starts being handled correctly, promote it to the gated corpus so the
    improvement is locked in and the documentation stays true."""
    limits = _known_limits()
    fixed_misses = _detected(pipeline, limits["missed_attacks"])
    fixed_fps = [s for s in limits["false_positives"]
                 if pipeline.run(s, "inbound").action == "allow"]
    assert not fixed_misses, f"now detected, move to a gated corpus: {fixed_misses}"
    assert not fixed_fps, f"no longer a false positive, move to benign.yaml: {fixed_fps}"


def test_inspection_latency_budget(pipeline):
    """Guard against an accidental quadratic rule. Generous bound: the point
    is to catch a 100x regression, not to benchmark the CI runner."""
    prompt = ("Summarize the following incident report and list action items. " * 160)[:10_000]
    timings = []
    for _ in range(30):
        started = time.perf_counter()
        pipeline.run(prompt, "inbound")
        timings.append(time.perf_counter() - started)
    assert statistics.median(timings) < 0.05, f"median {statistics.median(timings) * 1000:.1f} ms"


def test_print_benchmark_summary(pipeline, capsys):
    """Emit the benchmark table used in the README (visible with pytest -s)."""
    lines = []
    for name in ATTACK_SETS:
        samples = load_corpus(name)
        lines.append(f"{Path(name).stem}: {len(_detected(pipeline, samples))}/{len(samples)}")
    indirect = load_corpus("indirect.yaml")
    attacks = [s["text"] for s in indirect if s["label"] == "attack"]
    clean = [s["text"] for s in indirect if s["label"] == "benign"]
    lines.append(f"indirect: {len(_detected(pipeline, attacks, 'tool_result'))}/{len(attacks)}")
    benign = load_corpus("benign.yaml")
    flagged = len(_detected(pipeline, benign)) + len(_detected(pipeline, clean, "tool_result"))
    lines.append(f"benign flagged: {flagged}/{len(benign) + len(clean)}")
    limits = _known_limits()
    lines.append(
        f"known limits: {len(_detected(pipeline, limits['missed_attacks']))}"
        f"/{len(limits['missed_attacks'])} hard attacks detected, "
        f"{len(_detected(pipeline, limits['false_positives']))}"
        f"/{len(limits['false_positives'])} quoted-attack texts flagged"
    )
    print("\n[benchmark] " + " | ".join(lines))
