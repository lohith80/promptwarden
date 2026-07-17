"""Corpus benchmark: the numbers reported in the README come from here."""

from conftest import load_corpus


def test_injection_detection_rate(pipeline):
    samples = load_corpus("injections.yaml")
    detected = [s for s in samples if pipeline.run(s, "inbound").action != "allow"]
    rate = len(detected) / len(samples)
    missed = [s[:60] for s in samples if s not in detected]
    assert rate >= 0.85, f"detection rate {rate:.0%}; missed: {missed}"


def test_benign_false_positive_rate(pipeline):
    samples = load_corpus("benign.yaml")
    false_positives = [
        (s[:60], [d.rule_id for d in v.detections])
        for s in samples
        if (v := pipeline.run(s, "inbound")).action != "allow"
    ]
    assert not false_positives, f"benign samples flagged: {false_positives}"


def test_secret_egress_detection(pipeline):
    samples = load_corpus("secrets.yaml")
    for sample in samples:
        verdict = pipeline.run(sample["text"], "outbound")
        rule_ids = {d.rule_id for d in verdict.detections}
        assert sample["expect_rule"] in rule_ids, (
            f"expected {sample['expect_rule']} on: {sample['text'][:50]}, got {rule_ids}"
        )


def test_print_benchmark_summary(pipeline, capsys):
    """Emit the benchmark table used in the README (visible with pytest -s)."""
    injections = load_corpus("injections.yaml")
    benign = load_corpus("benign.yaml")
    tp = sum(1 for s in injections if pipeline.run(s, "inbound").action != "allow")
    fp = sum(1 for s in benign if pipeline.run(s, "inbound").action != "allow")
    print(
        f"\n[benchmark] injections: {tp}/{len(injections)} detected "
        f"({tp / len(injections):.0%}) | benign flagged: {fp}/{len(benign)}"
    )
