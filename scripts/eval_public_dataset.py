#!/usr/bin/env python3
"""Out-of-sample evaluation on a public dataset.

The repository's own corpus is written alongside the rules, so it cannot say
how the engine does on attacks nobody here wrote. This script scores the
default policy against "In-The-Wild Jailbreak Prompts" (Shen et al., ACM CCS
2024, https://github.com/verazuo/jailbreak_llms, MIT license): 1,405
jailbreak prompts and 13,735 regular prompts collected from Reddit, Discord
and prompt-sharing sites.

Nothing from the dataset is stored in this repository. The script downloads
the two CSV files into a cache directory and prints a JSON report.

    python scripts/eval_public_dataset.py --cache /tmp/pw-eval

Notes on reading the result:
- The dataset is jailbreak prompts (persona and policy-evasion text aimed at a
  chat model). It is a different distribution from indirect injection or
  tool poisoning, which have no comparable public set yet.
- "Regular" prompts come from the same communities and include role-play and
  prompt-engineering text, so the false positive rate here is a harsher test
  than typical enterprise traffic.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

from promptwarden import __version__
from promptwarden.config import Policy
from promptwarden.pipeline import Pipeline

BASE = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/"
FILES = {
    "jailbreak": "jailbreak_prompts_2023_12_25.csv",
    "regular": "regular_prompts_2023_12_25.csv",
}


def fetch(cache: Path, name: str) -> Path:
    target = cache / name
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(BASE + name, timeout=120) as response:  # noqa: S310
            target.write_bytes(response.read())
    return target


def in_split(text: str, split: str) -> bool:
    """Deterministic 50/50 split by content hash. Rules are only ever tuned
    against "dev"; the numbers published in the README are from "test"."""
    if split == "all":
        return True
    even = int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16) % 2 == 0
    return even == (split == "dev")


def prompts(path: Path, split: str) -> list[str]:
    csv.field_size_limit(sys.maxsize)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = [row["prompt"] for row in csv.DictReader(handle) if row.get("prompt")]
    return [text for text in rows if in_split(text, split)]


def score(pipeline: Pipeline, texts: list[str]) -> dict:
    actions = {"allow": 0, "flag": 0, "block": 0}
    rules: dict[str, int] = {}
    timings = []
    chars = 0
    for text in texts:
        started = time.perf_counter()
        verdict = pipeline.run(text, "inbound")
        timings.append((time.perf_counter() - started) * 1000)
        actions[verdict.action] += 1
        chars += len(text)
        if verdict.action != "allow":
            for rule_id in {d.rule_id for d in verdict.detections}:
                rules[rule_id] = rules.get(rule_id, 0) + 1
    total = len(texts)
    ordered = sorted(timings)
    return {
        "samples": total,
        "flagged_or_blocked": total - actions["allow"],
        "rate": round((total - actions["allow"]) / total, 4),
        "blocked": actions["block"],
        "block_rate": round(actions["block"] / total, 4),
        "mean_chars": round(chars / total),
        "latency_ms": {
            "p50": round(statistics.median(timings), 3),
            "p99": round(ordered[int(0.99 * (total - 1))], 3),
            "max": round(ordered[-1], 3),
        },
        "top_rules": dict(sorted(rules.items(), key=lambda item: -item[1])[:10]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cache", required=True, help="directory for the downloaded CSV files")
    parser.add_argument("--split", choices=["test", "dev", "all"], default="test",
                        help="test = held-out half (default); dev = half used for tuning")
    args = parser.parse_args()
    cache = Path(args.cache)
    pipeline = Pipeline(Policy())
    jailbreak = score(pipeline, prompts(fetch(cache, FILES["jailbreak"]), args.split))
    regular = score(pipeline, prompts(fetch(cache, FILES["regular"]), args.split))
    report = {
        "promptwarden": __version__,
        "dataset": "verazuo/jailbreak_llms (2023-12-25 snapshot)",
        "split": args.split,
        "policy": "built-in defaults (block_at 8, flag_at 5)",
        "jailbreak_prompts": jailbreak,
        "regular_prompts": regular,
    }
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
