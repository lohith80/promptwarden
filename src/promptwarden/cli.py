"""promptwarden command line.

  serve            run the gateway
  validate-policy  check a policy file (use in CI before deploying it)
  keygen           create a gateway key and the hash to put in policy
  canary           create a canary token for a system prompt
  tool-hash        hash tool definitions for pinning (OpenAI or MCP format)
  scan             inspect text or tool definitions offline; exit code gates CI
  bench            measure detection rate, false positives and latency on a
                   labeled JSONL file (your own traffic samples)
  rules            print the rule catalog with framework mappings
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from . import __version__, auth, catalog
from .config import Policy, PolicyError, load_policy
from .detectors import canary as canary_detector
from .detectors import tools
from .pipeline import Pipeline, Verdict
from .segments import InspectionInput, Segment

EXIT_ALLOW, EXIT_FLAG, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2, 3


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _load(path: str | None) -> Policy:
    if path is None:
        return Policy()
    return load_policy(path, must_exist=True)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _extract_tools(document: object) -> list:
    """Find the tool list in an OpenAI request, a bare list, or an MCP
    tools/list response."""
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("tools", "functions"):
            if isinstance(document.get(key), list):
                return document[key]
        result = document.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return result["tools"]
        if tools.canonical_tool(document) is not None:
            return [document]
    raise ValueError("no tool definitions found (expected a list, or an object with 'tools')")


def _verdict_json(verdict: Verdict) -> dict:
    return {
        "action": verdict.action,
        "score": verdict.score,
        "detections": [
            {
                "rule_id": d.rule_id,
                "severity": d.severity,
                "description": d.description,
                "evidence": d.evidence,
                "source": d.source,
                "tool_name": d.tool_name,
                "owasp_llm_top10": d.owasp_llm,
                "owasp_agentic_top10": d.owasp_agentic,
                "mitre_atlas": d.atlas,
                "tags": d.tags,
            }
            for d in verdict.detections
        ],
    }


def _exit_code(verdict: Verdict) -> int:
    return {"allow": EXIT_ALLOW, "flag": EXIT_FLAG, "block": EXIT_BLOCK}[verdict.action]


# -- commands ---------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "promptwarden.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def cmd_validate_policy(args: argparse.Namespace) -> int:
    policy = load_policy(args.path, must_exist=True)
    Pipeline(policy)  # compiles denylist rules
    if args.check_env:
        auth.AppIndex(policy)
    gw = policy.gateway
    _out(f"policy OK  hash={policy.fingerprint()}  mode={gw.mode}  "
         f"block_at={gw.block_at}  flag_at={gw.flag_at}  apps={len(policy.apps)}  "
         f"auth_required={policy.auth.required}")
    if gw.mode == "monitor":
        _out("note: gateway.mode is monitor, nothing will be blocked")
    if policy.apps and not policy.auth.required:
        _out("note: apps are defined but auth.required is false, anonymous traffic is accepted")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    key = auth.generate_key()
    _out(f"gateway key (give to the app team, shown once): {key}")
    _out("policy entry:")
    _out(f"  - id: {args.app}")
    _out(f"    key_hashes: [\"{auth.hash_key(key)}\"]")
    return 0


def cmd_canary(_: argparse.Namespace) -> int:
    _out(canary_detector.generate_canary())
    return 0


def cmd_tool_hash(args: argparse.Namespace) -> int:
    definitions = _extract_tools(json.loads(_read(args.file)))
    _out("tools:")
    _out("  pinned:")
    count = 0
    for definition in definitions:
        canonical = tools.canonical_tool(definition)
        if canonical is None:
            continue
        _out(f"    {json.dumps(canonical['name'])}: {tools.tool_hash(definition)}")
        count += 1
    if count == 0:
        raise ValueError("no function tools found in input")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    pipeline = Pipeline(_load(args.policy))
    if args.tools:
        payload = InspectionInput(tool_definitions=_extract_tools(json.loads(_read(args.tools))))
        verdict = pipeline.inspect(payload, "inbound")
    else:
        text = _read(args.file)
        source = args.source or ("user" if args.direction == "inbound" else "model_output")
        verdict = pipeline.inspect(
            InspectionInput(segments=[Segment(text, source)]), args.direction
        )
    _out(json.dumps(_verdict_json(verdict), indent=2, ensure_ascii=False))
    return _exit_code(verdict)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def run_bench(pipeline: Pipeline, samples: list[dict], repeat: int = 1) -> dict:
    """Score labeled samples. Each sample: {"text", "label": attack|benign,
    optional "source", optional "direction"}."""
    tp = fn = fp = tn = 0
    latencies: list[float] = []
    chars = 0
    missed: list[str] = []
    false_positives: list[dict] = []
    for sample in samples:
        text = sample["text"]
        direction = sample.get("direction", "inbound")
        source = sample.get("source") or ("user" if direction == "inbound" else "model_output")
        verdict = None
        for _ in range(max(1, repeat)):
            started = time.perf_counter()
            verdict = pipeline.run(text, direction, source=source)
            latencies.append((time.perf_counter() - started) * 1000)
        chars += len(text)
        hit = verdict.action != "allow"
        if sample["label"] == "attack":
            if hit:
                tp += 1
            else:
                fn += 1
                missed.append(text[:80])
        elif hit:
            fp += 1
            false_positives.append(
                {"text": text[:80], "rules": [d.rule_id for d in verdict.detections]}
            )
        else:
            tn += 1
    attacks, benign = tp + fn, fp + tn
    return {
        "samples": len(samples),
        "attacks": attacks,
        "benign": benign,
        "detected": tp,
        "detection_rate": round(tp / attacks, 4) if attacks else None,
        "false_positives": fp,
        "false_positive_rate": round(fp / benign, 4) if benign else None,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
            "p99": round(_percentile(latencies, 0.99), 4),
            "max": round(max(latencies), 4),
        } if latencies else {},
        "mean_chars": round(chars / len(samples), 1) if samples else 0,
        "missed": missed[:50],
        "false_positive_samples": false_positives[:50],
    }


def cmd_bench(args: argparse.Namespace) -> int:
    samples = []
    for number, line in enumerate(_read(args.file).splitlines(), 1):
        if not line.strip():
            continue
        sample = json.loads(line)
        if "text" not in sample or sample.get("label") not in {"attack", "benign"}:
            raise ValueError(f"line {number}: need 'text' and 'label' (attack|benign)")
        samples.append(sample)
    if not samples:
        raise ValueError("no samples in input")
    report = run_bench(Pipeline(_load(args.policy)), samples, args.repeat)
    _out(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        _out(json.dumps(catalog.as_dicts(), indent=2))
        return 0
    _out("| Rule | Detects | Severity | OWASP LLM | OWASP Agentic | MITRE ATLAS | Scope |")
    _out("|------|---------|----------|-----------|---------------|-------------|-------|")
    for info in catalog.rules():
        _out(f"| {info.rule_id} | {info.title} | {info.severity} | {info.owasp_llm or '-'} | "
             f"{info.owasp_agentic or '-'} | {info.atlas or '-'} | {info.scope} |")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptwarden", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"promptwarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--workers", type=int, default=1)
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    validate = sub.add_parser("validate-policy", help="check a policy file")
    validate.add_argument("path")
    validate.add_argument("--check-env", action="store_true",
                          help="also require every upstream_key_env variable to be set")
    validate.set_defaults(func=cmd_validate_policy)

    keygen = sub.add_parser("keygen", help="create a gateway key and its policy hash")
    keygen.add_argument("--app", default="my-app")
    keygen.set_defaults(func=cmd_keygen)

    canary = sub.add_parser("canary", help="create a canary token")
    canary.set_defaults(func=cmd_canary)

    tool_hash = sub.add_parser("tool-hash", help="hash tool definitions for pinning")
    tool_hash.add_argument("file", help="JSON file with tool definitions, or - for stdin")
    tool_hash.set_defaults(func=cmd_tool_hash)

    scan = sub.add_parser("scan", help="inspect text or tool definitions offline")
    scan.add_argument("file", nargs="?", default="-", help="text file, or - for stdin")
    scan.add_argument("--tools", help="JSON file of tool definitions to scan instead of text")
    scan.add_argument("--direction", choices=["inbound", "outbound"], default="inbound")
    scan.add_argument("--source", help="segment source, e.g. user, tool_result, document")
    scan.add_argument("--policy", help="policy file (default: built-in defaults)")
    scan.set_defaults(func=cmd_scan)

    bench = sub.add_parser("bench", help="score a labeled JSONL file")
    bench.add_argument("--file", required=True)
    bench.add_argument("--policy")
    bench.add_argument("--repeat", type=int, default=1, help="timing repetitions per sample")
    bench.set_defaults(func=cmd_bench)

    rules = sub.add_parser("rules", help="print the rule catalog")
    rules.add_argument("--format", choices=["markdown", "json"], default="markdown")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except (OSError, ValueError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
