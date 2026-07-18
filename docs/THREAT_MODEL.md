# PromptWarden Threat Model

A security tool that has not been threat-modeled is a liability, not a control.
This document applies STRIDE to PromptWarden itself - the gateway, its policy,
and its event pipeline - and states residual risks honestly.

## System Overview

```
Client app ──> PromptWarden gateway ──> Upstream LLM API (OpenAI-compatible)
                    │
                    ├── Policy (YAML, read at startup)
                    └── Event sinks (stdout / JSONL file / Splunk HEC)
```

Trust boundaries:

- **TB1**: client → gateway (untrusted prompts, untrusted client headers)
- **TB2**: gateway → upstream API (credentials in transit)
- **TB3**: upstream response → gateway (untrusted model output; may carry
  indirect injection from tool results or retrieved documents)
- **TB4**: gateway → event sinks (findings leave the traffic path)
- **TB5**: operator → policy file (configuration is code)

## STRIDE Analysis

| # | Threat | Category | Mitigation (implemented) | Residual risk |
|---|--------|----------|--------------------------|---------------|
| T1 | Malicious prompt bypasses heuristics (paraphrase, novel jailbreak, low-resource language) | Tampering / Bypass | Layered detectors (patterns + functional rules + canary); corpus regression tests; bypass reports triaged as detection gaps (SECURITY.md) | **High by design.** Pattern detection is a tripwire, not a boundary. Roadmap: classifier detector. Never deploy as the only control. |
| T2 | Instruction smuggling via invisible Unicode or encoding | Tampering | PW-H006 (tag block + zero-width), PW-H005 (base64+decode) | Other encodings (leet, homoglyph) not yet covered; tracked as corpus gaps |
| T3 | Client credential (Authorization header) leaked via events or logs | Information Disclosure | Header allowlist for forwarding; events built only from truncated/masked detector evidence; HEC token never logged; regression test asserts secrets absent from event JSON | Full request bodies intentionally never logged; do not add body logging without redaction review |
| T4 | Oversized payload DoS (regex work is O(n)) | Denial of Service | `max_body_bytes` limit (413 above it); bounded regex windows (`{0,40}`-style), no catastrophic backtracking patterns | Very high request *rate* needs an upstream rate limiter (out of scope for v0.1) |
| T5 | Event sink outage takes down traffic path | Denial of Service | HEC sink catches all HTTP errors and logs; emission is never in the request's failure path | Events can be lost during sink outage (availability of telemetry < availability of traffic, by decision) |
| T6 | Policy file tampering (weaken thresholds, disable detectors) | Tampering / Elevation | Policy is read-only mounted in the container example; missing file falls back to secure defaults | File integrity monitoring / GitOps for policy is the operator's responsibility - treat policy.yaml like sudoers |
| T7 | Spoofed events injected into SIEM (fake findings, alert fatigue) | Spoofing / Repudiation | HEC token authenticates the gateway to Splunk | Anyone with stdout/file access can forge JSONL lines; ship via authenticated HEC in production |
| T8 | Gateway impersonation (client tricked into sending traffic elsewhere) | Spoofing | Deployment concern: run behind TLS with a pinned internal hostname | TLS termination is out of scope for the app; do not expose the gateway without TLS |
| T9 | Canary token disclosure (token itself leaks, enabling silent bypass of PW-C001) | Information Disclosure | Tokens live only in policy + system prompt; events carry masked form only | Rotate canaries like credentials; `generate_canary()` makes rotation cheap |
| T10 | Malicious upstream response abuses the client (markdown beacon exfil) | Tampering (TB3) | PW-H009 scans outbound for image-beacon patterns; outbound blocking redacts content | Non-markdown exfil channels (URLs the client auto-fetches) depend on client behavior |

## Explicit Non-Goals (v0.1)

- Not a replacement for upstream provider safety systems.
- No streaming inspection (`stream` is forced off; documented in README).
- No multi-tenant isolation: run one gateway per trust domain.
- No prompt *rewriting*: PromptWarden blocks or flags; it does not attempt to
  sanitize-and-forward, which creates parser-differential risks.

## Review Cadence

Re-review this document at every minor release or when adding: a new sink, a
new upstream adapter, streaming support, or any body-logging feature.
