# PromptWarden threat model

A security tool that has not been threat-modeled is a liability, not a control.
This document applies STRIDE to PromptWarden itself - the gateway, its policy,
its keys and its event pipeline - and states residual risks honestly.

Reviewed for v0.2.0 (streaming, gateway authentication, provider key custody,
tool inspection, redaction, new sinks).

## System overview

```
                     gateway key                      provider key
Apps and agents ───────────────> PromptWarden ───────────────────> Upstream LLM API
                                     │
                                     ├── Policy (YAML, strict schema, hot reloaded)
                                     ├── Provider keys (environment variables)
                                     ├── Event sinks (stdout / JSONL / HEC / webhook / syslog)
                                     └── /metrics, /readyz (unauthenticated, cluster-internal)
```

Trust boundaries:

- **TB1**: client to gateway (untrusted prompts, untrusted headers, gateway key)
- **TB2**: gateway to upstream API (provider credential in transit)
- **TB3**: upstream response to gateway (untrusted model output, streamed or
  whole; may carry the effects of an indirect injection)
- **TB4**: gateway to event sinks (findings leave the traffic path)
- **TB5**: operator to policy file and environment (configuration is code)
- **TB6**: third-party content inside a request (tool results, documents,
  tool definitions from MCP servers and plugins). The client is honest; the
  content it relays is not.

## STRIDE analysis

| # | Threat | Category | Mitigation (implemented) | Residual risk |
|---|--------|----------|--------------------------|---------------|
| T1 | Malicious prompt bypasses the rules (paraphrase, novel jailbreak, unsupported language) | Tampering / Bypass | Layered detectors; normalization and decode-and-rescan; corpus regression tests; public out-of-sample benchmark; known limits tracked in `tests/corpus/known_limits.yaml` | **High by design.** Measured recall on in-the-wild jailbreaks is about 48% at flag level. Pattern detection is a tripwire, not a boundary. Never deploy as the only control. |
| T2 | Instruction smuggling through encoding or invisible characters | Tampering | Invisible-character stripping and counting, tag-block decoding, homoglyph folding, leetspeak, dotted letters, base64 rescan (PW-H005, H006, H010, `obfuscated` tag) | Uniformly spaced letters, ROT13, nested or exotic encodings are not undone |
| T3 | Client or provider credential leaked through events or logs | Information Disclosure | Header allowlist; Authorization never logged; events built only from truncated or masked evidence; log lines carry exception types, not messages; regression tests assert secrets are absent from events | Full bodies are never logged by design. Do not add body logging without a redaction review |
| T4 | Oversized or expensive payload exhausts the gateway | Denial of Service | Body size cap enforced while reading; bounded regex windows; prefilters; caps on base64 candidates, tool count and detections; latency regression test | Inspection is CPU-bound on the event loop: about 0.4 ms per KB. A flood of maximum-size bodies needs rate limits at the gateway and at the ingress |
| T5 | Event sink outage or slowness affects traffic | Denial of Service | Sinks run on a background thread behind a bounded queue; failures are caught, counted and never raised | Events are dropped when the queue is full. `promptwarden_events_dropped_total` and the `PromptWardenEventsDropped` alert make that visible; it is still lost telemetry |
| T6 | Policy tampering (weaker thresholds, monitor mode, removed pins) | Tampering / Elevation | Strict schema; `validate-policy` in CI; policy hash in every event and in `/readyz`; invalid reload rejected; "Policy Change Detected" search | Whoever can write the policy file controls the gateway. Manage it through reviewed change control and alert on unexpected hashes |
| T7 | Forged events injected into the SIEM | Spoofing / Repudiation | HEC and webhook sinks authenticate with a token; CEF fields are escaped so content cannot forge fields or lines | stdout, file and UDP syslog are unauthenticated: anyone with access to them can forge lines. Use HEC or the webhook sink in production |
| T8 | Gateway impersonation or traffic interception | Spoofing | Deployment concern: TLS termination in front of the gateway, NetworkPolicy limiting who can reach it | The app speaks plain HTTP. Do not expose the gateway without TLS in front |
| T9 | Canary token disclosure (silent bypass of PW-C001) | Information Disclosure | Tokens live only in policy and the system prompt; events carry the masked form | Rotate canaries like credentials |
| T10 | Model output abuses the client (image beacons, hostile tool calls) | Tampering (TB3) | PW-H009, PW-X001..X003 with optional image domain allowlist; tool-call allow and deny lists; blocked tool calls are removed from the response | Exfiltration through channels the gateway does not parse (plain links the user clicks, client-specific renderers) |
| T11 | Stolen gateway key | Spoofing | Keys are 32 random bytes, stored only as SHA-256 hashes; per-app rate limits, model allowlist and token caps bound the damage; revocation is removing one hash and reloading | No expiry and no IP binding yet. A stolen key works until revoked. Roadmap: short-lived keys through OIDC workload identity |
| T12 | Gateway becomes an open proxy to the provider key | Elevation of Privilege | A gateway-held provider key is only ever used for requests that present a valid gateway key; anonymous requests forward only what the client sent; a gateway key is never forwarded upstream (tested) | `auth.required: false` with apps defined still accepts anonymous passthrough traffic; `validate-policy` prints a note |
| T13 | Provider key exposure at the gateway | Information Disclosure | Keys come from environment variables, never from the policy file; never logged; container runs as non-root with a read-only filesystem and no service account token | The gateway process holds provider keys in memory: compromise of the pod is compromise of those keys. Scope provider keys per app and rotate them |
| T14 | Secret reaches the client before a streamed response is blocked | Information Disclosure (TB3) | Holdback window: any match no longer than `holdback_chars` is detected before any of it is released (property-tested across random chunkings); tool-call deltas are held until complete; buffer mode removes the gap entirely | In window mode, a match longer than the window can have its first characters released. Text sent before an unrelated later match is not recalled |
| T15 | Tool poisoning or rug pull from a compromised MCP server or plugin | Tampering (TB6) | Tool definition scan (PW-T002), hash pinning (PW-T003), `require_pinned` (PW-T005), drift alerts (PW-T004) | Only tools declared in the request are visible. Tools executed client-side without being declared to the model, and MCP traffic that does not pass through the gateway, are out of view. Drift memory is per replica and resets on restart: pins are the durable control |
| T16 | Indirect injection through tool results or documents | Tampering (TB6) | Tool results and embedding inputs are scanned with the full rule set plus PW-H012; findings name the source and index | Same recall limits as T1. Third-person instructions that never address the model are missed |
| T17 | Redaction changes meaning or misses a variant | Tampering | Redaction is limited to exact spans of high-confidence secret rules; nothing else is ever rewritten; the entropy rule is excluded | A secret in a format no rule knows is forwarded unchanged. A redacted placeholder can confuse the model's answer; that is the price of not blocking |
| T18 | Abuse of monitor mode (control silently off) | Elevation | Mode is in every event, in `/readyz` and in `promptwarden_policy_info`; `PromptWardenMonitorMode` alert after 30 days | Monitor mode is a legitimate state. Only review catches a deliberate downgrade |
| T19 | Rule IDs in block responses help an attacker tune a bypass | Information Disclosure | `gateway.expose_detections: false` removes them from client responses | On by default for developer experience. Turn off wherever the gateway's response can reach an end user |
| T20 | Non-text content carries the attack (image with embedded text, audio) | Bypass | Counted in `promptwarden_uninspected_parts_total`; pre-tokenized embedding input is refused (PW-G004) | Images, audio and files in chat messages pass uninspected. Roadmap: OCR and multimodal inspection |
| T21 | Client IP spoofing through X-Forwarded-For | Spoofing | The header is ignored unless `PW_TRUSTED_PROXY_HOPS` is set, and then only the entry added by the trusted proxy is used | A wrong hop count attributes traffic to the wrong address |
| T22 | SIEM flooding through the gateway | Denial of Service (TB4) | Gateway control events (auth failures, rate limits) are throttled per key with a suppressed count; detections per event are capped | Content findings are not throttled: an attacker with a valid key can generate one event per request, bounded by the app's rate limit |

## Explicit non-goals (v0.2)

- Not a replacement for upstream provider safety systems or for
  least-privilege agent design.
- No general prompt rewriting. The gateway blocks or flags; the one exception
  is span redaction of high-confidence secrets (T17), because sanitize and
  forward creates parser-differential risks.
- No inspection of what tools do when they run. The gateway sees the model's
  request to call a tool and the result that comes back, not the side effects.
- No cross-replica state. Rate limits and drift memory are per process.
- No TLS termination and no admin API. Both belong to the platform in front.

## Review cadence

Re-review this document at every minor release, and whenever any of these is
added: a sink, an upstream adapter, a new endpoint, a body-logging feature, a
detector that rewrites traffic, or shared state between replicas.
