# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-11

The enterprise and agent release. v0.1 inspected chat text. v0.2 inspects
agent traffic (tools, tool results, tool calls, streams), knows which
application is calling, and can be rolled out without breaking anything.

### Added

Gateway
- Streaming (SSE) inspection with a holdback window; `streaming.mode: buffer`
  holds the whole response instead. Tool-call deltas are always held until
  the call is complete and inspected.
- Gateway authentication: per-app keys (`promptwarden keygen`), stored as
  SHA-256 hashes, presented as `Authorization: Bearer pw_...` or
  `X-PromptWarden-Key`. Per-app overrides for mode, thresholds, limits and
  tool policy.
- Provider key custody: `apps[].upstream_key_env` and `PW_UPSTREAM_API_KEY`
  let the gateway hold the provider key so app teams never do.
- Monitor mode (`gateway.mode: monitor`): nothing is blocked, events carry
  `disposition: would_block`.
- Inbound secret redaction (`detectors.secrets.inbound_action: redact`).
- Per-app rate limits, model allowlists and output token caps.
- `/v1/embeddings` with inbound inspection, `/v1/models` passthrough,
  `/readyz`, `/metrics` (Prometheus).
- Policy hot reload on SIGHUP or file change; an invalid file is rejected and
  the running policy is kept.
- `gateway.on_error` (fail closed by default) and `gateway.expose_detections`.

Detection
- Segment-aware inspection: every finding carries its source (user, system,
  assistant, tool_result, document, tool_definition, model_output, tool_call),
  message index and tool name.
- Normalization layer: invisible Unicode, homoglyphs, fullwidth forms,
  leetspeak, dotted letters, tag-block decoding. Obfuscated hits are tagged
  `obfuscated` and `AML.T0068`.
- PW-H010 base64 decode-and-rescan, PW-H011 overrides in nine languages,
  PW-H012 instructions addressed to an AI inside untrusted data, PW-H013
  stacked policy-evasion language.
- PW-X001..X003: reference-style and HTML image beacons, image domain
  allowlist.
- PW-S008..S012: GitHub, Slack, Google, Stripe and Azure storage credentials.
- PW-T001..T005: tool-call policy, tool poisoning scan, pinned definition
  mismatch, definition drift, unpinned tool.
- PW-G001..G004 and PW-G900: rate limit, auth failure, model not allowed,
  uninspectable content, inspection engine error.
- OWASP Top 10 for Agentic Applications (2026) mapping on every finding where
  one applies.

Telemetry
- Events are delivered on a background thread through a bounded queue; drops
  are counted and exported.
- Events carry app, user, client IP, model, stream flag, policy hash, mode,
  disposition and a correlation ID.
- Per-request audit records (OCSF class 6003, metadata only).
- Webhook and CEF-over-syslog sinks; Splunk HEC batching and response checks.
- Throttling of repeated gateway events with a suppressed count.
- New Splunk and Sentinel content for agent traffic, shadow mode and spend;
  Prometheus alert rules.

Tooling and operations
- `promptwarden` CLI: `serve`, `validate-policy`, `keygen`, `canary`,
  `tool-hash`, `scan`, `bench`, `rules`.
- Generated detection catalog (`docs/DETECTIONS.md`), checked in CI.
- Out-of-sample evaluation script against a public jailbreak dataset, with a
  dev/test split.
- Kubernetes manifests with a restricted security context, NetworkPolicy,
  PodDisruptionBudget and HPA. Multi-stage Docker image.
- Test suite grown from 35 to 274 tests, run on Python 3.10, 3.12 and 3.13.

### Changed
- `stream: true` is now streamed and inspected. v0.1 silently downgraded it
  to a JSON response, which broke SSE clients.
- Messages with a trusted role (`system`, `developer` by default) are no
  longer scanned for injection phrasing. v0.1 blocked any app whose system
  prompt said "never reveal your system prompt". Secrets and denylist terms
  in those messages are still caught. Set `inspection.trusted_roles: []` to
  restore the old behavior.
- The policy schema is strict. Unknown keys and out-of-range values stop the
  gateway from starting instead of falling back to defaults.
- PW-H002 now maps to MITRE ATLAS `AML.T0056` (Extract LLM System Prompt)
  instead of `AML.T0051`.
- PW-H009 (inline image beacon) is flag-level when it appears in the caller's
  own turn and stays block-level in tool results, documents and model output.
- A blocked outbound response now also drops `tool_calls` and sets
  `finish_reason: content_filter`.
- Only an allowlist of upstream response headers is returned to the client
  (retry and rate-limit headers, request ID).
- The app object is built lazily: importing `promptwarden.app` no longer
  starts a gateway. `uvicorn promptwarden.app:app` still works.

### Fixed
- Sink I/O (Splunk HEC, file) ran inside the async request handler and could
  stall the event loop for seconds when the SIEM was slow.
- Splunk HEC responses were not checked; a rejected token failed silently.
- The body size limit was applied after the whole body had been read into
  memory. It is now enforced while reading.
- A JSON body that was not an object, or a `messages` array with non-object
  items, returned 500. Both return 400.
- A new HTTP client was created per request (no connection reuse).
- CEF output did not escape `|`, `=`, `\` or newlines, so denylist
  descriptions could forge fields.
- Invisible-character detection counted zero-width joiners inside emoji and
  zero-width non-joiners in Persian and similar scripts, blocking ordinary
  messages at severity 9.
- The entropy rule fired on long URLs and on base64 images; the card rule
  accepted Luhn-valid numbers no card network issues; the SSN rule accepted
  number ranges that are never issued; PW-H005 fired on any base64 blob near
  the word "base64".
- PW-H002 fired on defensive instructions such as "do not reveal your system
  prompt".

### Known limitations
- OpenAI-compatible chat, embeddings and models endpoints only. The
  Responses API, Anthropic Messages and Bedrock are on the roadmap.
- Images, audio and files inside messages are not inspected (counted in
  `promptwarden_uninspected_parts_total`).
- Rate limits and tool drift memory are per replica and in memory.
- Window-mode streaming can release the first characters of a match longer
  than `holdback_chars` before blocking.
- The engine is still pattern-based. Measured recall on public in-the-wild
  jailbreak prompts is about 48% at flag level; see the README benchmark.

## [0.1.0] - 2026-07-18

### Added
- OpenAI-compatible reverse proxy (`/v1/chat/completions`) with inbound and
  outbound inspection; blocking, flagging, and redaction actions.
- Detection engine with four detector families: heuristics (prompt injection,
  jailbreak, encoding smuggling, invisible Unicode, markdown exfil beacons),
  secrets/PII egress (AWS keys, private keys, API keys, JWTs, SSN, Luhn-valid
  cards, entropy), canary-token system-prompt-leak detection, and
  operator-defined denylist rules.
- Every detection mapped to OWASP LLM Top 10 (2025) and MITRE ATLAS.
- OCSF-aligned JSON events (Detection Finding, class 2004) + CEF formatter;
  stdout, JSONL file, and Splunk HEC sinks.
- Policy-as-YAML with severity thresholds and per-detector toggles.
- Adversarial test corpus and benchmark (detection rate / false positive rate).
- Splunk saved searches and Microsoft Sentinel KQL starter content.
- Threat model (docs/THREAT_MODEL.md), Dockerfile, docker-compose, CI.

### Known limitations
- Non-streaming only: `stream: true` is downgraded (roadmap: streaming inspection).
- OpenAI-compatible APIs only (roadmap: Anthropic Messages, Bedrock adapters).
- Heuristic detectors are pattern-based; a classifier detector is on the roadmap.
