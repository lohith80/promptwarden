# Roadmap

Where PromptWarden goes after v0.2, in the order that closes the biggest
measured gaps first. Each item states the problem it solves and what "done"
means, so progress can be checked rather than claimed.

Priorities come from three sources: the out-of-sample benchmark in the
README, the residual risks in the [threat model](THREAT_MODEL.md), and
[`tests/corpus/known_limits.yaml`](../tests/corpus/known_limits.yaml).

## 0.3: close the recall gap and cover more APIs

### Classifier detector alongside the patterns

Problem: patterns flag about 48% of in-the-wild jailbreak prompts and miss
paraphrase entirely (threat T1).

- An optional detector (`pip install promptwarden[classifier]`) that runs a
  small local model through ONNX Runtime. No prompt leaves the gateway.
- Patterns stay as the fast, explainable first layer. The classifier adds a
  score; policy decides what score flags and what blocks.
- Done when: the held-out jailbreak figure in the README is above 85% with
  the regular-prompt figure not higher than today, p99 added latency is
  published, and the model card states training data and known biases.

### More protocols

Problem: the gateway returns 404 for everything except OpenAI-style chat,
embeddings and models, so those calls either break or route around it.

- OpenAI Responses API, Anthropic Messages, AWS Bedrock Converse.
- One adapter interface: each protocol maps to the same segments
  (`user`, `tool_result`, `tool_definition`, `tool_call`, ...), so every
  detector and every event field works unchanged.
- Done when: each adapter passes the existing gateway test suite through a
  protocol-specific fixture, streaming included.

### Strict OCSF output

Problem: events are OCSF-aligned, not OCSF-valid (`finding_info` is an
array). Teams with an OCSF-native lake (Amazon Security Lake, Splunk OCSF
add-on) need valid records.

- `PW_EVENT_FORMAT=ocsf` emits one valid Detection Finding per detection.
- Done when: CI validates every emitted event against the published OCSF
  schema version named in `metadata.version`.

### Shared state

Problem: rate limits and tool drift memory are per replica (threats T15,
deployment guide).

- Optional Redis backend for token buckets and the tool registry.
- Done when: a two-replica integration test shows one global limit and one
  drift alert.

### Detection gaps with a known fix

- Uniformly spaced letters and ROT13 in the normalization layer.
- Hindi, Arabic and Turkish override rules, each with native-speaker review.
- Third-person indirect instructions, once the classifier can carry the
  precision.
- Done when: each sample moves from `known_limits.yaml` to the gated corpus.

### Packaging

- Helm chart with the same security defaults as the raw manifests.
- Signed container images and SBOM attestation published from CI.
- PyPI release.

## 0.4 to 0.5: agent-native controls

### MCP proxy mode

Problem: the gateway only sees tools that are declared in an LLM request.
Tool definitions and results that travel between an MCP client and an MCP
server never pass through it.

- Run PromptWarden as an MCP proxy: inspect `tools/list` (poisoning, pins)
  and `tools/call` results (indirect injection) at the source, with a
  per-server allowlist.
- Done when: the tool-poisoning corpus is caught on the MCP path with no LLM
  request involved.

### Tool-call argument policy

Problem: allow and deny lists work on tool names. Real damage is in the
arguments: `send_email` to an outside domain, `http_get` to an internal IP,
`run_sql` with `DROP`.

- Per-tool constraints in policy: JSON Schema or patterns on arguments
  (recipient domain allowlist, URL host allowlist, forbidden SQL verbs).
- An approval hook: hold a high-risk call and ask a human or a ticketing
  system before releasing it.
- Done when: a constrained call is blocked and an approved one is released
  in the streaming test suite.

### Conversation-level detection

Problem: each request is judged alone. Multi-turn attacks that escalate
slowly stay under every single-turn threshold.

- A session risk score keyed by app and user, with decay, carried in events.
- Done when: a multi-turn corpus exists and the score flags it while the
  benign multi-turn set stays clean.

### Workload identity

Problem: gateway keys are static secrets with no expiry (threat T11).

- Accept OIDC tokens (Kubernetes service account tokens, SPIFFE, cloud
  workload identity) and map claims to apps.
- Done when: an app authenticates with a projected service account token and
  no long-lived key exists anywhere.

### Privacy pack

- PII detectors with locale validators (IBAN, national IDs, phone numbers).
- Reversible tokenization: replace a value on the way out, restore it in the
  response, so the provider never sees it and the user still gets a useful
  answer.

### Multimodal inspection

Problem: images, audio and files pass uninspected (threat T20).

- OCR for image parts, text extraction for documents, with a size budget.

### Budgets

- Daily and monthly token budgets per app and per user, with events at
  thresholds, on top of today's rate limits.

## Toward 1.0: assurance

- **Tamper-evident audit.** Hash-chained events and signed policy bundles,
  so an auditor can verify that the log is complete and which policy was in
  force.
- **Continuous red teaming.** Run garak and PyRIT against the gateway in CI
  on a schedule, publish the trend.
- **Rule packs.** Versioned, signed detection content that updates
  independently of the gateway release, with a documented rule format so
  others can contribute.
- **Framework evidence.** A control mapping from gateway features to NIST AI
  RMF and ISO/IEC 42001, as documentation an assessor can use.
- **Coverage exports.** MITRE ATLAS Navigator layer generated from the rule
  catalog.
- **Plugin API** for custom detectors and sinks, with a stability promise.
- **Stable 1.0 contract**: policy schema, event schema and CLI covered by
  semantic versioning.

## Benchmark and research track

The benchmark is as much a deliverable as the code.

- Add public indirect-injection and agent benchmarks next to the jailbreak
  set (candidates: BIPIA, InjecAgent, AgentDojo attack suites), each with the
  same dev/test discipline.
- Publish a labeled tool-poisoning corpus; today's 18 samples are a start,
  not a dataset.
- Report every release's numbers in the changelog, including the ones that
  got worse.
- Keep `known_limits.yaml` honest: a limit leaves the file only through a
  test.

## How to influence this

Open an issue with a payload that gets through, a benign sample that gets
flagged, or a deployment constraint the gateway does not meet. Detection-gap
reports reorder this list faster than anything else.
