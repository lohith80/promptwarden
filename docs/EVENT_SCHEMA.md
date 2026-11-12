# Event schema

Every event is one JSON object. Two classes are emitted, both aligned with
[OCSF](https://schema.ocsf.io/) class and field names where one exists:

| `class_uid` | `class_name` | When |
|-------------|--------------|------|
| 2004 | Detection Finding | A verdict other than allow, or a gateway control (auth failure, rate limit, model policy) |
| 6003 | API Activity | Once per request, when `audit.enabled` is true |

"OCSF-aligned" is deliberate wording: class, category, severity and metadata
follow OCSF, but `finding_info` is an array (one entry per detection in the
request) where OCSF defines a single object. Strict OCSF output is on the
roadmap. Schema version is in `metadata.schema_version`; fields are only ever
added within a major version.

Events never contain prompt or response bodies, Authorization headers, or
gateway or provider keys. `evidence` is at most 80 characters of the matched
text, and secret detectors mask it down to a four-character prefix.

## Detection Finding (2004)

```json
{
  "time": "2026-11-11T16:02:11.482913+00:00",
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "activity_name": "llm_inbound_inspection",
  "severity_id": 4,
  "status": "block",
  "disposition": "blocked",
  "message": "PromptWarden blocked: 1 detection(s), max severity 8",
  "metadata": {
    "product": {"name": "PromptWarden", "version": "0.2.0"},
    "schema_version": "1.1",
    "event_uid": "0d0c7c1e-7f0e-4a6c-9a53-2f5a0a1f4c11",
    "uid": "f04b98ab-6a40-4de9-8642-dd212bb15bd4",
    "app_id": "support-bot",
    "policy_hash": "f0dbb4056c784080",
    "mode": "enforce",
    "correlation_uid": "trace-abc.123"
  },
  "actor": {"app_id": "support-bot", "user": "u-4821"},
  "src_endpoint": {"ip": "203.0.113.9"},
  "llm": {"endpoint": "/v1/chat/completions", "model": "gpt-4o-mini", "stream": false},
  "finding_info": [
    {
      "rule_id": "PW-H001",
      "detector": "heuristics",
      "title": "Instruction override attempt (ignore/disregard prior instructions)",
      "severity": 8,
      "confidence": 0.8,
      "evidence": "Ignore all previous instructions",
      "owasp_llm_top10": "LLM01",
      "owasp_agentic_top10": "ASI01",
      "mitre_atlas": "AML.T0051.001",
      "disposition": "detected",
      "source": "tool_result",
      "index": 2,
      "tool_name": "read_inbox",
      "tags": ["indirect"]
    }
  ]
}
```

### Top-level fields

| Field | Meaning |
|-------|---------|
| `time` | UTC, ISO 8601 |
| `activity_name` | `llm_inbound_inspection`, `llm_outbound_inspection`, or `llm_gateway_control` |
| `severity_id` | OCSF scale: 1 informational, 2 low, 3 medium, 4 high, 5 critical. Derived from the highest rule severity: 9-10 is 5, 7-8 is 4, 5-6 is 3, 3-4 is 2 |
| `status` | What the gateway did: `block` or `flag` |
| `disposition` | Why, in more detail (table below) |
| `suppressed_count` | Gateway control events only: how many identical events were collapsed since the previous one |

### `disposition`

| Value | Meaning |
|-------|---------|
| `blocked` | Enforce mode, severity at or above `block_at`. The request was rejected or the response withheld |
| `would_block` | Monitor mode: this would have been blocked under enforce. Traffic passed |
| `flagged` | Severity between `flag_at` and `block_at`. Traffic passed |
| `redacted` | A secret was replaced in the prompt and the request continued |
| `rate_limited` | PW-G001 |
| `denied` | PW-G002, PW-G003, PW-G004: authentication, model policy, or uninspectable content |

### `metadata`

| Field | Meaning |
|-------|---------|
| `uid` | Request ID. The same value is returned to the client in the `x-promptwarden-request-id` header and in error bodies, and it joins inbound, outbound and audit events for one request |
| `event_uid` | Unique per event, for deduplication |
| `app_id` | Application from the gateway key, or `default` for anonymous traffic |
| `policy_hash` | First 16 hex characters of the SHA-256 of the loaded policy |
| `mode` | `enforce` or `monitor`, as it applied to this app |
| `correlation_uid` | The client's `X-Request-Id`, if it sent a well-formed one |

### `actor`, `src_endpoint`, `llm`

| Field | Meaning |
|-------|---------|
| `actor.user` | The `user` (or `safety_identifier`) field of the request body, as set by the application. Up to 128 characters |
| `src_endpoint.ip` | Socket peer, or the address added by the trusted proxy when `PW_TRUSTED_PROXY_HOPS` is set |
| `llm.model` | Model requested |
| `llm.stream` | Whether the response was streamed |

### `finding_info[]`

| Field | Meaning |
|-------|---------|
| `rule_id` | See [DETECTIONS.md](DETECTIONS.md) |
| `severity` | 1-10, the policy scale |
| `confidence` | 0-1. 1.0 for deterministic rules (canary, pins, tool policy) |
| `evidence` | Truncated or masked match. Empty for some rules |
| `disposition` | `detected`, or `redacted` when this finding's span was removed |
| `source` | Where the text came from: `user`, `system`, `assistant`, `tool_result`, `document`, `tool_definition`, `model_output`, `tool_call` |
| `index` | Message index in the request, or choice index in the response |
| `tool_name` | The tool involved, for tool results, definitions and calls |
| `tags` | `obfuscated`, `indirect`, `via_tool_call`, `tool_poisoning`, ATLAS sub-technique IDs, and for composite rules the inner rule IDs |
| `owasp_llm_top10`, `owasp_agentic_top10`, `mitre_atlas` | Framework mappings; null when none applies |

## API Activity (6003)

```json
{
  "time": "2026-11-11T16:02:12.007421+00:00",
  "class_uid": 6003,
  "class_name": "API Activity",
  "category_uid": 6,
  "activity_name": "llm_request",
  "severity_id": 1,
  "status": "allowed",
  "message": "LLM request allowed (200)",
  "metadata": {
    "product": {"name": "PromptWarden", "version": "0.2.0"},
    "schema_version": "1.1",
    "event_uid": "7b5f3f0a-2f0d-4a1e-8a37-6f1f0c2d9e55",
    "uid": "f04b98ab-6a40-4de9-8642-dd212bb15bd4",
    "app_id": "support-bot",
    "policy_hash": "f0dbb4056c784080",
    "mode": "enforce"
  },
  "actor": {"app_id": "support-bot", "user": "u-4821"},
  "src_endpoint": {"ip": "203.0.113.9"},
  "llm": {"endpoint": "/v1/chat/completions", "model": "gpt-4o-mini", "stream": true},
  "http_response": {"code": 200},
  "duration_ms": 1423.81,
  "upstream_ms": 1401.22,
  "prompt_chars": 5120,
  "completion_chars": 3089,
  "usage": {"prompt_tokens": 1280, "completion_tokens": 772, "total_tokens": 2052},
  "rule_ids": []
}
```

| Field | Meaning |
|-------|---------|
| `status` | Request outcome: `allowed`, `flagged`, `blocked_inbound`, `blocked_outbound`, `rate_limited`, `unauthorized`, `model_denied`, `bad_request`, `too_large`, `upstream_error`, `config_error`, `client_disconnect` |
| `duration_ms` | Total time in the gateway |
| `upstream_ms` | Time waiting on the upstream API (to the end of the stream, for streams) |
| `prompt_chars`, `completion_chars` | Inspected text sizes. Content is never included |
| `usage` | Token usage as reported by the upstream API |
| `rule_ids` | Every rule that fired on this request, including ones below `flag_at` |

## CEF

The syslog sink renders the same events as CEF:

```
CEF:0|PromptWarden|gateway|0.2.0|PW-H001|Instruction override attempt (ignore/disregard prior instructions)|4|act=block cs1=LLM01 cs1Label=owaspLlmTop10 cs2=AML.T0051 cs2Label=mitreAtlas cs3=support-bot cs3Label=appId externalId=f04b98ab-6a40-4de9-8642-dd212bb15bd4 src=203.0.113.9 msg=PromptWarden blocked: 1 detection(s), max severity 8
```

The signature ID and name come from the first finding. Header and extension
values are escaped per the CEF specification.

## Metrics

| Metric | Labels | Meaning |
|--------|--------|---------|
| `promptwarden_requests_total` | `app`, `endpoint`, `outcome` | Requests by outcome (same values as audit `status`) |
| `promptwarden_detections_total` | `rule_id`, `direction`, `disposition` | Detections, including those below `flag_at` |
| `promptwarden_inspection_seconds` | `direction` | Histogram of pipeline time per inspection |
| `promptwarden_upstream_seconds` | - | Histogram of upstream latency |
| `promptwarden_tokens_total` | `app`, `type` | Tokens reported by the upstream API |
| `promptwarden_events_emitted_total` | - | Events delivered to sinks |
| `promptwarden_events_dropped_total` | - | Events lost to a full queue |
| `promptwarden_uninspected_parts_total` | `app` | Images, audio and files passed without inspection |
| `promptwarden_policy_reloads_total` | `result` | `applied`, `unchanged`, `rejected` |
| `promptwarden_policy_info` | `hash`, `mode` | Always 1; identifies the loaded policy |
