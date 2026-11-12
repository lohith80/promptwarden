# Deployment guide

How to put PromptWarden in front of real traffic without breaking it, and how
to run it afterwards.

## Rollout plan

Blocking controls that go live on day one get bypassed on day two. Use the
modes the gateway gives you.

1. **Shadow.** Deploy with `gateway.mode: monitor`, `audit.enabled: true`
   and `auth.required: true`. Move one application's `base_url` to the
   gateway. Nothing is blocked; the SIEM starts receiving findings with
   `disposition: would_block`.
2. **Review.** After one to two weeks, run the "Shadow Mode Rollout Report"
   search. Each row is an attack or a false positive. Tune with thresholds
   (`block_at`, `flag_at`), `inspection.trusted_roles`, tool pins, and
   denylist rules. `promptwarden bench` scores a labeled sample of your own
   traffic.
3. **Enforce per app.** Set `mode: enforce` on one app at a time under
   `apps:`. Keep the global default at monitor until every app is switched.
4. **Tighten.** Turn on `tools.require_pinned` for agents, set
   `detectors.exfil.allowed_image_domains`, add per-app
   `limits.allowed_models` and rate limits, set `expose_detections: false`
   for apps whose errors reach end users.

## Onboarding an application

Create a key:

```bash
promptwarden keygen --app support-bot
```

Add the printed entry to the policy, and put the provider key in an
environment variable on the gateway (a Kubernetes Secret, never the policy
file):

```yaml
apps:
  - id: support-bot
    key_hashes: ["sha256:..."]
    upstream_key_env: UPSTREAM_KEY_SUPPORT_BOT
    mode: monitor
    limits:
      requests_per_minute: 300
      allowed_models: ["gpt-4o-mini"]
```

The application changes two settings and no code:

```python
from openai import OpenAI

client = OpenAI(base_url="https://promptwarden.internal.example.com/v1",
                api_key="pw_...")
```

To revoke an app, remove its hash and reload. To rotate, add the new hash,
deploy the new key to the app, then remove the old hash: `key_hashes` is a
list so both work during the overlap.

## Agents and MCP tools

Export the tool list your agent sends to the model (an OpenAI `tools` array,
or the JSON result of an MCP `tools/list` call) and scan it:

```bash
promptwarden scan --tools tools.json
```

Pin what you approved:

```bash
promptwarden tool-hash tools.json
```

Paste the output under `tools.pinned` (globally or per app) and set
`require_pinned: true`. From then on:

- a changed definition is blocked with PW-T003 before the model reads it,
- a new tool nobody approved is blocked with PW-T005,
- a pinned definition is not rescanned, so a PW-T002 finding on a tool you
  have reviewed and trust is silenced by pinning it.

Run both commands in the CI pipeline of the repository that owns the agent,
so a tool change is a reviewed diff of hashes.

Deny dangerous tools outright with `tools.denied` (glob patterns). A denied
call is removed from the model's response, so the client never executes it.

## Kubernetes

Manifests are in [`deploy/kubernetes`](../deploy/kubernetes):

```bash
kubectl apply -k deploy/kubernetes
```

Before applying, replace the image reference (pin by digest), the example key
hash in the ConfigMap, the Splunk URL, and create the `promptwarden-secrets`
Secret from your secret manager (`secret.example.yaml` shows the keys).

What the manifests give you:

- Pod Security "restricted": non-root UID 10001, read-only root filesystem,
  all capabilities dropped, seccomp `RuntimeDefault`, no service account
  token.
- Readiness on `/readyz`, liveness on `/healthz`.
- A NetworkPolicy that denies by default. Only namespaces labeled
  `promptwarden.io/client: "true"` can reach the gateway; egress is DNS plus
  TLS to non-private addresses. Replace the egress block with an FQDN policy
  or an egress gateway if your CNI supports it.
- Two replicas spread across nodes, a PodDisruptionBudget, and a CPU-based
  HorizontalPodAutoscaler.
- Policy from a ConfigMap, picked up without a restart through
  `PW_POLICY_RELOAD_SECONDS`. An invalid ConfigMap is rejected; the pods keep
  the previous policy and `promptwarden_policy_reloads_total{result="rejected"}`
  increments.

Put TLS in front (ingress controller or service mesh). The gateway speaks
plain HTTP and should never be reachable from outside the cluster without it.
Set `PW_TRUSTED_PROXY_HOPS` to the number of proxies in front so events carry
the real client address.

## Sizing

Inspection is CPU-bound and runs on the request path.

| Input | Cost |
|-------|------|
| Plain text, default policy | about 0.3 ms per 1,000 characters |
| Hostile text built to exercise the rules | up to about 1.6 ms per 1,000 characters (1.6 s for 1 MB) |
| Window-mode stream | about 12 inspection passes over a 560-character window per 600 characters streamed |

Hostile text built to exercise the rules costs more, and is bounded: every
rule is linear, and bodies of 32 KB and above are inspected on a worker
thread so the event loop keeps serving other connections. See the threat
model (T4) for the measured worst case.

One process handles inspection on one core. Start with `--workers` equal to
the CPU request, or one worker per pod and more pods (simpler, and what the
HPA manifest assumes). Lower `gateway.max_body_bytes` if your applications
never send large contexts: it bounds worst-case inspection time.

Memory is flat: one worker measured about 60 MB resident, before and after
load. The event queue holds up to `PW_EVENT_QUEUE_SIZE` events (default
10,000), which is the main thing that can grow it.

## State and high availability

The gateway keeps two things in memory, per process:

- **Rate limit buckets.** With N replicas (or workers) the effective limit is
  N times `requests_per_minute`. Divide the configured value accordingly, or
  enforce a global limit at the ingress.
- **Tool drift memory (PW-T004).** Resets on restart and is not shared. Pins
  in policy (PW-T003) are the durable control and work identically on every
  replica.

Everything else is stateless. Any replica can serve any request, and a
replica can be killed at any time. Queued events not yet delivered are lost
when a pod dies without a graceful shutdown; a graceful shutdown flushes for
up to five seconds.

## Telemetry

| Destination | Setting | Notes |
|-------------|---------|-------|
| Splunk | `PW_HEC_URL`, `PW_HEC_TOKEN` | `sourcetype=promptwarden`; saved searches in `dashboards/splunk` |
| Microsoft Sentinel | `PW_EVENT_LOG` plus Azure Monitor Agent, or `PW_WEBHOOK_URL` to an ingestion proxy | KQL in `dashboards/sentinel` assumes a custom table with the event in `RawData` |
| QRadar, ArcSight | `PW_SYSLOG_ADDR` | CEF over UDP or TCP syslog |
| Elastic, Cribl, Chronicle | `PW_WEBHOOK_URL`, `PW_WEBHOOK_TOKEN` | JSON array of events per POST |
| Prometheus | `/metrics` | Alert rules in `dashboards/prometheus/alerts.yaml` |

Field reference: [EVENT_SCHEMA.md](EVENT_SCHEMA.md).

Alert on `promptwarden_events_dropped_total`. A gateway that is blocking
attacks nobody hears about is the failure mode this project exists to avoid.

## Operations

| Task | How |
|------|-----|
| Check a policy before deploying | `promptwarden validate-policy policy.yaml --check-env` |
| Apply a policy change | Update the file or ConfigMap; reload happens on the poll interval or on `SIGHUP` |
| Confirm what is running | `GET /readyz` returns the policy hash, mode and sink list |
| Rotate a canary | `promptwarden canary`, add the new token to `detectors.canary.tokens` and the system prompt, remove the old one after rollout |
| Investigate a block | Search the SIEM for the `request_id` returned to the client (`metadata.uid`) |
| Emergency: stop blocking | Set `gateway.mode: monitor` and reload. Detection and telemetry continue |

## Upgrading from 0.1

- `stream: true` requests are now streamed. Clients that depended on the
  silent downgrade to JSON should stop sending `stream: true`.
- System and developer messages are trusted by default. If your gateway
  clients are untrusted, set `inspection.trusted_roles: []`.
- The policy schema is strict. Run `promptwarden validate-policy` on your
  existing file; unknown keys that v0.1 ignored are now errors.
- Run the container with `promptwarden serve`. The old
  `uvicorn promptwarden.app:app` command still works.
- Events gained fields and kept all existing ones; v0.1 searches continue to
  work.
