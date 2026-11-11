# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Security fixes only until 2027-02-28 |

## Reporting a vulnerability

Please report vulnerabilities privately via **GitHub Security Advisories**
(Security tab, then "Report a vulnerability") or by email to
**indulohithnarisetty@gmail.com** with subject `[promptwarden security]`.

- You will receive an acknowledgment within 72 hours.
- Target fix window: 90 days from triage, faster for critical issues.
- Please do not open public issues for security reports.
- Credit is given in the changelog and advisory unless you request otherwise.

## What counts as a vulnerability

PromptWarden is a detection layer, not a guarantee. The line between a
detection gap and a vulnerability:

**Detection gaps (public issue, with the payload).** A prompt, tool
definition or model output that a rule should catch and does not. These are
expected, welcome, and tracked in the open: see
`tests/corpus/known_limits.yaml`.

**Vulnerabilities (private report).** A flaw in the gateway itself, for
example:

- a gateway key or provider key reaching the upstream API, an event, a log
  line or another tenant
- authentication or per-app policy bypass (acting as another app, escaping
  monitor or enforce mode, exceeding a rate limit by more than the documented
  per-replica factor)
- a streamed response releasing a match shorter than `holdback_chars`
- a blocked tool call still reaching the client
- event forgery or field injection through request content
- denial of service below the documented limits (a small body that takes
  seconds to inspect is a vulnerability; send the body)
- a policy that validates but is applied differently from how it reads

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the residual risks that
are already known and accepted.
