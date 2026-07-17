# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

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
