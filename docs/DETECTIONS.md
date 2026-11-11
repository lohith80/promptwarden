# Detection catalog

Every rule ID PromptWarden can emit, with its framework mappings. This file is
generated from the code and checked in CI, so it cannot drift. Regenerate it
after adding or changing a rule:

```bash
python scripts/gen_detections_doc.py
```

The same data as JSON, for SIEM lookups and coverage maps:

```bash
promptwarden rules --format json
```

Severity is on the policy scale (1-10): with default thresholds, 8 and above
blocks and 5 to 7 flags. Operator denylist rules (`PW-D*`) are defined in
policy and are not listed here.

Frameworks: OWASP Top 10 for LLM Applications 2025 (`LLM01`..`LLM10`), OWASP
Top 10 for Agentic Applications 2026 (`ASI01`..`ASI10`), MITRE ATLAS
(`AML.T*`). Detections found after de-obfuscation also carry the tag
`AML.T0068` (LLM Prompt Obfuscation); injections found in tool results or
documents are reported as `AML.T0051.001` (indirect); secrets or canaries
found in tool-call arguments are reported as `AML.T0086` (exfiltration via
agent tool invocation).

<!-- rules:start -->
| Rule | Detects | Severity | OWASP LLM | OWASP Agentic | MITRE ATLAS | Scope |
|------|---------|----------|-----------|---------------|-------------|-------|
| PW-C001 | Canary token from the system prompt found in model output | 10 | LLM07 | - | AML.T0057 | outbound |
| PW-G001 | Rate limit exceeded | 5 | LLM10 | - | AML.T0034 | gateway |
| PW-G002 | Gateway authentication failed | 5 | - | - | - | gateway |
| PW-G003 | Requested model is not on the app's model allowlist | 6 | LLM10 | - | - | gateway |
| PW-G004 | Request refused because its content cannot be inspected | 6 | - | - | - | gateway |
| PW-G900 | Inspection engine error | 10 | - | - | - | gateway |
| PW-H001 | Instruction override attempt (ignore/disregard prior instructions) | 8 | LLM01 | - | AML.T0051 | inbound, outbound |
| PW-H002 | System prompt exfiltration probe | 8 | LLM07 | - | AML.T0056 | inbound, outbound |
| PW-H003 | Role/persona override toward an unrestricted assistant | 7 | LLM01 | - | AML.T0054 | inbound, outbound |
| PW-H004 | Known jailbreak vocabulary (DAN / developer mode / jailbreak) | 7 | LLM01 | - | AML.T0054 | inbound, outbound |
| PW-H005 | Encoded payload with a decode instruction (encoding smuggling) | 7 | LLM01 | - | AML.T0051 | inbound, outbound |
| PW-H006 | Invisible Unicode characters (tag block / zero-width) | 9 | LLM01 | - | AML.T0051 | inbound, outbound |
| PW-H007 | Refusal-suppression instruction | 6 | LLM01 | - | AML.T0054 | inbound, outbound |
| PW-H009 | Markdown image beacon with query parameters (data exfiltration channel) | 8 | LLM05 | - | AML.T0057 | inbound, outbound |
| PW-H010 | Base64 payload that decodes to an injection | 9 | LLM01 | - | AML.T0051 | inbound, outbound |
| PW-H011 | Instruction override attempt in a non-English language | 8 | LLM01 | - | AML.T0051 | inbound, outbound |
| PW-H012 | Instruction addressed to the AI inside tool output or a document | 7 | LLM01 | ASI01 | AML.T0051.001 | tool results, documents |
| PW-H013 | Stacked policy-evasion language (persona jailbreak) | 6 | LLM01 | - | AML.T0054 | inbound |
| PW-S001 | AWS access key ID | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S002 | Private key material | 10 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S003 | API secret key (sk- prefix) | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S004 | JSON Web Token | 7 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S005 | US Social Security Number (formatted) | 8 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S006 | Payment card number (Luhn-valid) | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S007 | High-entropy token (possible credential) | 5 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S008 | GitHub access token | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S009 | Slack token | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S010 | Google API key | 8 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S011 | Stripe live secret key | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-S012 | Azure storage account key | 9 | LLM02 | - | AML.T0057 | inbound, outbound |
| PW-T001 | Model requested a tool that policy denies | 9 | LLM06 | ASI02 | AML.T0053 | outbound tool calls |
| PW-T002 | Tool definition contains hidden or instruction-like content (tool poisoning) | 8 | LLM01 | ASI04 | AML.T0051.001 | inbound tool definitions |
| PW-T003 | Tool definition does not match its pinned hash (rug pull) | 9 | LLM03 | ASI04 | AML.T0010 | inbound tool definitions |
| PW-T004 | Tool definition changed since first seen (drift) | 6 | LLM03 | ASI04 | AML.T0010 | inbound tool definitions |
| PW-T005 | Tool is not pinned and policy requires pinned tools | 8 | LLM03 | ASI04 | AML.T0010 | inbound tool definitions |
| PW-X001 | Reference-style markdown image beacon | 8 | LLM05 | - | AML.T0057 | inbound, outbound |
| PW-X002 | HTML image tag with query parameters | 8 | LLM05 | - | AML.T0057 | inbound, outbound |
| PW-X003 | Image URL outside the allowed image domains | 8 | LLM05 | - | AML.T0057 | outbound |
<!-- rules:end -->
