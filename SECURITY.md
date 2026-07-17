# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please report vulnerabilities privately via **GitHub Security Advisories**
(Security tab → "Report a vulnerability") or by email to
**indulohithnarisetty@gmail.com** with subject `[promptwarden security]`.

- You will receive an acknowledgment within 72 hours.
- Target fix window: 90 days from triage, faster for critical issues.
- Please do not open public issues for security reports.
- Credit is given in the changelog and advisory unless you request otherwise.

## Scope Notes

PromptWarden is a detection layer, not a guarantee. Bypasses of individual
heuristic rules are expected and welcome as *detection-gap reports* (open a
regular issue with the payload); vulnerabilities in the gateway itself
(auth-header leakage, event-pipeline injection, DoS below the documented
limits, sandbox escapes) are security reports and belong in the private
channel above.
