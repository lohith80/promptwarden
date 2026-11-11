"""Rule catalog: every rule ID the gateway can emit, with framework mappings.

Detection engineers need this as data, not prose: to build coverage maps, to
write SIEM lookups, and to know what a rule ID in an alert means. Pattern
rules are read from the detector tables so the catalog cannot drift from the
code; functional rules are listed by hand and checked by the test suite.

    promptwarden rules --format json
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .detectors import heuristics, secrets


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    detector: str
    severity: int
    owasp_llm: str | None = None
    owasp_agentic: str | None = None
    atlas: str | None = None
    scope: str = "inbound, outbound"


_FUNCTIONAL: list[RuleInfo] = [
    RuleInfo("PW-H005", "Encoded payload with a decode instruction (encoding smuggling)",
             "heuristics", 7, "LLM01", None, "AML.T0051"),
    RuleInfo("PW-H006", "Invisible Unicode characters (tag block / zero-width)",
             "heuristics", 9, "LLM01", None, "AML.T0051"),
    RuleInfo("PW-H010", "Base64 payload that decodes to an injection",
             "heuristics", 9, "LLM01", None, "AML.T0051"),
    RuleInfo("PW-S006", "Payment card number (Luhn-valid)", "secrets", 9, "LLM02", None,
             "AML.T0057"),
    RuleInfo("PW-S007", "High-entropy token (possible credential)", "secrets", 5, "LLM02", None,
             "AML.T0057"),
    RuleInfo("PW-C001", "Canary token from the system prompt found in model output",
             "canary", 10, "LLM07", None, "AML.T0057", "outbound"),
    RuleInfo("PW-X001", "Reference-style markdown image beacon", "exfil", 8, "LLM05", None,
             "AML.T0057"),
    RuleInfo("PW-X002", "HTML image tag with query parameters", "exfil", 8, "LLM05", None,
             "AML.T0057"),
    RuleInfo("PW-X003", "Image URL outside the allowed image domains", "exfil", 8, "LLM05", None,
             "AML.T0057", "outbound"),
    RuleInfo("PW-T001", "Model requested a tool that policy denies", "tools", 9, "LLM06",
             "ASI02", "AML.T0053", "outbound tool calls"),
    RuleInfo("PW-T002", "Tool definition contains hidden or instruction-like content "
             "(tool poisoning)", "tools", 8, "LLM01", "ASI04", "AML.T0051.001",
             "inbound tool definitions"),
    RuleInfo("PW-T003", "Tool definition does not match its pinned hash (rug pull)",
             "tools", 9, "LLM03", "ASI04", "AML.T0010", "inbound tool definitions"),
    RuleInfo("PW-T004", "Tool definition changed since first seen (drift)", "tools", 6,
             "LLM03", "ASI04", "AML.T0010", "inbound tool definitions"),
    RuleInfo("PW-T005", "Tool is not pinned and policy requires pinned tools", "tools", 8,
             "LLM03", "ASI04", "AML.T0010", "inbound tool definitions"),
    RuleInfo("PW-G001", "Rate limit exceeded", "gateway", 5, "LLM10", None, "AML.T0034",
             "gateway"),
    RuleInfo("PW-G002", "Gateway authentication failed", "gateway", 5, None, None, None,
             "gateway"),
    RuleInfo("PW-G003", "Requested model is not on the app's model allowlist", "gateway", 6,
             "LLM10", None, None, "gateway"),
    RuleInfo("PW-G004", "Request refused because its content cannot be inspected", "gateway",
             6, None, None, None, "gateway"),
    RuleInfo("PW-G900", "Inspection engine error", "gateway", 10, None, None, None, "gateway"),
]


def rules() -> list[RuleInfo]:
    catalog: list[RuleInfo] = []
    for rule in heuristics.PATTERN_RULES:
        scope = ", ".join(rule.directions)
        if rule.sources is not None:
            scope = "tool results, documents"
        catalog.append(
            RuleInfo(rule.rule_id, rule.description, "heuristics", rule.severity,
                     rule.owasp_llm, rule.owasp_agentic, rule.atlas, scope)
        )
    for rule in secrets.SECRET_RULES:
        catalog.append(
            RuleInfo(rule.rule_id, rule.description, "secrets", rule.severity, "LLM02", None,
                     "AML.T0057")
        )
    catalog.extend(_FUNCTIONAL)
    return sorted(catalog, key=lambda info: info.rule_id)


def as_dicts() -> list[dict]:
    return [asdict(info) for info in rules()]
