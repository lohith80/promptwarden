"""Heuristic prompt-injection and jailbreak detection.

Pattern rules are intentionally conservative: each requires a trigger verb or
phrase plus contextual anchors within a bounded window, which keeps the false
positive rate near zero on benign traffic (see tests/corpus/benign.yaml).

Three layers sit on top of the raw patterns:

1. Normalization. Each text is also scanned in canonical form (invisible
   characters stripped, homoglyphs folded, leetspeak and dotted letters
   undone, tag-block text decoded). See promptwarden.normalize.
2. Decode-and-rescan. Base64 blobs that decode to readable text are scanned
   with the same rules, so a payload does not need the word "decode" next to
   it to be caught.
3. Source awareness. Text that arrived as tool output or as a document gets an
   extra rule for instructions addressed to the AI (indirect injection).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from ..normalize import count_invisible, normalize
from .base import INDIRECT_SOURCES, Detection, Direction


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    pattern: re.Pattern
    severity: int
    description: str
    owasp_llm: str
    atlas: str
    directions: tuple[Direction, ...] = ("inbound", "outbound")
    # When set, the rule only applies to text from these sources.
    sources: frozenset[str] | None = None
    owasp_agentic: str | None = None
    # Skip a match that is directly negated ("do not reveal your system
    # prompt" is a defensive instruction, not a probe).
    negatable: bool = False
    # Severity when the text is the caller's own turn. A user asking for an
    # image beacon in their own chat only "exfiltrates" what they can already
    # read; the same pattern in tool output or model output is the attack.
    user_severity: int | None = None
    # Lowercase substrings, at least one of which must be present before the
    # regex is tried. A plain substring test is far cheaper than a large
    # alternation, and inspection time is on the request path.
    prefilter: tuple[str, ...] = ()


_AI_ENTITY = (
    r"(?:ai(?:\s+(?:assistant|agent|model|system|bot))?|a\.i\.|llm|(?:large\s+)?language\s+model"
    r"|chatbot|copilot|gpt)s?"
)

PATTERN_RULES: list[PatternRule] = [
    PatternRule(
        rule_id="PW-H001",
        pattern=re.compile(
            r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(previous|prior|above|earlier|system)\b[^.\n]{0,40}"
            r"\b(instructions?|prompts?|rules?|directives?)\b"
        ),
        severity=8,
        description="Instruction override attempt (ignore/disregard prior instructions)",
        owasp_llm="LLM01",
        atlas="AML.T0051",
    ),
    PatternRule(
        rule_id="PW-H002",
        pattern=re.compile(
            r"(?i)\b(reveal|show|print|repeat|output|display|leak)\b[^.\n]{0,60}"
            r"\b(system|initial|hidden|original)\b[^.\n]{0,20}"
            r"\b(prompt|instructions?|message)\b"
        ),
        severity=8,
        description="System prompt exfiltration probe",
        owasp_llm="LLM07",
        atlas="AML.T0056",
        negatable=True,
    ),
    PatternRule(
        rule_id="PW-H003",
        pattern=re.compile(
            r"(?i)(\bact\s+as\s+(if\s+you\s+are\s+)?an?\s+(unrestricted|unfiltered|jailbroken)\b"
            r"|\bpretend\s+(you\s+are|to\s+be)\b[^.\n]{0,40}\bwithout\s+(any\s+)?"
            r"(rules|restrictions|filters|guidelines)\b"
            r"|\byou\s+are\s+now\s+(free\s+of|no\s+longer\s+bound|dan\b|in\s+developer\s+mode))"
        ),
        severity=7,
        description="Role/persona override toward an unrestricted assistant",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H004",
        pattern=re.compile(
            r"(?i)(\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bdeveloper\s+mode\s+enabled\b"
            r"|\bjailbreak(s|ing|en)?\b)"
        ),
        severity=7,
        description="Known jailbreak vocabulary (DAN / developer mode / jailbreak)",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H007",
        pattern=re.compile(
            r"(?i)(\bnever\s+(refuse|say\s+no|apologi[sz]e)\b"
            r"|\bwithout\s+(any\s+)?(warnings?|disclaimers?|refusals?)\b)"
        ),
        severity=6,
        description="Refusal-suppression instruction",
        owasp_llm="LLM01",
        atlas="AML.T0054",
    ),
    PatternRule(
        rule_id="PW-H009",
        pattern=re.compile(r"!\[[^\]]*\]\(https?://[^\s)]*[?&][^\s)]+\)"),
        severity=8,
        description="Markdown image beacon with query parameters (data exfiltration channel)",
        owasp_llm="LLM05",
        atlas="AML.T0057",
        user_severity=5,
    ),
    PatternRule(
        rule_id="PW-H011",
        pattern=re.compile(
            r"(?i)("
            # Spanish
            r"\b(ignora|ignore|olvida|omite|descarta)\b[^.\n]{0,40}"
            r"\b(instrucciones|indicaciones|reglas)\b[^.\n]{0,20}\b(anteriores|previas)\b"
            # French (imperative forms only)
            r"|\b(ignore|ignorez|oublie|oubliez)\b[^.\n]{0,40}"
            r"\b(instructions|consignes|règles)\b[^.\n]{0,20}"
            r"\b(précédentes|precedentes|antérieures|ci-dessus)\b"
            # German
            r"|\b(ignoriere|ignorieren\s+sie|vergiss|missachte)\b[^.\n]{0,40}"
            r"\b(vorherigen?|vorigen?|bisherigen?|obigen?|früheren?)\b[^.\n]{0,20}"
            r"\b(anweisungen|instruktionen|regeln|befehle)\b"
            # Portuguese
            r"|\b(ignore|ignora|esqueça|esqueca|desconsidere)\b[^.\n]{0,40}"
            r"\b(instruções|instrucoes|regras)\b[^.\n]{0,20}\b(anteriores|prévias|previas)\b"
            # Italian
            r"|\b(ignora|dimentica)\b[^.\n]{0,40}\b(istruzioni|regole)\b[^.\n]{0,20}"
            r"\bprecedenti\b"
            # Russian
            r"|(игнорируй(те)?|забудь(те)?)[^.\n]{0,40}(предыдущие|прежние|все)"
            r"[^.\n]{0,20}(инструкции|указания|правила)"
            # Chinese
            r"|(忽略|无视|忘记|忽視|無視|忘記)[^。\n]{0,12}(之前|以上|先前|前面|上述|所有)"
            r"[^。\n]{0,8}(指令|指示|提示|说明|說明|规则|規則)"
            # Japanese
            r"|(以前|これまで|上記|前)の[^。\n]{0,8}(指示|命令|指令|ルール)[^。\n]{0,6}(無視|忘れ)"
            # Korean
            r"|(이전|위의|앞의)[^.\n]{0,10}(지시|명령|지침)[^.\n]{0,10}(무시|잊어)"
            r")"
        ),
        severity=8,
        description="Instruction override attempt in a non-English language",
        owasp_llm="LLM01",
        atlas="AML.T0051",
        prefilter=(
            "ignora", "ignore", "olvida", "omite", "descarta", "oublie", "ignoriere",
            "ignorieren", "vergiss", "missachte", "esqueça", "esqueca", "desconsidere",
            "dimentica", "игнорируй", "забудь", "忽略", "无视", "忘记", "忽視", "無視", "忘記",
            "忘れ", "무시", "잊어",
        ),
    ),
    PatternRule(
        rule_id="PW-H012",
        # Text that addresses an AI system directly. The entity has to be
        # unambiguous ("AI assistant", "LLM", "language model"): a bare
        # "assistant" or "agent" is usually a person in tickets and email.
        pattern=re.compile(
            r"(?i)(\b(attention|note|notice|important|instructions?|message)\b[^.\n]{0,20}"
            r"\b(for|to)\s+(the\s+|any\s+|all\s+)?" + _AI_ENTITY + r"\b"
            r"|\b" + _AI_ENTITY + r"\s*[,:]\s*(please\s+)?(you\s+)?"
            r"(must|should|shall|need\s+to|have\s+to|are\s+required\s+to|ignore|send|forward"
            r"|disregard|reveal|include|append)\b"
            r"|\b" + _AI_ENTITY + r"\b[^.\n]{0,30}"
            r"\b(reading|processing|summari[sz]ing|parsing|viewing|analy[sz]ing)\s+this\b"
            r"|\bif\s+you\s+are\s+an?\s+" + _AI_ENTITY + r"\b"
            r"|\b" + _AI_ENTITY + r"\b[^.\n]{0,12}"
            r"\byou\s+(must|should|shall|need\s+to|have\s+to)\b)"
        ),
        severity=7,
        description="Instruction addressed to the AI inside tool output or a document",
        owasp_llm="LLM01",
        atlas="AML.T0051.001",
        sources=INDIRECT_SOURCES,
        owasp_agentic="ASI01",
    ),
]

_NEGATION = re.compile(
    r"(?i)\b(never|not|don'?t|cannot|can'?t|won'?t|shouldn'?t|mustn'?t|refuse\s+to)\s+"
    r"(ever\s+)?(to\s+)?$"
)

# Policy-evasion language. Each phrase alone is too common to act on (role-play
# prompts say "stay in character" all the time); several different ones in the
# same prompt is the signature of a persona jailbreak. Chosen and thresholded
# on the dev half of a public in-the-wild dataset; see the README benchmark.
_EVASION_SIGNALS: list[tuple[tuple[str, ...], re.Pattern]] = [
    (prefilter, re.compile(pattern))
    for prefilter, pattern in (
        (("character",),
         r"(?i)\b(stay|remain)\s+in\s+character\b|\bnever\s+break\s+character\b"
         r"|\bbreak(ing)?\s+character\b"),
        (("restriction", "limitation", "filter", "censorship", "boundaries", "guidelines"),
         r"(?i)\b(no|without(\s+any)?|free\s+(of|from)(\s+all|\s+any)?)\s+"
         r"(restrictions?|limitations?|filters?|censorship|boundaries|ethical\s+guidelines"
         r"|moral\s+guidelines)\b"),
        (("bound", "restricted", "limited", "constrained"),
         r"(?i)\b(not|no\s+longer|isn'?t|aren'?t)\s+(bound|restricted|limited|constrained)"
         r"\s+by\b"),
        (("polic", "openai", "open ai"),
         r"(?i)\b(openai'?s?|open\s+ai'?s?)\s+(content\s+)?(policy|policies|guidelines|rules)\b"
         r"|\bcontent\s+polic(y|ies)\b"),
        (("unfiltered", "uncensored", "unrestricted", "amoral"),
         r"(?i)\b(unfiltered|uncensored|unrestricted|amoral)\b"),
        (("ethic", "moral", "legal"),
         r"(?i)\b(no|without(\s+any)?|disregard(s|ing)?|ignor(e|es|ing))\s+"
         r"(ethic(s|al)?|moral(s|ity)?|legal(ity)?)\b"),
        (("illegal", "unethical", "immoral", "harmful"),
         r"(?i)\b(illegal|unethical|immoral|harmful)\s*(or|and|,)\s*"
         r"(illegal|unethical|immoral|harmful|explicit)\b"),
        (("refuse", "decline", "reject", "deny"),
         r"(?i)\b(never|not|cannot|can'?t|won'?t|will\s+not|does\s+not|doesn'?t)\s+"
         r"(refuse|decline|reject|deny)\b"),
        (("matter",),
         r"(?i)\bno\s+matter\s+how\s+(immoral|unethical|illegal|dangerous|harmful|explicit"
         r"|offensive)\b"),
        (("follow", "abide", "adhere", "obey", "care"),
         r"(?i)\b(does(n'?t|\s+not)|do(n'?t|\s+not)|never)\s+(have\s+to\s+)?"
         r"(follow|abide\s+by|adhere\s+to|obey|care\s+about)\s+(any\s+|the\s+|openai'?s?\s+)?"
         r"(rules|guidelines|polic(y|ies)|restrictions|laws|ethics)\b"),
        (("answer", "respond", "comply", "anything", "do "),
         r"(?i)\b(answer|respond\s+to|comply\s+with|do)\s+(any|every|all)\s*"
         r"(thing|request|question|prompt)s?\b|\bcan\s+do\s+anything\b"),
        (("warning", "disclaimer", "moral", "ethical"),
         r"(?i)\b(no|without|never|don'?t|do\s+not)\s+(include\s+|add\s+|give\s+)?(any\s+)?"
         r"(warnings?|disclaimers?|moral(izing)?|ethical\s+advice)\b"),
        (("freed", "liberated", "broken", "escaped"),
         r"(?i)\b(freed|liberated|broken\s+free|escaped)\s+(from|of)\b"),
        (("pretend", "roleplay", "role-play", " act"),
         r"(?i)\b(you\s+are\s+going\s+to|you\s+will|you'?re\s+going\s+to)\s+"
         r"(pretend|act|roleplay|role-play)\b"),
        (("from now",),
         r"(?i)\bfrom\s+now\s+on,?\s+you\s+(are|will|must|shall)\b"),
    )
]
EVASION_THRESHOLD = 3

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{80,}")
_DECODE_HINT = re.compile(r"(?i)\b(decode|base64|rot13|hex)\b")

# Candidates for decode-and-rescan. Bounded so a hostile body cannot turn the
# decoder into a CPU sink.
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_MAX_B64_CANDIDATES = 8
_MAX_B64_LEN = 8192

INVISIBLE_THRESHOLD = 5


def _decode_candidate(blob: str) -> str | None:
    """Decode a base64 candidate; return it only if it is readable text."""
    blob = blob[:_MAX_B64_LEN].replace("-", "+").replace("_", "/")
    blob = blob.rstrip("=")
    blob += "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 12:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    if printable / len(text) < 0.95 or " " not in text:
        return None
    return text


def _match_rules(
    text: str, direction: Direction, source: str | None, skip: set[str]
) -> list[tuple[PatternRule, re.Match]]:
    hits: list[tuple[PatternRule, re.Match]] = []
    lowered = text.lower()
    for rule in PATTERN_RULES:
        if rule.rule_id in skip or direction not in rule.directions:
            continue
        if rule.sources is not None and source not in rule.sources:
            continue
        if rule.prefilter and not any(word in lowered for word in rule.prefilter):
            continue
        match = rule.pattern.search(text)
        if match and rule.negatable:
            match = next(
                (m for m in rule.pattern.finditer(text)
                 if not _NEGATION.search(text[max(0, m.start() - 24):m.start()])),
                None,
            )
        if match:
            hits.append((rule, match))
    return hits


def _detection(rule: PatternRule, evidence: str, source: str | None = None, *,
               obfuscated: bool = False) -> Detection:
    description = rule.description
    tags: list[str] = []
    if obfuscated:
        description += " (revealed after de-obfuscation)"
        tags = ["obfuscated", "AML.T0068"]
    severity = rule.severity
    if rule.user_severity is not None and source == "user":
        severity = rule.user_severity
    return Detection(
        detector="heuristics",
        rule_id=rule.rule_id,
        severity=severity,
        confidence=0.8,
        description=description,
        evidence=evidence,
        owasp_llm=rule.owasp_llm,
        atlas=rule.atlas,
        owasp_agentic=rule.owasp_agentic,
        tags=tags,
    )


def scan(text: str, direction: Direction, source: str | None = None) -> list[Detection]:
    detections: list[Detection] = []
    fired: set[str] = set()

    for rule, match in _match_rules(text, direction, source, fired):
        fired.add(rule.rule_id)
        detections.append(_detection(rule, match.group(0), source))

    # Layer 1: canonical variants. Only rules that did not fire on the raw
    # text are tried, so a hit here means the obfuscation was load-bearing.
    for variant in normalize(text):
        for rule, match in _match_rules(variant, direction, source, fired):
            fired.add(rule.rule_id)
            detections.append(_detection(rule, match.group(0), source, obfuscated=True))

    # A long blob next to a decode instruction, where the blob decodes to
    # readable text. Binary payloads (images, keys) pasted alongside the word
    # "base64" are everyday developer traffic and do not fire.
    blob = None
    if _DECODE_HINT.search(text):
        for index, candidate in enumerate(_BASE64_BLOB.finditer(text)):
            if index >= _MAX_B64_CANDIDATES:
                break
            if _decode_candidate(candidate.group(0)) is not None:
                blob = candidate
                break
    if blob:
        detections.append(
            Detection(
                detector="heuristics",
                rule_id="PW-H005",
                severity=7,
                confidence=0.7,
                description="Encoded payload with a decode instruction (encoding smuggling)",
                evidence=blob.group(0),
                owasp_llm="LLM01",
                atlas="AML.T0051",
                tags=["AML.T0068"],
            )
        )

    # Layer 2: decode-and-rescan.
    for index, candidate in enumerate(_B64_CANDIDATE.finditer(text)):
        if index >= _MAX_B64_CANDIDATES:
            break
        decoded = _decode_candidate(candidate.group(0))
        if decoded is None:
            continue
        inner = _match_rules(decoded, direction, source, set())
        if not inner:
            for variant in normalize(decoded):
                inner = _match_rules(variant, direction, source, set())
                if inner:
                    break
        if inner:
            rule, match = inner[0]
            detections.append(
                Detection(
                    detector="heuristics",
                    rule_id="PW-H010",
                    severity=9,
                    confidence=0.9,
                    description=(
                        f"Base64 payload decodes to an injection ({rule.rule_id}: "
                        f"{rule.description})"
                    ),
                    evidence=match.group(0),
                    owasp_llm="LLM01",
                    atlas="AML.T0051",
                    tags=["obfuscated", "AML.T0068", rule.rule_id],
                )
            )
            break

    if direction == "inbound":
        lowered = text.lower()
        signals = [
            match.group(0)
            for prefilter, pattern in _EVASION_SIGNALS
            if any(word in lowered for word in prefilter) and (match := pattern.search(text))
        ]
        if len(signals) >= EVASION_THRESHOLD:
            detections.append(
                Detection(
                    detector="heuristics",
                    rule_id="PW-H013",
                    severity=7 if len(signals) >= 5 else 6,
                    confidence=min(0.5 + 0.08 * len(signals), 0.9),
                    description=(
                        f"Stacked policy-evasion language ({len(signals)} distinct signals): "
                        "persona jailbreak"
                    ),
                    evidence="; ".join(signals)[:80],
                    owasp_llm="LLM01",
                    atlas="AML.T0054",
                )
            )

    invisible = count_invisible(text)
    if invisible >= INVISIBLE_THRESHOLD:
        detections.append(
            Detection(
                detector="heuristics",
                rule_id="PW-H006",
                severity=9,
                confidence=0.9,
                description=(
                    f"{invisible} invisible Unicode characters "
                    "(tag block / zero-width): hidden-instruction channel"
                ),
                evidence="",
                owasp_llm="LLM01",
                atlas="AML.T0051",
                tags=["AML.T0068"],
            )
        )

    return detections
