"""Rendered-content exfiltration channels in model output.

A chat client that auto-fetches images turns any image URL the model emits
into a zero-click exfiltration channel: the attacker's injected instruction
makes the model put conversation data in the query string, and the client
delivers it. PW-H009 covers the inline markdown form. This detector covers
the variants that slip past it (reference-style markdown, raw HTML) and adds
a deterministic control: an allowlist of domains images may load from.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..config import ExfilConfig
from .base import Detection, Direction

# ![alt][ref] ... [ref]: https://host/path?data
_REF_IMAGE_USE = re.compile(r"!\[[^\]\n]*\]\s?\[[^\]\n]*\]")
_REF_DEFINITION = re.compile(r"(?m)^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*<?(https?://[^\s>]+)")
_HTML_IMAGE = re.compile(r"(?i)<img\b[^>]{0,200}?\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)")
_INLINE_IMAGE = re.compile(r"!\[[^\]\n]*\]\(\s*<?(https?://[^\s)>]+)")

_HAS_QUERY = re.compile(r"[?&][^=\s]+=")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _allowed(host: str, domains: list[str]) -> bool:
    for domain in domains:
        domain = domain.lower().lstrip(".")
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _detection(rule_id: str, description: str, evidence: str, confidence: float) -> Detection:
    return Detection(
        detector="exfil",
        rule_id=rule_id,
        severity=8,
        confidence=confidence,
        description=description,
        evidence=evidence,
        owasp_llm="LLM05",
        atlas="AML.T0057",
    )


def scan(text: str, direction: Direction, config: ExfilConfig) -> list[Detection]:
    if "http" not in text:
        return []
    detections: list[Detection] = []

    ref_urls = [m.group(1) for m in _REF_DEFINITION.finditer(text)]
    html_urls = [m.group(1) for m in _HTML_IMAGE.finditer(text)]
    has_ref_image = bool(_REF_IMAGE_USE.search(text))

    if has_ref_image:
        beacon = next((url for url in ref_urls if _HAS_QUERY.search(url)), None)
        if beacon:
            detections.append(
                _detection(
                    "PW-X001",
                    "Reference-style markdown image beacon (data exfiltration channel)",
                    beacon,
                    0.8,
                )
            )

    beacon = next((url for url in html_urls if _HAS_QUERY.search(url)), None)
    if beacon:
        detections.append(
            _detection(
                "PW-X002",
                "HTML image tag with query parameters (data exfiltration channel)",
                beacon,
                0.8,
            )
        )

    if direction == "outbound" and config.allowed_image_domains:
        image_urls = [m.group(1) for m in _INLINE_IMAGE.finditer(text)] + html_urls
        if has_ref_image:
            image_urls += ref_urls
        for url in image_urls:
            host = _host(url)
            if not _allowed(host, config.allowed_image_domains):
                detections.append(
                    _detection(
                        "PW-X003",
                        "Image URL outside the allowed image domains",
                        host or url,
                        1.0,
                    )
                )
                break

    return detections
