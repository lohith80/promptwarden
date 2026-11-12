"""Linear-time extraction of image references from markdown and HTML.

These used to be regular expressions of the form `!\\[[^\\]]*\\]\\(...`. That
shape is quadratic: on a body made of repeated `![`, every opener rescans the
rest of the text looking for a `]` that never comes, and a 500 KB request
held a worker for over a minute. Inspection runs on the request path, so a
slow pattern is a denial of service against the gateway itself.

The scanners below walk the text with str.find and bounded lookahead. Each
opener costs at most a fixed number of characters, whatever follows it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

MAX_ALT_CHARS = 300
MAX_URL_CHARS = 2048
MAX_TAG_CHARS = 400

# The URL stops at a square bracket. Without that, in a body of back-to-back
# image openers every URL scan would run on through the following openers.
_URL_AFTER_PAREN = re.compile(rf"[ \t]{{0,4}}<?(https?://[^\s)>\[\]]{{1,{MAX_URL_CHARS}}})")
_IMG_OPEN = re.compile(r"(?i)<img\b")
_IMG_SRC = re.compile(
    rf"(?i)\bsrc\s{{0,4}}=\s{{0,4}}[\"']?(https?://[^\s\"'>]{{1,{MAX_URL_CHARS}}})"
)

def has_query(url: str) -> bool:
    """True when the URL carries anything after a ? or &. Deliberately loose:
    data can ride in a bare query string as easily as in name=value pairs."""
    cut = min((i for i in (url.find("?"), url.find("&")) if i != -1), default=-1)
    return cut != -1 and cut + 1 < len(url)


def _alt_end(text: str, start: int) -> int:
    """Index of the ] closing an image alt text opened at start, or -1."""
    close = text.find("]", start, start + MAX_ALT_CHARS + 1)
    if close == -1:
        return -1
    newline = text.find("\n", start, close)
    return -1 if newline != -1 else close


def inline_images(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, url) for each ![alt](url) in text."""
    position = text.find("![")
    while position != -1:
        close = _alt_end(text, position + 2)
        if close != -1 and text.startswith("(", close + 1):
            match = _URL_AFTER_PAREN.match(text, close + 2)
            if match:
                yield position, match.end(), match.group(1)
        position = text.find("![", position + 2)


def has_reference_image(text: str) -> bool:
    """True when text uses a reference-style image: ![alt][ref]."""
    position = text.find("![")
    while position != -1:
        close = _alt_end(text, position + 2)
        if close != -1:
            after = close + 1
            if text.startswith(" ", after):
                after += 1
            if text.startswith("[", after) and _alt_end(text, after + 1) != -1:
                return True
        position = text.find("![", position + 2)
    return False


def html_images(text: str) -> Iterator[str]:
    """Yield the src URL of each <img> tag in text."""
    for opener in _IMG_OPEN.finditer(text):
        end = text.find(">", opener.end(), opener.end() + MAX_TAG_CHARS)
        tag = text[opener.end(): end if end != -1 else opener.end() + MAX_TAG_CHARS]
        match = _IMG_SRC.search(tag)
        if match:
            yield match.group(1)
