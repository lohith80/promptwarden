"""Text normalization for obfuscation-resistant matching.

Pattern rules are easy to dodge with cosmetic tricks: zero-width characters
inside a keyword, Cyrillic letters that look Latin, leetspeak, dotted letters,
or instructions written in the invisible Unicode tag block ("ASCII
smuggling"). normalize() returns canonical variants of a text with those
tricks undone. Detectors scan the raw text first and then each variant; a rule
that only fires on a variant is tagged as obfuscated (MITRE ATLAS AML.T0068).

Everything here is a single linear pass. Nothing is ever forwarded upstream in
normalized form: variants exist only to be matched against.
"""

from __future__ import annotations

import re
import unicodedata

# Characters that render as nothing. Stripped before matching.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u206f\ufeff\U000e0000-\U000e007f]"
)

# Unicode tag block: U+E0020..U+E007E mirror printable ASCII.
_TAG_RE = re.compile("[\U000e0020-\U000e007e]+")

# Always suspicious when present in bulk.
_HARD_INVISIBLE = frozenset("\u200b\u2060\ufeff") | {chr(c) for c in range(0xE0000, 0xE0080)}
# Legitimate inside emoji sequences and in scripts such as Persian or Hindi;
# only suspicious next to ASCII text or other invisible characters.
_SOFT_INVISIBLE = frozenset("\u200c\u200d")

# Lookalike letters folded to Latin. Applied only to mixed-script tokens so
# ordinary Russian or Greek text is left alone.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ո": "n",
        "ѵ": "v", "ԛ": "q", "ԝ": "w", "ӏ": "l",
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
        "І": "I", "Ј": "J", "Ѕ": "S", "Т": "T", "К": "K", "М": "M", "Н": "H",
        "В": "B",
        "α": "a", "ε": "e", "ο": "o", "ι": "i", "ν": "v", "ρ": "p", "τ": "t",
        "υ": "u", "κ": "k", "ѡ": "w",
        "Α": "A", "Ε": "E", "Ο": "O", "Ι": "I", "Ρ": "P", "Τ": "T", "Κ": "K",
        "Ν": "N", "Μ": "M", "Β": "B", "Η": "H", "Ζ": "Z", "Χ": "X", "Υ": "Y",
    }
)  # fmt: skip

_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                         "@": "a", "$": "s"})  # fmt: skip
_LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
                         "@": "a", "$": "s"})  # fmt: skip

_LEET_HINT = re.compile(r"[A-Za-z][0134578@$]|[0134578@$][A-Za-z]")
_LEET_TOKEN = re.compile(r"[A-Za-z0-9@$]{3,24}")
_ASCII_LETTER = re.compile(r"[A-Za-z]")
_LEET_CHAR = re.compile(r"[013457@$]")

# i.g.n.o.r.e / i-g-n-o-r-e / i_g_n_o_r_e
_SEPARATED = re.compile(r"\b[A-Za-z](?:[.\-_*][A-Za-z]){3,}\b")
_SEPARATORS = re.compile(r"[.\-_*]")

_TOKEN = re.compile(r"\S+")


def count_invisible(text: str) -> int:
    """Count invisible characters that are plausibly an instruction-hiding
    channel. Zero-width joiners inside emoji or non-Latin script are ignored."""
    if text.isascii():
        return 0
    total = 0
    length = len(text)
    for i, ch in enumerate(text):
        if ch in _HARD_INVISIBLE:
            total += 1
        elif ch in _SOFT_INVISIBLE:
            prev = text[i - 1] if i > 0 else " "
            nxt = text[i + 1] if i + 1 < length else " "
            if _suspicious_neighbor(prev) or _suspicious_neighbor(nxt):
                total += 1
    return total


def _suspicious_neighbor(ch: str) -> bool:
    return ch.isascii() or ch in _HARD_INVISIBLE or ch in _SOFT_INVISIBLE


def decode_tag_block(text: str) -> str:
    """Return ASCII text hidden in the Unicode tag block, if any."""
    if text.isascii():
        return ""
    runs = _TAG_RE.findall(text)
    if not runs:
        return ""
    return " ".join("".join(chr(ord(ch) - 0xE0000) for ch in run) for run in runs)


def _fold_token(match: re.Match) -> str:
    token = match.group(0)
    if token.isascii():
        return token
    folded = token.translate(_HOMOGLYPHS)
    if folded == token:
        return token
    # Fold only when the token mixes scripts: it has a Latin letter already,
    # or folding turns it fully ASCII (every letter was a lookalike).
    if _ASCII_LETTER.search(token) or folded.isascii():
        return folded
    return token


def _deleet(text: str, table: dict) -> str:
    def repl(match: re.Match) -> str:
        token = match.group(0)
        if not _LEET_CHAR.search(token) or len(_ASCII_LETTER.findall(token)) < 2:
            return token
        return token.translate(table)

    return _LEET_TOKEN.sub(repl, text)


def normalize(text: str) -> list[str]:
    """Return canonical variants of text that differ from the original.

    An empty list means the text is already canonical, which is the common
    case for plain ASCII prose and keeps the fast path fast.
    """
    base = text
    hidden = ""
    if not text.isascii():
        hidden = decode_tag_block(text)
        base = unicodedata.normalize("NFKC", text)
        base = _INVISIBLE_RE.sub("", base)
        base = _TOKEN.sub(_fold_token, base)
    if _SEPARATED.search(base):
        base = _SEPARATED.sub(lambda m: _SEPARATORS.sub("", m.group(0)), base)

    candidates = [base]
    if _LEET_HINT.search(base):
        candidates.append(_deleet(base, _LEET_I))
        if "1" in base:
            candidates.append(_deleet(base, _LEET_L))
    if hidden:
        candidates = [f"{candidate}\n{hidden}" for candidate in candidates]

    variants: list[str] = []
    for candidate in candidates:
        if candidate != text and candidate not in variants:
            variants.append(candidate)
    return variants
