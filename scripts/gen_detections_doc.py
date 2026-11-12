#!/usr/bin/env python3
"""Regenerate the rule table in docs/DETECTIONS.md from the code.

    python scripts/gen_detections_doc.py
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

from promptwarden import cli

DOC = Path(__file__).resolve().parent.parent / "docs" / "DETECTIONS.md"
START, END = "<!-- rules:start -->", "<!-- rules:end -->"


def main() -> int:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main(["rules"])
    text = DOC.read_text(encoding="utf-8")
    head, _, rest = text.partition(START)
    _, _, tail = rest.partition(END)
    DOC.write_text(f"{head}{START}\n{buffer.getvalue()}{END}{tail}", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
