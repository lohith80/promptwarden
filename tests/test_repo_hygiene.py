"""Source hygiene for a project that detects hidden text.

Invisible and bidirectional control characters in source are the same trick
the gateway looks for in prompts (and the "Trojan Source" attack on code
review). Test data that needs them writes them as escapes.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".conf", ".kql", ".json", ".txt", ""}
HIDDEN = re.compile(
    "[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff"
    "\U000e0000-\U000e007f]"
)


def tracked_files() -> list[Path]:
    result = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,  # noqa: S603, S607
                            capture_output=True, text=True, check=False)
    names = result.stdout.split() if result.returncode == 0 else []
    return [ROOT / name for name in names if (ROOT / name).suffix in TEXT_SUFFIXES]


def test_no_raw_invisible_or_bidi_characters_in_the_repo():
    offenders = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            match = HIDDEN.search(line)
            if match:
                offenders.append(f"{path.relative_to(ROOT)}:{number} U+{ord(match.group()):04X}")
    assert not offenders, "write these as escapes: " + ", ".join(offenders[:10])
