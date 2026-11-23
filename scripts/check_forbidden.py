"""CI guard (§9.5): guardian/ must not contain shell=True, git push or npm publish."""

import pathlib
import re
import sys

PATTERNS = [re.compile(r"shell\s*=\s*True"), re.compile(r"git\s+push"), re.compile(r"npm\s+publish")]
ROOT = pathlib.Path(__file__).resolve().parent.parent / "guardian"

hits = []
for path in ROOT.rglob("*.py"):
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if any(p.search(line) for p in PATTERNS):
            hits.append(f"{path.relative_to(ROOT.parent)}:{lineno}: {line.strip()}")

if hits:
    print("Forbidden patterns found:\n" + "\n".join(hits))
    sys.exit(1)
print("check_forbidden: ok")
