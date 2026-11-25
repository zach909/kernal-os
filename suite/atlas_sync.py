"""Copy ``suite/atlas_core.py`` into every Atlas app.

An app's code lives in its own folder and apps never import each other (README rule: everything is separate),
so each Atlas app carries its own copy of the map maker's core. This is the one place that makes the copies.
``python3 -m suite.atlas_sync`` writes them; ``python3 -m suite.atlas_sync --check`` lists any that differ and
exits 1 (``tests/test_atlas_apps.py`` runs the same check). Change ``suite/atlas_core.py``, never a copy."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MASTER = ROOT / "suite" / "atlas_core.py"
NAME = "atlas_core.py"


def apps() -> list:
    return sorted(p.parent for p in (ROOT / "apps" / "atlas").glob("*/manifest.json"))


def drifted() -> list:
    want = MASTER.read_bytes()
    return [d for d in apps() if not (d / NAME).is_file() or (d / NAME).read_bytes() != want]


def sync() -> list:
    want = MASTER.read_bytes()
    out = []
    for d in apps():
        if not (d / NAME).is_file() or (d / NAME).read_bytes() != want:
            (d / NAME).write_bytes(want)
            out.append(d)
    return out


def main(argv: list) -> int:
    if "--check" in argv:
        bad = drifted()
        for d in bad:
            print(f"differs from suite/{NAME}: {d.relative_to(ROOT)}")
        return 1 if bad else 0
    for d in sync():
        print(f"wrote {(d / NAME).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
