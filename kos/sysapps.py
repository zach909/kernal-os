"""The OS's own apps: which they are, and how each becomes a .kapp.

``kos desktop install`` installs them in one step; ``suite/gen.py`` builds them with the rest of the
suite. Both use the manifest and launcher below, so an app cannot be built two different ways."""

from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path

from .kapp import pack

LAUNCHER = 'from kos.office.launch import entry\n\n\ndef main():\n    entry({name!r}{pack})\n'


def entries() -> list:
    """Every app that holds an OS function: pack_system's, and the pack_os titles that are built."""
    out = []
    for mod in ("pack_system", "pack_os"):
        for e in importlib.import_module("kos.office." + mod).ENTRIES:
            if e.scope != "none" and (e.services or mod == "pack_system"):
                e.pack = mod
                out.append(e)
    return out


def manifest(e) -> dict:
    perms = (["storage"] + [f"owns:{x}" for x in e.owns] + [f"uses:{x}" for x in e.uses]
             + [f"service:{x}" for x in getattr(e, "services", [])] + (["system"] if getattr(e, "system", False) else [])
             + (["network"] if e.network else []))
    modes = ["tui", "graphical"] if e.graphical else ["tui"]
    desc = f"{e.title}" + (f" - {e.note}" if e.note else "")
    return {"name": e.name, "version": "1.0", "runtime": "python", "entry": "app:main", "modes": modes,
            "permissions": perms, "description": desc[:200]}


def source(e) -> str:
    return LAUNCHER.format(name=e.name, pack=(f', {e.pack!r}' if getattr(e, 'pack', '') else ''))


def build_one(e, out: Path) -> Path:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td).joinpath(e.name)
        d.mkdir()
        (d.joinpath("manifest.json")).write_text(json.dumps(manifest(e), indent=2))
        (d.joinpath("app.py")).write_text(source(e))
        target = out.joinpath(f"{e.name}.kapp")
        pack(d, target)
    return target


def build(out: Path, only=None) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    return [build_one(e, out) for e in entries() if only is None or e.name in only]
