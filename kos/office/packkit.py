"""What a pack module needs: `app()` and `none()` make catalogue entries.

Deliberately tiny and free of imports from the rest of the suite, so that an
app which imports its pack module loads only its own code (the original
catalogue imports everything)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class PackEntry:
    title: str
    kind: str = "pack"
    scope: str = "full"          # full | partial | none  (see docs/CATALOG.md)
    note: str = ""
    name: str = ""
    args: dict = field(default_factory=dict)   # args["make"](host, entry) -> Screen
    network: bool = False
    graphical: bool = False
    owns: list = field(default_factory=list)
    uses: list = field(default_factory=list)
    pack: str = ""               # set by packs.entries()

    def __post_init__(self):
        if not self.name:
            self.name = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")


def app(title, make, scope="full", note="", *, name="", network=False, graphical=False, owns=(), uses=()) -> PackEntry:
    """make(host, entry) -> a ui.Screen. `host` is the app's vault/screen (ui.Host)."""
    assert scope in ("full", "partial"), scope
    return PackEntry(title, "pack", scope, note, name, {"make": make}, network, graphical, list(owns), list(uses))


def none(title, note, name="") -> PackEntry:
    """Not built. `note` must say why, and where to look instead if something else covers it."""
    return PackEntry(title, "pack", "none", note, name)
