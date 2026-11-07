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


# ---- shared folders -------------------------------------------------------------------------------------
# An app that `owns` a space stores its records there as {"next": N, "items": [...]} under the key "records" (the
# same shape RecordList/Data uses, so an owner built on RecordList is already compatible). An app that `uses` it
# reads or appends with these helpers. Nothing is readable until the owner grants it (`kos grant APP space:NAME`).
MAX_SHARED = 2000


def shared_items(host, space: str) -> list:
    """The records other apps put in `space`; [] if you have no grant, it is empty or it is malformed."""
    import json
    try:
        d = json.loads(host.get("records", space) or "null")
    except (ValueError, TypeError):
        return []
    items = d.get("items") if isinstance(d, dict) else None
    return [r for r in items if isinstance(r, dict)][:MAX_SHARED] if isinstance(items, list) else []


def shared_add(host, space: str, rec: dict) -> bool:
    """Append one record to a space you own or hold a write grant on. False if refused or full."""
    import json
    import time
    try:
        d = json.loads(host.get("records", space) or "null")
    except (ValueError, TypeError):
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("items"), list):
        d = {"next": 1, "items": []}
    if len(d["items"]) >= MAX_SHARED:
        return False
    n = d["next"] if isinstance(d.get("next"), int) else len(d["items"]) + 1
    d["items"].append({**{str(k)[:40]: v for k, v in rec.items()}, "_id": n, "_at": time.strftime("%Y-%m-%d %H:%M")})
    d["next"] = n + 1
    return bool(host.put("records", json.dumps(d, separators=(",", ":"), ensure_ascii=False), space))
