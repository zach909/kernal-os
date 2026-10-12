"""System mods: replace or extend a part of the interface with an app of your own.

The interface is made of apps, each filling a *slot*: the wallpaper, the menubar, the dock, the cursor, the
search box, the sidebar, the launcher, the pins, the click effects, and any number of widgets. A **mod** is an
ordinary ``.kapp`` whose manifest names the slot it fills (``"slot": "wallpaper"``). Enabling it makes the
desktop start it instead of the built-in app for that slot (or, for ``widget``, in addition to the others).

What keeps this safe:

* A mod is installed like any app: scanned, sealed with your password, nothing runs at install.
* Enabling or disabling one is a **kernel-layer** action: it asks for your password every time, even inside a
  sudo window, because it changes what the desktop itself runs.
* Each slot has a *ceiling* of permissions. A wallpaper may ask for nothing; a cursor for the pointer and
  animation ticks; a dock for the system and shell permissions the built-in dock has. A mod asking for more
  than its slot allows cannot be enabled. (It still runs in the same sandbox as every app.)
* The built-in app is never deleted: disabling a mod, or a mod that fails to start, falls back to it.
* Enabling a mod permits it (``kos permit``) as part of the same password.

Mods are listed in ``<state>/mods.json``, which no sandboxed app can read or write.
"""

from __future__ import annotations

import json
from typing import Optional

from .kapp import KApp, KAppError, SLOTS
from .paths import Paths, atomic_write

# What each slot may ask for. The built-in apps in each slot ask for exactly this or less.
CEILING: dict[str, frozenset[str]] = {
    "wallpaper": frozenset(),
    "menubar": frozenset({"system", "ticks", "shell"}),
    "dock": frozenset({"system", "shell"}),
    "pins": frozenset({"system", "shell"}),
    "search": frozenset({"system", "shell"}),
    "sidebar": frozenset({"system", "shell"}),
    "launcher": frozenset({"system", "shell"}),
    "widgets": frozenset({"shell"}),
    "cursor": frozenset({"pointer", "animate"}),
    "effects": frozenset({"pointer", "animate"}),
    "widget": frozenset({"ticks", "system"}),
}
assert set(CEILING) == set(SLOTS), "every slot needs a ceiling"

# The built-in app for each single slot (a "widget" mod adds one, it replaces nothing).
DEFAULTS = {"wallpaper": "wallpaper", "menubar": "menubar", "dock": "dock", "pins": "pins", "search": "search",
            "sidebar": "sidebar", "launcher": "launcher", "widgets": "widgets", "cursor": "cursor", "effects": "effects"}
MAX_WIDGET_MODS = 4


class ModError(KAppError):
    pass


def check(app: KApp) -> str:
    """Is this app a valid mod? Returns its slot, or raises ModError saying why not."""
    m = app.manifest
    if not m.slot:
        raise ModError(f"{m.name} is not a mod (its manifest has no \"slot\")")
    extra = set(m.permissions) - CEILING[m.slot]
    if extra:
        raise ModError(f"a {m.slot} mod may not ask for {sorted(extra)}; the most it may ask for is "
                       f"{sorted(CEILING[m.slot]) or 'nothing'}")
    if "graphical" not in m.modes:
        raise ModError("an interface mod must have a graphical mode")
    return m.slot


class Mods:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.state / "mods.json"

    def _load(self) -> dict:
        try:
            d = json.loads(self.file.read_text())
        except (OSError, ValueError):
            d = {}
        slots = {k: v for k, v in (d.get("slots") or {}).items() if k in DEFAULTS and isinstance(v, str)}
        widgets = [w for w in (d.get("widgets") or []) if isinstance(w, str)][:MAX_WIDGET_MODS]
        return {"slots": slots, "widgets": widgets}

    def _save(self, d: dict) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(d, indent=1).encode())

    def installed(self) -> list[dict]:
        """Every installed app that declares a slot, and whether it is the one in use."""
        from .store import AppStore
        cur = self._load()
        out = []
        for a in AppStore(self.paths).installed():
            try:
                app = KApp.from_file(self.paths.apps / f"{a.name}.kapp")
            except Exception:
                continue
            m = app.manifest
            if not m.slot:
                continue
            try:
                check(app)
                problem = ""
            except ModError as e:
                problem = str(e)
            on = (cur["slots"].get(m.slot) == m.name) if m.slot != "widget" else (m.name in cur["widgets"])
            out.append({"name": m.name, "slot": m.slot, "version": m.version, "description": m.description,
                        "enabled": on, "problem": problem, "permissions": list(m.permissions)})
        return sorted(out, key=lambda r: (r["slot"], r["name"]))

    def enable(self, name: str) -> dict:
        app = KApp.from_file(self.paths.apps / f"{name}.kapp") if (self.paths.apps / f"{name}.kapp").exists() else None
        if app is None:
            raise ModError(f"{name} is not installed (kos install it first)")
        slot = check(app)
        cur = self._load()
        if slot == "widget":
            if name not in cur["widgets"]:
                if len(cur["widgets"]) >= MAX_WIDGET_MODS:
                    raise ModError(f"at most {MAX_WIDGET_MODS} widget mods at once")
                cur["widgets"].append(name)
        else:
            cur["slots"][slot] = name
        self._save(cur)
        return {"name": name, "slot": slot}

    def disable(self, name: str) -> None:
        cur = self._load()
        cur["slots"] = {k: v for k, v in cur["slots"].items() if v != name}
        cur["widgets"] = [w for w in cur["widgets"] if w != name]
        self._save(cur)

    def resolve(self, slot: str, installed: set[str]) -> str:
        """The app to run for a slot: the enabled mod if it is installed, else the built-in."""
        mod = self._load()["slots"].get(slot)
        return mod if mod and mod in installed else DEFAULTS[slot]

    def widget_mods(self, installed: set[str]) -> list[str]:
        return [w for w in self._load()["widgets"] if w in installed]


def core_names(paths: Paths, defaults: tuple[str, ...], installed: set[str]) -> list[str]:
    """The names of the apps the desktop should run: ``defaults`` (the built-in core) with each slot swapped for
    its enabled mod, plus enabled widget mods. Mods that are not installed any more are ignored."""
    mods = Mods(paths)
    out = [mods.resolve(n, installed) if n in DEFAULTS else n for n in defaults]
    out += [w for w in mods.widget_mods(installed) if w not in out]
    return out
