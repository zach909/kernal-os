"""Add-ons: features that are not part of the default system and are off until you turn them on.

Virtual reality, augmented reality and the neural interface are add-ons. They reach for a headset, a camera or a neural device, and
most people never use them, so the default KOS does not have them: the three looks are not offered, and the compositor refuses to enter
them, until the owner enables the add-on - which is a **kernel-layer** action (password, every time, never remembered, not skipped by a
sudo window), like enabling a system mod. Entering one of the looks afterwards asks for the password again.

An add-on is *not* code that runs inside the OS. The trusted core stays small and nothing is loaded into it: an add-on turns on a look that
the compositor already knows how to draw, and the hardware side lives in separate driver apps (``"driver": "camera" | "xr" | "neural"``)
that are sandboxed, scoped and asked for separately. Turning an add-on off puts the interface back to a normal look at once.

The enabled list is ``<state>/addons.json``, which no sandboxed app can read or write.
"""

from __future__ import annotations

import json

from .auth import Authority
from .paths import Paths, atomic_write

ADDONS = {
    "vr": {"title": "Virtual reality", "looks": ("vr",), "driver": "xr",
           "about": "One picture per eye, side by side, with depth. A headset appears as one more display; its sensors come in through an xr driver app."},
    "ar": {"title": "Augmented reality", "looks": ("ar",), "driver": "camera",
           "about": "The interface floats over a camera passthrough supplied by a camera driver app in the wallpaper slot."},
    "neural": {"title": "Neural interface", "looks": ("neural",), "driver": "neural",
               "about": "A highlight scans the buttons; a neural driver app (EEG/EMG band) picks with five decisions. The signal never leaves the driver."},
}


class AddonError(Exception):
    pass


class Addons:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.state / "addons.json"

    def enabled(self) -> frozenset:
        try:
            raw = json.loads(self.file.read_text())
        except (OSError, ValueError):
            return frozenset()
        return frozenset(n for n in (raw.get("enabled") if isinstance(raw, dict) else []) or [] if n in ADDONS)

    def looks(self) -> frozenset:
        """The add-on looks that may be entered right now."""
        return frozenset(l for n in self.enabled() for l in ADDONS[n]["looks"])

    def _save(self, names) -> None:
        self.paths.ensure()
        atomic_write(self.file, json.dumps({"enabled": sorted(names)}).encode())

    def enable(self, authority: Authority, name: str) -> None:
        if name not in ADDONS:
            raise AddonError(f"no such add-on: {name} (there is {', '.join(ADDONS)})")
        with authority.authorize("addon.enable", name):
            self._save(self.enabled() | {name})

    def disable(self, authority: Authority, name: str) -> None:
        if name not in ADDONS:
            raise AddonError(f"no such add-on: {name}")
        with authority.authorize("addon.disable", name):
            self._save(self.enabled() - {name})
