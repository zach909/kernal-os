"""taskbar-pins: Mod for the taskbar: pinned apps and a new accent color.

It is an ordinary app (everything is). Switched on with `kos extend taskbar-pins`, the OS tells the taskbar
about the entries in extension.json. Run on its own, it just shows what it would add."""

import json

from kos.sdk import App


def main():
    app = App()
    info = json.loads(app.resource("extension.json"))
    for ev in app.events():
        if ev["cmd"] == "key" and ev["key"] in ("q", "escape"):
            app.exit(0)
            return
        if ev["cmd"] == "pointer":
            continue
        lines = ["", "  Mod for the taskbar: pinned apps and a new accent color.", "", "  Switch it on:  kos extend taskbar-pins", ""]
        lines += [f"    {e['label']:<18} {e['address']}" for e in info.get("entries", [])]
        for key, value in info.get("colors", {}).items():
            lines.append(f"    color {key}: {value}")
        lines += ["", "  q quits"]
        app.screen("taskbar-pins", lines)
