"""library-shelf: Mod for the App Library: a shelf of shortcuts and a new accent.

It is an ordinary app (everything is). Switched on with `kos extend library-shelf`, the OS tells the App Library
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
        lines = ["", "  Mod for the App Library: a shelf of shortcuts and a new accent.", "", "  Switch it on:  kos extend library-shelf", ""]
        lines += [f"    {e['label']:<18} {e['address']}" for e in info.get("entries", [])]
        for key, value in info.get("colors", {}).items():
            lines.append(f"    color {key}: {value}")
        lines += ["", "  q quits"]
        app.screen("library-shelf", lines)
