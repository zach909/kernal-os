"""web-bookmarks: Extension for the web browser: bookmarks on its start page.

It is an ordinary app (everything is). Switched on with `kos extend web-bookmarks`, the OS tells the web browser
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
        lines = ["", "  Extension for the web browser: bookmarks on its start page.", "", "  Switch it on:  kos extend web-bookmarks", ""]
        lines += [f"    {e['label']:<18} {e['address']}" for e in info.get("entries", [])]
        for key, value in info.get("colors", {}).items():
            lines.append(f"    color {key}: {value}")
        lines += ["", "  q quits"]
        app.screen("web-bookmarks", lines)
