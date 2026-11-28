"""home.devices - the smart home overview. It owns the ``home`` shared folder and only reads it.

Each device is one record ``dev-N`` -> JSON ``{name, room, kind, on, level}``. Whatever is in the folder
was written by another app, so every record is checked before it is shown; a bad one is skipped and
counted, never drawn. This app has no other power: it cannot add, change or remove a device.
Keys: r reloads, Esc leaves."""

import json
import re

from kos.sdk import App

SPACE = "home"
KINDS = ("light", "plug", "fan", "lock", "thermostat")
UNIT = {"light": "%", "fan": "%", "thermostat": " C"}
KEY_RE = re.compile(r"^dev-[0-9]{1,3}$")
BAD = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_DEVICES = 64


def clean(s, n):
    """Text from another app: control characters out, cut to n."""
    return BAD.sub("?", s)[:n]


def valid_record(raw):
    """A device record from the shared folder, or None. Nothing in it is believed."""
    try:
        d = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(d, dict) or set(d) != {"name", "room", "kind", "on", "level"}:
        return None
    if not (isinstance(d["name"], str) and isinstance(d["room"], str) and d["kind"] in KINDS):
        return None
    if type(d["on"]) is not bool or type(d["level"]) is not int or not 0 <= d["level"] <= 100:
        return None
    if not d["name"].strip() or len(d["name"]) > 24 or len(d["room"]) > 16:
        return None
    return {"name": clean(d["name"], 24), "room": clean(d["room"], 16), "kind": d["kind"],
            "on": d["on"], "level": d["level"]}


def load(app):
    devices, skipped = [], 0
    for key in sorted(app.vault_keys(space=SPACE))[:MAX_DEVICES]:
        rec = valid_record(app.vault_get(key, space=SPACE)) if KEY_RE.match(key) else None
        if rec:
            devices.append((key, rec))
        else:
            skipped += 1
    return devices, skipped


def lines(devices, skipped, height):
    out = ["", "  Smart home", ""]
    if not devices:
        out.append("  no devices yet - pair one with home.pair")
    room = max(3, height - 9)
    last = None
    for key, d in devices[:room]:
        if d["room"] != last:
            out.append(f"  [{d['room'] or 'no room'}]")
            last = d["room"]
        level = f" {d['level']}{UNIT[d['kind']]}" if d["kind"] in UNIT and d["on"] else ""
        out.append(f"    {key:<8} {d['name']:<24} {d['kind']:<10} {'ON' if d['on'] else 'off'}{level}")
    if len(devices) > room:
        out.append(f"    ... and {len(devices) - room} more")
    if skipped:
        out += ["", f"  {skipped} record(s) in the folder were not valid and are hidden"]
    out += ["", "  States are what you asked for. Nothing carries them to the device yet:",
            "  KOS has no device-to-device link (docs/MESH.md)."]
    return out


def main():
    app = App()
    state = {"devices": [], "skipped": 0}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello" or (cmd == "key" and ev["key"] == "r"):
            state["devices"], state["skipped"] = load(app)
        elif cmd == "key" and ev["key"] in ("escape", "q"):
            app.exit(0)
            return
        if cmd != "pointer":
            app.screen("Smart home", lines(state["devices"], state["skipped"], app.height),
                       status="r reload   Esc to leave")
