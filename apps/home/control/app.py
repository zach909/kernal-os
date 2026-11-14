"""home.control - turn a paired device on or off and set its level. It records what you ASKED for in the
``home`` shared folder. It cannot add or remove a device, and it does not reach the device: KOS has no
device-to-device link yet (docs/MESH.md), so nothing here moves a real light.

Keys: up/down choose, enter or space toggles, left/right change the level (10 at a time, 1 for a thermostat),
Esc leaves. Whole numbers only: a level is 0-100 (%), a thermostat 10-30 (degrees C)."""

import json
import re

from kos.sdk import App

SPACE = "home"
KINDS = ("light", "plug", "fan", "lock", "thermostat")
RANGE = {"light": (0, 100, 10), "fan": (0, 100, 10), "thermostat": (10, 30, 1)}   # lo, hi, step
KEY_RE = re.compile(r"^dev-[0-9]{1,3}$")
BAD = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_DEVICES = 64


def valid_record(raw):
    """A record from the shared folder, or None. Another app wrote it, so nothing in it is believed."""
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
    return {"name": BAD.sub("?", d["name"]), "room": BAD.sub("?", d["room"]), "kind": d["kind"],
            "on": d["on"], "level": d["level"]}


def adjust(rec, direction):
    """The record with its level moved one step (direction is -1 or 1), kept inside the kind's range."""
    if rec["kind"] not in RANGE or direction not in (-1, 1):
        return dict(rec)
    lo, hi, step = RANGE[rec["kind"]]
    return {**rec, "level": min(hi, max(lo, rec["level"] + direction * step))}


def toggle(rec):
    return {**rec, "on": not rec["on"]}


def load(app):
    out = []
    for key in sorted(app.vault_keys(space=SPACE))[:MAX_DEVICES]:
        rec = valid_record(app.vault_get(key, space=SPACE)) if KEY_RE.match(key) else None
        if rec:
            out.append([key, rec])
    return out


def write(app, state, change):
    key, rec = state["devices"][state["sel"]]
    new = change(rec)
    if new == rec:
        return
    if app.vault_put(key, json.dumps(new, sort_keys=True), space=SPACE):
        state["devices"][state["sel"]][1] = new
        state["note"] = f"asked for: {new['name']} {'ON' if new['on'] else 'off'}"
    else:
        state["note"] = "not saved: " + (app.vault_error or "refused")


def lines(state):
    out = ["", "  Control", ""]
    if not state["devices"]:
        out.append("  no devices - pair one with home.pair")
    for n, (key, d) in enumerate(state["devices"][:20]):
        extra = f" {d['level']}" if d["kind"] in RANGE and d["on"] else ""
        out.append(f"  {'>' if n == state['sel'] else ' '} {d['name']:<24} {d['kind']:<10} "
                   f"{'ON' if d['on'] else 'off'}{extra}")
    out += ["", "  up/down choose   enter toggle   left/right level   Esc leave"]
    if state["note"]:
        out += ["", "  " + state["note"]]
    out += ["", "  This records what you asked for. It does not reach the device yet."]
    return out


def main():
    app = App()
    state = {"devices": [], "sel": 0, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            state["devices"] = load(app)
        elif cmd == "key":
            k, n = ev["key"], len(state["devices"][:20])
            if k == "escape":
                app.exit(0)
                return
            if n and k == "up":
                state["sel"] = (state["sel"] - 1) % n
            elif n and k == "down":
                state["sel"] = (state["sel"] + 1) % n
            elif n and k in ("enter", " ", "space"):
                write(app, state, toggle)
            elif n and k in ("left", "right"):
                write(app, state, lambda r: adjust(r, -1 if k == "left" else 1))
        if cmd != "pointer":
            app.screen("Smart home - control", lines(state), status="enter: toggle")
