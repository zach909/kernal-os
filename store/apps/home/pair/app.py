"""home.pair - adds one device to the ``home`` shared folder. It can write a new record and nothing else:
it never changes or removes one. Tab moves between name, room and kind; left/right picks the kind;
enter saves; Esc leaves."""

import json
import re

from kos.sdk import App

SPACE = "home"
KINDS = ("light", "plug", "fan", "lock", "thermostat")
START = {"light": 100, "plug": 100, "fan": 50, "lock": 100, "thermostat": 20}
KEY_RE = re.compile(r"^dev-([0-9]{1,3})$")
MAX_DEVICES = 64
FIELDS = ("name", "room", "kind")
LIMIT = {"name": 24, "room": 16}


def new_key(existing):
    """The next free ``dev-N``, or None when the home is full."""
    if len(existing) >= MAX_DEVICES:
        return None
    used = {int(m.group(1)) for k in existing if (m := KEY_RE.match(k))}
    for n in range(1, 1000):
        if n not in used:
            return f"dev-{n}"
    return None


def record(state):
    """The record to save, or an error message."""
    name = state["name"].strip()
    if not name:
        return None, "give the device a name"
    return {"name": name, "room": state["room"].strip(), "kind": KINDS[state["kind"]],
            "on": False, "level": START[KINDS[state["kind"]]]}, ""


def type_key(state, k):
    f = FIELDS[state["field"]]
    if k == "tab":
        state["field"] = (state["field"] + 1) % len(FIELDS)
    elif f == "kind":
        if k in ("left", "up"):
            state["kind"] = (state["kind"] - 1) % len(KINDS)
        elif k in ("right", "down"):
            state["kind"] = (state["kind"] + 1) % len(KINDS)
    elif k == "backspace":
        state[f] = state[f][:-1]
    elif len(k) == 1 and k.isprintable() and len(state[f]) < LIMIT[f]:
        state[f] += k


def save(app, state):
    rec, err = record(state)
    if rec is None:
        state["note"] = err
        return
    key = new_key(app.vault_keys(space=SPACE))
    if key is None:
        state["note"] = "the home is full"
    elif app.vault_put(key, json.dumps(rec, sort_keys=True), space=SPACE):
        state.update(name="", room="", note=f"paired {rec['name']} as {key}", field=0)
    else:
        state["note"] = "not saved: " + (app.vault_error or "refused")


def lines(state):
    out = ["", "  Pair a device", ""]
    for i, f in enumerate(FIELDS):
        mark = ">" if i == state["field"] else " "
        val = KINDS[state["kind"]] if f == "kind" else state[f] + ("_" if i == state["field"] else "")
        out.append(f"  {mark} {f:<5} {val}")
    out += ["", "  tab next field   left/right kind   enter save   Esc leave"]
    if state["note"]:
        out += ["", "  " + state["note"]]
    return out


def main():
    app = App()
    state = {"name": "", "room": "", "kind": 0, "field": 0, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter":
                save(app, state)
            else:
                type_key(state, k)
        if cmd != "pointer":
            app.screen("Smart home - pair", lines(state), status="enter: save")
