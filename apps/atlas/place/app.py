"""atlas.place - say where each sensor and camera is. It writes two settings into the ``atlas`` folder and does
nothing else: it reads and controls no device.

Commands (whole numbers, millimetres, Enter runs one):
  ``sensor N X Y Z``      sensor number N (from atlas.sense) sits at X, Y, Z
  ``rig F X0 X1 [X2 X3]`` cameras video0.. sit at these positions along a line, F is the focal length in pixels
  ``pose X Y Z YAW``      where the whole rig is in the map and which way it faces (YAW in whole degrees)
  ``size W H``            picture size to ask the cameras for
  ``show``                what is set
Without a place a sensor's readings are marks that are *nowhere*, and nothing can be worked out about where they come from."""

import json

from kos.sdk import App

SPACE = "atlas"
RIG, SENSORS = "cfg-rig", "cfg-sensors"
DEFAULT_RIG = {"f": 120, "xs": [0, 60], "cams": ["video0", "video1"], "w": 128, "h": 96, "pose": [0, 0, 0, 0], "voxel": 100}


def _load(app, key, default):
    raw = app.vault_get(key, space=SPACE)
    try:
        d = json.loads(raw) if raw else None
    except ValueError:
        d = None
    return d if isinstance(d, type(default)) else default


def _nums(words, n):
    try:
        v = [int(w) for w in words]
    except ValueError:
        return None
    return v if len(v) == n else None


def run(app, line):
    """Do one command. Returns what to tell the user."""
    w = line.split()
    if not w:
        return "type a command: sensor, rig, pose, size or show"
    cmd, rest = w[0], w[1:]
    if cmd == "show":
        rig, sens = _load(app, RIG, dict(DEFAULT_RIG)), _load(app, SENSORS, {})
        return f"rig {json.dumps(rig, sort_keys=True)}   sensors {json.dumps(sens, sort_keys=True)}"
    if cmd == "sensor":
        v = _nums(rest, 4)
        if v is None or not 0 <= v[0] <= 999 or any(abs(c) > 1_000_000_000 for c in v[1:]):
            return "sensor N X Y Z   (whole numbers, N from 0 to 999)"
        sens = _load(app, SENSORS, {})
        sens[str(v[0])] = v[1:]
        return "saved" if app.vault_put(SENSORS, json.dumps(sens, sort_keys=True), space=SPACE) else "could not save"
    rig = _load(app, RIG, dict(DEFAULT_RIG))
    if cmd == "rig":
        v = _nums(rest, len(rest))
        if v is None or not 3 <= len(v) <= 5 or not 10 <= v[0] <= 5000 or len(set(v[1:])) != len(v) - 1 \
                or any(abs(x) > 10_000 for x in v[1:]):
            return "rig F X0 X1 [X2 X3]   (F 10-5000 pixels, positions different, whole mm)"
        rig["f"], rig["xs"] = v[0], v[1:]
        rig["cams"] = [f"video{i}" for i in range(len(v) - 1)]
    elif cmd == "pose":
        v = _nums(rest, 4)
        if v is None or any(abs(c) > 1_000_000 for c in v):
            return "pose X Y Z YAW   (whole numbers)"
        rig["pose"] = v
    elif cmd == "size":
        v = _nums(rest, 2)
        if v is None or not (32 <= v[0] <= 320 and 24 <= v[1] <= 240):
            return "size W H   (32-320 by 24-240)"
        rig["w"], rig["h"] = v
    else:
        return "unknown command: sensor, rig, pose, size or show"
    return "saved" if app.vault_put(RIG, json.dumps(rig, sort_keys=True), space=SPACE) else "could not save"


def main():
    app = App()
    text, note = "", "type a command and press Enter (see the list below)"
    help_lines = ["", "  sensor N X Y Z", "  rig F X0 X1 [X2 X3]", "  pose X Y Z YAW", "  size W H", "  show"]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter":
                note, text = run(app, text), ""
            elif k == "backspace":
                text = text[:-1]
            elif len(k) == 1 and k.isprintable() and len(text) < 120:
                text += k
        if ev["cmd"] != "pointer":
            app.screen("Atlas: place", [f"> {text}_", "", note] + help_lines, status="Enter runs   Esc leave")
