"""atlas.sense - smell, heat, humidity, pressure, light: one sweep of every plugged-in sensor.

Press ``r``: the OS (after one password) reads every sensor once and hands the numbers over; each becomes a mark in
the ``atlas`` folder, at the sensor's place if ``atlas.place`` has been told it (``cfg-sensors``), otherwise nowhere.
With three or more sensors in different places, ``atlas.digest`` compares them and works out where a smell or a
change comes from. A "smell" is a gas sensor's resistance: a number that moves, not the name of a smell."""

import json

import atlas_core as core
from kos.sdk import App

SPACE = "atlas"
CFG = "cfg-sensors"


class Space:
    def __init__(self, app):
        self.app = app

    def keys(self):
        return self.app.vault_keys(space=SPACE)

    def get(self, key):
        return self.app.vault_get(key, space=SPACE)

    def put(self, key, value):
        return self.app.vault_put(key, value, space=SPACE)

    def delete(self, key):
        return self.app.vault_delete(key, space=SPACE)


def load_positions(raw):
    """``{"0": [x, y, z]}`` from ``cfg-sensors``, keeping only well-formed entries."""
    try:
        d = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    if not isinstance(d, dict):
        return {}
    return {k: v for k, v in d.items() if isinstance(k, str) and k.isdigit() and isinstance(v, list) and len(v) == 3
            and all(type(c) is int and -1_000_000_000 < c < 1_000_000_000 for c in v)}


def marks_from_sweep(data, positions):
    """One mark per reading. A reading that is not a whole number is not a mark."""
    out = []
    for s in data["sensors"]:
        at = positions.get(str(s["index"]))
        for r in s["readings"]:
            try:
                out.append(core.mark(r["kind"], at, v=r["v"], t=data["t"], ref=f"{s['name']}-{s['index']}"[:60],
                                     unit=r["unit"], space="world"))
            except ValueError:
                continue
    return out


def main():
    app = App()
    store = core.MarkStore(Space(app))
    lines = ["Press r to read every sensor once (asks your password once)."]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "r":
                r = app.service("sensor.sweep")
                if not r.get("ok"):
                    lines = [f"refused: {r.get('detail', 'no answer')}"]
                else:
                    pos = load_positions(app.vault_get(CFG, space=SPACE))
                    marks = marks_from_sweep(r["data"], pos)
                    try:
                        store.add(marks)
                        lines = [f"{len(r['data']['sensors'])} sensors, {len(marks)} readings saved"]
                    except OSError:
                        lines = ["the map could not be saved (is atlas.sense allowed to write the folder?)"]
                    for s in r["data"]["sensors"]:
                        placed = "placed" if str(s["index"]) in pos else "nowhere yet (use atlas.place)"
                        lines.append(f"  {s['name']}-{s['index']}: {placed}")
                        lines += [f"    {x['kind']:<9}{x['v']} {x['unit']}" for x in s["readings"]]
        if ev["cmd"] != "pointer":
            app.screen("Atlas: sense", lines[:max(4, (app.height if isinstance(app.height, int) else 24) - 4)],
                       status="r read   Esc leave")
