"""atlas.scan - two or more cameras make a depth map, and the map notices what moves.

Press ``s``: the OS (after your password) takes four sets of pictures, one per camera, then closes the cameras.
The nearer a thing is, the more its two views differ; that difference gives its distance (``atlas_core.fuse_depth``).
Every point becomes a mark in the ``atlas`` folder. Voxels that were not there in the last few looks are new; a
group of them is an ``event`` ("person-sized movement" if it is about that size: a guess from size, never a
recognition). Look at least twice so the room is learned before anything counts as new.

It runs only when you press ``s`` and the cameras are open only inside that one call. Nothing here runs by itself.
Where the cameras are is set in ``atlas.place`` (``cfg-rig``); until then it assumes two cameras 60 mm apart."""

import json

import atlas_core as core
from kos.sdk import App

SPACE = "atlas"
CFG = "cfg-rig"
DEFAULT = {"f": 120, "xs": [0, 60], "cams": ["video0", "video1"], "w": 128, "h": 96, "pose": [0, 0, 0, 0], "voxel": 100}


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


def _int(v, lo, hi):
    return type(v) is int and lo <= v <= hi


def load_rig(raw):
    """``(rig, note)``: the rig from the ``cfg-rig`` item if it is complete and sensible, else the default and why."""
    if raw is None:
        return dict(DEFAULT), "using the default rig (set yours in atlas.place)"
    try:
        d = json.loads(raw)
    except ValueError:
        return dict(DEFAULT), "cfg-rig is not valid; using the default rig"
    ok = (isinstance(d, dict) and _int(d.get("f"), 10, 5000) and isinstance(d.get("xs"), list)
          and 2 <= len(d["xs"]) <= 4 and all(_int(x, -10_000, 10_000) for x in d["xs"]) and len(set(d["xs"])) == len(d["xs"])
          and isinstance(d.get("cams"), list) and len(d["cams"]) == len(d["xs"])
          and all(isinstance(c, str) and c.startswith("video") and c[5:].isdigit() and len(c) < 9 for c in d["cams"])
          and _int(d.get("w"), 32, 320) and _int(d.get("h"), 24, 240) and _int(d.get("voxel"), 20, 1000)
          and isinstance(d.get("pose"), list) and len(d["pose"]) == 4 and all(_int(x, -1_000_000, 1_000_000) for x in d["pose"]))
    if not ok:
        return dict(DEFAULT), "cfg-rig is incomplete or out of range; using the default rig"
    return d, "rig from cfg-rig"


def analyse(rig, data, bg):
    """What a capture adds to the map: ``(marks, summary)``. ``bg`` is the ``Background`` that learns the room."""
    w, h, vx = data["w"], data["h"], rig["voxel"]
    marks, sets, valid, events, skipped = [], 0, 0, 0, 0
    for s in data["sets"]:
        try:
            imgs = [list(bytes.fromhex(f)) for f in s["frames"]]
        except ValueError:
            skipped += 1
            continue
        if len(imgs) != len(rig["xs"]) or any(len(i) != w * h for i in imgs):
            skipped += 1
            continue
        zs, votes = core.fuse_depth({"f": rig["f"], "xs": rig["xs"]}, imgs, w, h, max_disp=min(24, w - 1))
        pts = core.project(zs, votes, imgs[0], w, h, {"f": rig["f"]}, tuple(rig["pose"]), stride=2)
        voxels = core.voxel_marks(pts, vx, s["t"])
        occupied = {tuple(c // vx for c in m["p"]) for m in voxels}
        found = core.blobs(bg.new(occupied), grow=3, min_voxels=6) if len(bg.hist) >= bg.keep else []
        evs = core.event_marks(found, vx, s["t"])
        bg.update(occupied)
        marks.extend(voxels)
        marks.extend(evs)
        sets += 1
        valid += sum(1 for z in zs if z)
        events += len(evs)
    return marks, {"sets": sets, "skipped": skipped, "pixels": valid, "voxels": sum(1 for m in marks if m["k"] == "sight"),
                   "events": events, "learning": len(bg.hist) < bg.keep}


def main():
    app = App()
    store = core.MarkStore(Space(app))
    rig, note = load_rig(app.vault_get(CFG, space=SPACE))
    bg = core.Background(keep=3)
    lines = [note, f"cameras {', '.join(rig['cams'])}   picture {rig['w']}x{rig['h']}   spacing {rig['xs']} mm",
             "", "Press s to take four looks (asks your password; the cameras close when done)."]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "s":
                app.screen("Atlas: scan", lines + ["", "looking..."], status="please wait")
                r = app.service("camera.capture", cams=rig["cams"], width=rig["w"], height=rig["h"], count=4, every_ms=400)
                if not r.get("ok"):
                    lines = lines[:4] + ["", f"refused: {r.get('detail', 'no answer')}"]
                else:
                    marks, sm = analyse(rig, r["data"], bg)
                    try:
                        kept = store.add(marks)
                        out = (f"{sm['sets']} looks, {sm['pixels']} pixels had a depth, {sm['voxels']} cells, "
                               f"{sm['events']} things that moved, {kept} marks saved")
                    except OSError:
                        out = "the map could not be saved (is atlas.scan allowed to write the folder?)"
                    lines = lines[:4] + ["", out] + (["The room is still being learned: look again."] if sm["learning"] else []) \
                        + ([f"{sm['skipped']} looks were unusable"] if sm["skipped"] else [])
        if ev["cmd"] != "pointer":
            app.screen("Atlas: scan", lines, status="s look   Esc leave")
