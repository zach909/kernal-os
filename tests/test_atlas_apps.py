"""The Atlas apps (apps/atlas/*) and zip.run (apps/zip/run): nine separate apps that share one folder.

Each is driven through its real ``main()`` with a fake OS (a dict for the shared folder, scripted service answers,
the screens it drew). The permission tests use the real shared-folder store. Not tested: any of this inside the real
sandbox on a real screen, or against a real camera or sensor (the services that feed them are tested in
test_senses.py against fakes)."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite"))
sys.path.insert(0, str(ROOT / "tests"))

import atlas_core as core  # noqa: E402
import atlas_sync  # noqa: E402
from kos import proof  # noqa: E402
from kos.kapp import KApp, Manifest, pack, pack_tree  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.spaces import AppStorage, StorageError  # noqa: E402
from test_atlas_core import H, W, Mem, two_layer_pair  # noqa: E402

ATLAS = ROOT / "apps" / "atlas"
NAMES = {"find": "atlas.find", "map": "atlas.map", "scan": "atlas.scan", "sense": "atlas.sense", "place": "atlas.place",
         "files": "atlas.files", "put": "atlas.put", "digest": "atlas.digest"}


def load(path):
    folder = Path(path)
    sys.path.insert(0, str(folder))
    try:
        sys.modules.pop("atlas_core", None)
        spec = importlib.util.spec_from_file_location(f"atlasapp_{folder.parent.name}_{folder.name}", folder / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(folder))
        sys.modules.pop("atlas_core", None)
    return mod


class FakeApp:
    """Stands in for kos.sdk.App: a dict for the shared folder, scripted service answers, the screens drawn."""

    def __init__(self, events=(), space=None, services=None, width=80, height=24, refuse=False):
        self.space, self._events, self.services = dict(space or {}), list(events), services or {}
        self.width, self.height, self.refuse = width, height, refuse
        self.calls, self.screens, self.puts, self.exited = [], [], [], False

    def events(self):
        yield from self._events

    def vault_keys(self, space=None):
        assert space == "atlas"
        return list(self.space)

    def vault_get(self, key, space=None):
        assert space == "atlas"
        return self.space.get(key)

    def vault_put(self, key, value, space=None):
        assert space == "atlas"
        self.puts.append(key)
        if self.refuse:
            return False
        self.space[key] = value
        return True

    def vault_delete(self, key, space=None):
        assert space == "atlas"
        self.puts.append(("delete", key))
        return self.space.pop(key, None) is not None

    def service(self, name, /, **args):
        self.calls.append((name, args))
        r = self.services[name]
        return r(args) if callable(r) else r

    def screen(self, title, lines, status=""):
        self.screens.append((title, list(lines), status))

    def exit(self, code=0):
        self.exited = True

    @property
    def text(self):
        return "\n".join("\n".join(s[1]) for s in self.screens)


class Backend:
    """The map's backend over a FakeApp's folder, for the test to read what an app wrote."""

    def __init__(self, app):
        self.app = app

    def keys(self):
        return list(self.app.space)

    def get(self, k):
        return self.app.space.get(k)

    def put(self, k, v):
        self.app.space[k] = v
        return True

    def delete(self, k):
        return self.app.space.pop(k, None) is not None


def store_of(app):
    return core.MarkStore(Backend(app))


def run(prog, keys=(), **kw):
    mod = load(ATLAS / prog)
    app = FakeApp(events=[{"cmd": "hello"}] + [{"cmd": "key", "key": k} for k in keys], **kw)
    mod.App = lambda: app
    mod.main()
    return app


def typed(text):
    return list(text)


class TestTheGroup(unittest.TestCase):
    def test_every_app_carries_an_identical_copy_of_the_core(self):
        self.assertEqual(atlas_sync.drifted(), [], "run python3 -m suite.atlas_sync")
        self.assertEqual(len(atlas_sync.apps()), 8)

    def test_the_check_would_notice_a_drifted_copy(self):
        victim = ATLAS / "map" / "atlas_core.py"
        orig = victim.read_bytes()
        try:
            victim.write_bytes(orig + b"\n# changed\n")
            self.assertEqual([d.name for d in atlas_sync.drifted()], ["map"])        # the negative control
        finally:
            victim.write_bytes(orig)
        self.assertEqual(atlas_sync.drifted(), [])

    def test_each_app_is_its_own_with_only_its_own_permissions(self):
        want = {"find": ["owns:atlas"], "map": ["uses:atlas"], "scan": ["uses:atlas", "service:camera"],
                "sense": ["uses:atlas", "service:sensor"], "place": ["uses:atlas"],
                "files": ["uses:atlas", "service:files"], "put": ["uses:atlas", "service:clock"], "digest": ["uses:atlas"]}
        for prog, perms in want.items():
            m = Manifest.parse((ATLAS / prog / "manifest.json").read_bytes())
            self.assertEqual((m.name, list(m.permissions)), (NAMES[prog], perms))
            for bad in ("network", "system", "storage"):
                self.assertNotIn(bad, m.permissions, f"{m.name} must not ask for {bad}")
        self.assertFalse((ATLAS / "manifest.json").exists(), "the group has no permissions of its own")
        self.assertEqual(sum(1 for m in want.values() if "owns:atlas" in m), 1, "exactly one owner of the folder")

    def test_the_whole_group_packs_through_the_proof_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            got = {m.name for m in pack_tree(ATLAS, Path(tmp))}
        self.assertEqual(got, set(NAMES.values()))

    def test_no_decimals_and_nothing_imported_from_the_os_but_the_sdk(self):
        files = sorted(ATLAS.rglob("*.py")) + [ROOT / "apps" / "zip" / "run" / "app.py"]
        self.assertGreater(len(files), 16)
        for p in files:
            self.assertEqual(proof.violations(p.read_bytes(), p.name, frozenset({"atlas_core"})), [], p)
            for node in ast.walk(ast.parse(p.read_text())):
                mods = ([node.module] if isinstance(node, ast.ImportFrom) and node.module else
                        [a.name for a in node.names] if isinstance(node, ast.Import) else [])
                for mod in mods:
                    self.assertTrue(not mod.startswith("kos") or mod == "kos.sdk", f"{p} imports {mod}")
                    self.assertNotIn("atlasapp", mod)
        # and no app imports another app: the only local import is its own copy of the core
        for p in ATLAS.rglob("app.py"):
            for node in ast.walk(ast.parse(p.read_text())):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        self.assertIn(a.name, {"json", "atlas_core"}, p)

    def test_the_packed_apps_carry_their_core_and_run_unproven_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for prog in NAMES:
                pack(ATLAS / prog, Path(tmp) / f"{prog}.kapp")
                app = KApp.from_file(Path(tmp) / f"{prog}.kapp")
                self.assertIn("atlas_core.py", app.names())
                proof.require(app)


class TestSharedFolderPermissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(Path(self.tmp.name))
        self.perms = Permissions(self.paths)

    def storage(self, prog):
        m = Manifest.parse((ATLAS / prog / "manifest.json").read_bytes())
        return AppStorage(self.paths, m.name, m.permissions)

    def test_nobody_gets_in_until_the_owner_of_the_device_lets_them(self):
        self.storage("find").vault("atlas", "get")                    # find creates the folder
        for prog in set(NAMES) - {"find"}:
            if "uses:atlas" in Manifest.parse((ATLAS / prog / "manifest.json").read_bytes()).permissions:
                with self.assertRaises(StorageError, msg=prog):
                    self.storage(prog).vault("atlas", "get")

    def test_the_map_viewer_can_be_given_read_and_then_still_cannot_write(self):
        self.storage("find").vault("atlas", "get")
        self.perms.grant("atlas.map", "space:atlas", "read")
        s = self.storage("map")
        s.vault("atlas", "get")
        with self.assertRaises(StorageError):
            s.vault("atlas", "put")

    def test_a_scanner_with_write_puts_marks_the_finder_then_reads(self):
        owner = self.storage("find")
        owner.vault("atlas", "get")
        self.perms.grant("atlas.put", "space:atlas", "write")
        vault = self.storage("put").vault("atlas", "put")
        store = core.MarkStore(type("B", (), {"keys": lambda s: vault.keys(), "get": lambda s, k: vault.get(k),
                                              "put": lambda s, k, v: (vault.put(k, v), True)[1],
                                              "delete": lambda s, k: vault.delete(k)})())
        store.add([core.ingest("note", "espresso grinder notes", t=5)])
        seen = owner.vault("atlas", "get")
        self.assertTrue(any(k.startswith("c.") for k in seen.keys()))
        self.assertEqual(len(store.search(kind="data")), 1)

    def test_the_map_fits_the_folders_limits(self):
        """A shared folder holds at most 500 items; the map keeps to 380 chunks plus its index."""
        from kos.vault import MAX_ITEM, MAX_ITEMS
        self.assertLess(core.MarkStore(Mem()).max_chunks + 1, MAX_ITEMS)
        self.assertLessEqual(core.MAX_CHUNK_CHARS, MAX_ITEM)


class TestFind(unittest.TestCase):
    def populated(self):
        app = FakeApp()
        s = store_of(app)
        s.add([core.ingest("recipe.txt", "Espresso: grind fine, tamp firmly, pull a thirty second shot.", t=10, space="mind"),
               core.mark("smell", (100, 100, 100), v=900, t=20, label="coffee", ref="nose-1", unit="ohm"),
               core.mark("event", (1000, 2000, 900), v=40, t=30, label="person-sized movement 400x300x1700 mm"),
               core.mark("likes", None, v=900, t=40, ref="photo.png", unit="likes", space="mind")])
        return app, s

    def test_each_kind_of_question(self):
        mod = load(ATLAS / "find")
        app, s = self.populated()
        self.assertTrue(any("coffee" in l for l in mod.answer(s, "coffee")))
        self.assertTrue(all("smell" in l for l in mod.answer(s, "/kind smell")))
        self.assertTrue(any("event" in l for l in mod.answer(s, "person")))
        self.assertTrue(any("900likes" in l or "n=" in l for l in mod.answer(s, "/about photo.png")))
        self.assertTrue(any("recipe.txt" in l for l in mod.answer(s, "/similar espresso grind fine tamp firmly shot")))
        self.assertTrue(any("event" in l and "mm away" in l for l in mod.answer(s, "/near 1050 2050 950 500")))
        self.assertTrue(any("data" in l for l in mod.answer(s, "/stats")))
        self.assertEqual(mod.answer(s, "/about nothing-here"), ["nothing about 'nothing-here'"])
        self.assertEqual(mod.answer(s, "zzzz"), ["nothing found"])
        self.assertEqual(mod.answer(s, "/near 1 2 3 x"), ["/near X Y Z RADIUS [space]   (whole millimetres)"])
        self.assertEqual(mod.answer(s, "/near 1 2"), ["/near X Y Z RADIUS [space]   (whole millimetres)"])
        self.assertEqual(mod.answer(s, ""), mod.HELP)
        self.assertEqual(mod.answer(s, "/bogus thing"), mod.HELP)

    def test_garbage_in_the_folder_does_not_break_it(self):
        mod = load(ATLAS / "find")
        app = FakeApp(space={"c.world.0_0_0": "not json at all", "c.world.1_1_1": json.dumps([{"k": "x", "v": 1.5}, 7]),
                             "index": "{{{"})
        s = store_of(app)
        self.assertEqual(mod.answer(s, "anything"), ["nothing found"])
        self.assertTrue(any("refused" in l for l in mod.answer(s, "/stats")))

    def test_the_screen_flow_types_asks_scrolls_and_leaves(self):
        app, _ = self.populated()
        mod = load(ATLAS / "find")
        mod.App = lambda: FakeApp(space=app.space, events=[{"cmd": "hello"}] + [{"cmd": "key", "key": k}
                                                                                for k in typed("coffee") + ["enter", "down", "up", "escape"]])
        run_app = mod.App()
        mod.App = lambda: run_app
        mod.main()
        self.assertIn("> coffee", run_app.text)
        self.assertIn("smell", run_app.text)
        self.assertTrue(run_app.exited)
        self.assertEqual(run_app.puts, [], "the finder only reads")

    def test_a_long_line_of_typing_is_capped(self):
        app = run("find", keys=["x"] * 500)
        self.assertLessEqual(max(len(l) for t, ls, s in app.screens for l in ls[:1]), 205)


class TestMap(unittest.TestCase):
    def test_marks_land_in_the_cells_their_places_say_and_the_worked_out_wins(self):
        mod = load(ATLAS / "map")
        marks = [core.mark("sight", (0, 0, 0), v=1, t=1), core.mark("region", (0, 0, 0), v=1, t=1, label="object"),
                 core.mark("smell", (500, 500, 0), v=1, t=1), core.mark("sight", (9999, 0, 0), v=1, t=1),
                 core.mark("file", (0, 0, 0), v=1, t=1, space="files")]
        rows = mod.render(marks, "world", 0, 0, 100, 21, 11)
        self.assertEqual(rows[5][10], "#", "a surface covers a raw reading in the same cell")
        self.assertEqual(rows[5 - 5][10 + 5], "~", "north is up and east is right")
        self.assertEqual(sum(r.count("f") for r in rows), 0, "other spaces are not drawn")
        self.assertTrue(all(len(r) == 21 for r in rows) and len(rows) == 11)
        self.assertEqual(sum(r.count(".") for r in rows), 0, "the far one is off the screen")

    def test_fit_shows_everything(self):
        mod = load(ATLAS / "map")
        marks = [core.mark("sight", (x, y, 0), v=1, t=1) for x, y in ((0, 0), (10000, 0), (0, 8000), (10000, 8000))]
        cx, cy, scale = mod.fit(marks, "world", 60, 20)
        rows = mod.render(marks, "world", cx, cy, scale, 60, 20)
        self.assertEqual(sum(r.count(".") for r in rows), 4)
        self.assertEqual(mod.fit([], "world", 60, 20), (0, 0, 100))

    def test_the_screen_flow_and_it_never_writes(self):
        app = FakeApp()
        s = store_of(app)
        s.add([core.mark("sight", (0, 0, 0), v=1, t=1), core.ingest("a.txt", "espresso grinder notes", t=1, space="mind")])
        mod = load(ATLAS / "map")
        shown = FakeApp(space=app.space, events=[{"cmd": "hello"}] + [{"cmd": "key", "key": k}
                                                                     for k in ["left", "up", "+", "-", "tab", "k", "f", "escape"]])
        mod.App = lambda: shown
        mod.main()
        self.assertTrue(shown.exited)
        self.assertEqual(shown.puts, [])
        self.assertIn("space", shown.screens[0][1][0])
        self.assertFalse(mod.Space(shown).put("x", "y"))
        self.assertFalse(mod.Space(shown).delete("x"))


def scene(rig_w=W, rig_h=H):
    """Four looks at a room: three of it empty (flat wall), then one with something big and near in it."""
    bare = two_layer_pair(4, 4, rect=(28, 92, 8, 62))
    near = two_layer_pair(4, 12, rect=(28, 92, 8, 62))
    sets = []
    for i, (l, r) in enumerate((bare, bare, bare, near)):
        sets.append({"t": 1000 + i, "frames": [bytes(l).hex(), bytes(r).hex()]})
    return {"w": rig_w, "h": rig_h, "sets": sets}


RIG = {"f": 100, "xs": [0, 60], "cams": ["video0", "video1"], "w": W, "h": H, "pose": [0, 0, 0, 0], "voxel": 100}


class TestScan(unittest.TestCase):
    def test_the_room_is_learned_then_what_is_new_is_an_event_at_the_right_distance(self):
        mod = load(ATLAS / "scan")
        marks, sm = mod.analyse(RIG, scene(), core.Background(keep=3))
        self.assertEqual((sm["sets"], sm["skipped"]), (4, 0))
        self.assertGreater(sm["voxels"], 100)
        ev = [m for m in marks if m["k"] == "event"]
        self.assertGreaterEqual(len(ev), 1)
        self.assertTrue(300 <= ev[0]["p"][1] <= 900, ev[0]["p"])                 # the near thing is about 500 mm away
        self.assertTrue(all(m["t"] == 1003 for m in ev), "only the last look had something new in it")

    def test_nothing_is_called_new_before_the_room_is_known(self):
        mod = load(ATLAS / "scan")
        one = {"w": W, "h": H, "sets": [scene()["sets"][3]]}
        marks, sm = mod.analyse(RIG, one, core.Background(keep=3))
        self.assertEqual(sm["events"], 0)
        self.assertTrue(sm["learning"])

    def test_the_wall_in_the_empty_room_is_at_the_right_distance(self):
        mod = load(ATLAS / "scan")
        marks, _ = mod.analyse(RIG, {"w": W, "h": H, "sets": [scene()["sets"][0]]}, core.Background())
        ys = sorted(m["p"][1] for m in marks if m["k"] == "sight")
        self.assertTrue(1300 <= ys[len(ys) // 2] <= 1700, ys[len(ys) // 2])     # f=100, B=60, d=4: 1500 mm

    def test_unusable_looks_are_skipped_not_believed(self):
        mod = load(ATLAS / "scan")
        data = scene()
        data["sets"][0]["frames"][0] = "zz"                                       # not hex
        data["sets"][1]["frames"] = data["sets"][1]["frames"][:1]                 # one camera missing
        data["sets"][2]["frames"][1] = "00" * 10                                  # wrong size
        marks, sm = mod.analyse(RIG, data, core.Background())
        self.assertEqual((sm["sets"], sm["skipped"]), (1, 3))

    def test_the_rig_is_checked(self):
        mod = load(ATLAS / "scan")
        good = json.dumps(RIG)
        self.assertEqual(mod.load_rig(good)[1], "rig from cfg-rig")
        bads = [None, "not json", "[]", json.dumps({**RIG, "f": 1.5}), json.dumps({**RIG, "xs": [0, 0]}),
                json.dumps({**RIG, "xs": [0]}), json.dumps({**RIG, "cams": ["video0"]}),
                json.dumps({**RIG, "cams": ["video0", "../../etc"]}), json.dumps({**RIG, "w": 9999}),
                json.dumps({**RIG, "pose": [1, 2, 3]}), json.dumps({**RIG, "voxel": 5})]
        for raw in bads:
            rig, note = mod.load_rig(raw)
            self.assertEqual(rig, mod.DEFAULT, raw)
            self.assertNotEqual(note, "rig from cfg-rig")

    def test_pressing_s_asks_the_os_for_exactly_what_the_rig_says_and_saves_the_marks(self):
        app = run("scan", keys=["s", "escape"], space={"cfg-rig": json.dumps(RIG)},
                  services={"camera.capture": {"ok": True, "detail": "", "data": scene()}})
        name, args = app.calls[0]
        self.assertEqual(name, "camera.capture")
        self.assertEqual(args, {"cams": ["video0", "video1"], "width": W, "height": H, "count": 4, "every_ms": 400})
        kinds = store_of(app).stats()["kinds"]
        self.assertGreater(kinds["sight"], 100)
        self.assertIn("event", kinds)
        self.assertIn("things that moved", app.text)
        self.assertEqual(len(app.calls), 1, "one capture per key press, nothing by itself")

    def test_a_refusal_from_the_os_is_shown_and_nothing_is_saved(self):
        app = run("scan", keys=["s", "escape"], services={"camera.capture": {"ok": False, "detail": "no password", "data": {}}})
        self.assertIn("refused: no password", app.text)
        self.assertEqual(app.puts, [])

    def test_no_write_permission_is_reported_not_crashed(self):
        app = run("scan", keys=["s", "escape"], refuse=True, services={"camera.capture": {"ok": True, "detail": "", "data": scene()}})
        self.assertIn("could not be saved", app.text)


class TestSense(unittest.TestCase):
    SWEEP = {"ok": True, "detail": "", "data": {"t": 5000, "sensors": [
        {"index": 0, "name": "bme680", "skipped": 0, "readings": [
            {"attr": "in_temp_input", "kind": "heat", "unit": "mC", "v": 23500},
            {"attr": "in_resistance_raw", "kind": "smell", "unit": "ohm", "v": 12345}]},
        {"index": 1, "name": "odd", "skipped": 0, "readings": [{"attr": "x", "kind": "smell", "unit": "ohm", "v": 1.5},
                                                                {"attr": "y", "kind": "Bad Kind", "unit": "", "v": 3}]}]}}

    def test_readings_become_marks_at_the_places_they_were_given(self):
        mod = load(ATLAS / "sense")
        marks = mod.marks_from_sweep(self.SWEEP["data"], {"0": [100, 200, 300]})
        self.assertEqual([(m["k"], m["v"], m["p"], m["r"]) for m in marks],
                         [("heat", 23500, [100, 200, 300], "bme680-0"), ("smell", 12345, [100, 200, 300], "bme680-0")],
                         "a reading that is not a whole number, or has a bad kind, is not a mark")

    def test_a_sensor_with_no_place_is_nowhere(self):
        mod = load(ATLAS / "sense")
        self.assertIsNone(mod.marks_from_sweep(self.SWEEP["data"], {})[0]["p"])

    def test_positions_are_checked(self):
        mod = load(ATLAS / "sense")
        raw = json.dumps({"0": [1, 2, 3], "x": [1, 2, 3], "1": [1, 2], "2": [1.5, 2, 3], "3": [10 ** 12, 0, 0], "4": "no"})
        self.assertEqual(mod.load_positions(raw), {"0": [1, 2, 3]})
        for bad in (None, "", "{{", "[]", "7"):
            self.assertEqual(mod.load_positions(bad), {})

    def test_pressing_r_sweeps_once_and_saves(self):
        app = run("sense", keys=["r", "escape"], space={"cfg-sensors": json.dumps({"0": [0, 0, 0]})}, services={"sensor.sweep": self.SWEEP})
        self.assertEqual([c[0] for c in app.calls], ["sensor.sweep"])
        self.assertEqual(store_of(app).stats()["kinds"], {"heat": 1, "smell": 1})
        self.assertIn("nowhere yet", app.text)

    def test_a_refusal_is_shown(self):
        app = run("sense", keys=["r", "escape"], services={"sensor.sweep": {"ok": False, "detail": "no password", "data": {}}})
        self.assertIn("refused: no password", app.text)


class TestPlace(unittest.TestCase):
    def say(self, *lines, space=None):
        keys = []
        for ln in lines:
            keys += typed(ln) + ["enter"]
        return run("place", keys=keys + ["escape"], space=space)

    def test_what_it_writes_is_what_scan_and_sense_read(self):
        app = self.say("sensor 0 100 200 300", "sensor 3 -5 0 40", "rig 100 0 60", "pose 10 20 30 90", "size 96 72")
        scan, sense = load(ATLAS / "scan"), load(ATLAS / "sense")
        self.assertEqual(sense.load_positions(app.space["cfg-sensors"]), {"0": [100, 200, 300], "3": [-5, 0, 40]})
        rig, note = scan.load_rig(app.space["cfg-rig"])
        self.assertEqual(note, "rig from cfg-rig")
        self.assertEqual((rig["f"], rig["xs"], rig["cams"], rig["pose"], rig["w"], rig["h"]),
                         (100, [0, 60], ["video0", "video1"], [10, 20, 30, 90], 96, 72))

    def test_three_cameras(self):
        app = self.say("rig 120 0 60 -40")
        rig = json.loads(app.space["cfg-rig"])
        self.assertEqual((rig["xs"], rig["cams"]), ([0, 60, -40], ["video0", "video1", "video2"]))

    def test_nonsense_is_refused_with_the_usage_and_nothing_is_written(self):
        for bad in ("sensor 0 1 2", "sensor x 1 2 3", "sensor 5000 1 2 3", "sensor 0 1.5 2 3", "rig 5 0 60", "rig 100 0 0",
                    "rig 100 0", "rig 100 0 60 1 2 3 4", "pose 1 2 3", "size 10 10", "size 9999 9999", "frobnicate", "rig 100 0 99999",
                    "sensor 0 9999999999 0 0"):
            app = self.say(bad)
            self.assertEqual(app.puts, [], bad)
            self.assertNotEqual(app.screens[-1][1][2], "saved", bad)

    def test_show_and_the_refusal_to_save(self):
        app = self.say("sensor 1 1 2 3", "show")
        self.assertIn('"1": [1, 2, 3]', app.text)
        self.assertIn("could not save", run("place", keys=typed("pose 1 2 3 4") + ["enter", "escape"], refuse=True).text)

    def test_it_reads_and_controls_nothing_but_its_two_settings(self):
        app = self.say("sensor 0 1 2 3", "rig 100 0 60", "pose 1 1 1 1", "size 64 48")
        self.assertEqual(set(app.puts), {"cfg-sensors", "cfg-rig"})
        self.assertEqual(app.calls, [], "no service of any kind")


class TestFiles(unittest.TestCase):
    WALK = {"ok": True, "detail": "", "data": {"root": "/r", "t": 7000, "truncated": False, "entries": [
        {"path": "notes", "dir": True, "size": 0},
        {"path": "notes/coffee.md", "dir": False, "size": 80, "head": "coffee espresso grinder crema extraction " * 3},
        {"path": "notes/coffee-copy.md", "dir": False, "size": 80, "head": "coffee espresso grinder crema extraction " * 3},
        {"path": "pics", "dir": True, "size": 0},
        {"path": "pics/a.png", "dir": False, "size": 9_000_000, "sample": (b"\x89PNG\r\n\x1a\n" + bytes(range(200))).hex()},
        {"path": "pics/bad.bin", "dir": False, "size": 10, "sample": "not hex"},
        {"path": 5, "dir": False, "size": 1}, {"path": "x", "dir": False, "size": 1.5}, "junk"]}}

    def test_text_and_non_text_files_both_get_a_place_and_malformed_entries_are_skipped(self):
        mod = load(ATLAS / "files")
        marks = mod.build(self.WALK["data"])
        files = [m for m in marks if m["k"] == "file"]
        self.assertEqual(len(files), 6, "the two malformed entries and the junk are skipped")
        data = {m["r"]: m for m in marks if m["k"] == "data"}
        self.assertEqual(set(data), {"notes/coffee.md", "notes/coffee-copy.md", "pics/a.png"})
        self.assertIn("png image", data["pics/a.png"]["l"])
        self.assertIn("9000000 bytes", data["pics/a.png"]["l"], "the real size, not the size of the sample")
        self.assertTrue(all(m["s"] == "files-text" for m in data.values()))

    def test_pressing_enter_walks_once_and_the_copies_collapse_when_digested(self):
        app = run("files", keys=typed("/r") + ["enter", "escape"], services={"files.walk": self.WALK})
        name, args = app.calls[0]
        self.assertEqual((name, args["path"], args["heads"], args["limit"], args["depth"]), ("files.walk", "/r", True, 1000, 5))
        self.assertEqual(len(app.calls), 1)
        s = store_of(app)
        self.assertEqual(s.stats()["kinds"]["data"], 3)
        rep = load(ATLAS / "digest").digest(s)
        self.assertIn("duplicates folded: 1", rep)
        self.assertEqual(s.stats()["kinds"]["data"], 2)

    def test_a_truncated_walk_says_so_and_a_refusal_is_shown(self):
        w = json.loads(json.dumps(self.WALK))
        w["data"]["truncated"] = True
        self.assertIn("stopped at the limit", run("files", keys=typed("/r") + ["enter", "escape"], services={"files.walk": w}).text)
        self.assertIn("refused: no", run("files", keys=typed("/r") + ["enter", "escape"],
                                         services={"files.walk": {"ok": False, "detail": "no", "data": {}}}).text)

    def test_nothing_is_asked_without_a_path(self):
        self.assertEqual(run("files", keys=["enter", "escape"], services={}).calls, [])


class TestPut(unittest.TestCase):
    CLOCK = {"ok": True, "detail": "", "data": {"t": 9000}}

    def test_naming(self):
        mod = load(ATLAS / "put")
        self.assertEqual(mod.split_name("espresso grind fine"), ("espresso grind fine", "espresso grind fine"))
        self.assertEqual(mod.split_name("/name recipe espresso: grind fine"), ("recipe", "espresso: grind fine"))
        self.assertEqual(mod.split_name("/name only"), ("", ""))

    def test_typed_text_is_timestamped_placed_and_found_again(self):
        app = run("put", keys=typed("espresso machine descaling needs citric acid") + ["enter", "escape"],
                  services={"clock.now": self.CLOCK})
        self.assertEqual([c[0] for c in app.calls], ["clock.now"])
        found = store_of(app).search(kind="data")
        self.assertEqual((len(found), found[0]["t"]), (1, 9000))
        self.assertIn("saved", app.text)

    def test_the_same_thing_typed_twice_folds_into_one_that_remembers(self):
        app = run("put", keys=typed("espresso machine descaling needs citric acid") + ["enter"] +
                  typed("Espresso machine descaling needs citric acid!") + ["enter", "escape"], services={"clock.now": self.CLOCK})
        s = store_of(app)
        load(ATLAS / "digest").digest(s)
        got = s.search(kind="data")
        self.assertEqual((len(got), got[0]["n"]), (1, 2))

    def test_a_refused_clock_saves_nothing_and_a_name_with_no_text_is_refused(self):
        app = run("put", keys=typed("hello world again") + ["enter", "escape"],
                  services={"clock.now": {"ok": False, "detail": "no password", "data": {}}})
        self.assertIn("refused: no password", app.text)
        self.assertEqual(app.puts, [])
        app = run("put", keys=typed("/name lonely") + ["enter", "escape"], services={})
        self.assertEqual(app.calls, [], "refused before the clock was asked")


class TestDigest(unittest.TestCase):
    def test_an_empty_map_says_so(self):
        self.assertEqual(load(ATLAS / "digest").digest(core.MarkStore(Mem())), ["the map is empty: nothing to do"])

    def test_pressing_d_reports_and_doing_it_twice_changes_nothing(self):
        app = FakeApp()
        s = store_of(app)
        s.add([core.ingest("a.txt", "espresso grinder notes crema", t=100), core.ingest("b.txt", "espresso grinder notes crema!", t=200)])
        a = run("digest", keys=["d", "escape"], space=app.space)
        self.assertIn("duplicates folded: 1", a.text)
        snapshot = dict(a.space)
        b = run("digest", keys=["d", "escape"], space=a.space)
        self.assertIn("duplicates folded: 0", b.text)
        self.assertEqual(b.space, snapshot, "the second pass wrote the same map")

    def test_a_folder_it_may_not_write_is_reported(self):
        app = FakeApp()
        store_of(app).add([core.ingest("a.txt", "espresso grinder notes crema", t=1)])

        class Failing(Backend):
            def put(self, k, v):
                return False
        mod = load(ATLAS / "digest")
        with self.assertRaises(OSError):
            mod.digest(core.MarkStore(Failing(app)))
        shown = run("digest", keys=["d", "escape"], space=app.space, refuse=True)
        self.assertIn("could not be saved", shown.text)


class TestOneMapManyKinds(unittest.TestCase):
    """The whole idea: pictures, smells, files, notes and a count of likes, in one map, folded and found."""

    def test_everything_goes_in_the_same_map_and_comes_out_smarter(self):
        app = FakeApp()
        # 1. cameras: an empty room, then something near in it
        s = store_of(app)
        marks, _ = load(ATLAS / "scan").analyse(RIG, scene(), core.Background(keep=3))
        s.add(marks)
        # 2. noses at four corners, the source near (500, 1500)
        src = (500, 1500, 0)
        for i, p in enumerate(((0, 0, 0), (2000, 0, 0), (0, 2000, 0), (2000, 2000, 0))):
            d2 = sum((p[j] - src[j]) ** 2 for j in range(3))
            s.add([core.mark("smell", p, v=4_000_000_000 // d2 + 100, t=1000, ref=f"nose-{i}", unit="ohm", space="world")])
        # 3. files and notes, with copies
        walk = json.loads(json.dumps(TestFiles.WALK["data"]))
        walk["entries"].append({"path": "notes/brew.md", "dir": False, "size": 90,
                                "head": "coffee espresso grinder crema extraction brewing " * 3})
        s.add(load(ATLAS / "files").build(walk))
        s.add([core.ingest("note", "espresso grinder crema extraction coffee", t=1100, space="files-text", ref="note")])
        # 4. likes rising on a video, and a much later note so the old raw cells are an hour old
        for i, n in enumerate((100, 180, 300, 520, 900)):
            s.add([core.mark("likes", None, v=n, t=1000 + 3600 * i, ref="video:cats", unit="likes", space="mind")])
        s.add([core.mark("note", None, label="later", t=1000 + 3600 * 5, ref="n")])
        before, raw_before = s.chars(), s.stats()["kinds"]["sight"]
        lines = load(ATLAS / "digest").digest(s)
        text = "\n".join(lines)
        self.assertIn("regions:", text)
        kinds = s.stats()["kinds"]
        self.assertIn("region", kinds)
        self.assertIn("source", kinds, "four noses found where the smell comes from")
        self.assertIn("trend", kinds, "the likes are rising")
        self.assertIn("theme", kinds, "the coffee notes belong together")
        self.assertGreater(raw_before, 100)
        self.assertLess(kinds.get("sight", 0) * 10, raw_before, "the old raw cells were folded into regions")
        self.assertLess(s.chars(), before)
        # and the finder finds each, asked the same way
        find = load(ATLAS / "find")
        self.assertTrue(any("smell source" in l for l in find.answer(s, "/kind source")))
        self.assertTrue(any("rising" in l for l in find.answer(s, "/kind trend")))
        self.assertTrue(any("theme" in l for l in find.answer(s, "/kind theme")))
        self.assertTrue(any("espresso" in l or "coffee" in l for l in find.answer(s, "/similar espresso grinder crema extraction coffee")))


class TestAgentZip(unittest.TestCase):
    def test_what_it_asks_and_what_it_shows(self):
        mod = load(ROOT / "apps" / "zip" / "run")
        ok = {"ok": True, "detail": "", "data": {"name": "hello-agent", "sha256": "a" * 64, "asked": ["network"], "status": 0,
                                                 "output": ["app| hi"]}}
        app = FakeApp(events=[{"cmd": "hello"}] + [{"cmd": "key", "key": k} for k in typed("/tmp/a.zip") + ["enter", "escape"]],
                      services={"zip.run": ok})
        mod.App = lambda: app
        mod.main()
        self.assertEqual(app.calls, [("zip.run", {"path": "/tmp/a.zip", "seconds": 30})])
        self.assertIn("asked for: network (none granted)", app.text)
        self.assertIn("app| hi", app.text)
        self.assertEqual(mod.show({"ok": False, "detail": "no"}), ["refused: no"])

    def test_it_asks_for_the_zip_service_and_nothing_else(self):
        m = Manifest.parse((ROOT / "apps" / "zip" / "run" / "manifest.json").read_bytes())
        self.assertEqual((m.name, list(m.permissions)), ("zip.run", ["service:zip"]))


if __name__ == "__main__":
    unittest.main()
