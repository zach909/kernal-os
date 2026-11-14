"""The smart home group (``apps/home``): three separate apps that share one folder, ``home``.

Imports only modules that stand on their own (proof gate, manifests, the shared-folder store), so it runs
without the session/CLI layer. The apps are driven through their real ``main()`` with a fake SDK."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import proof  # noqa: E402
from kos.kapp import Manifest, pack_tree  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.spaces import AppStorage, StorageError  # noqa: E402
from kos.vault import Vault  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "apps" / "home"
NAMES = {"devices": "home.devices", "pair": "home.pair", "control": "home.control"}
GOOD = {"name": "Lamp", "room": "Den", "kind": "light", "on": False, "level": 50}


def load(prog):
    spec = importlib.util.spec_from_file_location(f"home_{prog}", HOME / prog / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeApp:
    """Stands in for kos.sdk.App: a dict for the space, a scripted event list, the screens it drew."""
    def __init__(self, store=None, events=(), refuse=False):
        self.store, self._events, self.refuse = dict(store or {}), list(events), refuse
        self.vault_error, self.height, self.screens, self.exited = "", 24, [], False

    def events(self):
        yield from self._events

    def vault_keys(self, space=None):
        assert space == "home"
        return list(self.store)

    def vault_get(self, key, space=None):
        assert space == "home"
        return self.store.get(key)

    def vault_put(self, key, value, space=None):
        assert space == "home"
        if self.refuse:
            self.vault_error = "no write access"
            return False
        self.store[key] = value
        return True

    def screen(self, title, lines, status=""):
        self.screens.append("\n".join(lines))

    def exit(self, code=0):
        self.exited = True


def run(prog, **kw):
    mod, app = load(prog), FakeApp(**kw)
    mod.App = lambda: app
    mod.main()
    return app


def keys(*ks):
    return [{"cmd": "hello"}] + [{"cmd": "key", "key": k} for k in ks]


class TestGroupShape(unittest.TestCase):
    def test_each_program_is_its_own_app_with_only_its_own_permission(self):
        want = {"devices": ["owns:home"], "pair": ["uses:home"], "control": ["uses:home"]}
        for prog, perms in want.items():
            m = Manifest.parse((HOME / prog / "manifest.json").read_bytes())
            self.assertEqual((m.name, list(m.permissions)), (NAMES[prog], perms))
            self.assertNotIn("network", m.permissions)            # rule 3: no connection of any kind
            self.assertNotIn("system", m.permissions)

    def test_the_group_has_no_manifest_so_no_permissions_of_its_own(self):
        self.assertFalse((HOME / "manifest.json").exists())

    def test_the_group_packs_through_the_proof_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            got = {m.name for m in pack_tree(HOME, Path(tmp))}
        self.assertEqual(got, set(NAMES.values()))

    def test_no_decimals_and_nothing_imported_from_the_os_but_the_sdk(self):
        import ast
        for p in HOME.rglob("app.py"):
            self.assertEqual(proof.violations(p.read_bytes(), p.name), [], p)
            for node in ast.walk(ast.parse(p.read_text())):
                mods = ([node.module] if isinstance(node, ast.ImportFrom) and node.module else
                        [a.name for a in node.names] if isinstance(node, ast.Import) else [])
                for mod in mods:
                    self.assertTrue(not mod.startswith("kos") or mod == "kos.sdk", f"{p} imports {mod}")


class TestSharedFolderPermissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(Path(self.tmp.name))
        self.perms = Permissions(self.paths)

    def storage(self, prog):
        m = Manifest.parse((HOME / prog / "manifest.json").read_bytes())
        return AppStorage(self.paths, m.name, m.permissions)

    def test_pair_and_control_get_nothing_until_the_owner_grants_them(self):
        self.storage("devices").vault("home", "get")                  # the owner creates the folder
        for prog in ("pair", "control"):
            with self.assertRaises(StorageError):
                self.storage(prog).vault("home", "get")

    def test_a_read_grant_is_not_a_write_grant(self):
        self.storage("devices").vault("home", "get")
        self.perms.grant("home.control", "space:home", "read")
        s = self.storage("control")
        s.vault("home", "get")
        with self.assertRaises(StorageError):
            s.vault("home", "put")

    def test_a_write_grant_lets_it_write_and_the_overview_sees_it(self):
        owner = self.storage("devices")
        owner.vault("home", "get")
        self.perms.grant("home.pair", "space:home", "write")
        self.storage("pair").vault("home", "put").put("dev-1", json.dumps(GOOD))
        self.assertEqual(json.loads(owner.vault("home", "get").get("dev-1"))["name"], "Lamp")


class TestOverview(unittest.TestCase):
    def test_it_lists_devices_by_room_and_says_nothing_reaches_them(self):
        store = {"dev-1": json.dumps(GOOD), "dev-2": json.dumps({**GOOD, "name": "Heat", "kind": "thermostat",
                                                                 "on": True, "level": 21})}
        out = run("devices", store=store, events=keys()).screens[-1]
        self.assertIn("Lamp", out)
        self.assertIn("21 C", out)
        self.assertIn("no device-to-device link", out)

    def test_hostile_records_are_hidden_counted_and_never_drawn(self):
        evil = {**GOOD, "name": "\x1b[2Jowned\x00"}
        store = {"dev-1": json.dumps(GOOD), "dev-2": json.dumps(evil), "dev-3": "{nope", "../x": json.dumps(GOOD),
                 "dev-4": json.dumps({**GOOD, "level": 1.5}), "dev-5": json.dumps({**GOOD, "level": True}),
                 "dev-6": json.dumps({**GOOD, "kind": "oven"}), "dev-7": json.dumps({**GOOD, "extra": 1}),
                 "dev-8": json.dumps({**GOOD, "level": 101}), "dev-9": json.dumps({**GOOD, "name": "x" * 25}),
                 "dev-10": json.dumps([1])}
        out = run("devices", store=store, events=keys()).screens[-1]
        self.assertIn("Lamp", out)
        self.assertNotIn("\x1b", out)
        self.assertIn("?[2Jowned?", out)                  # the hostile name is shown defanged, not dropped
        self.assertIn("9 record(s)", out)                 # every other bad record is counted, none drawn

    def test_control_characters_in_a_valid_record_are_replaced_not_drawn(self):
        mod = load("devices")
        rec = mod.valid_record(json.dumps({**GOOD, "name": "a\x1b[2Jb"}))
        self.assertEqual(rec["name"], "a?[2Jb")

    def test_it_has_no_way_to_write(self):
        app = run("devices", store={"dev-1": json.dumps(GOOD)}, events=keys("r", "x", "enter", "left"))
        self.assertEqual(json.loads(app.store["dev-1"]), GOOD)
        self.assertEqual(list(app.store), ["dev-1"])

    def test_escape_leaves(self):
        self.assertTrue(run("devices", events=keys("escape")).exited)


class TestPair(unittest.TestCase):
    def test_it_pairs_a_device_with_a_safe_starting_state(self):
        app = run("pair", events=keys(*"Lamp", "tab", *"Den", "tab", "right", "enter"))
        self.assertEqual(json.loads(app.store["dev-1"]),
                         {"name": "Lamp", "room": "Den", "kind": "plug", "on": False, "level": 100})

    def test_a_new_device_never_overwrites_an_old_one(self):
        old = json.dumps(GOOD)
        app = run("pair", store={"dev-1": old, "dev-3": old}, events=keys(*"New", "enter"))
        self.assertEqual(app.store["dev-1"], old)
        self.assertEqual(app.store["dev-3"], old)
        self.assertEqual(json.loads(app.store["dev-2"])["name"], "New")

    def test_no_name_means_nothing_is_written(self):
        app = run("pair", events=keys("enter"))
        self.assertEqual(app.store, {})
        self.assertIn("give the device a name", app.screens[-1])

    def test_input_is_cut_at_the_limit_and_control_keys_are_not_typed(self):
        app = run("pair", events=keys(*("a" * 40), "ctrl-x", "enter"))
        self.assertEqual(json.loads(app.store["dev-1"])["name"], "a" * 24)

    def test_the_home_is_full_at_64_devices(self):
        full = {f"dev-{n}": json.dumps(GOOD) for n in range(1, 65)}
        app = run("pair", store=full, events=keys(*"X", "enter"))
        self.assertEqual(len(app.store), 64)
        self.assertIn("full", app.screens[-1])

    def test_a_refused_write_is_reported(self):
        app = run("pair", refuse=True, events=keys(*"X", "enter"))
        self.assertIn("not saved: no write access", app.screens[-1])

    def test_it_cannot_change_or_remove_a_device(self):
        src = (HOME / "pair" / "app.py").read_text()
        self.assertNotIn("vault_delete", src)
        self.assertNotIn("vault_get", src)


class TestControl(unittest.TestCase):
    def store(self, **kw):
        return {"dev-1": json.dumps({**GOOD, **kw})}

    def test_enter_toggles_and_records_the_request(self):
        app = run("control", store=self.store(), events=keys("enter"))
        self.assertTrue(json.loads(app.store["dev-1"])["on"])
        self.assertIn("asked for", app.screens[-1])
        self.assertIn("does not reach the device", app.screens[-1])

    def test_levels_move_in_whole_steps_and_stop_at_the_ends(self):
        app = run("control", store=self.store(level=95), events=keys("right", "right"))
        self.assertEqual(json.loads(app.store["dev-1"])["level"], 100)
        app = run("control", store=self.store(level=5), events=keys("left", "left"))
        self.assertEqual(json.loads(app.store["dev-1"])["level"], 0)

    def test_a_thermostat_stays_between_10_and_30_by_ones(self):
        app = run("control", store=self.store(kind="thermostat", level=29), events=keys("right", "right"))
        self.assertEqual(json.loads(app.store["dev-1"])["level"], 30)
        app = run("control", store=self.store(kind="thermostat", level=11), events=keys("left", "left", "left"))
        self.assertEqual(json.loads(app.store["dev-1"])["level"], 10)

    def test_a_lock_has_no_level_to_change(self):
        before = self.store(kind="lock", level=100)
        app = run("control", store=before, events=keys("left", "right"))
        self.assertEqual(app.store, before)

    def test_it_never_adds_or_removes_a_device(self):
        app = run("control", store=self.store(), events=keys("enter", "down", "up", "x", "delete"))
        self.assertEqual(list(app.store), ["dev-1"])

    def test_a_hostile_record_cannot_be_selected_or_rewritten(self):
        bad = {"dev-1": json.dumps({**GOOD, "level": 9999}), "dev-2": "{nope"}
        app = run("control", store=bad, events=keys("enter", "left"))
        self.assertEqual(app.store, bad)
        self.assertIn("no devices", app.screens[-1])

    def test_a_refused_write_changes_nothing_on_screen_state(self):
        app = run("control", store=self.store(), refuse=True, events=keys("enter"))
        self.assertIn("not saved: no write access", app.screens[-1])
        self.assertFalse(json.loads(app.store["dev-1"])["on"])

    def test_no_devices_does_not_crash_on_any_key(self):
        app = run("control", events=keys("up", "down", "enter", "left", "right"))
        self.assertIn("no devices", app.screens[-1])


if __name__ == "__main__":
    unittest.main()
