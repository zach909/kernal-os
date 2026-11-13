"""Rule 5, everything is separate: the ``apps/`` folder holds one folder per function of the OS, each an
app that carries its own code. Plus the read-only ``status`` request the mouse, keyboard and display apps
use, and the wallpaper app with the taskbar that reads it."""

import ast
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos.desktop import FUNCTION_APPS, SYSTEM_APPS  # noqa: E402
from kos.kapp import KApp, Manifest, pack  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.protocol import STATUS_TOPICS, ProtocolError, validate_app_message  # noqa: E402
from kos.spaces import AppStorage, StorageError  # noqa: E402
from kos.vault import Vault  # noqa: E402
from test_kos import DesktopSessionEnv, _keys  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APPS = ROOT / "apps"
# Imports from the OS package an app may make. kos.sdk is the protocol client every app speaks through.
# kos.office is the one known exception (the App Library's search): it is listed as a gap in the README,
# so a new shared import fails here instead of slipping in.
ALLOWED_KOS_IMPORTS = {"kos.sdk": None, "kos.office": {"app-library"}}


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAppsFolder(unittest.TestCase):
    def folders(self):
        return sorted(p for p in APPS.iterdir() if p.is_dir() and not p.name.startswith((".", "__")))

    def test_every_function_of_the_os_is_a_folder_with_its_own_app(self):
        names = {p.name for p in self.folders()}
        self.assertTrue({*SYSTEM_APPS, *FUNCTION_APPS} <= names)
        for p in self.folders():
            has_app = (p / "manifest.json").is_file() or any(p.glob("*/manifest.json"))
            self.assertTrue(has_app, f"{p.name}: an apps/ folder must be an app (manifest.json) or hold programs")

    def test_each_app_packs_through_the_proof_gate_under_its_folder_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in (*SYSTEM_APPS, *FUNCTION_APPS):
                m = pack(APPS / name, Path(tmp) / f"{name}.kapp")
                self.assertEqual(m.name, name)
                self.assertEqual(KApp.from_file(Path(tmp) / f"{name}.kapp").manifest.name, name)

    def test_no_app_code_lives_outside_apps(self):
        self.assertFalse((ROOT / "examples" / "system").exists(), "the system apps moved to apps/")

    def test_apps_import_nothing_shared_except_the_sdk_and_the_listed_gap(self):
        for path in APPS.rglob("*.py"):
            app = path.relative_to(APPS).parts[0]
            for node in ast.walk(ast.parse(path.read_text())):
                mods = ([node.module] if isinstance(node, ast.ImportFrom) and node.module else
                        [a.name for a in node.names] if isinstance(node, ast.Import) else [])
                for mod in mods:
                    if mod != "kos" and not mod.startswith("kos."):
                        continue
                    key = next((k for k in ALLOWED_KOS_IMPORTS if mod == k or mod.startswith(k + ".")), None)
                    ok = key is not None and (ALLOWED_KOS_IMPORTS[key] is None or app in ALLOWED_KOS_IMPORTS[key])
                    self.assertTrue(ok, f"{path.relative_to(ROOT)} imports {mod}: apps carry their own code")

    def test_the_status_apps_may_ask_for_status_and_nothing_else(self):
        for name in ("mouse", "keyboard", "display"):
            m = Manifest.parse((APPS / name / "manifest.json").read_bytes())
            self.assertEqual(list(m.permissions), ["ask:status"], name)

    def test_the_wallpaper_owns_one_folder_and_has_no_system_power(self):
        m = Manifest.parse((APPS / "wallpaper" / "manifest.json").read_bytes())
        self.assertEqual(list(m.permissions), ["owns:wallpaper"])


class TestStatusRequest(unittest.TestCase):
    def test_every_topic_is_accepted_in_every_mode(self):
        for mode in ("tui", "graphical", "cmd"):
            for topic in STATUS_TOPICS:
                out = validate_app_message({"cmd": "request", "action": "status", "topic": topic}, mode)
                self.assertEqual(out, {"cmd": "request", "action": "status", "topic": topic})

    def test_hostile_status_requests_are_rejected(self):
        for bad in ({"topic": "disk"}, {"topic": "../etc/passwd"}, {"topic": ["mouse"]}, {"topic": None},
                    {"topic": 7}, {}, {"topic": "mouse", "device": "/dev/input/event0"},
                    {"topic": "mouse", "path": "/x"}):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "request", "action": "status", **bad}, "tui")


class TestStatusApps(DesktopSessionEnv):
    def run_app(self, name, mode="tui", **kw):
        s = self.start(APPS / name, name, mode, **kw)
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        return self.output()

    def test_the_mouse_app_shows_what_the_os_says(self):
        out = self.run_app("mouse", status_ok=True)
        self.assertIn("booted", out)
        self.assertIn("scripted", out)                 # the backend the OS reads the mouse with

    def test_the_keyboard_app_shows_what_the_os_keeps(self):
        out = self.run_app("keyboard", status_ok=True)
        self.assertIn("Ctrl-C", out)
        self.assertIn("always the OS", out)

    def test_the_display_app_shows_the_mode_and_size(self):
        out = self.run_app("display", status_ok=True)
        self.assertIn("100", out)                      # width of the surface the test gives the app
        self.assertIn("tuisurface", out)

    def test_without_the_permission_the_os_says_no_and_tells_nothing(self):
        out = self.run_app("mouse")                    # status_ok left False: no 'ask:status' from the manifest
        self.assertIn("does not have the 'ask:status' or 'system' permission", out)
        self.assertNotIn("scripted", out)

    def test_a_session_with_only_a_bridge_still_needs_the_status_permission(self):
        from kos.system import SystemBridge
        out = self.run_app("mouse", bridge=SystemBridge(self.paths, allowed=frozenset({"apps"}), who="mouse"))
        self.assertIn("does not have the 'ask:status' or 'system' permission", out)


class TestWallpaper(DesktopSessionEnv):
    def test_it_saves_the_chosen_colour_in_its_own_shared_folder(self):
        storage = AppStorage(self.paths, "wallpaper", ["owns:wallpaper"])
        s = self.start(APPS / "wallpaper", "wallpaper", vault=storage)
        self.boot_both()
        threading.Timer(2.0, lambda: self.devices.push(*_keys("3"), {"type": "key", "key": "enter"})).start()
        threading.Timer(4.0, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        v = Vault(self.paths, directory=self.paths.state / "spaces" / "wallpaper")
        self.assertEqual(v.get("color"), "#16361f")
        self.assertIn("saved", self.output())

    def test_the_taskbar_cannot_read_it_until_the_owner_grants_it(self):
        Vault(self.paths, directory=self.paths.state / "spaces" / "wallpaper").put("color", "#16361f")
        Permissions(self.paths).grant("wallpaper", "space:wallpaper", "own")
        taskbar = AppStorage(self.paths, "taskbar", ["system", "uses:wallpaper"])
        with self.assertRaises(StorageError):
            taskbar.vault("wallpaper", "get")
        Permissions(self.paths).grant("taskbar", "space:wallpaper", "read")
        self.assertEqual(taskbar.vault("wallpaper", "get").get("color"), "#16361f")
        with self.assertRaises(StorageError):          # read access never lets it change the background
            taskbar.vault("wallpaper", "put")

    def test_the_taskbar_trusts_only_a_plain_colour_from_another_app(self):
        tb = load("apps/taskbar/app.py", "tb_for_wallpaper")
        self.assertEqual(tb.valid_color("#16361F"), "#16361f")
        for bad in (None, 7, "", "red", "#12345", "#1234567", "#12345g", "16361f", "#16361f\n", "url(x)", ["#000000"]):
            self.assertIsNone(tb.valid_color(bad), bad)

    def test_the_wallpaper_swatches_are_all_plain_colours(self):
        wp = load("apps/wallpaper/app.py", "wp_colours")
        tb = load("apps/taskbar/app.py", "tb_colours")
        for _, color in wp.SWATCHES:
            self.assertEqual(tb.valid_color(color), color)

    def test_clicking_outside_every_swatch_picks_nothing(self):
        wp = load("apps/wallpaper/app.py", "wp_click")
        self.assertIsNone(wp.swatch_at(0, 0, 320))
        self.assertIsNone(wp.swatch_at(2000, 2000, 320))
        self.assertEqual(wp.swatch_at(wp.GAP + 1, wp.TOP + 1, 320), 0)


if __name__ == "__main__":
    unittest.main()
