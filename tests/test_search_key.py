"""The Windows key, the search popup and the desktop screen.
Run with: python3 -m unittest discover -s tests

The Windows key is the OS's (like the right mouse button): it never reaches an app, it does nothing before the
keyboard is booted, and it only switches to the search app the desktop told the session about."""

import importlib.util
import json
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import protocol  # noqa: E402
from kos.desktop import SYSTEM_APPS, Desktop  # noqa: E402
from kos.devices import INPUT_EVENT, EvdevTranslator  # noqa: E402
from kos.display import Framebuffer, parse_color  # noqa: E402
from kos.guard import Guard  # noqa: E402
from kos.kapp import pack  # noqa: E402
from kos.sdk import App  # noqa: E402
from test_kos import EXAMPLE, DesktopSessionEnv, _keys  # noqa: E402

EV_KEY = 1


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def raw(code, value):
    return INPUT_EVENT.pack(0, 0, EV_KEY, code, value)


class TestWindowsKeyDevice(unittest.TestCase):
    def test_a_press_of_either_windows_key_is_a_search_event(self):
        for code in (125, 126):
            self.assertEqual(EvdevTranslator(80, 24).feed(raw(code, 1)), [{"type": "search"}])

    def test_release_and_autorepeat_are_nothing(self):
        for value in (0, 2):
            self.assertEqual(EvdevTranslator(80, 24).feed(raw(125, value)), [])

    def test_it_does_not_disturb_shift_ctrl_or_the_keys_after_it(self):
        t = EvdevTranslator(80, 24)
        out = t.feed(raw(125, 1) + raw(125, 0) + raw(30, 1))
        self.assertEqual(out, [{"type": "search"}, {"type": "key", "key": "a"}])


class TestWindowsKeyGuard(unittest.TestCase):
    def test_it_is_rebuilt_with_no_fields_whatever_arrives_with_it(self):
        g = Guard()
        self.assertEqual(g.input_event({"type": "search", "key": "rm -rf /", "x": 1e9}, 80, 24), {"type": "search"})

    def test_other_events_are_still_judged(self):
        g = Guard()
        for bad in ({"type": "super"}, {"type": "searching"}, {"type": None}, {}, "search", None, 7):
            self.assertIsNone(g.input_event(bad, 80, 24))


class TestWindowsKeySession(DesktopSessionEnv):
    SEARCH = {"type": "search"}

    def run_with(self, *events, **kw):
        s = self.start(EXAMPLE, "hello", "cmd", **kw)
        self.boot_both()
        self.devices.push(*events)
        s.run(first_frame_timeout=0.5)
        return self.output()

    def test_it_opens_the_search_popup_and_the_app_never_sees_it(self):
        out = self.run_with(*_keys("x"), self.SEARCH, search_to="search-aaaaaa")
        self.assertEqual(self.outcome["switch"], ("instance", "search-aaaaaa"))
        self.assertIn('"key":"x"', out)                              # ordinary keys still reach the app
        self.assertNotIn("search", out.replace("search-aaaaaa", ""))   # the event itself never does

    def test_with_no_search_app_it_does_nothing_and_is_still_not_forwarded(self):
        out = self.run_with(self.SEARCH, *_keys("x"), {"type": "interrupt"})
        self.assertIsNone(self.outcome.get("switch"))
        self.assertNotIn('"type":"search"', out)

    def routed(self, **kw):
        """A started session, not run: its route() can be called directly, with devices booted by hand."""
        s = self.start(EXAMPLE, "hello", "cmd", **kw)
        self.addCleanup(lambda: (s.proc.kill(), s.proc.wait()))
        return s

    def test_before_the_keyboard_is_booted_it_does_nothing_and_after_it_it_switches(self):
        s = self.routed(search_to="search-aaaaaa")
        s.route(self.SEARCH)
        self.assertIsNone(s.switch)                                  # no password given: nothing happens
        s.booted.add("keyboard")
        s.route(self.SEARCH)
        self.assertEqual(s.switch, ("instance", "search-aaaaaa"))

    def test_a_mouse_alone_does_not_make_the_key_work(self):
        s = self.routed(search_to="search-aaaaaa")
        s.booted.add("mouse")
        s.route(self.SEARCH)
        self.assertIsNone(s.switch)

    def test_with_no_search_app_route_does_nothing_even_when_booted(self):
        s = self.routed()
        s.booted.update({"mouse", "keyboard"})
        s.route(self.SEARCH)
        self.assertIsNone(s.switch)

    def test_the_keyboard_status_says_so(self):
        s = self.start(EXAMPLE, "hello", "cmd", search_to="search-aaaaaa")
        self.assertIn(["Windows key", "search popup (the OS keeps it)"], s.status_fields("keyboard"))
        s2 = self.start(EXAMPLE, "hello", "cmd")
        self.assertIn(["Windows key", "does nothing here"], s2.status_fields("keyboard"))


class TestDesktopRoutes(unittest.TestCase):
    def run_desktop(self, script, **kw):
        calls = []

        def attach(target, ctx):
            calls.append((target, dict(ctx)))
            return script.pop(0)
        Desktop("desktop-1", "library-2", attach, **kw).run()
        return calls

    def test_the_search_target_is_set_but_not_while_in_the_search_app(self):
        calls = self.run_desktop([{"switch": ("instance", "search-3")}, {"switch": None}, {"exit_code": 0}],
                                 search="search-3")
        self.assertEqual(calls[0][1]["search_to"], "search-3")
        self.assertIsNone(calls[1][1]["search_to"])
        self.assertEqual(calls[2][1]["search_to"], "search-3")

    def test_without_a_search_app_there_is_no_target(self):
        self.assertIsNone(self.run_desktop([{"exit_code": 0}])[0][1]["search_to"])

    def test_the_two_new_apps_are_part_of_the_desktop(self):
        self.assertIn("desktop", SYSTEM_APPS)
        self.assertIn("search", SYSTEM_APPS)


class TestSearchApp(unittest.TestCase):
    def setUp(self):
        self.s = load("apps/search/app.py", "search_app")
        names = ["backup", "browser", "wallpaper", "mouse", "notes", "load-effect", "calendar"]
        self.installed = [{"name": n, "version": "1", "modes": ["tui", "graphical"]} for n in names + list(self.s.SYSTEM)]

    def names(self, q):
        return [e["name"] for e in self.s.results(q, self.installed)]

    def test_empty_query_lists_the_library_then_apps_alphabetically_never_the_desktop_parts(self):
        got = self.names("")
        self.assertEqual(got[0], "app-library")
        self.assertEqual(got[1:], sorted(got[1:]))
        for hidden in ("desktop", "taskbar", "search"):
            self.assertNotIn(hidden, got)

    def test_prefix_beats_contains_beats_gaps(self):
        self.assertEqual(self.names("w")[0], "wallpaper")
        self.assertEqual(self.names("ow")[:1], ["browser"])               # 'ow' is inside "browser"
        self.assertIn("wallpaper", self.names("wlp"))                    # letters in order with gaps
        self.assertEqual(self.names("zzz"), [])
        self.assertEqual(self.names("WALL"), ["wallpaper"])              # case does not matter

    def test_hostile_text_is_just_a_query(self):
        for q in ("../../etc/passwd", "\x00\x1b[31m", "a" * 500, "%s%n", "'; drop table", "‮"):
            self.s.results(q, self.installed)                            # never raises

    def test_a_bad_wallpaper_colour_falls_back(self):
        for bad in (None, "", "red", "#12", "#zzzzzz", "#1234567", 5, "#12345G"):
            self.assertIsNone(self.s.valid_color(bad))
        self.assertEqual(self.s.valid_color("#1F3A5F"), "#1f3a5f")
        self.assertEqual(self.s.dim("#ffffff"), "#7f7f7f")

    def test_every_frame_it_draws_passes_the_protocol_for_any_query(self):
        class Fake:
            width, height, mode = 640, 400, "graphical"

            def present(self, c):
                self.ops = c.ops
        for q in ("", "w", "no match here", "x" * 40):
            f = Fake()
            st = {"installed": self.installed, "open": [], "query": q, "sel": 3, "note": "n" * 90, "background": "#1f3a5f"}
            self.s.draw_graphical(f, st)
            protocol.validate_app_message({"cmd": "frame", "ops": f.ops}, "graphical")

    def test_typing_picks_and_opens_through_the_os_not_by_itself(self):
        sent = self.drive([{"cmd": "hello", "mode": "graphical", "width": 320, "height": 240},
                           {"cmd": "key", "key": "w"}, {"cmd": "key", "key": "a"}, {"cmd": "key", "key": "enter"},
                           {"cmd": "quit"}])
        self.assertIn({"cmd": "request", "action": "open", "app": "wallpaper", "mode": "graphical"}, sent)

    def test_escape_asks_the_os_to_go_back_to_the_desktop(self):
        sent = self.drive([{"cmd": "hello", "mode": "graphical", "width": 320, "height": 240},
                           {"cmd": "key", "key": "escape"}, {"cmd": "quit"}])
        self.assertIn({"cmd": "request", "action": "focus", "id": "desktop-aa"}, sent)

    def drive(self, events):
        a, b = socket.socketpair()
        sent, done = [], threading.Event()

        def os_side():
            f = b.makefile("rb")
            for line in f:
                m = json.loads(line)
                sent.append(m)
                if m["cmd"] == "vault":
                    b.sendall(json.dumps({"cmd": "vault", "id": m["id"], "ok": False, "detail": "none"}).encode() + b"\n")
                elif m == {"cmd": "request", "action": "apps"}:
                    ans = {"cmd": "apps", "installed": self.installed,
                           "open": [{"name": "desktop", "mode": "graphical", "id": "desktop-aa", "status": "running"}]}
                    b.sendall(json.dumps(ans).encode() + b"\n")
                    for ev in events[1:]:
                        b.sendall(json.dumps(ev).encode() + b"\n")
            done.set()
        t = threading.Thread(target=os_side, daemon=True)
        t.start()
        b.sendall(json.dumps(events[0]).encode() + b"\n")
        app_mod = self.s
        app_mod.App = lambda: App(a)
        try:
            app_mod.main()
        finally:
            app_mod.App = App
            a.shutdown(socket.SHUT_RDWR)
            t.join(5)
            a.close()
            b.close()
        return sent


class TestDesktopApp(unittest.TestCase):
    def setUp(self):
        self.d = load("apps/desktop/app.py", "desktop_app")
        names = ["backup", "browser", "wallpaper", "mouse", "notes", "calendar", "display", "keyboard", "load-effect"]
        self.installed = [{"name": n, "version": "1", "modes": ["tui", "graphical"]} for n in names + list(self.d.SYSTEM)]

    def test_icons_are_the_library_then_installed_apps_without_the_desktop_parts(self):
        got = [i["name"] for i in self.d.icons(self.installed)]
        self.assertEqual(got[0], "app-library")
        self.assertEqual(got[1:], sorted(got[1:]))
        self.assertFalse({"desktop", "taskbar", "search"} & set(got))

    def test_a_click_lands_on_exactly_the_icon_drawn_there(self):
        n = len(self.d.icons(self.installed))
        for i in range(n):
            x, y = self.d.cell_xy(i, 640)
            self.assertEqual(self.d.icon_at(x + 5, y + 5, 640, n), i)
        self.assertIsNone(self.d.icon_at(2, 2, 640, n))                  # the margin
        self.assertIsNone(self.d.icon_at(639, 10, 640, n))
        self.assertIsNone(self.d.icon_at(-5, -5, 640, n))
        x, y = self.d.cell_xy(n, 640)
        self.assertIsNone(self.d.icon_at(x + 5, y + 5, 640, n))          # an empty cell

    def test_the_bar_shows_running_apps_but_not_the_desktop_itself(self):
        op = [{"name": n, "mode": "g", "id": n + "-1", "status": "running"} for n in ("desktop", "search", "notes", "browser")]
        op.append({"name": "mouse", "mode": "g", "id": "m", "status": "stopped"})
        self.assertEqual([c[4] for c in self.d.chips(640, op)], ["NOTES", "BROWSER"])

    def test_every_frame_it_draws_passes_the_protocol_even_for_hostile_names(self):
        class Fake:
            width, height, mode = 320, 200, "graphical"

            def present(self, c):
                self.ops = c.ops
        evil = [{"name": "x\x1b[31m" * 20, "version": "1", "modes": ["tui"]},
                {"name": "‮evil", "version": "1", "modes": ["graphical"]}]
        for inst in (self.installed, evil, []):
            f = Fake()
            self.d.draw_graphical(f, {"installed": inst, "open": [], "sel": 0, "note": "n" * 200,
                                      "background": "#101820"})
            protocol.validate_app_message({"cmd": "frame", "ops": f.ops}, "graphical")
            fb = Framebuffer(320, 200)
            fb.clear(parse_color("#000000"))
            fb.apply(f.ops)

    def test_the_wallpaper_colour_is_checked_and_the_icons_colours_are_stable(self):
        self.assertIsNone(self.d.valid_color("javascript"))
        self.assertEqual(self.d.icon_color("notes"), self.d.icon_color("notes"))
        self.assertIn(self.d.icon_color("anything"), self.d.PALETTE)


class TestPacking(unittest.TestCase):
    def test_both_pack_through_the_proof_gate_and_ask_for_system_and_the_wallpaper_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("desktop", "search"):
                m = pack(ROOT / "apps" / name, Path(tmp) / f"{name}.kapp")
                self.assertEqual(sorted(m.permissions), ["system", "uses:wallpaper"])


if __name__ == "__main__":
    unittest.main()
