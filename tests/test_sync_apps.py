"""The apps for linked devices, sync, migration and the agent (apps/devices, apps/sync, apps/migrate, apps/agent).

Three kinds of check: each app packs through the proof gate (no decimals, nothing forbidden); each manifest asks
for exactly one service group and every service an app calls is one the OS has, with the arguments the OS's spec
takes; and each app, driven with a fake OS, sends exactly those arguments, shows a refusal as a refusal, and never
calls the OS before the owner has typed something."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import sdk, servicespec  # noqa: E402
from kos.kapp import KApp, Manifest, pack_tree  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APPS = ROOT / "apps"
GROUP_OF = {"devices": "link", "sync": "sync", "migrate": "migrate", "agent": "agent"}
EXPECTED = {
    "devices": ["devices.list", "devices.pair", "devices.scope", "devices.unlink"],
    "sync": ["sync.folders", "sync.run", "sync.serve", "sync.share", "sync.unshare"],
    "migrate": ["migrate.export", "migrate.import"],
    "agent": ["agent.run"],
}


def app_dirs():
    return [(g, p) for g in GROUP_OF for p in sorted((APPS / g).iterdir()) if p.is_dir() and p.name != "__pycache__"]


class FakeApp:
    """What kos.sdk.App is, with no socket: scripted events in, recorded screens and service calls out."""

    def __init__(self, events, replies=None):
        self._events = events
        self.replies = replies or {}
        self.width, self.height = 80, 24
        self.screens, self.calls, self.exited = [], [], None

    def events(self):
        yield from self._events

    def screen(self, title, lines, status=""):
        self.screens.append((title, list(lines), status))

    def service(self, name, /, **args):
        self.calls.append((name, args))
        r = self.replies.get(name, {"ok": True, "detail": "", "data": {}})
        return r(args) if callable(r) else r

    def exit(self, code=0):
        self.exited = code

    @property
    def text(self):
        return "\n".join("\n".join(lines) for _, lines, _ in self.screens)

    @property
    def last(self):
        return "\n".join(self.screens[-1][1])


def keys(text):
    return [{"cmd": "key", "key": c} for c in text]


ENTER, ESC = {"cmd": "key", "key": "enter"}, {"cmd": "key", "key": "escape"}
HELLO = {"cmd": "hello", "mode": "tui", "width": 80, "height": 24}


def run(app_path: str, events, replies=None) -> FakeApp:
    """Load apps/<app_path>/app.py with kos.sdk.App replaced, run main(), return the fake."""
    fake = FakeApp([HELLO, *events], replies)
    with mock.patch.object(sdk, "App", lambda *a, **k: fake):
        spec = importlib.util.spec_from_file_location("app_under_test_" + app_path.replace("/", "_"),
                                                      APPS / app_path / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main()
    return fake


def service_of(path):
    """The service an app calls, read from its SERVICE constant (an app's name is not its service's name)."""
    for n in ast.walk(ast.parse((APPS / path / "app.py").read_text())):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SERVICE" for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(path)


def typed(*answers):
    out = []
    for a in answers:
        out += keys(a) + [ENTER]
    return out


class TestPacking(unittest.TestCase):
    def test_every_group_is_exactly_the_apps_we_expect(self):
        for g, names in EXPECTED.items():
            with tempfile.TemporaryDirectory() as tmp:
                made = pack_tree(APPS / g, Path(tmp))
                self.assertEqual(sorted(m.name for m in made), names)
                for m in made:
                    k = KApp.from_file(Path(tmp) / f"{m.name}.kapp")
                    self.assertIn("proof.json", k.names())              # nothing runs unproven

    def test_a_group_has_no_permissions_of_its_own(self):
        for g in GROUP_OF:
            self.assertFalse((APPS / g / "manifest.json").exists(), g)

    def test_each_app_asks_for_exactly_one_service_group_and_nothing_else(self):
        for g, p in app_dirs():
            m = Manifest.parse((p / "manifest.json").read_bytes())
            self.assertEqual(list(m.permissions), [f"service:{GROUP_OF[g]}"], m.name)
            self.assertEqual(m.name, f"{g}.{p.name}")
            self.assertEqual(list(m.modes), ["tui"])
            for power in ("network", "system", "storage", "ai", "admin", "cookies", "passwords"):
                self.assertNotIn(power, m.permissions)

    def test_every_service_an_app_calls_is_in_its_group_and_takes_the_arguments_the_app_sends(self):
        for g, p in app_dirs():
            tree = ast.parse((p / "app.py").read_text())
            names = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "service" and n.args:
                    if isinstance(n.args[0], ast.Constant):
                        names.add(n.args[0].value)
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SERVICE" for t in n.targets):
                    names.add(ast.literal_eval(n.value))
            self.assertTrue(names, p)
            for name in names:
                self.assertIn(name, servicespec.SPECS, f"{p}: {name}")
                self.assertEqual(servicespec.SPECS[name].group, GROUP_OF[g], f"{p}: {name}")
            fields = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "FIELDS" for t in n.targets)]
            if fields and len(names) == 1:
                spec = servicespec.SPECS[next(iter(names))]
                keys_ = {f[0] for f in ast.literal_eval(fields[0].value)}
                required = {k for k, a in spec.args.items() if a.required}
                self.assertTrue(required <= keys_ <= set(spec.args), f"{p}: asks {keys_}, the OS takes {set(spec.args)}")

    def test_no_app_imports_anything_from_the_os_but_the_sdk(self):
        for _, p in app_dirs():
            for n in ast.walk(ast.parse((p / "app.py").read_text())):
                mods = ([n.module] if isinstance(n, ast.ImportFrom) and n.module else
                        [a.name for a in n.names] if isinstance(n, ast.Import) else [])
                for m in mods:
                    self.assertTrue(m == "kos.sdk" or not m.startswith("kos"), f"{p}: {m}")

    def test_the_readme_of_each_group_names_every_app_in_it(self):
        for g, names in EXPECTED.items():
            text = (APPS / g / "README.md").read_text()
            for n in names:
                self.assertIn(f"`{n}`", text)


class TestFormsSendExactlyWhatTheOsTakes(unittest.TestCase):
    def test_sync_share(self):
        f = run("sync/share", typed("docs", "/home/me/Documents") + [ESC],
                {"sync.share": {"ok": True, "detail": "", "data": {"name": "docs", "path": "/home/me/Documents"}}})
        self.assertEqual(f.calls, [("sync.share", {"name": "docs", "path": "/home/me/Documents"})])
        self.assertIn("Sharing /home/me/Documents as 'docs'", f.text)
        self.assertEqual(f.exited, 0)

    def test_sync_run_defaults_and_whole_numbers(self):
        reply = {"ok": True, "detail": "", "data": {"pulled": ["a.txt"], "pushed": ["b.txt", "c.txt"], "trashed": [],
                                                    "conflicts": ["d (conflict x y).txt"], "refused": [], "skipped": [],
                                                    "counts": [1, 2, 0, 1, 0], "dry": False}}
        f = run("sync/run", typed("ab12", "docs", "10.0.0.7", "", "") + [ESC], {"sync.run": reply})
        self.assertEqual(f.calls, [("sync.run", {"device": "ab12", "folder": "docs", "host": "10.0.0.7", "port": 7007,
                                                 "dry": False})])
        self.assertIn("1 received, 2 sent", f.last)
        self.assertIn("d (conflict x y).txt", f.last)
        f = run("sync/run", typed("ab12", "docs", "10.0.0.7", "9000", "yes") + [ESC],
                {"sync.run": {"ok": True, "detail": "", "data": {"counts": [0, 0, 0, 0, 0], "dry": True}}})
        self.assertEqual(f.calls[0][1]["port"], 9000)
        self.assertIs(f.calls[0][1]["dry"], True)
        self.assertIn("Would change", f.last)

    def test_a_port_that_is_not_a_whole_number_is_never_sent(self):
        for bad in ("70.07", "7e3", "-1", "abc", "1_0"):
            f = run("sync/run", typed("ab12", "docs", "h", bad, "no") + [ESC])
            self.assertEqual(f.calls, [], bad)
            self.assertIn("whole number", f.last)

    def test_an_empty_required_answer_is_never_sent(self):
        f = run("sync/share", typed("docs", "") + [ESC])
        self.assertEqual(f.calls, [])
        self.assertIn("cannot be empty", f.last)

    def test_migrate_export_lists_and_yes_no(self):
        reply = {"ok": True, "detail": "", "data": {"out": "/o.kmig", "files": 3, "bytes": 99, "left_behind": ["x: a symlink"]}}
        f = run("migrate/export", typed("/home/me/a, /home/me/b ,", "/o.kmig", "no") + [ESC], {"migrate.export": reply})
        self.assertEqual(f.calls, [("migrate.export", {"roots": ["/home/me/a", "/home/me/b"], "out": "/o.kmig", "apps": False})])
        self.assertIn("Wrote /o.kmig: 3 files, 99 bytes", f.last)
        self.assertIn("the only way in", f.last)
        self.assertIn("left behind: x: a symlink", f.last)

    def test_migrate_import(self):
        reply = {"ok": True, "detail": "", "data": {"written": 5, "identical": 1, "kept_both": 1, "renamed": ["a:b -> a_b~1 (x)"],
                                                    "staged": ["kos-staging/apps/n.kapp"], "left_behind": [], "bytes": 10}}
        f = run("migrate/import", typed("/o.kmig", "/new", "windows") + [ESC], {"migrate.import": reply})
        self.assertEqual(f.calls, [("migrate.import", {"bundle": "/o.kmig", "dest": "/new", "target": "windows"})])
        self.assertIn("5 files", f.last)
        self.assertIn("kos install", f.last)

    def test_agent_run(self):
        reply = {"ok": True, "detail": "", "data": {"stopped": "final", "final": "the note says milk",
                                                    "steps": [{"n": 1, "kind": "tool", "tool": "read_file", "detail": "read notes.txt"}]}}
        f = run("agent/run", typed("summarise notes", "/home/me/ws", "") + [ESC], {"agent.run": reply})
        self.assertEqual(f.calls, [("agent.run", {"task": "summarise notes", "workspace": "/home/me/ws", "steps": 8})])
        self.assertIn("the note says milk", f.last)
        self.assertIn("read_file", f.last)

    def test_scope_and_unlink(self):
        f = run("devices/scope", typed("ab12", "") + [ESC],
                {"link.scope": {"ok": True, "detail": "", "data": {"device": "phone", "scope": "paused"}}})
        self.assertEqual(f.calls, [("link.scope", {"device": "ab12", "scope": "paused"})])
        self.assertIn("phone is now paused", f.last)
        f = run("devices/unlink", typed("ab12") + [ESC],
                {"link.unlink": {"ok": True, "detail": "", "data": {"unlinked": "phone"}}})
        self.assertEqual(f.calls, [("link.unlink", {"device": "ab12"})])
        self.assertIn("Unlinked phone", f.last)

    def test_sync_serve_and_unshare(self):
        f = run("sync/serve", typed("", "") + [ESC],
                {"sync.serve": {"ok": True, "detail": "", "data": {"requests_handled": 12}}})
        self.assertEqual(f.calls, [("sync.serve", {"host": "127.0.0.1", "port": 7007})])
        self.assertIn("12 requests", f.last)
        f = run("sync/unshare", typed("docs") + [ESC], {"sync.unshare": {"ok": True, "detail": "", "data": {"name": "docs"}}})
        self.assertEqual(f.calls, [("sync.unshare", {"name": "docs"})])
        self.assertIn("was not touched", f.last.replace("were not touched", "was not touched"))


class TestRefusalsAndOddAnswers(unittest.TestCase):
    FORMS = [("sync/share", ("docs", "/x")), ("sync/unshare", ("docs",)), ("devices/unlink", ("ab",)),
             ("devices/scope", ("ab", "all")), ("migrate/import", ("/b", "/d", "kos")), ("agent/run", ("t", "/w", "3")),
             ("sync/serve", ("127.0.0.1", "7007")), ("sync/run", ("ab", "docs", "h", "7007", "no")),
             ("migrate/export", ("/a", "/o", "no"))]

    def test_a_refusal_is_shown_as_a_refusal_and_says_nothing_changed(self):
        for path, answers in self.FORMS:
            service = service_of(path)
            f = run(path, typed(*answers) + [ESC], {service: {"ok": False, "detail": "wrong password", "data": {}}})
            self.assertIn("Refused: wrong password", f.last, path)
            self.assertIn("Nothing was changed", f.last, path)

    def test_an_answer_in_an_unexpected_shape_does_not_crash_the_app(self):
        for path, answers in self.FORMS:
            service = service_of(path)
            f = run(path, typed(*answers) + [ESC], {service: {"ok": True, "detail": "", "data": {"weird": [1, None, {}]}}})
            self.assertEqual(f.exited, 0, path)

    def test_a_closed_channel_ends_the_app_quietly(self):
        for path, answers in self.FORMS:
            f = run(path, keys(answers[0]))                             # events stop mid-answer, before Enter
            self.assertEqual(f.calls, [], path)

    def test_nothing_is_asked_of_the_os_until_the_last_answer(self):
        for path, answers in self.FORMS:
            f = run(path, typed(*answers[:-1]))
            self.assertEqual(f.calls, [], path)

    def test_escape_first_clears_what_is_typed_and_only_then_leaves(self):
        f = run("sync/share", keys("do") + [ESC] + keys("x") + [ESC, ESC])
        self.assertEqual(f.exited, 0)
        self.assertEqual(f.calls, [])
        self.assertNotIn("dox", f.text.replace("name (lowercase letters, digits, -): x_", ""))


class TestViewers(unittest.TestCase):
    def test_opening_a_viewer_asks_the_os_nothing_until_you_press_r(self):
        for path in ("devices/list", "sync/folders"):
            f = run(path, [ESC])
            self.assertEqual(f.calls, [], path)
            self.assertIn("Press r", f.text)

    def test_devices_list(self):
        data = {"me": {"name": "laptop", "platform": "linux", "id": "aa11"},
                "peers": [{"name": "phone", "platform": "android", "scope": "all", "id": "bb22", "since": "2026-11-14"}]}
        f = run("devices/list", keys("r") + [ESC], {"link.list": {"ok": True, "detail": "", "data": data}})
        self.assertEqual(f.calls, [("link.list", {})])
        self.assertIn("laptop (linux)", f.last)
        self.assertIn("phone  (android)  all  id bb22", f.last)
        self.assertIn("still types a password", f.last)

    def test_devices_list_with_no_identity_says_how_to_make_one(self):
        f = run("devices/list", keys("r") + [ESC], {"link.list": {"ok": True, "detail": "", "data": {"me": None, "peers": []}}})
        self.assertIn("devices.pair", f.last)
        self.assertIn("No linked devices", f.last)

    def test_sync_folders_and_a_refusal(self):
        f = run("sync/folders", keys("r") + [ESC],
                {"sync.folders": {"ok": True, "detail": "", "data": {"folders": [{"name": "docs", "path": "/home/me/Documents"}]}}})
        self.assertIn("docs  ->  /home/me/Documents", f.last)
        f = run("sync/folders", keys("r") + [ESC], {"sync.folders": {"ok": False, "detail": "no", "data": {}}})
        self.assertIn("Refused: no", f.last)
        self.assertIn("Nothing was shown", f.last)


class TestPair(unittest.TestCase):
    def reply(self, me):
        return {"link.list": {"ok": True, "detail": "", "data": {"me": me, "peers": []}},
                "link.identify": {"ok": True, "detail": "", "data": {}},
                "link.pair": {"ok": True, "detail": "", "data": {"code": "123456", "linked": {"name": "phone", "platform": "android"}}}}

    def test_a_device_that_already_has_an_identity_goes_straight_to_pairing(self):
        f = run("devices/pair", typed("connect", "10.0.0.7", "7007") + [ESC], self.reply({"name": "laptop"}))
        self.assertEqual([c[0] for c in f.calls], ["link.list", "link.pair"])
        self.assertEqual(f.calls[1][1], {"role": "connect", "host": "10.0.0.7", "port": 7007})
        self.assertIn("Linked with phone (android). Code was 123456.", f.last)
        self.assertIn("ask this device for any permission", f.last)

    def test_a_new_device_is_named_first_and_the_codes_are_left_to_the_os_prompt(self):
        f = run("devices/pair", typed("laptop", "linux", "listen", "", "") + [ESC], self.reply(None))
        self.assertEqual([c[0] for c in f.calls], ["link.list", "link.identify", "link.pair"])
        self.assertEqual(f.calls[1][1], {"name": "laptop", "platform": "linux"})
        self.assertEqual(f.calls[2][1], {"role": "listen", "host": "127.0.0.1", "port": 7007})
        self.assertIn("compare the code in the OS prompt", "\n".join("\n".join(s[1]) for s in f.screens))

    def test_a_refused_identity_stops_before_any_connection(self):
        r = self.reply(None)
        r["link.identify"] = {"ok": False, "detail": "already has an identity", "data": {}}
        f = run("devices/pair", typed("laptop", "linux", "listen", "", "") + [ESC], r)
        self.assertEqual([c[0] for c in f.calls], ["link.list", "link.identify"])
        self.assertIn("Refused: already has an identity", f.last)

    def test_a_refused_pairing_says_nothing_was_changed(self):
        r = self.reply({"name": "laptop"})
        r["link.pair"] = {"ok": False, "detail": "not linked: you said no", "data": {}}
        f = run("devices/pair", typed("listen", "", "") + [ESC], r)
        self.assertIn("Refused: not linked: you said no", f.last)
        self.assertIn("Nothing was changed", f.last)

    def test_a_role_that_is_neither_connect_nor_listen_is_never_sent(self):
        f = run("devices/pair", typed("both", "h", "7007") + [ESC], self.reply({"name": "laptop"}))
        self.assertEqual([c[0] for c in f.calls], ["link.list"])
        self.assertIn("connect or listen", f.last)

    def test_the_app_cannot_say_the_codes_matched_only_the_os_prompt_can(self):
        src = (APPS / "devices" / "pair" / "app.py").read_text()
        self.assertNotIn("confirm", src)
        self.assertNotIn("password", src.replace("your password", "").replace("the password", "").lower().replace("type your password", ""))


if __name__ == "__main__":
    unittest.main()
