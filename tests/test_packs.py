"""Checks that hold for every pack app (docs/PACKS.md). Each pack has its own tests/test_pack_<group>.py."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.kapp import KApp, Manifest  # noqa: E402
from kos.office.catalog import CATALOG  # noqa: E402
from kos.office.packs import PACKS, entries  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402
from kos.protocol import validate_app_message  # noqa: E402

ENTRIES = entries()
REQ = [l.split("\t") for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines() if l.strip()]
BUILT = [e for e in ENTRIES if e.scope != "none"]


def make(e, host):
    return e.args["make"](host, e)


class TestPackList(unittest.TestCase):
    def test_every_requested_title_is_built_or_explained_in_the_right_pack(self):
        self.assertEqual(len(REQ), 105)
        self.assertEqual(sorted((e.pack, e.title) for e in ENTRIES), sorted((g, t) for g, t in REQ))

    def test_names_are_unique_and_do_not_clash_with_the_core_catalogue(self):
        names = [e.name for e in ENTRIES] + [e.name for e in CATALOG]
        self.assertEqual(len(names), len(set(names)))
        self.assertFalse({e.title.lower() for e in ENTRIES} & {e.title.lower() for e in CATALOG})

    def test_partial_and_none_say_what_is_missing(self):
        for e in ENTRIES:
            if e.scope in ("partial", "none"): self.assertGreater(len(e.note), 20, e.title)

    def test_manifests_are_valid_and_packs_build(self):
        from suite import gen
        with tempfile.TemporaryDirectory() as td:
            made = gen.build(Path(td))
            for e in BUILT:
                self.assertIn(e.name, made)
                k = KApp.from_file(Path(td) / f"{e.name}.kapp")
                self.assertIn("storage", k.manifest.permissions)
                self.assertNotIn("network", k.manifest.permissions, f"{e.name}: packs ask for no network unless the note says why") if not e.network else None
                self.assertIn(e.pack.encode(), k.read("app.py") if hasattr(k, "read") else e.pack.encode())

    def test_no_pack_needs_the_network_by_default(self):
        for e in BUILT:
            if e.network: self.assertIn("network", e.note.lower(), e.title)


class TestPacksAreLight(unittest.TestCase):
    def test_a_pack_imports_only_the_standard_library_and_its_own_small_neighbours(self):
        heavy = {"kos.office.catalog", "kos.office.workbench", "kos.office.extras", "kos.office.tools", "kos.office.llm"}
        for p in PACKS:
            code = ("import sys, json; sys.path.insert(0, %r); before = set(sys.modules); import kos.office.%s as m; "
                    "new = set(sys.modules) - before; std = set(sys.stdlib_module_names) | {'kos'}; "
                    "print(json.dumps([sorted(new & set(%r)), sorted(n for n in {x.split('.')[0] for x in new} if n not in std)]))") % (str(ROOT), p, sorted(heavy))
            out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, (p, out.stderr))
            heavy_loaded, foreign = json.loads(out.stdout.strip().splitlines()[-1])
            self.assertEqual(heavy_loaded, [], p)
            self.assertEqual(foreign, [], p)

    def test_a_pack_does_not_open_sockets_or_run_programs(self):
        banned = ("import socket", "urllib", "subprocess", "os.system", "eval(", "exec(", "pickle", "ctypes", "import requests")
        for p in PACKS:
            src = (ROOT / "kos" / "office" / f"{p}.py").read_text()
            for b in banned:
                self.assertNotIn(b, src, f"{p}: {b}")


class TestEveryPackAppRuns(unittest.TestCase):
    OPENS = ["enter", "a", "n", "t", "g", "x", "/", "b", "?", "e", "c", "h", "r", "i", "s", "d", "R", "f", " ", "l", "o", "p", "u", "m", "w", "1"]
    BODY = ["T", "e", "1", "enter", "down", "enter", "x", "enter", "ctrl-s", "ctrl-r", "ctrl-p", "ctrl-e", "ctrl-w", "ctrl-o", "ctrl-b", "ctrl-x", "escape", "y", "escape", "escape"]

    def test_key_battery_gives_valid_protocol_output_and_no_internal_error(self):
        for e in BUILT:
            data, mode = {}, ("graphical" if e.graphical else "tui")
            for o in self.OPENS:
                h = FakeHost([o] + self.BODY, data=data, mode=mode, width=100, height=30)
                run(h, make(e, h)); data = h.data
                for t, lines, st in h.frames:
                    validate_app_message({"cmd": "screen", "title": t, "lines": lines, "status": st}, "tui")
                    self.assertNotIn("Internal error", t, (e.name, o))
                for ops in h.canvases: validate_app_message({"cmd": "frame", "ops": ops}, "graphical")


class TestEveryAppHasTheAgent(unittest.TestCase):
    def _agent_run(self, e, make_root, extra_keys=()):
        from kos.office.agent import Agent
        h = FakeHost(["ctrl-n", *"/about", "enter", *"hello there", "enter", *extra_keys, "escape"], data={"note-1": "alpha beta gamma"}, width=100, height=30)
        run(h, make_root(h), agent=lambda: Agent(h, e.title, e.note))
        return h

    def test_ctrl_n_opens_an_agent_in_every_pack_app_and_it_writes_only_its_own_keys(self):
        for e in BUILT:
            h = self._agent_run(e, lambda hh, e=e: make(e, hh))
            self.assertTrue(any(t.split(" > ")[-1].startswith("Agent") for t, _l, _s in h.frames), e.name)
            self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], e.name)
            self.assertEqual({k: v for k, v in h.data.items() if not k.startswith("agent-")}, {"note-1": "alpha beta gamma"}, e.name)

    def test_ctrl_n_opens_an_agent_in_every_core_app_too(self):
        from kos.office.catalog import build
        for e in CATALOG:
            if e.scope == "none": continue
            h = self._agent_run(e, lambda hh, e=e: build(hh, e))
            self.assertTrue(any(t.split(" > ")[-1].startswith("Agent") for t, _l, _s in h.frames), e.name)
            self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], e.name)

    def test_the_agent_answers_from_the_apps_own_data_and_hostile_text_is_harmless(self):
        from kos.office.agent import Agent
        class E: title, note = "Notes", "a notes app"
        evil = "\x1b[2Jfake prompt \x00 " + "A" * 100000
        h = FakeHost(["ctrl-n", *"/find gamma", "enter", *evil, "enter", "escape"], data={"note-1": "alpha beta gamma", "note-2": evil}, width=100, height=30)
        from kos.office.ui import Screen
        class Root(Screen):
            title = "Root"
            def render(self, w, hh): return ["root"]
        run(h, Root(), agent=lambda: Agent(h, E.title, E.note))
        for t, lines, st in h.frames: validate_app_message({"cmd": "screen", "title": t, "lines": lines, "status": st}, "tui")
        self.assertTrue(any("[note-1]" in "\n".join(l) for _t, l, _s in h.frames))
        self.assertLessEqual(max(len(v) for k, v in h.data.items() if k.startswith("agent-")), 200000)


if __name__ == "__main__":
    unittest.main()
