"""The one search box: talk to the assistant, search commands, apps and files (kos/office/finder.py).

The rules under test (kos-rules): search shows and never does; files means only what the app can
already read; everything searched is untrusted text; everything is bounded; the command list cannot
drift from `kos help`."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.office import cmdindex, finder  # noqa: E402
from kos.office.agent import Agent  # noqa: E402
from kos.office.findscreen import Finder  # noqa: E402
from kos.office.ui import FakeHost, Message, Screen, run  # noqa: E402

ESC = "\x1b[2J\x1b]0;pwned\x07"


def kinds(rows): return [r.kind for r in rows]
def labels(rows): return [r.label for r in rows]


class TestCommandIndex(unittest.TestCase):
    def test_the_list_is_exactly_what_kos_help_lists(self):
        self.assertEqual(list(cmdindex.COMMANDS), cmdindex._live(),
                         "kos/office/cmdindex.py is stale: python3 -m kos.office.cmdindex --write")

    def test_every_command_has_help_and_a_usage_line(self):
        for name, helptext, usage in cmdindex.COMMANDS:
            self.assertTrue(helptext and usage.startswith("kos " + name), name)


class TestSearch(unittest.TestCase):
    def test_empty_box_is_just_talk(self):
        rows = finder.search("")
        self.assertEqual((kinds(rows), labels(rows)), ([finder.ASK], ["Talk to the assistant"]))

    def test_a_command_name_finds_the_command_then_offers_the_assistant_last(self):
        rows = finder.search("bac")
        self.assertEqual(rows[0].label, "kos backup")
        self.assertEqual(rows[-1].kind, finder.ASK)

    def test_a_question_puts_the_assistant_first_and_still_finds_the_command(self):
        rows = finder.search("how do I back up?")
        self.assertEqual(rows[0].kind, finder.ASK)
        self.assertIn("kos backup", labels(rows))
        self.assertLessEqual(kinds(rows).count(finder.ACTION), 2)

    def test_a_slash_is_always_talk(self):
        self.assertEqual(finder.search("/calc 1+1")[0].kind, finder.ASK)

    def test_nothing_matches_means_only_the_assistant(self):
        self.assertEqual(kinds(finder.search("zzqxj")), [finder.ASK])

    def test_files_are_found_with_a_snippet(self):
        files = [("", "note-1", "the quarterly report is due on friday"), ("", "note-2", "buy milk")]
        rows = [r for r in finder.search("quarterly", files=files) if r.kind == finder.FILE]
        self.assertEqual([r.label for r in rows], ["note-1"])
        self.assertIn("quarterly", rows[0].detail)

    def test_apps_only_appear_when_the_screen_knows_apps(self):
        apps = [{"name": "notes", "description": "write notes"}]
        self.assertNotIn(finder.APP, kinds(finder.search("notes")))
        self.assertIn(finder.APP, kinds(finder.search("notes", apps=apps)))

    def test_rows_per_kind_are_bounded(self):
        files = [("", f"n{i}", "report") for i in range(50)]
        rows = finder.search("report", files=files)
        self.assertLessEqual(kinds(rows).count(finder.FILE), finder.PER_GROUP)

    def test_a_huge_query_is_cut(self):
        rows = finder.search("a" * 100000)
        self.assertLessEqual(len(rows[-1].label), 80)


class TestUntrustedText(unittest.TestCase):
    def test_hostile_app_descriptions_and_file_text_never_reach_the_screen_raw(self):
        apps = [{"name": "evil", "description": "free money " + ESC}, "not-a-dict", {"name": 5}, {"description": "x"}]
        files = [("", "k" + ESC, "free money " + ESC)]
        for r in finder.search("free money", apps=apps, files=files):
            for text in (r.label, r.detail):
                self.assertNotIn("\x1b", text)
                self.assertNotIn("\x07", text)

    def test_plain_removes_controls_and_bounds(self):
        self.assertEqual(finder.plain("a\x1b[31m\nb\tc\x00d", 50), "a [31m b c d")
        self.assertEqual(len(finder.plain("x" * 1000, 10)), 10)

    def test_the_screen_shows_hostile_file_text_without_escapes(self):
        h = FakeHost(["ctrl-n", *"money", "down", "enter", "escape", "escape", "escape"],
                     data={"note-1": "free money\n" + ESC + "\nmore"}, width=80, height=24)
        run(h, _Root(), agent=lambda: Finder(h, "T", lambda t: Agent(h, "T")))
        self.assertTrue(h.frames)
        for _t, lines, status in h.frames:
            for line in lines:
                self.assertNotIn("\x1b", line)


class TestFilesMeansWhatTheAppCanAlreadyRead(unittest.TestCase):
    SECRETS = {"llm": json.dumps({"provider": "x", "key": "sk-SECRET-123", "model": "m"}),
               "agent-chat": "sk-SECRET-123 in history", "export-1": "sk-SECRET-123 exported",
               "api_key": "sk-SECRET-123", "my-password": "sk-SECRET-123", "token-store": "sk-SECRET-123"}

    def test_credentials_history_and_exports_are_never_indexed(self):
        h = FakeHost([], data={**self.SECRETS, "note-1": "a normal note"})
        got = {k for _sp, k, _t in finder.gather_files(h)}
        self.assertEqual(got, {"note-1"})
        self.assertEqual([r for r in finder.search("SECRET", files=finder.gather_files(h)) if r.kind == finder.FILE], [])

    def test_a_secret_key_in_a_shared_space_is_also_hidden(self):
        h = FakeHost([], data={})
        h.spaces["contacts"] = {"card-1": "Ann 555", "api-key": "sk-SECRET-123"}
        got = {(sp, k) for sp, k, _t in finder.gather_files(h)}
        self.assertEqual(got, {("contacts", "card-1")})

    def test_only_spaces_the_host_offers_are_read(self):
        class Host(FakeHost):
            def space_names(self): return ["granted"]
        h = Host([], data={"mine": "x"})
        h.spaces["granted"] = {"a": "shared note"}
        h.spaces["not-granted"] = {"b": "private to another app"}
        self.assertEqual({sp for sp, _k, _t in finder.gather_files(h)}, {"", "granted"})

    def test_reading_is_bounded(self):
        h = FakeHost([], data={f"k{i:04}": "x" * (finder.MAX_CHARS * 3) for i in range(finder.MAX_FILES * 2)})
        files = finder.gather_files(h)
        self.assertEqual(len(files), finder.MAX_FILES)
        self.assertTrue(all(len(t) <= finder.MAX_CHARS for _s, _k, t in files))

    def test_a_host_that_fails_does_not_crash_the_box(self):
        class Bad(FakeHost):
            def space_names(self): return ["s"]
            def keys(self, space=None):
                if space: raise OSError("denied")
                return super().keys(space)
        self.assertEqual([k for _s, k, _t in finder.gather_files(Bad([], data={"n": "x"}))], ["n"])


class TestSearchOnlyShows(unittest.TestCase):
    def test_the_search_code_cannot_reach_the_password_or_the_command_line_program(self):
        code = ("import sys; sys.path.insert(0, %r)\n"
                "import kos.office.finder, kos.office.findscreen\n"
                "bad = [m for m in ('kos.auth', 'kos.cli', 'kos.system', 'subprocess', 'socket') if m in sys.modules]\n"
                "print(bad)") % str(ROOT)
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), "[]")

    def test_choosing_a_command_shows_the_line_to_type_and_runs_nothing(self):
        h = FakeHost(["ctrl-n", *"backup", "enter", "escape", "escape", "escape"], width=80, height=24)
        run(h, _Root(), agent=lambda: Finder(h, "T", lambda t: Agent(h, "T")))
        shown = "\n".join("\n".join(lines) for _t, lines, _s in h.frames)
        self.assertIn("Type this in the KOS shell:", shown)
        self.assertIn("kos backup", shown)
        self.assertIn("Searching never runs a command", shown)


class _Root(Screen):
    title = "Root"
    def render(self, w, h): return ["root"]


class TestTheBox(unittest.TestCase):
    def drive(self, keys, **kw):
        h = FakeHost(keys, width=90, height=24, **kw)
        made = []

        def assistant(text):
            a = Agent(h, "T", "note"); made.append((text, a))
            if text: a.submit(text)
            return a
        run(h, _Root(), agent=lambda: Finder(h, "T", assistant))
        return h, made

    def screens(self, h): return ["\n".join(lines) for _t, lines, _s in h.frames]

    def test_empty_enter_just_talks(self):
        h, made = self.drive(["ctrl-n", "enter", *"hi", "enter", "escape", "escape", "escape"])
        self.assertEqual([t for t, _a in made], [""])
        self.assertIn("you: hi", "\n".join(self.screens(h)))

    def test_a_question_is_handed_to_the_assistant_already_asked(self):
        h, made = self.drive(["ctrl-n", *"what is this?", "enter", "escape", "escape", "escape"])
        self.assertEqual([t for t, _a in made], ["what is this?"])
        self.assertEqual(made[0][1].hist[0], ["you", "what is this?"])
        self.assertTrue(any("you: what is this?" in s for s in self.screens(h)))

    def test_esc_from_the_assistant_comes_back_to_the_box_with_the_text_kept(self):
        h, _ = self.drive(["ctrl-n", *"what is this?", "enter", "escape"])
        self.assertIn("find> what is this?", self.screens(h)[-1])

    def test_ctrl_n_inside_the_box_does_not_stack_another(self):
        h, _ = self.drive(["ctrl-n", "ctrl-n", "ctrl-n"])
        self.assertEqual(self.screens(h)[-1].count("find>"), 1)

    def test_a_file_hit_opens_the_file(self):
        h, _ = self.drive(["ctrl-n", *"quarterly", "down", "enter"], data={"note-1": "the quarterly report is due friday"})
        self.assertTrue(any("is due friday" in s and "find>" not in s for s in self.screens(h)))

    def test_the_box_reads_files_only_after_you_type(self):
        class Spy(FakeHost):
            reads = 0
            def keys(self, space=None):
                Spy.reads += 1; return super().keys(space)
        h = Spy(["ctrl-n", "escape"], width=80, height=24)
        run(h, _Root(), agent=lambda: Finder(h, "T", lambda t: Agent(h, "T")))
        self.assertEqual(Spy.reads, 0)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


class TestAppLibrarySearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = _load("examples/system/app-library/app.py", "lib_search")

    def state(self, installed=None, query=""):
        apps = installed if installed is not None else [
            {"name": "notes", "version": "1", "description": "write notes", "modes": ["tui"], "permitted": True, "kind": "app", "extends": ""},
            {"name": "ai-assistant", "version": "1", "description": "chat", "modes": ["tui"], "permitted": True, "kind": "app", "extends": ""}]
        return {"installed": apps, "open": [], "sel": 0, "graphical": False, "note": "", "ext": [], "query": query}

    def type(self, st, text):
        for ch in text: self.lib.search_key(st, ch)

    def test_typing_finds_an_app_and_enter_asks_the_os_to_open_it(self):
        st = self.state(); self.type(st, "notes")
        self.assertEqual(self.lib.search_key(st, "enter"), ("open", "notes", "tui"))

    def test_a_command_is_shown_not_run(self):
        st = self.state(); self.type(st, "backup")
        self.assertIsNone(self.lib.search_key(st, "enter"))
        self.assertIn("kos backup", st["note"])

    def test_ask_opens_the_assistant_app_when_installed(self):
        st = self.state(); self.type(st, "zzqxj")
        self.assertEqual(self.lib.search_key(st, "enter"), ("open", "ai-assistant", "tui"))

    def test_ask_says_so_when_no_assistant_is_installed(self):
        st = self.state(installed=[]); self.type(st, "zzqxj")
        self.assertIsNone(self.lib.search_key(st, "enter"))
        self.assertIn("no assistant installed", st["note"])

    def test_escape_leaves_search_and_the_list_returns(self):
        st = self.state(); self.type(st, "no")
        self.lib.search_key(st, "escape")
        self.assertIsNone(st["query"])
        self.assertIn("Installed apps", "\n".join(self.lib.tui_lines(st, 30)))

    def test_hostile_app_text_is_not_drawn_raw(self):
        evil = [{"name": "evil", "version": "1", "description": "free money " + ESC, "modes": ["tui"],
                 "permitted": True, "kind": "app", "extends": ""}]
        st = self.state(installed=evil); self.type(st, "money")
        self.assertNotIn("\x1b", "\n".join(self.lib.tui_lines(st, 30)))

    def test_the_query_is_bounded(self):
        st = self.state()
        for _ in range(finder.MAX_QUERY + 50): self.lib.search_key(st, "a")
        self.assertEqual(len(st["query"]), finder.MAX_QUERY)


if __name__ == "__main__":
    unittest.main()
