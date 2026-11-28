"""pack_devvc: Version Control, Code Review, Package Manager, Build Planner, Config Editor."""
import unittest

from kos.office import pack_devvc as d
from kos.office.ui import FakeHost, run
from kos.protocol import validate_app_message


class CodeReview(unittest.TestCase):
    def rules(self, src):
        return {f["rule"] for f in d.review(src, "python")}

    def test_shell_true_is_an_error_whatever_the_module(self):
        self.assertIn("shell-true", self.rules("import subprocess\nsubprocess.run('ls', shell=True)\n"))
        self.assertIn("shell-true", self.rules("import x\nx.call('ls', shell=True)\n"))
        self.assertNotIn("shell-true", self.rules("import subprocess\nsubprocess.run(['ls'])\n"))
        self.assertNotIn("shell-true", self.rules("import subprocess\nsubprocess.run('ls', shell=False)\n"))

    def test_dangerous_calls_and_bare_except_are_found(self):
        r = self.rules("eval('1')\nimport os\nos.system('x')\ntry:\n    pass\nexcept:\n    pass\n")
        self.assertTrue({"dangerous-call", "bare-except"} <= r)

    def test_a_syntax_error_is_reported_not_raised(self):
        self.assertEqual([f["rule"] for f in d.review("def f(:\n", "python")], ["syntax"])


class Versions(unittest.TestCase):
    def test_order_is_numeric_and_a_prerelease_is_older(self):
        self.assertEqual(d.compare("1.2.3", "1.10.0"), -1)
        self.assertEqual(d.compare("1.0.0-rc.1", "1.0.0"), -1)

    def test_caret_and_tilde_ranges(self):
        self.assertTrue(d.satisfies("1.2.5", "^1.2.0"))
        self.assertFalse(d.satisfies("2.0.0", "^1.2.0"))
        self.assertTrue(d.satisfies("1.2.9", "~1.2.0"))
        self.assertFalse(d.satisfies("1.3.0", "~1.2.0"))


class BuildPlanner(unittest.TestCase):
    def test_waves_and_order(self):
        g, _ = d.parse_rules("app: lib main.o\nlib:\nmain.o:\n")
        p = d.plan(g)
        self.assertEqual(p["waves"], [["lib", "main.o"], ["app"]])
        self.assertEqual(p["order"][-1], "app")

    def test_a_cycle_is_found_and_a_clean_graph_has_none(self):
        g, _ = d.parse_rules("a: b\nb: a\n")
        self.assertEqual(d.find_cycle(g), ["a", "b", "a"])
        g, _ = d.parse_rules("a: b\nb:\n")
        self.assertIsNone(d.find_cycle(g))


class Merge(unittest.TestCase):
    def test_both_sides_changing_one_line_is_a_conflict_marked_in_the_text(self):
        out, conflicts = d.merge3(["a"], ["x"], ["y"])
        self.assertEqual(conflicts, 1)
        self.assertTrue(d.has_markers("\n".join(out)))

    def test_one_side_changing_is_taken_without_a_conflict(self):
        out, conflicts = d.merge3(["a", "b"], ["a", "B"], ["a", "b"])
        self.assertEqual((out, conflicts), (["a", "B"], 0))


class Config(unittest.TestCase):
    def test_bad_json_gives_a_line_numbered_error(self):
        data, errs = d.parse("json", "{bad")
        self.assertIsNone(data)
        self.assertEqual(errs[0][0], 1)

    def test_json_converts_to_toml(self):
        self.assertEqual(d.convert("json", '{"a":{"b":1}}', "toml"), ("[a]\nb = 1\n", []))


class VersionControlScreens(unittest.TestCase):
    """Regression: the 'Status' menu command once replaced the screen's status line with a tuple,
    which is not a valid `screen` message."""

    def frames(self, keys):
        h = FakeHost(keys)
        run(h, d.VC(h))
        return h.frames

    def test_every_frame_is_a_valid_screen_message(self):
        for keys in (["enter"], ["down", "enter"], ["down", "down", "enter"], ["down"] * 3 + ["enter"], ["down"] * 11 + ["enter"]):
            for t, lines, st in self.frames(keys):
                self.assertIsInstance(st, str, keys)
                validate_app_message({"cmd": "screen", "title": t, "lines": lines, "status": st}, "tui")

    def test_the_status_command_shows_the_repository_status(self):
        self.assertEqual(self.frames(["down", "enter"])[-1][0], "Version Control > Status")


if __name__ == "__main__":
    unittest.main()
