"""`kos help`: lists every command, explains one, needs no password."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import cli  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch("kos.cli.Authority", side_effect=AssertionError("help must not ask for a password")):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestHelp(unittest.TestCase):
    def test_lists_every_command_with_a_description(self):
        code, out, _ = run("help")
        self.assertEqual(code, 0)
        listed = {l.split()[0] for l in out.splitlines() if l.startswith("  ")}
        self.assertEqual(listed, set(cli.COMMANDS))
        for l in out.splitlines():
            if l.startswith("  "): self.assertGreater(len(l.split(None, 1)), 1, l)

    def test_explains_one_command(self):
        code, out, _ = run("help", "install")
        self.assertEqual(code, 0)
        self.assertIn("usage: kos install", out)

    def test_every_command_can_be_explained(self):
        for name in cli.COMMANDS:
            code, out, _ = run("help", name)
            self.assertEqual((code, "usage: kos " + name in out), (0, True), name)

    def test_an_unknown_command_is_refused_and_nothing_hostile_is_echoed_raw(self):
        code, out, err = run("help", "nope")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no command called 'nope'", err)
        code, _, err = run("help", "\x1b[2Jevil")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)     # repr() escapes it


if __name__ == "__main__":
    unittest.main()
