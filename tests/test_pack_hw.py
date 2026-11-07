import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.cli import COMMANDS  # noqa: E402
from kos.office.catalog import BY_NAME, CATALOG  # noqa: E402
from kos.office.pack_hw import ENTRIES  # noqa: E402

TITLES = [l.split("\t")[1] for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines()
          if l.startswith("pack_hw\t")]
CAT_TITLES = {e.title for e in CATALOG}
KNOWN_APPS = ("Video Conferencing Tool", "Screen Capture Tool", "Speech Recognition Tool", "Text-to-Speech Tool")


class TestHw(unittest.TestCase):
    def test_titles_match_group_exactly(self):
        self.assertEqual(len(TITLES), 14)
        self.assertEqual(sorted(e.title for e in ENTRIES), sorted(TITLES))

    def test_scope_none_and_note_length(self):
        for e in ENTRIES:
            self.assertEqual(e.scope, "none", e.title)
            self.assertTrue(60 <= len(e.note) <= 320, (e.title, len(e.note)))

    def test_named_apps_exist(self):
        for e in ENTRIES:
            for t in KNOWN_APPS:
                if t in e.note:
                    self.assertIn(t, CAT_TITLES, t)
        for t in KNOWN_APPS:
            self.assertIn(t, CAT_TITLES)

    def test_named_commands_exist(self):
        for e in ENTRIES:
            for c in re.findall(r"`kos (\w+)", e.note):
                self.assertIn(c, COMMANDS, e.title)

    def test_payments_and_weather_are_plain(self):
        n = {e.title: e.note for e in ENTRIES}
        p = n["Payments and Digital Keys"]
        for w in ("secure element", "encryption", "will not fake"):
            self.assertIn(w, p)
        self.assertIn("network", n["Weather"])


if __name__ == "__main__":
    unittest.main()
