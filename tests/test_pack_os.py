import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.cli import COMMANDS  # noqa: E402
from kos.office.pack_os import ENTRIES  # noqa: E402

TITLES = [l.split("\t")[1] for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines()
          if l.strip() and l.split("\t")[0] == "pack_os"]


class TestPackOs(unittest.TestCase):
    def test_titles_match_the_group_exactly(self):
        self.assertEqual(len(TITLES), 12)
        self.assertEqual([e.title for e in ENTRIES], TITLES)

    def test_every_entry_is_none(self):
        for e in ENTRIES: self.assertEqual(e.scope, "none", e.title)

    def test_note_length(self):
        for e in ENTRIES: self.assertTrue(60 <= len(e.note) <= 300, (e.title, len(e.note)))

    def test_every_named_command_exists(self):
        for e in ENTRIES:
            for cmd in re.findall(r"`kos (\w+)", e.note):
                self.assertIn(cmd, COMMANDS, (e.title, cmd))


if __name__ == "__main__":
    unittest.main()
