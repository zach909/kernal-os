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

    def test_nine_are_real_apps_and_three_stay_none(self):
        sysinfo_apps = {"Battery and Power", "Storage and Disk Management", "Process and Resource Monitor",
                        "System Information and Diagnostics", "Device Settings", "Network and Wireless",
                        "Software Updates"}
        for e in ENTRIES:
            if e.title in sysinfo_apps:
                self.assertEqual(e.scope, "partial", e.title)
                self.assertEqual(e.perms, ("sysinfo",), e.title)
                self.assertIn("password", e.note, e.title)
            elif e.title == "Firewall Management":
                self.assertEqual((e.scope, e.perms), ("partial", ("firewall",)))
            elif e.title == "Credential Manager":
                self.assertEqual((e.scope, e.perms), ("partial", ("credentials",)))
            else:
                self.assertEqual(e.scope, "none", e.title)
                self.assertEqual(e.perms, (), e.title)
        self.assertEqual(sum(e.scope == "none" for e in ENTRIES), 3)
        self.assertEqual(sorted(e.title for e in ENTRIES if e.scope == "none"),
                         ["Device Pairing", "Printer Management", "Window and Desktop Management"])
        for e in ENTRIES:
            self.assertLessEqual(len(e.name), 32, e.title)
            self.assertNotIn("system", e.perms)
            self.assertFalse(e.network, e.title)

    def test_note_length(self):
        for e in ENTRIES: self.assertTrue(60 <= len(e.note) <= 320, (e.title, len(e.note)))

    def test_every_named_command_exists(self):
        for e in ENTRIES:
            for cmd in re.findall(r"`kos (\w+)", e.note):
                self.assertIn(cmd, COMMANDS, (e.title, cmd))


if __name__ == "__main__":
    unittest.main()
