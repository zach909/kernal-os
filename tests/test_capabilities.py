"""docs/CAPABILITIES.md must account for every requested capability, honestly."""
import os
import unittest
from collections import Counter

from kos.cli import COMMANDS
from kos.office.catalog import CATALOG

DOCS = os.path.join(os.path.dirname(__file__), "..", "docs")


def _read(name):
    with open(os.path.join(DOCS, name), encoding="utf-8") as f:
        return f.read().splitlines()


def requested():
    out = {}
    cur = None
    for ln in _read("REQUESTED_CAPABILITIES.txt"):
        if ln.startswith("## "):
            cur = ln[3:].rsplit(" / ", 1)[0]
            out.setdefault(cur, [])
        elif ln.strip():
            out[cur].append(ln)
    return out


def rows_and_summary():
    rows, summary, mode = [], {}, None
    for ln in _read("CAPABILITIES.md"):
        if ln.startswith("## "):
            mode = ln[3:]
            continue
        if not ln.startswith("|") or ln.startswith("|---") or ln.startswith("| list"):
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split(" | ")]
        if mode == "Summary":
            summary[cells[0].strip("*")] = [int(x) for x in cells[1:]]
        elif mode == "Capabilities":
            rows.append(cells)
    return rows, summary


def titles():
    t = {e.title for e in CATALOG}
    with open(os.path.join(DOCS, "REQUESTED2.txt"), encoding="utf-8") as f:
        for ln in f:
            if "\t" in ln:
                t.add(ln.rstrip("\n").split("\t", 1)[1].strip())
    return t


class CapabilityDoc(unittest.TestCase):
    def setUp(self):
        self.req = requested()
        self.rows, self.summary = rows_and_summary()

    def test_five_lists(self):
        self.assertEqual(len(self.req), 5)
        self.assertIn("Neural interface applications", self.req)

    def test_nothing_dropped(self):
        got = {}
        for r in self.rows:
            got.setdefault(r[0], []).append(r[1])
        for name, caps in self.req.items():
            self.assertEqual(Counter(got.get(name, [])), Counter(caps), name)
        self.assertEqual(set(got), set(self.req))

    def test_status_valid(self):
        for r in self.rows:
            self.assertEqual(len(r), 5, r)
            self.assertIn(r[2], ("app", "os", "none"), r)

    def test_app_titles_exist(self):
        known = titles()
        for r in self.rows:
            if r[2] == "app":
                for t in r[3].split("; "):
                    self.assertIn(t, known, r)

    def test_os_commands_exist(self):
        for r in self.rows:
            if r[2] == "os":
                c = r[3].strip("`")
                c = c[4:] if c.startswith("kos ") else c
                self.assertTrue(c in COMMANDS or c in ("taskbar", "App Library", "web"), r)

    def test_none_has_reason(self):
        known = titles()
        for r in self.rows:
            if r[2] == "none":
                self.assertGreater(len(r[4]), 20, r)
                if r[3] != "-":
                    self.assertIn(r[3], known, r)

    def test_summary_matches(self):
        total = [0, 0, 0, 0]
        for name, caps in self.req.items():
            c = Counter(r[2] for r in self.rows if r[0] == name)
            exp = [c["app"], c["os"], c["none"], len(caps)]
            self.assertEqual(self.summary[name], exp, name)
            total = [a + b for a, b in zip(total, exp)]
        self.assertEqual(self.summary["All lists"], total)


if __name__ == "__main__":
    unittest.main()
