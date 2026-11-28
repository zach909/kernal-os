"""Every Python file under kos/ and store/ must parse.

A bad merge once left both sides of several conflicts in the source, so the package did not import and
most tests never ran. This fails by file name the moment it happens again."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestSourcesParse(unittest.TestCase):
    def test_every_file_under_kos_and_apps_parses(self):
        files = sorted(p for d in ("kos", "store") for p in (ROOT / d).rglob("*.py"))
        self.assertTrue(files, "no Python files found: the test is looking in the wrong place")
        bad = []
        for p in files:
            try:
                ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            except (SyntaxError, ValueError) as e:
                bad.append(f"{p.relative_to(ROOT)}: {e}")
        self.assertEqual(bad, [], "files that do not parse:\n" + "\n".join(bad))


if __name__ == "__main__":
    unittest.main()
