"""The lean profile: small, still the same program, still obeys the package rules."""

import importlib.util
import os
import subprocess
import sys
import tarfile
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packaging"))

import lean  # noqa: E402
from kos.debconv import _ar_members, _member, parse_deb  # noqa: E402


class TestStrip(unittest.TestCase):
    SRC = '''"""module doc"""
# a comment
import os

def f(x):
    """doc"""
    return x + 1  # trailing

class C:
    """doc"""

    def g(self):
        """doc"""

def empty():
    """only a docstring"""
'''

    def test_docstrings_and_comments_go_and_behaviour_stays(self):
        out = lean.strip_source(self.SRC)
        self.assertNotIn("doc", out)
        self.assertNotIn("comment", out)
        ns = {}
        exec(compile(out, "<lean>", "exec"), ns)
        self.assertEqual(ns["f"](1), 2)
        self.assertIsNone(ns["empty"]())
        self.assertIsNone(ns["C"]().g())

    def test_strings_that_are_not_docstrings_are_kept(self):
        out = lean.strip_source('def f():\n    x = "keep me"\n    "not first"\n    return x\n')
        self.assertIn("keep me", out)

    def test_it_is_idempotent_and_deterministic(self):
        once = lean.strip_source(self.SRC)
        self.assertEqual(lean.strip_source(once), once)
        self.assertEqual(lean.strip_source(self.SRC), once)

    def test_every_core_module_strips_compiles_and_gets_smaller(self):
        raw = out = 0
        for f in sorted((ROOT / "kos").glob("*.py")):
            src = f.read_text()
            stripped = lean.strip_source(src)
            compile(stripped, str(f), "exec")
            raw, out = raw + len(src.encode()), out + len(stripped.encode())
        self.assertLess(out, raw * 0.8)          # measured at about 0.74 when this was written

    def test_nothing_in_the_core_reads_a_docstring(self):
        for f in (ROOT / "kos").glob("*.py"):
            self.assertNotIn("__doc__", f.read_text(), f.name)


class TestWhatShips(unittest.TestCase):
    def test_core_is_in_and_the_rest_is_out(self):
        for p in ("bin/kos", "bin/run", "kos/auth.py", "kos/ai.py", "examples/system/taskbar/app.py"):
            self.assertTrue(lean.in_lean(p), p)
        for p in ("kos/office/sheet.py", "tests/test_kos.py", "docs/CATALOG.md", "README.md", "boot/cell-init",
                  "examples/web/web.py", "examples/ai/app.py", "suite/gen.py", "bin/suite", "packaging/build_deb.py"):
            self.assertFalse(lean.in_lean(p), p)


class TestLeanPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / ".git").exists():
            raise unittest.SkipTest("needs a git checkout")
        spec = importlib.util.spec_from_file_location("build_deb_lean", ROOT / "packaging" / "build_deb.py")
        cls.bd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bd)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.lean = cls.bd.build(Path(cls.tmp.name) / "lean", lean=True)
        cls.full = cls.bd.build(Path(cls.tmp.name) / "full")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_it_is_its_own_package_xz_compressed_and_several_times_smaller(self):
        d = parse_deb(self.lean.read_bytes())
        self.assertEqual(d.control["Package"], "kernal-os-core")
        self.assertEqual(d.control["Conflicts"], "kernal-os")
        names = list(_ar_members(self.lean.read_bytes()))
        self.assertIn("data.tar.xz", names)
        self.assertGreater(self.full.stat().st_size, 3 * self.lean.stat().st_size)

    def test_only_the_core_is_in_it(self):
        d = parse_deb(self.lean.read_bytes())
        paths = {p.removeprefix("usr/lib/kernal-os/") for p in d.files}
        self.assertTrue(paths)
        self.assertTrue(all(lean.in_lean(p) for p in paths), sorted(p for p in paths if not lean.in_lean(p)))
        self.assertFalse(any(p.startswith(("kos/office", "tests", "docs", "suite")) for p in paths))

    def test_same_package_rules_as_the_full_one(self):
        d = parse_deb(self.lean.read_bytes())
        self.assertEqual(d.scripts, [])                          # nothing runs at install or removal
        self.assertTrue(all(not (mode & 0o7000) for _, mode in d.files.values()))
        self.assertFalse(any(p.startswith(("etc/", "lib/systemd", "var/")) for p in d.files))
        self.assertEqual(sorted(x.split(": ", 1)[1] for x in d.dropped), ["usr/bin/kos", "usr/bin/kos-run"])

    def test_it_is_reproducible(self):
        with tempfile.TemporaryDirectory() as t2:
            self.assertEqual(self.bd.build(Path(t2), lean=True).read_bytes(), self.lean.read_bytes())

    def test_the_shipped_source_has_no_docstrings(self):
        d = parse_deb(self.lean.read_bytes())
        data = d.files["usr/lib/kernal-os/kos/auth.py"][0]
        self.assertNotIn(b'"""', data)

    def test_the_core_runs_on_its_own(self):
        """Extract only the lean package and run it: the OS must not secretly need the suite, tests or docs."""
        _, blob = _member(_ar_members(self.lean.read_bytes()), "data.tar")
        with tempfile.TemporaryDirectory() as d, tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
            t.extractall(d, filter="data")
            home = Path(d) / "usr" / "lib" / "kernal-os"
            self.assertFalse((home / "kos" / "office").exists())
            env = {"PATH": os.environ["PATH"], "KOS_ROOT": str(Path(d) / "root"), "PYTHONDONTWRITEBYTECODE": "1"}
            for argv in (["doctor"], ["--help"], ["ai", "set", "--url", "http://example.com/x", "--model", "m"]):
                r = subprocess.run([sys.executable, "-I", str(home / "bin" / "kos"), *argv], capture_output=True,
                                   text=True, env=env, cwd=d)
                self.assertNotIn("Traceback", r.stderr, (argv, r.stderr))
            self.assertIn("refused", r.stderr)                 # the AI's https-only rule holds in the lean build too


@unittest.skipUnless(os.environ.get("KOS_LEAN_FULL") == "1", "set KOS_LEAN_FULL=1: runs the whole suite on the stripped tree")
class TestWholeSuiteOnTheStrippedTree(unittest.TestCase):
    def test_every_other_test_passes_against_stripped_sources(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT.parent)) as d:       # apps run as nobody: must be traversable
            os.chmod(d, 0o755)
            subprocess.run(f"git -C {ROOT} archive HEAD | tar -x -C {d}", shell=True, check=True)
            for f in (Path(d) / "kos").glob("*.py"):
                f.write_text(lean.strip_source(f.read_text()))
            (Path(d) / "tests" / "test_lean.py").unlink()
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=d,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-3000:])


if __name__ == "__main__":
    unittest.main()
