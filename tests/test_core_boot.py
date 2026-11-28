"""The booting binary (store/core/boot/kos-boot.c): checks the core against a sealed manifest, then starts it.

Every test that must be refused also checks the refusal is the ONE uniform message, and that the
core was never started (a marker the fake core would print is absent)."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOT = ROOT / "store" / "core" / "boot"
UNIFORM = "kos-boot: refusing to start\n"
MARK = "CORE-STARTED"


def can_build():
    return bool(shutil.which("make") and shutil.which("gcc") and
                (Path("/usr/include/openssl/evp.h").exists()))


@unittest.skipUnless(can_build(), "needs make, gcc and the OpenSSL headers to build kos-boot")
class TestBootBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp())
        r = subprocess.run(["make", "-C", str(BOOT), f"OUT={cls.out}"], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr          # -Wall -Wextra -Werror -pedantic
        cls.exe = cls.out / "kos-boot"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        (self.root / "kos").mkdir(parents=True)
        (self.root / "bin").mkdir()
        (self.root / "kos" / "a.py").write_text("A = 1\n")
        (self.root / "bin" / "kos").write_text(
            "import os, sys\nprint('%s', sys.flags.isolated, sys.argv[1:], "
            "'PYTHONPATH' in os.environ, 'LD_PRELOAD' in os.environ)\n" % MARK)
        self.manifest = self.tmp / "CORE.sha256"
        self.seal()

    def seal(self):
        lines = []
        for d in ("kos", "bin"):
            for p in sorted((self.root / d).rglob("*")):
                if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts:
                    lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(self.root)}")
        self.manifest.write_text("\n".join(lines) + "\n")

    def run_boot(self, *args, env=None):
        base = {**os.environ, **(env or {})}
        return subprocess.run([str(self.exe), "--root", str(self.root), "--manifest", str(self.manifest),
                               "--python", sys.executable, *args], capture_output=True, text=True, env=base)

    def refused(self, r, why=""):
        self.assertEqual(r.returncode, 1, why)
        self.assertEqual(r.stderr, UNIFORM, why)
        self.assertNotIn(MARK, r.stdout, "the core was started although it was refused: " + why)

    # --- the happy path ------------------------------------------------------------------------

    def test_a_verified_core_starts_isolated_with_args_and_a_clean_environment(self):
        r = self.run_boot("--", "hello", "--flag", env={"PYTHONPATH": "/evil", "LD_PRELOAD": "/evil.so"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), f"{MARK} 1 ['hello', '--flag'] False False")

    def test_check_mode_verifies_and_starts_nothing(self):
        r = self.run_boot("--check")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "kos-boot: core verified (2 files)\n")
        self.assertNotIn(MARK, r.stdout)

    # --- refusals: one message, nothing started --------------------------------------------------

    def test_a_changed_file_is_refused(self):
        (self.root / "kos" / "a.py").write_text("A = 2\n")
        self.refused(self.run_boot())

    def test_a_missing_file_is_refused(self):
        (self.root / "kos" / "a.py").unlink()
        self.refused(self.run_boot())

    def test_a_file_not_in_the_manifest_is_refused(self):
        (self.root / "kos" / "extra.py").write_text("import os\n")
        self.refused(self.run_boot())

    def test_a_file_hidden_in_a_new_folder_is_refused(self):
        (self.root / "kos" / "sub").mkdir()
        (self.root / "kos" / "sub" / "x.py").write_text("x\n")
        self.refused(self.run_boot())

    def test_a_link_in_place_of_a_file_is_refused(self):
        real = self.tmp / "real.py"
        real.write_text("A = 1\n")                      # same bytes as the sealed file
        (self.root / "kos" / "a.py").unlink()
        (self.root / "kos" / "a.py").symlink_to(real)
        self.refused(self.run_boot())

    def test_a_link_in_place_of_a_folder_is_refused(self):
        moved = self.tmp / "kosdir"
        shutil.move(str(self.root / "kos"), str(moved))
        (self.root / "kos").symlink_to(moved)
        self.refused(self.run_boot())

    def test_a_special_file_in_the_core_is_refused(self):
        os.mkfifo(self.root / "kos" / "pipe")
        self.refused(self.run_boot())

    def test_a_missing_manifest_is_refused(self):
        self.manifest.unlink()
        self.refused(self.run_boot())

    def test_hostile_manifests_are_refused(self):
        good = hashlib.sha256((self.root / "kos" / "a.py").read_bytes()).hexdigest()
        script = hashlib.sha256((self.root / "bin" / "kos").read_bytes()).hexdigest()
        bad = {
            "dot-dot": f"{good}  kos/../kos/a.py\n{script}  bin/kos\n",
            "absolute": f"{good}  /etc/passwd\n{script}  bin/kos\n",
            "duplicate": f"{good}  kos/a.py\n{good}  kos/a.py\n{script}  bin/kos\n",
            "uppercase hex": f"{good.upper()}  kos/a.py\n{script}  bin/kos\n",
            "one space": f"{good} kos/a.py\n{script}  bin/kos\n",
            "short hash": f"{good[:60]}  kos/a.py\n{script}  bin/kos\n",
            "blank line": f"{good}  kos/a.py\n\n{script}  bin/kos\n",
            "no final newline": f"{good}  kos/a.py\n{script}  bin/kos",
            "control character": f"{good}  kos/a\x01.py\n{script}  bin/kos\n",
            "space in path": f"{good}  kos/a b.py\n{script}  bin/kos\n",
            "empty": "",
            "bin/kos missing": f"{good}  kos/a.py\n",
        }
        for why, text in bad.items():
            self.manifest.write_text(text)
            self.refused(self.run_boot(), why)

    def test_a_manifest_with_a_nul_byte_is_refused(self):
        self.manifest.write_bytes(self.manifest.read_bytes() + b"\0")
        self.refused(self.run_boot())

    def test_an_oversized_manifest_is_refused(self):
        self.manifest.write_bytes(b"0" * (1024 * 1024 + 1))
        self.refused(self.run_boot())

    def test_a_relative_interpreter_is_refused(self):
        r = subprocess.run([str(self.exe), "--root", str(self.root), "--manifest", str(self.manifest),
                            "--python", "python3"], capture_output=True, text=True)
        self.refused(r)

    def test_an_interpreter_that_cannot_start_is_refused(self):
        r = subprocess.run([str(self.exe), "--root", str(self.root), "--manifest", str(self.manifest),
                            "--python", "/nonexistent/python"], capture_output=True, text=True)
        self.refused(r)

    def test_every_refusal_says_the_same_thing(self):
        """No hint which check failed: a changed file and a missing manifest look identical."""
        (self.root / "kos" / "a.py").write_text("A = 2\n")
        first = self.run_boot().stderr
        self.manifest.unlink()
        self.assertEqual(self.run_boot().stderr, first)

    def test_check_mode_is_the_only_place_that_says_why(self):
        (self.root / "kos" / "a.py").write_text("A = 2\n")
        r = self.run_boot("--check")
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stderr.startswith(UNIFORM))
        self.assertIn("does not match the manifest", r.stderr)

    # --- the real core ---------------------------------------------------------------------------

    def test_the_real_core_seals_and_verifies(self):
        """make seal on this repo's own kos/ and bin/, then the binary accepts exactly that tree."""
        r = subprocess.run(["make", "-C", str(BOOT), "seal", f"OUT={self.tmp / 'sealed'}", f"ROOT={ROOT}"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([str(self.exe), "--root", str(ROOT), "--manifest", str(self.tmp / "sealed" / "CORE.sha256"),
                            "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"core verified \(\d+ files\)")


if __name__ == "__main__":
    unittest.main()
