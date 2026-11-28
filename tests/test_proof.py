"""The proof gate and the no-decimals rule (kos/proof.py)."""

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import proof  # noqa: E402
from kos.kapp import KApp, KAppError, pack  # noqa: E402
from kos.protocol import Channel, ProtocolError  # noqa: E402
from kos.store import AppStore  # noqa: E402
sys.path.insert(0, str(ROOT / "tests"))
from test_kos import PW, Env  # noqa: E402

MANIFEST = {"name": "p", "version": "1", "runtime": "python", "entry": "app"}


def tree(root: Path, code: str, extra=None, manifest=None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest or MANIFEST))
    (root / "app.py").write_text(code)
    for name, data in (extra or {}).items():
        (root / name).write_bytes(data)
    return root


def v(code: str) -> list:
    return proof.violations(code.encode(), "app.py")


class TestNoDecimals(unittest.TestCase):
    def test_each_way_to_make_a_decimal_is_found(self):
        for code in ("x = 1.5", "x = 1e3", "x = 2j", "x = a / b", "x /= 2", "x = float(3)",
                     "x = complex(1)", "import decimal", "from fractions import Fraction",
                     "import math\nx = math.sqrt(4)", "from math import pi", "import time\nx = time.time()",
                     "import random\nx = random.random()", "import statistics"):
            self.assertTrue(v(code), code)

    def test_whole_number_code_is_clean(self):
        self.assertEqual(v("import math\nimport json\nx = 7 // 2\nn = math.isqrt(10) + math.gcd(4, 6)\n"
                           "y = divmod(9, 4)\nz = 3 * 4 ** 2\n"), [])

    def test_a_syntax_error_does_not_compile_and_so_is_refused(self):
        self.assertTrue(v("def (:"))

    def test_ways_out_of_the_check_are_found(self):
        for code in ("eval('1')", "exec('x=1')", "compile('1', 'a', 'eval')", "__import__('os')",
                     "import ctypes", "import importlib", "import pickle", "import subprocess",
                     "x = ().__class__.__bases__", "import relative_to_nothing_real",
                     "from . import x"):
            self.assertTrue(v(code), code)


class TestProofGate(Env):
    def packed(self, name, code="def main():\n    pass\n", **kw):
        d = tree(Path(self.tmp.name) / f"src-{name}", code, **kw)
        out = Path(self.tmp.name) / f"{name}.kapp"
        pack(d, out)
        return out

    def test_pack_adds_a_proof_and_the_app_installs_and_loads(self):
        out = self.packed("ok")
        self.assertIn("proof.json", KApp.from_file(out).names())
        AppStore(self.paths).install(out, self.authority(PW))
        store = AppStore(self.paths)
        with self.authority(PW).authorize("app.run", "p") as g:
            self.assertEqual(store.load_verified("p", g).manifest.name, "p")

    def test_pack_refuses_code_it_cannot_prove(self):
        d = tree(Path(self.tmp.name) / "src-bad", "def main():\n    return 1 / 2\n")
        with self.assertRaises(proof.ProofError):
            pack(d, Path(self.tmp.name) / "bad.kapp")

    def test_an_app_with_no_proof_is_not_installed_and_no_password_is_asked(self):
        d = tree(Path(self.tmp.name) / "src-np", "def main():\n    pass\n")
        out = Path(self.tmp.name) / "np.kapp"
        pack(d, out, prove=False)
        with self.assertRaises(proof.ProofError):
            AppStore(self.paths).install(out, self.authority())   # no answers given: would fail if asked
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_an_unproven_app_already_in_the_store_does_not_run(self):
        out = self.packed("ok")
        store = AppStore(self.paths)
        store.install(out, self.authority(PW))
        d = tree(Path(self.tmp.name) / "src-np", "def main():\n    pass\n")
        raw = Path(self.tmp.name) / "np.kapp"
        pack(d, raw, prove=False)
        # swap in an unproven zip and a seal made with the real password, as a careless admin would
        import hashlib
        from kos.kapp import compute_seal
        kapp, seal = self.paths.apps / "p.kapp", self.paths.apps / "p.seal"
        kapp.write_bytes(raw.read_bytes())
        with self.authority(PW).authorize("app.run", "p") as g:
            meta = json.loads(seal.read_text())
            meta["sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
            meta["seal"] = compute_seal(g.key("kapp-seal"), "p", "1", meta["sha256"])
            seal.write_text(json.dumps(meta))
        with self.authority(PW).authorize("app.run", "p") as g:
            with self.assertRaises(proof.ProofError):
                store.load_verified("p", g)

    def test_changed_code_does_not_match_its_proof(self):
        good = self.packed("ok").read_bytes()
        src = zipfile.ZipFile(io.BytesIO(good))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n in src.namelist():
                z.writestr(n, b"def main():\n    return 1\n" if n == "app.py" else src.read(n))
        with self.assertRaises(proof.ProofError):
            proof.require(KApp(buf.getvalue()))

    def test_a_hand_made_proof_for_code_with_a_decimal_is_still_refused(self):
        import hashlib
        code = b"def main():\n    return 1.5\n"
        fake = json.dumps({"format": 1, "verifier": proof.VERIFIER,
                           "files": {"app.py": hashlib.sha256(code).hexdigest()}})
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(MANIFEST))
            z.writestr("app.py", code)
            z.writestr("proof.json", fake)
        with self.assertRaises(proof.ProofError):
            proof.require(KApp(buf.getvalue()))

    def test_a_proof_with_a_decimal_in_it_is_not_valid(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(MANIFEST))
            z.writestr("app.py", "")
            z.writestr("proof.json", '{"format": 1.0}')
        with self.assertRaises(proof.ProofError):
            proof.require(KApp(buf.getvalue()))

    def test_a_binary_cannot_ride_inside_a_python_app(self):
        d = tree(Path(self.tmp.name) / "src-elf", "def main():\n    pass\n",
                 extra={"tool": b"\x7fELF" + b"\0" * 60})
        with self.assertRaises(proof.ProofError):
            pack(d, Path(self.tmp.name) / "elf.kapp")

    def test_a_native_program_cannot_be_proven(self):
        d = tree(Path(self.tmp.name) / "src-nat", "", extra={"bin": b"\x7fELF" + b"\0" * 60},
                 manifest={**MANIFEST, "runtime": "native", "entry": "bin"})
        with self.assertRaises(proof.ProofError):
            pack(d, Path(self.tmp.name) / "nat.kapp")

    def test_an_import_from_outside_the_app_the_os_or_the_stdlib_is_refused(self):
        self.assertTrue(v("import requests"))


class TestWireHasNoDecimals(unittest.TestCase):
    def feed(self, raw: bytes):
        import socket
        a, b = socket.socketpair()
        ch = Channel(a)
        b.sendall(raw)
        return ch.receive()

    def test_whole_numbers_pass(self):
        self.assertEqual(self.feed(b'{"cmd":"pointer","x":3,"y":-4}\n'), [{"cmd": "pointer", "x": 3, "y": -4}])

    def test_a_number_with_a_point_or_an_exponent_or_nan_is_refused(self):
        for raw in (b'{"x":1.5}\n', b'{"x":1e2}\n', b'{"x":NaN}\n', b'{"x":Infinity}\n'):
            with self.assertRaises(ProtocolError, msg=raw):
                self.feed(raw)


class TestTheOsRatchet(unittest.TestCase):
    """The OS's own code still uses decimals in places (clocks, throttle delays, the office packs).
    That is a known gap. It may only shrink: no file may gain a use, and no clean file may start."""

    def test_no_file_gains_a_decimal(self):
        baseline = json.loads((ROOT / "tests" / "nodecimal_baseline.json").read_text())
        grew = []
        for p in sorted((ROOT / "kos").rglob("*.py")):
            rel = p.relative_to(ROOT).as_posix()
            n = proof.decimal_uses(p.read_bytes())
            if n > baseline.get(rel, 0):
                grew.append(f"{rel}: {n} (allowed {baseline.get(rel, 0)})")
        self.assertEqual(grew, [], "new decimals in OS code: use whole numbers (and '//')")

    def test_the_proof_module_itself_has_none(self):
        self.assertEqual(proof.decimal_uses((ROOT / "kos" / "proof.py").read_bytes()), 0)


if __name__ == "__main__":
    unittest.main()
