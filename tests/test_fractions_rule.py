"""No decimals, only fractions."""

import json
import sys
import unittest
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import exact, rulecheck  # noqa: E402


class TestExact(unittest.TestCase):
    def test_fractions_in_and_out(self):
        self.assertEqual(exact.frac("3/4"), Fraction(3, 4))
        self.assertEqual(exact.frac(" -6 / 8 "), Fraction(-3, 4))
        self.assertEqual(exact.frac(5), Fraction(5))
        self.assertEqual(exact.show("6/8"), "3/4")
        self.assertEqual(exact.show(Fraction(10, 5)), "2")
        self.assertEqual(exact.show(-7 * Fraction(1, 2)), "-7/2")

    def test_decimals_are_refused_never_rounded(self):
        for bad in ("0.5", "1e3", ".5", "5.", "1/0", "1/2/3", "", "nan", "1_0", "+1/2x", "١/٢"):
            with self.assertRaises(exact.DecimalRefused, msg=bad):
                exact.frac(bad)
        for bad in (0.5, 1.0, True, None, [1]):
            with self.assertRaises(exact.DecimalRefused, msg=repr(bad)):
                exact.frac(bad)

    def test_a_float_from_hardware_is_kept_exactly(self):
        x = 0.1
        self.assertEqual(exact.from_hardware(x), Fraction(x))
        self.assertEqual(float(exact.from_hardware(x)), x)
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(exact.DecimalRefused):
                exact.from_hardware(bad)

    def test_exact_division(self):
        self.assertEqual(exact.div(1, 3) * 3, 1)         # a float would give 0.9999...
        with self.assertRaises(exact.DecimalRefused):
            exact.div(1, 0)

    def test_nothing_shown_has_a_decimal_point(self):
        for n in range(-20, 21):
            for d in range(1, 13):
                self.assertNotIn(".", exact.show(Fraction(n, d)))


class TestChecker(unittest.TestCase):
    def found(self, src):
        return [w for _, w in rulecheck.breaches(src)]

    def test_it_finds_each_kind(self):
        self.assertEqual(len(self.found("x = 0.5")), 1)
        self.assertEqual(len(self.found("x = 1e3")), 1)
        self.assertEqual(len(self.found("x = float(a)")), 1)
        self.assertEqual(len(self.found("x = a / 2")), 1)
        self.assertEqual(len(self.found("x = len(a) / len(b)")), 1)
        self.assertEqual(len(self.found("x /= y")), 1)
        self.assertEqual(len(self.found("x = -1.5")), 1)

    def test_it_leaves_fractions_and_paths_alone(self):
        for ok in ("x = Fraction(1, 2)", "x = a // 2", 'p = base / "dir"', "p = paths.apps / name",
                   "x = frac('3/4')", "x = int(a) // 3"):
            self.assertEqual(self.found(ok), [], ok)

    def test_new_code_has_no_decimals_and_old_code_cannot_grow(self):
        baseline = json.loads((ROOT / "tests" / "fractions_baseline.json").read_text())
        now = rulecheck.scan_tree(ROOT)
        grew = {f: (baseline.get(f, 0), n) for f, n in now.items() if n > baseline.get(f, 0)}
        self.assertEqual(grew, {}, "decimals added (file: was, now) - use Fraction, see kos/exact.py")

    def test_the_new_security_code_is_clean(self):
        for f in ("kos/exact.py", "kos/crypt.py", "kos/proofs.py", "kos/rulecheck.py"):
            self.assertEqual(rulecheck.scan_file(ROOT / f), [], f)


if __name__ == "__main__":
    unittest.main()
