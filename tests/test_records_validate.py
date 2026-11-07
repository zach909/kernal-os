"""records.validate must refuse, never raise on, hostile numbers."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office.records import Field, validate  # noqa: E402


class TestNumbers(unittest.TestCase):
    def test_nan_and_infinity_are_refused_not_raised(self):
        for kind in ("number", "money", "percent"):
            for v in ("nan", "NaN", "inf", "-inf", "Infinity", "1e999", "-1e999", "1e400"):
                self.assertEqual(validate(Field("x", "X", kind), v), (False, "must be a number" if kind != "percent" else "must be a number"), (kind, v))

    def test_ordinary_numbers_still_work(self):
        self.assertEqual(validate(Field("x", "X", "money"), "$1,234.50"), (True, "1234.5"))
        self.assertEqual(validate(Field("x", "X", "number"), "12"), (True, "12"))
        self.assertEqual(validate(Field("x", "X", "percent"), "101"), (False, "must be 0-100"))


if __name__ == "__main__":
    unittest.main()
