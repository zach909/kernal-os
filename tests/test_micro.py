"""KOS-micro (micro/): builds the C core and runs its tests, including the 7 KiB RAM budget."""
import shutil
import subprocess
import unittest
from pathlib import Path

MICRO = Path(__file__).resolve().parent.parent / "micro"


@unittest.skipUnless(shutil.which("make") and shutil.which("cc"), "needs make and a C compiler")
class MicroTests(unittest.TestCase):
    def test_check_passes_and_fits_budget(self):
        r = subprocess.run(["make", "-C", str(MICRO), "clean", "check"], capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        line = next(x for x in r.stdout.splitlines() if x.startswith("RAM:"))
        total, budget = [int(t) for t in line.replace("=", " ").split() if t.isdigit()][-2:]
        self.assertLessEqual(total, budget)
        self.assertEqual(budget, 7168)


if __name__ == "__main__":
    unittest.main()
