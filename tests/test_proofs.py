"""The proofs run, and they can fail (a proof that cannot fail proves nothing)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import z3
    from kos import proofs
except ImportError:  # z3-solver is a development dependency
    z3 = None


@unittest.skipIf(z3 is None, "z3-solver not installed (pip install -r requirements-dev.txt)")
class TestProofs(unittest.TestCase):
    def test_every_proof_holds(self):
        self.assertEqual({k: v for k, v in proofs.prove_all().items() if not v}, {})

    def test_negative_controls_are_not_provable(self):
        a, b = z3.BitVecs("a b", 64)
        # a nonce that keeps only 32 bits of the counter is NOT injective
        self.assertFalse(proofs._proved(z3.Extract(31, 0, a) != z3.Extract(31, 0, b), a != b))
        # accepting any counter at or above the expected one does NOT refuse a skip
        e, o = z3.BitVecs("e o", 64)
        self.assertFalse(proofs._proved(o != e, z3.UGE(o, e)))
        # a header that drops a byte does NOT round-trip
        n = z3.BitVec("n", 32)
        self.assertFalse(proofs._proved(z3.ZeroExt(8, z3.Extract(23, 0, n)) == n))
        # a counter that may reach the limit CAN wrap
        s = z3.BitVec("s", 64)
        self.assertFalse(proofs._proved(z3.UGT(s + 1, s)))


if __name__ == "__main__":
    unittest.main()
