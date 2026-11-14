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
        # KOS-SILENT: a one-byte length field cannot hold a full record's length
        m = z3.BitVec("m", 32)
        self.assertFalse(proofs._proved(z3.ZeroExt(24, z3.Extract(7, 0, m)) == m, z3.ULE(m, proofs.CELL_CAP)))
        # KOS-SILENT: if more records than the fewest were allowed, the padding could be more than a record
        n, c = z3.Ints("n c")
        pad = c * proofs.CELL_CAP - n
        self.assertFalse(proofs._proved(pad <= proofs.CELL_CAP,
                                        z3.And(n >= 0, n <= proofs.MAX_MESSAGE, c >= 1, c * proofs.CELL_CAP >= n)))
        # KOS-SILENT: with the wrong padding the answer is NOT the size of the question
        p = z3.Int("p")
        self.assertFalse(proofs._proved(proofs.X_LEN + proofs.CT_LEN + p == proofs.HS_PLAIN, p >= 0))


if __name__ == "__main__":
    unittest.main()
