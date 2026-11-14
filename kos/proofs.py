"""Machine-checked proofs of the rules that can be stated as maths.

Each proof asks the Z3 solver for a counter-example to the claim; "unsat" (none
exists) is the proof. Z3 is a development dependency (``requirements-dev.txt``):
the OS does not need it to run, ``tests/test_proofs.py`` needs it to pass.

What is proved here is about the *model* below, and the model is checked
against the real code in ``tests/test_crypt.py``. It is not a proof of the
``cryptography`` library or of Python. Things that are not maths (the
password prompt, the sandbox) are covered by tests that try to break them,
and the README says so.
"""

from __future__ import annotations

from typing import Callable

import z3

from .crypt import COUNTER_LIMIT, MAX_PLAIN, MAX_RECORD, TAG_LEN
from .silent import CELL_CAP, CELL_HEAD, CELL_PLAIN, CT_LEN, EK_LEN, HS_LEN, HS_PAD, HS_PLAIN, MAX_MESSAGE, SALT_LEN, X_LEN
from .silent import TAG_LEN as SILENT_TAG

_BITS64 = 64


def _proved(claim, *assumptions) -> bool:
    s = z3.Solver()
    s.add(*assumptions)
    s.add(z3.Not(claim))
    return s.check() == z3.unsat


def nonce_is_injective() -> bool:
    """Two different message counters never give the same nonce (no nonce reuse in one direction)."""
    a, b = z3.BitVecs("a b", _BITS64)
    nonce = lambda c: z3.Concat(z3.BitVecVal(0, 32), c)
    return _proved(nonce(a) != nonce(b), a != b)


def header_round_trips() -> bool:
    """Writing a length as 4 big-endian bytes and reading it back gives the same length."""
    n = z3.BitVec("n", 32)
    b0, b1, b2, b3 = (z3.Extract(31 - 8 * i, 24 - 8 * i, n) for i in range(4))
    return _proved(z3.Concat(b0, b1, b2, b3) == n)


def record_size_fits_header() -> bool:
    """Every size the code allows fits in the 4-byte header, with room to spare."""
    n = z3.BitVec("n", 64)
    ok = z3.And(z3.UGT(n, 0), z3.ULE(n, MAX_RECORD))
    return _proved(z3.ULT(n, z3.BitVecVal(1 << 32, 64)), ok) and MAX_RECORD == MAX_PLAIN + 1 + TAG_LEN


def counter_never_wraps() -> bool:
    """While the counter is below the limit, adding one makes it bigger (it cannot wrap to a used value)."""
    s = z3.BitVec("s", _BITS64)
    return _proved(z3.UGT(s + 1, s), z3.ULT(s, z3.BitVecVal(COUNTER_LIMIT, _BITS64)))


def replay_is_refused() -> bool:
    """A receiver takes a record only if its counter equals the next expected one and then expects one more,
    so no counter that was already taken (or any earlier one) is ever taken again."""
    expected, taken, offered = z3.BitVecs("expected taken offered", _BITS64)
    after = expected + 1
    below_limit = z3.ULT(expected, z3.BitVecVal(COUNTER_LIMIT, _BITS64))
    already_taken = z3.ULE(taken, expected)          # everything taken so far is at or before `expected`
    would_be_accepted_again = z3.And(offered == after, z3.ULE(offered, taken))
    return _proved(z3.Not(would_be_accepted_again), below_limit, already_taken)


def skip_is_refused() -> bool:
    """Dropping a record means the next one carries a counter that is not the expected one, so it is refused."""
    expected, offered = z3.BitVecs("expected offered", _BITS64)
    return _proved(offered != expected, z3.UGT(offered, expected))


def silent_length_field_round_trips() -> bool:
    """KOS-SILENT: a record's length (at most CELL_CAP) written as 2 bytes and read back is the same number."""
    n = z3.BitVec("n", 32)
    back = z3.ZeroExt(16, z3.Extract(15, 0, n))
    return _proved(back == n, z3.ULE(n, CELL_CAP)) and CELL_CAP + CELL_HEAD == CELL_PLAIN


def silent_padding_fits_one_record() -> bool:
    """KOS-SILENT: cutting a message of n bytes into the fewest records of CELL_CAP leaves padding
    in the last record that is never negative and never more than one record (so exactly
    ceil(n / CELL_CAP) records, and the number of records shows the size only to the nearest record)."""
    n, c = z3.Ints("n c")
    fewest = z3.And(c >= 1, c * CELL_CAP >= n, z3.Or(c == 1, (c - 1) * CELL_CAP < n))
    pad = c * CELL_CAP - n
    return _proved(z3.And(pad >= 0, pad <= CELL_CAP), z3.And(n >= 0, n <= MAX_MESSAGE), fewest)


def silent_handshake_messages_are_one_size() -> bool:
    """KOS-SILENT: the question (X25519 key + ML-KEM key) and the answer (X25519 key + ML-KEM
    ciphertext + padding) are the same length, so neither side's message tells which it is."""
    pad = z3.Int("pad")
    answer = X_LEN + CT_LEN + pad
    return (_proved(answer == HS_PLAIN, pad == HS_PAD) and HS_PAD >= 0 and HS_PLAIN == X_LEN + EK_LEN
            and HS_LEN == SALT_LEN + HS_PLAIN + SILENT_TAG)


PROOFS: dict[str, Callable[[], bool]] = {
    "nonce_is_injective": nonce_is_injective,
    "header_round_trips": header_round_trips,
    "record_size_fits_header": record_size_fits_header,
    "counter_never_wraps": counter_never_wraps,
    "replay_is_refused": replay_is_refused,
    "skip_is_refused": skip_is_refused,
    "silent_length_field_round_trips": silent_length_field_round_trips,
    "silent_padding_fits_one_record": silent_padding_fits_one_record,
    "silent_handshake_messages_are_one_size": silent_handshake_messages_are_one_size,
}


def prove_all() -> dict[str, bool]:
    return {name: fn() for name, fn in PROOFS.items()}


if __name__ == "__main__":  # python3 -m kos.proofs
    results = prove_all()
    for name, ok in results.items():
        print(("proved   " if ok else "FAILED   ") + name)
    raise SystemExit(0 if all(results.values()) else 1)
