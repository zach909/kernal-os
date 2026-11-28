"""Exact numbers: fractions, never decimals.

KOS rule: a number that is not a whole number is a ``Fraction``. There are no
decimal literals (``0.5``), no ``float()`` and no ``/`` between numbers in KOS
code; ``//`` for whole-number division, ``Fraction(a, b)`` for exact division.
Text that people read is shown the same way: ``7/2``, never ``3.5``.

``kos/rulecheck.py`` scans the source for breaches and ``tests/`` fails if one
is added. Hardware and the standard library hand back floats (clock readings,
socket timeouts); the place that receives one converts it at once with
``from_hardware``, which is exact (every float *is* a fraction) and so loses
nothing.
"""

from __future__ import annotations

import re
from fractions import Fraction
from typing import Union

Number = Union[int, Fraction]
_TEXT = re.compile(r"^\s*(-?[0-9]+)\s*(?:/\s*([0-9]+))?\s*$")


class DecimalRefused(ValueError):
    """Raised for anything that is not a whole number or ``a/b``."""


def frac(value: Union[int, str, Fraction]) -> Fraction:
    """A ``Fraction`` from an int, a Fraction, or text ``"a"`` / ``"a/b"``.

    Decimals (``"0.5"``, ``"1e3"``) and floats are refused, not rounded.
    """
    if isinstance(value, bool):
        raise DecimalRefused("a truth value is not a number")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, str):
        m = _TEXT.match(value)
        if not m:
            raise DecimalRefused(f"{value!r} is not a whole number or a fraction a/b")
        top, bottom = m.group(1), m.group(2)
        if bottom is not None and int(bottom) == 0:
            raise DecimalRefused("a fraction cannot have 0 underneath")
        return Fraction(int(top), int(bottom) if bottom is not None else 1)
    raise DecimalRefused(f"{type(value).__name__} is not allowed; use an int, a Fraction or 'a/b'")


def from_hardware(reading: float) -> Fraction:
    """Take a float the outside world gave us and make it an exact fraction.

    The only place a float may be received. Not finite (nan, inf) is refused.
    """
    try:
        return Fraction(reading)
    except (ValueError, OverflowError, TypeError):
        raise DecimalRefused(f"reading {reading!r} is not a finite number") from None


def show(value: Union[int, str, Fraction]) -> str:
    """How a number is written for a person: ``3``, ``-7/2``. Never a decimal point."""
    f = frac(value)
    return str(f.numerator) if f.denominator == 1 else f"{f.numerator}/{f.denominator}"


def div(top: Number, bottom: Number) -> Fraction:
    """Exact division. Dividing by zero is an error, not infinity."""
    b = frac(bottom)
    if b == 0:
        raise DecimalRefused("cannot divide by 0")
    return frac(top) / b
