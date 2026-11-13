"""Turn pixels into draw ops: how an app shows a picture on KOS.

KOS has no image command. The OS draws only ``clear``, ``rect``, ``line`` and
``text`` (see ``protocol.py``), at most ``MAX_OPS`` per frame, and it validates
every one. So a picture has to become geometry before it is sent. This module
is that step, and it lives on the app side (standard library only, like
``kos.sdk``) so the OS core stays small and nothing new reaches the OS.

How it works:

1. The most common colour becomes one background ``rect`` (one op for the
   whole picture).
2. Each row is cut into runs of one colour.
3. A run that repeats unchanged on the next row is merged with it, so a solid
   shape is one box, not one line per row.
4. A box one pixel thin is a ``line`` op, anything bigger is a ``rect`` op.

Pictures that do not fit the budget (a photo has thousands of tiny runs) are
degraded on purpose, in this order, until they fit: fewer colours first, then
the picture averaged down in 2x blocks. ``Vectorized.lossless`` says whether
the result is pixel-exact. Nothing here is a codec: a photo comes out as a
posterised, blocky approximation, and that is the honest limit of drawing with
boxes and lines.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from itertools import groupby
from typing import Any, Optional, Sequence

# These mirror protocol.MAX_OPS / MAX_COORD. They are copied, not imported, so an
# app needs nothing but the standard library; a test keeps them equal.
MAX_OPS = 5000
MAX_COORD = 16384
DEFAULT_BUDGET = 4000          # leaves room in a frame for the app's own UI
MAX_SIDE = 1024
MAX_PIXELS = 512 * 512         # bounds the work an app can make the converter do
MAX_SCALE = 64

_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}\Z")
_STEPS = (1, 8, 24, 64)        # colour bucket sizes, finest first


@dataclass
class Vectorized:
    ops: list                  # draw ops, ready for a frame
    width: int                 # picture size in source pixels
    height: int
    lossless: bool             # True: every source pixel is reproduced exactly
    downscale: int = 1         # 2 means each drawn cell stands for 2x2 source pixels
    step: int = 1              # colour bucket size; 1 means exact colours


def _int(v: Any, name: str, lo: int, hi: int) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise ValueError(f"{name} must be an integer in [{lo}, {hi}]")
    return v


def _pixel(p: Any) -> int:
    """One source pixel -> 0xRRGGBB. Accepts '#rrggbb' or (r, g, b)."""
    if isinstance(p, str):
        if not _HEX_RE.match(p):
            raise ValueError("a pixel string must look like '#1e90ff'")
        return int(p[1:], 16)
    if isinstance(p, (tuple, list)) and len(p) == 3:
        r, g, b = (_int(c, "a colour channel", 0, 255) for c in p)
        return r << 16 | g << 8 | b
    raise ValueError("a pixel must be '#rrggbb' or an (r, g, b) triple")


def _grid(pixels: Any) -> list[list[int]]:
    if not isinstance(pixels, (list, tuple)) or not pixels:
        raise ValueError("pixels must be a non-empty list of rows")
    if len(pixels) > MAX_SIDE:
        raise ValueError(f"pixels may have at most {MAX_SIDE} rows")
    width = None
    cache: dict = {}
    grid = []
    for row in pixels:
        if not isinstance(row, (list, tuple)) or not row:
            raise ValueError("every row must be a non-empty list of pixels")
        if width is None:
            width = len(row)
            if width > MAX_SIDE or width * len(pixels) > MAX_PIXELS:
                raise ValueError(f"the picture is too big (at most {MAX_PIXELS} pixels, {MAX_SIDE} per side)")
        elif len(row) != width:
            raise ValueError("every row must be the same length")
        out = []
        for p in row:
            key = p if isinstance(p, str) else tuple(p) if isinstance(p, (tuple, list)) else None
            try:
                c = cache[key]
            except (KeyError, TypeError):
                c = cache[key] = _pixel(p)
            out.append(c)
        grid.append(out)
    return grid


def _quantize(grid: list[list[int]], step: int) -> list[list[int]]:
    if step == 1:
        return grid
    table = [min(255, v // step * step + step // 2) for v in range(256)]
    memo: dict = {}

    def q(c: int) -> int:
        r = memo.get(c)
        if r is None:
            r = memo[c] = table[c >> 16] << 16 | table[c >> 8 & 255] << 8 | table[c & 255]
        return r
    return [[q(c) for c in row] for row in grid]


def _downscale(grid: list[list[int]], d: int) -> list[list[int]]:
    """Average each d x d block (edge blocks are smaller) into one pixel."""
    if d == 1:
        return grid
    h, w = len(grid), len(grid[0])
    out = []
    for by in range(0, h, d):
        rows = grid[by:by + d]
        line = []
        for bx in range(0, w, d):
            n = r = g = b = 0
            for row in rows:
                for c in row[bx:bx + d]:
                    n += 1
                    r += c >> 16
                    g += c >> 8 & 255
                    b += c & 255
            line.append((r // n) << 16 | (g // n) << 8 | b // n)
        out.append(line)
    return out


def _boxes(grid: list[list[int]], bg: int, limit: int):
    """Non-background boxes (x0, x1, y0, y1, colour), each pixel in exactly one.
    Returns None as soon as there are more than ``limit`` of them."""
    boxes = []
    open_: dict = {}
    h = len(grid)
    for y, row in enumerate(grid):
        cur: dict = {}
        x = 0
        for color, run in groupby(row):
            n = sum(1 for _ in run)
            if color != bg:
                key = (x, x + n - 1, color)
                cur[key] = open_.pop(key, y)
            x += n
        for (x0, x1, color), y0 in open_.items():
            boxes.append((x0, x1, y0, y - 1, color))
        if len(boxes) > limit:
            return None
        open_ = cur
    for (x0, x1, color), y0 in open_.items():
        boxes.append((x0, x1, y0, h - 1, color))
    return boxes if len(boxes) <= limit else None


def vectorize(pixels: Sequence[Sequence[Any]], x: int = 0, y: int = 0, scale: int = 1,
              max_ops: int = DEFAULT_BUDGET) -> Vectorized:
    """Draw ops for a picture. ``pixels`` is a list of rows of '#rrggbb' strings
    or (r, g, b) triples; (x, y) is where its top-left corner goes and ``scale``
    makes every source pixel a scale x scale square. Never returns more than
    ``max_ops`` ops. Raises ValueError for anything malformed, never anything else."""
    x = _int(x, "x", -MAX_COORD, MAX_COORD)
    y = _int(y, "y", -MAX_COORD, MAX_COORD)
    scale = _int(scale, "scale", 1, MAX_SCALE)
    max_ops = _int(max_ops, "max_ops", 1, MAX_OPS)
    source = _grid(pixels)
    w, h = len(source[0]), len(source)
    if not (-MAX_COORD <= x and x + w * scale <= MAX_COORD
            and -MAX_COORD <= y and y + h * scale <= MAX_COORD):
        raise ValueError("the picture would reach outside the coordinate range")

    d = 1
    while True:
        base = _downscale(source, d)
        for step in _STEPS:
            grid = _quantize(base, step)
            colours = Counter(c for row in grid for c in row)
            bg = colours.most_common(1)[0][0]
            boxes = _boxes(grid, bg, max_ops - 1)
            if boxes is not None:
                return Vectorized(
                    _ops(boxes, bg, x, y, scale, d, w, h),
                    w, h, lossless=(d == 1 and step == 1), downscale=d, step=step)
        if len(base) == 1 and len(base[0]) == 1:   # one cell is always one op; cannot get here
            raise ValueError("max_ops is too small for this picture")
        d *= 2


def _ops(boxes, bg: int, x: int, y: int, scale: int, d: int, w: int, h: int) -> list:
    """Boxes (in cells of d x d source pixels) -> screen ops. A cell on the right
    or bottom edge may be partial, so extents are clipped to the real picture."""
    hexc: dict = {}

    def hx(c: int) -> str:
        v = hexc.get(c)
        if v is None:
            v = hexc[c] = "#%06x" % c
        return v

    ops: list = [["rect", x, y, w * scale, h * scale, hx(bg)]]
    for x0, x1, y0, y1, c in boxes:
        bx, by = x + x0 * d * scale, y + y0 * d * scale
        bw = min((x1 + 1) * d, w) * scale - x0 * d * scale
        bh = min((y1 + 1) * d, h) * scale - y0 * d * scale
        if bw == 1 or bh == 1:     # one screen pixel thin: a line, not a box
            ops.append(["line", bx, by, bx + bw - 1, by + bh - 1, hx(c)])
        else:
            ops.append(["rect", bx, by, bw, bh, hx(c)])
    return ops
