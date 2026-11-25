"""Draw like GPUI: describe a tree of elements, KOS lays it out and paints it.

Zed's GPUI builds a tree of styled elements every frame, lays it out with flexbox,
then paints it as a flat scene of primitives. This is the same shape for KOS::

    from kos.sdk import App, Canvas, div, text

    ui = (div().flex_col().size_full().bg("#101820").p(8).gap(4).children([
        text("Hello").scale(2).color("#ffffff"),
        div().flex_row().gap(4).children([
            div().id("ok").flex_1().p(4).bg("#2a6").rounded(3).child(text("OK")),
            div().id("no").flex_1().p(4).bg("#a33").rounded(3).child(text("NO")),
        ]),
    ]))
    canvas = Canvas()
    frame = canvas.paint(ui, 320, 200)     # layout + paint, ops appended
    app.present(canvas)
    frame.hit(x, y)                         # -> "ok", "no" or None  (for a click)

Three phases, like GPUI: *measure* (natural size of each element), *layout* (flexbox
gives each element a box) and *paint* (the boxes become ``rect``/``text`` ops).
The OS still only sees ``clear``/``rect``/``line``/``text``: no new wire op, so the
protocol checks, the frame budget and the trusted overlay are untouched. Whole numbers
only (the KOS no-decimals rule): sizes are pixels, ``//`` splits free space and the
remainder goes to the last element, so nothing is lost or invented.

Not here (the wire has no op for it): alpha, shadows, gradients, images, line wrap.
Colours are ``#rrggbb``.
"""

from __future__ import annotations

import re
from math import isqrt
from typing import Optional, Union

from . import font

MAX_DEPTH = 64          # a deeper tree is refused, not recursed into
MAX_NODES = 4000        # more elements than one frame can draw anyway
MAX_COORD = 16384       # same bound the protocol puts on every coordinate
MAX_TEXT_OP = 256       # the protocol's longest text op; longer runs are split
MAX_RADIUS = 64

_COLOR = re.compile(r"#[0-9a-fA-F]{6}\Z")


def _color(c: str) -> str:
    if not isinstance(c, str) or not _COLOR.match(c):
        raise ValueError(f"colour must be '#rrggbb', not {c!r}")
    return c.lower()


def _whole(v: int, lo: int = 0, hi: int = MAX_COORD, what: str = "size") -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise ValueError(f"{what} must be a whole number from {lo} to {hi}")
    return v


# --- elements --------------------------------------------------------------------------------


class Element:
    """Base of everything in the tree. Layout fills in ``bounds`` = (x, y, w, h)."""

    def __init__(self) -> None:
        self.bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
        self._id: Optional[str] = None
        self._w: Optional[int] = None
        self._h: Optional[int] = None
        self._fill_w = False
        self._fill_h = False
        self._grow = 0
        self._basis0 = False        # flex_1: ignore natural size, share the free space

    # sizing -- the same names GPUI uses
    def id(self, name: str):
        if not isinstance(name, str) or not 0 < len(name) <= 64:
            raise ValueError("id must be a name of 1 to 64 characters")
        self._id = name
        return self

    def w(self, n: int):
        self._w, self._fill_w = _whole(n, what="width"), False
        return self

    def h(self, n: int):
        self._h, self._fill_h = _whole(n, what="height"), False
        return self

    def size(self, w: int, h: int):
        return self.w(w).h(h)

    def w_full(self):
        self._w, self._fill_w = None, True
        return self

    def h_full(self):
        self._h, self._fill_h = None, True
        return self

    def size_full(self):
        return self.w_full().h_full()

    def flex_1(self):
        self._grow, self._basis0 = 1, True
        return self

    def flex_grow(self, n: int = 1):
        self._grow = _whole(n, 0, 1000, "grow")
        return self

    def _natural(self) -> tuple[int, int]:           # measure phase
        raise NotImplementedError


class Text(Element):
    def __init__(self, s: str) -> None:
        super().__init__()
        if not isinstance(s, str):
            raise ValueError("text must be a string")
        # control characters never reach the wire; keep line breaks, which are ours to split on
        self._s = "".join(ch if ch == "\n" or ch >= " " else "?" for ch in s)
        self._color = "#ffffff"
        self._scale = 1

    def color(self, c: str) -> "Text":
        self._color = _color(c)
        return self

    def scale(self, n: int) -> "Text":
        self._scale = _whole(n, 1, 8, "scale")
        return self

    def _natural(self) -> tuple[int, int]:
        lines = self._s.split("\n")
        w = max(len(l) for l in lines) * font.ADVANCE * self._scale
        return w, len(lines) * font.LINE_HEIGHT * self._scale


class Div(Element):
    """A flex box with a background, a border and rounded corners, like GPUI's ``div()``."""

    def __init__(self) -> None:
        super().__init__()
        self._dir = "row"
        self._gap = 0
        self._pad = [0, 0, 0, 0]            # left, top, right, bottom
        self._bg: Optional[str] = None
        self._bw = 0
        self._bc: Optional[str] = None
        self._radius = 0
        self._justify = "start"
        self._items = "stretch"
        self._clip = False
        self._kids: list[Element] = []

    # direction
    def flex(self):
        return self

    def flex_row(self):
        self._dir = "row"
        return self

    def flex_col(self):
        self._dir = "col"
        return self

    def gap(self, n: int):
        self._gap = _whole(n, what="gap")
        return self

    # padding
    def p(self, n: int):
        self._pad = [_whole(n, what="padding")] * 4
        return self

    def px(self, n: int):
        self._pad[0] = self._pad[2] = _whole(n, what="padding")
        return self

    def py(self, n: int):
        self._pad[1] = self._pad[3] = _whole(n, what="padding")
        return self

    def pl(self, n: int):
        self._pad[0] = _whole(n, what="padding")
        return self

    def pt(self, n: int):
        self._pad[1] = _whole(n, what="padding")
        return self

    def pr(self, n: int):
        self._pad[2] = _whole(n, what="padding")
        return self

    def pb(self, n: int):
        self._pad[3] = _whole(n, what="padding")
        return self

    # alignment
    def justify_start(self):
        self._justify = "start"
        return self

    def justify_center(self):
        self._justify = "center"
        return self

    def justify_end(self):
        self._justify = "end"
        return self

    def justify_between(self):
        self._justify = "between"
        return self

    def justify_around(self):
        self._justify = "around"
        return self

    def items_start(self):
        self._items = "start"
        return self

    def items_center(self):
        self._items = "center"
        return self

    def items_end(self):
        self._items = "end"
        return self

    def items_stretch(self):
        self._items = "stretch"
        return self

    # paint
    def bg(self, c: str):
        self._bg = _color(c)
        return self

    def border(self, width: int, c: str):
        self._bw, self._bc = _whole(width, 0, 16, "border"), _color(c)
        return self

    def rounded(self, r: int):
        self._radius = _whole(r, 0, MAX_RADIUS, "radius")
        return self

    def overflow_hidden(self):
        self._clip = True
        return self

    # children
    def child(self, el: Element):
        if not isinstance(el, Element):
            raise ValueError("a child must be div() or text()")
        self._kids.append(el)
        return self

    def children(self, els):
        for el in els:
            self.child(el)
        return self

    def _insets(self) -> tuple[int, int, int, int]:
        b = self._bw
        return self._pad[0] + b, self._pad[1] + b, self._pad[2] + b, self._pad[3] + b

    def _natural(self) -> tuple[int, int]:
        l, t, r, b = self._insets()
        sizes = [_nat(k) for k in self._kids]
        gaps = self._gap * max(0, len(sizes) - 1)
        if self._dir == "row":
            w = sum(s[0] for s in sizes) + gaps
            h = max((s[1] for s in sizes), default=0)
        else:
            w = max((s[0] for s in sizes), default=0)
            h = sum(s[1] for s in sizes) + gaps
        return l + r + w, t + b + h


def div() -> Div:
    return Div()


def text(s: str) -> Text:
    return Text(s)


def _nat(el: Element) -> tuple[int, int]:
    """Natural size with any explicit width/height applied (the measure phase)."""
    w, h = el._natural()
    return (el._w if el._w is not None else w), (el._h if el._h is not None else h)


# --- layout ----------------------------------------------------------------------------------


def _split(total: int, weights: list[int]) -> list[int]:
    """Divide ``total`` by weight in whole pixels; the remainder goes to the last non-zero weight,
    so the parts always add up to ``total`` exactly."""
    s = sum(weights)
    if s <= 0:
        return [0] * len(weights)
    parts = [total * w // s for w in weights]
    last = max(i for i, w in enumerate(weights) if w > 0)
    parts[last] += total - sum(parts)
    return parts


def _layout(el: Element, x: int, y: int, w: int, h: int, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError(f"the element tree is deeper than {MAX_DEPTH}")
    el.bounds = (x, y, max(0, w), max(0, h))
    if not isinstance(el, Div) or not el._kids:
        return
    l, t, r, b = el._insets()
    cx, cy = x + l, y + t
    cw, ch = max(0, w - l - r), max(0, h - t - b)
    row = el._dir == "row"
    main, cross = (cw, ch) if row else (ch, cw)
    kids = el._kids
    n = len(kids)

    nat = [_nat(k) for k in kids]
    basis, grow = [], []
    for k, (nw, nh) in zip(kids, nat):
        fill_main = k._fill_w if row else k._fill_h
        explicit_main = k._w if row else k._h
        g = k._grow or (1 if fill_main else 0)
        zero = k._basis0 or (fill_main and explicit_main is None)
        basis.append(0 if zero else (nw if row else nh))
        grow.append(g)

    gaps = el._gap * (n - 1)
    free = main - sum(basis) - gaps
    sizes = list(basis)
    lead, between = 0, el._gap
    if free > 0 and sum(grow) > 0:
        sizes = [s + e for s, e in zip(sizes, _split(free, grow))]
    elif free < 0:
        cut = _split(-free, [max(0, s) for s in basis])
        sizes = [max(0, s - c) for s, c in zip(sizes, cut)]
    elif free > 0:
        if el._justify == "center":
            lead = free // 2
        elif el._justify == "end":
            lead = free
        elif el._justify == "between" and n > 1:
            between = el._gap + free // (n - 1)
        elif el._justify == "around":
            unit = free // n
            lead, between = unit // 2, el._gap + unit

    pos = lead
    for k, size, (nw, nh) in zip(kids, sizes, nat):
        fill_cross = k._fill_h if row else k._fill_w
        explicit_cross = k._h if row else k._w
        nat_cross = nh if row else nw
        if explicit_cross is not None:
            csize = min(explicit_cross, cross)
        elif fill_cross or el._items == "stretch":
            csize = cross
        else:
            csize = min(nat_cross, cross)
        off = 0
        if el._items == "center":
            off = (cross - csize) // 2
        elif el._items == "end":
            off = cross - csize
        if row:
            _layout(k, cx + pos, cy + off, size, csize, depth + 1)
        else:
            _layout(k, cx + off, cy + pos, csize, size, depth + 1)
        pos += size + between


# --- paint -----------------------------------------------------------------------------------

Clip = tuple[int, int, int, int]        # x0, y0, x1, y1 (end exclusive)


def _rows(w: int, h: int, r: int) -> list[tuple[int, int]]:
    """For each row of a w x h rounded box: (left, right) of the filled span. Whole-number circle."""
    r = min(r, w // 2, h // 2)
    out = []
    for y in range(h):
        d = y if y < r else (h - 1 - y if y >= h - r else r)
        if d >= r:
            out.append((0, w))
            continue
        t = 2 * r - 2 * d - 1                       # twice the distance from the corner's centre row
        half = isqrt(4 * r * r - t * t) // 2        # whole pixels of the circle's half-width
        inset = r - half
        out.append((inset, w - inset))
    return out


class _Painter:
    def __init__(self, width: int, height: int, rounded: bool) -> None:
        self.ops: list[list] = []
        self.clips: list[Clip] = [(0, 0, width, height)]
        self.rounded = rounded
        self.ids: dict[str, Element] = {}
        self.order: list[tuple[Element, Clip]] = []

    def rect(self, x: int, y: int, w: int, h: int, color: str) -> None:
        cx0, cy0, cx1, cy1 = self.clips[-1]
        x0, y0, x1, y1 = max(x, cx0), max(y, cy0), min(x + w, cx1), min(y + h, cy1)
        if x0 < x1 and y0 < y1:
            self.ops.append(["rect", x0, y0, x1 - x0, y1 - y0, color])

    def spans(self, x: int, y: int, pieces: list[list[tuple[int, int]]], color: str) -> None:
        """Fill rows of spans, merging vertically identical neighbours into one rect each."""
        open_: dict[tuple[int, int], int] = {}
        for row, spans in enumerate(pieces + [[]]):
            now = set(spans)
            for key in [k for k in open_ if k not in now]:
                start = open_.pop(key)
                self.rect(x + key[0], y + start, key[1] - key[0], row - start, color)
            for key in now:
                open_.setdefault(key, row)

    def quad(self, x: int, y: int, w: int, h: int, bg: Optional[str], bw: int, bc: Optional[str], r: int) -> None:
        if w <= 0 or h <= 0:
            return
        r = r if self.rounded else 0
        outer = _rows(w, h, r)
        bw = min(bw, w // 2, h // 2)
        if bg and not bw:
            self.spans(x, y, [[s] for s in outer], bg)
            return
        if bg:                                          # the border sits over the fill
            self.spans(x, y, [[s] for s in outer], bg)
        if bw and bc:
            iw, ih = w - 2 * bw, h - 2 * bw
            inner = _rows(iw, ih, max(0, r - bw)) if iw > 0 and ih > 0 else []
            ring = []
            for row, (o0, o1) in enumerate(outer):
                ir = row - bw
                if 0 <= ir < len(inner):
                    i0, i1 = inner[ir][0] + bw, inner[ir][1] + bw
                    ring.append([s for s in ((o0, i0), (i1, o1)) if s[0] < s[1]])
                else:
                    ring.append([(o0, o1)])
            self.spans(x, y, ring, bc)

    def text(self, x: int, y: int, s: str, color: str, scale: int) -> None:
        cx0, cy0, cx1, cy1 = self.clips[-1]
        adv = font.ADVANCE * scale
        for n, line in enumerate(s.split("\n")):
            ly = y + n * font.LINE_HEIGHT * scale
            if ly < cy0 or ly + font.GLYPH_H * scale > cy1 or not line:
                continue
            first = max(0, -((x - cx0) // adv))              # first glyph whose left edge is inside
            last = min(len(line), (cx1 - x + (adv - font.GLYPH_W * scale)) // adv)
            for i in range(first, last, MAX_TEXT_OP):
                piece = line[i:min(i + MAX_TEXT_OP, last)]
                if piece.strip():
                    self.ops.append(["text", x + i * adv, ly, piece, color, scale])

    def paint(self, el: Element, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise ValueError(f"the element tree is deeper than {MAX_DEPTH}")
        if len(self.order) >= MAX_NODES:
            raise ValueError(f"more than {MAX_NODES} elements in one frame")
        self.order.append((el, self.clips[-1]))
        if el._id is not None:
            if el._id in self.ids:
                raise ValueError(f"two elements share the id {el._id!r}")
            self.ids[el._id] = el
        x, y, w, h = el.bounds
        if isinstance(el, Text):
            self.text(x, y, el._s, el._color, el._scale)
            return
        self.quad(x, y, w, h, el._bg, el._bw, el._bc, el._radius)
        if el._clip:
            cx0, cy0, cx1, cy1 = self.clips[-1]
            self.clips.append((max(cx0, x), max(cy0, y), min(cx1, x + w), min(cy1, y + h)))
        for k in el._kids:
            self.paint(k, depth + 1)
        if el._clip:
            self.clips.pop()


class Frame:
    """One laid-out, painted frame: the ops to send, plus where everything landed."""

    def __init__(self, root: Element, ops: list[list], ids: dict, order: list) -> None:
        self.root, self.ops, self._ids, self._order = root, ops, ids, order

    def bounds(self, id: str) -> Optional[tuple[int, int, int, int]]:
        el = self._ids.get(id)
        return el.bounds if el else None

    def hit(self, x: int, y: int) -> Optional[str]:
        """The id of the topmost element with an id under (x, y), or None (a click's target)."""
        for el, (cx0, cy0, cx1, cy1) in reversed(self._order):
            if el._id is None or not (cx0 <= x < cx1 and cy0 <= y < cy1):
                continue
            ex, ey, ew, eh = el.bounds
            if ex <= x < ex + ew and ey <= y < ey + eh:
                return el._id
        return None


def render(root: Element, width: int, height: int, room: Optional[int] = None) -> Frame:
    """Lay ``root`` out in a ``width`` x ``height`` window and paint it. ``room`` is how many ops may
    be used (default: a full frame). Too many and rounded corners are dropped first; still too many
    raises ValueError, so a frame is never silently cut."""
    if not isinstance(root, Element):
        raise ValueError("root must be div() or text()")
    _whole(width, 0, MAX_COORD, "width")
    _whole(height, 0, MAX_COORD, "height")
    if room is None:
        from .vectorize import MAX_OPS
        room = MAX_OPS
    _layout(root, 0, 0, width, height)
    for rounded in (True, False):
        p = _Painter(width, height, rounded)
        p.paint(root)
        if len(p.ops) <= room:
            return Frame(root, p.ops, p.ids, p.order)
    raise ValueError(f"the frame needs {len(p.ops)} ops and only {room} are left")
