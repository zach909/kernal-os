"""The load effect: how a picture arrives on screen, and how it stands up in 3D.

KOS draws only ``clear``, ``rect``, ``line`` and ``text`` (``protocol.py``), so everything here is
geometry made from those, on the app side (standard library only, whole numbers only, like
``kos.vectorize``). The OS core is unchanged and still validates every op.

**Arriving** (``Scene.frames``). For every *thing* in the picture (a connected patch of one colour):

1. *seed*: a point, at the middle of the thing.
2. *expand*: a rubber band grows out of the point until it is the thing's bounding box, the biggest
   room it will take up. With 3D on that box is seen in perspective at the thing's distance, so a nearer
   layer takes up more room: the band's size is how far away it is.
3. *vacuum*: the band shrinks inwards until it presses on every outer edge. That is the convex hull,
   the tightest rubber band round the thing.
4. *unblur*: the picture, blurred into the interface background all along, sharpens step by step until
   it is exact.

The band is the method, not something you see: it is not drawn (``frames(band_lines=True)`` draws it as an
outline to look at the method). What is drawn is the thing itself, a dim filled shape the size of the band.

Blur here is what the box drawer can do: cells of ``d`` x ``d`` source pixels averaged
(``vectorize(min_downscale=d)``), each mixed with the interface background colour. It is a blocky
blur, not a Gaussian.

**Standing up** (``Scene.render``; ``frames(three_d=True)`` arrives straight into it). Every thing gets a layer: a thing inside another thing's box is
one layer above it. Each layer is one ``layer_height`` higher. The picture is drawn in one-point
perspective: the vanishing point is the mouse, a raised thing is scaled out from it, and the walls
that face the vanishing point are filled in. A light direction (the sun) shades the walls and throws
each thing's shadow away from itself onto the ground.

Honest limits: a thing's walls are drawn only along its boundary, one row of 1-pixel ops per pixel of
wall, so a very busy picture falls back (walls first, then shadows, then lifting) to stay inside
the op budget; ``Rendered.note`` says which. Things beyond ``MAX_THINGS`` (the 48 biggest are kept)
and things too ragged to box stay flat. Shadows land on the ground only, never on other things.
There is no hidden-surface test between neighbours: raised things are painted lowest first.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any, Optional, Sequence

from . import vectorize as V

MAX_THINGS = 48
MAX_BOX_PIECES = 2000          # a thing needing more boxes than this is too ragged to stand up
MIX = 8                        # blur/background blend is in eighths
BAND_COLOR = "#ffd24a"
DEFAULT_LIGHT = (-1, -1)       # the sun is up and to the left; shadows fall down and right


# ---------------------------------------------------------------- colour (whole numbers only)

def _hex(c: int) -> str:
    return "#%06x" % c


def _split(c: int):
    return c >> 16, c >> 8 & 255, c & 255


def _join(r: int, g: int, b: int) -> int:
    return min(255, max(0, r)) << 16 | min(255, max(0, g)) << 8 | min(255, max(0, b))


def shade(c: int, pct: int) -> int:
    """Darken (pct < 100) or lighten (pct > 100, towards white) a colour. 100 is unchanged."""
    r, g, b = _split(c)
    if pct <= 100:
        pct = max(0, pct)
        return _join(r * pct // 100, g * pct // 100, b * pct // 100)
    k = min(100, pct - 100)
    return _join(r + (255 - r) * k // 100, g + (255 - g) * k // 100, b + (255 - b) * k // 100)


def mix(c: int, ui: int, m: int, d: int = MIX) -> int:
    """``m`` parts of ``c`` and ``d - m`` parts of ``ui``."""
    (r, g, b), (r2, g2, b2) = _split(c), _split(ui)
    return _join((r * m + r2 * (d - m)) // d, (g * m + g2 * (d - m)) // d, (b * m + b2 * (d - m)) // d)


# ---------------------------------------------------------------- geometry (whole numbers only)

def _cross(o, a, b) -> int:
    return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])


def hull(points) -> list:
    """Convex hull, counter-clockwise, no repeated or collinear points (Andrew's monotone chain)."""
    pts = sorted(set(points))
    if len(pts) <= 2:
        return pts
    lo: list = []
    for p in pts:
        while len(lo) >= 2 and _cross(lo[-2], lo[-1], p) <= 0:
            lo.pop()
        lo.append(p)
    up: list = []
    for p in reversed(pts):
        while len(up) >= 2 and _cross(up[-2], up[-1], p) <= 0:
            up.pop()
        up.append(p)
    return lo[:-1] + up[:-1]


def _ray_hit(poly: list, c, p):
    """Where the ray from the inside point ``c`` through ``p`` leaves the convex ``poly``."""
    dx, dy = p[0] - c[0], p[1] - c[1]
    n = len(poly)
    for i in range(n):
        a, b = poly[i], poly[(i + 1) % n]
        ex, ey = b[0] - a[0], b[1] - a[1]
        den = dx * ey - dy * ex
        if den == 0:
            continue
        acx, acy = a[0] - c[0], a[1] - c[1]
        s_num, u_num = acx * ey - acy * ex, acx * dy - acy * dx
        if den < 0:
            den, s_num, u_num = -den, -s_num, -u_num
        if s_num > 0 and 0 <= u_num <= den:
            return c[0] + dx * s_num // den, c[1] + dy * s_num // den
    return p


def _box_exit(c, p, box):
    """Where the ray from ``c`` through ``p`` leaves the box (x0, y0, x1, y1)."""
    dx, dy = p[0] - c[0], p[1] - c[1]
    best = None                                   # smallest positive t = num / den
    for d, lo, hi, o in ((dx, box[0], box[2], c[0]), (dy, box[1], box[3], c[1])):
        if d == 0:
            continue
        num, den = (hi - o, d) if d > 0 else (o - lo, -d)
        if best is None or num * best[1] < best[0] * den:
            best = (num, den)
    if best is None:
        return c
    return c[0] + dx * best[0] // best[1], c[1] + dy * best[0] // best[1]


def _by_angle(c):
    def key(a, b):
        ha = 0 if (a[1] > c[1] or (a[1] == c[1] and a[0] > c[0])) else 1
        hb = 0 if (b[1] > c[1] or (b[1] == c[1] and b[0] > c[0])) else 1
        if ha != hb:
            return ha - hb
        x = _cross(c, a, b)
        return -1 if x > 0 else 1 if x < 0 else 0
    return cmp_to_key(key)


def _lerp(a: int, b: int, t: int, d: int) -> int:
    return a + (b - a) * t // d


# ---------------------------------------------------------------- the things in a picture

@dataclass
class Thing:
    color: int
    bbox: tuple                # (x0, y0, x1, y1) in source pixels, inclusive
    hull: list                 # corners of source pixels, counter-clockwise
    center: tuple              # inside the hull
    pixels: frozenset
    boxes: Optional[list]      # [(x0, x1, y0, y1)] covering the thing exactly; None if too ragged
    layer: int = 0

    def __post_init__(self):
        self.edges: Optional[list] = None
        self.band: Optional[list] = None


def _components(grid: list, bg: int, limit: int) -> list:
    h, w = len(grid), len(grid[0])
    seen = bytearray(w * h)
    found = []
    for y in range(h):
        row = grid[y]
        for x in range(w):
            c = row[x]
            if c == bg or seen[y * w + x]:
                continue
            seen[y * w + x] = 1
            stack, pts = [(x, y)], []
            while stack:
                px, py = stack.pop()
                pts.append((px, py))
                for nx, ny in ((px + 1, py), (px - 1, py), (px, py + 1), (px, py - 1)):
                    if 0 <= nx < w and 0 <= ny < h and not seen[ny * w + nx] and grid[ny][nx] == c:
                        seen[ny * w + nx] = 1
                        stack.append((nx, ny))
            found.append((c, pts))
    found.sort(key=lambda t: (-len(t[1]), t[0], t[1][0]))
    return found[:limit]


def _make_thing(color: int, pts: list) -> Thing:
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    x0, y0, x1, y1 = min(xs), min(ys), max(xs), max(ys)
    span: dict = {}
    for px, py in pts:
        lo, hi = span.get(py, (px, px))
        span[py] = (min(lo, px), max(hi, px))
    corners = []
    for py, (lo, hi) in span.items():
        corners += [(lo, py), (hi + 1, py), (lo, py + 1), (hi + 1, py + 1)]
    hl = hull(corners)
    center = (sum(p[0] for p in hl) // len(hl), sum(p[1] for p in hl) // len(hl))
    sub = frozenset(pts)
    crop = [[color if (x, y) in sub else -1 for x in range(x0, x1 + 1)] for y in range(y0, y1 + 1)]
    raw = V._boxes(crop, -1, MAX_BOX_PIECES)
    boxes = None if raw is None else [(bx0 + x0, bx1 + x0, by0 + y0, by1 + y0) for bx0, bx1, by0, by1, _ in raw]
    return Thing(color, (x0, y0, x1, y1), hl, center, sub, boxes)


def _layers(things: list) -> None:
    """A thing whose box lies inside a bigger thing's box sits one layer above it."""
    for a in things:
        ax0, ay0, ax1, ay1 = a.bbox
        a.layer = sum(
            1 for b in things
            if b is not a and len(b.pixels) > len(a.pixels)
            and b.bbox[0] <= ax0 and b.bbox[1] <= ay0 and b.bbox[2] >= ax1 and b.bbox[3] >= ay1)


def _band(th: Thing) -> list:
    """(start, end) for every vertex of the shrinking band, in order round the thing. The start is
    on the bounding box, the end on the hull, both on the same ray from the thing's centre."""
    c = th.center
    x0, y0, x1, y1 = th.bbox[0], th.bbox[1], th.bbox[2] + 1, th.bbox[3] + 1
    pairs = [(_box_exit(c, v, (x0, y0, x1, y1)), v) for v in th.hull if v != c]
    for corner in ((x0, y0), (x1, y0), (x1, y1), (x0, y1)):
        pairs.append((corner, _ray_hit(th.hull, c, corner)))
    around = _by_angle(c)
    return sorted(pairs, key=lambda pr: around(pr[1]))


# ---------------------------------------------------------------- the owner's setting

SETTING_SPACE, SETTING_KEY = "load-effect", "effect"
DEFAULT_SETTING = {"on": False, "three_d": False, "light": DEFAULT_LIGHT, "ms": 40}


def parse_setting(raw: Any) -> dict:
    """The owner's choice, saved by the load-effect app as ``"ON 3D LX LY MS"`` (five whole numbers).
    Anything missing, malformed or out of range gives the default (off), never an error."""
    out = dict(DEFAULT_SETTING)
    if not isinstance(raw, str) or len(raw) > 64:
        return out
    parts = raw.split()
    if len(parts) != 5 or not all(p.lstrip("-").isdigit() and p.lstrip("-").isascii() for p in parts):
        return out
    on, three_d, lx, ly, ms = (int(p) for p in parts)
    if on in (0, 1) and three_d in (0, 1) and -9 <= lx <= 9 and -9 <= ly <= 9 and (lx, ly) != (0, 0) \
            and 10 <= ms <= 500:
        return {"on": bool(on), "three_d": bool(three_d), "light": (lx, ly), "ms": ms}
    return out


# ---------------------------------------------------------------- the scene

@dataclass
class Rendered:
    ops: list
    note: str = ""             # what was left out to fit the budget ("" = nothing)
    things: int = 0            # how many things stood up


def _int(v: Any, name: str, lo: int, hi: int) -> int:
    return V._int(v, name, lo, hi)


class Scene:
    """A picture with its things found, ready to arrive or to stand up.

    ``pixels`` are rows of '#rrggbb' or (r, g, b); (x, y) is the picture's top-left on screen and
    ``scale`` makes a source pixel a scale x scale square, as in ``vectorize``. ``ui_color`` is the
    interface background the picture is blurred into. ``layer_height`` is how many screen pixels each
    layer rises. ``light`` is the direction towards the sun as two whole numbers in -9..9, x to the
    right and y down: (-1, -1) is the top left.
    """

    def __init__(self, pixels: Sequence[Sequence[Any]], x: int = 0, y: int = 0, scale: int = 1,
                 ui_color: str = "#101820", layer_height: int = 8, light: tuple = DEFAULT_LIGHT,
                 max_things: int = MAX_THINGS):
        self.x = _int(x, "x", -V.MAX_COORD, V.MAX_COORD)
        self.y = _int(y, "y", -V.MAX_COORD, V.MAX_COORD)
        self.scale = _int(scale, "scale", 1, V.MAX_SCALE)
        self.layer_height = _int(layer_height, "layer_height", 1, 256)
        max_things = _int(max_things, "max_things", 1, MAX_THINGS)
        self.ui = V._pixel(ui_color)
        self.set_light(light)
        self.grid = V._grid(pixels)
        self.w, self.h = len(self.grid[0]), len(self.grid)
        if not (-V.MAX_COORD <= self.x and self.x + self.w * self.scale <= V.MAX_COORD
                and -V.MAX_COORD <= self.y and self.y + self.h * self.scale <= V.MAX_COORD):
            raise ValueError("the picture would reach outside the coordinate range")
        counts: dict = {}
        for row in self.grid:
            for c in row:
                counts[c] = counts.get(c, 0) + 1
        self.bg = max(counts, key=lambda c: (counts[c], -c))
        self.things = [_make_thing(c, pts) for c, pts in _components(self.grid, self.bg, max_things)]
        _layers(self.things)
        for th in self.things:
            th.band = _band(th)
        self._ground: Optional[list] = None

    def set_light(self, light: tuple) -> None:
        if (not isinstance(light, (tuple, list)) or len(light) != 2
                or any(type(v) is not int or not -9 <= v <= 9 for v in light) or light == (0, 0)
                or list(light) == [0, 0]):
            raise ValueError("light must be two whole numbers in -9..9, not both zero")
        self.light = (light[0], light[1])

    # --- screen coordinates
    def _sx(self, px: int) -> int:
        return self.x + px * self.scale

    def _sy(self, py: int) -> int:
        return self.y + py * self.scale

    def _clip(self, ops: list) -> list:
        """Every coordinate inside the range the protocol accepts."""
        lim = V.MAX_COORD
        out = []
        for op in ops:
            if op[0] == "rect":
                _, x, y, w, h, c = op
                x, y = max(-lim, min(lim, x)), max(-lim, min(lim, y))
                out.append(["rect", x, y, max(0, min(lim, w)), max(0, min(lim, h)), c])
            else:
                _, a, b, c2, d, c = op
                out.append(["line", *(max(-lim, min(lim, v)) for v in (a, b, c2, d)), c])
        return out

    # ------------------------------------------------------------ arriving
    def flat(self, max_ops: int = V.DEFAULT_BUDGET) -> V.Vectorized:
        """The picture as it is, no effect."""
        return V.from_grid(self.grid, self.x, self.y, self.scale, max_ops)

    def _blurred(self, d: int, m: int, max_ops: int) -> list:
        grid = self.grid if m >= MIX else [[mix(c, self.ui, m) for c in row] for row in self.grid]
        return V.from_grid(grid, self.x, self.y, self.scale, max_ops, d).ops

    def levels(self, count: int = 4) -> list:
        """[(blur, blend)] from the blurriest, mostly background, to exact. ``blur`` is the cell size
        in source pixels, ``blend`` is in eighths of the picture (the rest is interface background)."""
        count = _int(count, "levels", 2, 8)
        d = 1
        while d * 2 <= max(1, max(self.w, self.h) // 4):
            d *= 2
        sizes = []
        for _ in range(count - 1):
            sizes.append(d)
            d = max(1, d // 2)
        sizes.append(1)
        start = MIX // 4
        return [(s, start + (MIX - start) * i // (count - 1)) for i, s in enumerate(sizes)]

    def frames(self, steps: int = 6, levels: int = 4, max_ops: int = V.DEFAULT_BUDGET,
               vp: Optional[tuple] = None, three_d: bool = False, band_lines: bool = False) -> list:
        """The arrival as a list of frames; each is the ops for the picture's area, to draw after the
        app's own background. Every thing starts as a point, grows to the biggest box it will take up,
        tightens inwards to its outline, and the blur clears. The band that does the measuring is **not
        drawn** (``band_lines=True`` draws it as a yellow outline, for looking at the method): what you
        see is the thing itself, a filled blur the shape of the band, until it sharpens.

        With ``three_d`` every thing arrives at its own distance: the biggest box is its box in
        one-point perspective from ``vp`` (the mouse), so a nearer layer takes up more room, and the last
        frame is exactly ``render(vp)``. Without it the last frame is exactly ``flat()``."""
        steps = _int(steps, "steps", 1, 60)
        max_ops = _int(max_ops, "max_ops", 1, V.MAX_OPS)
        lv = self.levels(levels)
        vp = self._vp(vp)
        three_d = bool(three_d)
        heights = self._heights((1, 1) if three_d else (0, 1))
        top = max(heights.values(), default=0)
        lift = self._lifter(vp, top)
        moving = [th for th in self.things if not three_d or th.boxes is not None]
        erase = {id(th) for th in moving}
        d0, m0 = lv[0]
        pre = [self._clear(top)] if top else []
        ground = self._ground_at(d0, m0, erase, max(1, max_ops - len(pre)))
        colour = {id(th): _hex(mix(th.color, self.ui, m0)) for th in moving}

        def band(phase: int, t: int) -> list:
            groups = []
            for th in moving:
                z = heights.get(id(th), 0)
                groups.append((len(th.pixels), (z, -len(th.pixels)),
                               self._silhouette(th, phase, t, steps, lift, z, colour[id(th)], band_lines)))
            return self._clip(self._fit(pre + ground, groups, max_ops))

        out = [band(0, 1)]                                                   # the seed: a point
        out += [band(1, t) for t in range(1, steps + 1)]                     # out to the biggest box
        out += [band(2, t) for t in range(1, steps + 1)]                     # in to the outline
        for d, m in lv[1:-1]:                                                # the unblur
            out.append(self._stand_blurred(moving, heights, top, lift, d, m, erase, max_ops)
                       if three_d else self._blurred(d, m, max_ops))
        out.append(self.render(vp, (1, 1), max_ops).ops if three_d else self.flat(max_ops).ops)
        return out

    def _vp(self, vp: Optional[tuple]) -> tuple:
        if vp is None:
            return (self._sx(self.w // 2), self._sy(self.h // 2))
        if (not isinstance(vp, (tuple, list)) or len(vp) != 2
                or any(type(v) is not int or not -V.MAX_COORD <= v <= V.MAX_COORD for v in vp)):
            raise ValueError("vp must be two whole screen coordinates")
        return (vp[0], vp[1])

    def _lifter(self, vp: tuple, top: int, distance: Optional[int] = None):
        """lift(px, py, z): where source corner (px, py), raised z screen pixels, lands on screen when seen
        in one-point perspective from ``vp``. z = 0 is the picture plane and does not move."""
        vx, vy = vp
        dist = max(4 * max(self.w, self.h) * self.scale, 4 * top) if distance is None else _int(
            distance, "distance", 4 * top, 1 << 20)

        def lift(px: int, py: int, z: int):
            return (vx + (self._sx(px) - vx) * dist // (dist - z), vy + (self._sy(py) - vy) * dist // (dist - z))
        return lift

    def _clear(self, top: int) -> list:
        """The interface colour over the picture and the room a raised, shadowed picture can reach."""
        lx, ly = self.light
        pad = max(top * 4, 8) + abs(max(lx, ly, key=abs)) * top
        return ["rect", self.x - pad, self.y - pad, self.w * self.scale + 2 * pad,
                self.h * self.scale + 2 * pad, _hex(self.ui)]

    def _fit(self, base: list, groups: list, max_ops: int) -> list:
        """``base`` plus as many groups of ops as fit, the biggest things first, drawn lowest layer first.
        A group is (size, draw order, ops)."""
        room = max_ops - len(base)
        keep = []
        for g in sorted(groups, key=lambda g: -g[0]):
            if len(g[2]) <= room:
                room -= len(g[2])
                keep.append(g)
        ops = list(base)
        for g in sorted(keep, key=lambda g: g[1]):
            ops += g[2]
        return ops

    def _ground_at(self, d: int, m: int, erase: set, max_ops: int) -> list:
        """The picture without the things in ``erase`` (they are drawn on top), blurred to cells of ``d``
        and mixed ``m`` parts in ``MIX`` with the interface colour."""
        grid = [row[:] for row in self.grid]
        for th in self.things:
            if id(th) in erase:
                for px, py in th.pixels:
                    grid[py][px] = self.bg
        if m < MIX:
            grid = [[mix(c, self.ui, m) for c in row] for row in grid]
        return V.from_grid(grid, self.x, self.y, self.scale, max(1, max_ops), d).ops

    def _coarse(self, th: Thing, d: int) -> list:
        """The thing's boxes seen through blur cells of ``d`` x ``d`` pixels: a cell is in if at least half of it
        is the thing. ``d`` = 1 is the exact boxes. A small thing can blur away; that is the blur."""
        if d == 1:
            return th.boxes
        cache = th.__dict__.setdefault("_coarse_cache", {})
        if d not in cache:
            counts: dict = {}
            for px, py in th.pixels:
                k = (px // d, py // d)
                counts[k] = counts.get(k, 0) + 1
            x0, y0, x1, y1 = th.bbox
            cx0, cy0 = x0 // d, y0 // d

            def inside(cx: int, cy: int) -> int:
                area = (min((cx + 1) * d, self.w) - cx * d) * (min((cy + 1) * d, self.h) - cy * d)
                return th.color if counts.get((cx, cy), 0) * 2 >= area else -1
            grid = [[inside(cx, cy) for cx in range(cx0, x1 // d + 1)] for cy in range(cy0, y1 // d + 1)]
            raw = V._boxes(grid, -1, MAX_BOX_PIECES)
            cache[d] = th.boxes if raw is None else [
                (max(0, (bx0 + cx0) * d), min(self.w - 1, (bx1 + cx0 + 1) * d - 1),
                 max(0, (by0 + cy0) * d), min(self.h - 1, (by1 + cy0 + 1) * d - 1)) for bx0, bx1, by0, by1, _ in raw]
        return cache[d]

    def _stand_blurred(self, moving: list, heights: dict, top: int, lift, d: int, m: int, erase: set,
                       max_ops: int) -> list:
        """One unblur step of the 3D picture: every thing at its own distance, its top face blurred to
        cells of ``d`` and mixed with the interface colour. Walls and shadows arrive with the last step."""
        pre = [self._clear(top)]
        ground = self._ground_at(d, m, erase, max(1, max_ops - 1))
        groups = []
        for th in moving:
            z = heights[id(th)]
            colour = _hex(mix(shade(th.color, 100 + 5 * (th.layer + 1)), self.ui, m))
            ops = []
            for x0, x1, y0, y1 in self._coarse(th, d):
                ax, ay = lift(x0, y0, z)
                bx, by = lift(x1 + 1, y1 + 1, z)
                ops.append(["rect", ax, ay, max(1, bx - ax), max(1, by - ay), colour])
            groups.append((len(th.pixels), (z, -len(th.pixels)), ops))
        return self._clip(self._fit(pre + ground, groups, max_ops))

    def _silhouette(self, th: Thing, phase: int, t: int, steps: int, lift, z: int, colour: str, lines: bool) -> list:
        """The thing during the measuring: a point (phase 0), the box it is growing to (phase 1, ``t`` of
        ``steps``), then the band shrinking from that box to the hull (phase 2), filled in ``colour``."""
        sx, sy = lift(th.center[0], th.center[1], z)
        if phase == 0:
            return [["rect", sx - 1, sy - 1, 3, 3, colour]]
        if phase == 1:
            ax, ay = lift(th.bbox[0], th.bbox[1], z)
            bx, by = lift(th.bbox[2] + 1, th.bbox[3] + 1, z)
            ax, bx, ay, by = _lerp(sx, ax, t, steps), _lerp(sx, bx, t, steps), _lerp(sy, ay, t, steps), _lerp(sy, by, t, steps)
            poly = [(ax, ay), (bx, ay), (bx, by), (ax, by)]
            ops = [["rect", ax, ay, max(1, bx - ax), max(1, by - ay), colour]]
        else:
            poly = []
            for a, b in th.band:
                (x0, y0), (x1, y1) = lift(a[0], a[1], z), lift(b[0], b[1], z)
                poly.append((_lerp(x0, x1, t, steps), _lerp(y0, y1, t, steps)))
            ops = self._fill(poly, colour)
        if lines:
            ops += [["line", *poly[i], *poly[(i + 1) % len(poly)], BAND_COLOR] for i in range(len(poly))]
        return ops

    def _fill(self, poly: list, colour: str) -> list:
        """Fill a polygon with rows one source pixel tall (even-odd, so a star-shaped band is fine)."""
        lo, hi = min(p[1] for p in poly), max(p[1] for p in poly)
        step, n, out = self.scale, len(poly), []
        for y in range(lo, hi, step):
            yy = y + step // 2
            xs = []
            for i in range(n):
                (x0, y0), (x1, y1) = poly[i], poly[(i + 1) % n]
                if y0 != y1 and min(y0, y1) <= yy < max(y0, y1):
                    xs.append(x0 + (x1 - x0) * (yy - y0) // (y1 - y0))
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                if xs[i + 1] > xs[i]:
                    out.append(["rect", xs[i], y, xs[i + 1] - xs[i], min(step, hi - y), colour])
        return out

    # ------------------------------------------------------------ standing up
    def _heights(self, grow: tuple):
        num, den = grow
        return {id(th): (th.layer + 1) * self.layer_height * self.scale * num // den
                for th in self.things if th.boxes is not None}

    def _ground_ops(self, max_ops: int) -> list:
        """The picture with every standing thing taken out (it is drawn again, lifted)."""
        if self._ground is None:
            grid = [row[:] for row in self.grid]
            for th in self.things:
                if th.boxes is not None:
                    for px, py in th.pixels:
                        grid[py][px] = self.bg
            self._ground = V.from_grid(grid, self.x, self.y, self.scale, max(1, max_ops)).ops
        return self._ground

    def _edges(self, th: Thing) -> list:
        """Exposed wall segments: (nx, ny, fixed, a, b) in corner coordinates; (nx, ny) is the outward
        normal, ``fixed`` the y of a horizontal run or x of a vertical one, a..b the extent."""
        if th.edges is not None:
            return th.edges
        px = th.pixels
        out = []

        def runs(coords, outside):
            start = prev = None
            for v in coords:
                if outside(v):
                    if start is None:
                        start = v
                    prev = v
                elif start is not None:
                    yield start, prev + 1
                    start = None
            if start is not None:
                yield start, prev + 1

        for x0, x1, y0, y1 in th.boxes:
            for a, b in runs(range(x0, x1 + 1), lambda x: (x, y0 - 1) not in px):
                out.append((0, -1, y0, a, b))
            for a, b in runs(range(x0, x1 + 1), lambda x: (x, y1 + 1) not in px):
                out.append((0, 1, y1 + 1, a, b))
            for a, b in runs(range(y0, y1 + 1), lambda y: (x0 - 1, y) not in px):
                out.append((-1, 0, x0, a, b))
            for a, b in runs(range(y0, y1 + 1), lambda y: (x1 + 1, y) not in px):
                out.append((1, 0, x1 + 1, a, b))
        th.edges = out
        return out

    def render(self, vp: Optional[tuple] = None, rise: tuple = (1, 1), max_ops: int = V.DEFAULT_BUDGET,
               distance: Optional[int] = None) -> Rendered:
        """The picture standing up, seen in one-point perspective with ``vp`` (screen x, y; the mouse)
        as the vanishing point. ``rise`` is how far up the layers are, as (n, d): (0, 1) is flat, (1, 1) is
        full height, so a caller can animate the rise. ``distance`` is how far the viewer is from the
        picture in screen pixels (default 4x the picture's size)."""
        max_ops = _int(max_ops, "max_ops", 1, V.MAX_OPS)
        if (not isinstance(rise, (tuple, list)) or len(rise) != 2 or type(rise[0]) is not int
                or type(rise[1]) is not int or rise[1] < 1 or not 0 <= rise[0] <= rise[1]):
            raise ValueError("rise must be (n, d) with 0 <= n <= d")
        vp = self._vp(vp)
        vx, vy = vp
        heights = self._heights(rise)
        top = max(heights.values(), default=0)
        if top == 0:
            return Rendered(self.flat(max_ops).ops, "" if not self.things else "flat", 0)
        lift = self._lifter(vp, top, distance)

        lx, ly = self.light
        m = max(abs(lx), abs(ly))
        shadow_col = _hex(shade(self.bg, 55))
        order = sorted((th for th in self.things if id(th) in heights),
                       key=lambda th: (heights[id(th)], -len(th.pixels)))

        shadows, bodies = [], []
        for th in order:
            z = heights[id(th)]
            ox, oy = -lx * z // m, -ly * z // m
            for x0, x1, y0, y1 in th.boxes:
                shadows.append(["rect", self._sx(x0) + ox, self._sy(y0) + oy,
                                (x1 - x0 + 1) * self.scale, (y1 - y0 + 1) * self.scale, shadow_col])
            walls, tops = [], []
            for nx, ny, fixed, a, b in self._edges(th):
                if nx == 0:
                    gx, gy = (self._sx(a) + self._sx(b)) // 2, self._sy(fixed)
                else:
                    gx, gy = self._sx(fixed), (self._sy(a) + self._sy(b)) // 2
                if (vx - gx) * nx + (vy - gy) * ny <= 0:
                    continue                            # faces away from the vanishing point
                walls += self._wall(th, nx, ny, fixed, a, b, z, lift)
            for x0, x1, y0, y1 in th.boxes:
                ax, ay = lift(x0, y0, z)
                bx, by = lift(x1 + 1, y1 + 1, z)
                tops.append(["rect", ax, ay, max(1, bx - ax), max(1, by - ay),
                             _hex(shade(th.color, 100 + 5 * (th.layer + 1)))])
            bodies.append((walls, tops))

        ground = self._ground_ops(max_ops)
        clear = self._clear(top)
        walls_all = [op for w, _ in bodies for op in w]
        tops_all = [op for _, t in bodies for op in t]
        sections = (("", True, True), ("walls left out", False, True), ("walls and shadows left out", False, False))
        for note, with_walls, with_shadows in sections:
            ops = [clear, *ground]
            if with_shadows:
                ops += shadows
            if with_walls:
                for walls, tops in bodies:
                    ops += walls + tops                 # lowest first: each thing covers the one below
            else:
                ops += tops_all
            if len(ops) <= max_ops:
                return Rendered(self._clip(ops), note, len(order))
        return Rendered(self.flat(max_ops).ops, "too busy to lift; drawn flat", 0)

    def _wall(self, th, nx, ny, fixed, a, b, z, lift) -> list:
        """One wall: the strip between the ground edge and the lifted edge, one 1-pixel op per row
        (or column), shaded by how much it faces the sun."""
        lx, ly = self.light
        facing = nx * lx + ny * ly                      # -m .. m for a unit normal
        pct = 70 + 30 * facing // max(1, abs(lx) + abs(ly))
        color = _hex(shade(th.color, pct))
        if nx == 0:
            g0, g1 = (self._sx(a), self._sy(fixed)), (self._sx(b), self._sy(fixed))
            t0, t1 = lift(a, fixed, z), lift(b, fixed, z)
            span = t0[1] - g0[1]
            if span == 0:
                return []
            step = 1 if span > 0 else -1
            return [["rect", min(xl, xr), r, max(1, abs(xr - xl)), 1, color]
                    for r in range(g0[1], t0[1] + step, step)
                    for xl, xr in [(_lerp(g0[0], t0[0], r - g0[1], span), _lerp(g1[0], t1[0], r - g0[1], span))]]
        g0, g1 = (self._sx(fixed), self._sy(a)), (self._sx(fixed), self._sy(b))
        t0, t1 = lift(fixed, a, z), lift(fixed, b, z)
        span = t0[0] - g0[0]
        if span == 0:
            return []
        step = 1 if span > 0 else -1
        return [["rect", r, min(yt, yb), 1, max(1, abs(yb - yt)), color]
                for r in range(g0[0], t0[0] + step, step)
                for yt, yb in [(_lerp(g0[1], t0[1], r - g0[0], span), _lerp(g1[1], t1[1], r - g0[0], span))]]

    def rise_frames(self, vp: Optional[tuple] = None, steps: int = 5, max_ops: int = V.DEFAULT_BUDGET) -> list:
        """The layers lifting up from flat to full height; the last frame is ``render(vp)``."""
        steps = _int(steps, "steps", 1, 60)
        return [self.render(vp, (t, steps), max_ops).ops for t in range(1, steps + 1)]
