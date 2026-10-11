"""Anti-aliased TrueType text, in plain Python (standard library only).

KOS's built-in pixel font is capitals only. The modern desktop wants real type:
lowercase, proportional spacing, smooth edges. So the OS rasterizes TrueType
(``glyf`` outlines) itself: parse the font, flatten the quadratic curves, and
compute each pixel's *exact* coverage by accumulating signed area (the method
font-rs and stb_truetype use), then blend that coverage into the framebuffer.

Apps never see a font file (their sandbox cannot read one). They send
``["stext", x, y, text, color, size, bold]`` and the OS draws it. To lay text
out they need widths, so the ``hello`` message carries the font's advance table
(:meth:`Font.metrics`), and the SDKs measure strings from it.

Glyph bitmaps are cached per (font, glyph, size). Limits, honestly: no kerning,
no hinting, no OpenType (CFF) outlines - ``.otf`` files are skipped in favour of
a TrueType face. Overlapping contours are clamped, which is right for the usual
sans-serif faces.
"""

from __future__ import annotations

import math
import os
import struct
from dataclasses import dataclass
from typing import Optional


class FontError(Exception):
    pass


@dataclass
class Bitmap:
    w: int
    h: int
    left: int           # pixels from the pen position to the bitmap's left edge
    top: int            # pixels from the baseline UP to the bitmap's top edge
    cov: bytes          # w*h coverage 0..255


class Font:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        self.path = path
        d = self.data
        if d[:4] not in (b"\x00\x01\x00\x00", b"true"):
            raise FontError(f"{path}: not a TrueType (glyf) font")
        n = struct.unpack_from(">H", d, 4)[0]
        self.tables = {}
        for i in range(n):
            tag, _, off, ln = struct.unpack_from(">4sIII", d, 12 + 16 * i)
            self.tables[tag.decode("latin1")] = (off, ln)
        for need in ("head", "maxp", "hhea", "hmtx", "cmap", "loca", "glyf"):
            if need not in self.tables:
                raise FontError(f"{path}: missing {need} table")
        head = self.tables["head"][0]
        self.upm = struct.unpack_from(">H", d, head + 18)[0]
        self.loca_long = struct.unpack_from(">h", d, head + 50)[0] == 1
        self.num_glyphs = struct.unpack_from(">H", d, self.tables["maxp"][0] + 4)[0]
        hhea = self.tables["hhea"][0]
        self.ascent, self.descent = struct.unpack_from(">hh", d, hhea + 4)
        self.num_hm = struct.unpack_from(">H", d, hhea + 34)[0]
        self._cmap = self._read_cmap()
        self._adv_cache: dict[int, int] = {}
        self._outline_cache: dict[int, list] = {}
        self._bitmaps: dict[tuple, Optional[Bitmap]] = {}

    # ----------------------------------------------------------------- tables
    def _read_cmap(self) -> dict[int, int]:
        d, off = self.data, self.tables["cmap"][0]
        n = struct.unpack_from(">H", d, off + 2)[0]
        best = None
        for i in range(n):
            plat, enc, sub = struct.unpack_from(">HHI", d, off + 4 + 8 * i)
            if (plat, enc) in ((3, 10), (0, 4), (0, 6)) or (plat, enc) == (3, 1) or plat == 0:
                fmt = struct.unpack_from(">H", d, off + sub)[0]
                if fmt in (4, 12) and (best is None or fmt == 12 or best[2] != 12):
                    best = (plat, enc, fmt, off + sub)
        if best is None:
            raise FontError("no usable Unicode cmap")
        fmt, pos, out = best[2], best[3], {}
        if fmt == 4:
            segx2 = struct.unpack_from(">H", d, pos + 6)[0]
            seg = segx2 // 2
            ends = struct.unpack_from(f">{seg}H", d, pos + 14)
            starts = struct.unpack_from(f">{seg}H", d, pos + 16 + segx2)
            deltas = struct.unpack_from(f">{seg}h", d, pos + 16 + 2 * segx2)
            range_pos = pos + 16 + 3 * segx2
            offsets = struct.unpack_from(f">{seg}H", d, range_pos)
            for s in range(seg):
                for c in range(starts[s], ends[s] + 1):
                    if c == 0xFFFF:
                        continue
                    if offsets[s] == 0:
                        g = (c + deltas[s]) & 0xFFFF
                    else:
                        gp = range_pos + 2 * s + offsets[s] + 2 * (c - starts[s])
                        if gp + 2 > len(d):
                            continue
                        g = struct.unpack_from(">H", d, gp)[0]
                        g = (g + deltas[s]) & 0xFFFF if g else 0
                    if g:
                        out[c] = g
        else:
            groups = struct.unpack_from(">I", d, pos + 12)[0]
            for i in range(groups):
                s, e, g = struct.unpack_from(">III", d, pos + 16 + 12 * i)
                if e - s > 0x10000:
                    continue
                for c in range(s, e + 1):
                    out[c] = g + (c - s)
        return out

    def glyph_id(self, ch: str) -> int:
        return self._cmap.get(ord(ch), 0)

    def advance_units(self, gid: int) -> int:
        a = self._adv_cache.get(gid)
        if a is None:
            off = self.tables["hmtx"][0]
            i = gid if gid < self.num_hm else self.num_hm - 1
            a = struct.unpack_from(">H", self.data, off + 4 * i)[0]
            self._adv_cache[gid] = a
        return a

    def _glyph_span(self, gid: int) -> tuple[int, int]:
        d, off = self.data, self.tables["loca"][0]
        if self.loca_long:
            a, b = struct.unpack_from(">II", d, off + 4 * gid)
        else:
            a, b = (x * 2 for x in struct.unpack_from(">HH", d, off + 2 * gid))
        return a, b

    # --------------------------------------------------------------- outlines
    def outline(self, gid: int, depth: int = 0) -> list[list[tuple[float, float, bool]]]:
        """Contours of (x, y, on_curve) in font units."""
        if gid in self._outline_cache:
            return self._outline_cache[gid]
        if gid >= self.num_glyphs or depth > 6:
            return []
        a, b = self._glyph_span(gid)
        if a == b:
            self._outline_cache[gid] = []
            return []
        d, pos = self.data, self.tables["glyf"][0] + a
        n = struct.unpack_from(">h", d, pos)[0]
        pos += 10
        contours: list = []
        if n >= 0:
            ends = struct.unpack_from(f">{n}H", d, pos)
            pos += 2 * n
            ilen = struct.unpack_from(">H", d, pos)[0]
            pos += 2 + ilen
            count = (ends[-1] + 1) if n else 0
            flags: list[int] = []
            while len(flags) < count:
                f = d[pos]
                pos += 1
                flags.append(f)
                if f & 8:
                    r = d[pos]
                    pos += 1
                    flags.extend([f] * r)
            xs, ys, v = [], [], 0
            for f in flags[:count]:
                if f & 2:
                    dx = d[pos]
                    pos += 1
                    v += dx if f & 16 else -dx
                elif not f & 16:
                    v += struct.unpack_from(">h", d, pos)[0]
                    pos += 2
                xs.append(v)
            v = 0
            for f in flags[:count]:
                if f & 4:
                    dy = d[pos]
                    pos += 1
                    v += dy if f & 32 else -dy
                elif not f & 32:
                    v += struct.unpack_from(">h", d, pos)[0]
                    pos += 2
                ys.append(v)
            start = 0
            for e in ends:
                contours.append([(xs[i], ys[i], bool(flags[i] & 1)) for i in range(start, e + 1)])
                start = e + 1
        else:
            while True:
                fl, sub = struct.unpack_from(">HH", d, pos)
                pos += 4
                if fl & 1:
                    dx, dy = struct.unpack_from(">hh", d, pos)
                    pos += 4
                else:
                    dx, dy = struct.unpack_from(">bb", d, pos)
                    pos += 2
                if not fl & 2:
                    dx = dy = 0                               # point-matching placement: not supported
                m = [1.0, 0.0, 0.0, 1.0]
                if fl & 8:
                    m[0] = m[3] = struct.unpack_from(">h", d, pos)[0] / 16384
                    pos += 2
                elif fl & 0x40:
                    m[0], m[3] = (x / 16384 for x in struct.unpack_from(">hh", d, pos))
                    pos += 4
                elif fl & 0x80:
                    m[0], m[1], m[2], m[3] = (x / 16384 for x in struct.unpack_from(">hhhh", d, pos))
                    pos += 8
                for c in self.outline(sub, depth + 1):
                    contours.append([(x * m[0] + y * m[2] + dx, x * m[1] + y * m[3] + dy, on) for x, y, on in c])
                if not fl & 0x20:
                    break
        self._outline_cache[gid] = contours
        return contours

    @staticmethod
    def _flatten(contour, scale: float):
        """Contour -> polyline points in pixels (y flipped to point down)."""
        pts = contour
        if len(pts) < 2:
            return []
        # rotate so we start on an on-curve point (insert an implied one if there is none)
        first = next((i for i, p in enumerate(pts) if p[2]), None)
        if first is None:
            mx, my = (pts[0][0] + pts[-1][0]) / 2, (pts[0][1] + pts[-1][1]) / 2
            pts = [(mx, my, True)] + pts
            first = 0
        pts = pts[first:] + pts[:first]
        out = [(pts[0][0] * scale, -pts[0][1] * scale)]
        i, n = 1, len(pts)
        cur = pts[0]
        while i <= n:
            p = pts[i % n]
            if p[2]:
                out.append((p[0] * scale, -p[1] * scale))
                cur = p
                i += 1
                continue
            nxt = pts[(i + 1) % n]
            end = nxt if nxt[2] else ((p[0] + nxt[0]) / 2, (p[1] + nxt[1]) / 2, True)
            steps = max(2, min(10, int(math.hypot(end[0] - cur[0], end[1] - cur[1]) * scale / 2) + 2))
            for s in range(1, steps + 1):
                t = s / steps
                x = (1 - t) ** 2 * cur[0] + 2 * (1 - t) * t * p[0] + t * t * end[0]
                y = (1 - t) ** 2 * cur[1] + 2 * (1 - t) * t * p[1] + t * t * end[1]
                out.append((x * scale, -y * scale))
            cur = end
            i += 2 if nxt[2] else 1
        return out

    # ------------------------------------------------------------ rasterizing
    def bitmap(self, ch: str, px: int) -> Optional[Bitmap]:
        gid = self.glyph_id(ch)
        key = (gid, px)
        if key in self._bitmaps:
            return self._bitmaps[key]
        contours = self.outline(gid)
        if not contours:
            self._bitmaps[key] = None
            return None
        scale = px / self.upm
        polys = [self._flatten(c, scale) for c in contours]
        xs = [x for p in polys for x, _ in p]
        ys = [y for p in polys for _, y in p]
        if not xs:
            self._bitmaps[key] = None
            return None
        left, top = math.floor(min(xs)) - 1, math.floor(min(ys)) - 1
        w, h = math.ceil(max(xs)) - left + 2, math.ceil(max(ys)) - top + 2
        if w <= 0 or h <= 0 or w * h > 400_000:
            self._bitmaps[key] = None
            return None
        acc = [0.0] * (w * h + 2)
        for poly in polys:
            for i in range(len(poly)):
                (x0, y0), (x1, y1) = poly[i], poly[(i + 1) % len(poly)]
                _accumulate(acc, w, h, x0 - left, y0 - top, x1 - left, y1 - top)
        cov = bytearray(w * h)
        for y in range(h):
            run, row = 0.0, y * w
            for x in range(w):
                run += acc[row + x]
                v = abs(run)
                cov[row + x] = 255 if v >= 1.0 else int(v * 255 + 0.5)
        bm = Bitmap(w, h, left, -top, bytes(cov))
        self._bitmaps[key] = bm
        return bm

    # ---------------------------------------------------------------- drawing
    def advance(self, ch: str, px: float) -> float:
        return self.advance_units(self.glyph_id(ch)) * px / self.upm

    def width(self, text: str, px: float) -> float:
        return sum(self.advance(c, px) for c in text)

    def baseline(self, px: int) -> int:
        return round(self.ascent * px / self.upm)

    def line_height(self, px: int) -> int:
        return round((self.ascent - self.descent) * px / self.upm)

    def draw(self, fb, x: int, y: int, text: str, rgb: tuple[int, int, int], px: int) -> None:
        """Draw ``text`` with its line box's top-left at (x, y)."""
        pen, base = float(x), y + self.baseline(px)
        r, g, b = rgb
        stride, buf, W, H = fb.width * 4, fb.buf, fb.width, fb.height
        for ch in text:
            bm = self.bitmap(ch, px)
            if bm:
                gx, gy = int(pen) + bm.left, base - bm.top
                cov = bm.cov
                for row in range(bm.h):
                    py = gy + row
                    if not 0 <= py < H:
                        continue
                    for col in range(bm.w):
                        a = cov[row * bm.w + col]
                        if not a:
                            continue
                        pxx = gx + col
                        if not 0 <= pxx < W:
                            continue
                        i = py * stride + pxx * 4
                        if a == 255:
                            buf[i], buf[i + 1], buf[i + 2] = b, g, r
                        else:
                            buf[i] += ((b - buf[i]) * a + 127) // 255
                            buf[i + 1] += ((g - buf[i + 1]) * a + 127) // 255
                            buf[i + 2] += ((r - buf[i + 2]) * a + 127) // 255
            pen += self.advance(ch, px)

    def metrics(self) -> dict:
        """What an app needs to lay text out: advance of printable ASCII, in 1/1000 em."""
        return {"adv": [round(self.advance(chr(c), 1000)) for c in range(32, 127)],
                "asc": round(self.ascent * 1000 / self.upm), "desc": round(-self.descent * 1000 / self.upm)}


def _accumulate(a: list, w: int, h: int, x0: float, y0: float, x1: float, y1: float) -> None:
    """Add one edge's signed area/cover to the accumulation buffer (exact coverage)."""
    if y0 == y1:
        return
    direction = 1.0
    if y0 > y1:
        x0, y0, x1, y1, direction = x1, y1, x0, y0, -1.0
    dxdy = (x1 - x0) / (y1 - y0)
    x = x0
    if y0 < 0:
        x -= y0 * dxdy
    for y in range(max(0, int(y0)), min(h, math.ceil(y1))):
        dy = min(y + 1.0, y1) - max(float(y), y0)
        xn = x + dxdy * dy
        d = dy * direction
        lo, hi = (x, xn) if x < xn else (xn, x)
        lo_f = math.floor(lo)
        lo_i = int(lo_f)
        hi_c = math.ceil(hi)
        hi_i = int(hi_c)
        row = y * w
        if hi_i <= lo_i + 1:
            mid = 0.5 * (x + xn) - lo_f
            a[row + lo_i] += d - d * mid
            a[row + lo_i + 1] += d * mid
        else:
            s = 1.0 / (hi - lo)
            lf = lo - lo_f
            a0 = 0.5 * s * (1.0 - lf) ** 2
            hf = hi - hi_c + 1.0
            am = 0.5 * s * hf * hf
            a[row + lo_i] += d * a0
            if hi_i == lo_i + 2:
                a[row + lo_i + 1] += d * (1.0 - a0 - am)
            else:
                a1 = s * (1.5 - lf)
                a[row + lo_i + 1] += d * (a1 - a0)
                for xi in range(lo_i + 2, hi_i - 1):
                    a[row + xi] += d * s
                a2 = a1 + (hi_i - lo_i - 3) * s
                a[row + hi_i - 1] += d * (1.0 - a2 - am)
            a[row + hi_i] += d * am
        x = xn


# ------------------------------------------------------------------ font discovery
SANS = ("/usr/share/fonts/truetype/inter/Inter-Regular.ttf", "/usr/share/fonts/truetype/crosextra/Carlito-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf")
BOLD = ("/usr/share/fonts/truetype/inter/Inter-Bold.ttf", "/usr/share/fonts/truetype/crosextra/Carlito-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf")
MONO = ("/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf", "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf")
_loaded: dict[str, Optional[Font]] = {}


def load(kind: str) -> Optional[Font]:
    """The system's sans / bold / mono face, or None (callers then fall back to the pixel font)."""
    if kind in _loaded:
        return _loaded[kind]
    env = os.environ.get({"sans": "KOS_FONT", "bold": "KOS_FONT_BOLD", "mono": "KOS_FONT_MONO"}[kind])
    for path in ([env] if env else []) + list({"sans": SANS, "bold": BOLD, "mono": MONO}[kind]):
        if path and os.path.exists(path):
            try:
                _loaded[kind] = Font(path)
                return _loaded[kind]
            except (FontError, struct.error, OSError, IndexError):
                continue
    _loaded[kind] = None
    return None
