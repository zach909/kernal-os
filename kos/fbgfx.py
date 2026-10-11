"""Compositor-side graphics: what only the OS may do to pixels.

Apps draw with a handful of flat operations (``rect``, ``line``, ``text``). The
glass, the depth and the softness of the desktop are applied *by the OS around
and under* what apps draw, so they look the same for every app and no app can
fake the trusted chrome (title bars, the password prompt).

Everything works on :class:`kos.display.Framebuffer` (BGRX bytes) and is plain
Python. The trick that keeps it fast: a whole row (or a whole region) is one
big integer, so a blend or a blur is a handful of integer multiplies and adds
done in C, not a loop over pixels.

    blend(dst, region, color, alpha)     tint a region (translucency)
    blur(dst, region, radius)            frosted-glass backdrop
    shadow(dst, rect, spread, strength)  soft drop shadow
    gradient_v(dst, rect, top, bottom)   smooth vertical gradient
    rounded(...)                         corner masks
"""

from __future__ import annotations

from .display import Framebuffer


def _rgb(c: str) -> tuple[int, int, int]:
    return int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16)


def _clip(fb: Framebuffer, x: int, y: int, w: int, h: int) -> tuple[int, int, int, int]:
    x0, y0 = max(0, x), max(0, y)
    x1, y1 = min(fb.width, x + w), min(fb.height, y + h)
    return x0, y0, max(0, x1 - x0), max(0, y1 - y0)


def _rows(fb: Framebuffer, x: int, y: int, w: int, h: int) -> list[bytes]:
    stride = fb.width * 4
    return [bytes(fb.buf[(y + r) * stride + x * 4:(y + r) * stride + (x + w) * 4]) for r in range(h)]


def _put_rows(fb: Framebuffer, x: int, y: int, rows: list[bytes]) -> None:
    stride = fb.width * 4
    for r, row in enumerate(rows):
        start = (y + r) * stride + x * 4
        fb.buf[start:start + len(row)] = row


def _lanes(data: bytes, width: int) -> int:
    """Spread each byte into a ``width``-byte little-endian lane (room to do arithmetic)."""
    out = bytearray(len(data) * width)
    out[0::width] = data
    return int.from_bytes(out, "little")


def _unlanes(value: int, n: int, width: int, take: int) -> bytes:
    """Back to bytes: byte ``take`` of every lane."""
    raw = (value & ((1 << (8 * n * width)) - 1)).to_bytes(n * width, "little")
    return bytes(raw[take::width])


def blend_row(row: bytes, color_row: bytes, alpha: int) -> bytes:
    """out = (color*a + row*(255-a)) / 255, per byte, using 16-bit lanes."""
    n = len(row)
    mixed = _lanes(color_row, 2) * alpha + _lanes(row, 2) * (255 - alpha)
    # divide by 255 ~= (x + 128 + (x >> 8)) >> 8 ; the cheap form (x*257 + 32896) >> 16 is exact enough
    mixed = mixed + _lanes(b"\x80" * n, 2)                  # + 128 (rounding)
    mixed = mixed + ((mixed >> 8) & _lane_mask(n, 2, 0x00FF))   # + x >> 8 within each lane
    return _unlanes(mixed, n, 2, 1)


def _lane_mask(n: int, width: int, value: int) -> int:
    return int.from_bytes(value.to_bytes(width, "little") * n, "little")


def blend(fb: Framebuffer, x: int, y: int, w: int, h: int, color: str, alpha: float) -> None:
    """Tint a region toward ``color`` by ``alpha`` (0 = nothing, 1 = solid)."""
    x, y, w, h = _clip(fb, x, y, w, h)
    a = max(0, min(255, round(alpha * 255)))
    if not w or not h or a == 0:
        return
    r, g, b = _rgb(color)
    pixel = bytes((b, g, r, 0))
    crow = pixel * w
    _put_rows(fb, x, y, [blend_row(row, crow, a) for row in _rows(fb, x, y, w, h)])


def blend_rows(fb: Framebuffer, x: int, y: int, w: int, colors: list[tuple[str, float]]) -> None:
    """One (color, alpha) per row: vertical gradients of tint and opacity (glass sheen)."""
    for i, (color, alpha) in enumerate(colors):
        blend(fb, x, y + i, w, 1, color, alpha)


def gradient_v(fb: Framebuffer, x: int, y: int, w: int, h: int, top: str, bottom: str) -> None:
    (r0, g0, b0), (r1, g1, b1) = _rgb(top), _rgb(bottom)
    for i in range(h):
        t = i / max(1, h - 1)
        c = bytes((round(b0 + (b1 - b0) * t), round(g0 + (g1 - g0) * t), round(r0 + (r1 - r0) * t), 0))
        fb.rect(x, y + i, w, 1, c)


def blur(fb: Framebuffer, x: int, y: int, w: int, h: int, radius: int = 3, passes: int = 2) -> None:
    """Box blur of a region, edges clamped. ``passes`` of box blur approximate a
    Gaussian: this is the frosted-glass look. Cost is O(rows * radius)."""
    x, y, w, h = _clip(fb, x, y, w, h)
    if not w or not h or radius < 1:
        return
    rows = _rows(fb, x, y, w, h)
    k = 2 * radius + 1
    for _ in range(passes):
        # horizontal: average of 2r+1 pixel-shifted copies of the row, in 32-bit lanes
        blurred = []
        mult = (1 << 16) // k + 1
        for row in rows:
            padded = row[:4] * radius + row + row[-4:] * radius
            total = 0
            for s in range(k):
                total += _lanes(padded[s * 4:s * 4 + len(row)], 4)
            blurred.append(_unlanes(total * mult, len(row), 4, 2))
        rows = blurred
        # vertical: running sum of 2r+1 rows (clamped at the top and bottom)
        padded = [rows[0]] * radius + rows + [rows[-1]] * radius
        lanes = [_lanes(r, 4) for r in padded]
        running = sum(lanes[:k])
        out = [_unlanes(running * mult, len(rows[0]), 4, 2)]
        for i in range(1, h):
            running += lanes[i + k - 1] - lanes[i - 1]
            out.append(_unlanes(running * mult, len(rows[0]), 4, 2))
        rows = out
    _put_rows(fb, x, y, rows)


def shadow(fb: Framebuffer, x: int, y: int, w: int, h: int, spread: int = 8, strength: float = 0.45,
           dy: int = 3) -> None:
    """A soft drop shadow: nested translucent rectangles, darkest nearest the edge."""
    for i in range(spread, 0, -1):
        a = strength * (1 - i / (spread + 1)) ** 2 / 2.2
        blend(fb, x - i, y - i + dy, w + 2 * i, h + 2 * i, "#000000", a)


def save_region(fb: Framebuffer, x: int, y: int, w: int, h: int) -> list[bytes]:
    """Remember a region (to restore its corners after drawing a rounded panel over it)."""
    x0, y0, cw, ch = _clip(fb, x, y, w, h)
    return _rows(fb, x0, y0, cw, ch) if cw and ch else []


def round_corners(fb: Framebuffer, x: int, y: int, w: int, h: int, r: int, saved: list[bytes]) -> None:
    """Cut the four corners of a region to a radius, putting back what was there before
    (``saved`` is :func:`save_region` of the same, unclipped region)."""
    if not saved or x < 0 or y < 0 or x + w > fb.width or y + h > fb.height:
        return                                    # partly off screen: leave square rather than guess
    stride = fb.width * 4
    for cy in range(r):
        inset = r - int(round(((r * r) - (r - cy - 0.5) ** 2) ** 0.5))
        for py, row in ((y + cy, cy), (y + h - 1 - cy, h - 1 - cy)):
            for off in range(inset):
                for ox, col in ((x + off, off), (x + w - 1 - off, w - 1 - off)):
                    i = py * stride + ox * 4
                    fb.buf[i:i + 4] = saved[row][col * 4:col * 4 + 4]


def frost(fb: Framebuffer, x: int, y: int, w: int, h: int, radius: int = 4) -> None:
    """Frosted-glass backdrop, cheaply: blur a reduced-size copy and scale it back up.
    For big panels this is ~16x faster than blurring every pixel and looks the same
    (a blur is soft anyway)."""
    x, y, w, h = _clip(fb, x, y, w, h)
    if not w or not h:
        return
    f = 1 if w * h < 40_000 else 2 if w * h < 250_000 else 4
    if f == 1:
        return blur(fb, x, y, w, h, radius)
    sw, sh = max(1, w // f), max(1, h // f)
    small = Framebuffer(sw, sh)
    rows = _rows(fb, x, y, w, h)
    for r in range(sh):                                       # nearest-neighbour downsample
        src = rows[min(h - 1, r * f)]
        row = bytearray(sw * 4)
        for c in range(4):
            row[c::4] = src[c::4 * f][:sw] if len(src[c::4 * f]) >= sw else (src[c::4 * f] + src[-4 + c::4])[:sw]
        small.buf[r * sw * 4:(r + 1) * sw * 4] = row
    blur(small, 0, 0, sw, sh, max(1, radius // f * 2 // 2 + 1), 2)
    out = []
    for r in range(h):                                        # upsample: repeat pixels and rows
        srow = small.buf[min(sh - 1, r // f) * sw * 4:(min(sh - 1, r // f) + 1) * sw * 4]
        row = bytearray(w * 4)
        for c in range(4):
            col = bytes(srow[c::4])
            up = bytearray(len(col) * f)
            for k in range(f):
                up[k::f] = col
            row[c::4] = (bytes(up) + bytes(up[-1:]) * w)[:w]
        out.append(bytes(row))
    _put_rows(fb, x, y, out)


def circle(fb: Framebuffer, cx: int, cy: int, r: int, color: str) -> None:
    c = bytes((_rgb(color)[2], _rgb(color)[1], _rgb(color)[0], 0))
    for dy in range(-r, r + 1):
        half = int((r * r - dy * dy) ** 0.5 + 0.5)
        fb.rect(cx - half, cy + dy, 2 * half + 1, 1, c)


def shaded_text(fb: Framebuffer, x: int, y: int, s: str, color: str, scale: int = 1,
                shadow: str = "#000000") -> None:
    """Text with a 1px drop shadow, which keeps it readable on glass."""
    from .display import parse_color
    fb.text(x + scale, y + scale, s, parse_color(shadow), scale)
    fb.text(x, y, s, parse_color(color), scale)


def border(fb: Framebuffer, x: int, y: int, w: int, h: int, light: str, dark: str, alpha: float = 0.6) -> None:
    """A 1px bevel: light on the top/left edges, dark on the bottom/right - the 3D edge."""
    blend(fb, x, y, w, 1, light, alpha)
    blend(fb, x, y + 1, 1, h - 1, light, alpha * 0.7)
    blend(fb, x, y + h - 1, w, 1, dark, alpha)
    blend(fb, x + w - 1, y, 1, h - 1, dark, alpha * 0.7)
