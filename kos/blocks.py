"""The 3D look: every part of the interface is a block standing on the wallpaper.

Each layer - a window, the menubar, the dock, the sidebar, a widget, the launcher - is a solid box:

* the **front** is what the app draws (frosted glass and all);
* the **top** and **sides** are tinted glass edges;
* the **back** is the list of its buttons (the "select each button and press Enter" view);
* from the bottom edge of an app a **waterfall** of its own words - a falling terminal - runs down to the ground; click it and you are
  taken to that app's commands.

The **ground is a lake of terminal**: the same falling text, flowing along a bright river toward the viewer into the **Kernel**, and from
the kernel on into the **Hardware**. Clicking the Kernel or the Hardware opens the app for it (Isolation, Devices).

The camera orbits the whole desktop (Alt + arrows, or drag with the middle button), so you can go around it. Blocks sit on whatever is
beneath them - a widget on the sidebar, a window on the wallpaper - and rise by their own height.

How it is drawn (pure Python, no GPU): each face is a flat quad, and a flat quad seen through a perspective camera is a *homography*
of its texture, so each face is filled by walking its scanlines and, for every pixel, asking the inverse homography where in the
texture it came from (exact at the ends of short spans, linear between). Faces facing away are skipped; blocks are drawn farthest first.
It is not fast - a frame is composed once and cached until the scene or the camera changes.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Optional

from . import fbgfx, ttf
from .display import Framebuffer, parse_color
from .quad import point_in_quad, polygon_area, unit_to_quad, unproject_quad  # noqa: F401

SPAN = 8                                                       # pixels between exact texture lookups along a scanline
DEFAULT_YAW, DEFAULT_PITCH = 0.26, 0.32                         # radians: a little from the side, and enough from above to see the lake
GROUND_DEPTH = 1.0                                              # how far the lake runs toward the viewer, in screen widths                         # radians: a little from the side and from above


# ----------------------------------------------------------------------------------------------- geometry
class Camera:
    """Orbits the point ``(cx, cy, cz)``. Yaw turns around the vertical axis, pitch looks down (positive) from above."""

    def __init__(self, yaw: float, pitch: float, cx: float, cy: float, cz: float, dist: float, py: Optional[float] = None):
        """``cx, cy``: where the pivot appears on screen. ``py``: its height in the world (default ``cy``) - move it toward the ground to
        keep the lake in view while looking down."""
        self.yaw, self.pitch, self.cx, self.cy, self.cz, self.dist = yaw, pitch, cx, cy, cz, dist
        self.py = cy if py is None else py
        self._cy, self._sy, self._cp, self._sp = math.cos(yaw), math.sin(yaw), math.cos(pitch), math.sin(pitch)

    def rotate(self, x: float, y: float, z: float) -> tuple[float, float, float]:
        x, y, z = x - self.cx, y - self.py, z - self.cz
        x1, z1 = x * self._cy + z * self._sy, -x * self._sy + z * self._cy          # yaw about y
        y2, z2 = y * self._cp + z1 * self._sp, -y * self._sp + z1 * self._cp          # pitch about x (positive: look down)
        return x1, y2, z2

    def project(self, x: float, y: float, z: float) -> tuple[float, float, float]:
        """Screen x, y and the depth of a world point (z is height above the wallpaper, toward the viewer)."""
        rx, ry, rz = self.rotate(x, y, z)
        d = max(1.0, self.dist - rz)
        s = self.dist / d
        return self.cx + rx * s, self.cy + ry * s, d

    def normal_faces(self, nx: float, ny: float, nz: float) -> tuple[float, float, float]:
        """A direction (a face normal) turned the same way as the scene."""
        x1, z1 = nx * self._cy + nz * self._sy, -nx * self._sy + nz * self._cy
        return x1, ny * self._cp + z1 * self._sp, -ny * self._sp + z1 * self._cp


# ---------------------------------------------------------------------------------------------- textures
@dataclass
class Texture:
    fb: Framebuffer
    alpha: Optional[bytearray] = None            # one byte per texel (0 transparent .. 255 solid); None = all solid
    _words: Optional[memoryview] = field(default=None, repr=False)

    @property
    def w(self) -> int:
        return self.fb.width

    @property
    def h(self) -> int:
        return self.fb.height

    def words(self) -> memoryview:
        if self._words is None:
            self._words = memoryview(self.fb.buf).cast("I")
        return self._words

    def halved(self) -> "Texture":
        """Half size (nearest), for faces seen from far away - a cheap mipmap that keeps shrinking text from sparkling."""
        fb = self.fb
        W, H = fb.width, fb.height
        out = Framebuffer(max(1, W // 2), max(1, H // 2))
        src, dst, ow = self.words(), memoryview(out.buf).cast("I"), out.width
        al = bytearray(ow * out.height) if self.alpha is not None else None
        for y in range(out.height):
            dst[y * ow:(y + 1) * ow] = src[2 * y * W:2 * y * W + 2 * ow:2]
            if al is not None:
                al[y * ow:(y + 1) * ow] = self.alpha[2 * y * W:2 * y * W + 2 * ow:2]
        return Texture(out, al)


def rounded_mask(w: int, h: int, radius: int) -> bytearray:
    """Alpha for a rounded rectangle: solid inside, a one-pixel soft edge on the corners."""
    m = bytearray(b"\xff" * (w * h))
    r = max(0, min(radius, w // 2, h // 2))
    for i in range(r):
        for j in range(r):
            dx, dy = r - i - 0.5, r - j - 0.5
            d = math.hypot(dx, dy)
            a = 255 if d <= r - 1 else 0 if d >= r else int(255 * (r - d))
            if a != 255:
                for x, y in ((i, j), (w - 1 - i, j), (i, h - 1 - j), (w - 1 - i, h - 1 - j)):
                    m[y * w + x] = a
    return m


def fill_face(out: Framebuffer, quad, tex: Texture) -> None:
    """Draw ``tex`` onto the screen quad (TL, TR, BR, BL) with perspective-correct texture coordinates."""
    inv = unit_to_quad(quad)
    if inv is None:
        return
    W, H = out.width, out.height
    ys = [p[1] for p in quad]
    y0, y1 = max(0, int(math.floor(min(ys)))), min(H - 1, int(math.ceil(max(ys))))
    if y1 < y0:
        return
    tw, th = tex.w, tex.h
    src, dst, alpha = tex.words(), memoryview(out.buf).cast("I"), tex.alpha
    A, B, C, D, E, F, G, Hh, I = inv
    fw, fh = tw - 1e-3, th - 1e-3
    edges = [(quad[i], quad[(i + 1) % 4]) for i in range(4)]
    for y in range(y0, y1 + 1):
        yy = y + 0.5
        xs = []
        for (ax, ay), (bx, by) in edges:
            if (ay <= yy) != (by <= yy):
                xs.append(ax + (yy - ay) / (by - ay) * (bx - ax))
        if len(xs) < 2:
            continue
        xl, xr = max(0, int(math.floor(min(xs) + 0.5))), min(W, int(math.floor(max(xs) + 0.5)))
        if xr <= xl:
            continue
        row = y * W
        x = xl
        while x < xr:
            xe = min(xr, x + SPAN)
            # exact texture coordinates at both ends of this span; linear between
            den0 = G * (x + 0.5) + Hh * yy + I
            den1 = G * (xe + 0.5) + Hh * yy + I
            if abs(den0) < 1e-12 or abs(den1) < 1e-12:
                x = xe
                continue
            u0 = (A * (x + 0.5) + B * yy + C) / den0 * tw
            v0 = (D * (x + 0.5) + E * yy + F) / den0 * th
            u1 = (A * (xe + 0.5) + B * yy + C) / den1 * tw
            v1 = (D * (xe + 0.5) + E * yy + F) / den1 * th
            u0 = 0.0 if u0 < 0 else fw if u0 > fw else u0
            v0 = 0.0 if v0 < 0 else fh if v0 > fh else v0
            u1 = 0.0 if u1 < 0 else fw if u1 > fw else u1
            v1 = 0.0 if v1 < 0 else fh if v1 > fh else v1
            n = xe - x
            du, dv = (u1 - u0) / n, (v1 - v0) / n
            u, v = u0, v0
            if alpha is None:
                for px in range(x, xe):
                    dst[row + px] = src[int(v) * tw + int(u)]
                    u += du
                    v += dv
            else:
                for px in range(x, xe):
                    ti = int(v) * tw + int(u)
                    a = alpha[ti]
                    if a == 255:
                        dst[row + px] = src[ti]
                    elif a:
                        s, d = src[ti], dst[row + px]
                        ia = 255 - a
                        dst[row + px] = ((((s & 0xFF) * a + (d & 0xFF) * ia) // 255)
                                         | ((((s >> 8) & 0xFF) * a + ((d >> 8) & 0xFF) * ia) // 255) << 8
                                         | ((((s >> 16) & 0xFF) * a + ((d >> 16) & 0xFF) * ia) // 255) << 16)
                    u += du
                    v += dv
            x = xe


_PLANE: dict = {}                                              # the padded wallpaper plane, kept between frames


# ----------------------------------------------------------------------------------------- the blocks
@dataclass
class Block:
    layer_id: str
    name: str
    rect: tuple[int, int, int, int]               # x, y, w, h on the flat screen
    z_back: float
    z_front: float
    front: Texture
    tint: str = "#2a3a55"
    words: list[str] = field(default_factory=list)       # the text its top face rains
    controls: list[str] = field(default_factory=list)    # its buttons, for the back face
    title: str = ""
    name_kind: str = ""                            # the layer's kind (window, bar, ...)
    opens: str = ""                                # clicking this block opens that app (the Kernel and Hardware blocks)
    fall: bool = False                             # a waterfall runs from its bottom edge to the ground
    fall_quad: Optional[list] = None               # ...and where it is on screen
    quad: Optional[list] = None                    # the projected front face, filled in by render()
    inv: Optional[tuple] = None
    depth: float = 0.0


def _shade(color: str, k: float) -> tuple[int, int, int]:
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    return max(0, min(255, int(r * k))), max(0, min(255, int(g * k))), max(0, min(255, int(b * k)))


def side_texture(w: int, h: int, tint: str, k: float, label: str = "", u: int = 1) -> Texture:
    """A tinted glass edge: a vertical gradient, a bright rim, optionally the app's name."""
    fb = Framebuffer(max(2, w), max(2, h))
    top, bot = _shade(tint, k * 1.25), _shade(tint, k * 0.6)
    fbgfx.gradient_v(fb, 0, 0, fb.width, fb.height, "#%02x%02x%02x" % top, "#%02x%02x%02x" % bot)
    fb.rect(0, 0, fb.width, 1, parse_color("#ffffff"))
    fb.rect(0, fb.height - 1, fb.width, 1, parse_color("#000000"))
    if label and fb.height > 10 * u:
        face = ttf.load("bold")
        if face:
            px = max(6, min(10 * u, fb.height // 2))
            fb.stext(max(2, (fb.width - int(face.width(label, px))) // 2), (fb.height - face.line_height(px)) // 2, label[:24], "#ffffff", px, 1)
    return Texture(fb)


GLYPHS = "abcdefghijklmnopqrstuvwxyz0123456789#$%&*+-/<>=?@"


def matrix_texture(block: Block, w: int, h: int, t: float, u: int = 1, px: Optional[int] = None, *,
                   transparent: bool = False, river: Optional[tuple[int, int]] = None) -> Texture:
    """Green characters falling through a dark terminal, drawn from the block's own words - its title and the labels of its
    buttons - mixed with digits and symbols, so every block rains its own text. ``transparent``: only the characters are solid (a
    waterfall you can see through). ``river``: a band of columns (x0, x1 in texels) that runs brighter and denser - the current
    the lake flows along."""
    w, h = max(8, w), max(8, h)
    fb = Framebuffer(w, h)
    if not transparent:
        fbgfx.gradient_v(fb, 0, 0, w, h, "#00120a", "#000a05")
        if river:
            fbgfx.blend(fb, river[0], 0, river[1] - river[0], h, "#00ff90", 0.10)
    mono = ttf.load("mono")
    px = px or max(6, 6 * u)
    cw, lh = max(4, int(px * 0.6)), max(6, int(px * 1.15))
    cols, rows = max(1, w // cw), max(1, h // lh)
    corpus = [c for word in (block.words or [block.name]) for c in word if c.isprintable() and not c.isspace()] or list(GLYPHS)
    seed = sum(map(ord, block.layer_id)) + 17
    rng = random.Random(seed)
    for ci in range(cols):
        in_river = bool(river) and river[0] <= ci * cw < river[1]
        speed = (0.6 + rng.random() * 1.4) * (1.8 if in_river else 1.0)
        trail = 14 if in_river else 9
        phase = rng.random() * (rows + trail)
        head = (phase + t * speed * 6) % (rows + trail)
        for r in range(rows):
            dist = head - r
            if 0 <= dist < trail:                            # a trail of characters, fading
                level = 1 - dist / trail
                if dist < 1:
                    col = "#e8fff0"
                elif in_river:
                    col = "#%02x%02x%02x" % (int(60 + 120 * level), int(180 + 75 * level), int(120 + 100 * level))
                else:
                    col = "#%02x%02x%02x" % (int(30 + 40 * level), int(90 + 165 * level), int(50 + 60 * level))
                ch = corpus[(ci * 7 + r * 13 + int(t * 3)) % len(corpus)] if rng.random() < 0.65 else rng.choice(GLYPHS)
                if mono:
                    fb.stext(ci * cw, r * lh, ch, col, px, 2)
    alpha = None
    if transparent:
        words = memoryview(fb.buf).cast("I")
        alpha = bytearray(len(words))
        for i, wd in enumerate(words):
            if wd & 0xFFFFFF:
                alpha[i] = 255
    return Texture(fb, alpha)


def info_texture(w: int, h: int, title: str, lines: list[str], tint: str = "#06231a", u: int = 1) -> Texture:
    """The front of the Kernel and Hardware blocks: a dark terminal-green panel with a heading and a few facts."""
    fb = Framebuffer(max(8, w), max(8, h))
    fbgfx.gradient_v(fb, 0, 0, fb.width, fb.height, tint, "#02100b")
    fb.rect(0, 0, fb.width, 2, parse_color("#2cff8a"))
    bold, mono = ttf.load("bold"), ttf.load("mono")
    if bold:
        fb.stext(10 * u, 8 * u, title, "#9dffc8", 12 * u, 1)
    y = 8 * u + 18 * u
    for line in lines:
        if mono and y < fb.height - 6 * u:
            fb.stext(10 * u, y, line[:int(fb.width / (6 * u * 0.6)) or 1], "#4ce08c", 7 * u, 2)
        y += 11 * u
    return Texture(fb)


def controls_texture(block: Block, w: int, h: int, u: int = 1) -> Texture:
    """The back: the block's buttons as a plain list - the keyboard-and-Enter view."""
    w, h = max(8, w), max(8, h)
    fb = Framebuffer(w, h)
    fbgfx.gradient_v(fb, 0, 0, w, h, "#0b0f16", "#06080c")
    face, mono = ttf.load("bold"), ttf.load("mono")
    px = 7 * u
    if face:
        fb.stext(8 * u, 6 * u, f"{block.title or block.name}: buttons", "#4cb0ff", px + 1, 1)
    y = 6 * u + int(px * 2)
    labels = block.controls or ["(no buttons)"]
    for i, lab in enumerate(labels[:max(1, (h - y) // int(px * 1.5))], 1):
        if mono:
            fb.stext(10 * u, y, f"{i:>2}. {lab[:40]}", "#dfe8f5", px, 2)
        y += int(px * 1.5)
    return Texture(fb)


# -------------------------------------------------------------------------------------------- the scene
def faces_of(b: Block, matrix_t: float, u: int):
    """The six faces of a block as (name, outward normal, corners TL,TR,BR,BL in world space, texture getter)."""
    x0, y0, w, h = b.rect
    x1, y1 = x0 + w, y0 + h
    zb, zf = b.z_back, b.z_front
    T = max(1, int(zf - zb))

    def top():
        return side_texture(w, T, b.tint, 1.1)

    def back():
        return controls_texture(b, w, h, u)

    return [
        ("front", (0, 0, 1), [(x0, y0, zf), (x1, y0, zf), (x1, y1, zf), (x0, y1, zf)], lambda: b.front),
        ("top", (0, -1, 0), [(x0, y0, zb), (x1, y0, zb), (x1, y0, zf), (x0, y0, zf)], top),
        ("bottom", (0, 1, 0), [(x0, y1, zf), (x1, y1, zf), (x1, y1, zb), (x0, y1, zb)], lambda: side_texture(w, T, b.tint, 0.4)),
        ("left", (-1, 0, 0), [(x0, y0, zf), (x0, y0, zb), (x0, y1, zb), (x0, y1, zf)], lambda: side_texture(T, h, b.tint, 0.65, b.title, u)),
        ("right", (1, 0, 0), [(x1, y0, zb), (x1, y0, zf), (x1, y1, zf), (x1, y1, zb)], lambda: side_texture(T, h, b.tint, 0.8, b.title, u)),
        ("back", (0, 0, -1), [(x1, y0, zb), (x0, y0, zb), (x0, y1, zb), (x1, y1, zb)], back),
    ]


def render(out: Framebuffer, backdrop: Texture, blocks: list[Block], cam: Camera, matrix_t: float, u: int,
           shadow=None, floor_words: Optional[list] = None) -> dict:
    """Paint the wallpaper plane, then every block, farthest first. Fills in each block's projected front quad (``quad``, ``inv``)
    so a click on it can be traced back to the flat layer."""
    W, H = out.width, out.height
    # the wallpaper: a plane at z = 0, a little larger than the screen so its edge stays out of sight when the camera turns
    pad = 0.8
    corners = [(-pad * W, -pad * H, 0), ((1 + pad) * W, -pad * H, 0), ((1 + pad) * W, (1 + pad) * H, 0), (-pad * W, (1 + pad) * H, 0)]
    out.rect(0, 0, W, H, parse_color("#05070b"))
    # texture of the padded plane: the wallpaper centred, reflected beyond its edge (cached: it only changes with the wallpaper)
    key = (id(backdrop.fb), len(backdrop.fb.buf), W, H, pad)
    cached = _PLANE.get("k") == key and _PLANE.get("fb")
    if cached:
        pad_fb = _PLANE["fb"]
    else:
        pad_fb = Framebuffer(int(W * (1 + 2 * pad)) // 2, int(H * (1 + 2 * pad)) // 2)
        small = backdrop.halved() if backdrop.w >= 2 else backdrop
        ox, oy = (pad_fb.width - small.w) // 2, (pad_fb.height - small.h) // 2

        def mirror(i: int, n: int) -> int:
            i %= 2 * n
            return i if i < n else 2 * n - 1 - i

        cols = [mirror(x - ox, small.w) for x in range(pad_fb.width)]
        for y in range(pad_fb.height):
            sy = mirror(y - oy, small.h)
            row = memoryview(small.fb.buf)[sy * small.w * 4:(sy + 1) * small.w * 4].cast("I")
            line = memoryview(bytearray(pad_fb.width * 4)).cast("I")
            for x, c in enumerate(cols):
                line[x] = row[c]
            pad_fb.buf[y * pad_fb.width * 4:(y + 1) * pad_fb.width * 4] = bytes(line)
        _PLANE["k"], _PLANE["fb"] = key, pad_fb
    plane = [cam.project(*c)[:2] for c in corners]
    fill_face(out, plane, Texture(pad_fb))
    seen = {"ground": None}                                    # what the caller may want to know landed where
    if floor_words is not None:
        # the ground: a terminal. It runs from the bottom edge of the wall toward the viewer, and the same falling text rains on it
        H0 = H
        depth = int(GROUND_DEPTH * W)
        fw, fh = int(2.6 * W) // 2, depth // 2
        ground = Block("ground", "ground", (0, 0, fw, fh), 0, 1, None, words=floor_words or ["kos"])
        river = (int((0.5 - 0.07 + 0.8) / 2.6 * fw), int((0.5 + 0.07 + 0.8) / 2.6 * fw))          # the current runs down the middle
        gt = matrix_texture(ground, fw, fh, matrix_t, u, px=max(8, 7 * u), river=river)
        ground_quad = [cam.project(*c)[:2] for c in ((-0.8 * W, H0, 0), (1.8 * W, H0, 0), (1.8 * W, H0, depth), (-0.8 * W, H0, depth))]
        rc = cam.rotate(W / 2, H0, depth / 2)
        nr = cam.normal_faces(0, -1, 0)
        if nr[0] * (0 - rc[0]) + nr[1] * (0 - rc[1]) + nr[2] * (cam.dist - rc[2]) > 0:        # only when it faces the viewer
            fill_face(out, ground_quad, gt)
            seen["ground"] = ground_quad
    if shadow:
        shadow(out, cam)
    for b in blocks:
        b.depth = cam.rotate((b.rect[0] + b.rect[2] / 2), (b.rect[1] + b.rect[3] / 2), (b.z_back + b.z_front) / 2)[2]
        b.fall_quad = b.quad = b.inv = None
    camera_pos = (0.0, 0.0, cam.dist)
    for b in sorted(blocks, key=lambda b: b.depth):            # smallest rotated z = farthest from the viewer
        for name, n, corners, tex in faces_of(b, matrix_t, u):
            cx = sum(c[0] for c in corners) / 4
            cy = sum(c[1] for c in corners) / 4
            cz = sum(c[2] for c in corners) / 4
            rc = cam.rotate(cx, cy, cz)
            nr = cam.normal_faces(*n)
            if nr[0] * (camera_pos[0] - rc[0]) + nr[1] * (camera_pos[1] - rc[1]) + nr[2] * (camera_pos[2] - rc[2]) <= 0:
                continue                                          # facing away
            quad = [cam.project(*c)[:2] for c in corners]
            if name == "front":
                b.quad, b.inv = quad, unit_to_quad(quad)
            if name in ("top", "back") and polygon_area(quad) ** 2 < 4:
                continue                                          # edge-on: nothing to see (and no texture to build)
            t = tex()
            span = max(abs(quad[1][0] - quad[0][0]) + abs(quad[1][1] - quad[0][1]), 1.0)
            while t.w > 2.2 * span and t.w > 8:                   # far away or foreshortened: use a smaller copy
                t = t.halved()
            fill_face(out, quad, t)
    # the waterfalls: each app's own words falling from its bottom edge to the ground, over everything behind them
    for b in sorted((b for b in blocks if b.fall and b.rect[1] + b.rect[3] < H - 4), key=lambda b: b.depth):
        x0, y0, w, h = b.rect
        zf = b.z_front
        quad = [cam.project(x0, y0 + h, zf)[:2], cam.project(x0 + w, y0 + h, zf)[:2], cam.project(x0 + w, H, zf)[:2], cam.project(x0, H, zf)[:2]]
        b.fall_quad = quad
        if polygon_area(quad) ** 2 < 4:
            continue
        fh = max(8, (H - (y0 + h)) // 2)
        fill_face(out, quad, matrix_texture(b, max(8, w // 2), fh, matrix_t, u, px=max(6, 6 * u), transparent=True))
    return seen


def unproject(blocks: list[Block], x: float, y: float) -> Optional[tuple[Block, float, float]]:
    """Which block's front face is under the screen point, and where on that block (in flat-layer pixels from its top left)?
    Nearest block first."""
    for b in sorted(blocks, key=lambda b: -b.depth):
        if b.quad is None or b.inv is None or not point_in_quad(b.quad, x, y):
            continue
        A, B, C, D, E, F, G, H, I = b.inv
        den = G * x + H * y + I
        if abs(den) < 1e-12:
            continue
        u, v = (A * x + B * y + C) / den, (D * x + E * y + F) / den
        if -0.001 <= u <= 1.001 and -0.001 <= v <= 1.001:
            return b, u * b.rect[2], v * b.rect[3]
    return None
