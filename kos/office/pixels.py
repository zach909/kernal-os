"""Pictures: a pixel-art image editor and a procedural image generator.
Both draw with the KOS Canvas in graphical mode and fall back to text in tui
mode. Exports go to the vault as PPM (text), SVG and PNG (base64 text)."""

from __future__ import annotations

import base64
import colorsys
import math
import random
import struct
import zlib

from kos.sdk import Canvas

from .ui import ListNav, Prompt, Screen, Store, TextView, slug

PALETTE = ["#000000", "#ffffff", "#e03c31", "#f5a623", "#f8e71c", "#417505", "#4a90e2", "#9013fe", "#8b572a", "#9b9b9b"]


def rgb(hexcol: str) -> tuple:
    return int(hexcol[1:3], 16), int(hexcol[3:5], 16), int(hexcol[5:7], 16)


def hexc(c: tuple) -> str: return "#%02x%02x%02x" % tuple(max(0, min(255, int(v))) for v in c)


def png_b64(rows: list) -> str:
    """rows: list of rows of (r,g,b). Real PNG, base64-encoded so it fits in the text vault."""
    h, w = len(rows), len(rows[0])
    raw = b"".join(b"\x00" + bytes(v for px in r for v in px) for r in rows)
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    return base64.b64encode(png).decode()


def ppm(rows: list) -> str:
    return f"P3\n{len(rows[0])} {len(rows)}\n255\n" + "\n".join(" ".join(f"{v}" for px in r for v in px) for r in rows) + "\n"


def svg(rows: list, cell: int = 8) -> str:
    h, w = len(rows), len(rows[0]); out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w * cell}" height="{h * cell}" shape-rendering="crispEdges">']
    for y, r in enumerate(rows):
        x = 0
        while x < w:                       # run-length per row keeps files small
            x2 = x
            while x2 + 1 < w and r[x2 + 1] == r[x]: x2 += 1
            out.append(f'<rect x="{x * cell}" y="{y * cell}" width="{(x2 - x + 1) * cell}" height="{cell}" fill="{hexc(r[x])}"/>'); x = x2 + 1
    return "".join(out) + "</svg>"


class ImageEditor(Screen):
    N = 24

    def __init__(self, host, title="Image"):
        self.host, self.title, self.st = host, title, Store(host)
        n = self.N
        self.px = self.st.load("pixels", None) or [["#ffffff"] * n for _ in range(n)]
        self.cx = self.cy = 0
        self.color = 0
        self.undo: list = []
        self.msg = ""
        self.help = "arrows move  space paint  0-9 colour  f fill  h/v flip  r rotate  i invert  g gray  u undo  c clear  s save  e export"

    def snap(self): self.undo.append([r[:] for r in self.px]); del self.undo[:-30]
    def commit(self): self.st.save("pixels", self.px)

    def paint(self, x, y):
        if 0 <= x < self.N and 0 <= y < self.N and self.px[y][x] != PALETTE[self.color]:
            self.px[y][x] = PALETTE[self.color]

    def fill(self, x, y):
        old, new = self.px[y][x], PALETTE[self.color]
        if old == new: return
        stack = [(x, y)]
        while stack:
            a, b = stack.pop()
            if 0 <= a < self.N and 0 <= b < self.N and self.px[b][a] == old:
                self.px[b][a] = new; stack += [(a + 1, b), (a - 1, b), (a, b + 1), (a, b - 1)]

    def render(self, w, h):
        ch = {c: str(i) for i, c in enumerate(PALETTE)}
        out = [f" colour {self.color} = {PALETTE[self.color]}   cursor {self.cx},{self.cy}   (graphical mode shows real colours)"]
        for y in range(self.N):
            out.append("  " + "".join(("[" if (x, y) == (self.cx, self.cy) else " ") + ch.get(self.px[y][x], "?") + ("]" if (x, y) == (self.cx, self.cy) else " ") for x in range(self.N)))
        if self.msg: out.append(" " + self.msg)
        return out[:h]

    def canvas(self, w, h):
        cell = max(4, min((h - 40) // self.N, (w - 20) // self.N)); c = Canvas().clear("#202020")
        ox, oy = 10, 30
        for y in range(self.N):
            for x in range(self.N): c.rect(ox + x * cell, oy + y * cell, cell, cell, self.px[y][x])
        c.rect(ox + self.cx * cell, oy + self.cy * cell, cell, 1, "#ff00ff").rect(ox + self.cx * cell, oy + self.cy * cell + cell - 1, cell, 1, "#ff00ff")
        for i, col in enumerate(PALETTE):
            c.rect(10 + i * 18, 6, 16, 16, col)
            if i == self.color: c.rect(10 + i * 18, 22, 16, 2, "#ffffff")
        self._geo = (ox, oy, cell)
        return c

    def event(self, ev):
        if ev["cmd"] == "button" and ev.get("pressed") and hasattr(self, "_geo"):
            ox, oy, cell = self._geo; x, y = (ev["x"] - ox) // cell, (ev["y"] - oy) // cell
            if 0 <= x < self.N and 0 <= y < self.N: self.snap(); self.paint(x, y); self.cx, self.cy = x, y; self.commit()
            elif 6 <= ev["y"] <= 22 and 10 <= ev["x"] < 10 + 18 * len(PALETTE): self.color = (ev["x"] - 10) // 18

    def key(self, k):
        self.msg = ""
        n = self.N
        if k == "left": self.cx = max(0, self.cx - 1)
        elif k == "right": self.cx = min(n - 1, self.cx + 1)
        elif k == "up": self.cy = max(0, self.cy - 1)
        elif k == "down": self.cy = min(n - 1, self.cy + 1)
        elif k == " ": self.snap(); self.paint(self.cx, self.cy); self.commit()
        elif len(k) == 1 and k.isdigit() and int(k) < len(PALETTE): self.color = int(k)
        elif k == "f": self.snap(); self.fill(self.cx, self.cy); self.commit()
        elif k == "h": self.snap(); self.px = [r[::-1] for r in self.px]; self.commit()
        elif k == "v": self.snap(); self.px = self.px[::-1]; self.commit()
        elif k == "r": self.snap(); self.px = [list(r) for r in zip(*self.px[::-1])]; self.commit()
        elif k == "i": self.snap(); self.px = [[hexc(tuple(255 - v for v in rgb(c))) for c in r] for r in self.px]; self.commit()
        elif k == "g": self.snap(); self.px = [[hexc((lambda t: (t, t, t))(sum(rgb(c)) // 3)) for c in r] for r in self.px]; self.commit()
        elif k == "u" and self.undo: self.px = self.undo.pop(); self.commit()
        elif k == "c": self.snap(); self.px = [[PALETTE[1]] * n for _ in range(n)]; self.commit()
        elif k == "e":
            rows = [[rgb(c) for c in r] for r in self.px]
            self.host.put("export-image.ppm", ppm(rows)); self.host.put("export-image.svg", svg(rows)); self.host.put("export-image.png.b64", png_b64(rows))
            self.msg = "exported image.ppm / .svg / .png.b64 to the vault"
        elif k == "escape": return ("quit",)


# ------------------------------------------------------------ generator ----
def ramp(name: str, t: float) -> tuple:
    t = t % 1.0 if name == "rainbow" else max(0.0, min(1.0, t))
    if name == "gray": v = 255 * t; return (v, v, v)
    if name == "fire": return (255 * min(1, t * 2), 255 * max(0, min(1, t * 2 - 0.6)), 255 * max(0, t * 3 - 2))
    if name == "ocean": return (20 * t, 90 + 120 * t, 140 + 115 * t)
    r, g, b = colorsys.hsv_to_rgb(t, 0.85, 0.95); return (r * 255, g * 255, b * 255)


KINDS = ("gradient", "checker", "stripes", "noise", "plasma", "mandelbrot", "spiral", "rings")
PALETTES = ("rainbow", "fire", "ocean", "gray")


def generate(kind: str, n: int, seed: int) -> list:
    """-> n x n grid of values in [0,1]. Deterministic for a (kind, n, seed)."""
    rnd = random.Random(seed); o1, o2, o3 = rnd.random() * 6.28, rnd.random() * 6.28, rnd.random() * 6.28
    f = 3 + seed % 5
    g = []
    for y in range(n):
        row = []
        for x in range(n):
            u, v = x / (n - 1), y / (n - 1)
            if kind == "gradient": t = (u + v) / 2
            elif kind == "checker": t = float(((x * f // n) + (y * f // n)) % 2)
            elif kind == "stripes": t = 0.5 + 0.5 * math.sin((u * 2 + v) * f * 3 + o1)
            elif kind == "noise":
                t = random.Random(seed * 1000003 + y * n + x).random()
            elif kind == "plasma":
                t = (math.sin(u * f + o1) + math.sin(v * f + o2) + math.sin((u + v) * f / 2 + o3) + math.sin(math.hypot(u - .5, v - .5) * f * 2)) / 8 + 0.5
            elif kind == "mandelbrot":
                c = complex(-2.2 + u * 3.2 * (1 - 0.02 * (seed % 10)), -1.4 + v * 2.8); z = 0j; i = 0
                while abs(z) <= 2 and i < 40: z = z * z + c; i += 1
                t = i / 40
            elif kind == "spiral":
                a = math.atan2(v - .5, u - .5); r = math.hypot(u - .5, v - .5); t = 0.5 + 0.5 * math.sin(a * (1 + seed % 4) + r * 30)
            else: t = 0.5 + 0.5 * math.sin(math.hypot(u - .5, v - .5) * f * 12 + o1)
            row.append(t)
        g.append(row)
    return g


class ImageGenerator(Screen):
    N = 56

    def __init__(self, host, title="Generate"):
        self.host, self.title, self.st = host, title, Store(host)
        s = self.st.load("settings", {"kind": 0, "seed": 1, "pal": 0})
        self.kind, self.seed, self.pal = s["kind"], s["seed"], s["pal"]
        self.msg = ""
        self.help = "left/right seed  up/down kind  p palette  r random seed  e export"

    def grid(self, n): return generate(KINDS[self.kind], n, self.seed)

    def rows(self, n=None):
        n = n or self.N
        return [[tuple(int(v) for v in ramp(PALETTES[self.pal], t)) for t in r] for r in self.grid(n)]

    def render(self, w, h):
        n = min(h - 3, 24); ramp_chars = " .:-=+*#%@"
        out = [f" {KINDS[self.kind]}  seed {self.seed}  palette {PALETTES[self.pal]}   (run graphical for colour)"]
        for r in self.grid(n):
            out.append("  " + "".join(ramp_chars[min(9, max(0, int(t * 9.99)))] * 2 for t in r))
        if self.msg: out.append(" " + self.msg)
        return out

    def canvas(self, w, h):
        n = self.N; cell = max(2, min((h - 24) // n, (w - 10) // n)); c = Canvas().clear("#101010")
        c.text(6, 6, f"{KINDS[self.kind]}  seed {self.seed}  {PALETTES[self.pal]}", "#ffffff")
        for y, r in enumerate(self.rows(n)):
            for x, px in enumerate(r): c.rect(6 + x * cell, 18 + y * cell, cell, cell, hexc(px))
        return c

    def key(self, k):
        self.msg = ""
        if k == "left": self.seed = max(0, self.seed - 1)
        elif k == "right": self.seed += 1
        elif k == "up": self.kind = (self.kind - 1) % len(KINDS)
        elif k == "down": self.kind = (self.kind + 1) % len(KINDS)
        elif k == "p": self.pal = (self.pal + 1) % len(PALETTES)
        elif k == "r": self.seed = random.randrange(1, 10 ** 6)
        elif k == "e":
            rows = self.rows(128)
            self.host.put("export-generated.ppm", ppm(rows)); self.host.put("export-generated.svg", svg(self.rows(48), 6)); self.host.put("export-generated.png.b64", png_b64(rows))
            self.msg = "exported ppm + png.b64 (128x128) and svg (48x48) to the vault"
        elif k == "escape": return ("quit",)
        self.st.save("settings", {"kind": self.kind, "seed": self.seed, "pal": self.pal})
