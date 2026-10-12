"""The ways the desktop can look, and the controls it can be driven by.

Four *looks* share one interface. Apps never know which one is on, except through a flag:

* ``normal``   glass, pills, smooth type (the default).
* ``3d``       more depth (deeper bevels and shadows), a 3D pointer, click bubbles, and the whole
               screen tilts a little toward where you move or click.
* ``text``     everything built from text: windows are boxes, labels and buttons are characters.
* ``terminal`` no pictures at all: a numbered list of every control on screen. Pick one, press Enter.

All of them work because apps *declare* their controls with invisible ``hit`` ops
(``["hit", x, y, w, h, "Files"]``). The OS collects them (plus the window frames it draws itself)
into one list of :class:`Control`. That list is what the terminal look prints, what Tab walks
through in every look, and what the text look draws as ``[ Files ]``. An app with no ``hit`` ops
still shows its text in the text look, but its buttons are not reachable from the keyboard.

Tilt is a shear done with row and strip copies (fast in plain Python): a small, cheap approximation
of perspective, not a real 3D transform.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import ttf
from .display import Framebuffer, parse_color

ACCENT = "#0078d4"
BORDER = "#5b6475"
LOOKS = ("normal", "3d", "text", "terminal")


@dataclass
class Control:
    layer: str                      # layer id that owns it
    app: str
    label: str
    rect: tuple[int, int, int, int]  # screen coordinates
    kind: str = "hit"               # hit | close | minimize | focus

    @property
    def center(self) -> tuple[int, int]:
        x, y, w, h = self.rect
        return x + w // 2, y + h // 2


# ------------------------------------------------------------------------------------ tilt
def shear(fb: Framebuffer, tx: float, ty: float) -> Framebuffer:
    """A gentle perspective-like skew: rows slide sideways by up to ``tx`` px (top one way, bottom the
    other), vertical strips slide up or down by up to ``ty`` px. The uncovered edge stays black."""
    W, H = fb.width, fb.height
    if abs(tx) < 0.5 and abs(ty) < 0.5:
        return fb
    stride = W * 4
    src = fb.buf
    out = Framebuffer(W, H)
    dst = out.buf
    cy = H / 2
    for y in range(H):
        dx = round(tx * (y - cy) / cy)
        a = y * stride
        if dx == 0:
            dst[a:a + stride] = src[a:a + stride]
        elif dx > 0:
            dst[a + dx * 4:a + stride] = src[a:a + stride - dx * 4]
        else:
            dst[a:a + stride + dx * 4] = src[a - dx * 4:a + stride]
    if abs(ty) >= 0.5:
        step = 16
        tmp = bytearray(dst)
        cx = W / 2
        for x0 in range(0, W, step):
            w = min(step, W - x0)
            dy = round(ty * (x0 + w / 2 - cx) / cx)
            if dy == 0:
                continue
            for y in range(H):
                ny = y + dy
                a = y * stride + x0 * 4
                if 0 <= ny < H:
                    b = ny * stride + x0 * 4
                    dst[b:b + w * 4] = tmp[a:a + w * 4]
            # rows the strip vacated (top or bottom) go black
            rng = range(0, dy) if dy > 0 else range(H + dy, H)
            for y in rng:
                b = y * stride + x0 * 4
                dst[b:b + w * 4] = bytes(w * 4)
    return out


# ------------------------------------------------------------------------------- focus ring
def draw_ring(fb: Framebuffer, rect: tuple[int, int, int, int], u: int = 1) -> None:
    """A KOS Blue outline around the control the keyboard is on."""
    x, y, w, h = rect
    col = parse_color(ACCENT)
    t = max(2, u)
    for dx, dy, rw, rh in ((x - t, y - t, w + 2 * t, t), (x - t, y + h, w + 2 * t, t),
                           (x - t, y, t, h), (x + w, y, t, h)):
        fb.rect(dx, dy, rw, rh, col)


# ------------------------------------------------------------------------------------ the stack
def half(fb: Framebuffer) -> Framebuffer:
    """A frame at half size (every other pixel of every other row) - memoryview slicing, so it is quick."""
    W, H = fb.width, fb.height
    mv = memoryview(fb.buf).cast("I")
    out = Framebuffer(W // 2, H // 2)
    ow = out.width
    dst = memoryview(out.buf).cast("I")
    for y in range(out.height):
        dst[y * ow:(y + 1) * ow] = mv[2 * y * W:2 * y * W + 2 * ow:2]
    return out


def stack(shell, cards: list[tuple[str, str, Framebuffer]]) -> tuple[Framebuffer, list[tuple[str, tuple[int, int, int, int]]]]:
    """The looks as layers in space: the interface in front, the others behind it, each a half-size card offset up and to
    the left of the one before. ``cards`` is back to front: (look name, title, full-size frame). Returns the picture and each
    card's rectangle (front-most last) so a click can pick one."""
    from . import fbgfx
    W, H, u = shell.W, shell.H, shell.u
    out = Framebuffer(W, H)
    fbgfx.gradient_v(out, 0, 0, W, H, "#0e1118", "#06080c")
    rects = []
    n = len(cards)
    cw, ch = W // 2, H // 2
    step_x, step_y = max(24 * u, (W - cw - 40 * u) // max(1, n - 1) // 2), max(20 * u, (H - ch - 70 * u) // max(1, n - 1) // 2)
    x0, y0 = (W - cw) // 2 - step_x * (n - 1) // 2, 36 * u
    for i, (look, title, frame) in enumerate(cards):
        x, y = x0 + i * step_x, y0 + i * step_y
        small = half(frame)
        fbgfx.shadow(out, x, y, cw, ch, spread=10 * u, strength=0.7, dy=6 * u)
        for r in range(ch):
            out.buf[(y + r) * W * 4 + x * 4:(y + r) * W * 4 + (x + cw) * 4] = small.buf[r * cw * 4:(r + 1) * cw * 4]
        if i < n - 1:
            fbgfx.blend(out, x, y, cw, ch, "#000000", 0.35 * (1 - i / max(1, n - 1)) + 0.1)      # cards further back sit in shadow
        fbgfx.border(out, x, y, cw, ch, "#ffffff", "#000000", 0.55)
        px = 7 * u + 2
        face = ttf.load("bold")
        if face:
            tw = int(face.width(title, px))
            out.stext(x + 8 * u + 1, y - face.line_height(px) - 3 * u + 1, title, "#000000", px, 1)
            out.stext(x + 8 * u, y - face.line_height(px) - 3 * u, title, ACCENT if i == n - 1 else "#dfe8f5", px, 1)
        rects.append((look, (x, y, cw, ch)))
    return out, rects


# --------------------------------------------------------------------------------- text look
class Grid:
    """A character-cell screen: what 'everything is text' draws onto."""

    def __init__(self, cols: int, rows: int):
        self.cols, self.rows = cols, rows
        self.cells: list[list[Optional[tuple[str, str]]]] = [[None] * cols for _ in range(rows)]

    def put(self, col: int, row: int, text: str, color: str) -> None:
        if not 0 <= row < self.rows:
            return
        for i, ch in enumerate(text):
            c = col + i
            if 0 <= c < self.cols:
                self.cells[row][c] = (ch, color) if ch != " " else None

    def clear(self, c0: int, r0: int, c1: int, r1: int) -> None:
        for r in range(max(0, r0), min(self.rows, r1)):
            row = self.cells[r]
            for c in range(max(0, c0), min(self.cols, c1)):
                row[c] = None

    def occupied(self, c0: int, r0: int, c1: int, r1: int) -> bool:
        """Is there text (not a box border) in these cells?"""
        return any(self.cells[r][c] and self.cells[r][c][1] != BORDER for r in range(max(0, r0), min(self.rows, r1))
                   for c in range(max(0, c0), min(self.cols, c1)))

    def box(self, c0: int, r0: int, c1: int, r1: int, title: str, color: str) -> None:
        if c1 - c0 < 4 or r1 - r0 < 2:
            return
        self.clear(c0, r0, c1, r1)
        self.put(c0, r0, "+" + "-" * (c1 - c0 - 2) + "+", color)
        self.put(c0, r1 - 1, "+" + "-" * (c1 - c0 - 2) + "+", color)
        for r in range(r0 + 1, r1 - 1):
            self.put(c0, r, "|", color)
            self.put(c1 - 1, r, "|", color)
        if title:
            t = f" {title} "[: c1 - c0 - 4]
            self.put(c0 + 2, r0, t, "#ffffff")


def _lum(c: str) -> int:
    r, g, b = int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16)
    return (r * 3 + g * 6 + b) // 10


def render_text(shell) -> Framebuffer:
    """The whole desktop as text: layers become boxes, labels and controls become characters."""
    u = shell.u
    cw, ch = 6 * u, 12 * u
    cols, rows = shell.W // cw, shell.H // ch
    grid = Grid(cols, rows)
    layers = sorted((l for l in shell.layers.values() if shell.shown(l) and l.kind not in ("wallpaper", "cursor", "overlay")),
                    key=lambda l: l.z)
    for layer in layers:
        x, y, w, h = layer.rect
        c0, r0, c1, r1 = x // cw, y // ch, (x + w) // cw, (y + h) // ch
        c1, r1 = min(cols, max(c1, c0 + 1)), min(rows, max(r1, r0 + 1))
        if layer.kind == "window":
            grid.box(c0, r0, c1, r1, layer.title or layer.name, ACCENT if layer.id == shell.focus else BORDER)
            inner = (c0 + 1, r0 + 1, c1 - 1, r1 - 1)
        elif layer.kind in ("widget", "dock") and r1 - r0 >= 3:
            grid.box(c0, r0, c1, r1, "" if layer.kind == "dock" else layer.name.replace("widget-", ""), BORDER)
            inner = (c0 + 1, r0 + 1, c1 - 1, r1 - 1)
        else:
            if layer.kind == "bar":
                grid.clear(c0, r0, c1, r1)
            inner = (c0, r0, c1, r1)
        cx, cy, _, _ = shell.content_rect(layer)
        if layer.mode == "tui":
            scr = layer.screen or {}
            for i, line in enumerate(scr.get("lines", [])):
                row = r0 + 1 + i
                if row >= r1 - 1:
                    break
                grid.put(c0 + 1, row, line[: max(0, c1 - c0 - 2)], ACCENT if line.lstrip().startswith(">") else "#e3ebf6")
            if scr.get("status"):
                grid.put(c0 + 1, r1 - 2, scr["status"][: c1 - c0 - 2], "#a9c4e8")
            continue
        free: dict[int, int] = {}                          # row -> first column not yet used by this layer's text
        items = []
        for op in layer.ops:
            if op[0] in ("text", "stext") and op[3].strip() and _lum(op[4]) >= 50:     # dark text is a drop shadow
                items.append(((cy + op[2]) // ch, (cx + op[1]) // cw, op[3], op[4]))
        for row, col, text, color in sorted(items):
            if not inner[1] <= row < inner[3]:
                continue
            col = max(col, inner[0], free.get(row, 0))
            if col >= inner[2]:
                continue
            grid.put(col, row, text[: inner[2] - col], color)
            free[row] = col + min(len(text), inner[2] - col) + 1
        for op in layer.ops:
            if op[0] != "hit" or not op[5]:
                continue
            hx, hy, hw, hh = cx + op[1], cy + op[2], op[3], op[4]
            a, b, c, d = hx // cw, hy // ch, max(hx // cw + 1, (hx + hw) // cw), max(hy // ch + 1, (hy + hh) // ch)
            if grid.occupied(a, b, c, d):
                continue                                     # it already shows its own text
            row = min(max(b + (d - b - 1) // 2, inner[1]), inner[3] - 1)
            label = f"[{op[5]}]"
            col = max(a, inner[0], free.get(row, 0))
            if col + len(label) > (inner[2] if layer.kind in ("window", "widget") else cols):
                continue
            grid.put(col, row, label, ACCENT)
            free[row] = col + len(label) + 1
    return _draw_grid(grid, cw, ch, shell.W, shell.H, u)


def _draw_grid(grid: Grid, cw: int, ch: int, W: int, H: int, u: int) -> Framebuffer:
    fb = Framebuffer(W, H)
    fb.clear(parse_color("#0b0d11"))
    mono = ttf.load("mono")
    px = 10 * u
    for r, row in enumerate(grid.cells):
        for c, cell in enumerate(row):
            if not cell:
                continue
            char, color = cell
            if mono is None:
                fb.text(c * cw, r * ch + 2 * u, char.upper(), parse_color(color), u)
            else:
                p = parse_color(color)
                mono.draw(fb, c * cw, r * ch, char, (p[2], p[1], p[0]), px)
    return fb


# ----------------------------------------------------------------------------- terminal look
def render_terminal(shell, controls: list[Control], nav: int, typed: str) -> tuple[Framebuffer, dict[int, int]]:
    """No pictures: every control on screen as a numbered line. Up/Down or a number picks, Enter clicks."""
    u = shell.u
    cw, ch = 6 * u, 12 * u
    cols, rows = shell.W // cw, shell.H // ch
    grid = Grid(cols, rows)
    grid.put(1, 0, "KOS  -  terminal view: every button on screen, in order", "#ffffff")
    grid.put(1, 1, "Up/Down or a number picks one, Enter presses it, Tab moves on, Esc clears the number.", "#9aa3b2")
    row, shown = 3, 0
    row_of: dict[int, int] = {}                                    # screen row -> control index (for clicks)
    last_app = None
    first = max(0, nav - (rows - 8) // 2)
    for i, c in enumerate(controls):
        if i < first:
            continue
        if row >= rows - 3:
            grid.put(1, rows - 3, f"... {len(controls) - i} more (keep pressing Down)", "#9aa3b2")
            break
        if c.app != last_app:
            last_app = c.app
            row += 1 if row > 3 else 0
            grid.put(1, row, c.app.replace("-", " ").upper(), "#4cc2ff")
            row += 1
        row_of[row] = i
        text = f"{i + 1:>3}. {c.label}" + ("   (window: close)" if c.kind == "close" else "   (window: minimize)" if c.kind == "minimize" else "")
        if i == nav:
            for cc in range(2, cols - 2):
                grid.cells[row][cc] = (" ", "#ffffff")
            grid.put(2, row, text, "#ffffff")
        else:
            grid.put(3, row, text, "#e3ebf6")
        row += 1
        shown += 1
    grid.put(1, rows - 2, f"{len(controls)} controls" + (f"    number: {typed}_" if typed else ""), "#9aa3b2")
    fb = _draw_grid(grid, cw, ch, shell.W, shell.H, u)
    if 0 <= nav < len(controls):                                    # the selected row's highlight, in accent
        sel_row = next((r for r in range(rows) if grid.cells[r][3] and grid.cells[r][3][1] == "#ffffff" and grid.cells[r][2] == (" ", "#ffffff")), None)
        if sel_row is not None:
            fb.rect(2 * cw, sel_row * ch, (cols - 4) * cw, ch, parse_color(ACCENT))
            sub = Grid(cols, rows)
            sub.put(2, sel_row, grid_text(grid, sel_row), "#ffffff")
            mono = ttf.load("mono")
            if mono:
                for c, cell in enumerate(sub.cells[sel_row]):
                    if cell:
                        mono.draw(fb, c * cw, sel_row * ch, cell[0], (255, 255, 255), 10 * u)
    return fb, row_of


def grid_text(grid: Grid, row: int) -> str:
    return "".join((cell[0] if cell else " ") for cell in grid.cells[row][2:]).rstrip()
