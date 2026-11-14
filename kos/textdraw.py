"""``text`` mode: the same draw commands, drawn with text.

A graphical app sends ``frame`` ops (``clear``, ``rect``, ``line``, ``text``) in pixels. In ``text`` mode the
OS draws exactly those ops onto a grid of character cells instead of a framebuffer: a filled rectangle becomes
shaded cells (a big one gets a box of line-drawing characters), a line becomes ``─ │ ╲ ╱`` (``┼`` where two cross),
text is text. No pixels, no colour and no mouse pointer of its own are needed, so it runs on a serial console,
over SSH, or on a machine with no framebuffer. The app is the same program as the graphical one: it does not
know which of the two it is drawing on, only the ``hello`` mode.

**The button clicker works here.** A click lands on a cell and the app is told the pixel at the *centre* of
that cell (``to_app_coords``). A rectangle fills a cell exactly when the cell's centre is inside the rectangle,
so what you see filled is what a click hits. Two honest exceptions, both documented in the README: a rectangle
narrower or shorter than half a cell is drawn as a rule (``─`` or ``│``) and may not be hit by a click; and a
rectangle too small to contain any cell centre is drawn in the one cell around its middle, which a click may miss.

Safety, in the same order as the rest of the display layer:

* The OS draws the title bar and the status bar, so an app cannot hide which devices it was given.
* Every character that reaches the terminal is one the OS chose: a cell holds a single vetted character
  (a control, bidi, combining or double-width character becomes ``?``), never an app's string, so an app
  cannot inject an escape sequence. The only escape sequences written are the OS's own.
* The trusted password overlay is drawn last, over everything, by the same code as the text page.
* Work per frame is bounded (``WORK_BUDGET`` cells touched); ops past it are dropped and counted, never
  queued. The grid is at most ``MAX_COLS`` x ``MAX_ROWS``.

Whole numbers only (``//``, no decimals), as everywhere in KOS.
"""

from __future__ import annotations

import os
import unicodedata
from typing import Optional

from . import font
from .display import Modal, render_text_modal

CELL_W = font.CELL_W
CELL_H = font.CELL_H
MAX_COLS = 400
MAX_ROWS = 200
WORK_BUDGET = 400_000          # cells one frame may touch; the rest of its ops are dropped

_SHADES = {False: " ░▒▓█", True: " .:*#"}          # indexed by ascii_only; by brightness, dark first
_LINES = {False: {"h": "─", "v": "│", "x": "┼", "down": "╲", "up": "╱", "dot": "·",
                  "tl": "┌", "tr": "┐", "bl": "└", "br": "┘"},
          True: {"h": "-", "v": "|", "x": "+", "down": "\\", "up": "/", "dot": ".",
                 "tl": "+", "tr": "+", "bl": "+", "br": "+"}}

Cell = tuple          # (char, background brightness 0..255, reverse video)
BLANK: Cell = (" ", 0, False)


def luminance(color: object) -> int:
    """'#rrggbb' -> brightness 0..255, whole numbers only. Anything else is 0 (the protocol has already
    refused it; this is the second check)."""
    if not (isinstance(color, str) and len(color) == 7 and color[0] == "#"):
        return 0
    try:
        r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    except ValueError:
        return 0
    return (299 * r + 587 * g + 114 * b) // 1000


def safe_char(ch: str, ascii_only: bool = False) -> str:
    """One character that is safe to put in a terminal cell: printable, one column wide, not combining.
    Anything else becomes '?'. A space-like character becomes a space."""
    if len(ch) != 1:
        return "?"
    o = ord(ch)
    if o < 0x20 or 0x7F <= o < 0xA0:
        return "?"
    cat = unicodedata.category(ch)
    if cat == "Zs":
        return " "
    if ascii_only and o > 0x7E:
        return "?"
    if (cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Mn", "Me")
            or unicodedata.combining(ch) or unicodedata.east_asian_width(ch) in ("W", "F")):
        return "?"
    return ch


def _span(start: int, size: int, cell: int, count: int) -> tuple[int, int]:
    """The cells [first, last] along one axis whose centre lies in the pixel span [start, start+size),
    clipped to the grid. If the span contains no centre it still gets the one cell around its middle."""
    half = cell // 2
    first = -((half - start) // cell)                  # ceil((start - half) / cell)
    last = (start + size - 1 - half) // cell
    if last < first:
        first = last = (start + size // 2) // cell
    return max(0, first), min(count - 1, last)


class TextDrawSurface:
    """Drop-in for ``TUISurface`` / ``GraphicalSurface``: same methods, drawn with characters."""

    def __init__(self, out_fd: int, cols: int, rows: int, app_name: str, ascii_only: Optional[bool] = None):
        self.fd = out_fd
        self.cols = max(8, min(int(cols), MAX_COLS))
        self.rows = max(4, min(int(rows), MAX_ROWS))
        self.body = self.rows - 2                       # row 0 is the title bar, the last row the status bar
        self.app = app_name
        if ascii_only is None:
            ascii_only = os.environ.get("KOS_TEXT_ASCII") == "1" or os.environ.get("TERM") in ("dumb", "vt100")
        self.ascii = bool(ascii_only)
        self.grid: list[list[Cell]] = [[BLANK] * self.cols for _ in range(self.body)]
        self.status = ""
        self.modal: Optional[Modal] = None
        self.has_content = False
        self.pointer: Optional[tuple[int, int]] = None
        self.dropped = 0           # ops dropped (over budget or malformed) since the surface was made
        self.last_dropped = 0      # ... in the most recent frame

    # --- the surface interface the session uses ------------------------------------------------
    def hello_size(self) -> tuple[int, int]:
        """What the app is told: the drawing area in its own pixels (cells x cell size)."""
        return self.cols * CELL_W, self.body * CELL_H

    def to_app_coords(self, x: int, y: int) -> tuple[int, int]:
        """A terminal cell (col, row; row 0 is the OS title bar) -> the pixel at the centre of that cell
        in the app's drawing area. This is what makes a click land on what is drawn."""
        return x * CELL_W + CELL_W // 2, (y - 1) * CELL_H + CELL_H // 2

    def set_pointer(self, x: int, y: int) -> None:
        self.pointer = (x, y)

    def set_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal

    def set_status(self, text: str) -> None:
        self.status = text

    def present(self, msg: dict) -> None:
        """Apply a validated ``frame`` onto the scene already on the grid (like the graphical surface, a
        frame changes the last one; send ``clear`` to start blank)."""
        budget = WORK_BUDGET
        self.last_dropped = 0
        for op in msg.get("ops", ()):
            cost = self._cost(op)
            if cost is None or cost > budget:
                self.last_dropped += 1
                continue
            try:
                self._apply(op)
            except (TypeError, ValueError, IndexError, KeyError):
                self.last_dropped += 1
                continue
            budget -= cost
        self.dropped += self.last_dropped
        self.has_content = True

    def close(self) -> None:
        pass

    # --- drawing ---------------------------------------------------------------------------------
    def _cost(self, op) -> Optional[int]:
        """Cells an op will touch, worked out before it runs; None for an op that is not well formed."""
        try:
            kind = op[0]
            if kind == "clear":
                return self.cols * self.body
            if kind == "rect":
                _, x, y, w, h = op[:5]
                if w <= 0 or h <= 0:
                    return 0
                c0, c1 = _span(x, w, CELL_W, self.cols)
                r0, r1 = _span(y, h, CELL_H, self.body)
                return max(0, c1 - c0 + 1) * max(0, r1 - r0 + 1)
            if kind == "line":
                _, x0, y0, x1, y1 = op[:5]
                return max(abs(x1 // CELL_W - x0 // CELL_W), abs(y1 // CELL_H - y0 // CELL_H)) + 1
            if kind == "text":
                return len(op[3])
        except (TypeError, ValueError, IndexError):
            return None
        return None

    def _apply(self, op) -> None:
        kind = op[0]
        if kind == "clear":
            lum = luminance(op[1])
            self.grid = [[(" ", lum, False)] * self.cols for _ in range(self.body)]
        elif kind == "rect":
            self._rect(op[1], op[2], op[3], op[4], luminance(op[5]))
        elif kind == "line":
            self._line(op[1], op[2], op[3], op[4])
        elif kind == "text":
            scale = op[5] if len(op) > 5 else 1
            self._text(op[1], op[2], op[3], luminance(op[4]), scale if type(scale) is int and scale >= 1 else 1)

    def _put(self, col: int, row: int, ch: str, lum: Optional[int] = None, rev: bool = False) -> None:
        if 0 <= col < self.cols and 0 <= row < self.body:
            old = self.grid[row][col]
            self.grid[row][col] = (ch, old[1] if lum is None else lum, rev)

    def _rect(self, x: int, y: int, w: int, h: int, lum: int) -> None:
        if w <= 0 or h <= 0:
            return
        ln = _LINES[self.ascii]
        thin_w, thin_h = w < CELL_W // 2, h < CELL_H // 2
        c0, c1 = _span(x, w, CELL_W, self.cols)
        r0, r1 = _span(y, h, CELL_H, self.body)
        if thin_w and thin_h:
            self._put((x + w // 2) // CELL_W, (y + h // 2) // CELL_H, ln["dot"])
            return
        if thin_h:                                     # a rule: one row of ─
            row = (y + h // 2) // CELL_H
            for col in range(c0, c1 + 1):
                self._join(col, row, ln["h"])
            return
        if thin_w:                                     # a rule: one column of │
            col = (x + w // 2) // CELL_W
            for row in range(r0, r1 + 1):
                self._join(col, row, ln["v"])
            return
        if c1 < c0 or r1 < r0:                         # entirely off the grid: nothing to draw. (A negative end
            return                                     # index in the slice below would delete cells, not clip.)
        for row in range(r0, r1 + 1):
            self.grid[row][c0:c1 + 1] = [(" ", lum, False)] * (c1 - c0 + 1)
        if c1 - c0 >= 2 and r1 - r0 >= 2:              # big enough for a box around it
            for col in range(c0 + 1, c1):
                self._put(col, r0, ln["h"]); self._put(col, r1, ln["h"])
            for row in range(r0 + 1, r1):
                self._put(c0, row, ln["v"]); self._put(c1, row, ln["v"])
            self._put(c0, r0, ln["tl"]); self._put(c1, r0, ln["tr"])
            self._put(c0, r1, ln["bl"]); self._put(c1, r1, ln["br"])

    def _join(self, col: int, row: int, ch: str) -> None:
        """Draw a line character, making ┼ where a horizontal and a vertical meet."""
        if 0 <= col < self.cols and 0 <= row < self.body:
            ln = _LINES[self.ascii]
            have = self.grid[row][col][0]
            if {have, ch} == {ln["h"], ln["v"]}:
                ch = ln["x"]
            self._put(col, row, ch)

    def _line(self, x0: int, y0: int, x1: int, y1: int) -> None:
        ln = _LINES[self.ascii]
        c0, r0, c1, r1 = x0 // CELL_W, y0 // CELL_H, x1 // CELL_W, y1 // CELL_H
        if r0 == r1:
            ch = ln["h"]
        elif c0 == c1:
            ch = ln["v"]
        else:
            ch = ln["down"] if (c1 > c0) == (r1 > r0) else ln["up"]
        dx, dy = abs(c1 - c0), -abs(r1 - r0)
        sx, sy = (1 if c0 < c1 else -1), (1 if r0 < r1 else -1)
        err = dx + dy
        for _ in range(dx - dy + 1):
            self._join(c0, r0, ch)
            if c0 == c1 and r0 == r1:
                break
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                c0 += sx
            if e2 <= dx:
                err += dx
                r0 += sy

    def _text(self, x: int, y: int, s: str, lum: int, scale: int) -> None:
        row, col0 = y // CELL_H, x // CELL_W
        if not 0 <= row < self.body:
            return
        for i, raw in enumerate(s):
            col = col0 + i * scale
            if col >= self.cols:
                break
            ch = safe_char(raw, self.ascii)
            if ch == " " or col < 0:
                continue                                # a space draws nothing, as in the graphical font
            self._put(col, row, ch, None, lum < self.grid[row][col][1])

    # --- the screen ------------------------------------------------------------------------------
    def rows_text(self) -> list[str]:
        """The drawing area as plain text, one string per row (no attributes). For tests and screenshots."""
        shades = _SHADES[self.ascii]
        return ["".join(c[0] if c[0] != " " else shades[min(4, c[1] * 5 // 256)] for c in row)
                for row in self.grid]

    def compose(self) -> str:
        """The whole screen as one string of the OS's own escape sequences and vetted characters."""
        w = self.cols
        shades = _SHADES[self.ascii]
        out = ["\x1b[H"]
        header = " KOS > " + safe_text(self.app) + " [text]"
        out.append("\x1b[0;1;37;44m" + header[:w].ljust(w) + "\x1b[0m")
        for i, row in enumerate(self.grid):
            parts = [f"\x1b[{i + 2};1H\x1b[0m"]
            rev = False
            for ch, lum, r in row:
                if ch == " ":
                    r, ch = False, shades[min(4, lum * 5 // 256)]
                if r != rev:
                    parts.append("\x1b[7m" if r else "\x1b[0m")
                    rev = r
                parts.append(ch)
            parts.append("\x1b[0m")
            out.append("".join(parts))
        if self.pointer is not None:
            px, py = self.pointer
            if 0 <= px < self.cols and 1 <= py <= self.body:
                ch = self.grid[py - 1][px][0]
                if ch == " ":
                    ch = shades[min(4, self.grid[py - 1][px][1] * 5 // 256)]
                out.append(f"\x1b[{py + 1};{px + 1}H\x1b[7m{ch}\x1b[0m")     # the OS's pointer, drawn last
        shown = safe_text(self.status)
        if self.last_dropped:
            shown += f" | {self.last_dropped} draw op(s) dropped"
        out.append(f"\x1b[{self.rows};1H\x1b[0;7m" + shown[:w].ljust(w) + "\x1b[0m")
        if self.modal:
            out.append(render_text_modal(self.modal, self.cols, self.rows))      # the password overlay, last
        return "".join(out)

    def render(self) -> None:
        data = self.compose().encode("utf-8", "replace")
        while data:
            n = os.write(self.fd, data)
            data = data[n:]


def safe_text(s: str, ascii_only: bool = False) -> str:
    """A string for the OS's own bars: every character vetted."""
    return "".join(safe_char(c, ascii_only) for c in str(s))
