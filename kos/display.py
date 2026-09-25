"""Graphical output: a tiny software compositor.

The app sends draw commands; the OS rasterizes them into a framebuffer it owns,
then composites things only the OS may draw on top: the mouse pointer and the
*trusted overlay* used for password prompts. Because the OS draws the overlay
last and withholds input from the app while it is up, an app cannot fake or
cover a password prompt.

Backends:
* ``FbdevBackend``    - real hardware, writes to /dev/fb0 (KOS on a real VT).
* ``TerminalBackend`` - any truecolor terminal, two pixels per character cell
                        using the upper-half-block glyph. Used when KOS runs
                        on top of another OS or over a serial/SSH console.
* ``HeadlessBackend`` - keeps frames in memory (tests, screenshots).
"""

from __future__ import annotations

import fcntl
import mmap
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from . import font


def parse_color(c: str) -> bytes:
    """'#rrggbb' -> the 4 bytes of a BGRX pixel (the common fbdev layout)."""
    r, g, b = int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16)
    return bytes((b, g, r, 0))


class Framebuffer:
    BPP = 4

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.buf = bytearray(width * height * self.BPP)

    def copy(self) -> "Framebuffer":
        fb = Framebuffer.__new__(Framebuffer)
        fb.width, fb.height, fb.buf = self.width, self.height, bytearray(self.buf)
        return fb

    def pixel(self, x: int, y: int) -> tuple[int, int, int]:
        i = (y * self.width + x) * self.BPP
        b, g, r = self.buf[i], self.buf[i + 1], self.buf[i + 2]
        return r, g, b

    def clear(self, color: bytes) -> None:
        self.buf[:] = color * (self.width * self.height)

    def rect(self, x: int, y: int, w: int, h: int, color: bytes) -> None:
        x0, y0 = max(0, x), max(0, y)
        x1, y1 = min(self.width, x + w), min(self.height, y + h)
        if x0 >= x1 or y0 >= y1:
            return
        row = color * (x1 - x0)
        stride = self.width * self.BPP
        for yy in range(y0, y1):
            start = yy * stride + x0 * self.BPP
            self.buf[start:start + len(row)] = row

    def put(self, x: int, y: int, color: bytes) -> None:
        if 0 <= x < self.width and 0 <= y < self.height:
            i = (y * self.width + x) * self.BPP
            self.buf[i:i + 4] = color

    def line(self, x0: int, y0: int, x1: int, y1: int, color: bytes) -> None:
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
        err = dx + dy
        for _ in range(dx - dy + 1):
            self.put(x0, y0, color)
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                x0 += sx
            if e2 <= dx:
                err += dx
                y0 += sy

    def text(self, x: int, y: int, s: str, color: bytes, scale: int = 1) -> None:
        for n, ch in enumerate(s):
            gx = x + n * font.ADVANCE * scale
            if gx >= self.width:
                break
            for row, bits in enumerate(font.glyph(ch)):
                for col in range(font.GLYPH_W):
                    if bits & (0x10 >> col):
                        self.rect(gx + col * scale, y + row * scale, scale, scale, color)

    def apply(self, ops: list[list]) -> None:
        for op in ops:
            kind = op[0]
            if kind == "clear":
                self.clear(parse_color(op[1]))
            elif kind == "rect":
                self.rect(op[1], op[2], op[3], op[4], parse_color(op[5]))
            elif kind == "line":
                self.line(op[1], op[2], op[3], op[4], parse_color(op[5]))
            elif kind == "text":
                self.text(op[1], op[2], op[3], parse_color(op[4]), op[5])


_CURSOR = [
    "X..........", "XX.........", "X#X........", "X##X.......", "X###X......",
    "X####X.....", "X#####X....", "X######X...", "X#######X..", "X####XXXXX.",
    "X##X##X....", "X#X.X##X...", "XX..X##X...", "X....X##X..", ".....XXX...",
]


def draw_cursor(fb: Framebuffer, x: int, y: int, scale: int = 1) -> None:
    black, white = parse_color("#000000"), parse_color("#ffffff")
    for dy, row in enumerate(_CURSOR):
        for dx, c in enumerate(row):
            if c != ".":
                fb.rect(x + dx * scale, y + dy * scale, scale, scale, black if c == "X" else white)


@dataclass
class Modal:
    """The trusted overlay. Only the OS creates these."""
    title: str
    lines: list[str] = field(default_factory=list)
    secret_len: Optional[int] = None  # password being typed (never shown)


def draw_modal(fb: Framebuffer, modal: Modal, scale: int = 1) -> None:
    lines = modal_lines(modal)
    w = min(fb.width - 4, max(font.text_width(l, scale) for l in lines) + 16 * scale)
    h = min(fb.height - 4, len(lines) * font.LINE_HEIGHT * scale + 12 * scale)
    x, y = (fb.width - w) // 2, (fb.height - h) // 2
    fb.rect(x - 2, y - 2, w + 4, h + 4, parse_color("#ffcc00"))
    fb.rect(x, y, w, h, parse_color("#1b1b2f"))
    for i, l in enumerate(lines):
        color = parse_color("#ffcc00" if i in (0, len(lines) - 1) else "#ffffff")
        fb.text(x + 8 * scale, y + 6 * scale + i * font.LINE_HEIGHT * scale, l, color, scale)


def modal_lines(modal: Modal) -> list[str]:
    lines = [modal.title, ""] + modal.lines
    if modal.secret_len is not None:
        lines += ["", "Password: " + ("(hidden)" if modal.secret_len else "")]
    return lines + ["", "KOS secure prompt - the app cannot see or draw over this."]


def render_text_modal(modal: Modal, cols: int, rows: int) -> str:
    """A centered box of real terminal text (used by the terminal backends)."""
    lines = modal_lines(modal)
    w = min(cols - 2, max(len(l) for l in lines) + 4)
    top = max(0, (rows - len(lines) - 2) // 2)
    left = max(1, (cols - w) // 2 + 1)
    out = [f"\x1b[{top + 1};{left}H\x1b[0;1;33;44m" + "+" + "-" * (w - 2) + "+"]
    for i, l in enumerate(lines):
        style = "1;33" if i == 0 else "0;37"
        out.append(f"\x1b[{top + 2 + i};{left}H\x1b[0;44;1;33m|\x1b[0;44;{style}m "
                   f"{l[:w - 4].ljust(w - 4)} \x1b[0;44;1;33m|")
    out.append(f"\x1b[{top + 2 + len(lines)};{left}H\x1b[0;1;33;44m+" + "-" * (w - 2) + "+")
    return "".join(out) + "\x1b[0m"


class HeadlessBackend:
    def __init__(self, width: int = 320, height: int = 200):
        self.width, self.height = width, height
        self.frames: list[Framebuffer] = []
        self.status = ""

    def show(self, fb: Framebuffer) -> None:
        self.frames.append(fb.copy())

    def set_status(self, text: str) -> None:
        self.status = text

    def close(self) -> None:
        pass


class TerminalBackend:
    """Renders 2 vertical pixels per cell with '▀' and 24-bit color."""

    def __init__(self, out_fd: int, cols: int, rows: int):
        self.fd = out_fd
        self.cols, self.rows = cols, rows
        self.width, self.height = cols, (rows - 1) * 2
        self._prev: list[Optional[bytes]] = [None] * (rows - 1)
        self.status = ""
        self._status_drawn: Optional[str] = None
        self._modal_rows: list[int] = []

    text_overlay = True

    def show(self, fb: Framebuffer, modal: Optional[Modal] = None) -> None:
        out = []
        stride = fb.width * 4
        if self._modal_rows:
            for r in self._modal_rows:  # force repaint of what the overlay covered
                if r < len(self._prev):
                    self._prev[r] = None
            self._modal_rows = []
        for row in range(self.height // 2):
            top = fb.buf[(2 * row) * stride:(2 * row + 1) * stride]
            bot = fb.buf[(2 * row + 1) * stride:(2 * row + 2) * stride]
            key = bytes(top) + bytes(bot)
            if self._prev[row] == key:
                continue
            self._prev[row] = key
            out.append(f"\x1b[{row + 1};1H")
            last = None
            for x in range(fb.width):
                i = x * 4
                pair = (top[i + 2], top[i + 1], top[i], bot[i + 2], bot[i + 1], bot[i])
                if pair != last:
                    out.append("\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm" % pair)
                    last = pair
                out.append("▀")
        if self.status != self._status_drawn:
            self._status_drawn = self.status
            out.append(f"\x1b[{self.rows};1H\x1b[0;7m{self.status[:self.cols].ljust(self.cols)}")
        if modal:
            out.append(render_text_modal(modal, self.cols, self.rows))
            self._modal_rows = list(range(self.rows - 1))
        out.append("\x1b[0m")
        os.write(self.fd, "".join(out).encode())

    def set_status(self, text: str) -> None:
        self.status = text

    def close(self) -> None:
        pass


FBIOGET_VSCREENINFO = 0x4600
FBIOGET_FSCREENINFO = 0x4602
KDSETMODE = 0x4B3A
KD_TEXT, KD_GRAPHICS = 0, 1


class FbdevBackend:
    """Linux framebuffer (/dev/fb0), 32 bits per pixel."""

    def __init__(self, path: str = "/dev/fb0", tty_fd: Optional[int] = None):
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        vinfo = fcntl.ioctl(self.fd, FBIOGET_VSCREENINFO, bytes(160))
        xres, yres, _, _, _, _, bpp = struct.unpack_from("7I", vinfo)
        finfo = fcntl.ioctl(self.fd, FBIOGET_FSCREENINFO, bytes(80))
        # struct fb_fix_screeninfo: char id[16]; unsigned long smem_start; u32 smem_len;
        # u32 type, type_aux, visual; u16 xpanstep, ypanstep, ywrapstep; u32 line_length
        ptr = struct.calcsize("16sL")
        smem_len = struct.unpack_from("I", finfo, ptr)[0]
        self.line_length = struct.unpack_from("I", finfo, ptr + 4 * 4 + 2 * 3 + 2)[0]
        if bpp != 32:
            os.close(self.fd)
            raise OSError(f"framebuffer is {bpp}bpp; KOS needs 32bpp")
        self.width, self.height = xres, yres
        self.mem = mmap.mmap(self.fd, smem_len)
        self.tty_fd = tty_fd
        if tty_fd is not None:
            fcntl.ioctl(tty_fd, KDSETMODE, KD_GRAPHICS)  # stop the text console drawing over us
        self.status = ""

    def show(self, fb: Framebuffer) -> None:
        stride = fb.width * 4
        if self.line_length == stride:
            self.mem[:len(fb.buf)] = fb.buf
        else:
            for y in range(fb.height):
                self.mem[y * self.line_length:y * self.line_length + stride] = \
                    fb.buf[y * stride:(y + 1) * stride]

    def set_status(self, text: str) -> None:
        self.status = text

    def close(self) -> None:
        if self.tty_fd is not None:
            fcntl.ioctl(self.tty_fd, KDSETMODE, KD_TEXT)
        self.mem.close()
        os.close(self.fd)


class GraphicalSurface:
    """What the session draws into in graphical mode."""

    def __init__(self, backend, status_in_frame: bool = False):
        self.backend = backend
        self.scale = max(1, backend.width // 640)
        self.width, self.height = backend.width, backend.height
        self.scene = Framebuffer(self.width, self.height)
        self.scene.clear(parse_color("#000000"))
        self.pointer: Optional[tuple[int, int]] = None
        self.modal: Optional[Modal] = None
        self.status = ""
        self.status_in_frame = status_in_frame
        self.has_content = False

    def hello_size(self) -> tuple[int, int]:
        return self.width, self.height

    def present(self, msg: dict) -> None:
        fb = Framebuffer(self.width, self.height)
        fb.apply(msg["ops"])
        self.scene = fb
        self.has_content = True

    def set_pointer(self, x: int, y: int) -> None:
        self.pointer = (max(0, min(self.width - 1, x)), max(0, min(self.height - 1, y)))

    def set_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal

    def set_status(self, text: str) -> None:
        self.status = text
        self.backend.set_status(text)

    def render(self) -> None:
        out = self.scene.copy()
        if self.status_in_frame and self.status:
            h = font.LINE_HEIGHT * self.scale + 2
            out.rect(0, self.height - h, self.width, h, parse_color("#333333"))
            out.text(2, self.height - h + 1, self.status, parse_color("#ffffff"), self.scale)
        if self.pointer and not self.modal:
            draw_cursor(out, *self.pointer, scale=self.scale)
        if getattr(self.backend, "text_overlay", False):
            self.backend.show(out, self.modal)
            return
        if self.modal:
            draw_modal(out, self.modal, self.scale)
        self.backend.show(out)

    def close(self) -> None:
        self.backend.close()
