"""Raw terminal I/O and a parser that turns terminal bytes into input events.

Events are plain dicts, the same shape the evdev backend produces:
    {"type": "key", "key": "a" | "enter" | "up" | "ctrl-x" | ...}
    {"type": "pointer", "x": col, "y": row}             (0-based cells)
    {"type": "button", "button": "left", "pressed": True, "x": col, "y": row}
    {"type": "scroll", "dy": 1, "x": col, "y": row}
    {"type": "interrupt"}                                (Ctrl-C: OS-reserved)
"""

from __future__ import annotations

import codecs
import os
import re
import termios
import tty

_CSI_KEYS = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end"}
_TILDE_KEYS = {"1": "home", "2": "insert", "3": "delete", "4": "end", "5": "pageup", "6": "pagedown"}
_MOUSE_RE = re.compile(rb"\x1b\[<(\d+);(\d+);(\d+)([Mm])")
_CSI_RE = re.compile(rb"\x1b\[([0-9;]*)([A-Za-z~])")
_SS3_RE = re.compile(rb"\x1bO([A-Za-z])")


class KeyParser:
    def __init__(self) -> None:
        self._buf = b""
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def feed(self, data: bytes) -> list[dict]:
        self._buf += data
        events: list[dict] = []
        b = self._buf
        i = 0
        while i < len(b):
            c = b[i]
            if c == 0x1B:
                rest = b[i:]
                m = _MOUSE_RE.match(rest)
                if m:
                    events.append(_mouse_event(m))
                    i += m.end()
                    continue
                m = _CSI_RE.match(rest)
                if m:
                    params, final = m.group(1).decode(), m.group(2).decode()
                    if final == "~":
                        key = _TILDE_KEYS.get(params.split(";")[0])
                    else:
                        key = _CSI_KEYS.get(final)
                    if key:
                        events.append({"type": "key", "key": key})
                    i += m.end()
                    continue
                m = _SS3_RE.match(rest)
                if m:
                    key = _CSI_KEYS.get(m.group(1).decode())
                    if key:
                        events.append({"type": "key", "key": key})
                    i += m.end()
                    continue
                if len(rest) == 1 or rest[1:2] not in (b"[", b"O"):
                    events.append({"type": "key", "key": "escape"})
                    i += 1
                    continue
                if len(rest) < 32:  # incomplete sequence: wait for more bytes
                    break
                i += 1  # garbage; drop the ESC
                continue
            i += 1
            if c == 0x03:
                events.append({"type": "interrupt"})
            elif c in (0x0D, 0x0A):
                events.append({"type": "key", "key": "enter"})
            elif c in (0x7F, 0x08):
                events.append({"type": "key", "key": "backspace"})
            elif c == 0x09:
                events.append({"type": "key", "key": "tab"})
            elif c < 0x20:
                events.append({"type": "key", "key": "ctrl-" + chr(c + 0x60)})
            else:
                s = self._dec.decode(bytes([c]))
                if s:
                    events.append({"type": "key", "key": s})
        self._buf = b[i:]
        return events


def _mouse_event(m: re.Match) -> dict:
    code, col, row, final = int(m.group(1)), int(m.group(2)) - 1, int(m.group(3)) - 1, m.group(4)
    if code & 64:
        return {"type": "scroll", "dy": 1 if code & 1 else -1, "x": col, "y": row}
    if code & 32:
        return {"type": "pointer", "x": col, "y": row}
    button = {0: "left", 1: "middle", 2: "right"}.get(code & 3, "left")
    return {"type": "button", "button": button, "pressed": final == b"M", "x": col, "y": row}


class RawTerminal:
    """Context manager: raw mode + alternate screen, always restored on exit."""

    def __init__(self, in_fd: int = 0, out_fd: int = 1):
        self.in_fd, self.out_fd = in_fd, out_fd
        self._saved = None
        self.mouse = False

    def write(self, s: str) -> None:
        os.write(self.out_fd, s.encode())

    def size(self) -> tuple[int, int]:
        try:
            sz = os.get_terminal_size(self.out_fd)
            return sz.columns, sz.lines
        except OSError:
            return 80, 24

    def __enter__(self) -> "RawTerminal":
        self._saved = termios.tcgetattr(self.in_fd)
        tty.setraw(self.in_fd)
        self.write("\x1b[?1049h\x1b[?25l\x1b[2J")
        return self

    def enable_mouse(self) -> None:
        self.mouse = True
        # 1000: clicks, 1002: drag, 1003: all motion, 1006: SGR coordinates
        self.write("\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h")

    def __exit__(self, *exc) -> None:
        self.write("\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[0m\x1b[?25h\x1b[?1049l")
        if self._saved is not None:
            termios.tcsetattr(self.in_fd, termios.TCSAFLUSH, self._saved)
