"""The command protocol between the OS and an app.

Everything is a command. Your mouse and keyboard produce commands that the OS
sends *to* the app; the app responds with commands the OS executes (draw this
screen, draw these shapes, exit). The app never touches a device, the terminal
or the screen itself.

Transport: newline-delimited JSON over a socket. Every message from an app is
treated as hostile: size-limited, schema-checked, and every string is stripped
of control characters so an app cannot inject terminal escape sequences.

OS -> app
    {"cmd": "hello", "mode": "tui"|"graphical", "width": W, "height": H}
    {"cmd": "key", "key": "a" | "enter" | "backspace" | "up" | ...}
    {"cmd": "pointer", "x": X, "y": Y}
    {"cmd": "button", "button": "left"|"middle"|"right", "pressed": bool, "x": X, "y": Y}
    {"cmd": "scroll", "dy": -1|1, "x": X, "y": Y}
    {"cmd": "device", "device": "mouse"|"keyboard", "state": "attached"}
    {"cmd": "quit"}

app -> OS
    {"cmd": "screen", "title": str, "lines": [str], "status": str}      (tui)
    {"cmd": "frame", "ops": [op, ...]}                                   (graphical)
        op = ["clear", color] | ["rect", x, y, w, h, color]
           | ["line", x0, y0, x1, y1, color] | ["text", x, y, str, color, scale?]
        color = "#rrggbb"
    {"cmd": "log", "msg": str}
    {"cmd": "exit", "code": int}
"""

from __future__ import annotations

import json
import re
import socket
from typing import Any

MAX_LINE = 1 << 20
MAX_LINES = 500
MAX_LINE_CHARS = 1000
MAX_OPS = 5000
MAX_COORD = 16384
_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


class ProtocolError(Exception):
    pass


def clean_text(s: Any, limit: int) -> str:
    if not isinstance(s, str):
        raise ProtocolError("expected a string")
    return _CONTROL_RE.sub("", s)[:limit]


def _int(v: Any, lo: int = -MAX_COORD, hi: int = MAX_COORD) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ProtocolError(f"expected an integer in [{lo}, {hi}]")
    return v


def _color(v: Any) -> str:
    if not isinstance(v, str) or not _COLOR_RE.match(v):
        raise ProtocolError("expected a color like '#1e90ff'")
    return v.lower()


def _op(op: Any) -> list:
    if not isinstance(op, list) or not op:
        raise ProtocolError("draw op must be a non-empty list")
    kind = op[0]
    if kind == "clear" and len(op) == 2:
        return ["clear", _color(op[1])]
    if kind == "rect" and len(op) == 6:
        return ["rect", _int(op[1]), _int(op[2]), _int(op[3], 0), _int(op[4], 0), _color(op[5])]
    if kind == "line" and len(op) == 6:
        return ["line", *(_int(v) for v in op[1:5]), _color(op[5])]
    if kind == "text" and len(op) in (5, 6):
        scale = _int(op[5], 1, 8) if len(op) == 6 else 1
        return ["text", _int(op[1]), _int(op[2]), clean_text(op[3], 256), _color(op[4]), scale]
    raise ProtocolError(f"bad draw op {kind!r}")


def validate_app_message(msg: Any, mode: str) -> dict:
    if not isinstance(msg, dict) or not isinstance(msg.get("cmd"), str):
        raise ProtocolError("message must be an object with a 'cmd'")
    cmd = msg["cmd"]
    if cmd == "screen" and mode == "tui":
        lines = msg.get("lines", [])
        if not isinstance(lines, list) or len(lines) > MAX_LINES:
            raise ProtocolError("screen.lines must be a list of at most 500 strings")
        return {"cmd": "screen",
                "title": clean_text(msg.get("title", ""), 80),
                "lines": [clean_text(l, MAX_LINE_CHARS) for l in lines],
                "status": clean_text(msg.get("status", ""), 200)}
    if cmd == "frame" and mode == "graphical":
        ops = msg.get("ops")
        if not isinstance(ops, list) or len(ops) > MAX_OPS:
            raise ProtocolError("frame.ops must be a list of at most 5000 ops")
        return {"cmd": "frame", "ops": [_op(o) for o in ops]}
    if cmd == "log":
        return {"cmd": "log", "msg": clean_text(msg.get("msg", ""), 2000)}
    if cmd == "exit":
        return {"cmd": "exit", "code": _int(msg.get("code", 0), 0, 255)}
    raise ProtocolError(f"command {cmd!r} not allowed in {mode} mode")


class Channel:
    """Non-blocking JSON-lines endpoint used by the OS side."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sock.setblocking(False)
        self._buf = bytearray()
        self.closed = False

    def fileno(self) -> int:
        return self.sock.fileno()

    def send(self, obj: dict) -> None:
        if self.closed:
            return
        data = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        try:
            self.sock.setblocking(True)
            self.sock.settimeout(2.0)
            self.sock.sendall(data)
        except OSError:
            self.closed = True
        finally:
            if not self.closed:
                self.sock.setblocking(False)

    def receive(self) -> list[Any]:
        """Read whatever is available; returns decoded (unvalidated) messages."""
        try:
            chunk = self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return []
        except OSError:
            chunk = b""
        if not chunk:
            self.closed = True
        self._buf += chunk
        out = []
        while True:
            i = self._buf.find(b"\n")
            if i < 0:
                break
            line = bytes(self._buf[:i])
            del self._buf[:i + 1]
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    raise ProtocolError("app sent invalid JSON") from None
        if len(self._buf) > MAX_LINE:
            raise ProtocolError("app sent an oversized message")
        return out

    def close(self) -> None:
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass
