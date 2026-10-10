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
    {"cmd": "apps", "installed": [{name, version, description, modes, permitted}],
                    "open": [{id, name, mode, status}]}                  (answer to request apps)
    {"cmd": "result", "action": str, "ok": bool, "detail": str, "id": str?}   (answer to a request)
    {"cmd": "info", "admin": str, "kernel": [str], "owed": [str], "audit": [str], "permits": [str]}
    {"cmd": "listing", "path": str, "entries": [{name, kind: dir|zip|file}]}
    {"cmd": "text", "action": str, "title": str, "lines": [str], "lossy": bool?}
    {"cmd": "backups", "backups": [{name, path, size, t, files}], "remote": str}
    {"cmd": "quit"}

app -> OS
    {"cmd": "screen", "title": str, "lines": [str], "status": str}      (tui)
    {"cmd": "frame", "ops": [op, ...]}                                   (graphical)
        op = ["clear", color] | ["rect", x, y, w, h, color]
           | ["line", x0, y0, x1, y1, color] | ["text", x, y, str, color, scale?]
        color = "#rrggbb"
    {"cmd": "log", "msg": str}
    {"cmd": "request", "action": "apps"}                       list installed + open apps
    {"cmd": "request", "action": "open", "app": NAME, "mode": "tui"|"graphical"|"cmd"}
    {"cmd": "request", "action": "focus", "id": INSTANCE}      switch the desktop to an open app
    {"cmd": "request", "action": "close", "id": INSTANCE}
    {"cmd": "request", "action": "info"}                       kernel/admin/owed/audit facts
    {"cmd": "request", "action": "ls", "path": PATH}           names in a directory or zip
    {"cmd": "request", "action": "view", "path": PATH}         file text (password first)
    {"cmd": "request", "action": "scan", "path": PATH}         security-scan a file or zip
    {"cmd": "request", "action": "optimize" | "settle"}        (password first)
    {"cmd": "request", "action": "permit" | "revoke", "app": NAME}   (password first)
    {"cmd": "request", "action": "line", "text": LINE}         one line of the line shell
    {"cmd": "request", "action": "save", "path": PATH, "text": TEXT}   guarded write (admin keyboard + password)
    {"cmd": "request", "action": "backup", "path": PATH}       back a file/folder up (password)
    {"cmd": "request", "action": "backups"}                    list backups
    {"cmd": "request", "action": "push", "backup": ZIP}        push a backup to the user's OWN private GitHub (password)
    {"cmd": "request", "action": "remote", "url": URL}         set that GitHub repository (password; github.com only)
    {"cmd": "request", "action": "restore", "backup": ZIP, "member": PATH, "to": PATH}   guarded write
    {"cmd": "exit", "code": int}

``request`` is how an app does anything beyond drawing: it *asks*. The OS only
listens if the app's manifest has the ``system`` permission, the app was
permitted to run, and - for anything that starts or stops something - the owner
types the password in the OS's own prompt.
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
_APP_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_INSTANCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}-[0-9a-f]{6}$")
REQUEST_MODES = ("tui", "graphical", "cmd")
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


def _request(msg: dict) -> dict:
    action = msg.get("action")
    if action == "apps":
        return {"cmd": "request", "action": "apps"}
    if action == "open":
        app, mode = msg.get("app"), msg.get("mode", "tui")
        if not isinstance(app, str) or not _APP_NAME_RE.match(app):
            raise ProtocolError("request.app must be an app name")
        if mode not in REQUEST_MODES:
            raise ProtocolError("request.mode must be tui, graphical or cmd")
        return {"cmd": "request", "action": "open", "app": app, "mode": mode}
    if action in ("focus", "close"):
        ident = msg.get("id")
        if not isinstance(ident, str) or not _INSTANCE_RE.match(ident):
            raise ProtocolError("request.id must be an open instance id")
        return {"cmd": "request", "action": action, "id": ident}
    if action in ("info", "optimize", "settle"):
        return {"cmd": "request", "action": action}
    if action in ("ls", "view", "scan"):
        path = msg.get("path", "/")
        if not isinstance(path, str) or not path or len(path) > 1024 or "\x00" in path:
            raise ProtocolError("request.path must be a path")
        return {"cmd": "request", "action": action, "path": path}
    if action in ("permit", "revoke"):
        app = msg.get("app")
        if not isinstance(app, str) or not _APP_NAME_RE.match(app):
            raise ProtocolError("request.app must be an app name")
        return {"cmd": "request", "action": action, "app": app}
    if action == "line":
        return {"cmd": "request", "action": "line", "text": clean_text(msg.get("text", ""), 500)}
    if action == "backups":
        return {"cmd": "request", "action": "backups"}
    if action == "remote":
        url = msg.get("url")
        if not isinstance(url, str) or not url or len(url) > 300 or "\x00" in url:
            raise ProtocolError("remote.url must be a repository URL")
        return {"cmd": "request", "action": "remote", "url": url}
    if action == "push":
        b = msg.get("backup")
        if not isinstance(b, str) or not _BACKUP_RE.match(b):
            raise ProtocolError("push.backup must be a backup name")
        return {"cmd": "request", "action": "push", "backup": b}
    if action in ("save", "backup", "restore"):
        return _file_request(action, msg)
    raise ProtocolError(f"unknown request {action!r}")


_BACKUP_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}\.zip$")
MAX_SAVE = 256 << 10
_BAD_TEXT_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _path(v: Any) -> str:
    if not isinstance(v, str) or not v or len(v) > 1024 or "\x00" in v:
        raise ProtocolError("expected a path")
    return v


def _file_request(action: str, msg: dict) -> dict:
    if action == "backup":
        return {"cmd": "request", "action": "backup", "path": _path(msg.get("path"))}
    if action == "save":
        text = msg.get("text")
        if not isinstance(text, str) or len(text) > MAX_SAVE or _BAD_TEXT_RE.search(text):
            raise ProtocolError("save.text must be plain text of at most 256 KiB")
        return {"cmd": "request", "action": "save", "path": _path(msg.get("path")), "text": text}
    backup = msg.get("backup")
    if not isinstance(backup, str) or not _BACKUP_RE.match(backup):
        raise ProtocolError("restore.backup must be a backup name")
    member = _path(msg.get("member"))
    return {"cmd": "request", "action": "restore", "backup": backup, "member": member,
            "to": _path(msg.get("to"))}


def validate_app_message(msg: Any, mode: str) -> dict:
    if not isinstance(msg, dict) or not isinstance(msg.get("cmd"), str):
        raise ProtocolError("message must be an object with a 'cmd'")
    cmd = msg["cmd"]
    if mode == "cmd" and cmd in ("screen", "frame"):
        raise ProtocolError("cmd mode has no drawing surface; use log")
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
    if cmd == "request":
        return _request(msg)
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
