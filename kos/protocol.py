"""The command protocol between the OS and an app.

Everything is a command. Your mouse and keyboard produce commands that the OS
sends *to* the app; the app responds with commands the OS executes (draw this
screen, draw these shapes, exit). The app never touches a device, the terminal
or the screen itself.

Transport: newline-delimited JSON over a socket. Every message from an app is
treated as hostile: size-limited, schema-checked, and every string is stripped
of control characters so an app cannot inject terminal escape sequences.

OS -> app
    {"cmd": "hello", "mode": "tui"|"graphical"|"text"|"cmd", "width": W, "height": H}
        (text mode: W, H are the drawing area in the app's own pixels, CELL_W x CELL_H per character cell;
         a click is reported at the pixel in the middle of the cell it landed on - see textdraw.py)
    {"cmd": "key", "key": "a" | "enter" | "backspace" | "up" | ...}
    {"cmd": "pointer", "x": X, "y": Y}
    {"cmd": "button", "button": "left"|"middle"|"right", "pressed": bool, "x": X, "y": Y}
    {"cmd": "scroll", "dy": -1|1, "x": X, "y": Y}
    {"cmd": "device", "device": "mouse"|"keyboard", "state": "attached"}
    {"cmd": "apps", "installed": [{name, version, description, modes, permitted, kind, extends}],
                    "open": [{id, name, mode, status}]}                  (answer to request apps)
    {"cmd": "extensions", "items": [{name, version, kind, entries: [{label, address}], colors: {..}}],
                          "skipped": [{name, why}]}
                       sent once after hello, only if an extension (for an ordinary app) or a mod (for a
                       system app) was switched on for *this* app with `kos extend`. Data, never code:
                       what to do with it is up to the app. See extensions.py.
    {"cmd": "answer", "ok": bool, "lines": [str], "model": str, "detail": str}              (answer to request ask)
    {"cmd": "result", "action": str, "ok": bool, "detail": str, "id": str?}   (answer to a request)
    {"cmd": "vault", "id": N, "ok": bool, "detail": str, "value": str?, "keys": [str]?, "spaces": [..]?}
                                                       (answer to a vault command)
    {"cmd": "service", "id": N, "ok": bool, "detail": str, "data": {..}}
                                                       (answer to a service call; see servicespec.py)
    {"cmd": "quit"}

app -> OS
    {"cmd": "screen", "title": str, "lines": [str], "status": str}      (tui)
    {"cmd": "frame", "ops": [op, ...]}                                   (graphical, text: same ops)
        op = ["clear", color] | ["rect", x, y, w, h, color]
           | ["line", x0, y0, x1, y1, color] | ["text", x, y, str, color, scale?]
        color = "#rrggbb"
    {"cmd": "log", "msg": str}
    {"cmd": "request", "action": "apps"}                       list installed + open apps
    {"cmd": "request", "action": "open", "app": NAME, "mode": "tui"|"graphical"|"text"|"cmd"}
    {"cmd": "request", "action": "open", "address": "kos://NAME[/path][?query]", "mode": ...}
                                         the same, as an address (see address.py); the app is told the path
    {"cmd": "request", "action": "focus", "id": INSTANCE}      switch the desktop to an open app
    {"cmd": "request", "action": "close", "id": INSTANCE}
    {"cmd": "request", "action": "ask", "text": str, "context": str?, "source": str?}
                                         ask the AI (needs the 'ai' permission; the OS asks for the
                                         password and says what leaves the computer). The answer is text.
    {"cmd": "vault", "id": N, "op": "put"|"get"|"list"|"delete"|"spaces", "key": str?, "value": str?, "space": str?, "store": "cookies"|"passwords"?}
                                         durable storage: the app's private data ('storage' permission) or a
                                         shared space (manifest 'owns:NAME'/'uses:NAME' + the owner's grant)
    {"cmd": "service", "id": N, "name": "audit.tail", "args": {..}}
                                         ask the OS for one of the functions in servicespec.SPECS (the audit log, the
                                         security check, the firewall, ...). Needs the manifest permission
                                         ``service:GROUP``; the password, where one is needed, is typed in the OS's
                                         own prompt. Every argument is checked against the spec; none is trusted.
                                         shared space (manifest 'owns:NAME'/'uses:NAME' + the owner's grant), or - with "store" - the app's
                                         cookie jar ('cookies' permission) or saved passwords ('passwords'
                                         permission): separate stores, never reachable through 'storage'
    {"cmd": "exit", "code": int}

``request`` is how an app does anything beyond drawing: it *asks*. The OS only
listens if the app's manifest has the ``system`` permission, the app was
permitted to run, and - for anything that starts or stops something - the owner
types the password in the OS's own prompt.
"""

from __future__ import annotations

import functools
import json
import re
import socket
from typing import Any

from .address import AddressError, parse as parse_address
from .servicespec import SPECS, SpecError
from .kapp import ID_RE, INSTANCE_RE

MAX_LINE = 1 << 20
MAX_LINES = 500
MAX_LINE_CHARS = 1000
MAX_OPS = 5000
MAX_COORD = 16384
_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_APP_NAME_RE = ID_RE
_INSTANCE_RE = INSTANCE_RE
REQUEST_MODES = ("tui", "graphical", "text", "cmd")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


class ProtocolError(Exception):
    pass


def clean_text(s: Any, limit: int) -> str:
    if not isinstance(s, str):
        raise ProtocolError("expected a string")
    return _CONTROL_RE.sub("", s)[:limit]


def escape_text(s: str, limit: int = 4096) -> str:
    """Make untrusted text safe to print on the owner's terminal.

    Unlike :func:`clean_text` nothing is dropped: each control or bidi character
    becomes a visible ``\\xNN`` / ``\\uNNNN``. A hostile file or zip-entry name
    therefore cannot move the cursor, clear the screen or fake a password prompt
    - and cannot pass for a different name either."""
    return _CONTROL_RE.sub(
        lambda m: "\\x%02x" % ord(m.group()) if ord(m.group()) < 0x100 else "\\u%04x" % ord(m.group()),
        str(s))[:limit]


def _int(v: Any, lo: int = -MAX_COORD, hi: int = MAX_COORD) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise ProtocolError(f"expected an integer in [{lo}, {hi}]")
    return v


@functools.lru_cache(maxsize=4096)
def _color_str(v: str) -> str:
    if not _COLOR_RE.match(v):
        raise ProtocolError("expected a color like '#1e90ff'")
    return v.lower()


def _color(v: Any) -> str:
    # Frames repeat a handful of colours thousands of times; validate each once.
    if not isinstance(v, str):
        raise ProtocolError("expected a color like '#1e90ff'")
    return _color_str(v)


def _op(op: Any) -> list:
    if not isinstance(op, list) or not op:
        raise ProtocolError("draw op must be a non-empty list")
    kind = op[0]
    if kind == "clear" and len(op) == 2:
        return ["clear", _color(op[1])]
    if kind == "rect" and len(op) == 6:
        _, x, y, w, h, c = op
        if (type(x) is int and type(y) is int and type(w) is int and type(h) is int
                and -MAX_COORD <= x <= MAX_COORD and -MAX_COORD <= y <= MAX_COORD
                and 0 <= w <= MAX_COORD and 0 <= h <= MAX_COORD):
            return ["rect", x, y, w, h, _color(c)]
        return ["rect", _int(x), _int(y), _int(w, 0), _int(h, 0), _color(c)]
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
        mode, launch = msg.get("mode", "tui"), ""
        if "address" in msg:
            if "app" in msg:
                raise ProtocolError("request.open takes an app or an address, not both")
            try:
                addr = parse_address(msg["address"])
            except AddressError as e:
                raise ProtocolError(f"request.address: {e}") from None
            app, launch, mode = addr.app, addr.launch, addr.mode or mode
        else:
            app = msg.get("app")
        if not isinstance(app, str) or not _APP_NAME_RE.match(app):
            raise ProtocolError("request.app must be an app name")
        if mode not in REQUEST_MODES:
            raise ProtocolError("request.mode must be tui, graphical, text or cmd")
        return {"cmd": "request", "action": "open", "app": app, "mode": mode, "address": launch}
    if action in ("focus", "close"):
        ident = msg.get("id")
        if not isinstance(ident, str) or not _INSTANCE_RE.match(ident):
            raise ProtocolError("request.id must be an open instance id")
        return {"cmd": "request", "action": action, "id": ident}
    if action == "ask":
        from . import ai
        extra = set(msg) - {"cmd", "action", "text", "context", "source"}
        if extra:
            raise ProtocolError(f"request.ask has no field {sorted(extra)[0]!r}")
        for k in ("context", "source"):
            if k in msg and not isinstance(msg[k], str):
                raise ProtocolError(f"request.{k} must be text")
        if not isinstance(msg.get("text"), str):
            raise ProtocolError("request.text must be text")
        if len(msg["text"]) > ai.MAX_QUESTION or len(msg.get("context", "")) > ai.MAX_CONTEXT:
            raise ProtocolError("request.ask is too long")
        return {"cmd": "request", "action": "ask", "text": clean_text(msg["text"], ai.MAX_QUESTION),
                "context": clean_text(msg.get("context", ""), ai.MAX_CONTEXT),
                "source": clean_text(msg.get("source", ""), ai.MAX_SOURCE)}
    if action == "backup":
        return {"cmd": "request", "action": "backup"}
    if action == "backup_add":
        path = msg.get("path")
        if not isinstance(path, str) or not path or len(path) > 1024 or "\x00" in path:
            raise ProtocolError("request.path must be a file or folder path")
        return {"cmd": "request", "action": "backup_add", "path": path}
    if action == "backup_remove":
        ident = msg.get("id")
        if not isinstance(ident, str) or not re.fullmatch(r"[0-9a-f]{12}", ident):
            raise ProtocolError("request.id must be a backup item id")
        return {"cmd": "request", "action": "backup_remove", "id": ident}
    raise ProtocolError(f"unknown request {action!r}")


VAULT_OPS = ("put", "get", "list", "delete", "spaces")
VAULT_STORES = ("cookies", "passwords")
_SPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_VAULT_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_VAULT_VALUE = 400_000


def _vault(msg: dict) -> dict:
    op, ident = msg.get("op"), msg.get("id")
    if op not in VAULT_OPS:
        raise ProtocolError(f"vault.op must be one of {VAULT_OPS}")
    ident = _int(ident, 0, 2**31)
    out = {"cmd": "vault", "op": op, "id": ident}
    if msg.get("space") is not None:
        if not isinstance(msg["space"], str) or not _SPACE_RE.match(msg["space"]) or op == "spaces":
            raise ProtocolError("vault.space must be a plain space name (and not used with 'spaces')")
        out["space"] = msg["space"]
    if msg.get("store") is not None:
        if msg["store"] not in VAULT_STORES or op == "spaces" or "space" in out:
            raise ProtocolError(f"vault.store must be one of {VAULT_STORES} (not used with 'space' or 'spaces')")
        out["store"] = msg["store"]
    if op not in ("list", "spaces"):
        key = msg.get("key")
        if not isinstance(key, str) or not _VAULT_KEY_RE.match(key):
            raise ProtocolError("vault.key must be a plain lowercase name")
        out["key"] = key
    if op == "put":
        value = msg.get("value")
        if not isinstance(value, str) or len(value) > MAX_VAULT_VALUE:
            raise ProtocolError("vault.value must be text")
        out["value"] = value        # data, never displayed by the OS: not stripped
    return out


def _service(msg: dict) -> dict:
    name, ident = msg.get("name"), _int(msg.get("id"), 0, 2**31)
    spec = SPECS.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ProtocolError("service.name is not a service")
    try:
        args = spec.check(msg.get("args", {}))
    except SpecError as e:
        raise ProtocolError(f"service.args: {e}") from None
    return {"cmd": "service", "id": ident, "name": name, "args": args}


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
    if cmd == "frame" and mode in ("graphical", "text"):
        ops = msg.get("ops")
        if not isinstance(ops, list) or len(ops) > MAX_OPS:
            raise ProtocolError("frame.ops must be a list of at most 5000 ops")
        return {"cmd": "frame", "ops": [_op(o) for o in ops]}
    if cmd == "log":
        return {"cmd": "log", "msg": clean_text(msg.get("msg", ""), 2000)}
    if cmd == "request":
        return _request(msg)
    if cmd == "vault":
        return _vault(msg)
    if cmd == "service":
        return _service(msg)
    if cmd == "exit":
        return {"cmd": "exit", "code": _int(msg.get("code", 0), 0, 255)}
    raise ProtocolError(f"command {cmd!r} not allowed in {mode} mode")


def _no_decimal(token: str):
    """The no-decimals rule on the wire: a number with a point or exponent, or NaN/Infinity,
    is refused before any validator sees it (the protocol only ever carries whole numbers)."""
    raise ValueError("decimal number")


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
        data = json.dumps(obj, separators=(",", ":"), allow_nan=False).encode() + b"\n"
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
                    out.append(json.loads(line, parse_float=_no_decimal, parse_constant=_no_decimal))
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
