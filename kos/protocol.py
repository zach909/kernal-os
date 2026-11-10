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
    {"cmd": "apps", "installed": [{name, version, description, modes, permitted, kind, extends}],
                    "open": [{id, name, mode, status}]}                  (answer to request apps)
    {"cmd": "extensions", "items": [{name, version, kind, entries: [{label, address}], colors: {..}}],
                          "skipped": [{name, why}]}
                       sent once after hello, only if an extension (for an ordinary app) or a mod (for a
                       system app) was switched on for *this* app with `kos extend`. Data, never code:
                       what to do with it is up to the app. See extensions.py.
    {"cmd": "result", "action": str, "ok": bool, "detail": str, "id": str?}   (answer to a request)
    {"cmd": "assistant", "ok": true, "text": str} | {"cmd": "assistant", "ok": false,
                          "error": "not-configured"|"refused"|"blocked"|"unreachable"|"bad-reply"}   (answer to request assistant)
    {"cmd": "sysinfo", "ok": true, "data": {..}} | {"cmd": "sysinfo", "ok": false,
                          "error": "refused"|"unavailable"}   (answer to request sysinfo)
    {"cmd": "fetch", "ok": true, "status": int, "content_type": str, "body_b64": str} |
    {"cmd": "fetch", "ok": false, "error": "blocked"|"refused"|"unreachable"|"redirect"|"too-big"|"bad-url"}
                                                       (answer to request fetch)
    {"cmd": "vault", "id": N, "ok": bool, "detail": str, "value": str?, "keys": [str]?, "spaces": [..]?}
                                                       (answer to a vault command)
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
    {"cmd": "request", "action": "open", "address": "kos://NAME[/path][?query]", "mode": ...}
                                         the same, as an address (see address.py); the app is told the path
    {"cmd": "request", "action": "focus", "id": INSTANCE}      switch the desktop to an open app
    {"cmd": "request", "action": "close", "id": INSTANCE}
    {"cmd": "request", "action": "assistant", "system": str<=2000,
                       "messages": [{"role": "user"|"assistant", "content": str<=4000}, ...]}
                                         ask the owner's chosen model (needs the narrow 'assistant' permission,
                                         NOT 'system'; the OS asks the password once per app instance and makes
                                         the connection itself - the app gets no network). At most 20 messages,
                                         24000 characters. Anything else is refused.
    {"cmd": "request", "action": "sysinfo", "topic": one of SYSINFO_TOPICS}
                                         read-only facts about this computer, read by the OS (needs the narrow
                                         'sysinfo' permission, NOT 'system'; password once per app instance,
                                         audited). Any other key or topic is refused.
    {"cmd": "request", "action": "firewall", "op": "list"|"log"}   |
    {"cmd": "request", "action": "firewall", "op": "allow", "who": "app:NAME"|"os:...", "host": str, "port": int,
                       "proto": "https"|"loopback"}   |   {... "op": "remove", "who", "host", "port"}
                                         the owner's firewall rules, through the OS (needs the narrow 'firewall'
                                         permission, NOT 'system'). list/log: password once per app instance;
                                         allow/remove: the OS asks the password EVERY time and shows the exact
                                         rule. The wildcard host is refused. Answer: {"cmd": "firewall", "ok":
                                         bool, "rules"|"log"|"detail": ..., "error"?: "refused"|"unavailable"}.
    {"cmd": "request", "action": "credential", "op": "list"}   |   {... "op": "get"|"delete", "label": str}   |
    {... "op": "add", "label", "username", "secret", "url", "notes": all str}
                                         the owner's stored credentials, through the OS (needs the narrow
                                         'credentials' permission, NOT 'system'). list (labels, user names and
                                         URLs only, never a secret): password once per app instance; get (reveals
                                         the secret), add, delete: the OS asks the password EVERY time and shows
                                         the operation and label. Exact keys, str values with length caps and no
                                         control characters. Answer: {"cmd": "credential", "ok": bool,
                                         "entries"|"entry"|"detail": ..., "error"?: "refused"|"unavailable"|
                                         "not-found"|"exists"|"full"}.
    {"cmd": "request", "action": "fetch", "url": "https://HOST[:PORT]/path", "method": "GET"|"POST",
                       "headers": {accept|content-type|authorization|x-api-key|anthropic-version|user-agent: str},
                       "body": str<=262144}
                                         one https request made BY THE OS for the app (needs the narrow
                                         'network' permission, NOT 'system'; the app gets no network). The
                                         firewall decides first (app:NAME, host, port, https); blocked ->
                                         error 'blocked' and nothing is connected. No redirects, 4 MiB reply cap.
    {"cmd": "vault", "id": N, "op": "put"|"get"|"list"|"delete"|"spaces", "key": str?, "value": str?, "space": str?}
                                         durable storage: the app's private data ('storage' permission) or a
                                         shared space (manifest 'owns:NAME'/'uses:NAME' + the owner's grant)
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


MAX_ASSIST_SYSTEM, MAX_ASSIST_CONTENT, MAX_ASSIST_MESSAGES, MAX_ASSIST_TOTAL = 2000, 4000, 20, 24000
_ASSIST_CONTROL_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _assist_text(s: Any, limit: int, what: str) -> str:
    """Strict: too long is refused, not cut. Newlines stay (it is a chat); other control chars go."""
    if not isinstance(s, str) or len(s) > limit:
        raise ProtocolError(f"request.{what} must be text of at most {limit} characters")
    return _ASSIST_CONTROL_RE.sub("", s.replace("\t", " "))


def _assistant(msg: dict) -> dict:
    if set(msg) - {"cmd", "action", "system", "messages"}:
        raise ProtocolError("request.assistant takes only system and messages")
    system = _assist_text(msg.get("system", ""), MAX_ASSIST_SYSTEM, "system")
    messages = msg.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_ASSIST_MESSAGES:
        raise ProtocolError(f"request.messages must be a list of 1 to {MAX_ASSIST_MESSAGES} messages")
    out, total = [], 0
    for m in messages:
        if not isinstance(m, dict) or set(m) != {"role", "content"} or m["role"] not in ("user", "assistant"):
            raise ProtocolError("each message must be {role: user|assistant, content: text}")
        content = _assist_text(m["content"], MAX_ASSIST_CONTENT, "messages content")
        total += len(content)
        out.append({"role": m["role"], "content": content})
    if total > MAX_ASSIST_TOTAL:
        raise ProtocolError(f"request.messages are too long in total (limit {MAX_ASSIST_TOTAL} characters)")
    return {"cmd": "request", "action": "assistant", "system": system, "messages": out}


SYSINFO_TOPICS = ("os", "sandbox", "memory", "load", "storage", "battery", "apps", "network", "settings")   # == sysinfo.TOPICS


def _sysinfo(msg: dict) -> dict:
    topic = msg.get("topic")
    if set(msg) != {"cmd", "action", "topic"} or type(topic) is not str or topic not in SYSINFO_TOPICS:
        raise ProtocolError("request.sysinfo takes only a topic: " + ", ".join(SYSINFO_TOPICS))
    return {"cmd": "request", "action": "sysinfo", "topic": topic}


FIREWALL_OPS = ("list", "log", "allow", "remove")


def _firewall(msg: dict) -> dict:
    """Exact keys per op; every value validated by firewall.check_rule / check_key. An app can never ask for
    the wildcard host: the owner types wildcards on the command line only. ``remove`` has no proto (it
    removes the who+host+port rule, whatever its protocol)."""
    from . import firewall
    op = msg.get("op")
    base = {"cmd", "action", "op"}
    if type(op) is not str or op not in FIREWALL_OPS:
        raise ProtocolError("request.firewall op must be one of " + ", ".join(FIREWALL_OPS))
    if op in ("list", "log"):
        if set(msg) != base:
            raise ProtocolError(f"request.firewall {op} takes only op")
        return {"cmd": "request", "action": "firewall", "op": op}
    keys = base | {"who", "host", "port"} | ({"proto"} if op == "allow" else set())
    if set(msg) != keys:
        raise ProtocolError(f"request.firewall {op} takes exactly: " + ", ".join(sorted(keys - {"cmd", "action"})))
    if msg["host"] == firewall.WILDCARD:
        raise ProtocolError("an app cannot ask for the wildcard host; the owner types it with `kos firewall`")
    try:
        if op == "allow":
            r = firewall.check_rule(msg["who"], msg["host"], msg["port"], msg["proto"])
            return {"cmd": "request", "action": "firewall", "op": op, **r}
        who, host, port = firewall.check_key(msg["who"], msg["host"], msg["port"])
    except firewall.FirewallError as e:
        raise ProtocolError(f"request.firewall: {e}") from None
    return {"cmd": "request", "action": "firewall", "op": op, "who": who, "host": host, "port": port}


def _credential(msg: dict) -> dict:
    """Exact keys per op, str values only, caps and control-character rule from kos.credentials."""
    from . import credentials as C
    op = msg.get("op")
    if type(op) is not str or op not in C.OPS:
        raise ProtocolError("request.credential op must be one of " + ", ".join(C.OPS))
    want = {"list": set(), "get": {"label"}, "delete": {"label"}, "add": set(C.FIELDS)}[op]
    if set(msg) != {"cmd", "action", "op"} | want:
        raise ProtocolError(f"request.credential {op} takes exactly: op" + "".join(", " + k for k in sorted(want)))
    try:
        vals = {k: C.check_field(k, msg[k]) for k in want}
    except C.CredentialError:
        raise ProtocolError("request.credential: a field is not text, is empty, too long or has control characters") from None
    return {"cmd": "request", "action": "credential", "op": op, **vals}


def _fetch(msg: dict) -> dict:
    from . import netfetch
    if set(msg) - {"cmd", "action", "url", "method", "headers", "body"}:
        raise ProtocolError("request.fetch takes only url, method, headers and body")
    url, method = msg.get("url"), msg.get("method", "GET")
    if not isinstance(url, str) or not url or len(url) > netfetch.MAX_URL:
        raise ProtocolError("request.url must be an https URL")
    if method not in netfetch.METHODS:
        raise ProtocolError("request.method must be GET or POST")
    try:
        headers = netfetch.check_headers(msg.get("headers", {}))
    except netfetch.FetchError:
        raise ProtocolError("request.headers: only " + ", ".join(netfetch.HEADER_NAMES) + " with short plain values") from None
    body = msg.get("body", "")
    if not isinstance(body, str) or len(body) > netfetch.MAX_BODY or (body and method != "POST"):
        raise ProtocolError(f"request.body must be text of at most {netfetch.MAX_BODY} characters, and only for POST")
    return {"cmd": "request", "action": "fetch", "url": url, "method": method, "headers": headers, "body": body}


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
            raise ProtocolError("request.mode must be tui, graphical or cmd")
        return {"cmd": "request", "action": "open", "app": app, "mode": mode, "address": launch}
    if action in ("focus", "close"):
        ident = msg.get("id")
        if not isinstance(ident, str) or not _INSTANCE_RE.match(ident):
            raise ProtocolError("request.id must be an open instance id")
        return {"cmd": "request", "action": action, "id": ident}
    if action == "assistant":
        return _assistant(msg)
    if action == "sysinfo":
        return _sysinfo(msg)
    if action == "fetch":
        return _fetch(msg)
    if action == "credential":
        return _credential(msg)
    if action == "firewall":
        return _firewall(msg)
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
    if cmd == "vault":
        return _vault(msg)
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
