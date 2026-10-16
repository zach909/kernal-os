"""The command protocol between the OS and an app.

Everything is a command. Your mouse and keyboard produce commands that the OS
sends *to* the app; the app responds with commands the OS executes (draw this
screen, draw these shapes, exit). The app never touches a device, the terminal
or the screen itself.

Transport: newline-delimited JSON over a socket. Every message from an app is
treated as hostile: size-limited, schema-checked, and every string is stripped
of control characters so an app cannot inject terminal escape sequences.

OS -> app
    {"cmd": "hello", "mode": "tui"|"graphical", "width": W, "height": H, "scale": N?, "insets": [l,t,r,b]?, "font": {sans|bold|mono: {adv,asc,desc}}?}
    {"cmd": "tick", "t": epoch, "local": {year, month, day, hour, minute, second, weekday, yday, zone, offset}}
    {"cmd": "widgets", "widgets": [{name, title, visible}], "order": [NAME]}   (the widget handler)
    {"cmd": "windows", "windows": [{id, name, title, focused, minimized}], "desktop": ID, "focus": ID}   (desktop shell)
    {"cmd": "launch", "command": ID, "line": str?}      (opened to run one of its own commands)
    {"cmd": "focus"}                                     (the desktop shell wants the desktop's search box)
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
    {"cmd": "sys", "kind": str, "data": object}
    {"cmd": "updates", "op": str, "data": object}
    {"cmd": "tick", "t": epoch}                                (apps with the 'ticks' permission, 1/s)
    {"cmd": "backups", "backups": [{name, path, size, t, files}], "remote": str}
    {"cmd": "quit"}

app -> OS
    {"cmd": "screen", "title": str, "lines": [str], "status": str}      (tui)
    {"cmd": "frame", "ops": [op, ...]}                                   (graphical)
        op = ["clear", color] | ["rect", x, y, w, h, color]
           | ["line", x0, y0, x1, y1, color] | ["text", x, y, str, color, scale?]
           | ["stext", x, y, str, color, px, face?]     smooth text, face 0 sans / 1 bold / 2 mono
           | ["poly", [[x, y], ...], color, alpha?]      smooth (anti-aliased) filled shape, alpha 0-255, up to 64 points
           | ["blit", x, y, w, h, scale, base64]        raw RGB pixels (w*h*3 bytes, at most 96000 pixels), drawn
                                                       scale times larger - a camera preview, say
           | ["hit", x, y, w, h, label]                 draws nothing: declares a clickable control, so the
                                                       interface can be listed, tabbed through, or shown as text
        color = "#rrggbb"
    {"cmd": "log", "msg": str}
    {"cmd": "request", "action": "apps"}                       list installed + open apps
    {"cmd": "request", "action": "open", "app": NAME, "mode": "tui"|"graphical"|"cmd", "command": ID?, "line": TEXT?,
         "new": bool?, "background": bool?}           new: another instance; background: open minimized, no focus
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
    {"cmd": "request", "action": "sys", "kind": KIND, "arg": str?}   read-only OS facts (see osinfo.KINDS)
    {"cmd": "request", "action": "signal", "pid": N, "sig": "TERM"|"KILL"|"STOP"|"CONT"}   (password)
    {"cmd": "request", "action": "renice", "pid": N, "nice": 0..19}   (password)
    {"cmd": "request", "action": "animate", "on": bool}      (animate permission) ask for / stop ~24 'anim' events a second
    {"cmd": "request", "action": "look", "op": "get"|"set", "look": normal|3d|vr|mr|neural|text|terminal, "cursor_direction"|"tilt"|"bubbles": bool}   (shell permission to set)
    {"cmd": "request", "action": "intent", "name": next|prev|select|back|pause}   (neural permission, neural look only) one decision
                                                              a neural driver made from the wearer's signals - never the signals
    {"cmd": "request", "action": "links", "op": "list"|"add"|"remove", "kind", "target", "title", "where": shelf|desktop, "id"}
    {"cmd": "request", "action": "openlink", "id": ID}      open a pinned link (the OS looks up what it points to)
    {"cmd": "request", "action": "workspace", "n": 0..3, "id": WINDOW?}   (shell permission) switch desktop, or move a window to one
    {"cmd": "request", "action": "tab", "name": "notifications"|"widgets"}   (shell permission) the sidebar's tab
    {"cmd": "request", "action": "toggle", "app": NAME}      (shell permission) show or hide an interface app's layer
    {"cmd": "request", "action": "notify", "op": "post"|"clear"|"dismiss", "title": str, "body": str, "id"}   notifications (posting is rate-limited)
    {"cmd": "request", "action": "keys", "on": bool}         (shell permission) take the keyboard for a text box until a click elsewhere
    {"cmd": "request", "action": "quantum", "op": "devices"|"run", "driver", "device", "program": OpenQASM, "shots", "seed"}
    {"cmd": "request", "action": "autoupdate", "op": "status"|"refresh"|"set"|"run", "enabled", "mode": ask|auto, "every_hours", "scheduled"}
    {"cmd": "request", "action": "heal", "op": "check"|"fix"}   look for broken state / repair it (password for the parts that need it)
    {"cmd": "request", "action": "mods", "op": "list"|"enable"|"disable", "name": APP}   system mods (password to change)
    {"cmd": "request", "action": "sudo", "op": "status"|"open"|"close", "minutes": 1..60, "layers": [..]}
                                                       remember the password for a while (password to open)
    {"cmd": "request", "action": "policy", "op": "get"|"set", "interface": "required"|"off"}   (password to set)
    {"cmd": "request", "action": "fschange", "op": "mkdir"|"trash"|"rename"|"chmod", "path": P, ...}   (admin keyboard + password)
    {"cmd": "request", "action": "netcheck"}                   test the internet (password)
    {"cmd": "request", "action": "resize", "w": N?, "h": N?}   (shell permission) change my own layer's size
    {"cmd": "request", "action": "layout", "order": [NAME], "hidden": [NAME]}   (shell permission) arrange the widgets
    {"cmd": "request", "action": "updates", "op": OP, ...}     where software comes from + updates:
        op = provenance (read-only) | check (password; network) | install NAME [permissions] (password)
           | install_all | core (password) | source_add NAME KIND LOCATION | source_remove NAME (password)
    {"cmd": "request", "action": "remote", "url": URL}         set that GitHub repository (password; github.com only)
    {"cmd": "request", "action": "restore", "backup": ZIP, "member": PATH, "to": PATH}   guarded write
    {"cmd": "exit", "code": int}

``request`` is how an app does anything beyond drawing: it *asks*. The OS only
listens if the app's manifest has the ``system`` permission, the app was
permitted to run, and - for anything that starts or stops something - the owner
types the password in the OS's own prompt.
"""

from __future__ import annotations

import base64
import json
import re
import socket
from typing import Any

INTENTS = ("next", "prev", "select", "back", "pause")      # what a neural driver may say: never raw signals
MAX_LINE = 1 << 20
MAX_LINES = 500
MAX_LINE_CHARS = 1000
MAX_OPS = 12000
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
    if kind == "stext" and len(op) in (5, 6, 7):
        face = _int(op[6], 0, 2) if len(op) == 7 else 0
        return ["stext", _int(op[1]), _int(op[2]), clean_text(op[3], 256), _color(op[4]),
                _int(op[5], 6, 120) if len(op) >= 6 else 14, face]
    if kind == "poly" and len(op) in (3, 4):
        pts = op[1]
        if not isinstance(pts, list) or not 3 <= len(pts) <= 64:
            raise ProtocolError("a poly needs 3 to 64 points")
        clean = []
        for p in pts:
            if not (isinstance(p, list) and len(p) == 2 and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in p)):
                raise ProtocolError("poly points are [x, y] numbers")
            clean.append([round(max(-8192.0, min(8192.0, float(v))), 2) for v in p])
        return ["poly", clean, _color(op[2]), _int(op[3], 0, 255) if len(op) == 4 else 255]
    if kind == "blit" and len(op) == 7:
        w, h, scale = _int(op[3], 1, 640), _int(op[4], 1, 640), _int(op[5], 1, 32)
        if w * h > 96000:
            raise ProtocolError("a blit is at most 96000 pixels")
        try:
            raw = base64.b64decode(op[6], validate=True) if isinstance(op[6], str) else b""
        except ValueError:
            raise ProtocolError("blit pixels must be base64") from None
        if len(raw) != w * h * 3:
            raise ProtocolError("blit needs exactly width*height*3 bytes")
        return ["blit", _int(op[1]), _int(op[2]), w, h, scale, op[6]]
    if kind == "hit" and len(op) == 6:
        return ["hit", _int(op[1]), _int(op[2]), _int(op[3], 0), _int(op[4], 0), clean_text(op[5], 60)]
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
        out = {"cmd": "request", "action": "open", "app": app, "mode": mode}
        for flag in ("new", "background"):
            if flag in msg:
                if not isinstance(msg[flag], bool):
                    raise ProtocolError(f"open.{flag} must be true or false")
                out[flag] = msg[flag]
        command = msg.get("command")
        if command is not None:
            if not isinstance(command, str) or not _COMMAND_RE.match(command):
                raise ProtocolError("request.command must be a command id")
            out["command"] = command
        if msg.get("line") is not None:
            out["line"] = clean_text(msg["line"], 200)
        return out
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
    if action == "sys":
        from .osinfo import KINDS
        kind = msg.get("kind")
        if kind not in KINDS:
            raise ProtocolError(f"sys.kind must be one of {sorted(KINDS)}")
        arg = msg.get("arg", "")
        if not isinstance(arg, str) or len(arg) > 1024 or "\x00" in arg:
            raise ProtocolError("sys.arg must be a short string")
        return {"cmd": "request", "action": "sys", "kind": kind, "arg": arg}
    if action in ("signal", "renice"):
        pid = msg.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or not 2 <= pid <= 4194304:
            raise ProtocolError("pid must be an integer")
        if action == "signal":
            if msg.get("sig") not in ("TERM", "KILL", "STOP", "CONT"):
                raise ProtocolError("sig must be TERM, KILL, STOP or CONT")
            return {"cmd": "request", "action": "signal", "pid": pid, "sig": msg["sig"]}
        return {"cmd": "request", "action": "renice", "pid": pid, "nice": _int(msg.get("nice"), 0, 19)}
    if action == "netcheck":
        return {"cmd": "request", "action": "netcheck"}
    if action == "resize":
        out = {"cmd": "request", "action": "resize"}
        for k in ("w", "h"):
            if k in msg:
                out[k] = _int(msg[k], 1, 8192)
        return out
    if action == "layout":
        names = {}
        for k in ("order", "hidden"):
            v = msg.get(k, [])
            if (not isinstance(v, list) or len(v) > 24
                    or not all(isinstance(n, str) and _APP_NAME_RE.match(n) for n in v)):
                raise ProtocolError(f"layout.{k} must be a list of widget names")
            names[k] = v
        return {"cmd": "request", "action": "layout", **names}
    if action == "updates":
        op = msg.get("op")
        if op not in ("provenance", "check", "install", "install_all", "core", "source_add", "source_remove"):
            raise ProtocolError("unknown updates op")
        out = {"cmd": "request", "action": "updates", "op": op}
        if op in ("install", "source_add", "source_remove"):
            name = msg.get("name")
            if not isinstance(name, str) or not _APP_NAME_RE.match(name):
                raise ProtocolError("updates.name must be a name")
            out["name"] = name
        if op == "install":
            out["permissions"] = msg.get("permissions") is True
        if op == "source_add":
            kind, loc = msg.get("kind"), msg.get("location")
            if kind not in ("folder", "https", "github"):
                raise ProtocolError("updates.kind must be folder, https or github")
            if not isinstance(loc, str) or not loc or len(loc) > 300 or "\x00" in loc:
                raise ProtocolError("updates.location must be a short string")
            out.update(kind=kind, location=loc)
        return out
    if action == "fschange":
        op = msg.get("op")
        if op not in ("mkdir", "trash", "rename", "chmod"):
            raise ProtocolError("fschange.op must be mkdir, trash, rename or chmod")
        out = {"cmd": "request", "action": "fschange", "op": op, "path": _path(msg.get("path"))}
        if op == "rename":
            out["to"] = _path(msg.get("to"))
        if op == "chmod":
            mode = msg.get("mode")
            if not isinstance(mode, str) or not re.match(r"^[0-7]{3,4}$", mode):
                raise ProtocolError("fschange.mode must be octal like 644")
            out["mode"] = mode
        return out
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
    if action == "animate":
        on = msg.get("on")
        if not isinstance(on, bool):
            raise ProtocolError("animate.on must be true or false")
        return {"cmd": "request", "action": "animate", "on": on}
    if action == "look":
        op = msg.get("op", "get")
        if op not in ("get", "set"):
            raise ProtocolError("look.op must be get or set")
        out = {"cmd": "request", "action": "look", "op": op}
        if op == "set":
            if "look" in msg:
                if msg["look"] not in ("normal", "3d", "vr", "mr", "neural", "text", "terminal"):
                    raise ProtocolError("look.look must be normal, 3d, vr, mr, neural, text or terminal")
                out["look"] = msg["look"]
            for k in ("cursor_direction", "tilt", "bubbles"):
                if k in msg:
                    if not isinstance(msg[k], bool):
                        raise ProtocolError(f"look.{k} must be true or false")
                    out[k] = msg[k]
        return out
    if action == "intent":
        if msg.get("name") not in INTENTS:
            raise ProtocolError(f"intent.name must be one of {', '.join(INTENTS)}")
        return {"cmd": "request", "action": "intent", "name": msg["name"]}
    if action == "links":
        op = msg.get("op", "list")
        if op not in ("list", "add", "remove"):
            raise ProtocolError("links.op must be list, add or remove")
        out = {"cmd": "request", "action": "links", "op": op}
        if op == "add":
            if msg.get("kind") not in ("app", "file", "folder", "url"):
                raise ProtocolError("links.kind must be app, file, folder or url")
            if msg.get("where", "shelf") not in ("shelf", "desktop"):
                raise ProtocolError("links.where must be shelf or desktop")
            out.update(kind=msg["kind"], target=clean_text(msg.get("target", ""), 1024),
                       title=clean_text(msg.get("title", ""), 40), where=msg.get("where", "shelf"))
        if op == "remove":
            lid = msg.get("id")
            if not isinstance(lid, str) or not re.match(r"^[0-9a-f]{10}$", lid):
                raise ProtocolError("links.id must be a link id")
            out["id"] = lid
        return out
    if action == "openlink":
        lid = msg.get("id")
        if not isinstance(lid, str) or not re.match(r"^[0-9a-f]{10}$", lid):
            raise ProtocolError("openlink.id must be a link id")
        return {"cmd": "request", "action": "openlink", "id": lid}
    if action == "workspace":
        out = {"cmd": "request", "action": "workspace", "n": _int(msg.get("n"), 0, 3)}
        if "id" in msg:
            if not isinstance(msg["id"], str) or not re.match(r"^[a-z0-9-]{1,80}$", msg["id"]):
                raise ProtocolError("workspace.id must be a window id")
            out["id"] = msg["id"]
        return out
    if action == "tab":
        if msg.get("name") not in ("notifications", "widgets"):
            raise ProtocolError("tab.name must be notifications or widgets")
        return {"cmd": "request", "action": "tab", "name": msg["name"]}
    if action == "toggle":
        app = msg.get("app")
        if not isinstance(app, str) or not _APP_NAME_RE.match(app):
            raise ProtocolError("toggle.app must be an app name")
        return {"cmd": "request", "action": "toggle", "app": app}
    if action == "notify":
        op = msg.get("op", "post")
        if op not in ("post", "clear", "dismiss"):
            raise ProtocolError("notify.op must be post, clear or dismiss")
        out = {"cmd": "request", "action": "notify", "op": op, "title": clean_text(msg.get("title", ""), 60),
               "body": clean_text(msg.get("body", ""), 200)}
        if op == "dismiss":
            nid = msg.get("id")
            if not isinstance(nid, str) or not re.match(r"^n[0-9a-z-]{1,30}$", nid):
                raise ProtocolError("notify.id must be a notification id")
            out["id"] = nid
        return out
    if action == "keys":
        on = msg.get("on")
        if not isinstance(on, bool):
            raise ProtocolError("keys.on must be true or false")
        return {"cmd": "request", "action": "keys", "on": on}
    if action == "quantum":
        op = msg.get("op", "devices")
        if op not in ("devices", "run"):
            raise ProtocolError("quantum.op must be devices or run")
        out = {"cmd": "request", "action": "quantum", "op": op}
        if op == "run":
            prog = msg.get("program")
            if not isinstance(prog, str) or not prog.strip() or len(prog) > 64 << 10 or "\x00" in prog:
                raise ProtocolError("quantum.program must be OpenQASM text of at most 64 KiB")
            drv = msg.get("driver", "")
            if drv and (not isinstance(drv, str) or not _APP_NAME_RE.match(drv)):
                raise ProtocolError("quantum.driver must be an app name")
            out.update(program=prog, shots=_int(msg.get("shots", 1024), 1, 100000), driver=drv,
                       device=clean_text(msg.get("device", ""), 80))
            if msg.get("seed") is not None:
                out["seed"] = _int(msg["seed"], 0, 2 ** 31)
        return out
    if action == "autoupdate":
        op = msg.get("op", "status")
        if op not in ("status", "refresh", "set", "run"):
            raise ProtocolError("autoupdate.op must be status, refresh, set or run")
        out = {"cmd": "request", "action": "autoupdate", "op": op}
        if op == "set":
            if "enabled" in msg:
                if not isinstance(msg["enabled"], bool):
                    raise ProtocolError("autoupdate.enabled must be true or false")
                out["enabled"] = msg["enabled"]
            if "mode" in msg:
                if msg["mode"] not in ("ask", "auto"):
                    raise ProtocolError("autoupdate.mode must be ask or auto")
                out["mode"] = msg["mode"]
            if "every_hours" in msg:
                out["every_hours"] = _int(msg["every_hours"], 1, 720)
        if op == "run":
            out["scheduled"] = bool(msg.get("scheduled", False))
        return out
    if action == "heal":
        op = msg.get("op", "check")
        if op not in ("check", "fix"):
            raise ProtocolError("heal.op must be check or fix")
        return {"cmd": "request", "action": "heal", "op": op}
    if action == "mods":
        op = msg.get("op", "list")
        if op not in ("list", "enable", "disable"):
            raise ProtocolError("mods.op must be list, enable or disable")
        out = {"cmd": "request", "action": "mods", "op": op}
        if op != "list":
            name = msg.get("name")
            if not isinstance(name, str) or not _APP_NAME_RE.match(name):
                raise ProtocolError("mods.name must be an app name")
            out["name"] = name
        return out
    if action == "sudo":
        op = msg.get("op", "status")
        if op not in ("status", "open", "close"):
            raise ProtocolError("sudo.op must be status, open or close")
        out = {"cmd": "request", "action": "sudo", "op": op}
        if op == "open":
            out["minutes"] = _int(msg.get("minutes", 5), 1, 60)
            layers = msg.get("layers", ["interface", "app", "command"])
            if (not isinstance(layers, list) or not layers or len(layers) > 4
                    or not all(l in ("interface", "app", "command", "kernel") for l in layers)):
                raise ProtocolError("sudo.layers must name layers")
            out["layers"] = layers
        return out
    if action == "policy":
        op = msg.get("op", "get")
        if op not in ("get", "set"):
            raise ProtocolError("policy.op must be get or set")
        out = {"cmd": "request", "action": "policy", "op": op}
        if op == "set":
            if msg.get("interface") not in ("required", "off"):
                raise ProtocolError("policy.interface must be required or off")
            out["interface"] = msg["interface"]
        return out
    raise ProtocolError(f"unknown request {action!r}")


_COMMAND_RE = re.compile(r"^[A-Za-z0-9:_.-]{1,60}$")
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
            raise ProtocolError("frame.ops must be a list of at most 12000 ops")
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
