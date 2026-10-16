"""The app side of the KOS command protocol. Standard library only.

A minimal app::

    from kos.sdk import App, Canvas

    def main():
        app = App()
        for event in app.events():
            if app.mode == "tui":
                app.screen("Hello", [f"last event: {event}"])
            else:
                c = Canvas()
                c.clear("#101820")
                c.text(10, 10, "Hello", "#ffffff", 2)
                app.present(c)

The first event is always ``{"cmd": "hello"}`` so the app can draw its first
screen before any input arrives.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Iterator, Optional


class Canvas:
    """Collects draw ops for one graphical frame."""

    def __init__(self) -> None:
        self.ops: list[list] = []

    def clear(self, color: str) -> "Canvas":
        self.ops.append(["clear", color])
        return self

    def rect(self, x: int, y: int, w: int, h: int, color: str) -> "Canvas":
        self.ops.append(["rect", int(x), int(y), int(w), int(h), color])
        return self

    def line(self, x0: int, y0: int, x1: int, y1: int, color: str) -> "Canvas":
        self.ops.append(["line", int(x0), int(y0), int(x1), int(y1), color])
        return self

    def text(self, x: int, y: int, s: str, color: str, scale: int = 1) -> "Canvas":
        self.ops.append(["text", int(x), int(y), s, color, int(scale)])
        return self

    def hit(self, x: int, y: int, w: int, h: int, label: str) -> "Canvas":
        """Declare a clickable control (draws nothing): it can then be listed, tabbed to and pressed from the keyboard."""
        self.ops.append(["hit", int(x), int(y), int(w), int(h), str(label)])
        return self

    def blit(self, x: int, y: int, w: int, h: int, rgb: bytes, scale: int = 1) -> "Canvas":
        """Raw RGB pixels (``w*h*3`` bytes), drawn ``scale`` times larger: a camera preview, say."""
        import base64
        self.ops.append(["blit", int(x), int(y), int(w), int(h), int(scale), base64.b64encode(rgb).decode()])
        return self

    def poly(self, pts, color: str, alpha: int = 255) -> "Canvas":
        """A smooth (anti-aliased) filled shape: ``pts`` is a list of (x, y)."""
        self.ops.append(["poly", [[float(x), float(y)] for x, y in pts], color, int(alpha)])
        return self

    def stext(self, x: int, y: int, s: str, color: str, px: int = 14, face: int = 0) -> "Canvas":
        """Smooth proportional text; face 0 sans, 1 bold, 2 mono."""
        self.ops.append(["stext", int(x), int(y), s, color, int(px), int(face)])
        return self


class App:
    def __init__(self, sock: Optional[socket.socket] = None):
        if sock is None:
            sock = socket.socket(fileno=int(os.environ["KOS_CHANNEL_FD"]))
        self._sock = sock
        self._rfile = sock.makefile("rb")
        self.mode = os.environ.get("KOS_MODE", "tui")
        self.width = 80
        self.height = 24
        self.scale = 1
        self.font: dict = {}
        self.look = "normal"                   # normal | 3d | text | terminal (the OS may change it at any time)
        self.options: dict = {}
        self.insets = [0, 0, 0, 0]
        self.devices: set[str] = set()

    def send(self, obj: dict) -> None:
        self._sock.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")

    def events(self) -> Iterator[dict]:
        for line in self._rfile:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            cmd = ev.get("cmd")
            if cmd == "hello":
                self.mode = ev.get("mode", self.mode)
                self.width = ev.get("width", self.width)
                self.height = ev.get("height", self.height)
                self.scale = ev.get("scale", self.scale)
                self.font = ev.get("font", self.font)
                self.look = ev.get("look", self.look)
                self.options = ev.get("options", self.options)
            elif cmd == "look":
                self.look = ev.get("look", self.look)
                self.options = ev.get("options", self.options)
                self.insets = ev.get("insets", self.insets)
            elif cmd == "device" and ev.get("state") == "attached":
                self.devices.add(ev.get("device", ""))
            elif cmd == "quit":
                return
            yield ev

    # --- commands the app can issue -------------------------------------
    def screen(self, title: str, lines: list[str], status: str = "") -> None:
        self.send({"cmd": "screen", "title": title, "lines": lines, "status": status})

    def text_width(self, s: str, px: int = 14, face: int = 0) -> int:
        """Pixel width of smooth text, from the advances the OS sent in hello."""
        adv = self.font.get(("sans", "bold", "mono")[face], {}).get("adv")
        if not adv:
            return int(len(s) * px * 0.55)
        return round(sum(adv[ord(c) - 32] if 32 <= ord(c) < 127 else 600 for c in s) * px / 1000)

    def present(self, canvas: Canvas) -> None:
        self.send({"cmd": "frame", "ops": canvas.ops})

    def log(self, msg: str) -> None:
        self.send({"cmd": "log", "msg": msg})

    def exit(self, code: int = 0) -> None:
        try:
            self.send({"cmd": "exit", "code": code})
        except OSError:
            pass

    # --- asking the OS for things (needs the 'system' permission) --------
    # Each of these only *asks*. The answer arrives later as an event:
    # {"cmd": "apps", ...} or {"cmd": "result", "ok": bool, "detail": str}.
    def request_apps(self) -> None:
        self.send({"cmd": "request", "action": "apps"})

    def request_open(self, app: str, mode: str = "tui", command: str = "", line: str = "") -> None:
        msg = {"cmd": "request", "action": "open", "app": app, "mode": mode}
        if command:
            msg["command"] = command
        if line:
            msg["line"] = line
        self.send(msg)

    def request_focus(self, instance_id: str) -> None:
        self.send({"cmd": "request", "action": "focus", "id": instance_id})

    def request_close(self, instance_id: str) -> None:
        self.send({"cmd": "request", "action": "close", "id": instance_id})

    def request_info(self) -> None:
        self.send({"cmd": "request", "action": "info"})

    def request_ls(self, path: str) -> None:
        self.send({"cmd": "request", "action": "ls", "path": path})

    def request_view(self, path: str) -> None:
        self.send({"cmd": "request", "action": "view", "path": path})

    def request_scan(self, path: str) -> None:
        self.send({"cmd": "request", "action": "scan", "path": path})

    def request_optimize(self) -> None:
        self.send({"cmd": "request", "action": "optimize"})

    def request_settle(self) -> None:
        self.send({"cmd": "request", "action": "settle"})

    def request_permit(self, app: str, revoke: bool = False) -> None:
        self.send({"cmd": "request", "action": "revoke" if revoke else "permit", "app": app})

    def request_save(self, path: str, text: str) -> None:
        self.send({"cmd": "request", "action": "save", "path": path, "text": text})

    def request_backup(self, path: str) -> None:
        self.send({"cmd": "request", "action": "backup", "path": path})

    def request_backups(self) -> None:
        self.send({"cmd": "request", "action": "backups"})

    def request_sys(self, kind: str, arg: str = "") -> None:
        self.send({"cmd": "request", "action": "sys", "kind": kind, "arg": arg})

    def request_signal(self, pid: int, sig: str) -> None:
        self.send({"cmd": "request", "action": "signal", "pid": pid, "sig": sig})

    def request_renice(self, pid: int, nice: int) -> None:
        self.send({"cmd": "request", "action": "renice", "pid": pid, "nice": nice})

    def request_fschange(self, op: str, path: str, **extra) -> None:
        self.send({"cmd": "request", "action": "fschange", "op": op, "path": path, **extra})

    def request_netcheck(self) -> None:
        self.send({"cmd": "request", "action": "netcheck"})

    def request_updates(self, op: str, **extra) -> None:
        self.send({"cmd": "request", "action": "updates", "op": op, **extra})

    def request_resize(self, w: int = 0, h: int = 0) -> None:
        msg = {"cmd": "request", "action": "resize"}
        if w:
            msg["w"] = int(w)
        if h:
            msg["h"] = int(h)
        self.send(msg)

    def request_layout(self, order: list, hidden: list) -> None:
        self.send({"cmd": "request", "action": "layout", "order": order, "hidden": hidden})

    def request_remote(self, url: str) -> None:
        self.send({"cmd": "request", "action": "remote", "url": url})

    def request_push(self, backup: str) -> None:
        self.send({"cmd": "request", "action": "push", "backup": backup})

    def request_restore(self, backup: str, member: str, to: str) -> None:
        self.send({"cmd": "request", "action": "restore", "backup": backup, "member": member, "to": to})

    def request_intent(self, name: str) -> None:
        """A neural driver (``"driver": "neural"``): one decision - next, prev, select, back or pause - made from the wearer's
        signals. The signals themselves never leave the driver."""
        self.send({"cmd": "request", "action": "intent", "name": name})

    def request_line(self, text: str) -> None:
        self.send({"cmd": "request", "action": "line", "text": text})

    def cache_dir(self) -> Optional[str]:
        """This run's private scratch directory, or None if this launch
        didn't provide one. It is wiped the moment this app's process ends -
        never use it for anything you need to keep."""
        return os.environ.get("KOS_CACHE_DIR")

    def data_dir(self) -> Optional[str]:
        """This app's own folder: private to it, persistent across runs and updates. Put what you want to keep here."""
        return os.environ.get("KOS_DATA_DIR")

    def resource(self, name: str) -> bytes:
        """Read a file from this app's own zip (still never extracted)."""
        root = os.environ.get("KOS_APP_DIR")
        if root:                              # npm apps are unpacked read-only into RAM
            full = os.path.realpath(os.path.join(root, name))
            if not full.startswith(os.path.realpath(root) + os.sep):
                raise ValueError("outside the app")
            with open(full, "rb") as f:
                return f.read()
        import zipfile
        with zipfile.ZipFile(f"/proc/self/fd/{os.environ['KOS_KAPP_FD']}") as z:
            return z.read(name)
