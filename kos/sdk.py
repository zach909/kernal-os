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
from collections import deque
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


class App:
    def __init__(self, sock: Optional[socket.socket] = None):
        if sock is None:
            sock = socket.socket(fileno=int(os.environ["KOS_CHANNEL_FD"]))
        self._sock = sock
        self._rfile = sock.makefile("rb")
        self.mode = os.environ.get("KOS_MODE", "tui")
        self.width = 80
        self.height = 24
        self.devices: set[str] = set()
        # The path+query of the kos:// address this app was opened with, e.g. "/news?n=3" ("" if none).
        self.address = os.environ.get("KOS_ADDRESS", "")
        # What extensions (or, for a system app, mods) the owner switched on for this app:
        # [{name, version, kind, entries: [{label, address}], colors: {..}}]. Set by the
        # {"cmd": "extensions"} event that follows hello; empty when there are none.
        self.extensions: list = []
        self._queue: deque = deque()     # events that arrived while waiting for a vault reply
        self._seq = 0
        self.vault_error = ""           # why the last vault call was refused, for the app to show

    def send(self, obj: dict) -> None:
        self._sock.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")

    def _read_event(self) -> Optional[dict]:
        """Next decoded message from the OS, or None when the channel closes."""
        for line in self._rfile:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict):
                return ev
        return None

    def events(self) -> Iterator[dict]:
        while True:
            ev = self._queue.popleft() if self._queue else self._read_event()
            if ev is None:
                return
            cmd = ev.get("cmd")
            if cmd == "hello":
                self.mode = ev.get("mode", self.mode)
                self.width = ev.get("width", self.width)
                self.height = ev.get("height", self.height)
            elif cmd == "device" and ev.get("state") == "attached":
                self.devices.add(ev.get("device", ""))
            elif cmd == "extensions":
                self.extensions = list(ev.get("items", []))
            elif cmd == "quit":
                return
            yield ev

    # --- durable storage (needs the 'storage' permission) -----------------
    # Blocking round trips: the OS answers a vault command straight away and
    # never prompts. Any other event that arrives meanwhile is kept for events().
    def _vault(self, op: str, key: str = "", value: Optional[str] = None, space: Optional[str] = None) -> dict:
        self._seq += 1
        msg = {"cmd": "vault", "op": op, "id": self._seq}
        if op not in ("list", "spaces"):
            msg["key"] = key
        if value is not None:
            msg["value"] = value
        if space is not None:
            msg["space"] = space
        self.send(msg)
        while True:
            ev = self._read_event()
            if ev is None:
                return {"ok": False, "detail": "channel closed"}
            if ev.get("cmd") == "vault" and ev.get("id") == self._seq:
                self.vault_error = "" if ev.get("ok") or ev.get("detail") == "no such key" else ev.get("detail", "")
                return ev
            if ev.get("cmd") == "quit":
                self._queue.append(ev)
                return {"ok": False, "detail": "quit"}
            self._queue.append(ev)

    # ``space`` names a shared folder (manifest 'owns:NAME' to create it, 'uses:NAME' to look for it
    # once the device owner granted access). Without it you get your own private data.
    def vault_put(self, key: str, value: str, space: Optional[str] = None) -> bool:
        return bool(self._vault("put", key, value, space).get("ok"))

    def vault_get(self, key: str, space: Optional[str] = None) -> Optional[str]:
        r = self._vault("get", key, space=space)
        return r.get("value") if r.get("ok") else None

    def vault_keys(self, space: Optional[str] = None) -> list:
        r = self._vault("list", space=space)
        return list(r.get("keys", [])) if r.get("ok") else []

    def vault_delete(self, key: str, space: Optional[str] = None) -> bool:
        return bool(self._vault("delete", key, space=space).get("ok"))

    def vault_spaces(self) -> list:
        """Shared spaces this app can open right now: [{space, access, owner}]."""
        r = self._vault("spaces")
        return list(r.get("spaces", [])) if r.get("ok") else []

    # --- the OS's own functions (needs a 'service:GROUP' permission) ------
    # A blocking round trip like the vault: the OS checks the call against servicespec.py, asks the
    # owner for the password in its own prompt where the service needs one, and answers
    # {"ok": bool, "detail": str, "data": {..}}. Events that arrive meanwhile are kept for events().
    def service(self, name: str, /, **args) -> dict:       # positional-only: services have arguments called 'name'
        self._seq += 1
        self.send({"cmd": "service", "id": self._seq, "name": name, "args": args})
        while True:
            ev = self._read_event()
            if ev is None:
                return {"ok": False, "detail": "channel closed", "data": {}}
            if ev.get("cmd") == "service" and ev.get("id") == self._seq:
                return ev
            if ev.get("cmd") == "quit":
                self._queue.append(ev)
                return {"ok": False, "detail": "quit", "data": {}}
            self._queue.append(ev)

    # --- commands the app can issue -------------------------------------
    def screen(self, title: str, lines: list[str], status: str = "") -> None:
        self.send({"cmd": "screen", "title": title, "lines": lines, "status": status})

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

    def request_open(self, app: str, mode: str = "tui") -> None:
        self.send({"cmd": "request", "action": "open", "app": app, "mode": mode})

    def request_address(self, address: str, mode: str = "tui") -> None:
        """Ask the OS to open ``kos://NAME[/path][?query]`` (like clicking a link)."""
        self.send({"cmd": "request", "action": "open", "address": address, "mode": mode})

    def request_focus(self, instance_id: str) -> None:
        self.send({"cmd": "request", "action": "focus", "id": instance_id})

    def request_close(self, instance_id: str) -> None:
        self.send({"cmd": "request", "action": "close", "id": instance_id})

    # Backups (needs the 'system' permission). The OS asks for the password in
    # its own prompt for every one of these; the app only ever sees the answer:
    # {"cmd": "backup", "stats": {...}, "items": [...]} or a "result" event.
    def request_backup(self) -> None:
        self.send({"cmd": "request", "action": "backup"})

    def request_backup_add(self, path: str) -> None:
        self.send({"cmd": "request", "action": "backup_add", "path": path})

    def request_backup_remove(self, item_id: str) -> None:
        self.send({"cmd": "request", "action": "backup_remove", "id": item_id})

    def cache_dir(self) -> Optional[str]:
        """This run's private scratch directory, or None if this launch
        didn't provide one. It is wiped the moment this app's process ends -
        never use it for anything you need to keep."""
        return os.environ.get("KOS_CACHE_DIR")

    def resource(self, name: str) -> bytes:
        """Read a file from this app's own zip (still never extracted)."""
        import zipfile
        with zipfile.ZipFile(f"/proc/self/fd/{os.environ['KOS_KAPP_FD']}") as z:
            return z.read(name)
