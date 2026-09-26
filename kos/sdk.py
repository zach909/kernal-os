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
            elif cmd == "device" and ev.get("state") == "attached":
                self.devices.add(ev.get("device", ""))
            elif cmd == "quit":
                return
            yield ev

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
