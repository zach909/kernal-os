"""Library for interface apps: what an app needs to draw the desktop.

An interface app (``"driver": "interface"``, the ``compose`` permission) is told what is running and hands back a frame (see
``scenehost.py`` for the OS side). This module is its side: a model of the layers it was told about - a :class:`SceneModel`, which is a
:class:`~kos.compositor.Compositor`, so it can draw them the same way the flat desktop is drawn - and a :class:`Runner` that reads the OS's
messages on a thread (so a slow frame never makes the OS wait), folds a burst of changes into one frame, writes the frame to the app's
scratch directory and says it is ready.

An interface is a small class: ``render()`` returns ``(frame, hits, regions)``; ``on_input``, ``on_intent`` and ``tick`` are optional.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Optional

from .compositor import Compositor, SeatFocus, Surface
from .display import Framebuffer
from .sdk import App


class SceneModel(Compositor):
    """The layers an interface app was told about, ready to be drawn."""

    def __init__(self) -> None:
        self.layers: dict[str, Surface] = {}
        self.W = self.H = 0
        self.u, self.ws = 1, 0
        self.cfg = {"look": "normal"}
        self.seats = {0: SeatFocus()}
        self._base: Optional[Framebuffer] = None
        self._base_sig = None
        self.composed: Optional[Framebuffer] = None
        self.look = "normal"

    def apply_state(self, st: dict) -> None:
        self.W, self.H, self.u, self.ws = int(st["w"]), int(st["h"]), max(1, int(st["u"])), int(st.get("ws", 0))
        self.look = self.cfg["look"] = st.get("look", "normal")
        focus = [f for f in st.get("focus", []) if isinstance(f, str)]
        self.seats = {i: SeatFocus(f) for i, f in enumerate(focus)} or {0: SeatFocus()}
        keep = set()
        for m in st.get("layers", []):
            lid = m["id"]
            keep.add(lid)
            s = self.layers.get(lid)
            if s is None:
                s = self.layers[lid] = Surface(id=lid, name=m["name"], kind=m["kind"], mode=m["mode"], rect=list(m["rect"]))
            s.frameless = bool(m.get("frameless"))
            s.name, s.kind, s.mode, s.rect, s.z = m["name"], m["kind"], m["mode"], list(m["rect"]), m["z"]
            s.title, s.visible, s.minimized, s.ws = m.get("title", ""), bool(m.get("visible", True)), bool(m.get("minimized")), None
        for gone in [i for i in self.layers if i not in keep]:
            del self.layers[gone]
        self._titlebar = int(st.get("titlebar", 9 * self.u + 10))

    @property
    def titlebar(self) -> int:
        return getattr(self, "_titlebar", 9 * self.u + 10)

    def apply_layer(self, msg: dict) -> None:
        s = self.layers.get(msg["id"])
        if s is None:
            return
        s.ops, s.screen, s.rev = msg.get("ops") or [], msg.get("screen"), msg["rev"]
        if s.kind == "wallpaper":
            s.wall = None
        s.cache = None


class Interface:
    """One way of drawing the desktop. Subclass and override ``render``."""

    captures: dict = {"keys": [], "buttons": [], "pointer": False}
    pointer = False                                  # does the frame already contain the pointer (once per eye, say)?
    wait = 1.0                                       # seconds to wait for a message before calling ``tick`` anyway

    def __init__(self, model: SceneModel, runner: "Runner"):
        self.model, self.runner = model, runner

    def render(self) -> tuple[Framebuffer, list, list]:
        raise NotImplementedError

    def on_input(self, ev: dict) -> bool:
        return False

    def on_intent(self, name: str) -> bool:
        return False

    def on_event(self, ev: dict) -> bool:
        return False

    def tick(self, now: float) -> bool:
        return False


class Runner:
    """Runs an interface: reads the OS, folds changes together, publishes frames."""

    def __init__(self, factory, app: Optional[App] = None):
        self.app = app or App()
        self.model = SceneModel()
        self.q: queue.Queue = queue.Queue()
        self.factory = factory
        self.rev = 0
        self.scratch = os.environ.get("KOS_CACHE_DIR", "")
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.app._rfile:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                continue
        self.q.put(None)

    def press(self, x: int, y: int) -> None:
        """Ask the OS to click a flat position (the neural interface's 'select')."""
        self.app.send({"cmd": "press", "x": int(x), "y": int(y)})

    def publish(self, frame: Framebuffer, hits: list, regions: list, iface: Interface) -> None:
        if not self.scratch or frame.width != self.model.W or frame.height != self.model.H:
            return
        tmp, final = os.path.join(self.scratch, "frame.tmp"), os.path.join(self.scratch, "frame.bin")
        try:
            with open(tmp, "wb") as f:
                f.write(frame.buf)
            os.replace(tmp, final)
        except OSError:
            return                                              # the OS took the scratch space away: nothing to show it on
        self.rev += 1
        self.app.send({"cmd": "scene", "rev": self.rev, "w": frame.width, "h": frame.height, "hits": hits, "regions": regions,
                       "pointer": iface.pointer, "captures": iface.captures})

    def handle(self, ev: dict, iface: Interface) -> bool:
        cmd = ev.get("cmd")
        if cmd == "scene_state":
            self.model.apply_state(ev)
            return True
        if cmd == "scene_layer":
            self.model.apply_layer(ev)
            return True
        if cmd == "input":
            return iface.on_input(ev.get("ev", {}))
        if cmd == "intent":
            return iface.on_intent(ev.get("name", ""))
        return bool(iface.on_event(ev))                       # anything else: replies to the app's own requests, say

    def run(self) -> None:
        iface = self.factory(self.model, self)
        dirty = False
        while True:
            try:
                first = self.q.get(timeout=iface.wait)
                batch = [first]
            except queue.Empty:
                batch = []
            while True:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            for ev in batch:
                if ev is None or ev.get("cmd") == "quit":
                    return
                dirty = self.handle(ev, iface) or dirty
            dirty = iface.tick(time.monotonic()) or dirty
            if dirty and self.model.W:
                frame, hits, regions = iface.render()
                self.publish(frame, hits, regions, iface)
                dirty = False
