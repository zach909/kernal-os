"""Interface apps: the part of the OS that lets an app draw the desktop.

The desktop's *interface* is made of apps - the wallpaper, the menubar, the dock, the windows - and so is the thing that puts them
together on the screen. Normal, 3D, virtual reality, augmented reality and the neural interface are each an **interface app** (``"driver":
"interface"``, the ``compose`` permission). The OS keeps only the system's own interface: the terminal and the button selector
(the *terminal look*), the password prompt, and the plumbing below.

What the OS does for an interface app, and nothing more:

* **tells it what is running**: every layer's name, kind, rectangle, depth, title, focus and the draw ops the app sent (``scene_state``
  and ``scene_layer`` messages). It can draw them any way it likes - flat, as blocks, once per eye.
* **shows its frame**: the app writes ``frame.bin`` (width x height x 4 bytes) in its own scratch directory and says ``scene``; that is the
  screen. The OS adds the password prompt on top, always.
* **maps clicks back**: the app says where each layer's rectangle landed (a quad per layer, nearest first). A click on a quad is turned back
  into the position it has on the flat layer, and handled exactly as a flat click would be. It can also declare *regions* (a waterfall, the
  kernel): a click on one is handed back to the app as ``{"type": "region", "id": ...}`` and the app decides - by asking the OS, like any app,
  with the scopes it holds.
* **forwards what it asks for**: the keys and buttons it declares (Alt+arrows, the middle button, ...) and, if it wants them, pointer moves.
  It can also ask the OS to ``press`` a flat position (the neural interface's "select").

An interface app cannot read files, run commands or reach the network, cannot see anything but the layers it is sent, and the OS refuses its
frame unless it is exactly the size of the screen. If it dies, the OS draws the flat desktop itself until it is back.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .display import Framebuffer
from .quad import point_in_quad, unproject_quad

MAX_STATE_BYTES = 900_000                                     # one scene message must fit a protocol line


class SceneHost:
    """Mixed into the compositor (``Shell``). Needs ``layers``, ``W``, ``H``, ``u``, ``ws``, ``cfg``, ``titlebar``, ``focused_ids``, ``shown``."""

    def _scene_init(self) -> None:
        self.scenes: dict[str, object] = {}                   # look -> the interface app's layer (running, active or not)
        self.scene = None                                     # the interface app whose frames are on screen now
        self._scene_sig: dict[str, object] = {}               # per scene layer id: what it was last told
        self._scene_frame: Optional[Framebuffer] = None
        self._scene_rev = -1
        self.scene_hits: list = []
        self.scene_regions: list = []
        self.scene_caps: dict = {"keys": [], "buttons": [], "pointer": False}
        self.scene_pointer = False
        self._scene_capture: Optional[str] = None             # a captured button that is held down

    # ----------------------------------------------------------------------------------- attach / detach
    def _interfaces(self) -> dict:
        """look -> the installed interface app that provides it."""
        try:
            return dict(self._interfaces_of())
        except Exception:
            return {}

    def _attach_scene(self, inst, activate: bool = False):
        look = next((lk for lk, name in self._interfaces().items() if name == inst.name), "")
        layer = self._add(inst, "scene", [0, 0, 0, 0], "graphical")
        layer.visible = False                                 # it is drawn by itself, not composited
        layer.slot = f"interface:{look or inst.name}"
        self.scenes[look or inst.name] = layer
        if activate or look == self.cfg["look"] or self.scene is None and not look:
            self._activate_scene(layer)
        return layer

    def _activate_scene(self, layer) -> None:
        self.scene = layer
        self._scene_sig.pop(layer.id, None)
        self._scene_frame, self._scene_rev, self.scene_hits, self.scene_regions = None, -1, [], []
        self.scene_caps = {"keys": [], "buttons": [], "pointer": False}
        self.surface_dirty = True

    def _forget_scene(self, layer_id: str) -> None:
        for k in [k for k, l in self.scenes.items() if l.id == layer_id]:
            del self.scenes[k]
        if self.scene is not None and self.scene.id == layer_id:
            self.scene = None
            self._scene_frame, self.scene_hits, self.scene_regions = None, [], []
        self._scene_sig.pop(layer_id, None)

    def _switch_interface(self, look: str) -> bool:
        """Make ``look`` the one on screen: start its interface app if none is running (that asks for the password, like starting any app),
        or use the one already running. Looks with no interface app - the terminal look, or one nobody installed - are drawn by the OS itself."""
        app = self._interfaces().get(look)
        if app is None:
            self.scene = None
            return True
        have = self.scenes.get(look)
        if have is not None and have.id in self.layers:
            self._activate_scene(have)
            return True
        if self._opener is None:
            self.scene = None
            return True
        try:
            try:
                inst = self._opener(app, "graphical", False, frozenset(self.layers))
            except TypeError:
                inst = self._opener(app, "graphical")
        except Exception as e:                                # a refused password, a missing app
            self.notify("desktop", f"Could not start {app}", str(e)[:150])
            return False
        self._attach_scene(inst, activate=True)
        return True

    # ----------------------------------------------------------------------------------------- the push
    def _scene_sync(self) -> None:
        """Tell the active interface app what is running, and what changed since it was last told."""
        sc = self.scene
        if sc is None or sc.channel.closed:
            return
        metas = []
        for l in sorted(self.layers.values(), key=lambda l: l.z):
            if l is sc or l.kind in ("cursor", "scene"):
                continue
            metas.append({"id": l.id, "name": l.name, "kind": l.kind, "mode": l.mode, "rect": list(l.rect), "z": l.z, "title": l.title,
                          "visible": self.shown(l), "minimized": l.minimized, "ws": l.ws, "rev": l.rev, "slot": l.slot, "frameless": l.frameless})
        state = {"cmd": "scene_state", "w": self.W, "h": self.H, "u": self.u, "titlebar": self.titlebar, "ws": self.ws,
                 "focus": sorted(self.focused_ids()), "look": self.cfg["look"], "layers": metas}
        sent = self._scene_sig.setdefault(sc.id, {"state": None, "revs": {}})
        sig = json.dumps(state, sort_keys=True)
        if sig != sent["state"]:
            sc.send(state)
            sent["state"] = sig
        live = set()
        for l in self.layers.values():
            if l is sc or l.kind in ("cursor", "scene"):
                continue
            live.add(l.id)
            if sent["revs"].get(l.id) != l.rev:
                msg = {"cmd": "scene_layer", "id": l.id, "rev": l.rev, "ops": l.ops, "screen": l.screen}
                if len(json.dumps(msg)) > MAX_STATE_BYTES:
                    self.log.append(f"{l.name}: too much to show an interface app; skipped")
                    msg["ops"], msg["screen"] = [], None
                sc.send(msg)
                sent["revs"][l.id] = l.rev
        for gone in [i for i in sent["revs"] if i not in live]:
            del sent["revs"][gone]

    # ------------------------------------------------------------------------------- what comes back
    def _on_scene(self, layer, msg: dict) -> None:
        """An interface app says a frame is ready."""
        if layer is not self.scene:
            return                                            # not the one on screen (an idle one): ignore
        path = Path(layer.scratch) / "frame.bin"
        try:
            data = path.read_bytes()
        except OSError as e:
            self.log.append(f"{layer.name}: no frame ({e})")
            return
        if msg["w"] != self.W or msg["h"] != self.H or len(data) != self.W * self.H * 4:
            self.log.append(f"{layer.name}: a frame of the wrong size was refused")
            return
        fb = Framebuffer.__new__(Framebuffer)
        fb.width, fb.height, fb.buf = self.W, self.H, bytearray(data)
        self._scene_frame, self._scene_rev = fb, msg["rev"]
        self.scene_hits, self.scene_regions = msg["hits"], msg["regions"]
        self.scene_caps, self.scene_pointer = msg["captures"], msg["pointer"]
        self.surface_dirty = True

    def _scene_press(self, layer, msg: dict) -> None:
        if layer is self.scene:
            for pressed in (True, False):
                self.pending.append({"type": "button", "button": "left", "pressed": pressed, "x": msg["x"], "y": msg["y"], "flat": True})

    # ----------------------------------------------------------------------------- mapping a click
    def _flat(self, x: int, y: int) -> tuple[int, int]:
        """A screen point as the flat position it has on its layer, if an interface app drew the layers somewhere else."""
        if self.scene is None or not self.scene_hits:
            return x, y
        for h in self.scene_hits:
            layer = self.layers.get(h["id"])
            if layer is None:
                continue
            got = unproject_quad(h["quad"], x, y, layer.rect[2], layer.rect[3])
            if got is not None:
                return int(layer.rect[0] + got[0]), int(layer.rect[1] + got[1])
        return x, y

    def _scene_region(self, x: int, y: int) -> bool:
        """A click on a region the interface app declared (a waterfall, the kernel), unless a layer's own face is in front: it is handed to the app."""
        if self.scene is None or self.scene.channel.closed:
            return False
        for h in self.scene_hits:
            if point_in_quad(h["quad"], x, y):
                return False
        region = next((r for r in self.scene_regions if point_in_quad(r["quad"], x, y)), None)
        if region is None:
            return False
        self.scene.send({"cmd": "input", "ev": {"type": "region", "id": region["id"]}})
        return True

    def _scene_wants(self, ev: dict) -> bool:
        """Should this input go to the interface app (and be taken from the rest of the OS)? Only what it declared - and pointer moves, forwarded
        (not taken) if it asked for them, and taken while a captured button is held."""
        sc, caps, t = self.scene, self.scene_caps, ev.get("type")
        if sc is None or sc.channel.closed:
            return False
        if t == "key" and ev.get("key") in caps["keys"]:
            sc.send({"cmd": "input", "ev": {"type": "key", "key": ev["key"]}})
            return True
        if t == "button" and ev.get("button") in caps["buttons"]:
            self._scene_capture = ev["button"] if ev.get("pressed") else None
            sc.send({"cmd": "input", "ev": {"type": "button", "button": ev["button"], "pressed": bool(ev.get("pressed")),
                                            "x": ev.get("x", 0), "y": ev.get("y", 0)}})
            return True
        if t == "pointer" and (self._scene_capture or caps["pointer"]):
            sc.send({"cmd": "input", "ev": {"type": "pointer", "x": ev.get("x", 0), "y": ev.get("y", 0)}})
            return bool(self._scene_capture)
        return False
