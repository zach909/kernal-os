"""The desktop shell: several separate apps, on screen at once.

Until now KOS showed one app at a time. The shell is a *compositor*: every
piece of the desktop is its own sandboxed app, each drawing into its own
layer, and the OS stacks them:

    desktop      the wallpaper (drawn by code), the launcher and the search box
    taskbar      the bar: start button, running apps, clock, network
    widget-*     clock, calendar, network, system monitor - one app each
    <any app>    a window: OS-drawn frame + the app's content

What stays with the OS - never an app - is everything trusted: window frames,
the title text, the close/minimize buttons, the mouse pointer, and the password
prompt. And the *glass*: an app draws flat shapes and text; the OS blurs what is
behind the layer, tints it, adds a sheen, a bevel and a shadow. Apps cannot
read the screen (they only ever receive their own events), so a widget never
sees what is behind it, only the frosted result is shown to you.

Input goes to one place: the pointer position decides which layer receives the
mouse (translated to that layer's own coordinates), the focused window - or, with
none, the desktop's search box - receives the keyboard. The right mouse button is
the OS's: it shows the desktop. Ctrl-C leaves the shell (apps keep running).

Layers are repainted from a cache keyed on what is underneath them, so a
ticking clock re-draws a few shapes, not a blur.
"""

from __future__ import annotations

import math
import os
import select
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import capabilities, fbgfx, looks, ttf
from .compositor import (ACCENT, BAR_GLASS, DOCK_GLASS, GLASS, NO_HIT, NOT_IN_BASE, POPUP_GLASS, TITLE_TINT, WINDOW_BODY, Z,  # noqa: F401
                         Compositor)
from .auth import Authority, AuthorizationDenied
from .display import Framebuffer, Modal, crop, draw_cursor, draw_modal, parse_color
from .protocol import Channel, ProtocolError, validate_app_message
from .registry import Registry
from .scenehost import SceneHost
from .session import SessionPrompter

# The interface is a series of separate apps. The OS composites them; it does not draw them.
#   wallpaper  the background            icons   the app icon grid        search  the search box + results
#   widgets    the widget handler        widget-*  the widgets
#   menubar    the top panel: menus, stats, clock             dock    the floating dock: pinned + running apps
CORE = ("wallpaper", "pins", "search", "sidebar", "launcher", "widgets", "widget-clock", "widget-calendar", "widget-network",
        "widget-system", "menubar", "dock", "effects", "cursor")
WIDGETS = ("widget-clock", "widget-calendar", "widget-network", "widget-system")
WIDGET_TITLES = {"widget-clock": "Clock", "widget-calendar": "Calendar", "widget-network": "Network",
                 "widget-system": "System"}
WIDGET_HEIGHTS = {"widget-clock": 56, "widget-calendar": 112, "widget-network": 48, "widget-system": 70}
SIDE_TAB_H, SHELF_H = 24, 56                              # sidebar: tab strip on top, link shelf at the bottom (units of u)
KINDS = {"wallpaper": "wallpaper", "pins": "plain", "search": "plain", "sidebar": "sidebar", "launcher": "popup", "widgets": "widget", "menubar": "bar",
         "dock": "dock", "cursor": "cursor", "effects": "overlay", **{w: "widget" for w in WIDGETS}}
DEFAULT_CFG = {"look": "normal", "cursor_direction": True, "tilt": True, "bubbles": True, "side_tab": "widgets"}
TILT_PX = 5                                              # at most this many px (times the UI scale) of tilt


_METRICS: dict = {}


def _font_metrics() -> dict:
    """Advance tables of the OS fonts, so apps can lay out smooth text they cannot rasterize."""
    if not _METRICS:
        for key in ("sans", "bold", "mono"):
            f = ttf.load(key)
            if f:
                _METRICS[key] = f.metrics()
    return _METRICS


@dataclass
class Layer:
    id: str
    name: str
    kind: str                      # wallpaper | bar | widget | window
    channel: Channel
    mode: str                      # graphical | tui
    rect: list[int]                # x, y, w, h  (windows: including the frame)
    z: int = 0
    ops: list = field(default_factory=list)
    screen: Optional[dict] = None
    wall: Optional[Framebuffer] = None
    title: str = ""
    visible: bool = True
    minimized: bool = False
    system: bool = False
    scopes: frozenset = frozenset()   # the system:<scope>s it holds ({"*"}: the bare 'system'); what it may ask of the OS
    ticks: bool = False
    shell: bool = False            # may resize itself / arrange the widgets
    ws: Optional[int] = None       # the workspace a window lives on (None: interface apps show on every workspace)
    slot: str = ""                 # the interface slot it fills (its own name for built-ins; a mod's declared slot)
    pointer: bool = False          # is told about the pointer and where clicks land
    animate: bool = False          # may ask for animation ticks
    assistant: bool = False        # an assistant: may propose plans (run only after the owner's password)
    scene: bool = False            # an interface app: its frames are the screen (see scenehost.py)
    scratch: str = ""              # its scratch directory: where an interface app writes frame.bin
    neural: bool = False           # a neural driver: may send intents while the neural look is on
    rev: int = 0                   # bumps whenever what this layer shows changes
    cache: Optional[tuple] = None  # (signature, region rows) of its glass, before content

    def __post_init__(self) -> None:
        if not self.slot and self.kind != "window":
            self.slot = self.name                  # a built-in fills the slot of its own name
        if self.system and not self.scopes:
            self.scopes = frozenset({"*"})         # a layer built by hand as "system" holds every scope

    def allows(self, action: str) -> bool:
        """May this app ask the OS for ``action``? Needs a system scope that covers it (see ``capabilities``)."""
        return self.system and capabilities.allows(self.scopes, action)

    def send(self, obj: dict) -> None:
        self.channel.send(obj)


SEAT_COLORS = ("#0078d4", "#e8a317", "#2fa84f", "#c0392b")
MAX_SEATS = 4
WORKSPACES = 4


@dataclass
class Seat:
    """One pointer and the keyboard that goes with it: its own position, focus, drag and text-box. Several
    seats work at once (several mice and keyboards); seat 0 is drawn by the cursor app, the others by the OS."""
    id: int
    pointer: tuple = (0, 0)
    drag: Optional[tuple] = None
    focus: Optional[str] = None
    key_target: Optional[str] = None
    down: bool = False
    vel: list = field(default_factory=lambda: [0.0, 0.0])


class Shell(Compositor, SceneHost):
    def __init__(self, paths, authority: Authority, backend, devices, *,
                 connect: Optional[Callable] = None, opener: Optional[Callable] = None,
                 closer: Optional[Callable] = None, modes_of: Optional[Callable] = None,
                 commands_of: Optional[Callable] = None, restarter: Optional[Callable] = None, keep_prompter: bool = False,
                 interfaces_of: Optional[Callable] = None,
                 preboot: tuple[str, ...] = ("mouse", "keyboard"), now: Callable[[], float] = time.time):
        self.paths, self.authority, self.backend, self.devices = paths, authority, backend, devices
        self.W, self.H = backend.width, backend.height      # the whole screen: every output side by side
        self.outputs = list(getattr(backend, "outputs", None) or [(0, 0, self.W, self.H)])
        _, _, self.PW, self.PH = self.outputs[0]            # the primary output: the panel, dock and sidebar live here
        self.u = max(1, self.PH // 360)                     # UI scale: 1 at 640x360, 2 at 720p, 3 at 1080p
        self.layers: dict[str, Layer] = {}
        self._interfaces_of = interfaces_of or (lambda: {})   # look -> the installed interface app that draws it
        self._scene_init()
        self.seats: dict[int, Seat] = {0: Seat(0, (self.PW // 2, self.PH // 2))}
        self._seat = self.seats[0]          # the seat whose event is being handled (seat 0 otherwise)
        self.modal: Optional[Modal] = None
        self.pending: deque = deque()
        self.stop_requested = False
        self.detach_on_interrupt = False
        self.detached = False
        self.surface_dirty = True
        self.z_top = Z["window"]
        self.cascade = 0
        self._restarter: Optional[Callable] = restarter        # starts an interface app again (asks for the password)
        self._heal: dict[str, dict] = {}                       # slot -> {name, tries, at}
        self.ws = 0                                          # the workspace being shown
        self._now, self._last_tick, self._last_render = now, 0.0, 0.0
        self._connect, self._opener, self._closer = connect or self._default_connect, opener, closer
        self._modes_of = modes_of or self._default_modes
        self._commands_of = commands_of or (lambda name: {})
        self.composed: Optional[Framebuffer] = None
        self.booted: set[str] = set()
        self.preboot = preboot
        self.prompter = SessionPrompter(self)
        if not keep_prompter:
            authority.prompter = self.prompter
        self.log: list[str] = []
        self.widget_names: list[str] = list(WIDGETS)          # the built-in widgets plus any widget mods
        self.layout = self._load_layout()
        self.cfg = self._load_cfg()
        self.tilt, self.tilt_target = [0.0, 0.0], [0.0, 0.0]
        self._moved_at = self._click_hold = self._last_anim = self._last_cursor = self._fx_until = 0.0
        self._cur_dirty = True
        self.anim_ids: set[str] = set()
        self.nav, self.ring, self.typed = -1, False, ""
        self.stack_open = False                                  # the looks shown as a stack of cards (Ctrl-Up)
        self._stack_rects: list = []
        self.notes: list[dict] = []

        self._base: Optional[Framebuffer] = None
        self._base_sig = None
        self._look_cache = None
        self.dock_w = 0                                      # the dock app asks for its width (resize)

    # -------------------------------------------- per-seat state (the seat whose event is being handled)
    focus = property(lambda self: self._seat.focus, lambda self, v: setattr(self._seat, "focus", v))
    pointer = property(lambda self: self._seat.pointer, lambda self, v: setattr(self._seat, "pointer", v))
    drag = property(lambda self: self._seat.drag, lambda self, v: setattr(self._seat, "drag", v))
    key_target = property(lambda self: self._seat.key_target, lambda self, v: setattr(self._seat, "key_target", v))
    down = property(lambda self: self._seat.down, lambda self, v: setattr(self._seat, "down", v))
    vel = property(lambda self: self._seat.vel)

    def set_workspace(self, n: int) -> None:
        n = max(0, min(WORKSPACES - 1, int(n)))
        if n == self.ws:
            return
        self.ws = n
        for seat in self.seats.values():                     # each seat's focus moves to the top window here, if any
            tops = [w for w in self.windows() if w.ws == n and not w.minimized]
            seat.focus = tops[-1].id if tops else None
        self._touch_all()
        self._push_windows()

    def move_to_workspace(self, layer: Layer, n: int) -> None:
        if layer.kind == "window":
            layer.ws = max(0, min(WORKSPACES - 1, int(n)))
            for seat in self.seats.values():
                if seat.focus == layer.id and layer.ws != self.ws:
                    seat.focus = None
            self._touch_all()
            self._push_windows()

    def seat(self, sid: int) -> Seat:
        """The seat with this id, made on first use (a second mouse plugged in, a second keyboard typing)."""
        sid = sid if isinstance(sid, int) and 0 <= sid < MAX_SEATS else 0
        if sid not in self.seats:
            self.seats[sid] = Seat(sid, (self.PW // 2 + 40 * self.u * sid, self.PH // 2 + 20 * self.u * sid))
            self.surface_dirty = True
        return self.seats[sid]

    # ------------------------------------------------------------------ geometry
    @property
    def bar_h(self) -> int:
        """The top panel's height; windows and widgets live below it."""
        return 11 * self.u + 8

    @property
    def dock_h(self) -> int:
        return 26 * self.u + 6

    @property
    def dock_margin(self) -> int:
        return 7 * self.u

    @property
    def dock_top(self) -> int:
        return self.PH - self.dock_h - self.dock_margin

    def dock_rect(self) -> list[int]:
        w = max(8, min(getattr(self, "dock_w", 0) or 320 * self.u, self.PW - 4 * self.u))
        return [(self.PW - w) // 2, self.dock_top, w, self.dock_h]

    def core_rect(self, name: str) -> tuple[str, list[int]]:
        W, H, u, bar = self.PW, self.PH, self.u, self.bar_h        # everything but the wallpaper sits on the primary output
        wide, m = 200 * u, 8 * u
        kind = KINDS.get(name, "widget")                      # a widget mod has no entry of its own
        if name == "wallpaper":
            return kind, [0, 0, self.W, self.H]
        if name == "menubar":
            return kind, [0, 0, W, bar]
        if name == "cursor":
            box = 40 * u
            p = self.seats[0].pointer
            return kind, [p[0] - box // 2, p[1] - box // 2, box, box]
        if name == "effects":
            box = 96 * u
            return kind, [self.pointer[0] - box // 2, self.pointer[1] - box // 2, box, box]
        if name == "dock":
            return kind, self.dock_rect()
        top = bar + 10 * u
        sx, sh = W - wide - m, H - top - m
        if name == "pins":
            return kind, [16 * u, top + 36 * u, max(40, W - wide - 4 * m - 16 * u), max(40, self.dock_top - top - 44 * u)]
        if name == "search":
            return kind, [28 * u, top, max(60, min(460 * u, W - wide - 6 * m - 28 * u)), 26 * u + 2]
        if name == "sidebar":
            return kind, [sx, top, wide, sh]
        if name == "launcher":
            lw, lh = min(W - 4 * m, 560 * u), min(self.dock_top - bar - 6 * m, 330 * u)
            return kind, [(W - lw) // 2, bar + 3 * m, lw, lh]
        if name == "widgets":
            return kind, [sx, top + SIDE_TAB_H * u + 2 * u, wide, 16 * u]
        for n, rect, _ in self.widget_plan():
            if n == name:
                return kind, rect
        return kind, [sx, top, wide, WIDGET_HEIGHTS.get(name, 56) * u]

    def widget_plan(self) -> list[tuple[str, list[int], bool]]:
        """(widget, rect, shown) in layout order: widgets are stacked in the sidebar's content area and the
        ones that do not fit are hidden (reorder or hide others to see them). Only on the Widgets tab."""
        W, H, u, m = self.PW, self.PH, self.u, 8 * self.u
        wide, top = 200 * u, self.bar_h + 10 * u
        x = W - wide - m
        y = top + SIDE_TAB_H * u + 2 * u + 16 * u + m // 2
        limit = H - m - SHELF_H * u - m // 2
        out = []
        for n in self.layout["order"]:
            h = WIDGET_HEIGHTS.get(n, 56) * u
            shown = n not in self.layout["hidden"] and self.cfg["side_tab"] == "widgets" and y + h <= limit
            out.append((n, [x, y, wide, h], shown))
            if n not in self.layout["hidden"] and y + h <= limit:
                y += h + m // 2
        return out

    def insets(self, name: str = "") -> list[int]:
        """Room an app must leave free inside its layer (none of the current apps need any)."""
        return [0, 0, 0, 0]

    # ---- the widget layout (what the widget handler arranges; remembered across restarts)
    def _layout_file(self):
        return self.paths.state / "shell.json" if self.paths is not None else None

    def _load_layout(self) -> dict:
        import json
        base = {"order": list(self.widget_names), "hidden": []}
        f = self._layout_file()
        try:
            d = json.loads(f.read_text()) if f else {}
        except (OSError, ValueError):
            return base
        return self._clean_layout(d.get("order", []), d.get("hidden", []))

    def _clean_layout(self, order, hidden) -> dict:
        names = self.widget_names
        order = [n for n in order if n in names]
        order += [n for n in names if n not in order]
        return {"order": order, "hidden": [n for n in dict.fromkeys(hidden) if n in names]}

    def _load_cfg(self) -> dict:
        import json
        cfg = dict(DEFAULT_CFG)
        f = self._layout_file()
        try:
            d = json.loads(f.read_text()) if f else {}
        except (OSError, ValueError):
            return cfg
        if d.get("look") in looks.LOOKS:
            cfg["look"] = d["look"]
        for k in ("cursor_direction", "tilt", "bubbles", "blocks"):
            if isinstance(d.get(k), bool):
                cfg[k] = d[k]
        if d.get("side_tab") in ("notifications", "widgets"):
            cfg["side_tab"] = d["side_tab"]
        return cfg

    def _save(self) -> None:
        import json
        from .paths import atomic_write
        f = self._layout_file()
        if f is not None:
            try:
                f.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(f, json.dumps({**self.layout, **self.cfg}).encode())
            except OSError as e:
                self.log.append(f"could not save the layout: {e}")

    def set_layout(self, order, hidden) -> None:
        self.layout = self._clean_layout(order, hidden)
        self._save()
        self.relayout()

    def set_look(self, **opts) -> dict:
        """Change the look or one of its options. Remembered across restarts. Every app is sent a fresh ``hello`` so it redraws in the new
        look. A look drawn by an interface app (3D, virtual reality, ...) starts that app if it is not running - which asks for the password,
        like starting any app - and a look nobody provides an app for is drawn by the OS itself (the terminal look always is)."""
        changed = False
        for k, v in opts.items():
            if k == "look" and v in looks.LOOKS and v != self.cfg["look"]:
                if not self._switch_interface(v):                    # the interface app for this look would not start
                    continue
                self.cfg["look"], changed = v, True
            elif k in ("cursor_direction", "tilt", "bubbles") and isinstance(v, bool) and v != self.cfg[k]:
                self.cfg[k], changed = v, True
        if changed:
            self._save()
            self._base_sig = self._look_cache = None
            self.nav, self.ring, self.typed = -1, False, ""
            for layer in self.layers.values():
                if layer.mode == "graphical":
                    self._hello(layer)
            self._touch_all()
        return dict(self.cfg)

    def relayout(self) -> None:
        for layer in self.layers.values():
            if layer.slot in KINDS and layer.slot not in ("effects", "cursor"):
                _, rect = self.core_rect(layer.slot)
                if layer.slot == "search":
                    rect[3] = layer.rect[3]                     # the search box keeps the height it asked for
                layer.rect[:] = rect
            if layer.slot == "widgets":
                layer.visible = self.cfg["side_tab"] == "widgets"
        for n, rect, shown in self.widget_plan():
            for layer in self.layers.values():
                if layer.slot == n:
                    layer.rect[:] = rect
                    layer.visible = shown
        for layer in self.layers.values():
            if layer.slot == "sidebar":
                layer.send({"cmd": "tab", "name": self.cfg["side_tab"]})
        self._touch_all()
        self._push_widgets()

    def _push_widgets(self) -> None:
        h = next((l for l in self.layers.values() if l.slot == "widgets"), None)
        if h:
            h.send({"cmd": "widgets", "order": self.layout["order"],
                    "widgets": [{"name": n, "title": WIDGET_TITLES.get(n, n.replace("-", " ").title()), "visible": n not in self.layout["hidden"]}
                                for n in self.layout["order"]]})

    def window_rect(self) -> list[int]:
        W, H, u = self.PW, self.PH, self.u
        top, bottom = self.bar_h + 4, self.dock_top - 6 * u
        avail_h = bottom - top
        w, h = (W - 16, avail_h - 8) if W < 640 else (int(W * 0.60), int(avail_h * 0.78))
        off = (self.cascade % 6) * 22 * u
        x = max(4, min(W - w - 4, (W - w) // 3 + off))
        y = top + max(4, min(avail_h - h - 4, (avail_h - h) // 5 + off))
        self.cascade += 1
        return [x, y, w, h]

    @staticmethod
    def _default_connect(sock_path: str) -> Channel:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        return Channel(s)

    @staticmethod
    def _default_modes(name: str) -> list[str]:
        return ["graphical"]

    def add_core(self, inst, slot: Optional[str] = None) -> Layer:
        """Add one of the interface apps. ``slot`` is the part of the interface it fills; for the built-in apps it
        is their own name, for a mod it is the slot the mod declares (a ``widget`` mod fills a new widget slot)."""
        slot = slot or inst.name
        if getattr(inst, "compose", False):                        # an interface app: it draws the desktop, it is not drawn on it
            return self._attach_scene(inst)
        if slot == "widget":                                       # a widget mod: a new widget, not a replacement
            slot = inst.name
            if slot not in self.widget_names:
                self.widget_names.append(slot)
                self.layout = self._clean_layout(self.layout["order"], self.layout["hidden"])
        kind, rect = self.core_rect(slot)
        layer = self._add(inst, kind, rect, "graphical")
        layer.slot = slot
        if slot in self.widget_names:
            layer.visible = next((sh for n, _, sh in self.widget_plan() if n == slot), True)
        elif slot == "widgets":
            layer.visible = self.cfg["side_tab"] == "widgets"
        elif slot == "launcher":
            layer.visible = False                                  # shown by the Super key / the KOS menu
        self._push_widgets()
        return layer

    def _add(self, inst, kind: str, rect: list[int], mode: str, launch: Optional[dict] = None) -> Layer:
        channel = self._connect(inst.sock_path)
        layer = Layer(id=inst.id, name=inst.name, kind=kind, channel=channel, mode=mode, rect=rect,
                      z=Z[kind] if kind != "window" else self._raise_z(), title=inst.name,
                      system=getattr(inst, "system", False), scopes=frozenset(getattr(inst, "scopes", None) or (["*"] if getattr(inst, "system", False) else [])), ticks=getattr(inst, "ticks", False),
                      shell=getattr(inst, "shell", False), pointer=getattr(inst, "pointer", False),
                      animate=getattr(inst, "animate", False), neural=getattr(inst, "neural", False),
                      assistant=getattr(inst, "assistant", False), scene=getattr(inst, "compose", False),
                      scratch=getattr(inst, "scratch", ""))
        if kind == "window":
            layer.ws = self.ws
        self.layers[layer.id] = layer
        self._hello(layer)
        if launch:
            layer.send({"cmd": "launch", **launch})
        for dev in self.booted:                          # the apps learn what the desktop has booted
            layer.send({"cmd": "device", "device": dev, "state": "attached"})
        if layer.allows("links"):
            self._push_links(layer)
        if layer.allows("notify"):
            if self.notes:
                layer.send({"cmd": "notifications", "notes": [{k: n[k] for k in ("id", "app", "title", "body", "t")} for n in self.notes]})
        self._push_windows()
        self.surface_dirty = True
        return layer

    def _raise_z(self) -> int:
        self.z_top += 1
        return self.z_top

    def _hello(self, layer: Layer) -> None:
        if layer.mode == "tui":
            s, cols, rows, _ = self.tui_metrics(layer)
            msg = {"cmd": "hello", "mode": "tui", "width": cols, "height": rows, "scale": 1}
        else:
            _, _, w, h = self.content_rect(layer)
            msg = {"cmd": "hello", "mode": "graphical", "width": w, "height": h, "scale": self.u}
            msg["insets"] = self.insets(layer.name)
            msg["font"] = _font_metrics()
            msg["look"] = self.cfg["look"]
            msg["options"] = {**{k: self.cfg[k] for k in ("cursor_direction", "tilt", "bubbles", "side_tab")},
                              "interfaces": sorted(self._interfaces())}
        layer.send(msg)

    HEAL_DELAYS = (1.0, 3.0, 8.0)                           # seconds before each restart attempt, then give up

    def remove(self, layer_id: str, expected: bool = False) -> None:
        """Drop a layer. An interface app that goes away *unexpectedly* (it crashed, broke the protocol, or its
        channel died) is scheduled for a restart - self-healing - unless the desktop is shutting down."""
        layer = self.layers.pop(layer_id, None)
        if not layer:
            return
        layer.channel.close()
        if layer.scene:
            self._forget_scene(layer_id)
        if not expected and layer.kind != "window" and self._restarter is not None and not self.stop_requested:
            self._schedule_heal(layer)
        self.anim_ids.discard(layer_id)
        for seat in self.seats.values():
            if seat.focus == layer_id:
                seat.focus = None
            if seat.key_target == layer_id:
                seat.key_target = None
        self._push_windows()
        self.surface_dirty = True

    def windows(self) -> list[Layer]:
        return sorted((l for l in self.layers.values() if l.kind == "window"), key=lambda l: l.z)

    def desktop_layer(self) -> Optional[Layer]:
        """The layer that receives the keyboard when no window is focused: the search app."""
        return next((l for l in self.layers.values() if l.slot == "search"), None)

    def _push_windows(self) -> None:
        info = [{"id": w.id, "name": w.name, "title": w.title, "focused": w.id in self.focused_ids(),
                 "minimized": w.minimized, "ws": w.ws} for w in self.windows()]
        d = self.desktop_layer()
        for layer in self.layers.values():
            if layer.allows("apps"):
                layer.send({"cmd": "windows", "windows": info, "desktop": d.id if d else "",
                            "focus": self.seats[0].focus or "", "workspace": self.ws, "workspaces": WORKSPACES})

    # ------------------------------------------------------------------ window actions
    def raise_window(self, layer: Layer) -> None:
        if layer.ws is not None and layer.ws != self.ws:
            self.set_workspace(layer.ws)                       # asking for a window on another desktop goes there
        layer.z = self._raise_z()
        layer.minimized = False
        layer.visible = True
        self.focus = layer.id
        self._touch_all()
        self._push_windows()

    def minimize(self, layer: Layer) -> None:
        layer.minimized, layer.visible = True, False
        if self.focus == layer.id:
            self.focus = None
        self._touch_all()
        self._push_windows()

    def show_desktop(self) -> None:
        for w in self.windows():
            if w.ws == self.ws:
                w.minimized, w.visible = True, False
        self.focus = None
        d = self.desktop_layer()
        if d:
            d.send({"cmd": "focus"})
        self._touch_all()
        self._push_windows()

    def _touch_all(self) -> None:
        for l in self.layers.values():
            l.rev += 1
        self.surface_dirty = True

    def open_window(self, name: str, command: Optional[dict] = None, *, new: bool = False,
                    background: bool = False) -> Optional[Layer]:
        """Show an app in a window. By default an app already in a window is brought forward; ``new`` starts another
        instance (any number may be open, on any desktop); ``background`` opens it minimized, without taking focus."""
        existing = None if new else next((w for w in self.windows() if w.name == name), None)
        if existing:
            if not background:
                self.raise_window(existing)
            if command:
                existing.send({"cmd": "launch", **command})
            return existing
        modes = self._modes_of(name)
        mode = "graphical" if "graphical" in modes else "tui" if "tui" in modes else None
        if mode is None:
            raise ProtocolError(f"{name} has no window mode")
        taken = frozenset(self.layers)
        try:
            inst = self._opener(name, mode, new, taken)
        except TypeError:                                      # an opener that predates the extra arguments
            inst = self._opener(name, mode)
        layer = self._add(inst, "window", self.window_rect(), getattr(inst, "mode", mode) or mode, command)
        if background:
            layer.minimized, layer.visible = True, False
            self._touch_all()
            self._push_windows()
        else:
            self.raise_window(layer)
        return layer

    # -------------------------------------------------------------------- app requests
    def _on_request(self, layer: Layer, msg: dict) -> None:
        def result(ok: bool, detail: str, **extra) -> None:
            layer.send({"cmd": "result", "action": msg["action"], "ok": ok, "detail": detail, **extra})

        action = msg["action"]
        if action == "animate":
            if not layer.animate:
                return result(False, "this app does not have the 'animate' permission")
            (self.anim_ids.add if msg["on"] else self.anim_ids.discard)(layer.id)
            self._last_anim = 0.0
            return result(True, "animating" if msg["on"] else "stopped")
        if action == "look":
            if msg["op"] == "set":
                if not layer.shell:
                    return result(False, "this app does not have the 'shell' permission")
                self.set_look(**{k: v for k, v in msg.items() if k in ("look", "cursor_direction", "tilt", "bubbles")})
            layer.send({"cmd": "look", "look": self.cfg["look"],
                        "options": {**{k: self.cfg[k] for k in ("cursor_direction", "tilt", "bubbles")},
                                    "interfaces": sorted(self._interfaces())}})
            return
        if action == "intent":
            if not layer.neural:
                return result(False, "this app is not a neural driver")
            if self.scene is None or self.scene.slot != "interface:neural":
                return result(False, "the neural interface is not running")
            self.scene.send({"cmd": "intent", "name": msg["name"]})                # the interface app decides what a decision does
            return result(True, msg["name"])
        if action == "propose":
            return self._propose(layer, msg, result)
        if action == "toggle":
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            target = next((l for l in self.layers.values() if msg["app"] in (l.name, l.slot) and l.kind != "window"), None)
            if target is None:
                return result(False, f"{msg['app']} is not part of the interface")
            target.visible = not target.visible
            target.rev += 1
            if target.visible:
                target.send({"cmd": "focus"})
            self._touch_all()
            return result(True, "shown" if target.visible else "hidden")
        if action == "notify":
            if not layer.allows("notify"):
                return result(False, "this app does not have the 'system:notify' permission")
            if msg["op"] == "clear":
                self.notes.clear()
                self._push_notes()
            elif msg["op"] == "dismiss":
                self.notes[:] = [n for n in self.notes if n["id"] != msg["id"]]
                self._push_notes()
            else:
                self.notify(layer.name, msg["title"], msg["body"])
            return result(True, "done")
        if action == "keys":
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            self.key_target = layer.id if msg["on"] else None
            return result(True, "keyboard taken" if msg["on"] else "keyboard released")
        if action == "workspace":
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            if "id" in msg:
                target = self.layers.get(msg["id"])
                if target is None or target.kind != "window":
                    return result(False, "no such window")
                self.move_to_workspace(target, msg["n"])
            else:
                self.set_workspace(msg["n"])
            return result(True, f"workspace {self.ws + 1}")
        if action == "tab":
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            self.cfg["side_tab"] = msg["name"]
            self._save()
            self.relayout()
            return
        if action in ("links", "openlink"):
            if not layer.allows("links"):
                return result(False, "this app does not have the 'system:links' permission")
            from .links import LinkError, Links
            store = Links(self.paths)
            try:
                if action == "links" and msg["op"] == "list":
                    return self._push_links(layer)
                if action == "links":
                    if msg["op"] == "add":
                        store.add(msg["kind"], msg["target"], msg["title"], msg["where"])
                    else:
                        store.remove(msg["id"])
                    self._push_links()
                    return result(True, "saved")
                link = next((l for l in store.list() if l["id"] == msg["id"]), None)
                if link is None:
                    return result(False, "that link no longer exists")
                self.open_link(link)
                return result(True, f"opened {link['title']}")
            except (LinkError, ProtocolError) as e:
                return result(False, str(e))
            except Exception as e:                              # an app that is not installed, a refused password
                self.notify("desktop", "Could not open that", str(e)[:150])
                return result(False, str(e)[:200])
        if action in ("resize", "layout"):                       # shell-level: needs the 'shell' permission
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            if action == "layout":
                self.set_layout(msg.get("order", []), msg.get("hidden", []))
                return result(True, "layout saved")
            x, y, w, h = layer.rect
            if layer.slot == "dock":                                 # the dock stays centred, whatever its width
                self.dock_w = max(8, min(msg.get("w", w), self.W - 4 * self.u))
                layer.rect[:] = self.dock_rect()
            else:
                layer.rect[2] = max(8, min(msg.get("w", w), int(self.W * 0.7)))
                layer.rect[3] = max(8, min(msg.get("h", h), self.H - self.bar_h - y - 4))
            layer.rev += 1
            layer.cache = None
            self.surface_dirty = True
            return result(True, "resized")
        if not layer.allows(action):
            return result(False, f"this app does not have the '{capabilities.needed(action) or 'system'}' permission")
        try:
            if action == "open":
                cid, line = msg.get("command"), msg.get("line")
                cmd = None
                if line:                                         # "print(1)": run this line (the terminal does)
                    cmd = {"command": cid or "line", "line": line}
                elif cid:
                    cmd = {"command": cid, "line": self._commands_of(msg["app"]).get(cid, "")}
                w = self.open_window(msg["app"], cmd, new=bool(msg.get("new")), background=bool(msg.get("background")))
                return result(True, f"opened {msg['app']}", id=w.id if w else "")
            if action == "focus":
                return self._focus_request(layer, msg["id"], result)
            if action == "close":
                target = self.layers.get(msg["id"])
                self._closer(msg["id"])
                if target:
                    self.remove(target.id, expected=True)
                return result(True, f"closed {msg['id']}", id=msg["id"])
        except Exception as e:                                 # a refused password, a bad app: tell the app
            if action in ("open", "close"):
                self.notify("desktop", f"Could not {action} {msg.get('app') or msg.get('id', '')}", str(e)[:150])
            return result(False, str(e)[:200])
        from .system import SystemBridge
        self._bridge(layer).handle(msg, layer.send, self.authority)

    def _bridge(self, layer):
        from .system import SystemBridge
        return SystemBridge(self.paths, scopes=layer.scopes)

    def _focus_request(self, layer: Layer, target_id: str, result) -> None:
        target = self.layers.get(target_id)
        if target is None:
            return result(False, f"{target_id} is not on the desktop")
        if target.slot == "search" or target.kind == "wallpaper":
            self.show_desktop()
        elif target.kind == "window":
            if target.id == self.focus and not target.minimized:
                self.minimize(target)                          # click the focused window's chip: minimize
            else:
                self.raise_window(target)
        result(True, "ok", id=target_id)

    def _handle_app(self, layer: Layer) -> None:
        try:
            raws = layer.channel.receive()
        except ProtocolError as e:
            self.log.append(f"{layer.name}: protocol violation: {e}")
            return self.remove(layer.id)
        for raw in raws:
            try:
                msg = validate_app_message(raw, layer.mode)
            except ProtocolError as e:
                self.log.append(f"{layer.name}: protocol violation: {e}")
                return self.remove(layer.id)
            kind = msg["cmd"]
            if kind == "frame":
                layer.ops, layer.rev = msg["ops"], layer.rev + 1
                if layer.kind == "wallpaper":
                    layer.wall = None
                    self._touch_all()
                self.surface_dirty = True
            elif kind == "screen":
                layer.screen, layer.title = msg, msg["title"] or layer.name
                layer.rev += 1
                self.surface_dirty = True
            elif kind in ("scene", "press"):
                if not layer.scene:
                    self.log.append(f"{layer.name}: {kind} is for interface apps")
                    return self.remove(layer.id)
                (self._on_scene if kind == "scene" else self._scene_press)(layer, msg)
            elif kind == "request":
                self._on_request(layer, msg)
            elif kind == "exit":
                return self.remove(layer.id)
            elif kind == "log":
                self.log.append(f"{layer.name}: {msg['msg']}")
        if layer.channel.closed:
            self.remove(layer.id)

    # ------------------------------------------------------------------------- input
    def at(self, x: int, y: int) -> Optional[Layer]:
        for layer in sorted(self.layers.values(), key=lambda l: -l.z):
            lx, ly, lw, lh = layer.rect
            if self.shown(layer) and layer.kind not in NO_HIT and lx <= x < lx + lw and ly <= y < ly + lh:
                return layer
        return None

    def _local(self, layer: Layer, x: int, y: int) -> tuple[int, int]:
        cx, cy, _, _ = self.content_rect(layer)
        if layer.mode == "tui":
            s, _, _, pad = self.tui_metrics(layer)
            return max(0, (x - cx - pad) // (6 * s)), max(0, (y - cy - pad) // (12 * s))
        return x - cx, y - cy

    def chrome_hit(self, layer: Layer, x: int, y: int) -> Optional[str]:
        """What part of a window frame is at (x, y): close | minimize | title | None (content)."""
        lx, ly, lw, lh = layer.rect
        if y >= ly + self.titlebar:
            return None
        r, u = 5 * self.u, self.u
        cy = ly + self.titlebar // 2
        for name, cx in (("close", lx + 12 * u), ("minimize", lx + 12 * u + 14 * u)):
            if (x - cx) ** 2 + (y - cy) ** 2 <= (r + u) ** 2:
                return name
        return "title"

    def route(self, ev: dict) -> None:
        """Handle one input event for the seat it came from (``ev["seat"]``, default 0)."""
        seat = self.seat(ev.get("seat", 0))
        prev, self._seat = self._seat, seat
        try:
            self._route(ev)
        finally:
            self._seat = prev

    def _route(self, ev: dict) -> None:
        t = ev["type"]
        if t == "interrupt":
            self.stop_requested = True
            return
        if self.scene is not None and not ev.get("flat") and t in ("key", "button", "pointer") and self._scene_wants(ev):
            return                                         # an interface app asked for this input (Alt+arrows, the middle button): it is its own
        if t == "key":
            if ev["key"] == "super":                            # the Super key: the launcher
                self._toggle_named("launcher")
                return
            if ev["key"] in ("ctrl-up", "ctrl-down") or (self.stack_open and ev["key"] == "escape"):
                self.stack_open = ev["key"] == "ctrl-up"          # Ctrl-Up: look down at the stack of looks; Ctrl-Down/Esc: back
                self.surface_dirty = True
                return
            if ev["key"] in ("ctrl-1", "ctrl-2", "ctrl-3", "ctrl-4"):    # Ctrl-1..4: switch desktop
                self.set_workspace(int(ev["key"][-1]) - 1)
                return
            pop = next((l for l in self.layers.values() if l.kind == "popup" and l.visible), None)
            if pop is not None:                                 # the launcher is open: it gets the keyboard
                pop.send({"cmd": "key", "key": ev["key"]})
                return
            if self._nav_key(ev["key"]):
                return
            target = (self.layers.get(self.focus) if self.focus else
                      self.layers.get(self.key_target) if self.key_target else self.desktop_layer())
            if target:
                target.send({"cmd": "key", "key": ev["key"]})
            return
        if "mouse" not in self.booted:
            return
        x, y = ev.get("x", self.pointer[0]), ev.get("y", self.pointer[1])
        x, y = max(0, min(self.W - 1, x)), max(0, min(self.H - 1, y))
        ax, ay = x, y                                    # where the pointer really is on screen...
        if t == "button" and ev.get("pressed") and ev.get("button") == "left" and self.scene is not None and not ev.get("flat"):
            if self._scene_region(ax, ay):                  # a region the interface app declared (a waterfall): the app decides what it means
                self.pointer = (ax, ay)
                self._place_pointer_layers()
                return
        if not ev.get("flat"):
            x, y = self._flat(x, y)                      # ...and where it lands on its flat layer, if an interface app drew the layers elsewhere
        if t == "pointer":
            self._note_motion(ax, ay)
            self.pointer = (ax, ay)
            self._place_pointer_layers()
            self.surface_dirty = True
            if self.drag:
                lid, dx, dy = self.drag
                w = self.layers.get(lid)
                if w:
                    w.rect[0] = max(-w.rect[2] + 60, min(self.W - 60, x - dx))
                    w.rect[1] = max(0, min(self.H - self.bar_h - self.titlebar, y - dy))
                    w.rev += 1
                return
            hit = self.at(x, y)
            if hit and not (hit.kind == "window" and self.chrome_hit(hit, x, y)):
                lx, ly = self._local(hit, x, y)
                hit.send({"cmd": "pointer", "x": lx, "y": ly})
            return
        if t == "button" and self.stack_open:                   # a click on a card of the stack picks that look
            if ev["pressed"]:
                for look, (rx, ry, rw, rh) in reversed(self._stack_rects):
                    if rx <= x < rx + rw and ry <= y < ry + rh:
                        self.set_look(look="3d" if look == "normal" and self.cfg["look"] == "3d" else look)
                        break
                self.stack_open = False
                self.surface_dirty = True
            return
        if t == "button":
            self.pointer = (ax, ay)
            self._place_pointer_layers()
            if ev["button"] == "left":
                self._note_click(ax, ay, ev["pressed"], ev["button"])
            if self.cfg["look"] == "terminal":                  # no picture to aim at: the click picks the row under it
                return self._terminal_click(x, y, ev["pressed"])
            if ev["button"] == "right":
                if ev["pressed"]:
                    self.show_desktop()
                return
            if not ev["pressed"]:
                self.drag = None
                hit = self.at(x, y)
                if hit and not (hit.kind == "window" and self.chrome_hit(hit, x, y)):
                    lx, ly = self._local(hit, x, y)
                    hit.send({"cmd": "button", "button": ev["button"], "pressed": False, "x": lx, "y": ly})
                return
            hit = self.at(x, y)
            pop = next((l for l in self.layers.values() if l.kind == "popup" and l.visible), None)
            if pop is not None and hit is not pop:              # a click outside the launcher closes it
                pop.visible = False
                pop.rev += 1
                self._touch_all()
                return
            if hit is None:
                return
            if hit.kind == "window":
                part = self.chrome_hit(hit, x, y)
                if hit.id != self.focus or hit.minimized:
                    self.raise_window(hit)
                if part == "close":
                    try:
                        self._closer(hit.id)
                        self.remove(hit.id, expected=True)
                    except Exception as e:
                        self.log.append(f"close refused: {e}")
                    return
                if part == "minimize":
                    return self.minimize(hit)
                if part == "title":
                    self.drag = (hit.id, x - hit.rect[0], y - hit.rect[1])
                    return
            elif hit.kind in ("wallpaper", "plain", "sidebar", "widget"):
                self.focus = None
                if self.key_target and hit.id != self.key_target:   # a click elsewhere gives the keyboard back
                    old = self.layers.get(self.key_target)
                    self.key_target = None
                    if old:
                        old.send({"cmd": "keys", "on": False})
                self._push_windows()
            lx, ly = self._local(hit, x, y)
            hit.send({"cmd": "button", "button": ev["button"], "pressed": True, "x": lx, "y": ly})
            return
        if t == "scroll":
            hit = self.at(x, y)
            if hit:
                lx, ly = self._local(hit, x, y)
                hit.send({"cmd": "scroll", "dy": ev["dy"], "x": lx, "y": ly})

    # ------------------------------------------------- pointer, clicks, tilt, animation, controls
    def _place_pointer_layers(self) -> None:
        if self._seat.id != 0:
            return                                              # only seat 0's pointer is drawn by the cursor app
        for layer in self.layers.values():
            if layer.kind == "cursor":
                layer.rect[:] = self.core_rect("cursor")[1]

    def _note_motion(self, x: int, y: int) -> None:
        dx, dy = x - self.pointer[0], y - self.pointer[1]
        if not dx and not dy:
            return
        self.vel[0], self.vel[1] = 0.55 * self.vel[0] + 0.45 * dx, 0.55 * self.vel[1] + 0.45 * dy
        self._moved_at = time.monotonic()
        self._cur_dirty = True
        if self.cfg["look"] == "3d" and self.cfg["tilt"] and self._seat.id == 0:
            k = TILT_PX * self.u
            m = max(abs(self.vel[0]), abs(self.vel[1]), 1.0)
            self.tilt_target[0] = max(-k, min(k, self.vel[0] / m * k * min(1.0, m / 12)))
            self.tilt_target[1] = max(-k, min(k, self.vel[1] / m * k * min(1.0, m / 12)))

    def _note_click(self, x: int, y: int, pressed: bool, button: str) -> None:
        self.down = pressed
        if self._seat.id == 0:
            self._cur_dirty = True
        for layer in self.layers.values():
            if layer.pointer:
                layer.send({"cmd": "click", "x": x, "y": y, "button": button, "pressed": pressed, "seat": self._seat.id})
        if pressed and self.cfg["look"] == "3d":
            now = time.monotonic()
            if self.cfg["bubbles"]:
                for layer in self.layers.values():
                    if layer.kind == "overlay":
                        layer.rect[:] = self.core_rect("effects")[1]
                        layer.visible = True
                        self._fx_until = now + 1.2
            if self.cfg["tilt"] and self._seat.id == 0:
                k = TILT_PX * self.u
                self.tilt_target[0] = (x - self.W / 2) / (self.W / 2) * k
                self.tilt_target[1] = (y - self.H / 2) / (self.H / 2) * k
                self._click_hold = now + 0.18

    def _schedule_heal(self, layer: Layer) -> None:
        e = self._heal.get(layer.slot)
        if e is None:
            e = self._heal[layer.slot] = {"name": layer.name, "tries": 0, "at": 0.0}
            self.notify("desktop", f"{layer.name} stopped", "Restarting it. This needs your password unless a sudo window is open.")
        e["name"] = layer.name
        e["at"] = time.monotonic() + self.HEAL_DELAYS[min(e["tries"], len(self.HEAL_DELAYS) - 1)]

    def _run_heal(self, now: float) -> None:
        from .mods import DEFAULTS
        for slot, e in list(self._heal.items()):
            if now < e["at"] or self._restarter is None:
                continue
            try:
                inst = self._restarter(e["name"])
                self.add_core(inst, slot=slot)
                del self._heal[slot]
                self.log.append(f"healed {slot}: restarted {e['name']}")
            except AuthorizationDenied as ex:                  # the owner did not type the password: do not nag
                del self._heal[slot]
                self.notify("desktop", f"{e['name']} was not restarted", "No password was given. `kos heal` or restarting the desktop brings it back.")
            except Exception as ex:
                e["tries"] += 1
                self.log.append(f"heal {slot} attempt {e['tries']} failed: {ex}")
                if e["tries"] >= len(self.HEAL_DELAYS):
                    default = DEFAULTS.get(slot)
                    if default and e["name"] != default:       # a mod that keeps failing: fall back to the built-in app
                        self.notify("desktop", f"{e['name']} keeps failing", f"Using the built-in {default} instead.")
                        e["name"], e["tries"] = default, 0
                    else:
                        del self._heal[slot]
                        self.notify("desktop", f"{e['name']} keeps stopping", "Giving up for now. Run `kos heal` to look into it.")
                        continue
                e["at"] = now + self.HEAL_DELAYS[min(e["tries"], len(self.HEAL_DELAYS) - 1)]

    def _update_motion(self, now: float) -> None:
        """Called every step: ease the tilt, feed the pointer app, run the animation clock, heal what stopped."""
        if self._heal:
            self._run_heal(now)
        if self.cfg["look"] == "3d":
            if now > self._click_hold and now - self._moved_at > 0.05:
                self.tilt_target[0] *= 0.6
                self.tilt_target[1] *= 0.6
            moving = False
            for i in (0, 1):
                self.tilt[i] += (self.tilt_target[i] - self.tilt[i]) * 0.4
                if abs(self.tilt[i]) < 0.15 and abs(self.tilt_target[i]) < 0.15:
                    self.tilt[i] = self.tilt_target[i] = 0.0
                moving = moving or abs(self.tilt[i]) >= 0.15
            if moving:
                self.surface_dirty = True
        elif any(self.tilt) or any(self.tilt_target):
            self.tilt, self.tilt_target = [0.0, 0.0], [0.0, 0.0]
            self.surface_dirty = True
        if self._cur_dirty and now - self._last_cursor >= 0.05:
            self._cur_dirty, self._last_cursor = False, now
            for layer in self.layers.values():
                if layer.pointer and layer.kind == "cursor":
                    s0 = self.seats[0]
                    layer.send({"cmd": "cursor", "x": s0.pointer[0], "y": s0.pointer[1],
                                "dx": round(s0.vel[0], 2), "dy": round(s0.vel[1], 2), "down": s0.down})
            self.surface_dirty = True
        if self.anim_ids and now - self._last_anim >= 1 / 24:
            dt, self._last_anim = now - self._last_anim, now
            for lid in list(self.anim_ids):
                layer = self.layers.get(lid)
                if layer is None:
                    self.anim_ids.discard(lid)
                else:
                    layer.send({"cmd": "anim", "t": now, "dt": round(min(dt, 0.2), 3)})
        for layer in self.layers.values():
            if layer.kind == "overlay" and layer.visible and now > self._fx_until and layer.id not in self.anim_ids:
                layer.visible = False
                self.surface_dirty = True

    def _toggle_named(self, name: str) -> None:
        target = next((l for l in self.layers.values() if name in (l.name, l.slot) and l.kind != "window"), None)
        if target is not None:
            target.visible = not target.visible
            target.rev += 1
            if target.visible:
                target.send({"cmd": "focus"})                   # shown: reset its state (the launcher clears its search)
            self._touch_all()

    def _push_links(self, only: Optional[Layer] = None) -> None:
        from .links import Links
        msg = {"cmd": "links", "links": Links(self.paths).list()}
        for layer in ([only] if only else list(self.layers.values())):
            if layer.allows("links"):
                layer.send(msg)

    def open_link(self, link: dict) -> None:
        """Open a pinned link: the OS looks up what it points to and starts the right app for it."""
        kind, target = link["kind"], link["target"]
        if kind == "app":
            self.open_window(target)
        elif kind == "file":
            self.open_window("editor", {"command": "open-file", "line": target})
        elif kind == "folder":
            self.open_window("files", {"command": "open-path", "line": target})
        else:
            self.open_window("browser", {"command": "open-url", "line": target})

    NOTE_LIMIT = 50

    def notify(self, app: str, title: str, body: str) -> None:
        """Post a notification (shown by the sidebar). At most 5 a second from one app, 50 kept."""
        now = time.monotonic()
        recent = [n for n in self.notes if n["app"] == app and now - n["mono"] < 1.0]
        if len(recent) >= 5 or not (title or body):
            return
        self.notes.append({"id": f"n{int(now * 1000)}-{len(self.notes)}", "app": app, "title": title, "body": body,
                           "t": self._now(), "mono": now})
        del self.notes[:-self.NOTE_LIMIT]
        self._push_notes()

    def _push_notes(self) -> None:
        payload = [{k: n[k] for k in ("id", "app", "title", "body", "t")} for n in self.notes]
        for layer in self.layers.values():
            if layer.allows("notify"):
                layer.send({"cmd": "notifications", "notes": payload})

    def activate(self, c: "looks.Control") -> None:
        """Press a control: exactly what clicking it would do."""
        layer = self.layers.get(c.layer)
        if layer is None:
            return
        if c.kind == "close":
            try:
                self._closer(layer.id)
                self.remove(layer.id, expected=True)
            except Exception as e:
                self.log.append(f"close refused: {e}")
            return
        if c.kind == "minimize":
            return self.minimize(layer)
        if layer.kind == "window" and (layer.id != self.focus or layer.minimized):
            self.raise_window(layer)
        if c.kind == "focus":
            return
        x, y = c.center
        lx, ly = self._local(layer, x, y)
        for pressed in (True, False):
            layer.send({"cmd": "button", "button": "left", "pressed": pressed, "x": lx, "y": ly})

    def _nav_key(self, key: str) -> bool:
        """Keyboard navigation of the controls. Terminal look: always. Other looks: Tab starts it (when no
        window is focused, so apps keep their own Tab), Enter presses, Esc leaves."""
        look = self.cfg["look"]
        terminal = look == "terminal"
        if not terminal and not self.ring:
            if key == "tab" and self.focus is None:
                self.ring, self.nav = True, 0
                self.surface_dirty = True
                return True
            return False
        ctl = self.controls()
        n = len(ctl)
        if n == 0:
            return False
        if key in ("down", "right", "tab"):
            self.nav = (self.nav + 1) % n
        elif key in ("up", "left"):
            self.nav = (self.nav - 1) % n
        elif key == "enter" and 0 <= self.nav < n:
            self.typed = ""
            self.activate(ctl[self.nav])
            if not terminal:
                self.ring = False
        elif key == "escape":
            if self.typed:
                self.typed = ""
            elif not terminal:
                self.ring = False
            else:
                return False
        elif terminal and key.isdigit() and len(key) == 1:
            self.typed = (self.typed + key)[:4]
            self.nav = max(0, min(n - 1, int(self.typed) - 1))
        elif terminal and key == "backspace" and self.typed:
            self.typed = self.typed[:-1]
            if self.typed:
                self.nav = max(0, min(n - 1, int(self.typed) - 1))
        else:
            if not terminal:
                self.ring = False                      # any other key: back to normal typing
                self.surface_dirty = True
                return False
            return False                               # terminal look: letters still reach the search box
        self.surface_dirty = True
        return True

    def _terminal_click(self, x: int, y: int, pressed: bool) -> None:
        if not pressed:
            return
        ctl = self.controls()
        ch = 12 * self.u
        self._look_frame()                                  # make sure the row map matches what is on screen
        row_of = getattr(self, "_term_rows", {})
        i = row_of.get(y // ch)
        if i is not None:
            self.nav = i
            self.activate(ctl[i])
        self.surface_dirty = True

    # ---------------------------------------------------------------------- painting
    def show_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal
        self.surface_dirty = True

    def _stack_frame(self) -> Framebuffer:
        """The looks as cards in space: terminal and buttons behind, the interface in front."""
        saved = self.cfg["look"]
        try:
            self.cfg["look"] = "terminal"
            ctl = self.controls()
            term, _ = looks.render_terminal(self, ctl, self.nav, self.typed)
            text = looks.render_text(self)
            self.cfg["look"] = "normal"
            front = self.compose().copy()
        finally:
            self.cfg["look"] = saved
        frame, self._stack_rects = looks.stack(self, [("terminal", "Terminal: every button in a list", term),
                                                     ("text", "Buttons: all text, Tab and Enter", text),
                                                     ("normal", "Interface", front)])
        return frame

    def _look_frame(self) -> Framebuffer:
        """The frame for the current look, before the pointer is drawn."""
        if self.stack_open:
            return self._stack_frame()
        look = self.cfg["look"]
        if self.scene is not None and look not in ("terminal",):
            self._scene_sync()
            if self._scene_frame is not None:                           # an interface app draws this look: its frame is the screen
                fb = self._scene_frame.copy()
                if look == "3d" and (abs(self.tilt[0]) >= 0.5 or abs(self.tilt[1]) >= 0.5):
                    fb = looks.shear(fb, self.tilt[0], self.tilt[1])
                return fb
        if look in ("text", "terminal"):
            ctl = self.controls() if look == "terminal" else []
            sig = (look, self._base_signature(), self.nav, self.typed, self.ring, tuple(c.rect for c in ctl))
            if self._look_cache and self._look_cache[0] == sig:
                return self._look_cache[1]
            if look == "text":
                fb = looks.render_text(self)
            else:
                fb, self._term_rows = looks.render_terminal(self, ctl, self.nav, self.typed)
            self._look_cache = (sig, fb)
            return fb.copy()
        fb = self.compose().copy()
        if look == "3d" and (abs(self.tilt[0]) >= 0.5 or abs(self.tilt[1]) >= 0.5):
            fb = looks.shear(fb, self.tilt[0], self.tilt[1])
        return fb

    # ------------------------------------------------------------------ the 3D look: every layer is a block
    def _propose(self, layer: Layer, msg: dict, result) -> None:
        """An assistant's plan. It needs the assist permission; every step must be a launching/looking action the assistant also holds the scope
        for; the owner is shown the plan and must type the password (never remembered, so a sudo window cannot approve it); then each step runs
        *as the assistant* - with its scopes, and with whatever password that step needs on its own."""
        if not layer.assistant:
            return result(False, "this app is not an assistant (it does not have the 'assist' permission)")
        steps = msg["steps"]
        for st in steps:
            if not layer.allows(st["action"]):
                return result(False, f"the plan needs '{capabilities.needed(st['action'])}', which this assistant does not hold")
        summary = "; ".join(self._describe_step(st) for st in steps)
        self.notify(layer.name, "Plan awaiting your approval", f"{msg['title']}: {summary}"[:240])
        try:
            self.authority.authorize("assistant.plan", f"{layer.name}: {msg['title']} - {summary}"[:300]).close()
        except Exception as e:                                   # a wrong password, a cancelled prompt
            self.log.append(f"plan refused: {e}")
            return result(False, "the owner did not approve the plan; nothing was run")
        done = 0
        for st in steps:
            self._on_request(layer, st)                           # as the assistant: its scopes, and the step's own password
            done += 1
        result(True, f"approved: ran {done} step(s)")

    @staticmethod
    def _describe_step(st: dict) -> str:
        bits = [st["action"]] + [str(st[k]) for k in ("app", "path", "id", "kind") if st.get(k)]
        return " ".join(bits)[:60]

    def _draw_modal(self, fb: Framebuffer) -> None:
        """The trusted password prompt, centered on the primary output (not on the whole wide screen)."""
        if len(self.outputs) <= 1:
            return draw_modal(fb, self.modal, self.u)
        px, py, pw, ph = self.outputs[0]
        sub = crop(fb, px, py, pw, ph)
        draw_modal(sub, self.modal, self.u)
        stride = fb.width * 4
        for r in range(ph):
            fb.buf[(py + r) * stride + px * 4:(py + r) * stride + (px + pw) * 4] = sub.buf[r * pw * 4:(r + 1) * pw * 4]

    def render(self) -> None:
        fb = self._look_frame()
        if self.cfg["look"] != "terminal" and self.ring:
            ctl = self.controls()
            if 0 <= self.nav < len(ctl):
                looks.draw_ring(fb, ctl[self.nav].rect, self.u * (2 if self.cfg["look"] == "neural" else 1))
        if not self.modal and not (self.scene is not None and self._scene_frame is not None and self.scene_pointer):   # an interface app that draws the pointer itself (once per eye) says so
            cur = next((l for l in self.layers.values() if l.kind == "cursor" and l.visible and l.ops), None)
            if cur is not None:
                self._paint_content(fb, cur)
            else:
                draw_cursor(fb, *self.seats[0].pointer, scale=self.u)
            for sid, seat in self.seats.items():                 # more pointers: the OS draws them, each with its seat's colour
                if sid:
                    draw_cursor(fb, *seat.pointer, scale=self.u)
                    fbgfx.circle(fb, seat.pointer[0] + 14 * self.u, seat.pointer[1] + 14 * self.u, 4 * self.u, SEAT_COLORS[sid % len(SEAT_COLORS)])
        if getattr(self.backend, "text_overlay", False):
            self.backend.show(fb, self.modal)
        else:
            if self.modal:
                self._draw_modal(fb)
            self.backend.show(fb)
        self.surface_dirty = False

    def pull_input(self, timeout: float, include_app: bool) -> None:
        fds = list(self.devices.fds())
        chans = [l.channel for l in self.layers.values() if not l.channel.closed] if include_app else []
        r, _, _ = select.select(fds + chans, [], [], timeout)
        for item in r:
            if item in chans:
                layer = next((l for l in self.layers.values() if l.channel is item), None)
                if layer:
                    self._handle_app(layer)
            else:
                self.pending.extend(self.devices.read(item))

    def boot_devices(self) -> None:
        for dev in self.preboot:
            try:
                getattr(self.devices, f"boot_{dev}")()
            except Exception as e:
                self.log.append(f"{dev}: {e}")
                continue
            self.booted.add(dev)

    def tick(self) -> None:
        t = self._now()
        if t - self._last_tick < 1.0:
            return
        self._last_tick = t
        lt = time.localtime(t)
        local = {"year": lt.tm_year, "month": lt.tm_mon, "day": lt.tm_mday, "hour": lt.tm_hour,
                 "minute": lt.tm_min, "second": lt.tm_sec, "weekday": lt.tm_wday, "yday": lt.tm_yday,
                 "zone": lt.tm_zone or "", "offset": lt.tm_gmtoff or 0}
        for layer in list(self.layers.values()):
            if layer.ticks:
                layer.send({"cmd": "tick", "t": t, "local": local})

    MIN_FRAME = 0.033                     # at most ~30 repaints a second (the base frame is cached)

    def pump(self, timeout: float = 0.1) -> None:
        """Handle input and app messages without painting."""
        self.pull_input(timeout, include_app=True)
        while self.pending and not self.stop_requested:
            self.route(self.pending.popleft())
        self.tick()
        if self.scene is not None:
            self._scene_sync()                              # the interface app hears what changed even when nothing is being painted
        self._update_motion(time.monotonic())

    def step(self, timeout: float = 0.1) -> None:
        now = time.monotonic()
        if self.surface_dirty and now - self._last_render >= self.MIN_FRAME:
            self.render()
            self._last_render = time.monotonic()
        self.pump(timeout)

    def run(self) -> None:
        self.boot_devices()
        for layer in self.layers.values():
            for dev in self.booted:
                layer.send({"cmd": "device", "device": dev, "state": "attached"})
        try:
            while not self.stop_requested:
                self.step(0.25)
        finally:
            self.close()

    def close(self) -> None:
        for layer in list(self.layers.values()):
            layer.channel.close()                       # detach: the apps keep running
        self.layers.clear()
