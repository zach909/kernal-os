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

import select
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import fbgfx, ttf
from .auth import Authority
from .display import Framebuffer, Modal, draw_cursor, draw_modal, parse_color
from .protocol import Channel, ProtocolError, validate_app_message
from .registry import Registry
from .session import SessionPrompter

# The interface is a series of separate apps. The OS composites them; it does not draw them.
#   wallpaper  the background            icons   the app icon grid        search  the search box + results
#   widgets    the widget handler        widget-*  the widgets
#   menubar    the top panel: menus, stats, clock             dock    the floating dock: pinned + running apps
CORE = ("wallpaper", "icons", "search", "widgets", "widget-clock", "widget-calendar", "widget-network",
        "widget-system", "menubar", "dock")
WIDGETS = ("widget-clock", "widget-calendar", "widget-network", "widget-system")
WIDGET_TITLES = {"widget-clock": "Clock", "widget-calendar": "Calendar", "widget-network": "Network",
                 "widget-system": "System"}
WIDGET_HEIGHTS = {"widget-clock": 64, "widget-calendar": 124, "widget-network": 52, "widget-system": 84}
KINDS = {"wallpaper": "wallpaper", "icons": "plain", "search": "plain", "widgets": "widget", "menubar": "bar",
         "dock": "dock", **{w: "widget" for w in WIDGETS}}
ACCENT = "#0078d4"                  # Windows Blue: active states, selection, focus
GLASS = {"tint": "#dfe8f5", "alpha": 0.16, "radius": 4}
BAR_GLASS = {"tint": "#0d1016", "alpha": 0.42, "radius": 5}
DOCK_GLASS = {"tint": "#e9eff8", "alpha": 0.20, "radius": 5}
WINDOW_BODY = {"tint": "#12151b", "alpha": 0.84, "radius": 4}
TITLE_TINT = ("#4a505c", "#20242c")
Z = {"wallpaper": 0, "plain": 4, "widget": 10, "window": 20, "bar": 90, "dock": 91, "top": 92}


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
    ticks: bool = False
    shell: bool = False            # may resize itself / arrange the widgets
    rev: int = 0                   # bumps whenever what this layer shows changes
    cache: Optional[tuple] = None  # (signature, region rows) of its glass, before content

    def send(self, obj: dict) -> None:
        self.channel.send(obj)


class Shell:
    def __init__(self, paths, authority: Authority, backend, devices, *,
                 connect: Optional[Callable] = None, opener: Optional[Callable] = None,
                 closer: Optional[Callable] = None, modes_of: Optional[Callable] = None,
                 commands_of: Optional[Callable] = None, keep_prompter: bool = False,
                 preboot: tuple[str, ...] = ("mouse", "keyboard"), now: Callable[[], float] = time.time):
        self.paths, self.authority, self.backend, self.devices = paths, authority, backend, devices
        self.W, self.H = backend.width, backend.height
        self.u = max(1, self.H // 360)                      # UI scale: 1 at 640x360, 2 at 720p, 3 at 1080p
        self.layers: dict[str, Layer] = {}
        self.focus: Optional[str] = None
        self.pointer = (self.W // 2, self.H // 2)
        self.drag: Optional[tuple[str, int, int]] = None
        self.modal: Optional[Modal] = None
        self.pending: deque = deque()
        self.stop_requested = False
        self.detach_on_interrupt = False
        self.detached = False
        self.surface_dirty = True
        self.z_top = Z["window"]
        self.cascade = 0
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
        self.layout = self._load_layout()
        self.dock_w = 0                                      # the dock app asks for its width (resize)

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
        return self.H - self.dock_h - self.dock_margin

    def dock_rect(self) -> list[int]:
        w = max(8, min(getattr(self, "dock_w", 0) or 320 * self.u, self.W - 4 * self.u))
        return [(self.W - w) // 2, self.dock_top, w, self.dock_h]

    @property
    def titlebar(self) -> int:
        return 9 * self.u + 10

    def core_rect(self, name: str) -> tuple[str, list[int]]:
        W, H, u, bar = self.W, self.H, self.u, self.bar_h
        wide, m = 200 * u, 8 * u
        kind = KINDS[name]
        if name == "wallpaper":
            return kind, [0, 0, W, H]
        if name == "menubar":
            return kind, [0, 0, W, bar]
        if name == "dock":
            return kind, self.dock_rect()
        top = bar + 10 * u
        if name == "icons":
            return kind, [16 * u, top + 36 * u, max(40, W - wide - 4 * m - 16 * u),
                          max(40, self.dock_top - top - 44 * u)]
        if name == "search":
            return kind, [28 * u, top, max(60, min(460 * u, W - wide - 6 * m - 28 * u)), 26 * u + 2]
        dock_h = 16 * u
        if name == "widgets":
            return kind, [W - wide - m, top, wide, dock_h]
        y = top + dock_h + m
        for n in self.layout["order"]:
            if n in self.layout["hidden"]:
                continue
            h = WIDGET_HEIGHTS[n] * u
            if n == name:
                return kind, [W - wide - m, y, wide, h]
            y += h + m
        return kind, [W - wide - m, y, wide, WIDGET_HEIGHTS[name] * u]          # hidden: not shown, rect irrelevant

    def insets(self, name: str = "") -> list[int]:
        """Room an app must leave free inside its layer (none of the current apps need any)."""
        return [0, 0, 0, 0]

    # ---- the widget layout (what the widget handler arranges; remembered across restarts)
    def _layout_file(self):
        return self.paths.state / "shell.json" if self.paths is not None else None

    def _load_layout(self) -> dict:
        import json
        base = {"order": list(WIDGETS), "hidden": []}
        f = self._layout_file()
        try:
            d = json.loads(f.read_text()) if f else {}
        except (OSError, ValueError):
            return base
        return self._clean_layout(d.get("order", []), d.get("hidden", []))

    @staticmethod
    def _clean_layout(order, hidden) -> dict:
        order = [n for n in order if n in WIDGETS]
        order += [n for n in WIDGETS if n not in order]
        return {"order": order, "hidden": [n for n in dict.fromkeys(hidden) if n in WIDGETS]}

    def set_layout(self, order, hidden) -> None:
        import json
        from .paths import atomic_write
        self.layout = self._clean_layout(order, hidden)
        f = self._layout_file()
        if f is not None:
            try:
                f.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(f, json.dumps(self.layout).encode())
            except OSError as e:
                self.log.append(f"could not save the layout: {e}")
        self.relayout()

    def relayout(self) -> None:
        for layer in self.layers.values():
            if layer.name in KINDS:
                _, rect = self.core_rect(layer.name)
                if layer.name == "search":
                    rect[3] = layer.rect[3]                     # the search box keeps the height it asked for
                layer.rect[:] = rect
            if layer.name in WIDGETS:
                layer.visible = layer.name not in self.layout["hidden"]
        self._touch_all()
        self._push_widgets()

    def _push_widgets(self) -> None:
        h = next((l for l in self.layers.values() if l.name == "widgets"), None)
        if h:
            h.send({"cmd": "widgets", "order": self.layout["order"],
                    "widgets": [{"name": n, "title": WIDGET_TITLES[n], "visible": n not in self.layout["hidden"]}
                                for n in self.layout["order"]]})

    def window_rect(self) -> list[int]:
        W, H, u = self.W, self.H, self.u
        top, bottom = self.bar_h + 4, self.dock_top - 6 * u
        avail_h = bottom - top
        w, h = (W - 16, avail_h - 8) if W < 640 else (int(W * 0.60), int(avail_h * 0.78))
        off = (self.cascade % 6) * 22 * u
        x = max(4, min(W - w - 4, (W - w) // 3 + off))
        y = top + max(4, min(avail_h - h - 4, (avail_h - h) // 5 + off))
        self.cascade += 1
        return [x, y, w, h]

    def content_rect(self, layer: Layer) -> tuple[int, int, int, int]:
        x, y, w, h = layer.rect
        if layer.kind != "window":
            return x, y, w, h
        return x + 1, y + self.titlebar, w - 2, h - self.titlebar - 1

    def tui_metrics(self, layer: Layer) -> tuple[int, int, int, int]:
        """(scale, columns, rows, padding) of a text-mode window."""
        _, _, cw, ch = self.content_rect(layer)
        s, pad = self.u, 5 * self.u
        return s, max(8, (cw - 2 * pad) // (6 * s)), max(3, (ch - 2 * pad - 14 * s) // (12 * s)), pad

    # --------------------------------------------------------------- layer lifecycle
    @staticmethod
    def _default_connect(sock_path: str) -> Channel:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        return Channel(s)

    @staticmethod
    def _default_modes(name: str) -> list[str]:
        return ["graphical"]

    def add_core(self, inst) -> Layer:
        kind, rect = self.core_rect(inst.name)
        layer = self._add(inst, kind, rect, "graphical")
        if inst.name in WIDGETS:
            layer.visible = inst.name not in self.layout["hidden"]
        self._push_widgets()
        return layer

    def _add(self, inst, kind: str, rect: list[int], mode: str, launch: Optional[dict] = None) -> Layer:
        channel = self._connect(inst.sock_path)
        layer = Layer(id=inst.id, name=inst.name, kind=kind, channel=channel, mode=mode, rect=rect,
                      z=Z[kind] if kind != "window" else self._raise_z(), title=inst.name,
                      system=getattr(inst, "system", False), ticks=getattr(inst, "ticks", False),
                      shell=getattr(inst, "shell", False))
        self.layers[layer.id] = layer
        self._hello(layer)
        if launch:
            layer.send({"cmd": "launch", **launch})
        for dev in self.booted:                          # the apps learn what the desktop has booted
            layer.send({"cmd": "device", "device": dev, "state": "attached"})
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
        layer.send(msg)

    def remove(self, layer_id: str) -> None:
        layer = self.layers.pop(layer_id, None)
        if not layer:
            return
        layer.channel.close()
        if self.focus == layer_id:
            self.focus = None
        self._push_windows()
        self.surface_dirty = True

    def windows(self) -> list[Layer]:
        return sorted((l for l in self.layers.values() if l.kind == "window"), key=lambda l: l.z)

    def desktop_layer(self) -> Optional[Layer]:
        """The layer that receives the keyboard when no window is focused: the search app."""
        return next((l for l in self.layers.values() if l.name == "search"), None)

    def wallpaper_layer(self) -> Optional[Layer]:
        return next((l for l in self.layers.values() if l.kind == "wallpaper"), None)

    def _push_windows(self) -> None:
        info = [{"id": w.id, "name": w.name, "title": w.title, "focused": w.id == self.focus,
                 "minimized": w.minimized} for w in self.windows()]
        d = self.desktop_layer()
        for layer in self.layers.values():
            if layer.system:
                layer.send({"cmd": "windows", "windows": info, "desktop": d.id if d else "",
                            "focus": self.focus or ""})

    # ------------------------------------------------------------------ window actions
    def raise_window(self, layer: Layer) -> None:
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

    def open_window(self, name: str, command: Optional[dict] = None) -> Optional[Layer]:
        existing = next((w for w in self.windows() if w.name == name), None)
        if existing:
            self.raise_window(existing)
            if command:
                existing.send({"cmd": "launch", **command})
            return existing
        modes = self._modes_of(name)
        mode = "graphical" if "graphical" in modes else "tui" if "tui" in modes else None
        if mode is None:
            raise ProtocolError(f"{name} has no window mode")
        inst = self._opener(name, mode)
        layer = self._add(inst, "window", self.window_rect(), mode, command)
        self.raise_window(layer)
        return layer

    # -------------------------------------------------------------------- app requests
    def _on_request(self, layer: Layer, msg: dict) -> None:
        def result(ok: bool, detail: str, **extra) -> None:
            layer.send({"cmd": "result", "action": msg["action"], "ok": ok, "detail": detail, **extra})

        action = msg["action"]
        if action in ("resize", "layout"):                       # shell-level: needs the 'shell' permission
            if not layer.shell:
                return result(False, "this app does not have the 'shell' permission")
            if action == "layout":
                self.set_layout(msg.get("order", []), msg.get("hidden", []))
                return result(True, "layout saved")
            x, y, w, h = layer.rect
            if layer.name == "dock":                                 # the dock stays centred, whatever its width
                self.dock_w = max(8, min(msg.get("w", w), self.W - 4 * self.u))
                layer.rect[:] = self.dock_rect()
            else:
                layer.rect[2] = max(8, min(msg.get("w", w), int(self.W * 0.7)))
                layer.rect[3] = max(8, min(msg.get("h", h), self.H - self.bar_h - y - 4))
            layer.rev += 1
            layer.cache = None
            self.surface_dirty = True
            return result(True, "resized")
        if not layer.system:
            return result(False, "this app does not have the 'system' permission")
        try:
            if action == "open":
                cid, line = msg.get("command"), msg.get("line")
                cmd = None
                if line:                                         # "print(1)": run this line (the terminal does)
                    cmd = {"command": cid or "line", "line": line}
                elif cid:
                    cmd = {"command": cid, "line": self._commands_of(msg["app"]).get(cid, "")}
                w = self.open_window(msg["app"], cmd)
                return result(True, f"opened {msg['app']}", id=w.id if w else "")
            if action == "focus":
                return self._focus_request(layer, msg["id"], result)
            if action == "close":
                target = self.layers.get(msg["id"])
                self._closer(msg["id"])
                if target:
                    self.remove(target.id)
                return result(True, f"closed {msg['id']}", id=msg["id"])
        except Exception as e:                                 # a refused password, a bad app: tell the app
            return result(False, str(e)[:200])
        from .system import SystemBridge
        self._bridge().handle(msg, layer.send, self.authority)

    def _bridge(self):
        from .system import SystemBridge
        return SystemBridge(self.paths)

    def _focus_request(self, layer: Layer, target_id: str, result) -> None:
        target = self.layers.get(target_id)
        if target is None:
            return result(False, f"{target_id} is not on the desktop")
        if target.name == "search" or target.kind == "wallpaper":
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
            if layer.visible and lx <= x < lx + lw and ly <= y < ly + lh:
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
        t = ev["type"]
        if t == "interrupt":
            self.stop_requested = True
            return
        if t == "key":
            target = self.layers.get(self.focus) if self.focus else self.desktop_layer()
            if target:
                target.send({"cmd": "key", "key": ev["key"]})
            return
        if "mouse" not in self.booted:
            return
        x, y = ev.get("x", self.pointer[0]), ev.get("y", self.pointer[1])
        x, y = max(0, min(self.W - 1, x)), max(0, min(self.H - 1, y))
        if t == "pointer":
            self.pointer = (x, y)
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
        if t == "button":
            self.pointer = (x, y)
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
            if hit is None:
                return
            if hit.kind == "window":
                part = self.chrome_hit(hit, x, y)
                if hit.id != self.focus or hit.minimized:
                    self.raise_window(hit)
                if part == "close":
                    try:
                        self._closer(hit.id)
                        self.remove(hit.id)
                    except Exception as e:
                        self.log.append(f"close refused: {e}")
                    return
                if part == "minimize":
                    return self.minimize(hit)
                if part == "title":
                    self.drag = (hit.id, x - hit.rect[0], y - hit.rect[1])
                    return
            elif hit.kind in ("wallpaper", "plain"):
                self.focus = None
                self._push_windows()
            lx, ly = self._local(hit, x, y)
            hit.send({"cmd": "button", "button": ev["button"], "pressed": True, "x": lx, "y": ly})
            return
        if t == "scroll":
            hit = self.at(x, y)
            if hit:
                lx, ly = self._local(hit, x, y)
                hit.send({"cmd": "scroll", "dy": ev["dy"], "x": lx, "y": ly})

    # ---------------------------------------------------------------------- painting
    def _wallpaper(self) -> Framebuffer:
        d = self.wallpaper_layer()
        if d is None or not d.ops:
            fb = Framebuffer(self.W, self.H)
            fbgfx.gradient_v(fb, 0, 0, self.W, self.H, "#0b0a2e", "#2b1450")
            return fb
        if d.wall is None:
            d.wall = Framebuffer(self.W, self.H)
            d.wall.apply(d.ops)
        return d.wall

    def _signature(self, layer: Layer, ordered: list[Layer]) -> tuple:
        below = tuple((l.id, l.rev, tuple(l.rect), l.visible) for l in ordered if l.z < layer.z)
        return (below, tuple(layer.rect), layer.id == self.focus)

    def _glass(self, fb: Framebuffer, rect: list[int], spec: dict, *, radius: int) -> None:
        """Frosted glass: shadow, blur what is behind, tint, sheen, bevel, rounded corners."""
        x, y, w, h = rect
        fbgfx.shadow(fb, x, y, w, h, spread=6 * self.u, strength=0.5, dy=2 * self.u)
        saved = fbgfx.save_region(fb, x, y, w, h)
        fbgfx.frost(fb, x, y, w, h, spec["radius"] * self.u)
        fbgfx.blend(fb, x, y, w, h, spec["tint"], spec["alpha"])
        sheen = max(1, h // 2)
        fbgfx.blend_rows(fb, x, y, w, [("#ffffff", 0.15 * (1 - i / sheen) ** 1.5) for i in range(sheen)])
        fbgfx.border(fb, x, y, w, h, "#ffffff", "#000000", 0.5)
        fbgfx.round_corners(fb, x, y, w, h, radius, saved)

    def _paint_content(self, fb: Framebuffer, layer: Layer) -> None:
        cx, cy, cw, ch = self.content_rect(layer)
        if cw <= 0 or ch <= 0:
            return
        if layer.mode == "tui":
            return self._paint_tui(fb, layer)
        x0, y0 = max(0, cx), max(0, cy)
        x1, y1 = min(self.W, cx + cw), min(self.H, cy + ch)
        if x1 <= x0 or y1 <= y0:
            return
        tmp = Framebuffer(cw, ch)                         # clip to the layer by drawing into its own surface
        stride = self.W * 4
        for r in range(y0 - cy, y1 - cy):
            src = (cy + r) * stride + x0 * 4
            tmp.buf[r * cw * 4 + (x0 - cx) * 4:r * cw * 4 + (x1 - cx) * 4] = fb.buf[src:src + (x1 - x0) * 4]
        tmp.apply(layer.ops)
        for r in range(y0 - cy, y1 - cy):
            dst = (cy + r) * stride + x0 * 4
            fb.buf[dst:dst + (x1 - x0) * 4] = tmp.buf[r * cw * 4 + (x0 - cx) * 4:r * cw * 4 + (x1 - cx) * 4]

    def _paint_tui(self, fb: Framebuffer, layer: Layer) -> None:
        scr = layer.screen
        if not scr:
            return
        cx, cy, cw, ch = self.content_rect(layer)
        s, cols, rows, pad = self.tui_metrics(layer)
        mono = ttf.load("mono")
        px, pitch = 10 * s, 6 * s                              # monospaced: columns line up whatever the font's own advance

        def put(x: int, y: int, text: str, color: str) -> None:
            if mono is None:
                return fbgfx.shaded_text(fb, x, y, text, color, s)
            c = parse_color(color)
            rgb = (c[2], c[1], c[0])
            for n, ch in enumerate(text):
                if ch != " ":
                    mono.draw(fb, x + n * pitch, y, ch, rgb, px)

        for i, line in enumerate(scr["lines"][:rows]):
            y = cy + pad + i * 12 * s
            text = line[:cols]
            if text.lstrip().startswith(">"):
                fbgfx.blend(fb, cx + 3, y - s, cw - 6, 12 * s, ACCENT, 0.80)
                put(cx + pad, y, text, "#ffffff")
            elif text.strip() and not text.startswith("  ") and i < 2:
                put(cx + pad, y, text, "#ffd27a")
            else:
                put(cx + pad, y, text, "#e3ebf6")
        status = scr.get("status", "")
        if status:
            sy = cy + ch - 12 * s - 2
            fbgfx.blend(fb, cx, sy - 2 * s, cw, 14 * s, "#000000", 0.35)
            put(cx + pad, sy, status[:cols], "#a9c4e8")

    def _paint_window(self, fb: Framebuffer, layer: Layer, focused: bool) -> None:
        x, y, w, h = layer.rect
        u, tb = self.u, self.titlebar
        fbgfx.shadow(fb, x, y, w, h, spread=(12 if focused else 7) * u, strength=0.65 if focused else 0.4, dy=4 * u)
        saved = fbgfx.save_region(fb, x, y, w, h)
        fbgfx.frost(fb, x, y, w, h, WINDOW_BODY["radius"] * u)
        fbgfx.blend(fb, x, y, w, h, WINDOW_BODY["tint"], WINDOW_BODY["alpha"])
        top, bot = TITLE_TINT
        for i in range(tb):                                        # the title bar: lighter glass, a gradient
            t = i / max(1, tb - 1)
            fbgfx.blend(fb, x, y + i, w, 1, top if t < 0.5 else bot, 0.55 - 0.25 * t if focused else 0.25)
        fbgfx.blend(fb, x, y + tb - 1, w, 1, "#000000", 0.5)
        fbgfx.blend(fb, x, y + 1, w, 1, "#ffffff", 0.35 if focused else 0.15)
        fbgfx.border(fb, x, y, w, h, "#ffffff", "#000000", 0.6 if focused else 0.3)
        fbgfx.round_corners(fb, x, y, w, h, 7 * u, saved)
        cy = y + tb // 2
        for cx, color in ((x + 12 * u, "#ff5f57" if focused else "#6b6f80"), (x + 26 * u, "#febc2e" if focused else "#6b6f80")):
            fbgfx.circle(fb, cx, cy + u, 5 * u, "#000000")
            fbgfx.circle(fb, cx, cy, 5 * u, color)
            fbgfx.blend(fb, cx - 3 * u, cy - 4 * u, 6 * u, 2 * u, "#ffffff", 0.45)
        px = 6 * u + 1
        title = layer.title
        face = ttf.load("bold")
        while face and len(title) > 3 and face.width(title, px) > w - 80 * u:
            title = title[:-2]
        if face:
            tw = int(face.width(title, px))
            ty = y + (tb - face.line_height(px)) // 2
            fb.stext(x + (w - tw) // 2 + 1, ty + 1, title, "#000000", px, 1)
            fb.stext(x + (w - tw) // 2, ty, title, "#ffffff" if focused else "#aab4d0", px, 1)
        else:
            title = title[: max(4, (w - 70 * u) // (6 * u))].upper()
            fbgfx.shaded_text(fb, x + (w - len(title) * 6 * u) // 2, y + (tb - 7 * u) // 2, title,
                              "#ffffff" if focused else "#aab4d0", u)
        self._paint_content(fb, layer)

    def compose(self) -> Framebuffer:
        fb = self._wallpaper().copy()
        ordered = sorted((l for l in self.layers.values() if l.visible and l.kind != "wallpaper"), key=lambda l: l.z)
        every = sorted(self.layers.values(), key=lambda l: l.z)
        for layer in ordered:
            if layer.kind == "window":
                self._paint_window(fb, layer, layer.id == self.focus)
                continue
            if layer.kind in ("plain", "top"):               # no glass: the app's own shapes, over what is beneath
                self._paint_content(fb, layer)
                continue
            x, y, w, h = layer.rect
            m = 8 * self.u
            region = (max(0, x - m), max(0, y - m), min(self.W, x + w + m) - max(0, x - m),
                      min(self.H, y + h + m) - max(0, y - m))
            sig = self._signature(layer, [l for l in every if l.visible])
            if layer.cache and layer.cache[0] == sig:
                fbgfx._put_rows(fb, region[0], region[1], layer.cache[1])
            else:
                self._glass(fb, layer.rect, {"bar": BAR_GLASS, "dock": DOCK_GLASS}.get(layer.kind, GLASS),
                            radius={"bar": 0, "dock": 12 * self.u}.get(layer.kind, 7 * self.u))
                layer.cache = (sig, fbgfx.save_region(fb, *region))
            self._paint_content(fb, layer)
        self.composed = fb
        return fb

    # ----------------------------------------------------------------- the main loop
    def show_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal
        self.surface_dirty = True

    def render(self) -> None:
        fb = self.compose().copy()
        if not self.modal:
            draw_cursor(fb, *self.pointer, scale=self.u)
        if getattr(self.backend, "text_overlay", False):
            self.backend.show(fb, self.modal)
        else:
            if self.modal:
                draw_modal(fb, self.modal, self.u)
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

    MIN_FRAME = 0.06                      # at most ~16 repaints a second: composing glass is not free

    def pump(self, timeout: float = 0.1) -> None:
        """Handle input and app messages without painting."""
        self.pull_input(timeout, include_app=True)
        while self.pending and not self.stop_requested:
            self.route(self.pending.popleft())
        self.tick()

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
