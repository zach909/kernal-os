"""Compositing: how a set of layers becomes one picture.

This is a library, not a service. The OS's own compositor (``Shell``) inherits it to draw the flat desktop when no interface app is
running, and the interface apps (``interface-normal``, ``interface-3d``, ...) use the very same class inside their own sandbox to draw the
layers the OS hands them - so there is one drawing of the desktop, and it runs wherever the interface runs.

A *layer* here is anything with the fields of :class:`Surface`: an app's draw ops, where it is, how deep, its glass cache. The class needs
its host to provide ``layers`` (id -> layer), ``W``, ``H``, ``u`` (UI scale), ``cfg`` (only ``cfg["look"]`` is read), ``ws`` (the desktop being
shown), ``seats`` (objects with a ``focus``) and the two cache slots ``_base`` and ``_base_sig``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import fbgfx, ttf
from .display import Framebuffer, parse_color

ACCENT = "#0078d4"                  # KOS Blue: active states, selection, focus
GLASS = {"tint": "#dfe8f5", "alpha": 0.16, "radius": 4}
BAR_GLASS = {"tint": "#0d1016", "alpha": 0.42, "radius": 5}
DOCK_GLASS = {"tint": "#e9eff8", "alpha": 0.20, "radius": 5}
POPUP_GLASS = {"tint": "#141820", "alpha": 0.80, "radius": 5}
WINDOW_BODY = {"tint": "#12151b", "alpha": 0.84, "radius": 4}
TITLE_TINT = ("#4a505c", "#20242c")
Z = {"wallpaper": 0, "plain": 4, "sidebar": 9, "widget": 10, "window": 20, "bar": 90, "dock": 91, "top": 92, "overlay": 95, "popup": 96, "cursor": 99}
NOT_IN_BASE = ("wallpaper", "overlay", "cursor")        # painted separately: the base frame is cached without them
NO_HIT = ("cursor", "overlay")                          # layers the pointer passes through


@dataclass
class Surface:
    """What a layer is to a drawing: an app's ops and where they go. (The OS's own ``Layer`` has these fields and more.)"""
    id: str
    name: str
    kind: str                      # wallpaper | bar | dock | widget | plain | popup | sidebar | window ...
    mode: str                      # graphical | tui
    rect: list                     # x, y, w, h  (windows: including the frame)
    z: int = 0
    ops: list = field(default_factory=list)
    screen: Optional[dict] = None
    wall: Optional[Framebuffer] = None
    title: str = ""
    visible: bool = True
    minimized: bool = False
    ws: Optional[int] = None
    rev: int = 0
    cache: Optional[tuple] = None


@dataclass
class SeatFocus:
    focus: Optional[str] = None


class Compositor:
    def shown(self, layer: Layer) -> bool:
        """Is this layer on screen: visible, and on the workspace being shown (interface apps are on all)."""
        return layer.visible and (layer.ws is None or layer.ws == self.ws)

    def focused_ids(self) -> set[str]:
        return {s.focus for s in self.seats.values() if s.focus}

    @property
    def titlebar(self) -> int:
        return 9 * self.u + 10

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

    def wallpaper_layer(self) -> Optional[Layer]:
        return next((l for l in self.layers.values() if l.kind == "wallpaper"), None)

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
        """What this layer's glass depends on: the layers *behind it that reach its rectangle* (its blur and shadow only
        see pixels near itself), its own rectangle and its focus. A layer somewhere else redrawing - the clock, the search
        box - therefore does not make every glass panel re-blur (that was 90% of the cost of a repaint)."""
        u = self.u
        m = (16 if self.cfg["look"] == "3d" else 9) * u        # this layer's own blur/shadow touches this far around it (the 3d look casts deeper)
        x, y, w, h = layer.rect
        zone = (x - m, y - m, x + w + m, y + h + m)
        reach = {"window": 28 * u, "plain": 0, "top": 0, "overlay": 0, "cursor": 0, "wallpaper": 0}

        def near(l: Layer) -> bool:                            # does l (and the shadow it casts) reach this layer's zone?
            r = reach.get(l.kind, 16 * u)
            lx, ly, lw, lh = l.rect
            return lx - r < zone[2] and lx + lw + r > zone[0] and ly - r < zone[3] and ly + lh + r > zone[1]
        below = tuple((l.id, l.rev, tuple(l.rect), self.shown(l)) for l in ordered if l.z < layer.z and near(l))
        return (below, tuple(layer.rect), layer.id in self.focused_ids())

    def _glass(self, fb: Framebuffer, rect: list[int], spec: dict, *, radius: int) -> None:
        """Frosted glass: shadow, blur what is behind, tint, sheen, bevel, rounded corners."""
        x, y, w, h = rect
        deep = self.cfg["look"] == "3d"                      # 3d look: deeper shadow, brighter sheen
        fbgfx.shadow(fb, x, y, w, h, spread=(10 if deep else 6) * self.u, strength=0.62 if deep else 0.5, dy=(5 if deep else 2) * self.u)
        saved = fbgfx.save_region(fb, x, y, w, h)
        fbgfx.frost(fb, x, y, w, h, spec["radius"] * self.u)
        fbgfx.blend(fb, x, y, w, h, spec["tint"], spec["alpha"])
        sheen = max(1, h // 2)
        fbgfx.blend_rows(fb, x, y, w, [("#ffffff", (0.26 if deep else 0.15) * (1 - i / sheen) ** 1.5) for i in range(sheen)])
        fbgfx.border(fb, x, y, w, h, "#ffffff", "#000000", 0.75 if deep else 0.5)
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
        tmp.apply(layer.ops, extrude=self.cfg["look"] == "3d")
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
        deep = self.cfg["look"] == "3d"
        fbgfx.shadow(fb, x, y, w, h, spread=(18 if deep else 12 if focused else 7) * u, strength=(0.8 if deep else 0.65) if focused else 0.4,
                     dy=(8 if deep else 4) * u)
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

    def _base_signature(self) -> tuple:
        return (self.ws, tuple((l.id, l.rev, tuple(l.rect), self.shown(l), l.z) for l in self.layers.values()
                      if l.kind not in NOT_IN_BASE or l.kind == "wallpaper"),
                tuple(sorted(self.focused_ids())), tuple(sorted(s.focus or "" for s in self.seats.values())), self.cfg["look"])

    def compose(self) -> Framebuffer:
        """The scene: the cached base frame (everything but the click effects and the pointer) with the
        effects painted over a copy. The base is rebuilt only when something under it changed."""
        sig = self._base_signature()
        if self._base is None or sig != self._base_sig:
            self._base, self._base_sig = self._compose_base(), sig
        fb = self._base.copy()
        for layer in sorted((l for l in self.layers.values() if self.shown(l) and l.kind == "overlay"), key=lambda l: l.z):
            self._paint_content(fb, layer)
        self.composed = fb
        return fb

    def _compose_base(self) -> Framebuffer:
        fb = self._wallpaper().copy()
        ordered = sorted((l for l in self.layers.values() if self.shown(l) and l.kind not in NOT_IN_BASE), key=lambda l: l.z)
        every = sorted(self.layers.values(), key=lambda l: l.z)
        for layer in ordered:
            if layer.kind == "window":
                self._paint_window(fb, layer, layer.id in self.focused_ids())
                continue
            if layer.kind in ("plain", "top"):               # no glass: the app's own shapes, over what is beneath
                self._paint_content(fb, layer)
                continue
            x, y, w, h = layer.rect
            m = 8 * self.u
            region = (max(0, x - m), max(0, y - m), min(self.W, x + w + m) - max(0, x - m),
                      min(self.H, y + h + m) - max(0, y - m))
            sig = self._signature(layer, [l for l in every if self.shown(l)])
            if layer.cache and layer.cache[0] == sig:
                fbgfx._put_rows(fb, region[0], region[1], layer.cache[1])
            else:
                self._glass(fb, layer.rect, {"bar": BAR_GLASS, "dock": DOCK_GLASS, "popup": POPUP_GLASS}.get(layer.kind, GLASS),
                            radius={"bar": 0, "dock": 12 * self.u, "popup": 12 * self.u}.get(layer.kind, 7 * self.u))
                layer.cache = (sig, fbgfx.save_region(fb, *region))
            self._paint_content(fb, layer)
        return fb

    # ----------------------------------------------------------------- the main loop
