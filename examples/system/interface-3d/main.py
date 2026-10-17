"""The 3D interface: every layer is a block, the terminal falls as waterfalls into a lake that flows to the kernel and the hardware.
(An app: ``interface-3d``.) See ``blocks.py`` for the drawing; this is the scene: which layer becomes which block, where the camera is, and
what a click on each part means.
"""

from __future__ import annotations

import math
import os
import time
from typing import Optional

from kos import blocks
from kos.compositor import BAR_GLASS, DOCK_GLASS, GLASS, NOT_IN_BASE, POPUP_GLASS
from kos.display import Framebuffer
from kos.scenelib import Interface, Runner, SceneModel

BLOCK_HEIGHT = {"bar": 8, "dock": 14, "sidebar": 12, "widget": 10, "plain": 6, "popup": 16, "top": 6}   # in units of u; windows scale with their size
BLOCK_TINT = {"bar": "#1b2740", "dock": "#2b3555", "sidebar": "#26324d", "widget": "#2d3a5c", "plain": "#3a4660", "popup": "#3a4a6e", "window": "#2f4a86"}
FALLS = ("window", "dock", "sidebar", "popup")      # the kinds of layer an app's waterfall runs down from
BLOCK_RADIUS = {"bar": 0, "dock": 12, "popup": 12, "window": 7, "sidebar": 7, "widget": 7}
ORBIT_KEYS = ["alt-left", "alt-right", "alt-up", "alt-down", "alt-0"]


class Blocks3D(Interface):
    captures = {"keys": ORBIT_KEYS, "buttons": ["middle"], "pointer": False}   # Alt + arrows, and a middle-button drag, go around the blocks

    def __init__(self, model: SceneModel, runner):
        super().__init__(model, runner)
        self.cam = [blocks.DEFAULT_YAW, blocks.DEFAULT_PITCH]
        self.blocks: list = []
        self.cache: Optional[tuple] = None
        self.tex: dict = {}
        self.matrix_t = 0.0
        self.matrix_at = 0.0
        self.last_cost = 0.1
        self.drag: Optional[tuple] = None
        self.regions_by_id: dict = {}                           # region id -> (app, command, line)
        self.wait = 0.25

    # ---------------------------------------------------------------------------------- the camera
    def orbit(self, dyaw: float = 0.0, dpitch: float = 0.0, reset: bool = False) -> None:
        if reset:
            self.cam = [blocks.DEFAULT_YAW, blocks.DEFAULT_PITCH]
        else:
            self.cam[0] = ((self.cam[0] + dyaw + math.pi) % (2 * math.pi)) - math.pi
            self.cam[1] = max(-0.25, min(1.45, self.cam[1] + dpitch))

    def on_input(self, ev: dict) -> bool:
        t = ev.get("type")
        if t == "key":
            step = 0.12
            if ev["key"] == "alt-0":
                self.orbit(reset=True)
            else:
                self.orbit({"alt-left": -step, "alt-right": step}.get(ev["key"], 0.0), {"alt-up": step, "alt-down": -step}.get(ev["key"], 0.0))
            return True
        if t == "button" and ev.get("button") == "middle":
            self.drag = (ev.get("x", 0), ev.get("y", 0)) if ev.get("pressed") else None
            return False
        if t == "region":                                      # a click on a waterfall or the kernel: ask the OS to open the app (it asks for the password)
            what = self.regions_by_id.get(ev.get("id"))
            if what:
                self.runner.app.request_open(what[0], "graphical", what[1], what[2])
            return False
        if t == "pointer" and self.drag is not None:
            self.orbit((ev["x"] - self.drag[0]) * 0.006, (ev["y"] - self.drag[1]) * 0.006)
            self.drag = (ev["x"], ev["y"])
            return True
        return False

    def tick(self, now: float) -> bool:
        """The rain moves on at a pace the machine can afford: never more than about a third of the time spent drawing it."""
        if not self.rain_visible():
            return False
        period = max(0.25, 3.0 * self.last_cost)
        if now - self.matrix_at >= period:
            self.matrix_at = now
            self.matrix_t += period
            return True
        return False

    def rain_visible(self) -> bool:
        return self.cam[1] > 0.3 or any(b.fall_quad for b in self.blocks)

    # ---------------------------------------------------------------------------- layers into blocks
    def paint_isolated(self, fb: Framebuffer, layer) -> None:
        """One layer painted alone onto ``fb``, as it would be in the flat frame."""
        c = self.model
        if layer.kind == "window":
            return c._paint_window(fb, layer, layer.id in c.focused_ids())
        if layer.kind in ("plain", "top"):
            return c._paint_content(fb, layer)
        c._glass(fb, layer.rect, {"bar": BAR_GLASS, "dock": DOCK_GLASS, "popup": POPUP_GLASS}.get(layer.kind, GLASS),
                 radius=BLOCK_RADIUS.get(layer.kind, 7) * c.u)
        c._paint_content(fb, layer)

    def front_texture(self, layer) -> "blocks.Texture":
        """What the front of a layer's block shows. Glass layers are painted over the wallpaper (so the frost is real) and given rounded
        corners; layers with no glass (the pins, the search box) are painted over black and over white, and the difference is their
        transparency."""
        c = self.model
        x, y, w, h = layer.rect
        x0, y0 = max(0, x), max(0, y)
        x1, y1 = min(c.W, x + w), min(c.H, y + h)
        cw, ch = max(2, x1 - x0), max(2, y1 - y0)
        key = (layer.rev, tuple(layer.rect), layer.id in c.focused_ids(), c.cfg["look"], c.ws, layer.title)
        hit = self.tex.get(layer.id)
        if hit and hit[0] == key:
            return hit[1]

        def crop(src: Framebuffer) -> Framebuffer:
            out = Framebuffer(cw, ch)
            for r in range(ch):
                a = ((y0 + r) * c.W + x0) * 4
                out.buf[r * cw * 4:(r + 1) * cw * 4] = src.buf[a:a + cw * 4]
            return out

        if layer.kind in ("plain", "top"):
            black, white = Framebuffer(c.W, c.H), Framebuffer(c.W, c.H)
            white.buf[:] = b"\xff" * len(white.buf)
            self.paint_isolated(black, layer)
            self.paint_isolated(white, layer)
            bl, wh = crop(black), crop(white)
            b, wv = memoryview(bl.buf).cast("I"), memoryview(wh.buf).cast("I")
            alpha = bytearray(cw * ch)
            for i in range(cw * ch):
                p, q = b[i], wv[i]
                a = 255 - ((((q & 0xFF) - (p & 0xFF)) + (((q >> 8) & 0xFF) - ((p >> 8) & 0xFF)) + (((q >> 16) & 0xFF) - ((p >> 16) & 0xFF))) // 3)
                alpha[i] = 0 if a < 0 else 255 if a > 255 else a
                if 0 < alpha[i] < 255:                                  # un-premultiply: the colour the layer drew itself
                    k = 255 / alpha[i]
                    b[i] = (min(255, int((p & 0xFF) * k)) | min(255, int(((p >> 8) & 0xFF) * k)) << 8 | min(255, int(((p >> 16) & 0xFF) * k)) << 16)
            tex = blocks.Texture(bl, alpha)
        else:
            bg = c._wallpaper().copy()
            self.paint_isolated(bg, layer)
            fb = crop(bg)
            tex = blocks.Texture(fb, blocks.rounded_mask(cw, ch, BLOCK_RADIUS.get(layer.kind, 7) * c.u) if BLOCK_RADIUS.get(layer.kind, 7) else None)
        self.tex[layer.id] = (key, tex)
        return tex

    def layer_blocks(self) -> list:
        """One block per visible layer, stacked: each rests on the highest block beneath it that overlaps it."""
        c = self.model
        u = c.u
        ctl: dict[str, list[str]] = {}
        for k in c.controls():
            ctl.setdefault(k.layer, []).append(k.label)
        out: list = []
        for layer in sorted(c.layers.values(), key=lambda l: l.z):
            if not c.shown(layer) or layer.kind in NOT_IN_BASE or layer.minimized:
                continue
            x, y, w, h = layer.rect
            if w < 4 or h < 4:
                continue
            rank = sum(1 for b in out if b.name_kind == "window")           # windows stack by a small step, not by their whole depth
            if layer.kind == "window":
                T = max(30 * u, min(70 * u, int(0.3 * min(w, h)))) + 8 * u * rank
            else:
                T = BLOCK_HEIGHT.get(layer.kind, 8) * u
            z_back = 0.0
            for b in out:
                bx, by, bw, bh = b.rect
                if b.name_kind != "window" or layer.kind != "window":     # a block rests on the panels beneath it, not on other windows
                    if x < bx + bw and bx < x + w and y < by + bh and by < y + h:
                        z_back = max(z_back, b.z_front)
            words = [layer.title or layer.name, layer.name, *ctl.get(layer.id, [])]
            out.append(blocks.Block(layer.id, layer.name, (x, y, w, h), z_back, z_back + T, self.front_texture(layer),
                                    BLOCK_TINT.get(layer.kind, "#2a3a55"), words, ctl.get(layer.id, []), layer.title or layer.name,
                                    name_kind=layer.kind, fall=layer.kind in FALLS))
        out += self.system_blocks()
        return out

    def system_blocks(self) -> list:
        """The two things the lake flows into: the Kernel, and beyond it the Hardware. They stand on the ground, on the river; clicking one
        opens the app for it. (They show what a system call and a sysconf tell; no files are read.)"""
        c = self.model
        W, H, u = c.W, c.H, c.u
        D = int(blocks.GROUND_DEPTH * W)
        try:
            un = os.uname()
            kernel = [f"Linux {un.release}", f"{un.machine}, {os.cpu_count() or '?'} cpus", "every app below runs in a sandbox", "click: isolation"]
            mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1 << 20)
            hardware = [f"{os.cpu_count() or '?'} cpus, {mem} MiB RAM", "devices need your password", "click: devices"]
        except (OSError, ValueError, AttributeError):
            kernel, hardware = ["Linux"], ["the machine"]
        out = []
        for name, title, lines, app, wf, hf, z, depth in (("kernel", "KERNEL", kernel, "isolation", 0.34, 0.22, 0.16, 0.07),
                                                          ("hardware", "HARDWARE", hardware, "devices", 0.24, 0.14, 0.36, 0.05)):
            w, h = int(W * wf), int(H * hf)
            x, y = (W - w) // 2, H - h
            tex = blocks.info_texture(w, h, title, lines, "#06231a", u)
            out.append(blocks.Block(f"{name}-system", name, (x, y, w, h), z * D, z * D + depth * W, tex, "#0b3a28", [title, *lines], [], title,
                                    name_kind="system", opens=app))
        return out

    # ------------------------------------------------------------------------------------ the frame
    def render(self):
        c = self.model
        W, H, u = c.W, c.H, c.u
        mt = round(self.matrix_t, 2) if self.rain_visible() else 0.0
        look = max(0.0, min(1.0, (self.cam[1] - 0.3) / 0.9))          # looking down: the pivot slides toward the lake, so the lake stays in view
        cam = blocks.Camera(self.cam[0], self.cam[1], W / 2, H / 2, 40 * u + look * 0.22 * W, 3.4 * W, py=H / 2 + look * 0.42 * H)
        bl = self.layer_blocks()
        out = Framebuffer(W, H)

        def shadows(frame: Framebuffer, camera) -> None:
            for b in bl:                                              # a soft shadow on the wallpaper under each block's footprint
                x, y, w, h = b.rect
                foot = [camera.project(px, py, 0.0)[:2] for px, py in ((x, y), (x + w, y), (x + w, y + h), (x, y + h))]
                cx = sum(p[0] for p in foot) / 4 + 5 * u
                cy = sum(p[1] for p in foot) / 4 + 7 * u
                for grow, alpha in ((10, 26), (7, 30), (4, 34), (1, 38)):
                    k = grow * u
                    frame.poly([(cx + (p[0] - cx + 5 * u) + (k if p[0] > cx else -k), cy + (p[1] - cy + 7 * u) + (k if p[1] > cy else -k))
                                for p in foot], "#000000", alpha)

        words = [w for b in bl for w in b.words][:200]                 # the ground rains the words of everything on the desktop
        t0 = time.monotonic()
        blocks.render(out, blocks.Texture(c._wallpaper()), bl, cam, mt, u, shadow=shadows, floor_words=words)
        self.last_cost = time.monotonic() - t0
        self.blocks = bl
        for layer in sorted((l for l in c.layers.values() if c.shown(l) and l.kind == "overlay"), key=lambda l: l.z):
            c._paint_content(out, layer)                              # the click bubbles float in front of everything
        # where each thing landed, for the OS to map clicks back: layers' faces nearest first; the waterfalls and the kernel and hardware
        # are regions that open an app
        hits = [{"id": b.layer_id, "quad": b.quad} for b in sorted(bl, key=lambda b: -b.depth) if b.quad and b.name_kind != "system"]
        self.regions_by_id = {}
        regions = []
        for b in bl:
            if b.opens and b.quad:
                self.regions_by_id[b.layer_id] = (b.opens, "", "")
                regions.append({"quad": b.quad, "id": b.layer_id})
            if b.fall_quad:
                self.regions_by_id[b.layer_id + ":fall"] = ("commands", "list", b.name[:40])
                regions.append({"quad": b.fall_quad, "id": b.layer_id + ":fall"})
        return out, hits, regions


def main() -> None:
    Runner(Blocks3D).run()
