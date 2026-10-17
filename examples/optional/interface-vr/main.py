"""Virtual reality and augmented reality interfaces: the desktop once per eye, side by side. (Apps: ``interface-vr``, ``interface-ar``.)

Every layer sits at a depth (the wallpaper far away, windows and the sidebar nearer, effects and the pointer nearest): each eye sees it shifted
by that depth's disparity, and moving the pointer turns your head, which slides the far layers more than the near ones - so panels float in
front of the picture. Each eye is squeezed to half width (the usual half side-by-side format; a headset runtime widens it again and adds the
lens correction). Augmented reality is the same, but the wallpaper is a camera passthrough when a camera driver app fills the wallpaper slot
(it sends the frames as ``blit`` ops). Pure Python: the two eyes are composed once and cached until something changes.

A headset's own sensors (head tracking) would come in through an ``xr`` driver app; none was available to test, so the head is turned by the
pointer. The pointer is drawn here, once per eye, because it is the nearest thing in the picture.
"""

from __future__ import annotations

from kos import ttf
from kos.display import Framebuffer, draw_cursor, parse_color
from kos.scenelib import Interface, Runner, SceneModel

DEPTH = {"wallpaper": 0, "plain": 1, "top": 1, "widget": 1, "bar": 2, "dock": 2, "sidebar": 3, "popup": 3, "window": 3, "overlay": 4}
POINTER_DEPTH = 5


def hsqueeze(fb: Framebuffer) -> Framebuffer:
    """Half the width, full height (every other column): the "half side-by-side" format a headset un-squeezes."""
    W, H = fb.width, fb.height
    mv = memoryview(fb.buf).cast("I")
    out = Framebuffer(W // 2, H)
    ow = out.width
    dst = memoryview(out.buf).cast("I")
    for y in range(H):
        dst[y * ow:(y + 1) * ow] = mv[y * W:y * W + 2 * ow:2]
    return out


def has_passthrough(model: SceneModel) -> bool:
    """Is the wallpaper layer showing camera pixels (a ``blit``)? That is what augmented reality calls passthrough."""
    wall = model.wallpaper_layer()
    return bool(wall and any(op[0] == "blit" for op in wall.ops))


class Stereo(Interface):
    pointer = True
    captures = {"keys": [], "buttons": [], "pointer": True}            # pointer moves turn the head

    def __init__(self, model: SceneModel, runner: Runner, augmented: bool):
        super().__init__(model, runner)
        self.augmented = augmented
        self.at = (0, 0)
        self.cached: tuple = ()
        self.wait = 1.0

    def on_input(self, ev: dict) -> bool:
        if ev.get("type") == "pointer":
            self.at = (int(ev["x"]), int(ev["y"]))
            return True
        return False

    def yaw(self) -> int:
        W, u = self.model.W, self.model.u
        return int(round((self.at[0] - W / 2) / max(1, W / 2) * 4)) * 2 * u         # head turn: -8u .. 8u in steps of 2u

    def eyes(self) -> list:
        m = self.model
        key = (m._base_signature(), self.yaw(), self.augmented)
        if self.cached and self.cached[0] == key:
            return self.cached[1]
        u, yaw = m.u, self.yaw()
        saved = {l.id: l.rect[0] for l in m.layers.values()}
        eyes = []
        try:
            for eye in (-1, 1):
                for l in m.layers.values():
                    d = DEPTH.get(l.kind, 3)
                    l.rect[0] = saved[l.id] + eye * d * u + int(yaw * (5 - d) / 5)
                m._base = m._base_sig = None
                eyes.append(m.compose().copy())
        finally:
            for l in m.layers.values():
                l.rect[0] = saved[l.id]
            m._base = m._base_sig = None
            for l in m.layers.values():
                l.cache = None
        self.cached = (key, eyes)
        return eyes

    def render(self):
        m = self.model
        W, H, u = m.W, m.H, m.u
        out = Framebuffer(W, H)
        half_w = W // 2
        px_, py_ = self.at if self.at != (0, 0) else (W // 2, H // 2)
        for i, full in enumerate(self.eyes()):
            full = full.copy()
            draw_cursor(full, px_ + (1 if i else -1) * POINTER_DEPTH * u, py_, scale=u)          # the nearest thing: drawn each frame, never cached
            eye = hsqueeze(full)
            for y in range(H):
                out.buf[(y * W + i * half_w) * 4:(y * W + i * half_w + eye.width) * 4] = eye.buf[y * eye.width * 4:(y + 1) * eye.width * 4]
        out.rect(half_w - u, 0, 2 * u, H, parse_color("#000000"))
        face = ttf.load("bold")
        label = "AUGMENTED REALITY" if self.augmented else "VIRTUAL REALITY"
        sub = ("passthrough: the camera shows behind the interface" if has_passthrough(m)
               else "no camera driver: the interface floats over the plain wallpaper") if self.augmented else \
            "side by side, one picture per eye - move the pointer to look around"
        if face:
            px = 6 * u + 2
            for i in (0, 1):
                cx = i * half_w + half_w // 2
                tw = int(face.width(label, px))
                out.stext(cx - tw // 2 + 1, 3 * u + 1, label, "#000000", px, 1)
                out.stext(cx - tw // 2, 3 * u, label, "#4cb0ff", px, 1)
                sans = ttf.load("sans")
                if sans:
                    sw = int(sans.width(sub, px - 2))
                    out.stext(cx - sw // 2 + 1, H - 84 * u + 1, sub, "#000000", px - 2, 0)
                    out.stext(cx - sw // 2, H - 84 * u, sub, "#ffffff", px - 2, 0)
        # where each layer landed (each eye's picture is half width, shifted by its depth): clicks in either half map back to the flat layer
        hits = []
        yaw = self.yaw()
        for l in sorted(m.layers.values(), key=lambda l: -l.z):
            if not m.shown(l) or l.kind in ("wallpaper", "overlay", "cursor") or l.minimized:
                continue
            d = DEPTH.get(l.kind, 3)
            x, y, w, h = l.rect
            for i, eye in enumerate((-1, 1)):
                sx = (x + eye * d * u + int(yaw * (5 - d) / 5))
                x0, x1 = sx / 2 + i * half_w, (sx + w) / 2 + i * half_w
                hits.append({"id": l.id, "quad": [[x0, y], [x1, y], [x1, y + h], [x0, y + h]]})
        return out, hits[:96], []


def main() -> None:
    Runner(lambda model, runner: Stereo(model, runner, False)).run()
