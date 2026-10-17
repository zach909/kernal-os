"""The neural interface: the desktop with a highlight that scans the buttons. (App: ``interface-neural``.)

A surface neural device (an EEG band, an EMG wristband) is a *driver app* (``"driver": "neural"``, the ``neural`` permission) that turns the
wearer's signals into at most five decisions - ``next``, ``prev``, ``select``, ``back``, ``pause`` - and sends only those. The OS passes them
here. The highlight moves to the next control every 1.4 seconds by itself, so one signal is enough to use everything; ``select`` presses the
highlighted control (by asking the OS to click its position, exactly as a mouse click would), ``back`` presses the top window's Close.

The raw signal never leaves the driver: this app, and the OS, only ever see the five words.
"""

from __future__ import annotations

import time

from kos import fbgfx, ttf
from kos.compositor import ACCENT
from kos.display import Framebuffer, parse_color
from kos.scenelib import Interface, Runner, SceneModel

DWELL = 1.4


def hud(model: SceneModel, fb: Framebuffer, controls: list, nav: int, progress: float, state: dict) -> None:
    """The card: what is selected, how long until the scan moves on, what each decision does, and whether a driver has spoken."""
    W, H, u = model.W, model.H, model.u
    cw, ch = min(W - 40 * u, 220 * u), 46 * u
    x, y = (W - cw) // 2, H - ch - 80 * u                  # above the dock, so the highlight on it stays visible
    fbgfx.shadow(fb, x, y, cw, ch, spread=8 * u, strength=0.55, dy=4 * u)
    fbgfx.blend(fb, x, y, cw, ch, "#0b0f16", 0.86)
    fbgfx.border(fb, x, y, cw, ch, "#ffffff", "#000000", 0.4)
    bold, sans = ttf.load("bold"), ttf.load("sans")
    if not (bold and sans):
        return
    px = 6 * u + 2
    fb.rect(x + 8 * u, y + 7 * u, 36 * u, 11 * u, parse_color(ACCENT))
    fb.stext(x + 12 * u, y + 8 * u, "NEURAL", "#ffffff", px - 1, 1)
    status = ("paused" if state["paused"] else "scanning") + ("" if state["driver"] else " - no neural driver has spoken yet")
    fb.stext(x + 50 * u, y + 9 * u, status, "#9fb2c8", px - 1, 0)
    label = controls[nav].label if 0 <= nav < len(controls) else "nothing to select"
    fb.stext(x + 8 * u, y + 21 * u, label[:40], "#ffffff", 9 * u, 1)
    bw = cw - 16 * u
    fb.rect(x + 8 * u, y + ch - 12 * u, bw, 3 * u, parse_color("#2a303b"))
    if not state["paused"]:
        fb.rect(x + 8 * u, y + ch - 12 * u, max(1, int(bw * min(1.0, progress))), 3 * u, parse_color(ACCENT))
    legend = "next / prev move - select presses - back closes - pause stops the scan" + (f"      last: {state['last']}" if state["last"] else "")
    fb.stext(x + 8 * u, y + ch - 9 * u + 1, legend[:90], "#7f8da3", px - 3, 0)


class Neural(Interface):
    def __init__(self, model: SceneModel, runner: Runner):
        super().__init__(model, runner)
        self.nav = 0
        self.paused = False
        self.last = ""
        self.last_step = time.monotonic()
        self.last_intent = 0.0
        self.seen_driver = False
        self._bucket = -1
        self.wait = 0.1

    def controls(self) -> list:
        return self.model.controls()

    def tick(self, now: float) -> bool:
        if self.paused:
            return False
        ctl = self.controls()
        if ctl and now - self.last_step >= DWELL:
            self.nav = (self.nav + 1) % len(ctl)
            self.last_step = now
            return True
        bucket = int((now - self.last_step) * 10)                 # the progress bar fills smoothly: repaint when it moves a tenth
        if bucket != self._bucket:
            self._bucket = bucket
            return True
        return False

    def on_intent(self, name: str) -> bool:
        now = time.monotonic()
        if now - self.last_intent < 0.08:                       # at most ~12 decisions a second
            return False
        self.last_intent, self.last, self.seen_driver = now, name, True
        ctl = self.controls()
        if name == "pause":
            self.paused = not self.paused
        elif ctl:
            if name == "next":
                self.nav = (self.nav + 1) % len(ctl)
            elif name == "prev":
                self.nav = (self.nav - 1) % len(ctl)
            elif name == "select" and 0 <= self.nav < len(ctl):
                cx, cy = ctl[self.nav].center
                self.runner.press(cx, cy)                        # exactly what a mouse click there would do
            elif name == "back":
                close = next((c for c in ctl if c.kind == "close"), None)
                if close is not None:
                    self.runner.press(*close.center)
        self.last_step = now
        return True

    def render(self):
        m = self.model
        fb = m.compose().copy()
        ctl = self.controls()
        if ctl:
            self.nav = max(0, min(len(ctl) - 1, self.nav))
            x, y, w, h = ctl[self.nav].rect
            t = 2 * m.u                                          # a thick ring: the one the scan is on
            col = parse_color(ACCENT)
            for dx, dy, rw, rh in ((x - t, y - t, w + 2 * t, t), (x - t, y + h, w + 2 * t, t), (x - t, y, t, h), (x + w, y, t, h)):
                fb.rect(dx, dy, rw, rh, col)
        progress = min(1.0, (time.monotonic() - self.last_step) / DWELL)
        hud(m, fb, ctl, self.nav, progress, {"paused": self.paused, "last": self.last, "driver": self.seen_driver})
        return fb, [], []


def main() -> None:
    Runner(Neural).run()
