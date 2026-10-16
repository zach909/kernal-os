"""neurosim: a neural-interface *emulator* that speaks the KOS neural driver protocol.

A real surface-neural driver (an EEG headband, an EMG wristband) would open its device, filter the raw signal, and classify it
into a few decisions. This emulator draws a scripted signal and lets you "produce" the decisions by clicking its buttons, so
the whole path - a driver app, the 'neural' permission, the neural look scanning and acting on intents - can be exercised
without hardware. It says "emulator" on screen.

What the protocol guarantees (and a real driver inherits): the interface only ever receives one of next / prev / select / back /
pause. The raw signal, the features, the model - all stay inside this app's sandbox, which has no network and no files. A
neural device's data is some of the most private there is, so the OS never asks for it and nothing here can send it anywhere.
"""

import math

from kos.sdk import App, Canvas

INTENTS = ("next", "prev", "select", "back", "pause")


def main():
    app = App()
    t, last, zones = 0.0, "", []
    for ev in app.events():
        cmd = ev.get("cmd")
        if cmd == "tick":
            t += 1.0
        elif cmd == "button" and ev.get("pressed"):
            for name, (x, y, w, h) in zones:
                if x <= ev["x"] < x + w and y <= ev["y"] < y + h:
                    app.request_intent(name)
                    last = name
        elif cmd not in ("hello", "look", "focus", "result"):
            continue
        u, w, h = app.scale, app.width, app.height
        c = Canvas().clear("#0b0f16")
        c.stext(8 * u, 6 * u, "Neural interface", "#ffffff", 9 * u, 1)
        c.stext(8 * u, 20 * u, "EMULATOR - a scripted signal, not a person", "#f0b44a", 6 * u, 0)
        mid, amp = 46 * u, 10 * u
        prev = None
        for x in range(8 * u, w - 8 * u, 2 * u):
            y = mid + int(amp * (math.sin((x + t * 14) / (6 * u)) * 0.6 + math.sin((x + t * 5) / (2.3 * u)) * 0.3))
            if prev:
                c.line(prev[0], prev[1], x, y, "#3fb27f")
            prev = (x, y)
        zones = []
        bw, bh, y0 = (w - 16 * u - 4 * 6 * u) // 5, 14 * u, h - 24 * u
        for i, name in enumerate(INTENTS):
            x = 8 * u + i * (bw + 6 * u)
            c.rect(x, y0, bw, bh, "#0078d4" if name == last else "#262b34")
            c.stext(x + 4 * u, y0 + 3 * u, name, "#ffffff", 6 * u, 0)
            c.hit(x, y0, bw, bh, f"produce the {name} decision")
            zones.append((name, (x, y0, bw, bh)))
        c.stext(8 * u, h - 8 * u, "Only these five decisions ever leave this app.", "#7f8da3", 6 * u, 0)
        app.present(c)
