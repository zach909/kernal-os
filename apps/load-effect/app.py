"""Load effect settings. It owns the ``load-effect`` shared folder and stores one value in it, ``effect``:
five whole numbers ``"ON 3D LX LY MS"``. It draws nothing of the effect itself. An app that wants to follow
it declares ``uses:load-effect`` and the owner grants it: ``kos grant APP space:load-effect --level read``.

Keys: e arrival on/off, d 3D on/off, s turn the sun, + faster, - slower. Every change is saved at once."""

from kos.sdk import App, Canvas

SPACE, KEY = "load-effect", "effect"
# The sun's direction, as (x right, y down) towards the light: eight points of the compass.
SUN = [("top left", (-1, -1)), ("top", (0, -1)), ("top right", (1, -1)), ("right", (1, 0)),
       ("bottom right", (1, 1)), ("bottom", (0, 1)), ("bottom left", (-1, 1)), ("left", (-1, 0))]
MS_MIN, MS_MAX, MS_STEP = 10, 500, 10


def encode(st):
    return f"{int(st['on'])} {int(st['d3'])} {SUN[st['sun']][1][0]} {SUN[st['sun']][1][1]} {st['ms']}"


def decode(raw):
    st = {"on": False, "d3": False, "sun": 0, "ms": 40}
    parts = (raw or "").split()
    if len(parts) == 5 and all(p.lstrip("-").isdigit() for p in parts):
        on, d3, lx, ly, ms = (int(p) for p in parts)
        for i, (_, (sx, sy)) in enumerate(SUN):
            if (sx, sy) == (lx, ly):
                st.update(on=on == 1, d3=d3 == 1, sun=i, ms=min(MS_MAX, max(MS_MIN, ms)))
    return st


def rows(st):
    return [("e", "Arrival effect", "ON" if st["on"] else "off",
             "point, out to full size, in to the outline, unblur"),
            ("d", "3D layers", "ON" if st["d3"] else "off",
             "each layer arrives at its own distance, mouse = vanishing point"),
            ("s", "Sun", SUN[st["sun"]][0], "where the light comes from"),
            ("+/-", "Frame pause", f"{st['ms']} ms", "smaller is faster")]


def tui_lines(st):
    lines = ["", "  How pictures load", ""]
    for key, name, value, note in rows(st):
        lines.append(f"  {key:<4} {name:<16} {value:<14} {note}")
    lines += ["", "  Apps follow this only after: kos grant APP space:load-effect --level read"]
    if st["note"]:
        lines += ["", "  " + st["note"]]
    return lines


def draw_graphical(app, st):
    c = Canvas().clear("#101820").rect(0, 0, app.width, 18, "#1f3a5f").text(6, 5, "LOAD EFFECT", "#ffffff")
    y = 28
    for key, name, value, _ in rows(st):
        c.text(8, y, f"{key}  {name}  {value}".upper()[:60], "#a0ffa0")
        y += 14
    c.text(6, app.height - 12, ("E D S + -   " + st["note"]).upper()[:70], "#6080a0")
    app.present(c)


def save(app, st):
    st["note"] = "saved" if app.vault_put(KEY, encode(st), space=SPACE) else "not saved: " + (app.vault_error or "refused")


def main():
    app = App()
    st = {"on": False, "d3": False, "sun": 0, "ms": 40, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            st.update(decode(app.vault_get(KEY, space=SPACE)))
        elif cmd == "key":
            k = ev["key"]
            if k == "e":
                st["on"] = not st["on"]
            elif k == "d":
                st["d3"] = not st["d3"]
            elif k == "s":
                st["sun"] = (st["sun"] + 1) % len(SUN)
            elif k in ("+", "="):
                st["ms"] = max(MS_MIN, st["ms"] - MS_STEP)
            elif k in ("-", "_"):
                st["ms"] = min(MS_MAX, st["ms"] + MS_STEP)
            else:
                continue
            save(app, st)
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, st)
        else:
            app.screen("Load effect", tui_lines(st), status="e d s + -")
