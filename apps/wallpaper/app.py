"""The desktop background. It owns the ``wallpaper`` shared folder and stores one value in it: ``color``.
It does not draw the desktop and never talks to the taskbar. The taskbar reads the same folder, but only
after the owner grants it: ``kos grant taskbar space:wallpaper --level read``.

Keys: left/right (or 1-8) choose, enter saves. Click a swatch to choose, click it again to save."""

from kos.sdk import App, Canvas

SPACE, KEY = "wallpaper", "color"
SWATCHES = [("Night", "#101820"), ("Navy", "#1f3a5f"), ("Forest", "#16361f"), ("Plum", "#3a1f4a"),
            ("Brick", "#4a1f1f"), ("Slate", "#2b2f36"), ("Teal", "#124a4a"), ("Sand", "#6b5b3a")]
SW, SH, GAP, TOP = 44, 44, 6, 40


def swatch_at(x, y, width):
    """Index of the swatch under (x, y) in the graphical layout, or None."""
    per = max(1, (width - GAP) // (SW + GAP))
    if y < TOP:
        return None
    col, row = (x - GAP) // (SW + GAP), (y - TOP) // (SH + GAP)
    if not 0 <= col < per or (x - GAP) % (SW + GAP) >= SW or (y - TOP) % (SH + GAP) >= SH:
        return None
    n = row * per + col
    return n if 0 <= n < len(SWATCHES) else None


def tui_lines(state):
    lines = ["", "  Desktop background", ""]
    for n, (name, color) in enumerate(SWATCHES):
        lines.append(f"  {'>' if n == state['sel'] else ' '} {n + 1}  {name:<8} {color}"
                     + ("   (saved)" if color == state["saved"] else ""))
    lines += ["", "  left/right or 1-8 choose   enter save"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    c = Canvas().clear("#101820").rect(0, 0, app.width, 18, "#1f3a5f").text(6, 5, "WALLPAPER", "#ffffff")
    per = max(1, (app.width - GAP) // (SW + GAP))
    for n, (name, color) in enumerate(SWATCHES):
        x, y = GAP + (n % per) * (SW + GAP), TOP + (n // per) * (SH + GAP)
        if n == state["sel"]:
            c.rect(x - 2, y - 2, SW + 4, SH + 4, "#ffffff")
        c.rect(x, y, SW, SH, color)
    c.text(6, 24, SWATCHES[state["sel"]][0].upper(), "#ffcc00")
    c.text(6, app.height - 12, "ENTER SAVE" + ("  " + state["note"].upper()[:40] if state["note"] else ""), "#6080a0")
    app.present(c)


def save(app, state):
    color = SWATCHES[state["sel"]][1]
    if app.vault_put(KEY, color, space=SPACE):
        state["saved"], state["note"] = color, "saved"
    else:
        state["note"] = "not saved: " + (app.vault_error or "refused")


def main():
    app = App()
    state = {"sel": 0, "saved": "", "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            state["saved"] = app.vault_get(KEY, space=SPACE) or ""
            names = [c for _, c in SWATCHES]
            state["sel"] = names.index(state["saved"]) if state["saved"] in names else 0
        elif cmd == "key":
            k = ev["key"]
            if k in ("left", "up"):
                state["sel"] = (state["sel"] - 1) % len(SWATCHES)
            elif k in ("right", "down"):
                state["sel"] = (state["sel"] + 1) % len(SWATCHES)
            elif k.isdigit() and 1 <= int(k) <= len(SWATCHES):
                state["sel"] = int(k) - 1
            elif k == "enter":
                save(app, state)
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left" and app.mode == "graphical":
            n = swatch_at(ev["x"], ev["y"], app.width)
            if n is not None:
                again = n == state["sel"]
                state["sel"] = n
                if again:
                    save(app, state)
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, state)
        else:
            app.screen("Wallpaper", tui_lines(state), status="enter: save")
