"""The desktop: the wallpaper, an icon for every installed app, and a bar along the bottom (Start, then
what is open). It draws one screen and asks the OS for everything else (``request apps``, ``open``,
``focus``); it never opens a device and never reaches the search popup itself: the Windows key is the
OS's, and Start asks the OS to switch to it like any other running app.

Keys: arrows choose an icon, enter opens it, s Start (search), l App Library, r refresh.
Click an icon to choose it, click it again to open it. Click Start or a chip on the bar to switch."""

from kos.sdk import App, Canvas

SYSTEM = ("desktop", "taskbar", "app-library", "search")
LIBRARY, SEARCH, HOME = "app-library", "search", "desktop"
CELL_W, CELL_H, MARGIN, ICON = 72, 64, 8, 32
BAR_H, START_W, CHIP_W, CHIP_H = 28, 60, 90, 22
BACKGROUND, BAR, ACCENT = "#101820", "#1f3a5f", "#2f6db5"
PALETTE = ["#c04040", "#40a060", "#4070c0", "#c09030", "#8050b0", "#30a0a0", "#b05080", "#708030"]


def valid_color(text):
    """A colour the wallpaper app stored, only if it is exactly #rrggbb: another app's data is never trusted."""
    ok = isinstance(text, str) and len(text) == 7 and text[0] == "#"
    return text.lower() if ok and all(ch in "0123456789abcdefABCDEF" for ch in text[1:]) else None


def icon_color(name):
    return PALETTE[sum(ord(ch) for ch in name) % len(PALETTE)]


def icons(installed):
    """What sits on the desktop: the App Library first, then every installed app that is not part of the desktop."""
    rest = sorted((a for a in installed if a["name"] not in SYSTEM), key=lambda a: a["name"])
    return [{"name": LIBRARY, "label": "LIBRARY", "modes": ["tui", "graphical"]}] + rest


def running(open_list):
    return [i for i in open_list if i["name"] not in SYSTEM and i["status"] == "running"]


def find(open_list, name):
    return next((i for i in open_list if i["name"] == name and i["status"] == "running"), None)


def columns(width):
    return max(1, (width - MARGIN) // CELL_W)


def cell_xy(n, width):
    per = columns(width)
    return MARGIN + (n % per) * CELL_W, MARGIN + (n // per) * CELL_H


def icon_at(x, y, width, count):
    """Index of the icon under (x, y), or None."""
    col, row = (x - MARGIN) // CELL_W, (y - MARGIN) // CELL_H
    if x < MARGIN or y < MARGIN or col >= columns(width):
        return None
    n = row * columns(width) + col
    return n if 0 <= n < count else None


def chips(width, open_list):
    """(x, y, w, h, label, id) for every running app on the bar, to the right of Start."""
    out, x = [], 4 + START_W + 8
    for inst in running(open_list):
        if x + CHIP_W > width:
            break
        out.append((x, 0, CHIP_W, CHIP_H, inst["name"][:12].upper(), inst["id"]))
        x += CHIP_W + 4
    return out


def label_of(entry):
    return entry.get("label") or entry["name"].upper()


def mode_for(entry, graphical):
    modes = entry.get("modes", ["tui"])
    return "graphical" if graphical and "graphical" in modes else ("tui" if "tui" in modes else modes[0])


def draw_graphical(app, st):
    w, h = app.width, app.height
    c = Canvas().clear(st["background"])
    items = icons(st["installed"])
    for n, entry in enumerate(items):
        x, y = cell_xy(n, w)
        if y + CELL_H > h - BAR_H:
            break
        if n == st["sel"]:
            c.rect(x, y, CELL_W - 4, CELL_H - 4, "#3a5a8a")
        c.rect(x + 20, y + 4, ICON, ICON, icon_color(entry["name"]))
        c.text(x + 20 + (ICON - 6) // 2, y + 4 + (ICON - 7) // 2, label_of(entry)[0], "#ffffff")
        label = label_of(entry)[:10]
        c.text(x + (CELL_W - 4 - 6 * len(label)) // 2, y + 4 + ICON + 6, label, "#ffffff")
    by = h - BAR_H
    c.rect(0, by, w, BAR_H, BAR)
    c.rect(4, by + 3, START_W, CHIP_H, ACCENT).text(14, by + 10, "START", "#ffffff")
    for x, _, cw, ch, label, _id in chips(w, st["open"]):
        c.rect(x, by + 3, cw, ch, "#2a4f80").text(x + 6, by + 10, label, "#ffffff")
    if st["note"]:
        c.text(6, by - 12, st["note"][:60].upper(), "#ffcc00")
    app.present(c)


def tui_lines(st):
    lines = ["", "  Desktop", ""]
    for n, entry in enumerate(icons(st["installed"])):
        lines.append(f"  {'>' if n == st['sel'] else ' '} {label_of(entry):<16} {entry.get('version', '')}")
    run = running(st["open"])
    lines += ["", "  Open: " + (", ".join(i["name"] for i in run) or "nothing"), "",
              "  arrows choose  enter open  s search (Start)  l library  r refresh"]
    if st["note"]:
        lines += ["", "  " + st["note"]]
    return lines


def main():
    app = App()
    st = {"installed": [], "open": [], "sel": 0, "note": "", "background": BACKGROUND}

    def focus(name):
        inst = find(st["open"], name)
        if inst:
            app.request_focus(inst["id"])
        else:
            st["note"] = f"{name} is not open"

    def open_entry(n):
        items = icons(st["installed"])
        if not 0 <= n < len(items):
            return
        entry = items[n]
        if entry["name"] == LIBRARY:
            focus(LIBRARY)
        else:
            st["note"] = "opening - type your password in the OS prompt"
            app.request_open(entry["name"], mode_for(entry, app.mode == "graphical"))

    for ev in app.events():
        cmd = ev["cmd"]
        count = len(icons(st["installed"]))
        if cmd == "hello":
            st["background"] = valid_color(app.vault_get("color", space="wallpaper")) or BACKGROUND
            app.request_apps()
        elif cmd == "apps":
            st["installed"], st["open"] = ev["installed"], ev["open"]
            st["sel"] = min(st["sel"], max(0, len(icons(st["installed"])) - 1))
        elif cmd == "result":
            if ev["action"] == "open" and ev.get("ok"):
                st["note"] = ""
                app.request_focus(ev["id"])
            elif not ev.get("ok"):
                st["note"] = "not done: " + ev.get("detail", "")
            if ev["action"] == "open":
                app.request_apps()
        elif cmd == "key":
            k = ev["key"]
            per = columns(app.width) if app.mode == "graphical" else 1
            if k == "left" and count:
                st["sel"] = (st["sel"] - 1) % count
            elif k == "right" and count:
                st["sel"] = (st["sel"] + 1) % count
            elif k == "up" and count:
                st["sel"] = (st["sel"] - per) % count
            elif k == "down" and count:
                st["sel"] = (st["sel"] + per) % count
            elif k == "enter":
                open_entry(st["sel"])
            elif k == "s":
                focus(SEARCH)
            elif k == "l":
                focus(LIBRARY)
            elif k == "r":
                app.request_apps()
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left" and app.mode == "graphical":
            x, y = ev["x"], ev["y"]
            by = app.height - BAR_H
            if y >= by:
                if 4 <= x < 4 + START_W:
                    focus(SEARCH)
                for cx, _, cw, ch, _label, ident in chips(app.width, st["open"]):
                    if cx <= x < cx + cw and by + 3 <= y < by + 3 + ch:
                        app.request_focus(ident)
            else:
                n = icon_at(x, y, app.width, count)
                if n is not None:
                    if n == st["sel"]:
                        open_entry(n)
                    st["sel"] = n
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, st)
        else:
            app.screen("Desktop", tui_lines(st), status="enter: open | s: search | l: library")
