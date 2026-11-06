"""The App Library. Lists every installed app and *asks* the OS to open one.
It cannot open anything by itself: the OS checks the app is permitted and
asks for your password in its own prompt, which this app cannot see or cover.

Keys: up/down select, enter open, g toggles graphical, r refresh, q back.

Mods: a mod the owner switched on for the App Library (``kos extend NAME``) arrives as an
``extensions`` event - data, never code: shelf entries (label + kos:// address) listed after the
installed apps, and an accent color. Opening a shelf entry is a request for an address, like any
other: the OS still asks for your password."""

from kos.sdk import App, Canvas

HOME, LIBRARY = "taskbar", "app-library"
TOP_LINES = 3
ROW_H = 12
ACCENT = "#5a2fa0"


def shelf(items):
    """The shelf entries the switched-on mods added: [{label, address}]."""
    return [{"label": e["label"], "address": e["address"]}
            for it in items for e in it.get("entries", [])][:12]


def accent(items, default=ACCENT):
    for it in items:
        color = it.get("colors", {}).get("accent")
        if color:
            return color
    return default


def rows(state):
    """What the Library lists, top to bottom: installed apps, then the mods' shelf."""
    return ([("app", a) for a in listed(state["installed"])]
            + [("shelf", e) for e in shelf(state["ext"])])


def listed(installed):
    return [a for a in installed if a["name"] not in (HOME, LIBRARY)]


def chosen_mode(entry, prefer_graphical):
    modes = entry["modes"]
    if prefer_graphical and "graphical" in modes:
        return "graphical"
    return "tui" if "tui" in modes else modes[0]


def tui_lines(state, height):
    items = rows(state)
    room = max(3, height - TOP_LINES - 5)
    first = max(0, min(state["sel"] - room + 1, len(items) - room)) if len(items) > room else 0
    lines = ["", "  Installed apps - Enter opens the selected one", ""]
    if not items:
        lines.append("    (no apps installed: kos install APP.kapp)")
    for n in range(first, min(len(items), first + room)):
        kind, a = items[n]
        mark = ">" if n == state["sel"] else " "
        if kind == "shelf":
            lines.append(f"  {mark} {a['label']:<14} {'shelf':<8} {a['address']}")
            continue
        mode = chosen_mode(a, state["graphical"])
        lock = "" if a["permitted"] else "   [needs: kos permit " + a["name"] + "]"
        tag = f"   [{a['kind']} of {a['extends']}]" if a.get("kind", "app") != "app" else ""
        lines.append(f"  {mark} {a['name']:<14} {a['version']:<8} {mode:<9}{lock}{tag}")
        if n == state["sel"] and a["description"]:
            lines.append("      " + a["description"][:70])
    lines += ["", "  up/down select   enter open   g graphical   r refresh   q back"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    w, h = app.width, app.height
    items = rows(state)
    c = Canvas().clear("#181028")
    c.rect(0, 0, w, 18, accent(state["ext"])).text(6, 5, "APP LIBRARY", "#ffffff")
    y = 26
    for n, (kind, a) in enumerate(items):
        if y + ROW_H > h - 24:
            break
        if n == state["sel"]:
            c.rect(2, y - 2, w - 4, ROW_H, "#3a2a6a")
        if kind == "shelf":
            c.text(8, y, f"{a['label']}  SHELF  {a['address']}", "#a0e0ff")
        else:
            mode = chosen_mode(a, state["graphical"])
            c.text(8, y, f"{a['name']}  {a['version']}  {mode}", "#ffffff" if a["permitted"] else "#a07070")
        y += ROW_H
    if not items:
        c.text(8, y, "NO APPS INSTALLED", "#a0a0a0")
    c.text(6, h - 12, "ENTER OPEN  G GRAPHICAL  Q BACK", "#8070b0")
    if state["note"]:
        c.text(6, h - 24, state["note"][:60], "#ffcc00")
    app.present(c)


def main():
    app = App()
    state = {"installed": [], "open": [], "sel": 0, "graphical": False, "note": "", "ext": []}

    def back():
        home = next((i for i in state["open"]
                     if i["name"] == HOME and i["status"] == "running"), None)
        if home:
            app.request_focus(home["id"])

    def launch():
        items = rows(state)
        if items:
            kind, a = items[state["sel"]]
            state["note"] = "opening - type your password in the OS prompt"
            if kind == "shelf":
                app.request_address(a["address"])
            else:
                app.request_open(a["name"], chosen_mode(a, state["graphical"]))

    for ev in app.events():
        cmd = ev["cmd"]
        n = len(rows(state))
        if cmd == "hello":
            app.request_apps()
        elif cmd == "extensions":
            state["ext"] = ev.get("items", [])
        elif cmd == "apps":
            state["installed"], state["open"] = ev["installed"], ev["open"]
            state["sel"] = min(state["sel"], max(0, len(rows(state)) - 1))
        elif cmd == "result":
            if ev["action"] == "open" and ev.get("ok"):
                app.request_focus(ev["id"])        # opened: go there
            elif not ev.get("ok"):
                state["note"] = "NOT DONE: " + ev.get("detail", "")
            if ev["action"] == "open":
                app.request_apps()
        elif cmd == "key":
            k = ev["key"]
            if k in ("up", "k") and n:
                state["sel"] = (state["sel"] - 1) % n
            elif k in ("down", "j") and n:
                state["sel"] = (state["sel"] + 1) % n
            elif k == "enter":
                launch()
            elif k == "g":
                state["graphical"] = not state["graphical"]
            elif k == "r":
                app.request_apps()
            elif k in ("q", "escape"):
                back()
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left":
            if app.mode == "graphical":
                row = (ev["y"] - 26) // ROW_H
            else:
                row = ev["y"] - TOP_LINES
            if 0 <= row < n:
                if row == state["sel"]:
                    launch()
                else:
                    state["sel"] = row
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, state)
        else:
            app.screen("App Library", tui_lines(state, app.height), status="enter: open | q: back")
