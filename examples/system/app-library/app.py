"""The App Library. Lists every installed app and *asks* the OS to open one.
It cannot open anything by itself: the OS checks the app is permitted and
asks for your password in its own prompt, which this app cannot see or cover.

Keys: up/down select, enter open, g toggles graphical, r refresh, q back."""

from kos.sdk import App, Canvas

HOME, LIBRARY = "taskbar", "app-library"
TOP_LINES = 3
ROW_H = 12


def listed(installed):
    return [a for a in installed if a["name"] not in (HOME, LIBRARY)]


def chosen_mode(entry, prefer_graphical):
    modes = entry["modes"]
    if prefer_graphical and "graphical" in modes:
        return "graphical"
    return "tui" if "tui" in modes else modes[0]


def tui_lines(state, height):
    apps = listed(state["installed"])
    room = max(3, height - TOP_LINES - 5)
    first = max(0, min(state["sel"] - room + 1, len(apps) - room)) if len(apps) > room else 0
    lines = ["", "  Installed apps - Enter opens the selected one", ""]
    if not apps:
        lines.append("    (no apps installed: kos install APP.kapp)")
    for n in range(first, min(len(apps), first + room)):
        a = apps[n]
        mark = ">" if n == state["sel"] else " "
        mode = chosen_mode(a, state["graphical"])
        lock = "" if a["permitted"] else "   [needs: kos permit " + a["name"] + "]"
        lines.append(f"  {mark} {a['name']:<14} {a['version']:<8} {mode:<9}{lock}")
        if n == state["sel"] and a["description"]:
            lines.append("      " + a["description"][:70])
    lines += ["", "  up/down select   enter open   g graphical   r refresh   q back"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    w, h = app.width, app.height
    apps = listed(state["installed"])
    c = Canvas().clear("#181028")
    c.rect(0, 0, w, 18, "#5a2fa0").text(6, 5, "APP LIBRARY", "#ffffff")
    y = 26
    for n, a in enumerate(apps):
        if y + ROW_H > h - 24:
            break
        if n == state["sel"]:
            c.rect(2, y - 2, w - 4, ROW_H, "#3a2a6a")
        mode = chosen_mode(a, state["graphical"])
        c.text(8, y, f"{a['name']}  {a['version']}  {mode}", "#ffffff" if a["permitted"] else "#a07070")
        y += ROW_H
    if not apps:
        c.text(8, y, "NO APPS INSTALLED", "#a0a0a0")
    c.text(6, h - 12, "ENTER OPEN  G GRAPHICAL  Q BACK", "#8070b0")
    if state["note"]:
        c.text(6, h - 24, state["note"][:60], "#ffcc00")
    app.present(c)


def main():
    app = App()
    state = {"installed": [], "open": [], "sel": 0, "graphical": False, "note": ""}

    def back():
        home = next((i for i in state["open"]
                     if i["name"] == HOME and i["status"] == "running"), None)
        if home:
            app.request_focus(home["id"])

    def launch():
        apps = listed(state["installed"])
        if apps:
            a = apps[state["sel"]]
            state["note"] = f"opening {a['name']} - type your password in the OS prompt"
            app.request_open(a["name"], chosen_mode(a, state["graphical"]))

    for ev in app.events():
        cmd = ev["cmd"]
        n = len(listed(state["installed"]))
        if cmd == "hello":
            app.request_apps()
        elif cmd == "apps":
            state["installed"], state["open"] = ev["installed"], ev["open"]
            state["sel"] = min(state["sel"], max(0, len(listed(state["installed"])) - 1))
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
