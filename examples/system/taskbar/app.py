"""The taskbar. An ordinary app: it draws what the OS tells it and *asks* the
OS (never orders it) to switch to another app. The OS owns the right mouse
button - it opens the App Library from anywhere - so this app never sees it.

Keys: 1-9 jump to that open app, l opens the App Library, r refreshes."""

from kos.sdk import App, Canvas

HOME, LIBRARY = "taskbar", "app-library"
TOP_LINES = 3          # tui: first app sits on this line (hit-testing for clicks)
CHIP_W, CHIP_H, CHIP_GAP, BAR_H = 96, 20, 4, 28


def running(open_list):
    return [i for i in open_list
            if i["name"] not in (HOME, LIBRARY) and i["status"] == "running"]


def find(open_list, name):
    return next((i for i in open_list if i["name"] == name and i["status"] == "running"), None)


def chips(width, open_list):
    """(x, y, w, h, label, instance_id) for the bar: Library first, then apps."""
    out, x = [], 4
    lib = find(open_list, LIBRARY)
    out.append((x, 4, CHIP_W, CHIP_H, "LIBRARY", lib["id"] if lib else None))
    for inst in running(open_list):
        x += CHIP_W + CHIP_GAP
        if x + CHIP_W > width:
            break
        out.append((x, 4, CHIP_W, CHIP_H, inst["name"][:14].upper(), inst["id"]))
    return out


def tui_lines(state):
    apps = running(state["open"])
    lines = ["", "  Open apps", ""]
    if not apps:
        lines.append("    (nothing open yet - press l, or right-click, for the App Library)")
    for n, inst in enumerate(apps[:9], 1):
        lines.append(f"    {n}  {inst['name']:<14} {inst['mode']:<9} {inst['id']}")
    lines += ["", "  l  App Library      r  refresh      1-9  switch to that app",
              "  Right mouse = App Library      Ctrl-C leaves the desktop"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    w, h = app.width, app.height
    c = Canvas().clear("#101820")
    c.rect(0, 0, w, BAR_H, "#1f3a5f")
    for x, y, cw, ch, label, _ in chips(w, state["open"]):
        c.rect(x, y, cw, ch, "#2f6db5").text(x + 6, y + 6, label, "#ffffff")
    c.text(6, BAR_H + 10, "OPEN APPS", "#ffcc00")
    y = BAR_H + 26
    apps = running(state["open"])
    if not apps:
        c.text(6, y, "NOTHING OPEN - CLICK LIBRARY OR RIGHT-CLICK", "#a0a0a0")
    for inst in apps:
        c.text(6, y, f"{inst['name']}  {inst['mode']}  {inst['id']}", "#a0ffa0")
        y += 12
    c.text(6, h - 14, "RIGHT MOUSE = APP LIBRARY", "#6080a0")
    if state["note"]:
        c.text(6, h - 28, state["note"][:60], "#ff8080")
    app.present(c)


def main():
    app = App()
    state = {"open": [], "note": ""}

    def focus(inst):
        if inst:
            app.request_focus(inst["id"])
        else:
            state["note"] = "the App Library is not open"

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
        elif cmd == "apps":
            state["open"] = ev["open"]
        elif cmd == "result":
            state["note"] = "" if ev.get("ok") else ev.get("detail", "")
        elif cmd == "key":
            k = ev["key"]
            if k == "r":
                app.request_apps()
            elif k == "l":
                focus(find(state["open"], LIBRARY))
            elif k.isdigit() and k != "0":
                apps = running(state["open"])
                if int(k) <= len(apps):
                    focus(apps[int(k) - 1])
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left":
            if app.mode == "graphical":
                for x, y, cw, ch, _, ident in chips(app.width, state["open"]):
                    if x <= ev["x"] < x + cw and y <= ev["y"] < y + ch and ident:
                        app.request_focus(ident)
            else:
                row = ev["y"] - TOP_LINES
                apps = running(state["open"])
                if 0 <= row < len(apps[:9]):
                    focus(apps[row])
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, state)
        else:
            app.screen("Taskbar", tui_lines(state), status="l: App Library | r: refresh")
