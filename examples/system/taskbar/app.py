"""The taskbar. An ordinary app: it draws what the OS tells it and *asks* the
OS (never orders it) to switch to another app. The OS owns the right mouse
button - it opens the App Library from anywhere - so this app never sees it.

Keys: 1-9 jump to that open app, a-i open a pinned entry, l opens the App Library, r refreshes.

Mods: a mod the owner switched on for the taskbar (``kos extend NAME``) arrives as an
``extensions`` event. It is data - pinned entries (label + kos:// address) and an accent color -
and this app decides how to show it. A pinned entry is a *request* to open an address, like any
other: the OS still asks for your password."""

from kos.sdk import App, Canvas

HOME, LIBRARY = "taskbar", "app-library"
TOP_LINES = 3          # tui: first app sits on this line (hit-testing for clicks)
CHIP_W, CHIP_H, CHIP_GAP, BAR_H = 96, 20, 4, 28
PIN_KEYS = "abcdefghi"
PIN_H = 18
ACCENT = "#2f6db5"


def pinned(items):
    """(label, address) for every entry the switched-on mods pinned here; at most 9."""
    return [(e["label"], e["address"]) for it in items for e in it.get("entries", [])][:len(PIN_KEYS)]


def accent(items, default=ACCENT):
    for it in items:
        color = it.get("colors", {}).get("accent")
        if color:
            return color
    return default


def pin_chips(width, entries):
    """(x, y, w, h, label, address) for the second row of the bar."""
    out, x = [], 4
    for label, address in entries:
        if x + CHIP_W > width:
            break
        out.append((x, BAR_H + 4, CHIP_W, PIN_H, label[:14].upper(), address))
        x += CHIP_W + CHIP_GAP
    return out


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
    marks = pinned(state["ext"])
    if marks:
        lines += ["", "  Pinned (by your mods)", ""]
        lines += [f"    {PIN_KEYS[n]}  {label:<14} {address}" for n, (label, address) in enumerate(marks)]
    lines += ["", "  l  App Library      r  refresh      1-9  switch to that app",
              "  Right mouse = App Library      Ctrl-C leaves the desktop"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    w, h = app.width, app.height
    c = Canvas().clear("#101820")
    color = accent(state["ext"])
    pins = pin_chips(w, pinned(state["ext"]))
    c.rect(0, 0, w, BAR_H, "#1f3a5f")
    for x, y, cw, ch, label, _ in chips(w, state["open"]):
        c.rect(x, y, cw, ch, color).text(x + 6, y + 6, label, "#ffffff")
    for x, y, cw, ch, label, _ in pins:
        c.rect(x, y, cw, ch, color).text(x + 6, y + 5, label, "#ffffff")
    top = BAR_H + (PIN_H + 8 if pins else 0)
    c.text(6, top + 10, "OPEN APPS", "#ffcc00")
    y = top + 26
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
    state = {"open": [], "note": "", "ext": []}

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
        elif cmd == "extensions":
            state["ext"] = ev.get("items", [])
        elif cmd == "result":
            state["note"] = "" if ev.get("ok") else ev.get("detail", "")
            if ev.get("action") == "open" and ev.get("ok"):
                app.request_focus(ev["id"])           # a pinned entry opened: go there
        elif cmd == "key":
            k = ev["key"]
            marks = pinned(state["ext"])
            if k in PIN_KEYS and PIN_KEYS.index(k) < len(marks):
                state["note"] = "opening - type your password in the OS prompt"
                app.request_address(marks[PIN_KEYS.index(k)][1])
            elif k == "r":
                app.request_apps()
            elif k == "l":
                focus(find(state["open"], LIBRARY))
            elif k.isdigit() and k != "0":
                apps = running(state["open"])
                if int(k) <= len(apps):
                    focus(apps[int(k) - 1])
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left":
            if app.draws_frames:
                for x, y, cw, ch, _, ident in chips(app.width, state["open"]):
                    if x <= ev["x"] < x + cw and y <= ev["y"] < y + ch and ident:
                        app.request_focus(ident)
                for x, y, cw, ch, _, address in pin_chips(app.width, pinned(state["ext"])):
                    if x <= ev["x"] < x + cw and y <= ev["y"] < y + ch:
                        app.request_address(address)
            else:
                row = ev["y"] - TOP_LINES
                apps = running(state["open"])
                if 0 <= row < len(apps[:9]):
                    focus(apps[row])
        if cmd == "pointer":
            continue
        if app.draws_frames:
            draw_graphical(app, state)
        else:
            app.screen("Taskbar", tui_lines(state), status="l: App Library | r: refresh")
