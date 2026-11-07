"""The App Library. Lists every installed app and *asks* the OS to open one.
It cannot open anything by itself: the OS checks the app is permitted and
asks for your password in its own prompt, which this app cannot see or cover.

Keys: up/down select, enter open, g toggles graphical, r refresh, q back, / or Ctrl-Y search.

Search (/): one line that looks at the installed apps and the KOS commands, and offers "Ask the
assistant" (kos/office/finder.py - the same search the Ctrl-N box uses). Search only shows: a command
is text to read, an app is a request the OS still asks your password for.

Mods: a mod the owner switched on for the App Library (``kos extend NAME``) arrives as an
``extensions`` event - data, never code: shelf entries (label + kos:// address) listed after the
installed apps, and an accent color. Opening a shelf entry is a request for an address, like any
other: the OS still asks for your password."""

from kos.office import finder
from kos.sdk import App, Canvas

HOME, LIBRARY = "taskbar", "app-library"
ASSISTANT = "ai-assistant"      # the suite app that "Ask the assistant" opens
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


def hits(state):
    """The search rows for what is typed (apps and commands; the Library has no files of its own)."""
    return finder.search(state["query"] or "", apps=listed(state["installed"]))


def search_lines(state, height):
    hs = hits(state)
    room = max(3, height - 7)
    first = max(0, min(state["sel"] - room + 1, len(hs) - room)) if len(hs) > room else 0
    lines = ["", "  search> " + state["query"] + "_", ""]
    last = None
    for n in range(first, min(len(hs), first + room)):
        h = hs[n]
        if h.kind != last:
            lines.append("  " + finder.HEADINGS[h.kind]); last = h.kind
        lines.append(("  > " if n == state["sel"] else "    ") + h.label)
        if n == state["sel"] and h.detail:
            lines.append("      " + h.detail)
    lines += ["", "  type to search   up/down select   enter open   esc back"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def search_key(state, k):
    """Handle one key while searching. Returns None, or an action for main(): ("open", app, mode)."""
    n = len(hits(state))
    if k == "escape":
        state["query"], state["sel"], state["note"] = None, 0, ""
    elif k == "up" and n:
        state["sel"] = (state["sel"] - 1) % n
    elif k == "down" and n:
        state["sel"] = (state["sel"] + 1) % n
    elif k == "backspace":
        state["query"], state["sel"] = state["query"][:-1], 0
    elif len(k) == 1 and k.isprintable() and len(state["query"]) < finder.MAX_QUERY:
        state["query"], state["sel"] = state["query"] + k, 0
    elif k == "enter" and n:
        h = hits(state)[min(state["sel"], n - 1)]
        if h.kind == finder.APP:
            entry = next((a for a in state["installed"] if a["name"] == h.ref), None)
            if entry:
                return ("open", entry["name"], chosen_mode(entry, state["graphical"]))
        elif h.kind == finder.ACTION:
            state["note"] = finder.plain(next((u for c, _h, u in finder.COMMANDS if c == h.ref), ""), 70) + "   (type it in the KOS shell)"
        elif h.kind == finder.ASK:
            entry = next((a for a in listed(state["installed"]) if a["name"] == ASSISTANT), None)
            if entry:
                return ("open", ASSISTANT, chosen_mode(entry, state["graphical"]))
            state["note"] = "no assistant installed: build the suite (bin/suite build DIR), then kos install the AI Assistant"
    return None


def tui_lines(state, height):
    if state.get("query") is not None:
        return search_lines(state, height)
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
    if state.get("query") is not None:
        c = Canvas().clear("#181028").rect(0, 0, w, 18, accent(state["ext"])).text(6, 5, "SEARCH  " + state["query"].upper() + "_", "#ffffff")
        for n, r in enumerate(hits(state)):
            y = 26 + n * ROW_H
            if y + ROW_H > h - 24:
                break
            if n == state["sel"]:
                c.rect(2, y - 2, w - 4, ROW_H, "#3a2a6a")
            c.text(8, y, r.label.upper()[:60], "#ffffff")
        c.text(6, h - 12, "ENTER OPEN  ESC BACK", "#8070b0")
        if state["note"]:
            c.text(6, h - 24, state["note"].upper()[:60], "#ffcc00")
        app.present(c)
        return
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
    state = {"installed": [], "open": [], "sel": 0, "graphical": False, "note": "", "ext": [], "query": None}

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
        elif cmd == "key" and state["query"] is not None:
            act = search_key(state, ev["key"])
            if act:
                state["note"] = "opening - type your password in the OS prompt"
                app.request_open(act[1], act[2])
        elif cmd == "key":
            k = ev["key"]
            if k in ("/", "ctrl-y"):
                state["query"], state["sel"], state["note"] = "", 0, ""
            elif k in ("up", "k") and n:
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
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left" and state["query"] is None:
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
