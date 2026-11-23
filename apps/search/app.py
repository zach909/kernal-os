"""Search: the popup the Windows key opens. Type, pick with up/down, enter opens it, escape goes back.

It asks the OS for the installed apps (``request apps``) and matches the letters you type itself. It
searches app names only: no files, no web, no commands. Opening an app asks for the password in the OS's own
prompt, like every other way of opening one. The Windows key itself is the OS's: this app never sees it."""

from kos.sdk import App, Canvas

SYSTEM = ("desktop", "taskbar", "app-library", "search")
LIBRARY, HOMES = "app-library", ("desktop", "taskbar")
BACKGROUND, ACCENT, PANEL = "#101820", "#2f6db5", "#222c40"
MAX_QUERY, ROWS, ROW_H = 40, 7, 14


def valid_color(text):
    ok = isinstance(text, str) and len(text) == 7 and text[0] == "#"
    return text.lower() if ok and all(ch in "0123456789abcdefABCDEF" for ch in text[1:]) else None


def dim(color):
    """The wallpaper at half brightness: the dimmed desktop the popup sits on."""
    return "#%02x%02x%02x" % tuple(int(color[i:i + 2], 16) // 2 for i in (1, 3, 5))


def entries(installed):
    """Everything a search can open: the App Library, then every installed app that is not part of the desktop."""
    rest = sorted((a for a in installed if a["name"] not in SYSTEM), key=lambda a: a["name"])
    return [{"name": LIBRARY, "modes": ["tui", "graphical"], "version": ""}] + rest


def score(query, name):
    """0 = no match. A name that starts with the letters beats one that contains them, which beats
    one that has them in order with gaps ('wlp' finds wallpaper)."""
    q, n = query.lower(), name.lower()
    if not q:
        return 1
    if n.startswith(q):
        return 300 - len(n)
    if q in n:
        return 200 - n.index(q)
    it = iter(n)
    return 100 - len(n) if all(ch in it for ch in q) else 0


def results(query, installed):
    ranked = [(score(query, e["name"]), e) for e in entries(installed)]
    return [e for s, e in sorted(((s, e) for s, e in ranked if s), key=lambda t: (-t[0], t[1]["name"]))]


def mode_for(entry, graphical):
    modes = entry.get("modes", ["tui"])
    return "graphical" if graphical and "graphical" in modes else ("tui" if "tui" in modes else modes[0])


def draw_graphical(app, st):
    w, h = app.width, app.height
    c = Canvas().clear(dim(st["background"]))
    pw = min(w - 16, 360)
    x, y = (w - pw) // 2, max(8, h // 8)
    hits = results(st["query"], st["installed"])[:ROWS]
    ph = 40 + ROW_H * max(1, len(hits)) + 22
    c.rect(x - 2, y - 2, pw + 4, ph + 4, ACCENT).rect(x, y, pw, ph, PANEL)
    c.rect(x + 8, y + 8, pw - 16, 20, "#0e141e")
    c.text(x + 14, y + 15, ("SEARCH  " + st["query"] + "_").upper()[:60], "#ffffff")
    for n, e in enumerate(hits):
        ry = y + 36 + n * ROW_H
        if n == st["sel"]:
            c.rect(x + 8, ry - 2, pw - 16, ROW_H, "#3a5a8a")
        c.text(x + 14, ry, e["name"].upper()[:50], "#ffffff")
    if not hits:
        c.text(x + 14, y + 36, "NO APP MATCHES", "#a0a0a0")
    c.text(x + 8, y + ph - 14, (st["note"] or "ENTER OPEN  ESC BACK").upper()[:60], "#ffcc00" if st["note"] else "#8090b0")
    app.present(c)


def tui_lines(st):
    lines = ["", "  search> " + st["query"] + "_", ""]
    hits = results(st["query"], st["installed"])
    for n, e in enumerate(hits[:ROWS]):
        lines.append(("  > " if n == st["sel"] else "    ") + e["name"])
    if not hits:
        lines.append("    no app matches")
    lines += ["", "  up/down choose  enter open  esc back"]
    if st["note"]:
        lines += ["", "  " + st["note"]]
    return lines


def main():
    app = App()
    st = {"installed": [], "open": [], "query": "", "sel": 0, "note": "", "background": BACKGROUND}

    def back():
        home = next((i for name in HOMES for i in st["open"] if i["name"] == name and i["status"] == "running"), None)
        if home:
            app.request_focus(home["id"])
        else:
            st["note"] = "the desktop is not open"

    def launch():
        hits = results(st["query"], st["installed"])
        if not hits:
            return
        e = hits[min(st["sel"], len(hits) - 1)]
        if e["name"] == LIBRARY:
            lib = next((i for i in st["open"] if i["name"] == LIBRARY and i["status"] == "running"), None)
            if lib:
                app.request_focus(lib["id"])
            else:
                st["note"] = "the App Library is not open"
        else:
            st["note"] = "opening - type your password in the OS prompt"
            app.request_open(e["name"], mode_for(e, app.mode == "graphical"))

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            st["background"] = valid_color(app.vault_get("color", space="wallpaper")) or BACKGROUND
            app.request_apps()
        elif cmd == "apps":
            st["installed"], st["open"] = ev["installed"], ev["open"]
        elif cmd == "result":
            if ev["action"] == "open" and ev.get("ok"):
                st["note"] = ""
                app.request_focus(ev["id"])
            elif not ev.get("ok"):
                st["note"] = "not done: " + ev.get("detail", "")
            if ev["action"] == "open":
                app.request_apps()
        elif cmd == "key":
            k, n = ev["key"], len(results(st["query"], st["installed"]))
            if k == "escape":
                back()
            elif k == "enter":
                launch()
            elif k == "backspace":
                st["query"], st["sel"] = st["query"][:-1], 0
            elif k == "up" and n:
                st["sel"] = (st["sel"] - 1) % min(n, ROWS)
            elif k == "down" and n:
                st["sel"] = (st["sel"] + 1) % min(n, ROWS)
            elif len(k) == 1 and k.isprintable() and len(st["query"]) < MAX_QUERY:
                st["query"], st["sel"], st["note"] = st["query"] + k, 0, ""
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, st)
        else:
            app.screen("Search", tui_lines(st), status="enter: open | esc: back")
