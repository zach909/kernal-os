"""Backup. An ordinary sandboxed app: it cannot read your files or keep anything
after it exits, so it does not back anything up itself. It *asks* the OS (the
``system`` permission), and the OS does the work after you type your password in
its own prompt - which this app cannot see or cover. Every action asks: opening
the list, adding a path, removing an item.

Keys: up/down select, a add a file/folder (type its path, Enter), d remove the
selected item, r load/refresh the list, Esc leaves (or cancels typing a path)."""

from kos.sdk import App, Canvas

TOP_LINES = 3
ROW_H = 12


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,} {unit}"
        n //= 1024      # whole numbers only: sizes are shown rounded down


def ratio_line(stats):
    if not stats or not stats["logical"]:
        return "nothing backed up yet"
    pct = 100 * stats["saved"] // stats["logical"]
    return (f"{stats['items']} item(s), {stats['unique']} unique - "
            f"{human(stats['logical'])} backed up, {human(stats['stored'])} stored, "
            f"{pct}% saved")


def tui_lines(state, height):
    items = state["items"]
    room = max(3, height - TOP_LINES - 8)
    first = max(0, min(state["sel"] - room + 1, len(items) - room)) if len(items) > room else 0
    lines = ["", "  " + (ratio_line(state["stats"]) if state["loaded"]
                         else "press r to load (the OS will ask for your password)"), ""]
    if state["loaded"] and not items:
        lines.append("    (empty - press a to add a file or folder)")
    for n in range(first, min(len(items), first + room)):
        it = items[n]
        mark = ">" if n == state["sel"] else " "
        lines.append(f"  {mark} {it['id']}  {human(it['size']):>9}  {it['path'][-44:]}")
    if state["typing"] is not None:
        lines += ["", f"  path to back up: {state['typing']}_"]
    else:
        lines += ["", "  up/down select   a add   d remove   r refresh   Esc leave"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    w, h = app.width, app.height
    c = Canvas().clear("#0f1c18")
    c.rect(0, 0, w, 18, "#1f7a5a").text(6, 5, "BACKUP", "#ffffff")
    c.text(6, 24, ratio_line(state["stats"]).upper() if state["loaded"]
           else "PRESS R TO LOAD", "#ffcc00")
    y = 40
    for n, it in enumerate(state["items"]):
        if y + ROW_H > h - 30:
            break
        if n == state["sel"]:
            c.rect(2, y - 2, w - 4, ROW_H, "#1f4a3a")
        c.text(8, y, f"{it['id']}  {human(it['size'])}  {it['path'][-40:]}", "#a0ffa0")
        y += ROW_H
    if state["typing"] is not None:
        c.text(6, h - 28, "PATH: " + state["typing"][-(w // 6 - 8):] + "_", "#ffffff")
    else:
        c.text(6, h - 14, "A ADD   D REMOVE   R REFRESH   ESC LEAVE", "#608070")
    if state["note"]:
        c.text(6, h - 28, state["note"][:60], "#ff8080")
    app.present(c)


def handle_key(app, state, k):
    """Returns True when the app should exit."""
    if state["typing"] is not None:
        if k == "escape":
            state["typing"] = None
        elif k == "enter":
            path, state["typing"] = state["typing"].strip(), None
            if path:
                app.request_backup_add(path)
                state["note"] = "asking the OS to back it up - type your password in its prompt"
        elif k == "backspace":
            state["typing"] = state["typing"][:-1]
        elif len(k) == 1:
            state["typing"] += k
        return False
    if k == "escape" or k == "q":
        return True
    if k == "up":
        state["sel"] = max(0, state["sel"] - 1)
    elif k == "down":
        state["sel"] = min(max(0, len(state["items"]) - 1), state["sel"] + 1)
    elif k == "r":
        app.request_backup()
    elif k == "a":
        state["typing"], state["note"] = "", ""
    elif k == "d" and state["items"]:
        app.request_backup_remove(state["items"][state["sel"]]["id"])
        state["note"] = "asking the OS to remove it - type your password in its prompt"
    return False


def main():
    app = App()
    state = {"items": [], "stats": None, "loaded": False, "sel": 0, "typing": None, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key" and handle_key(app, state, ev["key"]):
            app.exit(0)
            return
        elif cmd == "backup":
            state.update(items=ev["items"], stats=ev["stats"], loaded=True, note="")
            state["sel"] = min(state["sel"], max(0, len(state["items"]) - 1))
        elif cmd == "result":
            ok = ev.get("ok")
            state["note"] = ev.get("detail", "") + ("  - press r to refresh" if ok else "")
        if app.mode == "tui":
            app.screen("Backup", tui_lines(state, app.height), status="Esc to leave")
        else:
            draw_graphical(app, state)
