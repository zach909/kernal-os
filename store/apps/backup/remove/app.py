"""backup.remove - one program of the backup app. It can ask the OS for the list (to pick an item)
and to remove one item - nothing else (its manifest says ask:backup and ask:backup_remove).
up/down select, d removes the selected item, r refreshes, Esc leaves."""

from kos.sdk import App


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,} {unit}"
        n //= 1024      # whole numbers only: sizes are shown rounded down


def lines(state, height):
    items = state["items"]
    out = ["", "  " + ("" if state["loaded"] else "press r to load (the OS will ask for your password)")]
    room = max(3, height - 8)
    first = max(0, min(state["sel"] - room + 1, len(items) - room)) if len(items) > room else 0
    for n in range(first, min(len(items), first + room)):
        it = items[n]
        out.append(f"  {'>' if n == state['sel'] else ' '} {it['id']}  {human(it['size']):>9}  {it['path'][-44:]}")
    out += ["", "  up/down select   d remove   r refresh   Esc leave"]
    if state["note"]:
        out += ["", "  " + state["note"]]
    return out


def handle_key(app, state, k):
    """Returns True when the program should exit."""
    if k in ("escape", "q"):
        return True
    if k == "up":
        state["sel"] = max(0, state["sel"] - 1)
    elif k == "down":
        state["sel"] = min(max(0, len(state["items"]) - 1), state["sel"] + 1)
    elif k == "r":
        app.request_backup()
    elif k == "d" and state["items"]:
        app.request_backup_remove(state["items"][state["sel"]]["id"])
        state["note"] = "asking the OS to remove it - type your password in its prompt"
    return False


def main():
    app = App()
    state = {"items": [], "loaded": False, "sel": 0, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key" and handle_key(app, state, ev["key"]):
            app.exit(0)
            return
        elif cmd == "backup":
            state.update(items=ev["items"], loaded=True, note="")
            state["sel"] = min(state["sel"], max(0, len(state["items"]) - 1))
        elif cmd == "result":
            state["note"] = ev.get("detail", "") + ("  - press r to refresh" if ev.get("ok") else "")
        app.screen("Backup - remove", lines(state, app.height), status="Esc to leave")
