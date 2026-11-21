"""backup.list - one program of the backup app. It can ask the OS for the list and nothing else
(its manifest says ask:backup). r loads/refreshes, Esc leaves."""

from kos.sdk import App


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
            f"{human(stats['logical'])} backed up, {human(stats['stored'])} stored, {pct}% saved")


def lines(state, height):
    out = ["", "  " + (ratio_line(state["stats"]) if state["loaded"]
                       else "press r to load (the OS will ask for your password)"), ""]
    room = max(3, height - 8)
    for it in state["items"][:room]:
        out.append(f"    {it['id']}  {human(it['size']):>9}  {it['path'][-44:]}")
    if state["note"]:
        out += ["", "  " + state["note"]]
    return out


def handle_key(app, state, k):
    """Returns True when the program should exit."""
    if k in ("escape", "q"):
        return True
    if k == "r":
        app.request_backup()
    return False


def main():
    app = App()
    state = {"items": [], "stats": None, "loaded": False, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key" and handle_key(app, state, ev["key"]):
            app.exit(0)
            return
        elif cmd == "backup":
            state.update(items=ev["items"], stats=ev["stats"], loaded=True, note="")
        elif cmd == "result":
            state["note"] = ev.get("detail", "")
        app.screen("Backup - list", lines(state, app.height), status="r refresh   Esc to leave")
