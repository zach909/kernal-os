"""backup.add - one program of the backup app. It can ask the OS to back up one path and nothing
else (its manifest says ask:backup_add). Type a path, Enter; Esc leaves (or cancels typing)."""

from kos.sdk import App


def lines(state):
    out = ["", f"  path to back up: {state['path']}_", "",
           "  Enter asks the OS (type your password in its prompt)   Esc leaves"]
    if state["note"]:
        out += ["", "  " + state["note"]]
    return out


def handle_key(app, state, k):
    """Returns True when the program should exit."""
    if k == "escape":
        if state["path"]:
            state["path"] = ""
            return False
        return True
    if k == "enter":
        path, state["path"] = state["path"].strip(), ""
        if path:
            app.request_backup_add(path)
            state["note"] = "asking the OS to back it up - type your password in its prompt"
    elif k == "backspace":
        state["path"] = state["path"][:-1]
    elif len(k) == 1:
        state["path"] += k
    return False


def main():
    app = App()
    state = {"path": "", "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key" and handle_key(app, state, ev["key"]):
            app.exit(0)
            return
        elif cmd == "result":
            state["note"] = ev.get("detail", "")
        app.screen("Backup - add", lines(state), status="Esc to leave")
