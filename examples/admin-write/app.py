"""An app with the ``admin`` permission. It cannot write files itself (it is sandboxed and has no
disk); it *asks* the OS to write one as the administrator. The OS refuses unless the administrator
keyboard is on, asks for your password naming this app and the file, then scans and optimizes.

Keys: type a path (absolute), Tab, type the text, Enter to ask. Esc leaves."""

from kos.sdk import App


def lines(state):
    f = state["field"]
    return ["", f"  {'>' if f == 0 else ' '} path: {state['path']}{'_' if f == 0 else ''}",
            f"  {'>' if f == 1 else ' '} text: {state['text']}{'_' if f == 1 else ''}", "",
            "  Tab switch field   Enter ask the OS to write it   Esc leave", "",
            "  " + state["note"]]


def main():
    app = App()
    state = {"path": "/tmp/admin-write.txt", "text": "hello", "field": 0, "note": ""}
    for ev in app.events():
        if ev["cmd"] == "result" and ev.get("action") in ("write", "admin"):
            state["note"] = ("ok: " if ev["ok"] else "refused: ") + ev["detail"]
        elif ev["cmd"] == "key":
            k, f = ev["key"], ("path", "text")[state["field"]]
            if k == "escape":
                app.exit(0)
            elif k == "tab":
                state["field"] ^= 1
            elif k == "enter":
                state["note"] = "asking the OS (it will ask for your password)..."
                app.request_write(state["path"], state["text"])
            elif k == "backspace":
                state[f] = state[f][:-1]
            elif len(k) == 1:
                state[f] += k
        app.screen("Admin write", lines(state), "admin")
