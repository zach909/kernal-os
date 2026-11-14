"""sync.folders - Shows the folders chosen for syncing.

A read-only screen. It asks the OS for exactly one function (sync.folders); your password is typed in the OS's
own prompt, which this program cannot see or draw over. r asks again (and asks for the password again);
Esc leaves. Whole numbers only."""

from kos.sdk import App

TITLE = 'Folders chosen for syncing'
SERVICE = 'sync.folders'


def wrap(text, width):
    out = []
    for raw in str(text).split("\n"):
        line = raw
        while len(line) > width:
            cut = line.rfind(" ", 0, width)
            cut = cut if cut > 0 else width
            out.append(line[:cut])
            line = line[cut:].lstrip()
        out.append(line)
    return out


def show(data, width):
    out = []
    rows = data.get("folders") or []
    if not rows:
        out.append("No folders are shared. Use sync.share to choose one.")
    for f in rows:
        out += wrap(f"{f['name']}  ->  {f['path']}", width)
    return out


def refresh(app, state):
    reply = app.service(SERVICE)
    if reply.get("ok"):
        try:
            state["lines"] = show(reply.get("data") or {}, app.width - 6)
        except (KeyError, TypeError, IndexError, ValueError, AttributeError):
            state["lines"] = ["The OS answered in a form this program does not understand."]
    else:
        state["lines"] = ["Refused: " + str(reply.get("detail", "the OS did not say why")), "", "Nothing was shown."]
    state["asked"] = True


def main():
    app = App()
    state = {"lines": ["Press r to ask the OS (it will ask for your password)."], "asked": False}
    for ev in app.events():
        if ev["cmd"] == "key":
            if ev["key"] == "escape":
                app.exit(0)
                return
            if ev["key"] in ("r", "enter"):
                refresh(app, state)
        app.screen(TITLE, [""] + ["  " + l for l in state["lines"]], status="r ask again   Esc leaves")
