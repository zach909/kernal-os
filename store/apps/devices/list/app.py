"""devices.list - Shows this device and every device linked to it.

A read-only screen. It asks the OS for exactly one function (link.list); your password is typed in the OS's
own prompt, which this program cannot see or draw over. r asks again (and asks for the password again);
Esc leaves. Whole numbers only."""

from kos.sdk import App

TITLE = 'Linked devices'
SERVICE = 'link.list'


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
    me = data.get("me")
    out.append("This device: " + (f"{me['name']} ({me['platform']})  id {me['id']}" if me else "no identity yet (run devices.pair)"))
    out.append("")
    peers = data.get("peers") or []
    if not peers:
        out.append("No linked devices.")
    for p in peers:
        out += wrap(f"{p['name']}  ({p['platform']})  {p['scope']}  id {p['id']}  since {p['since']}", width)
    out += ["", "A linked device may ASK for any permission; this device's owner still types a password for it.",
            "devices.scope pauses one. devices.unlink removes one."]
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
