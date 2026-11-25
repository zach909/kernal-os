"""devices.pair - links another device: the same code on both screens, the password on both devices.

One screen, one job. It asks the OS for two functions of the 'link' group: link.identify (once, to name this
device) and link.pair. The code to compare and the yes/no are in the OS's own prompt, which this program cannot
see or draw over, so nothing here can fake "the codes match". Esc leaves. Whole numbers only."""

from kos.sdk import App

TITLE = "Link a device"
PLATFORMS = "kos, linux, windows, macos, android or ios"
STATUS = "Enter next   Backspace erase   Esc leaves"


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


def ask_fields(has_identity):
    first = [] if has_identity else [("name", "name for this device: ", "text", ""),
                                     ("platform", "what it runs (" + PLATFORMS + "): ", "text", "linux")]
    return first + [("role", "this device connects or listens: ", "text", "listen"),
                    ("host", "address (the other device's, or this one's to listen on): ", "text", "127.0.0.1"),
                    ("port", "port: ", "int", "7007")]


def lines_for(state, width):
    out = [""]
    for (key, label, kind, default), v in zip(state["fields"], state["vals"]):
        out += wrap(f"  {label}{v}", width)
    if state["i"] < len(state["fields"]) and not state["done"]:
        key, label, kind, default = state["fields"][state["i"]]
        hint = f"  [{default}]" if default else ""
        out += wrap(f"  {label}{state['buf']}_{hint}", width)
    if state["note"]:
        out += ["", *wrap("  " + state["note"], width)]
    return out + [""] + ["  " + l for l in state["out"]]


def refused(state, reply):
    state["done"] = True
    state["out"] = ["Refused: " + str(reply.get("detail", "the OS did not say why")), "", "Nothing was changed."]


def submit(app, state):
    args = {}
    for (key, _l, kind, default), raw in zip(state["fields"], state["vals"]):
        raw = raw.strip() or default
        if not raw or (kind == "int" and not raw.isdigit()):
            state["note"], state["vals"], state["i"] = f"{key} is missing or not a whole number", [], 0
            return
        args[key] = int(raw) if kind == "int" else raw
    if args["role"] not in ("connect", "listen"):
        state["note"], state["vals"], state["i"] = "role is connect or listen", [], 0
        return
    if "name" in args:
        app.screen(TITLE, lines_for(state, app.width - 4), status="waiting for you at the OS prompt")
        made = app.service("link.identify", name=args.pop("name"), platform=args.pop("platform"))
        if not made.get("ok"):
            return refused(state, made)
    state["note"] = "compare the code in the OS prompt with the other screen, then type your password"
    app.screen(TITLE, lines_for(state, app.width - 4), status="waiting for you at the OS prompt")
    reply = app.service("link.pair", **args)
    state["done"], state["note"] = True, ""
    if not reply.get("ok"):
        return refused(state, reply)
    d = reply.get("data") or {}
    p = d.get("linked") or {}
    state["out"] = [f"Linked with {p.get('name', '?')} ({p.get('platform', '?')}). Code was {d.get('code', '?')}.",
                    "It may now ask this device for any permission; you type the password for each.",
                    "devices.list shows it; devices.scope pauses it; devices.unlink removes it."]


def main():
    app = App()
    state = {"i": 0, "vals": [], "buf": "", "out": [], "note": "", "done": False, "fields": ask_fields(True)}
    started = False
    for ev in app.events():
        if not started:
            started = True
            reply = app.service("link.list")          # does this device have an identity yet? (asks the password)
            if reply.get("ok"):
                state["fields"] = ask_fields(bool((reply.get("data") or {}).get("me")))
            else:
                refused(state, reply)
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                if state["done"] or not state["buf"]:
                    app.exit(0)
                    return
                state["buf"] = ""
            elif state["done"]:
                pass
            elif k == "enter":
                state["vals"].append(state["buf"])
                state["buf"], state["note"] = "", ""
                state["i"] += 1
                if state["i"] >= len(state["fields"]):
                    submit(app, state)
            elif k == "backspace":
                state["buf"] = state["buf"][:-1]
            elif len(k) == 1:
                state["buf"] += k
        app.screen(TITLE, lines_for(state, app.width - 4), status=STATUS if not state["done"] else "Esc leaves")
