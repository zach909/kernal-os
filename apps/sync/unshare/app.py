"""sync.unshare - Stops syncing a folder. Its files are left exactly as they are.

One screen, one job. It asks the OS for exactly one function (sync.unshare); your password is typed in the
OS's own prompt, which this program cannot see or draw over. Type each answer and press Enter; Esc leaves.
Whole numbers only."""

from kos.sdk import App

TITLE = 'Stop syncing a folder'
SERVICE = 'sync.unshare'
STATUS = "Enter next   Backspace erase   Esc leaves"
# (argument, what to ask, kind, default). kinds: text | int | yes | list (separated by commas)
FIELDS = [["name", "name of the shared folder: ", "text", ""]]


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


def convert(vals):
    """The typed answers as the service's arguments, or (None, why)."""
    args = {}
    for (key, _label, kind, default), raw in zip(FIELDS, vals):
        raw = raw.strip() or default
        if not raw and kind != "yes":
            return None, f"{key} cannot be empty"
        if kind == "int":
            if not raw.isdigit():
                return None, f"{key} must be a whole number"
            args[key] = int(raw)
        elif kind == "yes":
            args[key] = raw.lower() in ("y", "yes", "true", "1")
        elif kind == "list":
            args[key] = [x.strip() for x in raw.split(",") if x.strip()]
        else:
            args[key] = raw
    return args, ""


def show(data, width):
    return [f"'{data['name']}' is no longer shared. Its files were not touched."]


def lines_for(state, width):
    out = [""]
    for (key, label, kind, default), v in zip(FIELDS, state["vals"]):
        out += wrap(f"  {label}{v}", width)
    if state["i"] < len(FIELDS) and not state["done"]:
        key, label, kind, default = FIELDS[state["i"]]
        hint = f"  [{default}]" if default else ""
        out += wrap(f"  {label}{state['buf']}_{hint}", width)
    if state["note"]:
        out += ["", *wrap("  " + state["note"], width)]
    return out + [""] + ["  " + l for l in state["out"]]


def submit(app, state):
    args, why = convert(state["vals"])
    if args is None:
        state["note"], state["vals"], state["i"] = why, [], 0
        return
    state["note"] = "asking the OS: type your password in its prompt"
    app.screen(TITLE, lines_for(state, app.width - 4), status="waiting for you at the OS prompt")
    reply = app.service(SERVICE, **args)
    state["done"], state["note"] = True, ""
    if reply.get("ok"):
        try:
            state["out"] = show(reply.get("data") or {}, app.width - 6)
        except (KeyError, TypeError, IndexError, ValueError, AttributeError):
            state["out"] = ["Done, but the OS answered in a form this program does not understand."]
    else:
        state["out"] = ["Refused: " + str(reply.get("detail", "the OS did not say why")), "", "Nothing was changed."]


def main():
    app = App()
    state = {"i": 0, "vals": [], "buf": "", "out": [], "note": "", "done": False}
    for ev in app.events():
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
                if state["i"] >= len(FIELDS):
                    submit(app, state)
            elif k == "backspace":
                state["buf"] = state["buf"][:-1]
            elif len(k) == 1:
                state["buf"] += k
        app.screen(TITLE, lines_for(state, app.width - 4), status=STATUS if not state["done"] else "Esc leaves")
