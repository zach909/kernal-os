"""device-chooser - Chooses which device a task should run on, and says why each other one was refused.

One screen, one job. You describe a task (1 general, 2 parallel, 3 inference; m memory; d data may leave
this machine; i must run apart from the main kernel) and press Enter. It asks the OS for exactly one
function (compute.choose); your password is typed in the OS's own prompt, which this program cannot see or
draw over. The OS decides and writes the choice to the audit log; this program only shows the answer and
never runs anything on any device. Esc leaves. Whole numbers only."""

from kos.sdk import App

TITLE = 'Device chooser'
SERVICE = 'compute.choose'
TASKS = ["general", "parallel", "inference"]
MEMORY_MB = [0, 512, 2048, 8192, 32768]
STATUS = "1 2 3 task   m memory   d data may leave   i isolate   Enter ask the OS   Esc leaves"


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


def describe(state):
    mem = MEMORY_MB[state["mem"]]
    return [
        "Task:            " + TASKS[state["task"]] + "   (1 general, 2 parallel, 3 inference)",
        "Memory needed:   " + (str(mem) + " MB" if mem else "not stated") + "   (m changes it)",
        "Data may leave:  " + ("yes" if not state["private"] else "no, it stays on this machine") + "   (d changes it)",
        "Run apart:       " + ("yes, away from the main kernel" if state["isolate"] else "no") + "   (i changes it)",
    ]


def show(data, width):
    out = []
    device = data.get("device")
    ranked = data.get("ranked") or []
    refused = data.get("refused") or []
    if device is None:
        out.append("No device. Nothing may run this task as asked, and nothing was run.")
    else:
        top = next((r for r in ranked if r.get("id") == device), {})
        out.append("Chosen: " + str(device) + "  " + str(top.get("name", "")))
    if len(ranked) > 1:
        out += ["", "Also allowed, in order:"]
        for r in ranked:
            if r.get("id") != device:
                out += wrap("  " + str(r.get("id")) + "  " + str(r.get("name")) + "  score " + str(r.get("score")), width)
    if refused:
        out += ["", "Refused:"]
        for r in refused:
            out += wrap("  " + str(r.get("id")) + "  " + str(r.get("why")), width)
    if data.get("note"):
        out += ["", "Note: " + str(data["note"])]
    out += ["", "This chooses only. It does not start anything on the device."]
    return out


def ask(app, state):
    state["lines"] = ["Asking the OS: type your password in its prompt."]
    app.screen(TITLE, [""] + ["  " + l for l in describe(state) + [""] + state["lines"]], status="waiting for you at the OS prompt")
    reply = app.service(SERVICE, task=TASKS[state["task"]], memory=MEMORY_MB[state["mem"]],
                        private=state["private"], isolate=state["isolate"])
    if reply.get("ok"):
        try:
            state["lines"] = show(reply.get("data") or {}, app.width - 6)
        except (KeyError, TypeError, IndexError, ValueError, AttributeError):
            state["lines"] = ["The OS answered in a form this program does not understand."]
    else:
        state["lines"] = ["Refused: " + str(reply.get("detail", "the OS did not say why")), "", "Nothing was chosen."]


def main():
    app = App()
    state = {"task": 0, "mem": 0, "private": True, "isolate": False, "lines": ["Press Enter to ask the OS."]}
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k in ("1", "2", "3"):
                state["task"] = int(k) - 1
            elif k == "m":
                state["mem"] = (state["mem"] + 1) % len(MEMORY_MB)
            elif k == "d":
                state["private"] = not state["private"]
            elif k == "i":
                state["isolate"] = not state["isolate"]
            elif k == "enter":
                ask(app, state)
        app.screen(TITLE, [""] + ["  " + l for l in describe(state) + [""] + state["lines"]], status=STATUS)
