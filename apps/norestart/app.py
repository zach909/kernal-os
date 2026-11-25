"""norestart - No reboot: swap out-of-date apps for their new files while the machine stays on.

One screen, one job. After an update, an app that is already open keeps running the old file from memory.
This app asks the OS which open apps are out of date (s), swaps them now (r), or lets the OS keep doing it by
itself for some hours (a; + and - choose the hours; x stops it). Each of those asks the OS for exactly one
function, and your password is typed in the OS's own prompt, which this program cannot see or draw over.

It does not swap anything itself and never sees a key. A swap starts the new file first and closes the old
one only when the new one is running, and it never widens what an app may do: an app that now wants more,
or has not been permitted in its new version, is left running and listed here for you. A reboot is still
needed for a new kernel or new firmware, and this screen says so. Whole numbers only. Esc leaves."""

from kos.sdk import App

TITLE = "No reboot"
STATUS = "s check   r swap now   a automatic for N hours   + - hours   x stop automatic   Esc leaves"
ASKING = "waiting for you at the OS prompt"


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


def show_status(data, width):
    out = []
    if data.get("reboot_needed"):
        out.append("A reboot IS needed:")
        for why in data.get("reboot") or []:
            out += wrap("  - " + str(why), width)
    else:
        out.append("No reboot is needed.")
    rows = data.get("apps") or []
    current = [r for r in rows if r.get("state") == "current"]
    other = [r for r in rows if r.get("state") != "current"]
    out += ["", str(len(rows)) + " open app(s): " + str(len(current)) + " up to date."]
    for r in other:
        old = str(r.get("running") or "?")
        out += wrap("  " + str(r.get("name")) + "  " + old + " -> " + str(r.get("installed")) + "  " + str(r.get("state")), width)
        if r.get("why"):
            out += wrap("      " + str(r.get("why")), width)
    for line in data.get("session") or []:
        out += [""] + wrap(str(line), width)
    auto = data.get("auto")
    out.append("")
    if auto:
        out += wrap("Automatic swapping is ON: " + str(auto.get("minutes_left")) + " minute(s) left, "
                    + str(auto.get("swapped")) + " swapped, " + str(auto.get("kept")) + " left alone.", width)
    else:
        out.append("Automatic swapping is OFF.")
    return out


def show_refresh(data, width):
    out = []
    results = data.get("results") or []
    if not results:
        out.append("Nothing to swap: no open app is out of date and safe to swap.")
    for r in results:
        out += wrap(str(r.get("outcome")).upper() + "  " + str(r.get("name")) + "  "
                    + str(r.get("from") or "?") + " -> " + str(r.get("to")) + "  " + str(r.get("why")), width)
    return out + [""] + show_apps_left(data, width)


def show_apps_left(data, width):
    out = []
    for r in data.get("apps") or []:
        if r.get("state") not in ("current", "unknown"):
            out += wrap("  " + str(r.get("name")) + " is " + str(r.get("state")) + ": " + str(r.get("why")), width)
    return out


def ask(client, state, name, **args):
    """One question to the OS. ``args`` are the service's own arguments (one of them is called ``app``), so
    the connection is called ``client`` here."""
    state["lines"] = ["Asking the OS: type your password in its prompt."]
    client.screen(TITLE, [""] + ["  " + l for l in state["lines"]], status=ASKING)
    reply = client.service(name, **args)
    if not reply.get("ok"):
        state["lines"] = ["Refused: " + str(reply.get("detail", "the OS did not say why")), "", "Nothing was changed."]
        return
    data = reply.get("data") or {}
    width = client.width - 6
    try:
        if name == "norestart.status":
            state["lines"] = show_status(data, width)
        elif name == "norestart.refresh":
            state["lines"] = show_refresh(data, width)
        elif name == "norestart.auto":
            state["lines"] = wrap("Automatic swapping is ON for " + str(data.get("hours")) + " hour(s). Your password was "
                                  "typed once, just now, and is not kept: the OS holds three keys derived from it, "
                                  "in memory only, wiped when the time is up or you stop it.", width)
        else:
            state["lines"] = ["Automatic swapping stopped." if data.get("stopped") else "It was not running."]
    except (KeyError, TypeError, IndexError, ValueError, AttributeError):
        state["lines"] = ["The OS answered in a form this program does not understand."]


def main():
    app = App()
    state = {"hours": 8, "lines": ["Press s to ask the OS which open apps are out of date.", "",
                                   "Nothing is asked or changed until you press a key."]}
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "s":
                ask(app, state, "norestart.status")
            elif k == "r":
                ask(app, state, "norestart.refresh")            # no app named: every one that is safe to swap
            elif k == "a":
                ask(app, state, "norestart.auto", hours=state["hours"])
            elif k == "x":
                ask(app, state, "norestart.stop")
            elif k in ("+", "="):
                state["hours"] = min(24, state["hours"] + 1)
            elif k == "-":
                state["hours"] = max(1, state["hours"] - 1)
        head = ["", "  Automatic swapping would last " + str(state["hours"]) + " hour(s) when started (a)."]
        app.screen(TITLE, head + [""] + ["  " + l for l in state["lines"]], status=STATUS)
