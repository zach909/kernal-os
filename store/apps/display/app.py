"""Display: the screen: the mode, its size and which surface draws it

It never opens a device. It *asks* the OS (``request status``) and shows the answer. It needs
only ``ask:status``: it cannot open, close or switch apps. Keys: r refreshes. Ctrl-C is the OS's.
"""

from kos.sdk import App, Canvas

TOPIC, TITLE = "display", "Display"
BLURB = 'The screen: the mode, its size and which surface draws it'


def rows(state):
    """(name, value) rows to show: what the OS last said, or why there is nothing."""
    if state["note"]:
        return [("note", state["note"])]
    return [(str(n), str(v)) for n, v in state["fields"]] or [("waiting", "asking the OS")]


def tui_lines(state):
    lines = ["", "  " + BLURB, ""]
    lines += [f"    {n:<14} {v}" for n, v in rows(state)]
    return lines + ["", "  r  refresh      Ctrl-C  back"]


def draw_graphical(app, state):
    c = Canvas().clear("#101820").rect(0, 0, app.width, 18, "#1f3a5f").text(6, 5, TITLE.upper(), "#ffffff")
    y = 28
    for n, v in rows(state):
        c.text(8, y, (n + "  " + v).upper()[:60], "#a0ffa0")
        y += 12
    c.text(6, app.height - 12, "R REFRESH  CTRL-C BACK", "#6080a0")
    app.present(c)


def main():
    app = App()
    state = {"fields": [], "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello" or cmd == "device" or (cmd == "key" and ev["key"] == "r"):
            app.request_status(TOPIC)
        elif cmd == "status" and ev.get("topic") == TOPIC:
            state["fields"], state["note"] = ev.get("fields", []), ""
        elif cmd == "result" and ev.get("action") == "status" and not ev.get("ok"):
            state["note"] = ev.get("detail", "refused")
        if cmd == "pointer":
            continue
        if app.mode == "graphical":
            draw_graphical(app, state)
        else:
            app.screen(TITLE, tui_lines(state), status="r: refresh")
