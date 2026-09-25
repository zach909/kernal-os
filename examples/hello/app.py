"""Demo app. It never touches a device: it only reacts to the commands the OS
sends it (key, pointer, button) and answers with commands (screen, frame)."""

from kos.sdk import App, Canvas


def main():
    app = App()
    typed, clicks, dots, history = "", 0, [], []
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key":
            k = ev["key"]
            if k == "backspace":
                typed = typed[:-1]
            elif k == "escape":
                app.exit(0)
                return
            elif len(k) == 1:
                typed += k
        elif cmd == "button" and ev["pressed"]:
            clicks += 1
            if app.mode == "graphical" and ev["y"] > 40:
                dots.append((ev["x"], ev["y"]))
        if cmd != "pointer":
            history = (history + [f"{cmd}: {ev}"])[-8:]

        if app.mode == "tui":
            app.screen("Hello", [
                "",
                "  Welcome to KOS. This page is text, drawn by the OS from my commands.",
                "",
                f"  Devices booted for me : {', '.join(sorted(app.devices)) or 'none yet'}",
                f"  You typed             : {typed}",
                f"  Mouse clicks          : {clicks}",
                "",
                "  Commands the OS sent me:",
                *("    " + h for h in history),
            ], status="Esc to exit")
        else:
            w, h = app.width, app.height
            c = Canvas().clear("#102030")
            c.rect(0, 0, w, 14, "#2050a0").text(3, 4, "HELLO KOS", "#ffffff")
            c.text(3, 20, f"CLICKS {clicks}", "#ffcc00")
            c.text(3, 30, "TYPED " + typed[-(w // 6 - 7):], "#a0ffa0")
            c.rect(0, 40, w, 1, "#406080")
            for x, y in dots[-500:]:
                c.rect(x - 1, y - 1, 3, 3, "#ff5080")
            app.present(c)
