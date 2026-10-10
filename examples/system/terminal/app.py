"""Terminal. The line shell as an app: every line you type is a command, in
your own language (and code is a command too - the OS runs it in a sandbox).
It sends each line to the OS with a `line` request and shows what comes back.
Commands that need the real terminal say so. Esc goes back; Ctrl-C leaves."""

from kos.sdk import App

HOME = "taskbar"


def main():
    app = App()
    st = {"log": ["Every line is a command. Type 'help'."], "buf": "", "hist": [], "h": 0, "open": []}

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
        elif cmd == "apps":
            st["open"] = ev["open"]
        elif cmd == "text":
            st["log"] += ["  " + l for l in ev["lines"]] or []
        elif cmd == "result" and not ev.get("ok"):
            st["log"].append("  NOT DONE: " + ev.get("detail", ""))
        elif cmd == "key":
            k = ev["key"]
            if k == "enter":
                line = st["buf"].strip()
                st["buf"] = ""
                if line:
                    st["log"].append("kos> " + line)
                    st["hist"].append(line)
                    st["h"] = len(st["hist"])
                    app.request_line(line)
            elif k == "backspace":
                st["buf"] = st["buf"][:-1]
            elif k == "up" and st["hist"]:
                st["h"] = max(0, st["h"] - 1)
                st["buf"] = st["hist"][st["h"]]
            elif k == "down" and st["hist"]:
                st["h"] = min(len(st["hist"]), st["h"] + 1)
                st["buf"] = st["hist"][st["h"]] if st["h"] < len(st["hist"]) else ""
            elif k == "escape":
                back()
            elif len(k) == 1:
                st["buf"] += k
        if cmd == "pointer":
            continue
        st["log"] = st["log"][-200:]
        room = max(3, app.height - 3)
        app.screen("Terminal", st["log"][-room:] + ["kos> " + st["buf"] + "_"],
                   status="enter run | up/down history | esc back")
