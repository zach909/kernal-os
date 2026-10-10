"""Security Center. Shows the administrator keyboard, the kernel protections,
what is still owed (a scan / an optimize after a write) and the recent audit
trail - all of it facts the OS tells this app. Settling and optimizing are
*requests*: the OS asks for your password in its own prompt.

Keys: s settle what is owed, o optimize, c scan a path, r refresh, q back."""

from kos.sdk import App

HOME = "taskbar"


def main():
    app = App()
    st = {"info": None, "open": [], "report": [], "title": "", "typing": None, "note": ""}

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
            app.request_info()
        elif cmd == "apps":
            st["open"] = ev["open"]
        elif cmd == "info":
            st["info"] = ev
        elif cmd == "text":
            st.update(report=ev["lines"], title=ev["title"], note="")
            if ev["action"] in ("settle", "optimize"):
                app.request_info()
        elif cmd == "result" and not ev.get("ok"):
            st["note"] = "NOT DONE: " + ev.get("detail", "")
        elif cmd == "key":
            k = ev["key"]
            if st["typing"] is not None:
                if k == "enter":
                    path, st["typing"] = st["typing"], None
                    if path:
                        app.request_scan(path)
                elif k == "escape":
                    st["typing"] = None
                elif k == "backspace":
                    st["typing"] = st["typing"][:-1]
                elif len(k) == 1:
                    st["typing"] += k
            elif k == "r":
                app.request_info()
            elif k == "s":
                st["note"] = "settling - type your password in the OS prompt"
                app.request_settle()
            elif k == "o":
                st["note"] = "optimizing - type your password in the OS prompt"
                app.request_optimize()
            elif k == "c":
                st["typing"] = ""
            elif k in ("q", "escape"):
                back()
        if cmd == "pointer":
            continue
        info = st["info"] or {}
        lines = ["", "  Administrator keyboard", "    " + info.get("admin", "(asking the OS...)"), "",
                 "  Kernel protections"] + ["    " + l for l in info.get("kernel", [])]
        lines += ["", "  Owed"] + ["    " + l for l in info.get("owed", [])]
        lines += ["", "  Recent decisions"] + ["    " + l for l in info.get("audit", [])[-6:]]
        if st["report"]:
            lines += ["", "  " + st["title"][:60]] + ["    " + l for l in st["report"][:8]]
        if st["typing"] is not None:
            lines += ["", "  scan which path? " + st["typing"] + "_"]
        if st["note"]:
            lines += ["", "  " + st["note"]]
        app.screen("Security Center", lines[:app.height - 2],
                   status="s settle | o optimize | c scan path | r refresh | q back")
