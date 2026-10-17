"""Settings. Shows the kernel protections and which installed apps are
permitted to run; Enter on an app asks the OS to permit or revoke it (your
password, in the OS's own prompt). Keys: up/down, enter, r refresh, q back."""

from kos.sdk import App

HOME, SYSTEM = "taskbar", ("taskbar", "app-library")
TOP = 3


def main():
    app = App()
    st = {"info": None, "apps": [], "open": [], "sel": 0, "note": ""}

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    def toggle():
        if st["apps"]:
            a = st["apps"][st["sel"]]
            st["note"] = f"asking to {'revoke' if a['permitted'] else 'permit'} {a['name']}..."
            app.request_permit(a["name"], revoke=a["permitted"])

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_info()
            app.request_apps()
        elif cmd == "info":
            st["info"] = ev
        elif cmd == "apps":
            st["apps"] = [a for a in ev["installed"] if a["name"] not in SYSTEM]
            st["open"] = ev["open"]
            st["sel"] = min(st["sel"], max(0, len(st["apps"]) - 1))
        elif cmd == "result":
            st["note"] = ev.get("detail", "") if ev.get("ok") else "NOT DONE: " + ev.get("detail", "")
            if ev.get("ok"):
                app.request_apps()
        elif cmd == "key":
            k, n = ev["key"], len(st["apps"])
            if k == "up" and n:
                st["sel"] = (st["sel"] - 1) % n
            elif k == "down" and n:
                st["sel"] = (st["sel"] + 1) % n
            elif k == "enter":
                toggle()
            elif k == "r":
                app.request_info()
                app.request_apps()
            elif k in ("q", "escape"):
                back()
        if cmd == "pointer":
            continue
        info = st["info"] or {}
        lines = ["", "  Kernel protections"] + ["    " + l for l in info.get("kernel", [])]
        lines += ["", "  Apps - enter toggles permission to run"]
        for i, a in enumerate(st["apps"][:max(3, app.height - 14)]):
            mark = ">" if i == st["sel"] else " "
            lines.append(f"  {mark} {a['name']:<14} {'permitted' if a['permitted'] else 'NOT permitted'}")
        if not st["apps"]:
            lines.append("    (no other apps installed)")
        if st["note"]:
            lines += ["", "  " + st["note"]]
        app.screen("Settings", lines[:app.height - 2], status="enter: permit/revoke | r refresh | q back")
