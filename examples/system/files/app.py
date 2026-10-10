"""Files. Browses real folders and zips (never extracted) by *asking* the OS to
list them. Viewing a file asks for your password in the OS's own prompt.

Keys: up/down select, enter open/view, u up a folder, s scan, q back."""

import posixpath

from kos.sdk import App

HOME = "taskbar"
TOP = 3


def main():
    app = App()
    st = {"path": "/", "entries": [], "sel": 0, "open": [], "note": "", "view": None, "vtitle": "", "vpos": 0}

    def go(path):
        app.request_ls(path)

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    def activate():
        if not st["entries"]:
            return
        e = st["entries"][st["sel"]]
        target = posixpath.join(st["path"], e["name"])
        if e["kind"] in ("dir", "zip"):
            go(target)
        else:
            app.request_view(target)

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
            go(st["path"])
        elif cmd == "apps":
            st["open"] = ev["open"]
        elif cmd == "listing":
            st.update(path=ev["path"], entries=ev["entries"], sel=0, note="")
        elif cmd == "text":
            st.update(view=ev["lines"] or ["(empty)"], vtitle=ev["title"], vpos=0)
        elif cmd == "result" and not ev.get("ok"):
            st["note"] = ev.get("detail", "")
        elif cmd == "key":
            k, n = ev["key"], len(st["entries"])
            if st["view"] is not None:
                if k == "down":
                    st["vpos"] = min(st["vpos"] + 1, max(0, len(st["view"]) - 1))
                elif k == "up":
                    st["vpos"] = max(0, st["vpos"] - 1)
                elif k in ("q", "escape", "enter"):
                    st["view"] = None
            elif k == "up" and n:
                st["sel"] = (st["sel"] - 1) % n
            elif k == "down" and n:
                st["sel"] = (st["sel"] + 1) % n
            elif k == "enter":
                activate()
            elif k in ("u", "backspace"):
                go(posixpath.dirname(st["path"].rstrip("/")) or "/")
            elif k == "s" and n:
                app.request_scan(posixpath.join(st["path"], st["entries"][st["sel"]]["name"]))
            elif k in ("q", "escape"):
                back()
        elif cmd == "button" and ev["pressed"] and ev["button"] == "left" and st["view"] is None:
            row = ev["y"] - TOP
            if 0 <= row < len(st["entries"]):
                if row == st["sel"]:
                    activate()
                st["sel"] = row
        if cmd == "pointer":
            continue
        room = max(3, app.height - 6)
        if st["view"] is not None:
            lines = ["", "  " + st["vtitle"][:70], ""] + ["  " + l for l in st["view"][st["vpos"]:st["vpos"] + room]]
            app.screen("Files - viewing", lines, status="up/down scroll | q close")
            continue
        first = max(0, min(st["sel"] - room + 1, len(st["entries"]) - room)) if len(st["entries"]) > room else 0
        lines = ["", "  " + st["path"], ""]
        for i in range(first, min(len(st["entries"]), first + room)):
            e = st["entries"][i]
            mark = ">" if i == st["sel"] else " "
            tag = "/" if e["kind"] == "dir" else (" (zip)" if e["kind"] == "zip" else "")
            lines.append(f"  {mark} {e['name']}{tag}")
        if not st["entries"]:
            lines.append("    (empty)")
        lines += ["", "  enter open/view   u up   s scan   q back"]
        if st["note"]:
            lines += ["", "  " + st["note"]]
        app.screen("Files", lines, status="viewing a file asks for your password")
