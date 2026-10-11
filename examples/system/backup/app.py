"""Backup. Keeps safety copies of your documents as zips that only KOS
writes (and scans). Backing up asks for your password; browsing a backup
never extracts it; restoring one file is a guarded write (administrator
keyboard, password, scan, optimize).

Keys: n new backup, g set YOUR GitHub repo, p push to it, enter browse / restore,
u up, r refresh, q back."""

import posixpath

from kos.sdk import App

HOME = "taskbar"


def main():
    app = App()
    st = {"mode": "list", "remote": "", "backups": [], "sel": 0, "zip": None, "path": "", "entries": [],
          "bsel": 0, "typing": None, "note": "", "open": []}

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    def submit():
        t, st["typing"] = st["typing"], None
        if not t["buf"]:
            return
        if t["kind"] == "remote":
            st["note"] = "setting your private GitHub repository - password in the OS prompt"
            app.request_remote(t["buf"])
        elif t["kind"] == "backup":
            st["note"] = "backing up - type your password in the OS prompt"
            app.request_backup(t["buf"])
        else:
            st["note"] = "restoring - the guarded write asks for your password"
            app.request_restore(st["zip"]["name"], t["member"], t["buf"])

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
            app.request_backups()
        elif cmd == "apps":
            st["open"] = ev["open"]
        elif cmd == "launch":
            kind = {"new": "backup", "remote": "remote"}.get(ev.get("command"))
            if kind:
                st["typing"] = {"kind": kind, "buf": ""}
        elif cmd == "backups":
            st["backups"] = ev["backups"]
            st["remote"] = ev.get("remote", "")
            st["sel"] = min(st["sel"], max(0, len(ev["backups"]) - 1))
        elif cmd == "listing":
            st.update(path=ev["path"], entries=ev["entries"], bsel=0)
        elif cmd == "text":
            st["note"] = " | ".join(l.strip() for l in ev["lines"][:2])
            app.request_backups()
        elif cmd == "result":
            st["note"] = ("" if ev.get("ok") else "NOT DONE: ") + ev.get("detail", "")
            if ev.get("ok"):
                app.request_backups()
        elif cmd == "key":
            k = ev["key"]
            t = st["typing"]
            if t is not None:
                if k == "enter":
                    submit()
                elif k == "escape":
                    st["typing"] = None
                elif k == "backspace":
                    t["buf"] = t["buf"][:-1]
                elif len(k) == 1:
                    t["buf"] += k
            elif st["mode"] == "list":
                n = len(st["backups"])
                if k == "up" and n:
                    st["sel"] = (st["sel"] - 1) % n
                elif k == "down" and n:
                    st["sel"] = (st["sel"] + 1) % n
                elif k == "n":
                    st["typing"] = {"kind": "backup", "buf": ""}
                elif k == "g":
                    st["typing"] = {"kind": "remote", "buf": ""}
                elif k == "enter" and n:
                    st.update(mode="browse", zip=st["backups"][st["sel"]])
                    app.request_ls(st["zip"]["path"])
                elif k == "p" and n:
                    st["note"] = "pushing to your private GitHub - password in the OS prompt"
                    app.request_push(st["backups"][st["sel"]]["name"])
                elif k == "r":
                    app.request_backups()
                elif k in ("q", "escape"):
                    back()
            else:
                n = len(st["entries"])
                if k == "up" and n:
                    st["bsel"] = (st["bsel"] - 1) % n
                elif k == "down" and n:
                    st["bsel"] = (st["bsel"] + 1) % n
                elif k == "enter" and n:
                    e = st["entries"][st["bsel"]]
                    target = posixpath.join(st["path"], e["name"])
                    if e["kind"] in ("dir", "zip"):
                        app.request_ls(target)
                    else:
                        member = posixpath.relpath(target, st["zip"]["path"])
                        st["typing"] = {"kind": "restore", "buf": "", "member": member}
                elif k in ("u", "backspace"):
                    if st["path"].rstrip("/") == st["zip"]["path"]:
                        st["mode"] = "list"
                    else:
                        app.request_ls(posixpath.dirname(st["path"].rstrip("/")))
                elif k in ("q", "escape"):
                    st["mode"] = "list"
        if cmd == "pointer":
            continue
        room = max(3, app.height - 8)
        t = st["typing"]
        if st["mode"] == "list":
            lines = ["", "  Backups (kept where only KOS writes them)",
                     "  Your private GitHub: " + (st["remote"] or "(not set - press g)"), ""]
            for i, b in enumerate(st["backups"][:room]):
                mark = ">" if i == st["sel"] else " "
                lines.append(f"  {mark} {b['name'][:44]:<44} {b['files']:>4} files {b['size'] // 1024:>6} KB")
            if not st["backups"]:
                lines.append("    (none yet - press n)")
            lines += ["", "  n new  p push  g set your GitHub repo  enter browse  r refresh  q back"]
        else:
            lines = ["", "  " + st["zip"]["name"] + "  (never extracted)", ""]
            first = max(0, min(st["bsel"] - room + 1, len(st["entries"]) - room)) if len(st["entries"]) > room else 0
            for i in range(first, min(len(st["entries"]), first + room)):
                e = st["entries"][i]
                mark = ">" if i == st["bsel"] else " "
                lines.append(f"  {mark} {e['name']}{'/' if e['kind'] != 'file' else ''}")
            lines += ["", "  enter: open folder / restore this file   u up   q list"]
        if t is not None:
            ask = {"backup": "  back up which file or folder? ",
                   "remote": "  your private GitHub repository (https://github.com/YOU/REPO)? ",
                   "restore": f"  restore {t.get('member', '')} to (full path)? "}[t["kind"]]
            lines += ["", ask + t["buf"] + "_"]
        if st["note"]:
            lines += ["", "  " + st["note"][:96]]
        app.screen("Backup", lines[:app.height - 2], status="documents are scanned when backed up")
