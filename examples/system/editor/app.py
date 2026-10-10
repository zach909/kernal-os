"""Editor. Opens a file through the OS (your password), edits it here, and
saves by *asking* the OS for a guarded write: the administrator keyboard must
be booted, you type your password in the OS's own prompt, and the saved file
then owes a security scan and a disk optimize.

A file whose view would not round-trip exactly (tabs, CRLF, very long lines,
binary, too big) opens READ-ONLY - saving it back would damage it.

Keys: type to edit, arrows move, Ctrl-S save, Esc back (twice if unsaved)."""

from kos.sdk import App

HOME = "taskbar"
WIDTH = 96


def main():
    app = App()
    st = {"mode": "path", "pbuf": "", "path": "", "lines": [""], "cy": 0, "cx": 0, "top": 0,
          "dirty": False, "lossy": False, "note": "", "open": [], "confirm": False}

    def back():
        t = next((i for i in st["open"] if i["name"] == HOME and i["status"] == "running"), None)
        if t:
            app.request_focus(t["id"])

    def load(lines, path, lossy):
        st.update(mode="edit", lines=lines or [""], path=path, cy=0, cx=0, top=0, dirty=False,
                  lossy=lossy, confirm=False,
                  note="READ-ONLY: this file would not save back exactly" if lossy else "")

    def edit(k):
        ln, y, x = st["lines"], st["cy"], st["cx"]
        if k == "left":
            if x > 0:
                st["cx"] -= 1
            elif y > 0:
                st["cy"], st["cx"] = y - 1, len(ln[y - 1])
        elif k == "right":
            if x < len(ln[y]):
                st["cx"] += 1
            elif y < len(ln) - 1:
                st["cy"], st["cx"] = y + 1, 0
        elif k == "up" and y > 0:
            st["cy"] = y - 1
            st["cx"] = min(x, len(ln[y - 1]))
        elif k == "down" and y < len(ln) - 1:
            st["cy"] = y + 1
            st["cx"] = min(x, len(ln[y + 1]))
        elif k == "home":
            st["cx"] = 0
        elif k == "end":
            st["cx"] = len(ln[y])
        elif st["lossy"]:
            return
        elif k == "enter":
            ln[y:y + 1] = [ln[y][:x], ln[y][x:]]
            st["cy"], st["cx"], st["dirty"] = y + 1, 0, True
        elif k == "backspace":
            if x > 0:
                ln[y] = ln[y][:x - 1] + ln[y][x:]
                st["cx"] -= 1
            elif y > 0:
                st["cx"] = len(ln[y - 1])
                ln[y - 1:y + 1] = [ln[y - 1] + ln[y]]
                st["cy"] = y - 1
            st["dirty"] = True
        elif k == "delete":
            if x < len(ln[y]):
                ln[y] = ln[y][:x] + ln[y][x + 1:]
            elif y < len(ln) - 1:
                ln[y:y + 2] = [ln[y] + ln[y + 1]]
            st["dirty"] = True
        elif k == "tab" or (len(k) == 1 and k.isprintable()):
            ch = "    " if k == "tab" else k
            ln[y] = ln[y][:x] + ch + ln[y][x:]
            st["cx"] += len(ch)
            st["dirty"] = True

    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            app.request_apps()
        elif cmd == "apps":
            st["open"] = ev["open"]
        elif cmd == "text" and ev["action"] == "view":
            load(ev["lines"], ev["title"], bool(ev.get("lossy")))
        elif cmd == "text" and ev["action"] == "save":
            st.update(dirty=False, confirm=False, note="saved. " + " | ".join(l.strip() for l in ev["lines"][:3]))
        elif cmd == "result" and not ev.get("ok"):
            st["note"] = "NOT DONE: " + ev.get("detail", "")
        elif cmd == "key":
            k = ev["key"]
            if st["mode"] == "path":
                if k == "enter" and st["pbuf"]:
                    st["note"] = "opening - type your password in the OS prompt"
                    app.request_view(st["pbuf"])
                elif k == "ctrl-n" and st["pbuf"]:
                    load([""], st["pbuf"], False)
                    st["note"] = "new file"
                elif k == "backspace":
                    st["pbuf"] = st["pbuf"][:-1]
                elif k == "escape":
                    back()
                elif len(k) == 1:
                    st["pbuf"] += k
            elif k == "ctrl-s":
                if st["lossy"]:
                    st["note"] = "READ-ONLY: not saving"
                else:
                    st["note"] = "saving - type your password in the OS prompt"
                    app.request_save(st["path"], "\n".join(st["lines"]) + "\n")
            elif k == "escape":
                if st["dirty"] and not st["confirm"]:
                    st.update(confirm=True, note="unsaved changes - Esc again to leave without saving")
                else:
                    back()
            else:
                st["confirm"] = False
                edit(k)
        if cmd == "pointer":
            continue
        room = max(3, app.height - 5)
        if st["mode"] == "path":
            lines = ["", "  Open which file?  (Enter opens it, Ctrl-N starts a new file there)", "",
                     "  " + st["pbuf"] + "_"]
            if st["note"]:
                lines += ["", "  " + st["note"]]
            app.screen("Editor", lines, status="Esc: back")
            continue
        st["top"] = max(0, min(st["top"], st["cy"]), st["cy"] - room + 1)
        body = []
        for i in range(st["top"], min(len(st["lines"]), st["top"] + room)):
            ln = st["lines"][i]
            if i == st["cy"]:
                ln = ln[:st["cx"]] + "█" + ln[st["cx"]:]
            body.append(f"{i + 1:>4} {ln[:WIDTH]}")
        head = ["  " + st["path"][-80:] + ("   [modified]" if st["dirty"] else "")]
        foot = ["  " + st["note"]] if st["note"] else []
        app.screen("Editor", head + body + foot, status="Ctrl-S save | Esc back")
