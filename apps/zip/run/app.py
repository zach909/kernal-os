"""zip.run - drop in a zip, it runs.

Type the path of a zip file and press Enter. The OS scans it, checks that it holds a program it can prove (no
decimals, no banned calls, compiles, no compiled code), then asks your password naming the program, the zip's
SHA-256 and what the program *asked* for, and runs it in the sandbox with none of that: no network, no files, no
devices, no OS functions. It can print and finish; anything else stops it. At most 30 seconds. Every line it prints
starts ``app| `` so it cannot pass for the OS. A program that needs more is installed the usual way (``kos install``),
where each grant has its own password."""

from kos.sdk import App


def show(r):
    """The lines for one answer from the OS."""
    if not r.get("ok"):
        return [f"refused: {r.get('detail', 'no answer')}"]
    d = r["data"]
    out = [f"{d['name']}   zip sha256 {d['sha256'][:16]}   asked for: {', '.join(d['asked']) or 'nothing'} (none granted)",
           f"finished with status {d['status']}", ""]
    return out + list(d["output"])


def main():
    app = App()
    text, lines = "", ["Type the path of a zip file and press Enter."]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter" and text.strip():
                app.screen("Run a zip", [f"> {text}", "", "checking and running..."], status="please wait")
                lines = show(app.service("zip.run", path=text.strip(), seconds=30))
                text = ""
            elif k == "backspace":
                text = text[:-1]
            elif len(k) == 1 and k.isprintable() and len(text) < 300:
                text += k
        if ev["cmd"] != "pointer":
            h = app.height if isinstance(app.height, int) and app.height > 8 else 24
            app.screen("Run a zip", [f"> {text}_", ""] + lines[:h - 6], status="Enter runs   Esc leave")
