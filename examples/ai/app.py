"""The AI app: a small chat. Type a question, press Enter.

It has no network and no files. It asks the OS (`ask`), which asks for your password in its own
prompt, says which host receives the text and how much, sends it to the AI you set up with
`kos ai set`, and hands back text. The answer can only be read; nothing in it is run or opened.
Esc quits.
"""

from kos.sdk import App

NOTICE = "Each question needs your password and is sent to the host the prompt names."


def wrap(text, width):
    out = []
    for raw in text.split("\n"):
        while len(raw) > width:
            out.append(raw[:width]); raw = raw[width:]
        out.append(raw)
    return out


def main():
    app = App()
    chat, typed, msg = [], "", ""
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter" and typed.strip():
                q, typed = typed.strip(), ""
                chat.append("you: " + q)
                answer = app.ask(q)
                chat += ["ai: " + answer[0], *["    " + l for l in answer[1:]]] if answer else []
                msg = "" if answer else f"no answer: {app.ai_error}"
            elif k == "backspace":
                typed = typed[:-1]
            elif len(k) == 1:
                typed += k
        width, rows = max(20, app.width - 4), max(5, app.height - 6)
        shown = [l for c in chat for l in wrap(c, width)][-rows:]
        app.screen("ai", ["", *["  " + l for l in shown], "", f"  ! {NOTICE}", f"  > {typed}_", f"  {msg}"],
                   status="type + Enter: ask | Esc: quit")
