"""The App Builder. Makes a draft of a new app: a name, a one-line description and the screens it has.
It saves two items in the ``app-drafts`` shared folder it owns: ``NAME.manifest.json`` and ``NAME.app.py``.
It packs nothing and installs nothing: turning a draft into an app is the owner's `kos pack` and
`kos install` (a scan, then the password), so a draft never runs by itself and gets no permission.

Whole numbers only. The name rules copy kos/kapp.py (an app may not import it)."""

import json
import re

from kos.sdk import App

SPACE = "app-drafts"
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}\Z")
RESERVED = {"graphical", "text", "kos", "system", "all"}
MODES = ("tui", "graphical")
MAX_DESC = 200
FIELDS = ("name", "description", "modes")
STARTER = '''"""{title}. A starter: edit it, then `kos pack` and `kos install` it."""

from kos.sdk import App


def main():
    app = App()
    for ev in app.events():
        if ev["cmd"] == "hello" or ev["cmd"] == "key":
            app.screen({title!r}, ["", "  {title}", "", "  q: back"])
'''


def check_name(name):
    """'' if the name is a valid app name, else why not."""
    if not NAME_RE.match(name or ""):
        return "name: lowercase letters, digits and -, starting with a letter, at most 32"
    if name in RESERVED:
        return "name: reserved"
    return ""


def check_description(text):
    if not text or len(text) > MAX_DESC:
        return f"description: 1 to {MAX_DESC} characters"
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return "description: no control characters"
    return ""


def build(name, description, modes):
    """(error, manifest_text, code_text). Nothing is returned for a draft that is not valid."""
    err = check_name(name) or check_description(description)
    if not err and (not modes or any(m not in MODES for m in modes)):
        err = "screens: tui, graphical or both"
    if err:
        return err, "", ""
    manifest = {"name": name, "version": "1.0", "runtime": "python", "entry": "app:main",
                "modes": [m for m in MODES if m in modes], "permissions": [], "description": description}
    return "", json.dumps(manifest, indent=2) + "\n", STARTER.format(title=name)


def save(app, name, description, modes):
    err, manifest, code = build(name, description, modes)
    if err:
        return err
    if not (app.vault_put(f"{name}.manifest.json", manifest, space=SPACE)
            and app.vault_put(f"{name}.app.py", code, space=SPACE)):
        return "not saved: " + (getattr(app, "vault_error", "") or "refused")
    return f"saved draft {name}. Next: kos pack, then kos install (the OS asks your password)"


def lines(state):
    out = ["", "  App Builder", ""]
    for n, f in enumerate(FIELDS):
        v = state[f]
        v = ", ".join(v) if f == "modes" else v
        out.append(f"  {'>' if n == state['sel'] else ' '} {f:<12} {v}{'_' if n == state['sel'] and f != 'modes' else ''}")
    out += ["", "  up/down field   type to edit   space: toggle screens   enter: save draft   esc: back"]
    if state["note"]:
        out += ["", "  " + state["note"]]
    return out


def on_key(app, state, k):
    f = FIELDS[state["sel"]]
    if k == "up":
        state["sel"] = (state["sel"] - 1) % len(FIELDS)
    elif k == "down":
        state["sel"] = (state["sel"] + 1) % len(FIELDS)
    elif k == "enter":
        state["note"] = save(app, state["name"], state["description"], state["modes"])
    elif f == "modes":
        if k in (" ", "space"):
            state["modes"] = ["tui", "graphical"] if state["modes"] == ["tui"] else ["tui"]
    elif k == "backspace":
        state[f] = state[f][:-1]
    elif k in (" ", "space"):
        state[f] = (state[f] + " ")[:MAX_DESC]
    elif len(k) == 1 and k.isprintable():
        state[f] = (state[f] + k)[:MAX_DESC]


def main():
    app = App()
    state = {"sel": 0, "name": "", "description": "", "modes": ["tui"], "note": ""}
    for ev in app.events():
        if ev["cmd"] == "key":
            on_key(app, state, ev["key"])
        if ev["cmd"] in ("hello", "key"):
            app.screen("App Builder", lines(state), status="enter: save draft")
