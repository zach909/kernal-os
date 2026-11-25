"""atlas.put - put anything you type into the map. A note, a thought, a line from somewhere, random words.

Type and press Enter. The OS gives the time (one password for the clock, because apps have none of their own),
the text is placed in the map by its words, and if the map already holds something nearly the same, ``atlas.digest``
folds the two into one that remembers it was seen twice. ``/name NAME`` before the text names it (``/name recipe
espresso: grind fine``). Typed text only; for a folder of files use ``atlas.files``."""

import atlas_core as core
from kos.sdk import App

SPACE = "atlas"


class Space:
    def __init__(self, app):
        self.app = app

    def keys(self):
        return self.app.vault_keys(space=SPACE)

    def get(self, key):
        return self.app.vault_get(key, space=SPACE)

    def put(self, key, value):
        return self.app.vault_put(key, value, space=SPACE)

    def delete(self, key):
        return self.app.vault_delete(key, space=SPACE)


def split_name(line):
    """``(name, text)``: ``/name NAME rest`` gives the name; otherwise the first words are the name."""
    line = line.strip()
    if line.startswith("/name "):
        parts = line[6:].split(None, 1)
        if len(parts) == 2:
            return parts[0][:40], parts[1]
        return "", ""
    return " ".join(line.split()[:4])[:40], line


def main():
    app = App()
    store = core.MarkStore(Space(app))
    text, note, saved = "", "Type anything and press Enter.", 0
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter" and text.strip():
                name, body = split_name(text)
                if not name:
                    note = "/name NAME some text"
                else:
                    r = app.service("clock.now")
                    if not r.get("ok"):
                        note = f"refused: {r.get('detail', 'no answer')}"
                    else:
                        try:
                            store.add([core.ingest(name, body, t=r["data"]["t"], space="mind", ref=name)])
                            saved += 1
                            note = f"saved ({saved} this time)"
                            text = ""
                        except OSError:
                            note = "the map could not be saved (is atlas.put allowed to write the folder?)"
            elif k == "backspace":
                text = text[:-1]
            elif len(k) == 1 and k.isprintable() and len(text) < 2000:
                text += k
        if ev["cmd"] != "pointer":
            shown = text[-(app.width - 6 if isinstance(app.width, int) and app.width > 20 else 70):]
            app.screen("Atlas: put", [f"> {shown}_", "", note], status="Enter saves   Esc leave")
