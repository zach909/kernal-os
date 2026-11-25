"""atlas.find - ask the map. Owns the ``atlas`` shared folder; it only reads it.

Type and press Enter. Plain words must all match (a mark's kind, label, name or unit). Commands start with ``/``:
``/kind K words``, ``/about THING`` (everything the map holds about one thing), ``/similar TEXT`` (data like this
text), ``/near X Y Z RADIUS [space]`` (millimetres), ``/recent``, ``/stats``. Up/down scroll, Esc leaves."""

import atlas_core as core
from kos.sdk import App

SPACE = "atlas"
HELP = [
    "Type and press Enter.",
    "  words             every word must match (kind, label, name, unit)",
    "  /kind K words     only marks of kind K (sight, smell, data, region, ...)",
    "  /about THING      everything the map holds about one thing",
    "  /similar TEXT     data like this text",
    "  /near X Y Z R     marks within R mm of a place (add a space name at the end)",
    "  /recent           the newest marks",
    "  /stats            what the map holds",
    "Up/down scroll. Esc leaves.",
]


class Space:
    """The shared folder, as the map's backend."""

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


def _ints(words, n):
    try:
        return [int(w) for w in words[:n]]
    except ValueError:
        return None


def answer(store, line):
    """The lines to show for what was typed."""
    line = line.strip()
    if not line or line == "/help":
        return list(HELP)
    if line == "/stats":
        st = store.stats()
        out = [f"{st['marks']} marks; {st['refused']} refused as not valid"]
        out += [f"  {k}: {n}" for k, n in sorted(st["kinds"].items())]
        out += [f"  space {k}: {n}" for k, n in sorted(st["spaces"].items())]
        return out
    if line == "/recent":
        return [core.describe(m) for m in store.search(limit=20)] or ["the map is empty"]
    if line.startswith("/about"):
        ref = line[6:].strip()
        if not ref:
            return ["/about THING"]
        card = store.about(ref)
        if not card:
            return [f"nothing about {ref!r}"]
        return [f"{k}: {d['marks']} marks, n={d['n']}, newest {d['latest']}{d['unit']} at t={d['t']} {d['label']}"
                for k, d in sorted(card.items())]
    if line.startswith("/similar"):
        text = line[8:].strip()
        got = store.similar(text, space="mind") + store.similar(text, space="files-text")
        got.sort(key=lambda m: (m["d"], -m["n"]))
        return [f"{m['d']:>2} bits  n={m['n']}  {m['l']}" for m in got[:20]] or ["nothing like that"]
    if line.startswith("/near"):
        parts = line[5:].split()
        nums = _ints(parts, 4)
        if nums is None or len(nums) < 4:
            return ["/near X Y Z RADIUS [space]   (whole millimetres)"]
        space = parts[4] if len(parts) > 4 else "world"
        hits = store.search(near=(nums[0], nums[1], nums[2]), radius=nums[3], space=space, limit=30)
        return [core.describe(m) + f" ({m['d']} mm away)" for m in hits] or ["nothing there"]
    kind = ""
    if line.startswith("/kind"):
        parts = line[5:].split(None, 1)
        kind = parts[0] if parts else ""
        line = parts[1] if len(parts) > 1 else ""
    elif line.startswith("/"):
        return HELP
    return [core.describe(m) for m in store.search(text=line, kind=kind, limit=40)] or ["nothing found"]


def main():
    app = App()
    store = core.MarkStore(Space(app))
    text, lines, top = "", list(HELP), 0
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter":
                lines, top = answer(store, text), 0
            elif k == "backspace":
                text = text[:-1]
            elif k == "up":
                top = max(0, top - 1)
            elif k == "down":
                top = min(max(0, len(lines) - 1), top + 1)
            elif len(k) == 1 and k.isprintable() and len(text) < 200:
                text += k
        if ev["cmd"] != "pointer":
            h = app.height if isinstance(app.height, int) and app.height > 8 else 24
            app.screen("Atlas: ask the map", [f"> {text}_", ""] + lines[top:top + h - 6],
                       status="Enter asks   up/down scroll   Esc leave")
