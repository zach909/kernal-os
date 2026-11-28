"""atlas.files - map a folder. Every file and folder gets a place (a folder is a block, its files sit inside it, the
same tree always gives the same town), links (what contains what, what imports or links to what), and a fingerprint.
Any file works, text or not: text is placed by its words, anything else by its first 4 KiB, and copies of the same
thing end up in the same spot for ``atlas.digest`` to fold into one.

Type a folder path and press Enter. The OS asks your password once for the whole tree; it never follows a symlink,
reads at most 1000 entries 5 levels down, and never reads a file whose NAME looks like a secret (``.env``, ``*.pem``,
``id_rsa``, ``token``, ``password``...). That is a name pattern: a secret saved as ``notes.txt`` would be read."""

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


def build(data):
    """The marks for one walk: file and link marks for the layout, and a data mark per file that gave a head or a
    sample. Anything malformed in what the OS returned is skipped, not trusted."""
    entries, texts, extra = [], {}, []
    for e in data["entries"]:
        if not isinstance(e, dict) or not isinstance(e.get("path"), str) or type(e.get("size")) is not int:
            continue
        entries.append({"path": e["path"], "dir": bool(e.get("dir")), "size": e["size"]})
        if isinstance(e.get("head"), str):
            texts[e["path"]] = e["head"]
        if not e.get("dir"):
            raw = None
            if isinstance(e.get("head"), str):
                raw = e["head"].encode("utf-8")
            elif isinstance(e.get("sample"), str):
                try:
                    raw = bytes.fromhex(e["sample"])
                except ValueError:
                    raw = None
            if raw is not None:
                extra.append((e["path"], raw, e["size"]))
    t = data["t"]
    marks = core.file_marks(entries, t, space="files", texts=texts)
    for path, raw, size in extra:
        marks.append(core.ingest(path, raw, t=t, space="files-text", ref=path, size=size))
    return marks


def main():
    app = App()
    store = core.MarkStore(Space(app))
    text, lines = "", ["Type a folder path and press Enter (asks your password once for the whole tree)."]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter" and text.strip():
                app.screen("Atlas: files", [f"> {text}", "", "walking..."], status="please wait")
                r = app.service("files.walk", path=text.strip(), limit=1000, depth=5, heads=True)
                if not r.get("ok"):
                    lines = [f"refused: {r.get('detail', 'no answer')}"]
                else:
                    marks = build(r["data"])
                    try:
                        kept = store.add(marks)
                        n = len(r["data"]["entries"])
                        lines = [f"{n} entries mapped, {kept} marks saved"
                                 + ("   (stopped at the limit: map a smaller folder, or a deeper one on its own)"
                                    if r["data"].get("truncated") else ""),
                                 "Run atlas.digest to find themes, hubs and look-alike files."]
                    except OSError:
                        lines = ["the map could not be saved (is atlas.files allowed to write the folder?)"]
                text = ""
            elif k == "backspace":
                text = text[:-1]
            elif len(k) == 1 and k.isprintable() and len(text) < 300:
                text += k
        if ev["cmd"] != "pointer":
            app.screen("Atlas: files", [f"> {text}_", ""] + lines, status="Enter maps   Esc leave")
