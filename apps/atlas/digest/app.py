"""atlas.digest - make the map smaller and smarter. Press ``d``.

What it does, in whole numbers and nothing else:
  * old raw depth cells (an hour or more older than the newest mark) become surfaces and objects (floor-like,
    wall-like, horizontal, object) and the cells are forgotten; lone old specks seen once are dropped as noise;
  * movement that keeps coming back at the same place and time of day becomes a routine (times are UTC);
  * three or more sensors that agree make a source: where a smell, a sound or a heat is coming from;
  * files that talk about the same things become a theme; files many others point at become a hub;
    files that look the same become twins;
  * near-duplicate data is folded into one mark that keeps the count; nothing is lost but the repetition;
  * any quantity that keeps rising or falling, or jumps, becomes a trend.
It rewrites the ``atlas`` folder, so it asks nothing it can't do and keeps what people wrote down. It has no clock:
'now' is the newest time on the map. Run it as often as you like: doing it twice changes nothing."""

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


def digest(store):
    """Run the consolidation. Returns the lines to show."""
    st = store.stats()
    if not st["marks"]:
        return ["the map is empty: nothing to do"]
    now = st["last"] or 0
    rep = store.consolidate(now=now, keep_s=3600)
    saved = rep["before"] - rep["after"]
    out = [f"size {rep['before']} -> {rep['after']} characters" + (f" ({saved} saved)" if saved > 0 else ""),
           f"raw cells made into regions: {rep['voxels_digested']}   noise dropped: {rep['noise_dropped']}",
           f"duplicates folded: {rep['duplicates_merged']}", f"regions: {rep['regions']}"]
    for kind in ("routine", "source", "theme", "hub", "twin", "trend"):
        out.append(f"  {kind}: {rep[kind]}")
    return out


def main():
    app = App()
    store = core.MarkStore(Space(app))
    lines = ["Press d to digest the map."]
    for ev in app.events():
        if ev["cmd"] == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "d":
                try:
                    lines = digest(store)
                except OSError:
                    lines = ["the map could not be saved (is atlas.digest allowed to write the folder?)"]
        if ev["cmd"] != "pointer":
            app.screen("Atlas: digest", lines, status="d digest   Esc leave")
