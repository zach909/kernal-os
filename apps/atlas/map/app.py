"""atlas.map - a top-down picture of one space of the map. Reads the ``atlas`` shared folder; changes nothing.

Arrows pan, ``+`` and ``-`` zoom, Tab picks the next space (world, files, mind, ...), ``k`` picks the next kind,
``f`` fits everything on the screen, Esc leaves. North (larger y) is up. Each mark is one character; where
several land on one, the one the map worked out (a surface, a source, a routine) wins over a raw reading."""

import atlas_core as core
from kos.sdk import App

SPACE = "atlas"
SYMBOL = {"sight": ".", "event": "!", "region": "#", "source": "*", "smell": "~", "sound": ")", "heat": "^",
          "light": "o", "humidity": "h", "pressure": "p", "file": "f", "data": "d", "routine": "R", "theme": "T",
          "hub": "H", "twin": "=", "trend": "/", "likes": "+", "note": "n"}
PRIORITY = {"region": 9, "source": 9, "routine": 8, "theme": 8, "hub": 8, "twin": 8, "trend": 8, "event": 7}


class Space:
    def __init__(self, app):
        self.app = app

    def keys(self):
        return self.app.vault_keys(space=SPACE)

    def get(self, key):
        return self.app.vault_get(key, space=SPACE)

    def put(self, key, value):
        return False                      # this app only looks

    def delete(self, key):
        return False


def fit(marks, space, width, height):
    """``(cx, cy, scale)`` that puts every placed mark of ``space`` on a ``width`` x ``height`` screen."""
    pts = [m["p"] for m in marks if m["p"] is not None and m["s"] == space]
    if not pts:
        return 0, 0, 100
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    cx, cy = (min(xs) + max(xs)) // 2, (min(ys) + max(ys)) // 2
    need = max((max(xs) - min(xs)) // max(1, width - 2), (max(ys) - min(ys)) // max(1, height - 2)) + 1
    return cx, cy, max(10, need)


def render(marks, space, cx, cy, scale, width, height, kind=""):
    """The rows of characters for this view. The middle of the screen is ``(cx, cy)``; one cell is ``scale`` mm."""
    grid = {}
    for m in marks:
        if m["p"] is None or m["s"] != space or (kind and m["k"] != kind):
            continue
        gx = (m["p"][0] - cx) // scale + width // 2
        gy = height // 2 - (m["p"][1] - cy) // scale
        if 0 <= gx < width and 0 <= gy < height:
            pr = PRIORITY.get(m["k"], 1)
            cur = grid.get((gx, gy))
            if cur is None or pr > cur[0]:
                grid[(gx, gy)] = (pr, SYMBOL.get(m["k"], "o"))
    mid = (width // 2, height // 2)
    rows = []
    for y in range(height):
        rows.append("".join(grid[(x, y)][1] if (x, y) in grid else ("+" if (x, y) == mid else " ") for x in range(width)))
    return rows


def main():
    app = App()
    store = core.MarkStore(Space(app))
    marks = store.all_marks(limit=8000)
    spaces = sorted({m["s"] for m in marks if m["p"] is not None}) or ["world"]
    kinds = [""] + sorted({m["k"] for m in marks if m["p"] is not None})
    si = ki = 0
    w = app.width if isinstance(app.width, int) and app.width > 20 else 80
    h = app.height if isinstance(app.height, int) and app.height > 10 else 24
    cx, cy, scale = fit(marks, spaces[si], w - 2, h - 6)
    for ev in app.events():
        w = app.width if isinstance(app.width, int) and app.width > 20 else 80
        h = app.height if isinstance(app.height, int) and app.height > 10 else 24
        if ev["cmd"] == "key":
            k = ev["key"]
            step = scale * 5
            if k == "escape":
                app.exit(0)
                return
            elif k == "left":
                cx -= step
            elif k == "right":
                cx += step
            elif k == "up":
                cy += step
            elif k == "down":
                cy -= step
            elif k == "+":
                scale = max(10, scale // 2)
            elif k == "-":
                scale = min(100_000_000, scale * 2)
            elif k == "tab":
                si = (si + 1) % len(spaces)
                cx, cy, scale = fit(marks, spaces[si], w - 2, h - 6)
            elif k == "k":
                ki = (ki + 1) % len(kinds)
            elif k == "f":
                cx, cy, scale = fit(marks, spaces[si], w - 2, h - 6)
        if ev["cmd"] != "pointer":
            rows = render(marks, spaces[si], cx, cy, scale, w - 2, h - 6, kinds[ki])
            head = f"space {spaces[si]}   kind {kinds[ki] or 'all'}   1 cell = {scale} mm   centre {cx},{cy}"
            app.screen("Atlas: map", [head] + rows,
                       status="arrows pan  +/- zoom  Tab space  k kind  f fit  Esc leave")
