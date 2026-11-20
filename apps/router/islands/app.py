"""router.islands - finds the islands in a network and says what turning some of them off would save.

Take a network's weights (whole numbers), turn each one into 0 or 1 (1 = the connection is kept), and
treat every unit as a dot and every 1 as a line between two dots in neighbouring layers. Dots that are
joined, directly or through others, are one **island**. An island shares no connection with any other,
so it can be switched off without touching the rest: the units that read from it just see nothing.

What this program does and does not do:
  * It finds islands and counts them. It runs no model and moves no weights.
  * A dense network has ONE island (every unit reaches every other), so there is nothing to turn off.
    Islands exist only in a network that was pruned or trained into separate blocks. This app says so
    when it finds one island, instead of pretending.
  * Weights must already be whole numbers (a quantised model). Decimals are refused, not rounded.

The network comes from the shared folder ``router`` (key ``net``) as JSON:
  {"threshold": T, "layers": [M1, M2, ...]}   Mi[r][c] is the weight from unit r of layer i to unit c of
  layer i+1, a whole number; a connection is kept when |weight| > T. Everything read is hostile: shape,
  sizes and types are checked before any of it is used.
Keys: d demo network   l load ``net``   1-9 islands to keep   p publish to router.plan   Esc leaves."""

import json
import re

from kos.sdk import App

SPACE = "router"
NET_KEY = "net"
OUT_KEY = "islands"
MAX_LAYERS = 16            # matrices, so up to 17 layers of units
MAX_UNITS = 256            # per layer
MAX_EDGES = 60000          # kept connections, after the threshold
MAX_WEIGHT = 10 ** 9
MAX_ISLANDS = 64           # published; more than this is reported but only the biggest are kept
MAX_NET_CHARS = 380000


class NetError(Exception):
    pass


def is_whole(x):
    return type(x) is int and -MAX_WEIGHT <= x <= MAX_WEIGHT


def parse_net(text):
    """(threshold, layers) from the shared folder's text, or NetError. Nothing in it is believed."""
    if not isinstance(text, str) or len(text) > MAX_NET_CHARS:
        raise NetError("the network is missing or too large")
    try:
        d = json.loads(text)
    except ValueError:
        raise NetError("the network is not valid JSON (decimals are not accepted either)")
    if not isinstance(d, dict) or set(d) != {"threshold", "layers"}:
        raise NetError('the network must be {"threshold": T, "layers": [...]}')
    t, layers = d["threshold"], d["layers"]
    if type(t) is not int or not 0 <= t <= MAX_WEIGHT:
        raise NetError("threshold must be a whole number, 0 or more")
    if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS:
        raise NetError(f"layers must be a list of 1 to {MAX_LAYERS} weight matrices")
    prev_cols = None
    for n, m in enumerate(layers, 1):
        if not isinstance(m, list) or not 1 <= len(m) <= MAX_UNITS:
            raise NetError(f"matrix {n}: 1 to {MAX_UNITS} rows")
        width = None
        for row in m:
            if not isinstance(row, list) or not 1 <= len(row) <= MAX_UNITS:
                raise NetError(f"matrix {n}: every row needs 1 to {MAX_UNITS} weights")
            if width is None:
                width = len(row)
            elif len(row) != width:
                raise NetError(f"matrix {n}: rows are not all the same length")
            if not all(is_whole(w) for w in row):
                raise NetError(f"matrix {n}: every weight must be a whole number (a quantised model)")
        if prev_cols is not None and len(m) != prev_cols:
            raise NetError(f"matrix {n} has {len(m)} rows but the layer before it has {prev_cols} units")
        prev_cols = width
    return t, layers


def binarize(layers, threshold):
    """Every weight to 0 or 1: 1 when its size is above the threshold."""
    return [[[1 if abs(w) > threshold else 0 for w in row] for row in m] for m in layers]


def find_islands(bits):
    """The islands of a network of 0/1 matrices.

    Returns (islands, dead). An island is a dict with its units, connections and how many of those units
    are in the first layer (what it reads) and the last (what it writes). ``dead`` counts units with no
    connection at all: they belong to no island and can always be skipped. Islands are ordered biggest
    first (most connections), ties by the lowest unit number, so the result never depends on luck."""
    sizes = [len(bits[0])] + [len(m[0]) for m in bits]
    starts, total = [], 0
    for s in sizes:
        starts.append(total)
        total += s
    parent = list(range(total))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    edges, touched = 0, [False] * total
    for li, m in enumerate(bits):
        for r, row in enumerate(m):
            for c, b in enumerate(row):
                if b:
                    edges += 1
                    if edges > MAX_EDGES:
                        raise NetError(f"more than {MAX_EDGES} kept connections; raise the threshold")
                    a, z = starts[li] + r, starts[li + 1] + c
                    touched[a] = touched[z] = True
                    ra, rz = find(a), find(z)
                    if ra != rz:
                        parent[max(ra, rz)] = min(ra, rz)
    groups = {}
    for node in range(total):
        if touched[node]:
            groups.setdefault(find(node), {"units": 0, "edges": 0, "inputs": 0, "outputs": 0, "low": node})["units"] += 1
    last = len(sizes) - 1
    for li in range(len(sizes)):
        for u in range(sizes[li]):
            node = starts[li] + u
            if touched[node]:
                g = groups[find(node)]
                if li == 0:
                    g["inputs"] += 1
                if li == last:
                    g["outputs"] += 1
    for li, m in enumerate(bits):
        for r, row in enumerate(m):
            for c, b in enumerate(row):
                if b:
                    groups[find(starts[li] + r)]["edges"] += 1
    ordered = sorted(groups.values(), key=lambda g: (-g["edges"], g["low"]))
    islands = [{"id": n, "units": g["units"], "edges": g["edges"], "inputs": g["inputs"], "outputs": g["outputs"]}
               for n, g in enumerate(ordered, 1)]
    return islands, total - sum(g["units"] for g in islands)


def keep_cost(islands, keep):
    """Percent of all kept connections that still run when only the ``keep`` biggest islands do."""
    whole = sum(i["edges"] for i in islands)
    if whole == 0:
        return 0
    return sum(i["edges"] for i in islands[:keep]) * 100 // whole


def demo_net():
    """Two separate blocks (units 0-4 and 5-6) across three layers of 8 units; unit 7 has no connection."""
    m = [[0] * 8 for _ in range(8)]
    for blk in (range(0, 5), range(5, 7)):
        for r in blk:
            for c in blk:
                m[r][c] = 3 + (r + c) % 5
    return json.dumps({"threshold": 2, "layers": [m, [row[:] for row in m]]})


def publish_text(islands):
    return json.dumps([{k: i[k] for k in ("id", "units", "edges", "inputs", "outputs")}
                       for i in islands[:MAX_ISLANDS]])


def lines(state, height):
    out = ["", "  Islands: parts of a network that share no connection", ""]
    if state["note"]:
        out += ["  " + state["note"], ""]
    isl = state["islands"]
    if isl is None:
        return out + ["  d  look at a built-in demo network", f"  l  load the network in the '{SPACE}' folder (key '{NET_KEY}')"]
    n = len(isl)
    keep = min(state["keep"], n) if n else 0
    if n == 1:
        out += ["  ONE island: every unit reaches every other, so nothing can be turned off.",
                "  Islands only exist after a network is pruned or trained into separate blocks.", ""]
    out.append(f"  {n} island(s), {state['dead']} unused unit(s) that belong to none")
    out.append("  id  units  connections  reads  writes   share  runs")
    whole = sum(i["edges"] for i in isl) or 1
    for i in isl[: max(3, height - 14)]:
        mark = "yes" if i["id"] <= keep else "off"
        out.append(f"  {i['id']:>2}  {i['units']:>5}  {i['edges']:>11}  {i['inputs']:>5}  {i['outputs']:>6}  {i['edges'] * 100 // whole:>5}%  {mark}")
    if n > 1:
        out += ["", f"  keeping {keep} of {n}: {keep_cost(isl, keep)}% of the connections still run",
                "  An island that is off gives zero to what reads from it. Which islands a given prompt needs",
                "  is NOT worked out here: the biggest run first."]
    return out


def main():
    app = App()
    state = {"islands": None, "dead": 0, "keep": 1, "note": ""}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "key":
            k = ev["key"]
            if k in ("escape", "q"):
                app.exit(0)
                return
            if k in ("d", "l"):
                try:
                    text = demo_net() if k == "d" else app.vault_get(NET_KEY, space=SPACE)
                    t, layers = parse_net(text)
                    state["islands"], state["dead"] = find_islands(binarize(layers, t))
                    state["keep"], state["note"] = len(state["islands"]), ""
                except NetError as e:
                    state["islands"], state["note"] = None, f"refused: {e}"
            elif len(k) == 1 and k in "123456789" and state["islands"]:
                state["keep"] = int(k)
            elif k == "p" and state["islands"]:
                ok = app.vault_put(OUT_KEY, publish_text(state["islands"]), space=SPACE)
                state["note"] = "published for router.plan" if ok else "could not publish (no write access)"
        if cmd != "pointer":
            app.screen("Islands", lines(state, app.height), status="d demo   l load   1-9 keep   p publish   Esc to leave")
