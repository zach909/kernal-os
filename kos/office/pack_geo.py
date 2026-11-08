"""pack_geo: Map Tools, Route Planner, Places. See docs/PACKS.md.

Everything works on coordinates the user types. There are no map tiles, no GPS, no live traffic, no
imagery, no business listings and no directions. The Earth is a sphere of mean radius 6371.0088 km, so
distances are within about 0.5% of the true (ellipsoidal) value. Pure standard library, nothing runs
in the background, every input and every stored list is bounded."""

from __future__ import annotations

import json
import math
import re

from kos.sdk import Canvas

from .packkit import app, shared_items
from .records import Field, RecordList, Data, validate
from .specs import R
from .ui import (SpaceHost, Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextView, now_stamp,
                 table, today)

RADIUS_KM = 6371.0088
KM_PER_MI = 1.609344
KM_PER_NMI = 1.852
MAX_TEXT = 100_000          # bytes of any pasted block (GeoJSON, point lists)
MAX_POINTS = 500            # points in a polygon / plot
MAX_NODES = 5_000           # GeoJSON objects visited
MAX_WAYPOINTS = 40
MAX_PLACES = 500
MAX_VISITS = 2_000


class GeoError(ValueError):
    """A user-facing complaint about input."""


# ------------------------------------------------------------ coordinates ----
def _clean(s) -> str:
    if not isinstance(s, str) or not s.strip():
        raise GeoError("type a coordinate")
    if len(s) > 200:
        raise GeoError("too long")
    if any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise GeoError("control characters are not allowed")
    for ch in "°º˚′’'″”\"":
        s = s.replace(ch, " ")
    return s.replace("−", "-")


def _one(tok: str) -> tuple:
    """One half of a coordinate -> (signed degrees, hemisphere letter or '')."""
    t = tok.upper()
    letters = [c for c in t if c.isalpha()]
    if len(letters) > 1 or (letters and letters[0] not in "NSEW"):
        raise GeoError(f"cannot read '{tok.strip()[:20]}'")
    ts = t.strip()
    if letters and not (ts[0].isalpha() or ts[-1].isalpha()):
        raise GeoError(f"cannot read '{tok.strip()[:20]}'")
    body = "".join(c for c in t if not c.isalpha()).strip()
    if body.count("-") > 1 or ("-" in body and not body.startswith("-")) or body.count("+") > 1 or ("+" in body and not body.startswith("+")):
        raise GeoError("misplaced sign")
    neg = body.startswith("-")
    nums = re.findall(r"\d+(?:\.\d+)?|\.\d+", body)
    if not nums or len(nums) > 3 or re.sub(r"[\d.\s+-]", "", body):
        raise GeoError(f"cannot read '{tok.strip()[:20]}'")
    if len(nums) > 1 and not all(n.isdigit() for n in nums[:-1]):
        raise GeoError("only the last of degrees/minutes/seconds may have decimals")
    parts = [float(n) for n in nums]
    if any(p >= 60 for p in parts[1:]):
        raise GeoError("minutes and seconds must be below 60")
    v = parts[0] + (parts[1] / 60 if len(parts) > 1 else 0) + (parts[2] / 3600 if len(parts) > 2 else 0)
    letter = letters[0] if letters else ""
    if letter and neg:
        raise GeoError("use either a minus sign or N/S/E/W, not both")
    return (-v if neg or letter in ("S", "W") else v), letter


def parse_coord(s) -> tuple:
    """'40.7128, -74.0060' | '40.7128N 74.0060W' | '40 42 46.1 N, 74 0 21.6 W' | 'N 40 42 46 W 74 0 21'
    -> (lat, lon) in decimal degrees. Raises GeoError."""
    t = _clean(s).replace(";", ",")
    if "," in t:
        parts = t.split(",")
    else:
        idx = [i for i, c in enumerate(t.upper()) if c in "NSEW"]
        if len(idx) == 2:
            first_digit = next((i for i, c in enumerate(t) if c.isdigit() or c == "."), len(t))
            cut = idx[1] if idx[0] < first_digit else idx[0] + 1
            parts = [t[:cut], t[cut:]]
        elif not idx and len(t.split()) == 2:
            parts = t.split()
        else:
            raise GeoError("separate latitude and longitude with a comma")
    if len(parts) != 2:
        raise GeoError("need exactly two numbers: latitude, longitude")
    (a, la), (b, lb) = _one(parts[0]), _one(parts[1])
    if la in ("E", "W") or lb in ("N", "S"):
        a, la, b, lb = b, lb, a, la
    if la not in ("", "N", "S") or lb not in ("", "E", "W"):
        raise GeoError("one value must be latitude (N/S), the other longitude (E/W)")
    if abs(a) > 90:
        raise GeoError("latitude must be between -90 and 90")
    if abs(b) > 180:
        raise GeoError("longitude must be between -180 and 180")
    return a, b


def fmt_dd(p) -> str:
    return f"{p[0]:.6f}, {p[1]:.6f}"


def fmt_hem(p) -> str:
    return f"{abs(p[0]):.6f} {'N' if p[0] >= 0 else 'S'}, {abs(p[1]):.6f} {'E' if p[1] >= 0 else 'W'}"


def _dms(v: float, pos: str, neg: str) -> str:
    h = round(abs(v) * 360000)          # hundredths of an arc second
    return f"{h // 360000}° {h // 6000 % 60}' {h % 6000 / 100:.2f}\" {pos if v >= 0 else neg}"


def fmt_dms(p) -> str:
    return _dms(p[0], "N", "S") + ", " + _dms(p[1], "E", "W")


# --------------------------------------------------------------- geometry ----
def haversine(a, b) -> float:
    """Great-circle distance in km."""
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[1] - a[1]) / 2) ** 2
    return 2 * RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def bearing(a, b) -> float:
    """Initial bearing from a to b, degrees clockwise from north [0, 360)."""
    p1, p2, dl = math.radians(a[0]), math.radians(b[0]), math.radians(b[1] - a[1])
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def midpoint(a, b) -> tuple:
    p1, p2, l1, dl = math.radians(a[0]), math.radians(b[0]), math.radians(a[1]), math.radians(b[1] - a[1])
    bx, by = math.cos(p2) * math.cos(dl), math.cos(p2) * math.sin(dl)
    pm = math.atan2(math.sin(p1) + math.sin(p2), math.hypot(math.cos(p1) + bx, by))
    lm = l1 + math.atan2(by, math.cos(p1) + bx)
    return math.degrees(pm), (math.degrees(lm) + 540) % 360 - 180


def destination(a, brg: float, km: float) -> tuple:
    p1, l1, th, d = math.radians(a[0]), math.radians(a[1]), math.radians(brg), km / RADIUS_KM
    p2 = math.asin(max(-1.0, min(1.0, math.sin(p1) * math.cos(d) + math.cos(p1) * math.sin(d) * math.cos(th))))
    l2 = l1 + math.atan2(math.sin(th) * math.sin(d) * math.cos(p1), math.cos(d) - math.sin(p1) * math.sin(p2))
    return math.degrees(p2), (math.degrees(l2) + 540) % 360 - 180


def compass(deg: float) -> str:
    names = "N NNE NE ENE E ESE SE SSE S SSW SW WSW W WNW NW NNW".split()
    return names[int((deg % 360) / 22.5 + 0.5) % 16]


def bbox(pts) -> tuple:
    """(south, west, north, east). Does not handle boxes that cross the 180th meridian."""
    return min(p[0] for p in pts), min(p[1] for p in pts), max(p[0] for p in pts), max(p[1] for p in pts)


def _vec(p) -> tuple:
    la, lo = math.radians(p[0]), math.radians(p[1])
    return math.cos(la) * math.cos(lo), math.cos(la) * math.sin(lo), math.sin(la)


def _dot(u, v): return u[0] * v[0] + u[1] * v[1] + u[2] * v[2]
def _cross(u, v): return (u[1] * v[2] - u[2] * v[1], u[2] * v[0] - u[0] * v[2], u[0] * v[1] - u[1] * v[0])


def sphere_area_km2(pts) -> float:
    """Area of a polygon whose edges are great-circle arcs: fan of spherical triangles
    (Van Oosterom-Strackee signed excess). The smaller of the two regions the ring bounds."""
    pts = list(pts)
    if len(pts) > 1 and pts[0] == pts[-1]:
        pts.pop()
    if len(pts) < 3:
        return 0.0
    v = [_vec(p) for p in pts]
    tot = 0.0
    for b, c in zip(v[1:], v[2:]):
        tot += 2 * math.atan2(_dot(v[0], _cross(b, c)), 1 + _dot(v[0], b) + _dot(b, c) + _dot(c, v[0]))
    a = abs(tot) % (4 * math.pi)
    return min(a, 4 * math.pi - a) * RADIUS_KM ** 2


def path_km(pts, closed=False) -> float:
    pts = list(pts)
    t = sum(haversine(a, b) for a, b in zip(pts, pts[1:]))
    return t + (haversine(pts[-1], pts[0]) if closed and len(pts) > 2 else 0.0)


# ---------------------------------------------------------------- geojson ----
_DEPTH = {"Point": 0, "MultiPoint": 1, "LineString": 1, "MultiLineString": 2, "Polygon": 2, "MultiPolygon": 3}


def _walk(c, d: int, counter: list):
    if d == 0:
        if (not isinstance(c, list) or not 2 <= len(c) <= 3
                or any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) for x in c)):
            raise GeoError("a position must be [longitude, latitude] (numbers)")
        if abs(c[0]) > 180 or abs(c[1]) > 90:
            raise GeoError("position out of range (longitude +-180, latitude +-90)")
        counter[0] += 1
        if counter[0] > MAX_POINTS * 20:
            raise GeoError("too many positions")
        return (float(c[1]), float(c[0]))
    if not isinstance(c, list):
        raise GeoError("coordinates must be arrays")
    return [_walk(x, d - 1, counter) for x in c]


def _geometry(g, info: dict) -> None:
    t = g.get("type")
    if t not in _DEPTH:
        raise GeoError(f"unknown geometry type {str(t)[:20]!r}")
    cs = _walk(g.get("coordinates"), _DEPTH[t], info["n"])
    info["types"][t] = info["types"].get(t, 0) + 1
    lines, rings = [], []
    if t == "Point": info["shapes"].append(("point", [cs]))
    elif t == "MultiPoint": info["shapes"] += [("point", [p]) for p in cs]
    elif t == "LineString": lines = [cs]
    elif t == "MultiLineString": lines = cs
    elif t == "Polygon": rings = [cs]
    else: rings = cs
    for ln in lines:
        if len(ln) < 2:
            raise GeoError("a LineString needs at least 2 positions")
        info["length"] += path_km(ln)
        info["shapes"].append(("line", ln))
    for poly in rings:
        if not poly:
            raise GeoError("a Polygon needs at least one ring")
        for r in poly:
            if len(r) < 4 or r[0] != r[-1]:
                raise GeoError("a polygon ring needs 4+ positions and must be closed (first = last)")
        info["area"] += sphere_area_km2(poly[0]) - sum(sphere_area_km2(h) for h in poly[1:])
        info["shapes"].append(("poly", poly[0]))
    info["pts"] += [p for s in info["shapes"][-max(1, len(lines) + len(rings)):] for p in s[1]][:MAX_POINTS * 20]


def geojson_check(text) -> dict:
    """Safe parse + validate. Never raises for bad content: returns {'errors': [...], ...}."""
    info = {"errors": [], "types": {}, "shapes": [], "pts": [], "length": 0.0, "area": 0.0, "n": [0], "nodes": 0}
    if not isinstance(text, str) or not text.strip():
        info["errors"].append("empty")
        return info
    if len(text) > MAX_TEXT:
        info["errors"].append(f"too large ({len(text)} characters; the limit is {MAX_TEXT})")
        return info
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as e:
        info["errors"].append(f"not valid JSON: {str(e)[:80]}")
        return info
    stack = [(doc, "$", 0)]
    while stack and len(info["errors"]) < 10:
        o, path, depth = stack.pop()
        info["nodes"] += 1
        if info["nodes"] > MAX_NODES or depth > 8:
            info["errors"].append("too many or too deeply nested objects"); break
        if not isinstance(o, dict):
            info["errors"].append(f"{path}: expected an object"); continue
        t = o.get("type")
        try:
            if t == "FeatureCollection":
                fs = o.get("features")
                if not isinstance(fs, list): raise GeoError("features must be an array")
                info["types"][t] = info["types"].get(t, 0) + 1
                stack += [(f, f"{path}.features[{i}]", depth + 1) for i, f in reversed(list(enumerate(fs[:MAX_NODES])))]
            elif t == "Feature":
                info["types"][t] = info["types"].get(t, 0) + 1
                if o.get("geometry") is not None: stack.append((o["geometry"], path + ".geometry", depth + 1))
            elif t == "GeometryCollection":
                gs = o.get("geometries")
                if not isinstance(gs, list): raise GeoError("geometries must be an array")
                info["types"][t] = info["types"].get(t, 0) + 1
                stack += [(g, f"{path}.geometries[{i}]", depth + 1) for i, g in reversed(list(enumerate(gs[:MAX_NODES])))]
            else:
                _geometry(o, info)
        except GeoError as e:
            info["errors"].append(f"{path}: {e}")
    if not info["errors"] and not info["types"]:
        info["errors"].append("nothing found")
    return info


def geojson_report(text) -> list:
    r = geojson_check(text)
    if r["errors"]:
        return ["INVALID", *("  " + e for e in r["errors"])]
    out = ["VALID GeoJSON (structure and coordinate ranges checked; no schema beyond RFC 7946 shapes)", ""]
    out += [f"  {k:<18} {v}" for k, v in sorted(r["types"].items())]
    out += ["", f"  positions: {r['n'][0]}"]
    if r["pts"]:
        s, w, n, e = bbox(r["pts"])
        out.append(f"  bounding box (S,W,N,E): {s:.5f}, {w:.5f}, {n:.5f}, {e:.5f}")
    if r["length"]: out.append(f"  total line length: {r['length']:.3f} km")
    if r["area"]: out.append(f"  total polygon area: {r['area']:.3f} km2")
    return out


# ------------------------------------------------------------------- plot ----
def parse_plot(text) -> list:
    """Lines: 'lat, lon [| label]', 'line c | c | c', 'poly c | c | c'. -> [(kind, [(lat, lon)...], label)]"""
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise GeoError("nothing to plot, or too large")
    shapes, total = [], 0
    for n, line in enumerate(text.split("\n")[:1000], 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            word = line.split(None, 1)[0].lower()
            if word in ("line", "poly"):
                pts = [parse_coord(c) for c in line.split(None, 1)[1].split("|")] if " " in line else []
                if len(pts) < (2 if word == "line" else 3):
                    raise GeoError(f"{word} needs {2 if word == 'line' else 3}+ coordinates separated by |")
                shapes.append((word, pts, ""))
            else:
                c, _s, label = line.partition("|")
                pts = [parse_coord(c)]
                shapes.append(("point", pts, label.strip()[:20]))
            total += len(pts)
        except GeoError as e:
            raise GeoError(f"line {n}: {e}")
        if total > MAX_POINTS:
            raise GeoError(f"more than {MAX_POINTS} points")
    if not shapes:
        raise GeoError("no coordinates")
    return shapes


def project(shapes, w: int, h: int, margin: int = 10) -> list:
    """Equirectangular (plate carree, x scaled by cos of the middle latitude so shapes are not stretched).
    -> [(kind, [(x, y)...], label)] in pixels, centred in w x h."""
    pts = [p for s in shapes for p in s[1]]
    s, wst, n, e = bbox(pts)
    kx = max(0.05, math.cos(math.radians((s + n) / 2)))
    dx, dy = (e - wst) * kx, n - s
    aw, ah = max(1, w - 2 * margin), max(1, h - 2 * margin - 12)
    sc = min(aw / dx if dx else 1e9, ah / dy if dy else 1e9)
    if sc >= 1e9:
        sc = 1.0
    ox, oy = margin + (aw - dx * sc) / 2, margin + 12 + (ah - dy * sc) / 2

    def px(p): return (round(ox + (p[1] - wst) * kx * sc), round(oy + (n - p[0]) * sc))
    return [(k, [px(p) for p in ps], lab) for k, ps, lab in shapes]


class PlotScreen(Screen):
    def __init__(self, shapes, title="Plot"):
        self.title, self.shapes = title, shapes
        self.help = "Esc back"

    def canvas(self, w, h):
        c = Canvas().clear("#f4f4f0")
        for kind, ps, lab in project(self.shapes, w, h):
            if kind in ("line", "poly"):
                seq = ps + ([ps[0]] if kind == "poly" else [])
                for a, b in zip(seq, seq[1:]):
                    c.line(*a, *b, "#0070d2" if kind == "poly" else "#417505")
            else:
                x, y = ps[0]
                c.rect(x - 2, y - 2, 5, 5, "#d0021b")
                if lab: c.text(x + 5, y - 3, lab, "#111111")
        pts = [p for s in self.shapes for p in s[1]]
        sw, wst, n, e = bbox(pts)
        c.rect(0, 0, w, 12, "#222222").text(3, 2, f"{len(self.shapes)} shapes  lat {sw:.3f}..{n:.3f}  lon {wst:.3f}..{e:.3f}  (not a map)", "#ffffff")
        return c

    def render(self, w, h):
        gw, gh = max(10, w - 2), max(4, h - 3)
        grid = [[" "] * gw for _ in range(gh)]
        for kind, ps, _lab in project(self.shapes, gw, gh, margin=0):
            for x, y in ps:
                if 0 <= x < gw and 0 <= y < gh:
                    grid[y][x] = "o" if kind == "point" else "+"
        return ["  " + "".join(r) for r in grid] + [f"  {len(self.shapes)} shape(s). Plain sketch of typed coordinates, no map. Graphical mode draws lines."]

    def key(self, k):
        if k in ("escape", "q", "enter"): return ("pop", None)


# ------------------------------------------------------------- Map Tools ----
def _coords_lines(text) -> list:
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise GeoError("input too large")
    out = []
    for n, line in enumerate(text.split("\n")[:2000], 1):
        line = line.strip()
        if line and not line.startswith("#"):
            try: out.append(parse_coord(line))
            except GeoError as e: raise GeoError(f"line {n}: {e}")
    if len(out) > MAX_POINTS:
        raise GeoError(f"more than {MAX_POINTS} points")
    return out


def _convert(text) -> list:
    p = parse_coord(text)
    return ["Decimal:      " + fmt_dd(p), "Hemisphere:   " + fmt_hem(p), "DMS:          " + fmt_dms(p)]


def _two(text) -> tuple:
    parts = text.split("|")
    if len(parts) != 2:
        raise GeoError("type two coordinates separated by |   e.g.  51.5074, -0.1278 | 48.8566, 2.3522")
    return parse_coord(parts[0]), parse_coord(parts[1])


def _between(text) -> list:
    a, b = _two(text)
    d = haversine(a, b)
    f = (bearing(b, a) + 180) % 360
    m = midpoint(a, b)
    return [f"Distance:   {d:,.3f} km   {d / KM_PER_MI:,.3f} mi   {d / KM_PER_NMI:,.3f} nmi",
            f"Bearing:    {bearing(a, b):.2f} deg ({compass(bearing(a, b))}) at the start, {f:.2f} deg at the end",
            f"Midpoint:   {fmt_dd(m)}", "", "Great-circle on a sphere: within ~0.5% of the real distance. Not a road distance."]


def _dest(text) -> list:
    parts = text.split("|")
    if len(parts) != 3:
        raise GeoError("type start | bearing degrees | distance km   e.g.  0,0 | 90 | 100")
    a = parse_coord(parts[0])
    try:
        brg, km = float(parts[1]), float(parts[2])
    except ValueError:
        raise GeoError("bearing and distance must be numbers")
    if not (math.isfinite(brg) and math.isfinite(km)) or km < 0 or km > 40_100:
        raise GeoError("distance must be 0 to 40100 km")
    p = destination(a, brg, km)
    return ["Destination: " + fmt_dd(p), "             " + fmt_dms(p), f"Check: {haversine(a, p):,.3f} km from the start"]


def _polygon(text) -> list:
    pts = _coords_lines(text)
    if not pts:
        raise GeoError("type one coordinate per line")
    s, w, n, e = bbox(pts)
    out = [f"{len(pts)} point(s)", f"Bounding box  S {s:.5f}  W {w:.5f}  N {n:.5f}  E {e:.5f}",
           f"Box size      {haversine((s, w), (s, e)):,.3f} km (south edge) x {haversine((s, w), (n, w)):,.3f} km"]
    if len(pts) >= 2:
        out.append(f"Path length   {path_km(pts):,.3f} km open, {path_km(pts, True):,.3f} km closed")
    if len(pts) >= 3:
        a = sphere_area_km2(pts)
        out.append(f"Area          {a:,.4f} km2 = {a * 100:,.2f} ha = {a / KM_PER_MI ** 2:,.4f} mi2  (great-circle edges)")
    out.append("The box does not handle shapes that cross the 180th meridian.")
    return out


SAMPLE_GEOJSON = '{"type":"Feature","properties":{},"geometry":{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[0,0]]]}}'


def _stored_editor(host, title, key, example, keymap, hint):
    st = Store(host)
    cur = st.load(key, example)
    if not isinstance(cur, str): cur = example

    def save(t): st.save(key, t[:MAX_TEXT])

    def wrap_fn(fn):
        def go(ed):
            try:
                r = fn(ed.area.text)
            except GeoError as e:
                return ("push", Message(title, ["Error: " + str(e)]))
            return ("push", r if isinstance(r, Screen) else TextView(title + " result", r))
        return go
    return ("push", Editor(title, cur[:MAX_TEXT], on_save=save, extra_keys={k: wrap_fn(f) for k, f in keymap.items()}, hint=hint))


def make_map(host, entry):
    def ask(title, label, fn, initial=""):
        def done(text):
            try: lines = fn(text)
            except GeoError as e: lines = ["Error: " + str(e)]
            return ("push", Message(title, lines))
        return ("push", Prompt(title, label, initial, on_done=done))

    def plot_from(text): return PlotScreen(parse_plot(text))

    def geo_plot(text):
        r = geojson_check(text)
        if r["errors"]: raise GeoError(r["errors"][0])
        if not r["shapes"]: raise GeoError("no geometry to plot")
        return PlotScreen([(k, ps, "") for k, ps in r["shapes"][:MAX_POINTS]], "GeoJSON plot")

    def plot_places():
        ps = [(r, p) for r, p in place_pts(shared_items(host, "places"))][:MAX_POINTS]
        if not ps:
            return ("push", Message("Saved places", ["No saved places could be read.", "Either none are saved in the Places app, or Map Tools has no read grant:",
                                                       f"  kos grant {entry.name} space:places --level read"]))
        return ("push", PlotScreen([("point", [p], str(r.get("name", ""))[:20]) for r, p in ps], "Saved places"))

    return Menu("Map Tools", [
        ("Convert a coordinate (decimal, DMS, N/S/E/W)", lambda: ask("Convert", "Coordinate:", _convert, "40 42 46 N, 74 0 22 W")),
        ("Distance, bearing and midpoint", lambda: ask("Distance", "A | B :", _between, "51.5074, -0.1278 | 48.8566, 2.3522")),
        ("Destination from bearing and distance", lambda: ask("Destination", "start | bearing | km :", _dest, "0, 0 | 90 | 100")),
        ("Bounding box, length and area of points", lambda: _stored_editor(
            host, "Points", "mt-points", "0, 0\n0, 1\n1, 1\n1, 0", {"ctrl-r": _polygon}, "one coordinate per line   Ctrl-R measure")),
        ("GeoJSON: validate and summarise", lambda: _stored_editor(
            host, "GeoJSON", "mt-geojson", SAMPLE_GEOJSON, {"ctrl-r": geojson_report, "ctrl-l": geo_plot}, "Ctrl-R check   Ctrl-L plot")),
        ("Plot my saved places (from Places)", lambda: plot_places()),
        ("Plot points, lines and polygons", lambda: _stored_editor(
            host, "Plot", "mt-plot", "# point:  lat, lon | label     line/poly:  line c | c | c\n51.5074, -0.1278 | London\n48.8566, 2.3522 | Paris\nline 51.5074, -0.1278 | 48.8566, 2.3522",
            {"ctrl-r": plot_from}, "Ctrl-R plot")),
    ], intro=["  Works only on coordinates you type. No map tiles, GPS, traffic, imagery, addresses or directions.", "  Spherical Earth: distances within ~0.5%.", ""])


# ---------------------------------------------------------- Route Planner ----
def matrix(pts) -> list:
    return [[haversine(a, b) for b in pts] for a in pts]


def order_cost(order, dm, closed=False) -> float:
    t = sum(dm[a][b] for a, b in zip(order, order[1:]))
    return t + (dm[order[-1]][order[0]] if closed and len(order) > 2 else 0.0)


def nearest_neighbour(dm, start=0) -> list:
    left, order = set(range(len(dm))) - {start}, [start]
    while left:
        nxt = min(sorted(left), key=lambda j: dm[order[-1]][j])
        order.append(nxt); left.discard(nxt)
    return order


def two_opt(order, dm, closed=False, passes=50) -> list:
    """Reverse segments while that shortens the route. The first stop stays first. Terminates because every
    accepted move strictly lowers the cost; also capped at `passes` sweeps."""
    order, best = list(order), order_cost(order, dm, closed)
    for _ in range(passes):
        better = False
        for i in range(1, len(order) - 1):
            for j in range(i + 1, len(order)):
                cand = order[:i] + order[i:j + 1][::-1] + order[j + 1:]
                c = order_cost(cand, dm, closed)
                if c < best - 1e-9:
                    order, best, better = cand, c, True
        if not better:
            break
    return order


def fmt_eta(km: float, kmh: float) -> str:
    m = round(km / kmh * 60)
    return f"{m // 60} h {m % 60:02d} min" if m >= 60 else f"{m} min"


DEFAULT_SPEEDS = {"walk": 5.0, "cycle": 15.0, "drive": 50.0}


def _route_state(raw) -> dict:
    st = {"wps": [], "speeds": dict(DEFAULT_SPEEDS), "mode": "walk", "round": False}
    if not isinstance(raw, dict):
        return st
    for w in (raw.get("wps") or [])[:MAX_WAYPOINTS]:
        if (isinstance(w, list) and len(w) == 3 and isinstance(w[0], str)
                and all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in w[1:])
                and abs(w[1]) <= 90 and abs(w[2]) <= 180):
            st["wps"].append([w[0][:30], float(w[1]), float(w[2])])
    sp = raw.get("speeds")
    if isinstance(sp, dict):
        for k in DEFAULT_SPEEDS:
            v = sp.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and 0 < v <= 1000: st["speeds"][k] = float(v)
    if raw.get("mode") in DEFAULT_SPEEDS: st["mode"] = raw["mode"]
    st["round"] = raw.get("round") is True
    return st


class RouteScreen(Screen):
    title = "Route Planner"

    def __init__(self, host, entry=None):
        self.host, self.entry = host, entry
        self.store = Store(host)
        self.st = _route_state(self.store.load("route"))
        self.nav = ListNav(len(self.st["wps"]))
        self.msg = ""
        self.help = "a add  p saved place  d delete  < > move  m mode  v speeds  r round trip  o optimise  O apply  Esc quit"

    def save(self): self.store.save("route", self.st)

    def pts(self, order=None):
        w = self.st["wps"]
        return [(w[i][1], w[i][2]) for i in (range(len(w)) if order is None else order)]

    def render(self, w, h):
        st, wps = self.st, self.st["wps"]
        self.nav.resize(len(wps))
        sp = st["speeds"][st["mode"]]
        out = [f" Mode {st['mode']} at {sp:g} km/h   round trip: {'yes' if st['round'] else 'no'}   stops {len(wps)}/{MAX_WAYPOINTS}   (straight lines, not roads)"]
        rows, cum, pts = [], 0.0, self.pts()
        for i, p in enumerate(wps):
            leg = haversine(pts[i - 1], pts[i]) if i else 0.0
            cum += leg
            rows.append([i + 1, p[0], f"{leg:,.2f}" if i else "-", f"{cum:,.2f}", fmt_eta(cum, sp) if i else "-"])
        top, end = self.nav.window(max(1, h - 8))
        tbl = table(rows[top:end], ["#", "Stop", "Leg km", "Total km", "ETA"], maxw=w - 4)
        out += [tbl[0], tbl[1]] + [("> " if top + i == self.nav.sel else "  ") + l for i, l in enumerate(tbl[2:])]
        if not wps:
            out += ["", "  Press a to add a stop: 'name | lat, lon' or just 'lat, lon'."]
        else:
            tot = path_km(pts, st["round"])
            out += ["", f" Total {tot:,.2f} km   " + "   ".join(f"{m} {fmt_eta(tot, v)}" for m, v in st["speeds"].items())]
        if self.msg: out.append(" " + self.msg)
        return out

    def _add(self, text):
        text = text.strip()
        if len(self.st["wps"]) >= MAX_WAYPOINTS:
            self.msg = f"at most {MAX_WAYPOINTS} stops"; return
        try:
            try: name, p = "", parse_coord(text)
            except GeoError:
                name, _s, c = text.partition("|")
                p = parse_coord(c)
        except GeoError as e:
            self.msg = "not added: " + str(e); return
        self.st["wps"].append([(name.strip() or f"Stop {len(self.st['wps']) + 1}")[:30], p[0], p[1]])
        self.save(); self.msg = "added"

    def _add_place(self, r):
        p = latlon(r)
        if p and len(self.st["wps"]) < MAX_WAYPOINTS:
            self.st["wps"].append([str(r.get("name", "Place"))[:30], p[0], p[1]]); self.save(); self.msg = "added"
        else: self.msg = f"not added (at most {MAX_WAYPOINTS} stops)"

    def _speeds(self, text):
        try:
            v = [float(x) for x in text.replace(",", " ").split()]
            if len(v) != 3 or not all(0 < x <= 1000 and math.isfinite(x) for x in v): raise ValueError
        except ValueError:
            self.msg = "type three speeds in km/h, e.g. 5 15 50 (each above 0, up to 1000)"; return
        self.st["speeds"] = dict(zip(DEFAULT_SPEEDS, v)); self.save(); self.msg = "speeds saved"

    def optimise(self) -> tuple:
        """-> (nn order, improved order) over indices; stop 1 stays first."""
        dm = matrix(self.pts())
        nn = nearest_neighbour(dm, 0)
        return nn, two_opt(nn, dm, self.st["round"])

    def report(self) -> list:
        wps, closed = self.st["wps"], self.st["round"]
        if len(wps) < 3:
            return ["Add at least 3 stops to optimise."]
        dm = matrix(self.pts())
        nn, imp = self.optimise()
        mine = order_cost(range(len(wps)), dm, closed)
        sp = self.st["speeds"][self.st["mode"]]
        names = lambda o: " > ".join(wps[i][0] for i in o)
        c_nn, c_imp = order_cost(nn, dm, closed), order_cost(imp, dm, closed)
        save = mine - c_imp
        return [f"Starting at '{wps[0][0]}', {'round trip' if closed else 'one way'}, straight-line distances.", "",
                f"Your order:      {mine:,.2f} km  {fmt_eta(mine, sp)}", "  " + names(range(len(wps))),
                f"Nearest-neighbour: {c_nn:,.2f} km", f"Improved (2-opt): {c_imp:,.2f} km  {fmt_eta(c_imp, sp)}", "  " + names(imp), "",
                (f"Saves {save:,.2f} km ({100 * save / mine:.1f}%)." if save > 1e-6 else "Your order is already as short as this heuristic finds."),
                "Heuristic: not guaranteed to be the shortest possible.", "Press O on the list to apply the improved order."]

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        n, i = len(self.st["wps"]), self.nav.sel
        if k == "p": return pick_places(self.host, self.entry, self._add_place, "Add a saved place")
        if k == "a": return ("push", Prompt("Add stop", "name | lat, lon   (or just lat, lon):", "", self._add))
        if k == "d" and n: return ("push", Confirm("Delete this stop?", self._del))
        if k in ("<", ">") and n:
            j = i + (1 if k == ">" else -1)
            if 0 <= j < n:
                w = self.st["wps"]; w[i], w[j] = w[j], w[i]; self.nav.sel = j; self.save()
        elif k == "m":
            ms = list(DEFAULT_SPEEDS); self.st["mode"] = ms[(ms.index(self.st["mode"]) + 1) % 3]; self.save()
        elif k == "v":
            return ("push", Prompt("Speeds", "walk cycle drive in km/h:", " ".join(f"{v:g}" for v in self.st["speeds"].values()), self._speeds))
        elif k == "r": self.st["round"] = not self.st["round"]; self.save()
        elif k == "o": return ("push", TextView("Optimise", self.report()))
        elif k == "O" and n >= 3:
            w = self.st["wps"]; self.st["wps"] = [w[j] for j in self.optimise()[1]]; self.save(); self.msg = "improved order applied"
        elif k == "escape": return ("quit",)

    def _del(self):
        if self.st["wps"]:
            self.st["wps"].pop(self.nav.sel); self.save(); self.msg = "deleted"


def make_route(host, entry): return RouteScreen(host, entry)


# ----------------------------------------------------------------- Places ----
SPEC = R("places", "Places", "place",
         "name*; lat*; lon*; category: choice(home|work|food|shop|sight|nature|other)=other; notes: long; visits: number=0; last_visit: date",
         list_cols=("name", "lat", "lon", "category", "visits"), group="category",
         blurb="Places you save yourself: a name, latitude and longitude in decimal degrees, a category and notes. "
               "Press v to log a visit.")


def latlon(r):
    """(lat, lon) of a place record (own or shared), or None if missing or odd."""
    try:
        a, b = float(r.get("lat")), float(r.get("lon"))
    except (TypeError, ValueError):
        return None
    return (a, b) if math.isfinite(a) and math.isfinite(b) and abs(a) <= 90 and abs(b) <= 180 else None


def place_pts(items) -> list:
    return [(r, p) for r in items if isinstance(r, dict) for p in [latlon(r)] if p]


def pick_places(host, entry, on_pick, title):
    """A menu of the saved places (read from the shared 'places' folder), or a message saying why there is none."""
    items = [r for r, _p in place_pts(shared_items(host, "places"))][:MAX_WAYPOINTS]
    if not items:
        return ("push", Message(title, ["No saved places could be read.", "Either none are saved in the Places app yet, or this app has no read grant:",
                                        f"  kos grant {entry.name} space:places --level read", "You can still type coordinates."]))
    return ("push", Menu(title, [(f"{r.get('name', '?')}  ({r['lat']}, {r['lon']})", (lambda r=r: ("pop", lambda: on_pick(r)))) for r in items]))


def nearest(items, pt, n=10) -> list:
    return sorted(((haversine(pt, p), r) for r, p in place_pts(items)), key=lambda x: (x[0], x[1].get("name", "")))[:n]


def within(items, pt, km) -> list:
    return [(d, r) for d, r in nearest(items, pt, MAX_PLACES) if d <= km]


def most_visited(items, log, n=10) -> list:
    names = {r["_id"]: r.get("name", "") for r in items}
    cnt: dict = {}
    for v in log:
        if v.get("p") in names: cnt[v["p"]] = cnt.get(v["p"], 0) + 1
    return [(names[i], c) for i, c in sorted(cnt.items(), key=lambda x: (-x[1], names[x[0]]))[:n]]


class PlacesList(RecordList):
    def __init__(self, host):
        super().__init__(Data(SpaceHost(host, "places"), SPEC))
        self.store = Store(host)
        self.help += "   v visit  L log  n nearest  w within  m most visited"

    def log(self) -> list:
        raw = self.store.load("visits", [])
        return [v for v in raw if isinstance(v, dict) and isinstance(v.get("p"), int) and isinstance(v.get("d"), str)][:MAX_VISITS] if isinstance(raw, list) else []

    def _point(self, text):
        try: return parse_coord(text)
        except GeoError:
            for r, p in place_pts(self.data.items):
                if r.get("name", "").lower() == text.strip().lower(): return p
            raise GeoError("not a coordinate or a saved place name")

    def _norm(self, rec) -> bool:
        try: p = parse_coord(f"{rec.get('lat', '')}, {rec.get('lon', '')}")
        except GeoError as e:
            self.msg = "not saved: " + str(e); return False
        rec["lat"], rec["lon"] = f"{p[0]:.6f}".rstrip("0").rstrip("."), f"{p[1]:.6f}".rstrip("0").rstrip(".")
        return True

    def _added(self, rec):
        if len(self.data.items) >= MAX_PLACES: self.msg = f"at most {MAX_PLACES} places"
        elif self._norm(rec): super()._added(rec)

    def _saved(self, rec):
        if self._norm(rec): super()._saved(rec)

    def _deleted(self, rec):
        super()._deleted(rec)
        self.store.save("visits", [v for v in self.log() if v["p"] != rec["_id"]])

    def _visit(self, rec, text):
        tok = text.strip().split(None, 1)
        d, note = today(), text.strip()
        if tok and re.match(r"^\d{4}-\d{2}-\d{2}", tok[0]):
            ok, val = validate(Field("d", "d", "date"), tok[0])
            if not ok: self.msg = "date: " + val; return
            d, note = val, tok[1] if len(tok) > 1 else ""
        log = (self.log() + [{"p": rec["_id"], "d": d, "n": note[:80]}])[-MAX_VISITS:]
        self.store.save("visits", log)
        mine = [v["d"] for v in log if v["p"] == rec["_id"]]
        rec["visits"], rec["last_visit"] = str(len(mine)), max(mine)
        self.data.update(rec); self.msg = f"visit logged ({len(mine)} total)"

    def _show(self, title, fn):
        def done(text):
            try: lines = fn(text)
            except GeoError as e: lines = ["Error: " + str(e)]
            return ("push", Message(title, lines))
        return done

    def _near(self, text):
        res = nearest(self.data.items, self._point(text))
        return [f"{d:>9,.2f} km  {r['name']}  ({r.get('category', '')})" for d, r in res] or ["no saved places"]

    def _radius(self, text):
        c, _s, km = text.rpartition("|")
        try: rad = float(km)
        except ValueError: raise GeoError("type  point | radius km   e.g.  Home | 5")
        if not 0 < rad <= 20_100: raise GeoError("radius must be above 0 and at most 20100 km")
        res = within(self.data.items, self._point(c), rad)
        return [f"{len(res)} place(s) within {rad:g} km", ""] + [f"{d:>9,.2f} km  {r['name']}" for d, r in res]

    def key(self, k):
        cur = self.current()
        if k == "v" and cur:
            self.msg = ""
            return ("push", Prompt("Log visit", "date YYYY-MM-DD and note (empty = today):", "", lambda t: self._visit(cur, t)))
        if k == "L":
            names = {r["_id"]: r.get("name", "") for r in self.data.items}
            rows = sorted(self.log(), key=lambda v: v["d"], reverse=True)
            return ("push", TextView("Visit log", [f"{v['d']}  {names.get(v['p'], '?'):<24} {v.get('n', '')}" for v in rows[:300]] or ["no visits logged"]))
        if k == "n":
            return ("push", Prompt("Nearest", "point (coordinate or a saved place name):", "", self._show("Nearest places", self._near)))
        if k == "w":
            return ("push", Prompt("Within radius", "point | radius km :", "", self._show("Within radius", self._radius)))
        if k == "m":
            mv = most_visited(self.data.items, self.log())
            return ("push", TextView("Most visited", [f"{c:>4}  {n}" for n, c in mv] or ["no visits logged yet"]))
        return super().key(k)


def make_places(host, entry): return PlacesList(host)


ENTRIES: list = [
    app("Map Tools", make_map, "partial",
        "Coordinate conversion, great-circle distance/bearing/midpoint/destination, bounding box, polygon area, GeoJSON check and a plain plot, "
        "all on coordinates you type. No map tiles, GPS, traffic, imagery, address search or directions; spherical Earth (~0.5% error).",
        graphical=True, uses=["places"]),
    app("Route Planner", make_route, "partial",
        "Straight-line (great-circle) legs, totals and ETA by editable walk/cycle/drive speeds, and a nearest-neighbour + 2-opt visiting order. "
        "It is not road routing: no roads, traffic, one-ways or turn-by-turn directions. Up to 40 stops; the order is a heuristic. Can add stops from your saved Places.", uses=["places"]),
    app("Places", make_places, "full",
        "Saved places with coordinates, category and notes, a visit log with dates, nearest and within-radius queries and most-visited. "
        "KOS has no location sensor: it never tracks or shares your location; you enter every coordinate yourself.", owns=["places"]),
]
