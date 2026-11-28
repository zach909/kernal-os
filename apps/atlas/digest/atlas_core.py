"""atlas_core - the map maker's brain. Whole numbers only; standard library only.

MASTER COPY. Every Atlas app carries a byte-identical copy of this file (an app's code lives in its own
folder and apps never import each other). ``suite/atlas_sync.py`` copies it; ``tests/test_atlas_core.py``
fails if a copy drifts. Change this file, not the copies.

What it is
----------
A map of *anything*. The unit is a **mark**: what kind of thing (``k``), where (``p``, whole millimetres in
a named space ``s``, or nowhere), when (``t``, whole seconds), how much (``v``, a whole number, in unit
``u``), what it is called (``l``), what it belongs to (``r``) and how many observations it sums (``n``).
A photograph's depth, a whiff of gas, a sound's bearing, a temperature, a touch, a file on a disk, a link
between two files: all marks. The map keeps them in chunks, finds them again by text, kind, time and place.

The one idea behind every locating function here is the same: **comparing sensors tells you where**.

* two cameras: the nearer a thing is, the *more* its two views differ (``disparity``);
* several noses, thermometers, microphones, radios: the nearer the source, the stronger the reading
  (``locate_source``);
* two microphones: how much sooner the sound reaches one (``bearing_from_delay``).

What it is not
--------------
It is not recognition. It does not say who anyone is. Depth from two cameras needs the cameras to be
rectified (same height, looking the same way) and their spacing and focal length told to it; it does not
calibrate them. Smell and the like are reported as a number per sensor: what the number means (a gas
resistance, a VOC index) is for whoever reads the sensor to say in ``u``. The source finder assumes a
single point source whose reading falls off with distance; wind, walls and a second source break that.
"""

from itertools import accumulate
import hashlib
import json
import re
from math import isqrt

# --------------------------------------------------------------------------------------------- numbers

SIN1024 = (0, 18, 36, 54, 71, 89, 107, 125, 143, 160, 178, 195, 213, 230, 248, 265, 282, 299, 316, 333,
           350, 367, 384, 400, 416, 433, 449, 465, 481, 496, 512, 527, 543, 558, 573, 587, 602, 616, 630,
           644, 658, 672, 685, 698, 711, 724, 737, 749, 761, 773, 784, 796, 807, 818, 828, 839, 849, 859,
           868, 878, 887, 896, 904, 912, 920, 928, 935, 943, 949, 956, 962, 968, 974, 979, 984, 989, 994,
           998, 1002, 1005, 1008, 1011, 1014, 1016, 1018, 1020, 1022, 1023, 1023, 1024, 1024)


def sin1024(deg):
    """sin of a whole number of degrees, times 1024, as a whole number."""
    d = deg % 360
    if d <= 90:
        return SIN1024[d]
    if d <= 180:
        return SIN1024[180 - d]
    if d <= 270:
        return -SIN1024[d - 180]
    return -SIN1024[360 - d]


def cos1024(deg):
    return sin1024(deg + 90)


def asin_deg(s1024):
    """The whole degrees (0-90) whose sine times 1024 is nearest ``s1024`` (negative gives negative)."""
    sign = -1 if s1024 < 0 else 1
    s = min(abs(s1024), 1024)
    best = min(range(91), key=lambda d: abs(SIN1024[d] - s))
    return sign * best


def median(xs):
    ys = sorted(xs)
    n = len(ys)
    return ys[n // 2] if n % 2 else (ys[n // 2 - 1] + ys[n // 2]) // 2


# -------------------------------------------------------------------------------- 1. vision: two views

BIG = 1 << 40


def _box(flat, w, h, r):
    """Sum of ``flat`` (row-major, w x h) over the (2r+1) square around every cell; clamped at the edges."""
    lo = [max(x - r, 0) for x in range(w)]
    hi = [min(x + r, w - 1) + 1 for x in range(w)]
    cum = [[0] * w]
    for y in range(h):
        p = [0]
        p.extend(accumulate(flat[y * w:(y + 1) * w]))
        row = [p[b] - p[a] for a, b in zip(lo, hi)]
        cum.append([a + b for a, b in zip(cum[-1], row)])
    out = []
    for y in range(h):
        out.extend([b - a for a, b in zip(cum[max(y - r, 0)], cum[min(y + r, h - 1) + 1])])
    return out


def disparity(left, right, w, h, max_disp=24, min_disp=1, radius=2, uniq=10, max_avg_diff=24, lr_tol=1):
    """How far each pixel of ``left`` moved in ``right``, in sixteenths of a pixel (0 = no answer).

    ``left`` and ``right`` are flat row-major lists of 0-255 grey values, w x h, from two cameras that are
    side by side, same height, looking the same way, with the *right* camera to the right of the left one.
    A point then appears ``d`` pixels further left in the right picture, and the nearer the point, the
    larger ``d``: that is the whole trick. ``d`` of 0 would be infinitely far, so ``min_disp`` is at least 1.

    A pixel gets an answer only if all of these hold, and otherwise gets 0 rather than a guess:
    the window around it matches well enough (``max_avg_diff`` grey levels per pixel), the best match is
    clearly better than any other (``uniq`` percent), and matching the other way round (right to left)
    lands on the same place (``lr_tol``). Flat walls and repeating patterns fail the second check: no
    answer, which is the honest result for them. The leftmost ``max_disp + radius`` columns never get one
    (the right camera cannot see all of what they would be matched against); keep the subject out of them.
    """
    if len(left) != w * h or len(right) != w * h:
        raise ValueError("pictures must be w x h")
    if not (1 <= min_disp <= max_disp < w):
        raise ValueError("bad disparity range")
    n = 2 * radius + 1
    limit = max_avg_diff * n * n
    vol = []
    for d in range(min_disp, max_disp + 1):
        ad = []
        for y in range(h):
            a = left[y * w:(y + 1) * w]
            b = right[y * w:(y + 1) * w]
            ad.extend([255] * d)
            ad.extend([abs(p - q) for p, q in zip(a[d:], b[:w - d])])
        vol.append(_box(ad, w, h, radius))
    nd = max_disp - min_disp + 1
    out = [0] * (w * h)
    for i, col in enumerate(zip(*vol)):
        best = min(col)
        if best > limit:
            continue
        bi = col.index(best)
        d = bi + min_disp
        x = i % w
        if x < max_disp + radius:          # the strip the right camera cannot fully see: too few distances can
            continue                       # be tried there for "clearly the best" to mean anything
        second = BIG
        if bi > 1:
            second = min(col[:bi - 1])
        if bi + 2 < nd:
            second = min(second, min(col[bi + 2:]))
        if second != BIG and not best * 100 < second * (100 - uniq):
            continue
        y = i // w
        xr = x - d
        # right-to-left check: the best match for the right pixel must be (about) this same distance
        rbest, rd = BIG, 0
        for dd in range(min_disp, min(max_disp, w - 1 - xr) + 1):
            c = vol[dd - min_disp][y * w + xr + dd]
            if c < rbest:
                rbest, rd = c, dd
        if abs(rd - d) > lr_tol:
            continue
        off = 0
        if 0 < bi < nd - 1:
            den = col[bi - 1] - 2 * best + col[bi + 1]
            if den > 0:
                off = max(-8, min(8, (16 * (col[bi - 1] - col[bi + 1])) // (2 * den)))
        out[i] = max(1, 16 * d + off)
    return out


def depth_mm(disp16, f_px, baseline_mm):
    """Distance in whole millimetres from a disparity in sixteenths of a pixel: Z = f * B / d."""
    return f_px * baseline_mm * 16 // disp16 if disp16 > 0 else 0


def nearest_mm(f_px, baseline_mm, max_disp):
    """The nearest distance this ``max_disp`` can measure. Closer than this the two views differ by more
    than the search covers and the pixel gets no answer."""
    return f_px * baseline_mm // max_disp


def _mirror(img, w, h):
    out = []
    for y in range(h):
        out.extend(img[y * w:(y + 1) * w][::-1])
    return out


def fuse_depth(rig, images, w, h, max_disp=24, zmin=300, zmax=20000, agree_pct=15, **kw):
    """Depth in mm for every pixel of camera 0, from every other camera, and how many cameras agree.

    ``rig`` is ``{"f": focal length in pixels, "xs": [each camera's position along the baseline in mm]}``;
    camera 0 is the reference. ``images`` is one flat grey picture per camera. With two cameras this is one
    pair. With more, each other camera is a second opinion: the answers are compared and only those within
    ``agree_pct`` percent of one another count (``votes``). A pixel seen by two pairs that agree is far
    more believable than one seen by one; where they disagree the longer baseline wins, with a vote of 1.
    Returns ``(zs, votes)``, flat lists; 0 where nobody could say.
    """
    xs, f = list(rig["xs"]), rig["f"]
    if len(images) != len(xs) or len(xs) < 2:
        raise ValueError("need at least two cameras and one picture each")
    per = []
    for i in range(1, len(xs)):
        base = abs(xs[i] - xs[0])
        if base <= 0:
            raise ValueError("two cameras cannot be in the same place")
        a, b = images[0], images[i]
        flip = xs[i] < xs[0]               # the other camera is on the left: mirror both, so it is on the right
        if flip:
            a, b = _mirror(a, w, h), _mirror(b, w, h)
        d = disparity(a, b, w, h, max_disp=max_disp, **kw)
        if flip:
            d = _mirror(d, w, h)
        per.append(([depth_mm(v, f, base) for v in d], base))
    zs, votes = [0] * (w * h), [0] * (w * h)
    for i in range(w * h):
        got = [(p[i], base) for p, base in per if zmin <= p[i] <= zmax]
        if not got:
            continue
        # The answer is the biggest group of estimates that agree with one another; if two groups are as big,
        # the one measured over the longer baseline (more reliable) wins. A camera that disagrees with the
        # rest is outvoted, never averaged in.
        best = None
        for z0, base in got:
            group = [z for z, _ in got if abs(z - z0) * 100 <= z0 * agree_pct]
            key = (len(group), base)
            if best is None or key > best[0]:
                best = (key, group)
        zs[i], votes[i] = median(best[1]), len(best[1])
    return zs, votes


def project(zs, votes, grey, w, h, rig, pose=(0, 0, 0, 0), stride=2, min_votes=1):
    """Turn depth into points in the map: ``[(x, y, z, grey, votes)]`` in whole mm.

    The camera looks along +y, x is to its right and z is up. ``pose`` is ``(x, y, z, yaw)`` of the rig in
    the map, yaw in whole degrees counter-clockwise seen from above. Pass the real pose if the rig moves
    (from a compass, odometry, anything); nothing here works it out from the pictures.
    """
    f = rig["f"]
    cx, cy = rig.get("cx", w // 2), rig.get("cy", h // 2)
    px, py, pz, yaw = pose
    s, c = sin1024(yaw), cos1024(yaw)
    pts = []
    for v in range(0, h, stride):
        for u in range(0, w, stride):
            i = v * w + u
            z = zs[i]
            if z <= 0 or votes[i] < min_votes:
                continue
            bx, by, bz = (u - cx) * z // f, z, -((v - cy) * z // f)
            pts.append((px + (bx * c - by * s) // 1024, py + (bx * s + by * c) // 1024, pz + bz, grey[i], votes[i]))
    return pts


# ------------------------------------------------------------------------------------------ 2. marks

KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
SPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")
LIMIT = 10 ** 12              # a coordinate, value or time beyond this is not a measurement (a Unix time is ~1.8 x 10**9)
MAX_STR = 200
MAX_CHUNK_CHARS = 300_000       # a vault item may hold 400,000 characters
MAX_CHUNK_MARKS = 2500
# What the map has worked out for itself (consolidation, section 6) and what people wrote down: these are
# the last to be forgotten when a chunk is full.
DERIVED = frozenset({"region", "routine", "source", "theme", "hub", "twin", "trend"})
PINNED = frozenset({"event", "file", "link", "note"}) | DERIVED       # "data" is not: redundant data goes
# A mark of one of these kinds says how things *are*, not what a sensor read at a moment: seeing it again
# updates it instead of adding another reading in time.
TIMELESS = frozenset({"file", "link", "note", "data"}) | DERIVED
# Kinds that are not a sensor reading of some quantity; everything else with a place is read as a sensor.
NOT_A_SENSOR = frozenset({"sight", "event", "file", "link", "note", "data"}) | DERIVED
TBUCKET = 60                    # readings of one sensor within this many seconds are one mark (their average)


def _s(v, n=MAX_STR):
    return _CTRL.sub("?", v)[:n] if isinstance(v, str) else None


def _int(v):
    return v if type(v) is int and -LIMIT <= v <= LIMIT else None


def mark(kind, at=None, v=0, t=0, label="", ref="", unit="", n=1, space="world", to=""):
    """A mark, checked. Raises ValueError for one that is not a map entry."""
    m = clean_mark({"k": kind, "p": list(at) if at is not None else None, "v": v, "t": t, "l": label,
                    "r": ref, "u": unit, "n": n, "s": space, "o": to})
    if m is None:
        raise ValueError("not a valid mark")
    return m


def clean_mark(m):
    """A mark read from anywhere (a shared folder, a file, another program) is hostile until it is cleaned:
    only these keys, only whole numbers in range, strings without control characters. ``None`` if it cannot be
    made into a mark."""
    if not isinstance(m, dict):
        return None
    k, s = m.get("k"), m.get("s", "world")
    if not isinstance(k, str) or not KIND_RE.match(k) or not isinstance(s, str) or not SPACE_RE.match(s):
        return None
    p = m.get("p")
    if p is not None:
        if not isinstance(p, (list, tuple)) or len(p) != 3 or any(_int(a) is None for a in p):
            return None
        p = [p[0], p[1], p[2]]
    v, t, n = _int(m.get("v", 0)), _int(m.get("t", 0)), _int(m.get("n", 1))
    if v is None or t is None or n is None or n < 1:
        return None
    out = {"k": k, "s": s, "p": p, "v": v, "t": t, "n": n}
    for key, ln in (("l", MAX_STR), ("r", MAX_STR), ("u", 12), ("o", MAX_STR)):
        x = m.get(key, "")
        if not isinstance(x, str):
            return None
        out[key] = _s(x, ln)
    return out


def dump_marks(marks):
    return json.dumps(marks, separators=(",", ":"), sort_keys=True)


def load_marks(text):
    """``(marks, dropped)``: the good marks in ``text`` and how many entries were refused."""
    try:
        raw = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return [], 1
    if not isinstance(raw, list):
        return [], 1
    out, bad = [], 0
    for m in raw:
        c = clean_mark(m)
        if c is None:
            bad += 1
        else:
            out.append(c)
    return out, bad


def _isqrt_d2(a, b):
    return isqrt(sum((x - y) * (x - y) for x, y in zip(a, b)))


def worth(m):
    """What a mark is worth keeping, as a sort key (smallest is forgotten first): what the map worked out or
    people wrote down, then how many times it was seen, then how recently. A speck seen once is probably noise;
    a cell seen fifty times is probably real. Age alone never decides."""
    return (m["k"] in PINNED, min(m["n"], 1_000_000).bit_length(), m["t"])


class MarkStore:
    """The map: marks kept in chunks inside any key-value store.

    ``backend`` needs ``keys() -> list[str]``, ``get(key) -> str | None``, ``put(key, text) -> bool`` and
    ``delete(key)``. A KOS app gives it its shared folder; another program gives it a directory.

    A mark with a place goes in the chunk (a cube ``chunk_mm`` on a side) that holds it, snapped to the
    middle of its ``voxel_mm`` cell, and a second observation of the same thing in the same cell is *added
    to* it (``n`` grows, ``v`` becomes the average) instead of piling up. A mark with no place goes in a
    chunk chosen by its ``r``. At most ``max_chunks`` chunks are kept: when one more is needed, the chunk
    that was touched longest ago is forgotten whole. Whatever the backend returns is cleaned again before
    it is believed.
    """

    def __init__(self, backend, voxel_mm=100, chunk_mm=2048, max_chunks=380):
        self.b, self.voxel, self.chunk, self.max_chunks = backend, voxel_mm, chunk_mm, max_chunks
        self.dropped = 0

    # -- keys
    def _key(self, m):
        if m["p"] is None:
            h = sum(ord(c) for c in m["r"] or m["l"]) % 32
            return f"c.{m['s']}.n{h}"
        a = "_".join(str(c // self.chunk) for c in m["p"])
        return f"c.{m['s']}.{a}"

    def _snap(self, m):
        if m["p"] is not None:
            vx = self.voxel
            m["p"] = [(c // vx) * vx + vx // 2 for c in m["p"]]
        return m

    @staticmethod
    def _ident(m):
        when = 0 if m["k"] in TIMELESS else m["t"] // TBUCKET
        return (m["k"], tuple(m["p"]) if m["p"] is not None else None, m["r"], m["l"], m["o"], m["s"], when)

    def _read(self, key):
        text = self.b.get(key)
        if text is None:
            return []
        marks, bad = load_marks(text)
        self.dropped += bad
        return marks

    def _index(self):
        text = self.b.get("index")
        if text is None:
            return {}
        try:
            raw = json.loads(text)
        except (ValueError, RecursionError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {k: t for k, t in raw.items() if isinstance(k, str) and k.startswith("c.") and _int(t) is not None}

    # -- writing
    def _put(self, key, text):
        if not self.b.put(key, text):
            raise OSError("the map could not be saved")

    def _replace(self, drop, new):
        """Forget every mark for which ``drop(mark)`` is true and put ``new`` on the map, one chunk at a time: each
        chunk is read once, loses what is dropped, gains what is new, and is written once. Chunks that gain marks are
        written first, so if a write fails part-way the map is left with a duplicate, never a hole. A write that fails
        raises ``OSError``. Returns ``(kept, gone)``: how many new marks were put and how many were forgotten."""
        by, kept = {}, 0
        for raw in new:
            m = clean_mark(raw)
            if m is None:
                self.dropped += 1
                continue
            m = self._snap(m)
            by.setdefault(self._key(m), []).append(m)
            kept += 1
        index = self._index()
        existing = [k for k in self.b.keys() if k.startswith("c.")]
        for key in by:
            if key not in existing:
                while len(existing) >= self.max_chunks and index:          # one more chunk is wanted: forget the stalest
                    old = min(index, key=lambda k: index[k])
                    self.b.delete(old)
                    index.pop(old, None)
                    if old in existing:
                        existing.remove(old)
                existing.append(key)
        order = [k for k in existing if k in by] + [k for k in existing if k not in by]
        gone = 0
        for key in order:
            have_list = self._read(key) if key in self.b.keys() else []
            keepers = [m for m in have_list if not drop(m)]
            gone += len(have_list) - len(keepers)
            have = {self._ident(m): m for m in keepers}
            for m in by.get(key, ()):
                i = self._ident(m)
                e = have.get(i)
                if e is None:
                    have[i] = m
                else:
                    tot = e["n"] + m["n"]
                    e["v"] = (e["v"] * e["n"] + m["v"] * m["n"]) // tot
                    e["n"], e["t"] = tot, max(e["t"], m["t"])
            merged = list(have.values())
            if not merged:
                if have_list:
                    self.b.delete(key)
                index.pop(key, None)
                continue
            if len(merged) == len(have_list) and key not in by and gone == 0:
                continue
            merged.sort(key=worth)
            text = dump_marks(merged)
            while len(merged) > MAX_CHUNK_MARKS or len(text) > MAX_CHUNK_CHARS:
                merged = merged[max(1, len(merged) // 8):]       # forget the least worth keeping first
                text = dump_marks(merged)
            if key in by or len(merged) != len(have_list):
                self._put(key, text)
            index[key] = max(m["t"] for m in merged)
        self._put("index", json.dumps(index, separators=(",", ":"), sort_keys=True))
        return kept, gone

    def add(self, marks):
        """Put marks on the map. Returns how many were kept (a refused mark is counted in ``dropped``)."""
        return self._replace(lambda m: False, marks)[0]

    # -- reading
    def _chunks_for(self, space, near, radius):
        keys = [k for k in self.b.keys() if k.startswith("c.")]
        out = []
        for k in keys:
            parts = k.split(".", 2)
            if len(parts) != 3 or (space and parts[1] != space):
                continue
            if near is not None:
                if parts[2].startswith("n"):
                    continue
                try:
                    c = [int(a) for a in parts[2].split("_")]
                except ValueError:
                    continue
                if len(c) != 3:
                    continue
                reach = radius + self.chunk
                if any(abs(near[i] - (c[i] * self.chunk + self.chunk // 2)) > reach for i in range(3)):
                    continue
            out.append(k)
        return out

    def search(self, text="", kind="", space="", since=None, until=None, near=None, radius=1000, limit=20,
               min_n=1):
        """Marks matching every given condition, nearest first if ``near`` is given, else newest first.

        ``text``: every word must be in the mark's kind, label, reference or unit (case does not matter).
        ``near``: ``(x, y, z)`` and ``radius`` in mm, in one ``space``. Nothing is returned for a place
        in a space that has no places (a mark with no position is never "near" anything)."""
        words = [w for w in text.lower().split() if w]
        hits = []
        for key in self._chunks_for(space, near, radius):
            for m in self._read(key):
                if kind and m["k"] != kind:
                    continue
                if m["n"] < min_n or (since is not None and m["t"] < since) or (until is not None and m["t"] > until):
                    continue
                if words:
                    hay = f"{m['k']} {m['l']} {m['r']} {m['u']}".lower()
                    if any(w not in hay for w in words):
                        continue
                if near is not None:
                    if m["p"] is None:
                        continue
                    d = _isqrt_d2(m["p"], near)
                    if d > radius:
                        continue
                    m = dict(m, d=d)
                hits.append(m)
        if near is not None:
            hits.sort(key=lambda m: (m["d"], -m["t"]))
        else:
            hits.sort(key=lambda m: -m["t"])
        return hits[:max(1, min(limit, 200))]

    # -- consolidation
    def all_marks(self, limit=60000):
        out = []
        for key in self._chunks_for("", None, 0):
            out.extend(self._read(key))
            if len(out) >= limit:
                break
        return out

    def chars(self):
        return sum(len(self.b.get(k) or "") for k in self.b.keys() if k.startswith("c."))

    def _rewrite(self, drop):
        """Forget every mark for which ``drop(mark)`` is true. Returns how many went."""
        return self._replace(drop, [])[1]

    def consolidate(self, now, keep_s=3600, space="world", min_cells=40, floors=None):
        """Make the map smaller and smarter. Raw ``sight`` voxels older than ``keep_s`` seconds are found to be
        surfaces and objects (``region`` marks, merged into the ones already known) and then forgotten, and lone
        old specks that never became part of anything are dropped as noise; near-duplicate ``data`` is merged into
        one mark that keeps the count; what the
        map can work out about movement, sources and files is recomputed and replaces what it worked out
        last time (``floors``: the clean-air reading of each sensor kind, if known). Returns a report with the size
        before and after, in characters."""
        before = self.chars()
        digested = noise = 0
        old = [m for m in self.all_marks() if m["k"] == "sight" and m["s"] == space and m["t"] < now - keep_s]
        if old:
            boxes, used = region_boxes(old, self.voxel, space, min_cells)
            if boxes:
                known = boxes_from_region_marks(self.search(kind="region", space=space, limit=200))
                merged = merge_boxes(known + boxes, self.voxel)
                self._replace(lambda m: m["k"] == "region" and m["s"] == space, region_marks(merged, now, space))
            _, digested = self._replace(lambda m: m["k"] == "sight" and m["s"] == space and m["t"] < now - keep_s
                                        and tuple(c // self.voxel for c in m["p"]) in used, [])
            # what never became part of anything and was seen only once is noise: it goes
            _, noise = self._replace(lambda m: m["k"] == "sight" and m["s"] == space and m["t"] < now - keep_s
                                     and m["n"] < 2, [])
        merged, removed = dedupe(self.all_marks())
        if removed:
            gone = {self._ident(m) for m in removed}
            self._replace(lambda m: m["k"] == "data" and self._ident(m) in gone, merged)
        keep = self.all_marks()
        fresh = digest(keep, floors)
        kinds = {"routine", "source", "theme", "hub", "twin", "trend"}
        self._replace(lambda m: m["k"] in kinds, fresh)
        counts = {k: sum(1 for m in fresh if m["k"] == k) for k in sorted(kinds)}
        regions_now = sum(1 for m in self.all_marks() if m["k"] == "region")
        return {"before": before, "after": self.chars(), "voxels_digested": digested, "noise_dropped": noise,
                "duplicates_merged": len(removed) - len(merged), "regions": regions_now, **counts}

    def about(self, ref, space=""):
        """Everything the map holds about one thing, by kind: how many marks, how much they add up to (``n``), and
        the newest value. A video's frames, its likes, its title and a smell near it all share one ``ref``."""
        out = {}
        for key in self._chunks_for(space, None, 0):
            for m in self._read(key):
                if m["r"] != ref:
                    continue
                d = out.setdefault(m["k"], {"marks": 0, "n": 0, "latest": None, "unit": "", "t": -1, "label": ""})
                d["marks"] += 1
                d["n"] += m["n"]
                if m["t"] >= d["t"]:
                    d.update(latest=m["v"], unit=m["u"], t=m["t"], label=m["l"])
        return out

    def similar(self, text, space="mind", max_bits=16, limit=10):
        """Data like ``text``, closest first: ranked by how few of 64 fingerprint bits differ. A partial text lands
        10-13 bits from the text it came from; unrelated texts are a median 29 apart and almost never under 16."""
        p = embed(text)
        if p is None:
            return []
        sig = simhash(text)
        out = []
        for key in self._chunks_for(space, None, 0):
            for m in self._read(key):
                if m["k"] == "data" and _sig(m) is not None:
                    d = hamming(sig, _sig(m))
                    if d <= max_bits:
                        out.append(dict(m, d=d))
        out.sort(key=lambda m: (m["d"], -m["n"], -m["t"]))
        return out[:limit]

    def stats(self):
        """Counts by kind and space, the time span, and how many entries were refused."""
        kinds, spaces, n, t0, t1 = {}, {}, 0, None, None
        for key in self._chunks_for("", None, 0):
            for m in self._read(key):
                n += 1
                kinds[m["k"]] = kinds.get(m["k"], 0) + 1
                spaces[m["s"]] = spaces.get(m["s"], 0) + 1
                t0 = m["t"] if t0 is None else min(t0, m["t"])
                t1 = m["t"] if t1 is None else max(t1, m["t"])
        return {"marks": n, "kinds": kinds, "spaces": spaces, "first": t0, "last": t1, "refused": self.dropped}


def voxel_marks(points, voxel_mm, t, kind="sight", unit="grey", min_votes=1):
    """Fold points ``(x, y, z, value, votes)`` into one mark per voxel: ``v`` is their average value."""
    cells = {}
    for x, y, z, g, votes in points:
        if votes < min_votes:
            continue
        k = (x // voxel_mm, y // voxel_mm, z // voxel_mm)
        a = cells.get(k)
        if a is None:
            cells[k] = [1, g]
        else:
            a[0] += 1
            a[1] += g
    vx = voxel_mm
    return [mark(kind, ((a * vx) + vx // 2 for a in k), v=s // c, t=t, unit=unit, n=c)
            for k, (c, s) in cells.items()]


# ------------------------------------------------------------------- 3. who passed: change over time

class Background:
    """What the scene normally holds, so that what is *new* stands out.

    Feed it the occupied voxels of each look (``update``). A voxel seen occupied in at least ``keep`` of
    the last looks is background; ``new`` returns the occupied voxels that are not. Slow changes (a chair
    moved, daylight) settle into the background after ``keep`` looks; a person walking through never does.
    """

    def __init__(self, keep=3, memory=8):
        self.keep, self.memory, self.hist = keep, memory, []

    def known(self):
        seen = {}
        for frame in self.hist:
            for v in frame:
                seen[v] = seen.get(v, 0) + 1
        return {v for v, c in seen.items() if c >= self.keep}

    def new(self, occupied):
        bg = self.known()
        return {v for v in occupied if v not in bg}

    def update(self, occupied):
        self.hist.append(set(occupied))
        del self.hist[:-self.memory]


def blobs(voxels, grow=3, min_voxels=6):
    """Group new voxels into things: voxels within ``grow`` cells of each other are one thing.
    Returns ``[{"voxels": n, "lo": (x, y, z), "hi": (x, y, z)}]`` in voxel units, biggest first."""
    cells = {}
    for v in voxels:
        cells.setdefault((v[0] // grow, v[1] // grow, v[2] // grow), []).append(v)
    seen, out = set(), []
    for start in cells:
        if start in seen:
            continue
        seen.add(start)
        stack, mem = [start], []
        while stack:
            c = stack.pop()
            mem.extend(cells[c])
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    for dz in (-1, 0, 1):
                        nb = (c[0] + dx, c[1] + dy, c[2] + dz)
                        if nb in cells and nb not in seen:
                            seen.add(nb)
                            stack.append(nb)
        if len(mem) >= min_voxels:
            out.append({"voxels": len(mem), "lo": tuple(min(m[i] for m in mem) for i in range(3)),
                        "hi": tuple(max(m[i] for m in mem) for i in range(3)), "members": mem})
    out.sort(key=lambda b: -b["voxels"])
    return out


def event_marks(found, voxel_mm, t, space="world"):
    """One ``event`` mark per blob: where (its middle), when, how big. A blob 1.0-2.2 m tall and under 1.2 m
    across is labelled ``person-sized``: that is a guess from size alone, never a recognition."""
    out = []
    for b in found:
        lo, hi = b["lo"], b["hi"]
        w = [(hi[i] - lo[i] + 1) * voxel_mm for i in range(3)]
        mid = [((lo[i] + hi[i] + 1) * voxel_mm) // 2 for i in range(3)]
        person = 1000 <= w[2] <= 2200 and max(w[0], w[1]) <= 1200
        out.append(mark("event", mid, v=b["voxels"], t=t, space=space, unit="voxels",
                        label=("person-sized movement" if person else "movement") +
                              f" {w[0]}x{w[1]}x{w[2]} mm"))
    return out


# --------------------------------------------------------------- 4. smell, sound, heat, touch, radio

def _spread(pos, exc, point, power):
    """How badly the sensors disagree that ``point`` is the source: the mean difference of ``strength *
    distance ** power`` from its average, in percent of that average. 0 is perfect agreement."""
    prods = []
    for p, e in zip(pos, exc):
        if e > 0:
            d = max(1, isqrt((p[0] - point[0]) ** 2 + (p[1] - point[1]) ** 2 + (p[2] - point[2]) ** 2))
            prods.append(e * d ** power)
    if len(prods) < 2:
        return BIG
    m = sum(prods) // len(prods)
    return sum(abs(q - m) for q in prods) * 100 // (m * len(prods)) if m else BIG


def locate_source(readings, power=2, floor=None):
    """Where a source is, from several sensors that each report how strong it is: the nearer a sensor,
    the stronger its reading.

    ``readings``: ``[((x, y, z), value)]``, at least 3 sensors in at least two different places, whole mm
    and whole readings. ``power`` says how fast the reading falls with distance: 2 for light, sound and radio
    in open space, 1 for a smell drifting along a corridor (a guess; tune it by trying). ``floor`` is the
    reading of clean air or silence; by default the lowest reading is taken as the floor.

    How: every point on a grid around the sensors is scored by how well ``(reading - floor) * distance **
    power`` comes out the same for every sensor (the same source, seen from different distances), the best
    scoring places are refined, and the best is returned.

    The strength of the source is not known, so distances are only known in proportion, and then there are
    two places that fit: one near the sensors and a mirror-image one further out (a weak source close by looks
    like a strong one far away). It returns the nearer: the simplest explanation. Pass sensors on several
    sides of the source if that matters.

    ``alt`` is that other place (or ``None`` when only one fits): with the source outside the ring of sensors
    the nearer one is often the wrong one, and only a sensor on its other side, or knowing how strong the
    source really is, can say which.

    Returns ``{"at": (x, y, z), "spread": n, "alt": (x, y, z) or None}``, or ``None`` when no sensor stands out
    from the floor.
    ``spread`` is how badly the sensors still disagree there, in percent (0 is perfect; over 40 means do not
    trust it: wind, a wall, two sources).
    """
    if len(readings) < 3:
        raise ValueError("need at least three sensors to place a source")
    pos = [tuple(p) for p, _ in readings]
    vals = [v for _, v in readings]
    base = min(vals) if floor is None else floor
    exc = [v - base for v in vals]
    if max(exc) <= 0:
        return None
    lo = [min(p[i] for p in pos) for i in range(3)]
    hi = [max(p[i] for p in pos) for i in range(3)]
    live = [i for i in range(3) if hi[i] > lo[i]]
    if not live:
        raise ValueError("the sensors are all in one place")
    span = max(hi[i] - lo[i] for i in live)
    n = {1: 400, 2: 100, 3: 32}[len(live)]
    steps = [0, 0, 0]
    axes = []
    for i in range(3):
        if i in live:
            a, b = lo[i] - span, hi[i] + span
            steps[i] = max(1, (b - a) // n)
            axes.append(list(range(a, b + 1, steps[i])))
        else:
            axes.append([lo[i]])
    scored = [(_spread(pos, exc, (x, y, z), power), (x, y, z)) for x in axes[0] for y in axes[1] for z in axes[2]]
    scored.sort()
    picks = []
    for dev, pt in scored:
        if len(picks) >= 24:
            break
        if all(max(abs(pt[i] - q[i]) for i in range(3)) > 3 * max(steps) for _, q in picks):
            picks.append((dev, pt))
    refined = []
    for dev, pt in picks:
        st = list(steps)
        for _ in range(6):
            cand = [(pt[0] + dx * st[0], pt[1] + dy * st[1], pt[2] + dz * st[2])
                    for dx in ((-2, -1, 0, 1, 2) if st[0] else (0,))
                    for dy in ((-2, -1, 0, 1, 2) if st[1] else (0,))
                    for dz in ((-2, -1, 0, 1, 2) if st[2] else (0,))]
            dev, pt = min((_spread(pos, exc, c, power), c) for c in cand)
            st = [max(1, x // 2) if x else 0 for x in st]
        refined.append((dev, pt))
    top = min(d for d, _ in refined)
    ok = [(min(isqrt(sum((p[i] - pt[i]) ** 2 for i in range(3))) for p in pos), dev, pt)
          for dev, pt in refined if dev <= top + 4]
    _, dev, pt = min(ok)
    others = [(near, q) for near, _, q in ok if max(abs(pt[i] - q[i]) for i in range(3)) > 3 * max(steps)]
    alt = max(others)[1] if others else None             # the mirror-image fit: the one furthest from the sensors
    return {"at": pt, "spread": dev, "alt": alt}


def tdoa(a, b, max_lag):
    """How many samples later ``b`` hears what ``a`` hears (negative: sooner), by whole-number
    cross-correlation. ``a`` and ``b`` are lists of whole samples, equal length."""
    n = len(a)
    if n != len(b) or n < 2 * max_lag + 2:
        raise ValueError("need equal recordings longer than twice the lag")
    best, lag_best = None, 0
    for lag in range(-max_lag, max_lag + 1):
        if lag >= 0:
            s = sum(x * y for x, y in zip(a[:n - lag], b[lag:]))
        else:
            s = sum(x * y for x, y in zip(a[-lag:], b[:n + lag]))
        if best is None or s > best:
            best, lag_best = s, lag
    return lag_best


def bearing_from_delay(delay_samples, rate_hz, spacing_mm, speed_mm_s=343_000):
    """Direction of a sound from two microphones, in whole degrees from straight ahead (positive is toward
    the microphone that hears it first... the one ``a`` of ``tdoa``). Two microphones cannot tell front
    from back: the bearing is the same for both. Returns ``None`` if the delay is impossible for this
    spacing (a longer delay than sound takes to cross the gap)."""
    s = speed_mm_s * delay_samples * 1024 // (rate_hz * spacing_mm)
    if abs(s) > 1024:
        return None
    return asin_deg(s)


# ------------------------------------------------------------------------- 5. files, and any named thing

STOP = frozenset("the and for are but not you all can had her was one our out day get has him his how its may new now old see two "
                 "way who did let put say she too use from this that with have they will your what when which into "
                 "import return const self none true false def class void int str".split())
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,19}")
LINK_RES = (re.compile(r"^\s*from\s+([\w.]+)\s+import\b", re.M), re.compile(r"^\s*import\s+([\w.]+)", re.M),
            re.compile(r"""(?:require\(|from\s+|import\s+)['"](\.{0,2}/?[\w./-]+)['"]"""),
            re.compile(r'^\s*#\s*include\s+"([\w./-]+)"', re.M), re.compile(r"\]\(([\w./-]+\.\w{1,5})\)"))


def keywords(text, top=8):
    """The words a text says most, most first. Whole counts only."""
    counts = {}
    for w in WORD_RE.findall(text[:20000]):
        w = w.lower()
        if w not in STOP:
            counts[w] = counts.get(w, 0) + 1
    return [w for w, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]]


def references(text):
    """Names a file points at (imports, includes, links), as written, at most 30."""
    found = []
    for rx in LINK_RES:
        for m in rx.finditer(text[:20000]):
            if m.group(1) not in found:
                found.append(m.group(1))
    return found[:30]


def _tree(entries):
    kids = {}
    for e in entries:
        p = e["path"].strip("/")
        parent = p.rsplit("/", 1)[0] if "/" in p else ""
        kids.setdefault(parent, []).append(e)
    return kids


def layout(entries, cell=1000):
    """Give every file and folder a place, so a disk can be walked like a town: ``{path: (x, y, z)}``.

    Each folder is a square block and its contents sit in a grid inside it, in name order; ``z`` is how
    deep the folder is. The same tree always gives the same places, so the map stays put between runs."""
    kids = _tree(entries)
    size = {}

    def measure(path):
        cs = sorted(kids.get(path, ()), key=lambda e: e["path"])
        if not cs:
            size[path] = cell
            return cell
        biggest = max(measure(e["path"].strip("/")) for e in cs)
        cols = max(1, isqrt(len(cs) - 1) + 1)
        size[path] = cols * biggest
        return size[path]

    places = {}

    def place(path, x, y, depth):
        places[path] = (x, y, depth * cell)
        cs = sorted(kids.get(path, ()), key=lambda e: e["path"])
        if not cs:
            return
        biggest = max(size[e["path"].strip("/")] for e in cs)
        cols = max(1, isqrt(len(cs) - 1) + 1)
        for i, e in enumerate(cs):
            place(e["path"].strip("/"), x + (i % cols) * biggest, y + (i // cols) * biggest, depth + 1)

    roots = sorted(kids.get("", ()), key=lambda e: e["path"])
    top = ""
    # a virtual root holds the top-level entries
    kids.setdefault("", roots)
    measure(top)
    place(top, 0, 0, -1)               # the virtual root sits one level above the top-level entries
    places.pop("", None)
    return places


def file_marks(entries, t, space="files", texts=None):
    """Marks for a set of files and folders: one ``file`` mark each (``l`` holds its name and what it says,
    ``v`` its size), a ``link`` from every folder to what is in it and from a file to what it references.

    ``entries``: ``[{"path": "a/b.py", "dir": bool, "size": int}]``. ``texts``: ``{path: text}`` for the
    ones that were read. A reference only becomes a link if it names something in ``entries``."""
    texts = texts or {}
    pl = layout(entries)
    paths = {e["path"].strip("/") for e in entries}
    by_name = {}
    for p in paths:
        by_name.setdefault(p.rsplit("/", 1)[-1], []).append(p)
    out = []
    for e in entries:
        p = e["path"].strip("/")
        name = p.rsplit("/", 1)[-1]
        kw = keywords(texts[e["path"]]) if e["path"] in texts else []
        label = name + (" folder" if e.get("dir") else "") + ("  " + " ".join(kw) if kw else "")
        out.append(mark("file", pl.get(p), v=max(0, e.get("size", 0)), t=t, label=label, ref=p,
                        unit="bytes", space=space))
        parent = p.rsplit("/", 1)[0] if "/" in p else ""
        if parent:
            out.append(mark("link", pl.get(parent), t=t, label="contains", ref=parent, to=p, space=space))
        for ref in references(texts.get(e["path"], "")):
            cand = ref.replace(".", "/").split("/")[-1] if "/" not in ref and "." in ref else ref.rsplit("/", 1)[-1]
            for target in by_name.get(cand, []) + by_name.get(cand + ".py", []) + by_name.get(ref.rsplit("/", 1)[-1], []):
                if target != p:
                    out.append(mark("link", pl.get(p), t=t, label="references", ref=p, to=target, space=space))
                    break
    return out


# ------------------------------------------------------------- 6. patterns: the whole from the parts

def _tod(t):
    return (t % 86400) // 60              # minute of the day, UTC


def _planes(vox, axis, min_cells, reach=2):
    """Flat sheets of voxels perpendicular to ``axis`` (0=x, 1=y, 2=z): voxels in the same two-cell-thick layer
    that touch (within ``reach`` cells) form a sheet; a sheet of at least ``min_cells`` cells is a surface.
    Returns ``[set(voxels)]``."""
    a, b = [i for i in range(3) if i != axis]
    layers = {}
    for v in vox:
        layers.setdefault(v[axis] // 2, []).append(v)
    out = []
    for cells in layers.values():
        index = {(v[a], v[b]): v for v in cells}
        seen = set()
        for start in index:
            if start in seen:
                continue
            seen.add(start)
            stack, mem = [start], []
            while stack:
                c = stack.pop()
                mem.append(index[c])
                for da in range(-reach, reach + 1):
                    for db in range(-reach, reach + 1):
                        nb = (c[0] + da, c[1] + db)
                        if nb in index and nb not in seen:
                            seen.add(nb)
                            stack.append(nb)
            if len(mem) >= min_cells:
                out.append(set(mem))
    return out


def _box_of(cells, vx, vox):
    lo = [min(c[i] for c in cells) * vx for i in range(3)]
    hi = [(max(c[i] for c in cells) + 1) * vx for i in range(3)]
    n = sum(vox[c][0] for c in cells)
    grey = sum(vox[c][0] * vox[c][1] for c in cells) // max(1, n)
    return {"lo": lo, "hi": hi, "n": n, "grey": grey, "cls": ""}


def _class(box, thin):
    e = [box["hi"][i] - box["lo"][i] for i in range(3)]
    if e[2] <= thin and e[0] >= 800 and e[1] >= 800:
        return "horizontal surface"
    if (e[0] <= thin or e[1] <= thin) and e[2] >= 800 and max(e[0], e[1]) >= 800:
        return "wall-like surface"
    return "object"


def _near(a, b, tol):
    return all(a["lo"][i] <= b["hi"][i] + tol and b["lo"][i] <= a["hi"][i] + tol for i in range(3))


def merge_boxes(boxes, vx):
    """Boxes of the same class that overlap or touch become one. Repeats until nothing more merges."""
    boxes = [dict(b) for b in boxes]
    changed = True
    while changed:
        changed = False
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                a, b = boxes[i], boxes[j]
                if a["cls"] == b["cls"] and _near(a, b, vx):
                    tot = a["n"] + b["n"]
                    boxes[i] = {"lo": [min(a["lo"][k], b["lo"][k]) for k in range(3)],
                                "hi": [max(a["hi"][k], b["hi"][k]) for k in range(3)], "n": tot,
                                "grey": (a["grey"] * a["n"] + b["grey"] * b["n"]) // max(1, tot), "cls": a["cls"]}
                    del boxes[j]
                    changed = True
                    break
            if changed:
                break
    return boxes


def region_boxes(marks, vx, space="world", min_cells=40, reach=2):
    """Find the surfaces and objects in ``marks``' ``sight`` voxels. Floors and tabletops first (flat sheets
    perpendicular to z), then walls (sheets perpendicular to y, then x), then whatever is left that is
    still a lump (an object). Returns ``(boxes, used)``, ``used`` being the voxels that went into one.

    Planes are found along the map's own axes only: a wall at an angle to them is seen as steps, so point
    the rig (or give a ``yaw`` pose) so that the walls line up with x and y."""
    vox = {}
    for m in marks:
        if m["k"] == "sight" and m["p"] is not None and m["s"] == space:
            vox[tuple(c // vx for c in m["p"])] = (m["n"], m["v"])
    left, boxes = set(vox), []
    for axis in (2, 1, 0):
        for cells in _planes(left, axis, min_cells, reach):
            boxes.append(_box_of(cells, vx, vox))
            left -= cells
    for b in blobs(list(left), grow=3, min_voxels=8):
        boxes.append(_box_of(b["members"], vx, vox))
        left -= set(b["members"])
    for b in boxes:
        b["cls"] = _class(b, vx * 3)
    return boxes, set(vox) - left


def region_marks(boxes, t, space="world"):
    """One ``region`` mark per box. The lowest big horizontal surface is called floor-like; the box itself
    is kept in ``r`` so a later look can be merged into it. ``v`` is how many observations built it."""
    hs = [b for b in boxes if b["cls"] == "horizontal surface"
          and (b["hi"][0] - b["lo"][0]) * (b["hi"][1] - b["lo"][1]) >= 1_000_000]
    floor = min(hs, key=lambda b: b["lo"][2]) if hs else None
    out = []
    for b in boxes:
        name = "floor-like surface" if b is floor else b["cls"]
        e = [b["hi"][i] - b["lo"][i] for i in range(3)]
        mid = [(b["lo"][i] + b["hi"][i]) // 2 for i in range(3)]
        out.append(mark("region", mid, v=b["n"], t=t, space=space, unit="obs",
                        label=f"{name} {e[0]}x{e[1]}x{e[2]} mm",
                        ref="box:" + ",".join(str(c) for c in b["lo"] + b["hi"])))
    return out


def boxes_from_region_marks(marks):
    out = []
    for m in marks:
        if m["k"] != "region" or not m["r"].startswith("box:"):
            continue
        try:
            c = [int(x) for x in m["r"][4:].split(",")]
        except ValueError:
            continue
        if len(c) != 6:
            continue
        cls = "object"
        for name in ("horizontal surface", "floor-like surface", "wall-like surface"):
            if m["l"].startswith(name):
                cls = "horizontal surface" if name == "floor-like surface" else name
        out.append({"lo": c[:3], "hi": c[3:], "n": m["v"], "grey": 0, "cls": cls})
    return out


def routines(marks, cell_mm=1500, window_min=45, min_days=3):
    """Movement that comes back: ``event`` marks in the same 1.5 m square, at about the same time of day (UTC),
    on at least ``min_days`` different days. One ``routine`` mark each: where, when (``v`` = minute of the day),
    and on how many days (``n``). Nobody says this happens; it is only that it kept happening."""
    groups = {}
    for e in marks:
        if e["k"] == "event" and e["p"] is not None:
            groups.setdefault((e["s"], e["p"][0] // cell_mm, e["p"][1] // cell_mm), []).append(e)
    out = []
    for (space, _, _), evs in groups.items():
        evs.sort(key=lambda e: _tod(e["t"]))
        runs, cur = [], [evs[0]]
        for e in evs[1:]:
            if _tod(e["t"]) - _tod(cur[-1]["t"]) <= window_min:
                cur.append(e)
            else:
                runs.append(cur)
                cur = [e]
        runs.append(cur)
        for r in runs:
            days = {e["t"] // 86400 for e in r}
            if len(days) < min_days:
                continue
            mins = median([_tod(e["t"]) for e in r])
            at = [sum(e["p"][i] for e in r) // len(r) for i in range(3)]
            out.append(mark("routine", at, v=mins, unit="min", n=len(days), t=max(e["t"] for e in r), space=space,
                            label=f"recurring movement around {mins // 60:02d}:{mins % 60:02d} UTC"))
    return out


POWER = {"smell": 1, "gas": 1, "voc": 1, "taste": 1}        # falls off slowly; everything else: inverse square


def sources(marks, bucket_s=300, max_spread=40, min_contrast=10, floors=None):
    """Where something is coming from, found by comparing sensors. Every sensor kind (any mark kind with a
    place that is not one of the map's own: smell, sound, heat, radio, ...) is grouped by space, kind and
    five-minute slot; three or more sensors in different places are enough to ``locate_source``. A ``source``
    mark is kept only if the sensors agree (``max_spread``) and the reading really stands out
    (``min_contrast`` percent of the strongest). ``v`` is that contrast in reading units, ``n`` the sensors.
    ``floors`` is ``{kind: reading of clean air}`` if you know it; otherwise the lowest sensor is the floor,
    which hides some of the signal whenever even the farthest sensor smells it."""
    groups = {}
    for m in marks:
        if m["k"] in NOT_A_SENSOR or m["p"] is None:
            continue
        g = groups.setdefault((m["s"], m["k"], m["t"] // bucket_s), {})
        g[tuple(m["p"])] = (m["v"], m["u"], m["t"])
    out = []
    for (space, kind, _), g in groups.items():
        if len(g) < 3:
            continue
        readings = [(p, v) for p, (v, _, _) in g.items()]
        vals = [v for _, v in readings]
        top = max(vals)
        if (top - (floors or {}).get(kind, min(vals))) * 100 < min_contrast * max(1, abs(top)):
            continue
        r = locate_source(readings, power=POWER.get(kind, 2), floor=(floors or {}).get(kind))
        if r is None or r["spread"] > max_spread:
            continue
        unit = next(iter(g.values()))[1]
        out.append(mark("source", r["at"], v=top - (floors or {}).get(kind, min(vals)), unit=unit, n=len(g), space=space,
                        t=max(t for _, _, t in g.values()), label=f"{kind} source"))
    return out


def _file_words(m):
    head = m["l"].split("  ", 1)
    return set(head[1].split()) if len(head) > 1 else set()


def themes(marks, min_files=3, shared=3):
    """Groups of files that talk about the same things. Two files sharing ``shared`` of their most-used words
    are linked; a linked group of ``min_files`` or more is a ``theme`` mark, named by its commonest words and
    placed at the middle of its members. Words that nearly every file uses are ignored."""
    files = [m for m in marks if m["k"] == "file" and _file_words(m)][:3000]
    if len(files) < min_files:
        return []
    post, words = {}, {}
    for m in files:
        words[m["r"]] = _file_words(m)
        for w in words[m["r"]]:
            post.setdefault(w, []).append(m["r"])
    cap = min(60, max(8, len(files) // 4))
    pairs = {}
    for refs in post.values():
        if 2 <= len(refs) <= cap:
            for i in range(len(refs)):
                for j in range(i + 1, len(refs)):
                    k = (refs[i], refs[j])
                    pairs[k] = pairs.get(k, 0) + 1
    parent = {m["r"]: m["r"] for m in files}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for (a, b), c in pairs.items():
        if c >= shared:
            parent[find(a)] = find(b)
    groups = {}
    for m in files:
        groups.setdefault(find(m["r"]), []).append(m)
    out = []
    for members in groups.values():
        if len(members) < min_files:
            continue
        count = {}
        for m in members:
            for w in words[m["r"]]:
                count[w] = count.get(w, 0) + 1
        top = [w for w, c in sorted(count.items(), key=lambda kv: (-kv[1], kv[0])) if c >= 2][:3]
        if not top:
            continue
        placed = [m for m in members if m["p"] is not None]
        at = [sum(m["p"][i] for m in placed) // len(placed) for i in range(3)] if placed else None
        out.append(mark("theme", at, v=len(members), unit="files", n=len(members), t=max(m["t"] for m in members),
                        space=members[0]["s"], label="theme: " + " ".join(top), ref="theme:" + "-".join(top)))
    return out


def hubs(marks, min_refs=3):
    """Files that many others point at: a ``hub`` mark each, saying how many (``v``)."""
    count, place, name = {}, {}, {}
    for m in marks:
        if m["k"] == "link" and m["l"] == "references":
            count[m["o"]] = count.get(m["o"], 0) + 1
        elif m["k"] == "file":
            place[m["r"]], name[m["r"]] = (m["p"], m["s"]), m["l"].split("  ", 1)[0]
    out = []
    for target, c in count.items():
        if c >= min_refs and target in place:
            p, space = place[target]
            out.append(mark("hub", p, v=c, unit="refs", n=c, space=space, ref=target,
                            label=f"{name[target]} is referenced by {c} files"))
    return out


def twins(marks):
    """Files that look the same: same size and the same most-used words (at least three). Not proof they are
    byte for byte equal: that needs the bytes. A ``twin`` mark each group, ``v`` how many."""
    groups = {}
    for m in marks:
        if m["k"] == "file" and m["v"] > 0:
            w = sorted(_file_words(m))
            if len(w) >= 3:
                groups.setdefault((m["s"], m["v"], tuple(w)), []).append(m)
    out = []
    for (space, size, _), ms in groups.items():
        if len(ms) >= 2:
            ms.sort(key=lambda m: m["r"])
            out.append(mark("twin", ms[0]["p"], v=len(ms), unit="files", n=len(ms), space=space, ref=ms[0]["r"],
                            to=ms[1]["r"], t=max(m["t"] for m in ms),
                            label=f"{len(ms)} look-alike files of {size} bytes"))
    return out


def trends(marks, min_points=4, min_change_pct=20):
    """How any measured quantity is moving: smell, heat, a sensor, or how many people liked a video. Readings of
    the same thing (same space, kind and ``r``) at four or more different moments are fitted with a straight line
    (whole-number least squares). If the earlier readings were steady and the newest is at least double (or
    nothing) their median it is a spike; otherwise, if it moved by at least ``min_change_pct`` percent of its
    average over the span, it is rising or falling. One ``trend`` mark each: ``v`` is the change per hour, ``n`` the readings used."""
    series = {}
    for m in marks:
        if m["k"] not in NOT_A_SENSOR and m["r"]:
            series.setdefault((m["s"], m["k"], m["r"]), []).append(m)
    out = []
    for (space, kind, ref), ms in series.items():
        ms.sort(key=lambda m: m["t"])
        pts = {}
        for m in ms:
            pts[m["t"]] = m
        ms = [pts[t] for t in sorted(pts)]
        if len(ms) < min_points:
            continue
        t0 = ms[0]["t"]
        n = len(ms)
        st = sum(m["t"] - t0 for m in ms)
        sv = sum(m["v"] for m in ms)
        stv = sum((m["t"] - t0) * m["v"] for m in ms)
        stt = sum((m["t"] - t0) ** 2 for m in ms)
        den = n * stt - st * st
        if den <= 0:
            continue
        per_hour = 3600 * (n * stv - st * sv) // den
        span = ms[-1]["t"] - t0
        change = per_hour * span // 3600
        mean = sv // n
        last = ms[-1]
        label = ""
        before = [m["v"] for m in ms[:-1]]
        med = median(before)
        flat = (max(before) - min(before)) * 100 <= 20 * max(1, abs(med))
        if flat and abs(last["v"] - med) >= max(1, abs(med)):          # steady, then a jump: a spike, not a slope
            label = f"{kind} of {ref} spiked to {last['v']} {last['u']} from about {med}"
        elif abs(change) * 100 >= min_change_pct * max(1, abs(mean)):
            label = f"{kind} of {ref} {'rising' if per_hour > 0 else 'falling'} {per_hour} {last['u']}/h"
        if label:
            out.append(mark("trend", last["p"], v=per_hour, unit=(last["u"] + "/h")[:12], n=n, t=last["t"],
                            space=space, ref=ref, label=label))
    return out


def digest(marks, floors=None):
    """Everything the map can work out from what is in it, except regions (those digest raw voxels)."""
    return routines(marks) + sources(marks, floors=floors) + themes(marks) + hubs(marks) + twins(marks) + trends(marks)


# ------------------------------------------ 7. anything, put in space: the redundant goes, the good stays

EMBED_R = 100_000          # the half-width of the abstract space texts are placed in
MAX_TOKENS = 2000


def tokens(text):
    """The distinct words of a text that say something (3-20 letters, not a stop word), sorted."""
    seen = set()
    for w in WORD_RE.findall(text[:50000]):
        w = w.lower()
        if w not in STOP:
            seen.add(w)
            if len(seen) >= MAX_TOKENS:
                break
    return sorted(seen)


def _h(token, size):
    return hashlib.blake2b(token.encode("utf-8"), digest_size=size).digest()


def embed_features(features, radius=EMBED_R):
    """Where a set of features sits: each feature has a fixed pseudo-random point in the cube, and the place is the
    sum of the points divided by the square root of how many there are (a random projection, so distances are
    roughly kept). Sets that share most features land close together. ``None`` for no features."""
    feats = sorted(set(features))
    if not feats:
        return None
    sx = sy = sz = 0
    for w in feats:
        b = _h(w, 12)
        sx += int.from_bytes(b[0:4], "big") % (2 * radius + 1) - radius
        sy += int.from_bytes(b[4:8], "big") % (2 * radius + 1) - radius
        sz += int.from_bytes(b[8:12], "big") % (2 * radius + 1) - radius
    k = isqrt(len(feats)) or 1
    return (sx // k, sy // k, sz // k)


def simhash_features(features):
    """A 64-bit fingerprint where similar feature sets differ in few bits (``hamming``). 0 for none."""
    feats = sorted(set(features))
    if not feats:
        return 0
    votes = [0] * 64
    for w in feats:
        h = int.from_bytes(_h(w, 8), "big")
        for i in range(64):
            votes[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(64):
        if votes[i] > 0:
            out |= 1 << i
    return out


def embed(text, radius=EMBED_R):
    """Where a text sits: ``(x, y, z)`` whole numbers, or ``None`` if it has no words. Two texts that share most of
    their words land close together, texts that share none land far apart. It is *lexical*, not meaning: "car" and
    "automobile" are not near, and word order does not matter."""
    return embed_features(tokens(text), radius)


def simhash(text):
    """The fingerprint of a text's words (0 for a text with no words)."""
    return simhash_features(tokens(text))


def hamming(a, b):
    return bin(a ^ b).count("1")


def data_mark(text, ref="", t=0, space="mind", title=None, n=1):
    """Put a piece of data in space: its place is where its words put it, its fingerprint is in ``o``, its
    ``v`` is how many distinct words it has (a rough measure of how much it says), ``l`` a short title."""
    p = embed(text)
    if p is None:
        raise ValueError("nothing to place: no words")
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return mark("data", p, v=len(tokens(text)), t=t, label=(title if title is not None else first)[:120], ref=ref[:200],
                unit="tokens", n=n, space=space, to="sig:%016x" % simhash(text))


MAGIC = ((b"\x89PNG\r\n\x1a\n", "png image"), (b"\xff\xd8\xff", "jpeg image"), (b"GIF8", "gif image"),
         (b"%PDF", "pdf document"), (b"PK\x03\x04", "zip archive"), (b"\x7fELF", "program"), (b"\x1f\x8b", "gzip archive"),
         (b"ID3", "mp3 audio"), (b"OggS", "ogg audio"), (b"fLaC", "flac audio"), (b"SQLite format 3\x00", "sqlite database"),
         (b"7z\xbc\xaf\x27\x1c", "7z archive"), (b"MZ", "windows program"), (b"BM", "bmp image"),
         (b"\x1a\x45\xdf\xa3", "matroska video"), (b"%!PS", "postscript"))
MAX_INGEST = 64 << 20
SCAN_HEAD, SCAN_TAIL = 256 << 10, 64 << 10


def sniff(data):
    """What kind of thing these bytes are, from their first bytes: a short name, or ``"binary"``."""
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    if data[4:8] == b"ftyp":
        return "mp4 video"
    if data[:4] == b"RIFF":
        return {b"WAVE": "wav audio", b"AVI ": "avi video", b"WEBP": "webp image"}.get(data[8:12], "riff file")
    return "binary"


def is_text(data):
    """True if these bytes read as text: no NUL, almost no control characters, and valid UTF-8 nearly throughout."""
    head = data[:8192]
    if not head:
        return True
    if b"\x00" in head:
        return False
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 32)
    if ctrl * 20 > len(head):
        return False
    return head.decode("utf-8", "replace").count("\ufffd") * 20 <= len(head)


def shingles(data, take=4000):
    """Features of arbitrary bytes: the 4-byte windows whose hash falls in a fixed 1 in 16, taken from the start and
    the end. Which windows are picked depends only on the bytes in them, not on where they sit, so a copy with a
    few bytes changed, or something added at the front, still shares nearly all of them."""
    sample = data if len(data) <= SCAN_HEAD + SCAN_TAIL else data[:SCAN_HEAD] + data[-SCAN_TAIL:]
    out = set()
    for i in range(len(sample) - 3):
        w = int.from_bytes(sample[i:i + 4], "big")
        if ((w * 2654435761) >> 8) & 15 == 0:
            out.add("b:%08x" % w)
            if len(out) >= take:
                break
    return sorted(out)


def features_of(name, data):
    """What to place ``data`` by: its words if it is text, otherwise its sampled byte patterns and its kind. Only if
    it has none of its own (an empty file, a text of stop words) its file name's words are used, so a copy under a
    different name is still the same thing. Never empty: with no name either, it is placed by its size class."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    nm = ["name:" + w for w in tokens(name.replace("_", " ").replace(".", " ").replace("-", " "))]
    if is_text(data):
        kind, feats = "text", tokens(data[:200000].decode("utf-8", "replace"))
    else:
        kind = sniff(data)
        feats = shingles(data) + ["kind:" + kind]
    if not feats:                       # the name places only what has nothing of its own to be placed by
        feats = nm or ["size:%d" % len(data).bit_length(), "kind:" + kind]
    return kind, feats


def ingest(name, data, t=0, space="mind", ref="", n=1, size=None):
    """Put ANYTHING in space: a note, a file, a photo, a download, random bytes. Its place comes from what is in it
    (see ``features_of``); its fingerprint is in ``o``, so a copy, or a near copy, lands in the same spot and
    ``dedupe`` folds it into one mark. ``v`` is how many features it had, ``l`` says what it is. It does not
    understand what it ingests: a photo is placed by its bytes, not by what is in the picture. ``size`` is the
    real size when only the start of a big file is at hand. Raises ``ValueError`` only for something bigger
    than 64 MiB."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_INGEST:
        raise ValueError("too big to ingest")
    kind, feats = features_of(name, data)
    title = ""
    if kind == "text":
        title = next((ln.strip() for ln in data[:4000].decode("utf-8", "replace").splitlines() if ln.strip()), "")[:60]
    label = (f"{name} ({kind}, {len(data) if size is None else size} bytes)" + (f": {title}" if title else ""))[:120]
    return mark("data", embed_features(feats), v=len(set(feats)), t=t, label=label, ref=(ref or name)[:200],
                unit="features", n=n, space=space, to="sig:%016x" % simhash_features(feats))


def _sig(m):
    o = m.get("o", "")
    if not o.startswith("sig:") or len(o) != 20:
        return None
    try:
        return int(o[4:], 16)
    except ValueError:
        return None


def dedupe(marks, max_bits=7):
    """Collapse near-duplicate ``data`` marks (fingerprints within ``max_bits`` of 64 bits, in the same space; 7 means
    about 90% alike).

    The fingerprint is cut into 8 bytes and two marks are compared only if some byte is identical (if at most 7 bits
    differ, one byte must be), then checked exactly. Each group becomes ONE mark: the group's best
    (most corroborated, then the one that says most, then the newest) with ``n`` set to the group's total ``n``
    and the newest ``t``. Nothing is lost but the repetition: the sum of ``n`` over the marks is the same before
    and after. Returns ``(merged, removed)``: the new marks, and the marks they replace."""
    data = [m for m in marks if m["k"] == "data" and _sig(m) is not None][:20000]
    parent = list(range(len(data)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    buckets = {}
    for i, m in enumerate(data):
        sig = _sig(m)
        for b in range(8):
            buckets.setdefault((m["s"], b, (sig >> (8 * b)) & 255), []).append(i)
    for members in buckets.values():
        if 1 < len(members) <= 400:
            first = members[0]
            for j in members[1:]:
                if hamming(_sig(data[first]), _sig(data[j])) <= max_bits:
                    parent[find(j)] = find(first)
                else:                                   # not the first: compare with the others in the bucket too
                    for k in members[1:]:
                        if k != j and hamming(_sig(data[k]), _sig(data[j])) <= max_bits:
                            parent[find(j)] = find(k)
                            break
    groups = {}
    for i in range(len(data)):
        groups.setdefault(find(i), []).append(data[i])
    merged, removed = [], []
    for g in groups.values():
        if len(g) < 2:
            continue
        best = max(g, key=lambda m: (m["n"], m["v"], m["t"], [-ord(c) for c in m["r"]]))
        out = dict(best, n=sum(m["n"] for m in g), t=max(m["t"] for m in g))
        merged.append(out)
        removed.extend(g)
    return merged, removed


# ----------------------------------------------------------------------------------------------- show

def describe(m):
    """One line for a mark, with whole numbers only (millimetres), for a screen or a log."""
    where = "nowhere" if m["p"] is None else "at " + ",".join(str(c) for c in m["p"]) + " mm"
    what = m["l"] or m["r"] or m["k"]
    extra = f" > {m['o']}" if m.get("o") else ""
    return f"{m['k']} {what}{extra} {where} v={m['v']}{m['u']} n={m['n']} t={m['t']}"
