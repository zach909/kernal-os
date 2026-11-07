"""pack_media: File Format Converter, 3D Model Viewer, Avatar Maker, Animation Maker, Color Tools.

Plain stdlib code, nothing in the background, every input and output bounded. See docs/PACKS.md."""

from __future__ import annotations

import base64
import binascii
import colorsys
import csv
import html
import io
import json
import math
import re
import struct
import zlib
from collections import Counter
from xml.etree import ElementTree as ET

from kos.sdk import Canvas

from .packkit import app, shared_add, shared_items
from .records import Data, RecordList
from .specs import R
from .ui import Editor, Menu, Message, Prompt, Screen, SpaceHost, TextView

MAXTEXT = 200_000          # input text cap (characters)
MAXVAULT = 390_000         # protocol cap on one vault value is 400000
MAXROWS, MAXCOLS = 5000, 100
MAXPX = 65536              # largest image we decode/encode (pixels)


def put_safe(host, key: str, value: str) -> str:
    """Store in the vault if it fits; return a short status for the screen."""
    if len(value) > MAXVAULT:
        return "too big to save"
    return f"saved {key}" if host.put(key, value) else "could not save"


def chunk_lines(text: str, n: int = 100) -> list:
    out = []
    for line in text.split("\n")[:4000]:
        out += [line[i:i + n] for i in range(0, len(line), n)] or [""]
    return out


# ------------------------------------------------------------ PNG / PPM ----
_SIG = b"\x89PNG\r\n\x1a\n"


def png_encode(rows: list) -> bytes:
    """rows: list of rows of (r,g,b). 8-bit RGB PNG."""
    h, w = len(rows), len(rows[0])
    raw = b"".join(b"\x00" + bytes(v for px in r for v in px) for r in rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def png_decode(data: bytes) -> list:
    """-> rows of (r,g,b). 8-bit grey / RGB / RGBA, not interlaced; alpha is dropped. Raises ValueError."""
    if data[:8] != _SIG:
        raise ValueError("not a PNG file")
    pos, ihdr, idat = 8, None, []
    while pos + 12 <= len(data):
        n, = struct.unpack(">I", data[pos:pos + 4])
        t, d = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
        crc = data[pos + 8 + n:pos + 12 + n]
        if len(d) != n or len(crc) != 4 or struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF) != crc:
            raise ValueError("damaged PNG chunk")
        pos += 12 + n
        if t == b"IHDR": ihdr = d
        elif t == b"IDAT": idat.append(d)
        elif t == b"IEND": break
    if not ihdr or len(ihdr) != 13 or not idat:
        raise ValueError("PNG has no header or no image data")
    w, h, depth, ct, _c, _f, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth != 8 or ct not in (0, 2, 6) or interlace:
        raise ValueError("only 8-bit grey/RGB/RGBA, non-interlaced PNG is supported")
    if w < 1 or h < 1 or w * h > MAXPX:
        raise ValueError(f"image must be at most {MAXPX} pixels")
    bpp = {0: 1, 2: 3, 6: 4}[ct]
    stride = w * bpp
    try:
        raw = zlib.decompressobj().decompress(b"".join(idat), (stride + 1) * h)
    except zlib.error:
        raise ValueError("damaged PNG data") from None
    if len(raw) != (stride + 1) * h:
        raise ValueError("PNG data has the wrong length")
    prev, out = bytearray(stride), []
    for y in range(h):
        ft, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b, c = prev[i], (prev[i - bpp] if i >= bpp else 0)
            if ft == 1: p = a
            elif ft == 2: p = b
            elif ft == 3: p = (a + b) >> 1
            elif ft == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                p = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
            elif ft == 0: p = 0
            else: raise ValueError("unknown PNG filter")
            line[i] = (line[i] + p) & 255
        prev = line
        if ct == 0: out.append([(v, v, v) for v in line])
        else: out.append([tuple(line[i:i + 3]) for i in range(0, stride, bpp)])
    return out


def ppm_parse(text: str) -> list:
    """ASCII PPM (P3) text -> rows of (r,g,b). Raises ValueError."""
    toks = re.sub(r"#[^\n]*", "", text).split()
    if len(toks) < 4 or toks[0] != "P3":
        raise ValueError("expected ASCII PPM text starting with P3")
    try:
        w, h, mx = int(toks[1]), int(toks[2]), int(toks[3])
        vals = [int(t) for t in toks[4:4 + w * h * 3]] if 0 < w * h <= MAXPX else None
    except ValueError:
        raise ValueError("PPM numbers must be whole numbers") from None
    if vals is None or not 0 < mx < 65536 or len(vals) != w * h * 3 or min(vals) < 0 or max(vals) > mx:
        raise ValueError(f"PPM header/values are wrong (at most {MAXPX} pixels, values 0..maxval)")
    vals = [v * 255 // mx for v in vals]
    return [[tuple(vals[(y * w + x) * 3:(y * w + x) * 3 + 3]) for x in range(w)] for y in range(h)]


def ppm_text(rows: list) -> str:
    return f"P3\n{len(rows[0])} {len(rows)}\n255\n" + "\n".join(" ".join(str(v) for px in r for v in px) for r in rows) + "\n"


# ------------------------------------------------ File Format Converter ----
def _cell(v) -> str:
    if v is None: return ""
    if isinstance(v, str): return v
    return json.dumps(v, ensure_ascii=False)


def _unique(names: list) -> list:
    seen, out = Counter(), []
    for n in names:
        seen[n] += 1
        out.append(n if seen[n] == 1 else f"{n}_{seen[n]}")
    return out


def _check_rows(rows: list) -> list:
    if len(rows) > MAXROWS or any(len(r) > MAXCOLS for r in rows):
        raise ValueError(f"at most {MAXROWS} rows and {MAXCOLS} columns")
    return rows


def _from_dicts(items: list) -> list:
    head: list = []
    for d in items:
        if not isinstance(d, dict): raise ValueError("expected an object per row")
        head += [k for k in d if k not in head]
    return _check_rows([head] + [[_cell(d.get(k)) for k in head] for d in items])


def rows_from(text: str, fmt: str) -> list:
    """Text in `fmt` -> rows (first row = header). Raises ValueError."""
    if len(text) > MAXTEXT: raise ValueError(f"input is longer than {MAXTEXT} characters")
    try:
        if fmt in ("csv", "tsv"):
            rows = [r for r in csv.reader(io.StringIO(text), delimiter="," if fmt == "csv" else "\t") if r]
        elif fmt == "json":
            data = json.loads(text)
            if not isinstance(data, list): raise ValueError("expected a JSON array")
            if data and all(isinstance(r, list) for r in data): rows = [[_cell(c) for c in r] for r in data]
            else: return _from_dicts(data)
        elif fmt == "jsonl":
            return _from_dicts([json.loads(l) for l in text.splitlines() if l.strip()])
        elif fmt == "xml":
            if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I): raise ValueError("DOCTYPE/ENTITY is not allowed")
            root = ET.fromstring(text)
            if root.tag != "table": raise ValueError("expected a <table> element")
            items = [{f.get("name", ""): f.text or "" for f in r.findall("field")} for r in root.findall("row")]
            return _from_dicts(items)
        else:
            raise ValueError("unknown format " + fmt)
    except (csv.Error, json.JSONDecodeError, ET.ParseError, RecursionError) as e:
        raise ValueError(f"cannot read {fmt}: {e}") from None
    return _check_rows(rows)


def rows_to(rows: list, fmt: str) -> str:
    if not rows: return ""
    if fmt in ("csv", "tsv"):
        buf = io.StringIO()
        csv.writer(buf, delimiter="," if fmt == "csv" else "\t", lineterminator="\n").writerows(rows)
        return buf.getvalue()
    head = _unique([str(h) for h in rows[0]])
    recs = [dict(zip(head, r + [""] * (len(head) - len(r)))) for r in rows[1:]]
    if fmt == "json": return json.dumps(recs, indent=2, ensure_ascii=False) + "\n"
    if fmt == "jsonl": return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in recs)
    if fmt == "xml":
        bad = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
        esc = lambda s: html.escape(bad.sub("", s), quote=True)
        out = ['<?xml version="1.0" encoding="UTF-8"?>', "<table>"]
        for r in recs:
            out.append("<row>" + "".join(f'<field name="{esc(k)}">{esc(v)}</field>' for k, v in r.items()) + "</row>")
        return "\n".join(out + ["</table>"]) + "\n"
    raise ValueError("unknown format " + fmt)


_URL_OK = ("http://", "https://", "mailto:")


def md_inline(s: str) -> str:
    """Escape everything, then add a few tags. Links only for http(s), mailto or relative paths."""
    def link(m):
        raw = html.unescape(m.group(2))
        low = re.sub(r"[\x00-\x20]", "", raw).lower()
        if low.startswith("//") or not (low.startswith(_URL_OK) or ":" not in low):
            return m.group(0)
        return f'<a href="{m.group(2)}" rel="noopener noreferrer">{m.group(1)}</a>'

    out = []
    for seg in re.split(r"(`[^`]+`)", s):
        if len(seg) > 2 and seg[0] == "`" and seg[-1] == "`":
            out.append("<code>" + html.escape(seg[1:-1]) + "</code>")
            continue
        e = html.escape(seg)
        e = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", e)
        e = re.sub(r"\*(.+?)\*", r"<em>\1</em>", e)
        out.append(re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, e))
    return "".join(out)


def md_to_html(text: str) -> str:
    """Headings, paragraphs, lists, quotes, rules, code fences, bold/italic/code/links. No raw HTML ever."""
    if len(text) > MAXTEXT: raise ValueError(f"input is longer than {MAXTEXT} characters")
    out, para, lst, code = [], [], None, None

    def flush():
        nonlocal para, lst
        if para: out.append("<p>" + md_inline(" ".join(para)) + "</p>")
        if lst: out.append(f"</{lst}>")
        para, lst = [], None

    for line in text.splitlines():
        if code is not None:
            if line.strip().startswith("```"): out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>"); code = None
            else: code.append(line)
            continue
        s = line.strip()
        m, ul, ol = re.match(r"(#{1,6})\s+(.*)", s), re.match(r"[-*+]\s+(.*)", s), re.match(r"\d+[.)]\s+(.*)", s)
        if s.startswith("```"): flush(); code = []
        elif not s: flush()
        elif m: flush(); out.append(f"<h{len(m.group(1))}>{md_inline(m.group(2))}</h{len(m.group(1))}>")
        elif re.fullmatch(r"(-{3,}|\*{3,}|_{3,})", s): flush(); out.append("<hr>")
        elif s.startswith(">"): flush(); out.append("<blockquote>" + md_inline(s.lstrip("> ")) + "</blockquote>")
        elif ul or ol:
            kind = "ul" if ul else "ol"
            if lst != kind: flush(); out.append(f"<{kind}>"); lst = kind
            out.append("<li>" + md_inline((ul or ol).group(1)) + "</li>")
        else:
            if lst: flush()
            para.append(s)
    if code is not None: out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
    flush()
    return "\n".join(out) + "\n"


def _b64_dec(t: str) -> str:
    try: return base64.b64decode("".join(t.split()), validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError): raise ValueError("not valid base64") from None


def _hex_dec(t: str) -> str:
    try: return bytes.fromhex("".join(t.split())).decode("utf-8", "replace")
    except ValueError: raise ValueError("not valid hex") from None


def _png_to_ppm(t: str) -> str:
    try: data = base64.b64decode("".join(t.split()), validate=True)
    except (binascii.Error, ValueError): raise ValueError("expected a base64-encoded PNG") from None
    return ppm_text(png_decode(data))


def _ppm_to_png(t: str) -> str:
    return base64.b64encode(png_encode(ppm_parse(t))).decode()


TABLES = ["csv", "tsv", "json", "jsonl", "xml"]
CONVERSIONS: dict = {}
for _a in TABLES:
    for _b in TABLES:
        if _a != _b:
            CONVERSIONS[f"{_a} > {_b}"] = (lambda t, a=_a, b=_b: rows_to(rows_from(t, a), b))
CONVERSIONS.update({
    "markdown > html": md_to_html,
    "text > base64": lambda t: base64.b64encode(t[:MAXTEXT].encode()).decode(),
    "base64 > text": _b64_dec,
    "text > hex": lambda t: t[:MAXTEXT].encode().hex(),
    "hex > text": _hex_dec,
    "ppm (P3 text) > png (base64)": _ppm_to_png,
    "png (base64) > ppm (P3 text)": _png_to_ppm,
})


def convert(name: str, text: str) -> str:
    if name not in CONVERSIONS: raise ValueError("unknown conversion")
    return CONVERSIONS[name](text)


def make_converter(host, entry) -> Screen:
    def result(ed, name):
        try: out = convert(name, ed.area.text)
        except ValueError as e: return ("push", Message("Cannot convert", [str(e)]))
        note = put_safe(host, "last-output", out)
        return ("push", TextView(f"Result ({note})", chunk_lines(out)))

    def editor(name):
        hint = "Ctrl-R convert"
        ed = Editor(name, host.get("input") or "", on_save=lambda t: host.put("input", t[:MAXVAULT]),
                    extra_keys={"ctrl-r": lambda e, n=name: result(e, n)}, hint=hint)
        return ("push", ed)

    names = list(CONVERSIONS)
    return Menu("File Format Converter", [(n, lambda n=n: editor(n)) for n in names],
                ["Pick a conversion, paste text, Ctrl-R converts (Ctrl-S saves the input).", "Text and small images only."])


# ----------------------------------------------------------- 3D viewer ----
MAXV, MAXT, MAXLINES = 5000, 10000, 40000


class Mesh:
    def __init__(self, verts, tris, name="model", bad=0):
        self.verts, self.tris, self.name, self.bad = verts, tris, name, bad


def parse_obj(text: str) -> Mesh:
    """Wavefront OBJ: `v` and `f` lines only. Bad lines are counted and skipped, never fatal."""
    verts, raw, bad = [], [], 0
    for line in text[:MAXTEXT].splitlines()[:MAXLINES]:
        p = line.split()
        if not p or p[0].startswith("#"): continue
        if p[0] == "v" and len(p) >= 4:
            try: xyz = tuple(float(a) for a in p[1:4])
            except ValueError: bad += 1; continue
            if len(verts) < MAXV and all(math.isfinite(a) and abs(a) <= 1e6 for a in xyz): verts.append(xyz)
            else: bad += 1
        elif p[0] == "f" and len(p) >= 4:
            raw.append((p[1:17], len(verts)))
    tris = []
    for toks, n_then in raw:
        idx = []
        for tok in toks:
            try: i = int(tok.split("/")[0])
            except ValueError: idx = None; break
            j = i - 1 if i > 0 else n_then + i
            if i == 0 or not 0 <= j < len(verts): idx = None; break
            idx.append(j)
        if idx is None or len(idx) < 3: bad += 1; continue
        for k in range(1, len(idx) - 1):
            if len(tris) < MAXT: tris.append((idx[0], idx[k], idx[k + 1]))
    return Mesh(verts, tris, "model", bad)


def _sub(a, b): return (a[0] - b[0], a[1] - b[1], a[2] - b[2])
def _cross(a, b): return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])
def _dot(a, b): return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def bbox(m: Mesh):
    if not m.verts: return None
    return tuple(min(v[i] for v in m.verts) for i in range(3)), tuple(max(v[i] for v in m.verts) for i in range(3))


def area(m: Mesh) -> float:
    total = 0.0
    for a, b, c in m.tris:
        cr = _cross(_sub(m.verts[b], m.verts[a]), _sub(m.verts[c], m.verts[a]))
        total += 0.5 * math.sqrt(_dot(cr, cr))
    return total


def signed_volume(m: Mesh) -> float:
    return sum(_dot(m.verts[a], _cross(m.verts[b], m.verts[c])) for a, b, c in m.tris) / 6.0


def is_closed(m: Mesh) -> bool:
    """Every edge is used once in each direction (after welding equal vertices): a consistently oriented closed surface."""
    if len(m.tris) < 4: return False
    weld, canon = {}, []
    for v in m.verts: canon.append(weld.setdefault(tuple(round(c, 6) for c in v), len(weld)))
    edges = Counter()
    for a, b, c in m.tris:
        a, b, c = canon[a], canon[b], canon[c]
        if a == b or b == c or a == c: return False
        edges.update([(a, b), (b, c), (c, a)])
    return all(n == 1 and edges.get((y, x)) == 1 for (x, y), n in edges.items())


def volume(m: Mesh):
    """Volume of a closed, consistently wound mesh, else None."""
    return abs(signed_volume(m)) if is_closed(m) else None


def _outward(verts, tris, name) -> Mesh:
    m = Mesh(verts, tris, name)
    if signed_volume(m) < 0: m.tris = [(a, c, b) for a, b, c in tris]
    return m


def primitive(kind: str) -> Mesh:
    if kind == "cube":
        v = [(x - .5, y - .5, z - .5) for z in (0, 1) for y in (0, 1) for x in (0, 1)]
        quads = [(0, 4, 6, 2), (1, 3, 7, 5), (0, 1, 5, 4), (2, 6, 7, 3), (0, 2, 3, 1), (4, 5, 7, 6)]
        return Mesh(v, [t for q in quads for t in ((q[0], q[1], q[2]), (q[0], q[2], q[3]))], "cube")
    if kind == "pyramid":
        v = [(-.5, 0, -.5), (.5, 0, -.5), (.5, 0, .5), (-.5, 0, .5), (0, 1, 0)]
        return Mesh(v, [(0, 1, 2), (0, 2, 3)] + [(i, 4, (i + 1) % 4) for i in range(4)], "pyramid")
    if kind == "sphere":
        st, sl, r = 8, 12, 0.5
        v = [(0, r, 0)] + [(r * math.sin(math.pi * i / st) * math.cos(2 * math.pi * j / sl), r * math.cos(math.pi * i / st),
                            r * math.sin(math.pi * i / st) * math.sin(2 * math.pi * j / sl))
                           for i in range(1, st) for j in range(sl)] + [(0, -r, 0)]
        n, t = len(v) - 1, []
        for j in range(sl): t.append((0, 1 + j, 1 + (j + 1) % sl))
        for i in range(st - 2):
            for j in range(sl):
                a, b = 1 + i * sl + j, 1 + i * sl + (j + 1) % sl
                t += [(a, a + sl, b + sl), (a, b + sl, b)]
        s = 1 + (st - 2) * sl
        for j in range(sl): t.append((n, s + (j + 1) % sl, s + j))
        return _outward(v, t, "sphere")
    if kind == "torus":
        nu, nv, R, r = 16, 8, 0.4, 0.15
        v = [((R + r * math.cos(2 * math.pi * j / nv)) * math.cos(2 * math.pi * i / nu), r * math.sin(2 * math.pi * j / nv),
              (R + r * math.cos(2 * math.pi * j / nv)) * math.sin(2 * math.pi * i / nu)) for i in range(nu) for j in range(nv)]
        t = []
        for i in range(nu):
            for j in range(nv):
                a, b = i * nv + j, ((i + 1) % nu) * nv + j
                c, d = ((i + 1) % nu) * nv + (j + 1) % nv, i * nv + (j + 1) % nv
                t += [(a, b, c), (a, c, d)]
        return _outward(v, t, "torus")
    raise ValueError("unknown primitive")


def _num(v: float) -> str: return f"{v:.6g}"


def to_stl(m: Mesh) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]", "_", m.name)[:40] or "model"
    out = [f"solid {name}"]
    for a, b, c in m.tris:
        A, B, C = m.verts[a], m.verts[b], m.verts[c]
        n = _cross(_sub(B, A), _sub(C, A))
        ln = math.sqrt(_dot(n, n)) or 1.0
        out.append("facet normal " + " ".join(_num(x / ln) for x in n))
        out.append("  outer loop")
        out += ["    vertex " + " ".join(_num(x) for x in p) for p in (A, B, C)]
        out += ["  endloop", "endfacet"]
    return "\n".join(out + [f"endsolid {name}"]) + "\n"


def to_obj(m: Mesh) -> str:
    return "\n".join(["# KOS 3D Model Viewer"] + ["v " + " ".join(_num(x) for x in v) for v in m.verts]
                     + [f"f {a + 1} {b + 1} {c + 1}" for a, b, c in m.tris]) + "\n"


def wire(m: Mesh, yaw: float, pitch: float, zoom: float, W: int, H: int, xs: float = 1.0) -> list:
    """Orthographic wireframe as integer segments (x0,y0,x1,y1) inside a W x H area. xs stretches x (text cells are 2:1)."""
    if not m.verts: return []
    lo, hi = bbox(m)
    c = [(lo[i] + hi[i]) / 2 for i in range(3)]
    rad = max(math.sqrt(sum((v[i] - c[i]) ** 2 for i in range(3))) for v in m.verts) or 1.0
    k = max(0.05, min(zoom, 50)) * 0.45 * min(W / xs, H) / rad
    cy_, sy_, cp, sp = math.cos(yaw), math.sin(yaw), math.cos(pitch), math.sin(pitch)
    pts = []
    for v in m.verts:
        x, y, z = v[0] - c[0], v[1] - c[1], v[2] - c[2]
        x, z = x * cy_ + z * sy_, -x * sy_ + z * cy_
        y = y * cp - z * sp
        pts.append((max(-9999, min(9999, round(W / 2 + xs * k * x))), max(-9999, min(9999, round(H / 2 - k * y)))))
    edges = set()
    for a, b, d in m.tris:
        for u, v in ((a, b), (b, d), (d, a)): edges.add((min(u, v), max(u, v)))
    return [(*pts[a], *pts[b]) for a, b in sorted(edges)[:4000]]


def ascii_wire(segs: list, W: int, H: int) -> list:
    g = [[" "] * W for _ in range(H)]
    for x0, y0, x1, y1 in segs:
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx, sy, err = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1), dx + dy
        for _ in range(dx - dy + 2):
            if 0 <= x0 < W and 0 <= y0 < H: g[y0][x0] = "#"
            if x0 == x1 and y0 == y1: break
            e2 = 2 * err
            if e2 >= dy: err += dy; x0 += sx
            if e2 <= dx: err += dx; y0 += sy
    return ["".join(r) for r in g]


def info_lines(m: Mesh) -> list:
    bb = bbox(m)
    if not bb: return ["empty model"]
    v = volume(m)
    return [f"{m.name}: {len(m.verts)} vertices, {len(m.tris)} triangles" + (f", {m.bad} bad lines skipped" if m.bad else ""),
            "bounding box min " + " ".join(_num(x) for x in bb[0]) + "  max " + " ".join(_num(x) for x in bb[1]),
            "size " + " x ".join(_num(bb[1][i] - bb[0][i]) for i in range(3)),
            f"surface area {area(m):.6g}", "volume " + (f"{v:.6g}" if v is not None else "n/a (mesh is not a closed, consistently wound surface)")]


class Viewer(Screen):
    title = "3D Model Viewer"
    KINDS = {"1": "cube", "2": "pyramid", "3": "sphere", "4": "torus"}

    def __init__(self, host):
        self.host, self.yaw, self.pitch, self.zoom, self.msg = host, 0.6, 0.4, 1.0, ""
        self.mesh = primitive("cube")
        saved = host.get("model.obj")
        if saved:
            m = parse_obj(saved)
            if m.tris: self.mesh = m
        self.help = "arrows rotate  +/- zoom  1-4 shapes  o load OBJ  i info  x STL  e OBJ  r reset"

    def canvas(self, w, h):
        c = Canvas().clear("#101418")
        for x0, y0, x1, y1 in wire(self.mesh, self.yaw, self.pitch, self.zoom, w, h - 14):
            c.line(x0, y0 + 14, x1, y1 + 14, "#7fd1ff")
        return c.text(3, 2, f"{self.mesh.name} {len(self.mesh.tris)} tris  {self.msg}"[:100], "#ffffff")

    def render(self, w, h):
        rows = max(4, h - 4)
        segs = wire(self.mesh, self.yaw, self.pitch, self.zoom, max(10, w - 2), rows, 2.0)
        return [" " + r for r in ascii_wire(segs, max(10, w - 2), rows)] + [" " + info_lines(self.mesh)[0][:w - 2], " " + self.msg]

    def key(self, k):
        self.msg = ""
        step = math.radians(15)
        if k == "left": self.yaw -= step
        elif k == "right": self.yaw += step
        elif k == "up": self.pitch -= step
        elif k == "down": self.pitch += step
        elif k in ("+", "="): self.zoom = min(8.0, self.zoom * 1.2)
        elif k == "-": self.zoom = max(0.2, self.zoom / 1.2)
        elif k == "r": self.yaw, self.pitch, self.zoom = 0.6, 0.4, 1.0
        elif k in self.KINDS: self.mesh = primitive(self.KINDS[k])
        elif k == "i": return ("push", TextView("Model info", info_lines(self.mesh)))
        elif k == "x": self.msg = put_safe(self.host, "export-model.stl", to_stl(self.mesh))
        elif k == "e": self.msg = put_safe(self.host, "export-model.obj", to_obj(self.mesh))
        elif k == "o":
            def save(text):
                m = parse_obj(text)
                if m.tris:
                    self.mesh = m
                    self.host.put("model.obj", text[:MAXVAULT])
            return ("push", Editor("Paste OBJ", self.host.get("model.obj") or "", on_save=save, hint="Ctrl-S load"))


# --------------------------------------------------------- Avatar Maker ----
N = 16
OPT = [("face", 3), ("hair", 4), ("eyes", 4), ("mouth", 4), ("skin", 6), ("haircol", 8), ("bg", 6)]
NAMES = {"face": ["round", "oval", "square"], "hair": ["none", "short", "long", "spiky"], "eyes": ["dot", "wide", "sleepy", "glasses"],
         "mouth": ["smile", "flat", "open", "smirk"]}
SKIN = ["#f9d5b8", "#e8b98d", "#c68e5b", "#8d5a36", "#5b3a24", "#fbe7c6"]
HAIRC = ["#2b1b10", "#5a3a1a", "#b5651d", "#e6c15a", "#c0392b", "#8e44ad", "#3b82c4", "#d8d8d8"]
BGC = ["#cfe8f3", "#f3e1cf", "#d9f0d2", "#eadcf5", "#f5f0c8", "#444a54"]
INK, WHITE, LIP = "#2a1a1a", "#ffffff", "#8b1a1a"


def hex_rgb(h: str) -> tuple:
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def seed_parts(seed: int) -> dict:
    """Deterministic parts from a seed (xorshift32, no randomness from the system)."""
    x = (int(seed) * 2654435761 + 12345) & 0xFFFFFFFF or 1
    out = {}
    for k, n in OPT:
        x ^= (x << 13) & 0xFFFFFFFF; x ^= x >> 17; x ^= (x << 5) & 0xFFFFFFFF
        out[k] = x % n
    return out


def _face(shape, x, y, g=0.0):
    if shape == 0: return ((x - 7.5) / (5.5 + g)) ** 2 + ((y - 8.5) / (5.5 + g)) ** 2 <= 1
    if shape == 1: return ((x - 7.5) / (4.5 + g)) ** 2 + ((y - 8) / (6 + g)) ** 2 <= 1
    return 3 - g <= x <= 12 + g and 3 - g <= y <= 13 + g


def avatar_rows(p: dict, over: dict | None = None) -> list:
    """16x16 grid of (r,g,b) from a parts dict (indices are taken modulo the option count)."""
    q = {k: int(p.get(k, 0)) % n for k, n in OPT}
    g = [[hex_rgb(BGC[q["bg"]])] * N for _ in range(N)]
    skin, hair = hex_rgb(SKIN[q["skin"]]), hex_rgb(HAIRC[q["haircol"]])
    over = over or {}
    hair = over.get("hair", hair)
    if "bg" in over: g = [[over["bg"]] * N for _ in range(N)]
    ink, white, lip = hex_rgb(INK), hex_rgb(WHITE), hex_rgb(LIP)
    sh, hs = q["face"], q["hair"]

    def put(x, y, c):
        if 0 <= x < N and 0 <= y < N: g[y][x] = c

    for y in range(N):
        for x in range(N):
            if hs == 2 and 3 <= y <= 14 and _face(sh, x, y, 2): put(x, y, hair)            # long hair behind the face
    for y in range(N):
        for x in range(N):
            if _face(sh, x, y): put(x, y, skin)
    if hs:
        for y in range(6):
            for x in range(N):
                if _face(sh, x, y, 1): put(x, y, hair)
        if hs == 3:
            for x in (4, 7, 10):
                put(x, 1, hair); put(x, 2, hair)
    e = q["eyes"]
    for cx in (5, 10):
        if e == 0: put(cx, 7, ink)
        elif e == 1:
            for dx in (-1, 0):
                for dy in (6, 7): put(cx + dx, dy, white)
            put(cx, 7, ink)
        elif e == 2:
            put(cx - 1, 7, ink); put(cx, 7, ink)
        else:
            for dx in range(-2, 2):
                put(cx + dx, 6, ink); put(cx + dx, 8, ink)
            put(cx - 2, 7, ink); put(cx + 1, 7, ink); put(cx, 7, ink)
    if e == 3: put(7, 7, ink); put(8, 7, ink)
    m = q["mouth"]
    if m == 0:
        for x, y in ((5, 10), (6, 11), (7, 11), (8, 11), (9, 11), (10, 10)): put(x, y, ink)
    elif m == 1 or m == 3:
        for x in range(6, 10): put(x, 11, ink)
        if m == 3: put(10, 10, ink)
    else:
        for x in (7, 8):
            for y in (11, 12): put(x, y, lip)
    return g


def avatar_svg(rows: list, cell: int = 16) -> str:
    h, w = len(rows), len(rows[0])
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w * cell}" height="{h * cell}" shape-rendering="crispEdges">']
    for y, r in enumerate(rows):
        x = 0
        while x < w:
            x2 = x
            while x2 + 1 < w and r[x2 + 1] == r[x]: x2 += 1
            out.append(f'<rect x="{x * cell}" y="{y * cell}" width="{(x2 - x + 1) * cell}" height="{cell}" fill="#%02x%02x%02x"/>' % tuple(r[x]))
            x = x2 + 1
    return "".join(out) + "</svg>"


class Avatar(Screen):
    title = "Avatar Maker"

    def __init__(self, host):
        self.host, self.msg, self.sel, self.over, self.pi = host, "", 0, {}, -1
        try: self.parts = {k: int(v) % n for (k, n), v in zip(OPT, json.loads(host.get("avatar") or "[]"))}
        except (ValueError, TypeError): self.parts = {}
        if len(self.parts) != len(OPT): self.parts = seed_parts(1)
        self.help = "up/down part  left/right change  r random  d seed  c palette  s save  p PNG  v SVG"

    def label(self, k, i):
        return NAMES[k][i] if k in NAMES else f"#{i + 1}"

    def canvas(self, w, h):
        c = Canvas().clear("#202020")
        rows, cell = avatar_rows(self.parts, self.over), max(4, min(w - 160, h - 20) // N)
        for y, r in enumerate(rows):
            for x, px in enumerate(r): c.rect(8 + x * cell, 16 + y * cell, cell, cell, "#%02x%02x%02x" % tuple(px))
        for i, (k, n) in enumerate(OPT):
            c.text(16 + N * cell, 18 + i * 12, ("> " if i == self.sel else "  ") + f"{k}: {self.label(k, self.parts[k])}", "#ffffff")
        return c.text(3, 2, self.msg or "Avatar Maker", "#ffffff")

    def render(self, w, h):
        rows, chars, legend = avatar_rows(self.parts, self.over), {}, " .:-=+*#%@"
        art = []
        for r in rows:
            line = ""
            for px in r: line += chars.setdefault(px, legend[len(chars) % len(legend)]) * 2
            art.append("  " + line)
        side = [("> " if i == self.sel else "  ") + f"{k}: {self.label(k, self.parts[k])}" for i, (k, n) in enumerate(OPT)]
        return art[:h - 2] + [""] + side[:max(0, h - len(art) - 2)] + ["  " + self.msg]

    def save(self):
        return self.host.put("avatar", json.dumps([self.parts[k] for k, _n in OPT]))

    def key(self, k):
        self.msg = ""
        name, n = OPT[self.sel]
        if k == "up": self.sel = (self.sel - 1) % len(OPT)
        elif k == "down": self.sel = (self.sel + 1) % len(OPT)
        elif k == "left": self.parts[name] = (self.parts[name] - 1) % n
        elif k == "right": self.parts[name] = (self.parts[name] + 1) % n
        elif k == "r":
            self.seed = getattr(self, "seed", 0) + 1; self.parts = seed_parts(self.seed)
        elif k == "d":
            def got(t):
                try: self.parts = seed_parts(int(t.strip()[:12] or "0"))
                except ValueError: self.parts = seed_parts(sum(map(ord, t)))
            return ("push", Prompt("Seed", "Seed (a number or any text):", on_done=got))
        elif k == "c":
            pals, note = shared_palettes(self.host)
            if not pals: self.over, self.msg = {}, note[:90]
            else:
                self.pi = (self.pi + 1) % len(pals); name, cols = pals[self.pi]
                self.over = {"hair": cols[0], "bg": cols[-1]}; self.msg = f"palette {name}"
        elif k == "s": self.msg = "saved" if self.save() else "could not save"
        elif k == "p": self.msg = put_safe(self.host, "export-avatar.png.b64", base64.b64encode(png_encode(avatar_rows(self.parts, self.over))).decode())
        elif k == "v": self.msg = put_safe(self.host, "export-avatar.svg", avatar_svg(avatar_rows(self.parts, self.over)))


# ------------------------------------------------------- Animation Maker ----
MAXKF, MAXTIME, SIZE = 50, 60.0, 200
SHAPES = ("circle", "rect", "triangle")
DEMO = "0 circle 30 100 30 #e74c3c\n1 circle 100 40 50 #f1c40f\n2 rect 170 100 40 #3498db\n3 triangle 100 160 60 #2ecc71\n"
_HEX = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})")


def parse_keyframes(text: str):
    """Lines `time shape x y size #colour` -> (sorted keyframes, list of "line N: reason")."""
    frames, errs = [], []
    for n, line in enumerate(text[:20000].splitlines(), 1):
        if not line.strip() or line.strip().startswith("#"): continue
        p = line.split()
        try:
            if len(p) != 6 or p[1] not in SHAPES or not _HEX.fullmatch(p[5]): raise ValueError("need: time shape x y size #colour")
            t, x, y, s = (float(v) for v in (p[0], p[2], p[3], p[4]))
            if not all(math.isfinite(v) for v in (t, x, y, s)) or not 0 <= t <= MAXTIME or not 0 <= x <= SIZE or not 0 <= y <= SIZE or not 1 <= s <= SIZE:
                raise ValueError(f"time 0..{MAXTIME:g}, x/y 0..{SIZE}, size 1..{SIZE}")
            col = p[5].lower()
            if len(col) == 4: col = "#" + "".join(c * 2 for c in col[1:])
        except ValueError as e:
            errs.append(f"line {n}: {e}"); continue
        if len(frames) >= MAXKF: errs.append(f"line {n}: at most {MAXKF} keyframes"); break
        frames.append({"t": t, "shape": p[1], "x": x, "y": y, "size": s, "color": col})
    return sorted(frames, key=lambda f: f["t"]), errs


def _mix(a: str, b: str, f: float) -> str:
    return "#%02x%02x%02x" % tuple(int(hex_rgb(a)[i] + (hex_rgb(b)[i] - hex_rgb(a)[i]) * f + 0.5) for i in range(3))


def state_at(frames: list, t: float) -> dict:
    """Interpolated keyframe at time t (numbers and colour linear, shape steps)."""
    if t <= frames[0]["t"]: return dict(frames[0])
    for a, b in zip(frames, frames[1:]):
        if a["t"] <= t < b["t"]:
            f = (t - a["t"]) / (b["t"] - a["t"])
            out = {k: a[k] + (b[k] - a[k]) * f for k in ("x", "y", "size")}
            return {**out, "t": t, "shape": a["shape"], "color": _mix(a["color"], b["color"], f)}
    return dict(frames[-1])


def _f(v: float) -> str:
    return ("%.3f" % v).rstrip("0").rstrip(".") or "0"


def anim_svg(frames: list, title: str = "animation") -> str:
    """SMIL animated SVG, 200x200 viewBox. All text is escaped."""
    if not frames: raise ValueError("no keyframes")
    fs = [dict(f) for f in frames[:MAXKF]]
    if fs[0]["t"] > 0: fs.insert(0, {**fs[0], "t": 0.0})
    if fs[-1]["t"] <= 0: fs.append({**fs[-1], "t": 1.0})
    dur = fs[-1]["t"]
    kt = ";".join(_f(f["t"] / dur) for f in fs)
    anim = lambda attr, vals, extra="": f'<animate attributeName="{attr}" values="{";".join(vals)}" keyTimes="{kt}" dur="{_f(dur)}s" repeatCount="indefinite"{extra}/>'
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}" width="{SIZE * 2}" height="{SIZE * 2}">',
           f"<title>{html.escape(title, quote=True)}</title>", f'<rect width="{SIZE}" height="{SIZE}" fill="#ffffff"/>']
    for shape in [s for s in SHAPES if any(f["shape"] == s for f in fs)]:
        f0, col = fs[0], [f["color"] for f in fs]
        if shape == "circle":
            head, attrs = f'<circle cx="{_f(f0["x"])}" cy="{_f(f0["y"])}" r="{_f(f0["size"] / 2)}" fill="{f0["color"]}"', [
                anim("cx", [_f(f["x"]) for f in fs]), anim("cy", [_f(f["y"]) for f in fs]), anim("r", [_f(f["size"] / 2) for f in fs])]
        elif shape == "rect":
            head, attrs = f'<rect x="{_f(f0["x"] - f0["size"] / 2)}" y="{_f(f0["y"] - f0["size"] / 2)}" width="{_f(f0["size"])}" height="{_f(f0["size"])}" fill="{f0["color"]}"', [
                anim("x", [_f(f["x"] - f["size"] / 2) for f in fs]), anim("y", [_f(f["y"] - f["size"] / 2) for f in fs]),
                anim("width", [_f(f["size"]) for f in fs]), anim("height", [_f(f["size"]) for f in fs])]
        else:
            pts = lambda f: f'{_f(f["x"])},{_f(f["y"] - f["size"] / 2)} {_f(f["x"] + f["size"] / 2)},{_f(f["y"] + f["size"] / 2)} {_f(f["x"] - f["size"] / 2)},{_f(f["y"] + f["size"] / 2)}'
            head, attrs = f'<polygon points="{pts(f0)}" fill="{f0["color"]}"', [anim("points", [pts(f) for f in fs])]
        attrs.append(anim("fill", col))
        attrs.append(anim("opacity", ["1" if f["shape"] == shape else "0" for f in fs], ' calcMode="discrete"'))
        out.append(head + f' opacity="{"1" if f0["shape"] == shape else "0"}">' + "".join(attrs) + f"</{head[1:head.index(' ')]}>")
    return "\n".join(out + ["</svg>"]) + "\n"


def shape_rows(shape: str, x: float, y: float, size: float) -> list:
    """Scanline spans (x, y, width) in 200x200 space for the preview."""
    r, rows = size / 2, []
    for yy in range(max(0, int(y - r)), min(SIZE, int(y + r) + 1)):
        if shape == "circle": half = math.sqrt(max(0.0, r * r - (yy + .5 - y) ** 2))
        elif shape == "rect": half = r
        else: half = max(0.0, (yy - (y - r)) / size * r)
        if half > 0: rows.append((int(max(0, x - half)), yy, max(1, int(min(SIZE, x + half)) - int(max(0, x - half)))))
    return rows


class Animator(Screen):
    title = "Animation Maker"
    STEPS = 20

    def __init__(self, host):
        self.host, self.msg, self.i, self.name, self.pi = host, "", 0, "animation", -1
        self.text = host.get("keyframes") or DEMO
        self.frames, errs = parse_keyframes(self.text)
        if not self.frames: self.text = DEMO; self.frames, _ = parse_keyframes(DEMO)
        self.help = "left/right frame  e edit  x export SVG  n name  d demo  c palette colours"

    def now(self):
        dur = self.frames[-1]["t"]
        return state_at(self.frames, dur * self.i / self.STEPS), dur * self.i / self.STEPS

    def canvas(self, w, h):
        st, t = self.now()
        c, sc = Canvas().clear("#e8e8e8"), max(1, min(w, h - 14) // SIZE)
        c.rect(0, 14, SIZE * sc, SIZE * sc, "#ffffff")
        for x, y, wd in shape_rows(st["shape"], st["x"], st["y"], st["size"]):
            c.rect(x * sc, 14 + y * sc, wd * sc, sc, st["color"])
        return c.text(3, 2, f"frame {self.i}/{self.STEPS}  t={t:.2f}s  {st['shape']}  {self.msg}"[:100], "#111111")

    def render(self, w, h):
        st, t = self.now()
        cols, rows = 40, 20
        g = [["."] * cols for _ in range(rows)]
        for x, y, wd in shape_rows(st["shape"], st["x"], st["y"], st["size"]):
            for cx in range(x // 5, min(cols, (x + wd - 1) // 5 + 1)): g[min(rows - 1, y // 10)][cx] = "#"
        return ([f" frame {self.i}/{self.STEPS}  t={t:.2f}s  {st['shape']} at ({st['x']:.0f},{st['y']:.0f}) size {st['size']:.0f} {st['color']}"]
                + [" " + "".join(r) for r in g][:max(1, h - 3)] + [" " + self.msg])

    def key(self, k):
        self.msg = ""
        if k == "right": self.i = min(self.STEPS, self.i + 1)
        elif k == "left": self.i = max(0, self.i - 1)
        elif k == "home": self.i = 0
        elif k == "end": self.i = self.STEPS
        elif k == "d": self.text = DEMO; self.frames, _ = parse_keyframes(DEMO); self.host.put("keyframes", DEMO); self.msg = "demo loaded"
        elif k == "c":
            pals, note = shared_palettes(self.host)
            if not pals: self.msg = note[:90]
            else:
                self.pi = (self.pi + 1) % len(pals); name, cols = pals[self.pi]
                for n, f in enumerate(self.frames): f["color"] = hexc(cols[n % len(cols)])
                self.msg = f"palette {name} applied"
        elif k == "x": self.msg = put_safe(self.host, "export-animation.svg", anim_svg(self.frames, self.name))
        elif k == "n": return ("push", Prompt("Name", "Title of the animation:", self.name, on_done=lambda t: setattr(self, "name", t.strip()[:60] or "animation")))
        elif k == "e":
            def save(text):
                fr, errs = parse_keyframes(text)
                if fr:
                    self.text, self.frames, self.i = text, fr, 0
                    self.host.put("keyframes", text[:20000])
                self.msg = f"{len(fr)} keyframes" + (f", {len(errs)} line(s) ignored: {errs[0]}" if errs else "")
            return ("push", Editor("Keyframes", self.text, on_save=save, hint="line: time shape x y size #colour"))


# ----------------------------------------------------------- Color Tools ----
_NAMES = ("aliceblue f0f8ff antiquewhite faebd7 aqua 00ffff aquamarine 7fffd4 azure f0ffff beige f5f5dc black 000000 blue 0000ff "
          "blueviolet 8a2be2 brown a52a2a burlywood deb887 cadetblue 5f9ea0 chartreuse 7fff00 chocolate d2691e coral ff7f50 "
          "cornflowerblue 6495ed crimson dc143c darkblue 00008b darkcyan 008b8b darkgoldenrod b8860b darkgray a9a9a9 darkgreen 006400 "
          "darkkhaki bdb76b darkmagenta 8b008b darkolivegreen 556b2f darkorange ff8c00 darkorchid 9932cc darkred 8b0000 darksalmon e9967a "
          "darkseagreen 8fbc8f darkslateblue 483d8b darkslategray 2f4f4f darkturquoise 00ced1 darkviolet 9400d3 deeppink ff1493 "
          "deepskyblue 00bfff dimgray 696969 dodgerblue 1e90ff firebrick b22222 forestgreen 228b22 fuchsia ff00ff gainsboro dcdcdc "
          "gold ffd700 goldenrod daa520 gray 808080 green 008000 greenyellow adff2f hotpink ff69b4 indianred cd5c5c indigo 4b0082 "
          "ivory fffff0 khaki f0e68c lavender e6e6fa lawngreen 7cfc00 lightblue add8e6 lightcoral f08080 lightgray d3d3d3 "
          "lightgreen 90ee90 lightpink ffb6c1 lightsalmon ffa07a lightseagreen 20b2aa lightskyblue 87cefa lightyellow ffffe0 lime 00ff00 "
          "limegreen 32cd32 linen faf0e6 maroon 800000 mediumblue 0000cd mediumpurple 9370db mediumseagreen 3cb371 midnightblue 191970 "
          "mintcream f5fffa navy 000080 olive 808000 olivedrab 6b8e23 orange ffa500 orangered ff4500 orchid da70d6 palegreen 98fb98 "
          "peru cd853f pink ffc0cb plum dda0dd purple 800080 rebeccapurple 663399 red ff0000 royalblue 4169e1 salmon fa8072 "
          "sandybrown f4a460 seagreen 2e8b57 sienna a0522d silver c0c0c0 skyblue 87ceeb slateblue 6a5acd slategray 708090 snow fffafa "
          "springgreen 00ff7f steelblue 4682b4 tan d2b48c teal 008080 thistle d8bfd8 tomato ff6347 turquoise 40e0d0 violet ee82ee "
          "wheat f5deb3 white ffffff whitesmoke f5f5f5 yellow ffff00 yellowgreen 9acd32").split()
NAMED = {_NAMES[i]: tuple(int(_NAMES[i + 1][j:j + 2], 16) for j in (0, 2, 4)) for i in range(0, len(_NAMES), 2)}

MATRICES = {   # Machado et al. 2009, severity 1.0, applied to linear RGB
    "protanopia": ((0.152286, 1.052583, -0.204868), (0.114503, 0.786281, 0.099216), (-0.003882, -0.048116, 1.051998)),
    "deuteranopia": ((0.367322, 0.860646, -0.227968), (0.280085, 0.672501, 0.047413), (-0.011820, 0.042940, 0.968881)),
    "tritanopia": ((1.255528, -0.076749, -0.178779), (-0.078411, 0.930809, 0.147602), (0.004733, 0.691367, 0.303900)),
}


def _r(v: float) -> int: return max(0, min(255, int(v + 0.5)))
def hexc(c) -> str: return "#%02x%02x%02x" % tuple(c)


def parse_color(s: str) -> tuple:
    """hex (#rgb/#rrggbb), rgb(), hsl(), hsv(), 'r,g,b' or a CSS name -> (r,g,b). Raises ValueError."""
    s = s.strip().lower()
    if len(s) > 100: raise ValueError("too long")
    if s in NAMED: return NAMED[s]
    m = re.fullmatch(r"#?([0-9a-f]{3}|[0-9a-f]{6})", s)
    if m:
        h = m.group(1)
        if len(h) == 3: h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.fullmatch(r"(?:(rgb|hsl|hsv)\s*\(([^)]*)\)|([\d.,\s]+))", s)
    if not m: raise ValueError(f"cannot read colour {s!r}")
    kind = m.group(1) or "rgb"
    try: nums = [float(t) for t in re.split(r"[\s,]+", (m.group(2) or m.group(3)).replace("%", " ").replace("deg", " ").strip()) if t]
    except ValueError: raise ValueError(f"cannot read colour {s!r}") from None
    if len(nums) != 3 or not all(math.isfinite(n) for n in nums): raise ValueError("a colour needs three numbers")
    a, b, c = nums
    if kind == "rgb":
        if not all(0 <= n <= 255 for n in nums): raise ValueError("rgb values are 0..255")
        return (_r(a), _r(b), _r(c))
    if not (0 <= b <= 100 and 0 <= c <= 100): raise ValueError("saturation/lightness/value are 0..100")
    h = (a % 360) / 360
    r = colorsys.hls_to_rgb(h, c / 100, b / 100) if kind == "hsl" else colorsys.hsv_to_rgb(h, b / 100, c / 100)
    return tuple(_r(v * 255) for v in r)


def to_hsl(c):
    h, l, s = colorsys.rgb_to_hls(*(v / 255 for v in c))
    return (round(h * 360, 1) % 360, round(s * 100, 1), round(l * 100, 1))


def to_hsv(c):
    h, s, v = colorsys.rgb_to_hsv(*(x / 255 for x in c))
    return (round(h * 360, 1) % 360, round(s * 100, 1), round(v * 100, 1))


def to_cmyk(c):
    r, g, b = (v / 255 for v in c)
    k = 1 - max(r, g, b)
    if k >= 1: return (0.0, 0.0, 0.0, 100.0)
    return tuple(round(100 * v, 1) for v in ((1 - r - k) / (1 - k), (1 - g - k) / (1 - k), (1 - b - k) / (1 - k), k))


def nearest_name(c):
    """-> (name, hex, distance) among the built-in table (plain RGB distance, not perceptual)."""
    name = min(sorted(NAMED), key=lambda n: sum((NAMED[n][i] - c[i]) ** 2 for i in range(3)))
    return name, hexc(NAMED[name]), round(math.sqrt(sum((NAMED[name][i] - c[i]) ** 2 for i in range(3))), 1)


def _lin(v: int) -> float:
    v /= 255
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def _unlin(v: float) -> int:
    v = max(0.0, min(1.0, v))
    return _r(255 * (12.92 * v if v <= 0.0031308 else 1.055 * v ** (1 / 2.4) - 0.055))


def luminance(c) -> float:
    return 0.2126 * _lin(c[0]) + 0.7152 * _lin(c[1]) + 0.0722 * _lin(c[2])


def contrast(a, b) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def verdicts(ratio: float) -> dict:
    return {"AA normal text (4.5)": ratio >= 4.5, "AA large text (3)": ratio >= 3, "AAA normal text (7)": ratio >= 7, "AAA large text (4.5)": ratio >= 4.5}


def rotate(c, deg: float):
    h, s, l = to_hsl(c)
    return tuple(_r(v * 255) for v in colorsys.hls_to_rgb(((h + deg) % 360) / 360, l / 100, s / 100))


def palettes(c) -> dict:
    return {"complementary": [c, rotate(c, 180)], "triad": [c, rotate(c, 120), rotate(c, 240)],
            "analogous": [rotate(c, -30), c, rotate(c, 30)]}


def simulate(c, kind: str):
    """Colour-blindness simulation of one colour. Approximate: a model, not a medical test."""
    if kind == "achromatopsia":
        y = _unlin(luminance(c)); return (y, y, y)
    m, lin = MATRICES[kind], [_lin(v) for v in c]
    return tuple(_unlin(sum(m[i][j] * lin[j] for j in range(3))) for i in range(3))


def gradient(a, b, n: int) -> list:
    n = max(2, min(64, n))
    return [tuple(_r(a[i] + (b[i] - a[i]) * k / (n - 1)) for i in range(3)) for k in range(n)]


def describe(c) -> list:
    nm = nearest_name(c)
    return [f"hex    {hexc(c)}", f"rgb    {c[0]}, {c[1]}, {c[2]}", "hsl    %g, %g%%, %g%%" % to_hsl(c), "hsv    %g, %g%%, %g%%" % to_hsv(c),
            "cmyk   %g%%, %g%%, %g%%, %g%%" % to_cmyk(c), f"nearest name: {nm[0]} {nm[1]} (distance {nm[2]})"]


def _tokens(s: str) -> list:
    return re.findall(r"[a-z]+\([^)]*\)|[^\s|]+", s.lower()) if "|" not in s else [t.strip() for t in s.lower().split("|")]


def run_tool(name: str, text: str) -> list:
    """The text of one Color Tools command -> result lines. Raises ValueError."""
    t = _tokens(text[:300])
    if name == "convert":
        return describe(parse_color(" ".join(t)))
    if name == "contrast":
        if len(t) != 2: raise ValueError("give two colours: foreground background")
        r = contrast(parse_color(t[0]), parse_color(t[1]))
        return [f"contrast ratio {r:.2f}:1"] + [f"{k}: {'pass' if v else 'FAIL'}" for k, v in verdicts(r).items()]
    if name == "palette":
        return [f"{k}: " + "  ".join(hexc(c) for c in v) for k, v in palettes(parse_color(" ".join(t))).items()]
    if name == "blind":
        c = parse_color(" ".join(t))
        return [f"original {hexc(c)}"] + [f"{k}: {hexc(simulate(c, k))}" for k in (*MATRICES, "achromatopsia")]
    if name == "gradient":
        if len(t) != 3 or not t[2].isdigit(): raise ValueError("give: colour1 colour2 steps")
        return [hexc(c) for c in gradient(parse_color(t[0]), parse_color(t[1]), int(t[2]))]
    raise ValueError("unknown tool")


PALETTES = R("palettes", "Palettes", "palette", "name*; colors*")


def shared_palettes(host) -> tuple:
    """(list of (name, [rgb...]) from the palettes folder, note). Works without the grant: the note says so."""
    items = shared_items(host, "palettes")
    out = []
    for r in items:
        cols = []
        for c in str(r.get("colors", "")).split(",")[:16]:
            c = c.strip().lower()
            if re.fullmatch(r"#[0-9a-f]{6}", c): cols.append(hex_rgb(c))
        if cols: out.append((str(r.get("name", "palette"))[:30], cols))
    return out, ("" if items else "no saved palettes available (none yet, or this app has no grant for the palettes folder): using built-in colours")


class SavePalette(TextView):
    def __init__(self, host, title, lines, cols):
        super().__init__(title, lines); self.host, self.cols = host, cols

    def key(self, k):
        if k == "enter":
            ok = shared_add(self.host, "palettes", {"name": f"palette {self.cols[:7]}", "colors": self.cols})
            self.lines = self.lines[:-1] + ["saved" if ok else "could not save (palettes folder refused)"]
            return None
        return super().key(k)


def make_colors(host, entry) -> Screen:
    def tool(name, label, ask):
        def done(text):
            try: lines = run_tool(name, text)
            except ValueError as e: return ("push", Message("Colour Tools", [str(e)]))
            host.put("last-result", "\n".join(lines)[:MAXVAULT])
            if name == "palette":
                cols = ",".join(re.findall(r"#[0-9a-f]{6}", lines[0]))
                lines = lines + ["", "Press Enter to save the complementary palette to Saved palettes."]
                return ("push", SavePalette(host, label, lines, cols))
            return ("push", TextView(label, lines))
        return ("push", Prompt(label, ask, on_done=done))

    about = ["Works on colour values you type. It cannot measure colours on your screen or",
             "pick them from the display or a camera: KOS apps have no screen access.",
             "Names: a built-in table of common CSS colours. Colour-blindness: approximate."]
    ent = [("Convert a colour (hex / rgb / hsl / hsv / name)", lambda: tool("convert", "Convert", "Colour, e.g. #336699, rgb(10,20,30), hsl(210,50%,40%), tomato:")),
           ("Contrast ratio (WCAG)", lambda: tool("contrast", "Contrast", "Foreground and background, e.g. #777 #fff:")),
           ("Palette: complementary, triad, analogous", lambda: tool("palette", "Palette", "Base colour:")),
           ("Colour-blindness simulation", lambda: tool("blind", "Colour blindness", "Colour:")),
           ("Gradient steps", lambda: tool("gradient", "Gradient", "Start end steps, e.g. #000 #fff 5:")),
           ("Saved palettes (shared folder)", lambda: ("push", RecordList(Data(SpaceHost(host, "palettes"), PALETTES)))),
           ("About and limits", lambda: ("push", TextView("About", about)))]
    return Menu("Color Tools", ent, ["Type a colour, get every notation, contrast, palettes and more."])


# --------------------------------------------------------------- entries ----
ENTRIES: list = [
    app("File Format Converter", make_converter, "partial",
        "Converts text and small images only: CSV, TSV, JSON, JSON lines, a simple XML table, Markdown to HTML (escaped, no raw HTML), "
        "base64, hex, PPM(P3 text) and PNG(base64). Not audio, video or documents such as DOCX or PDF."),
    app("3D Model Viewer", lambda h, e: Viewer(h), "partial", name="model-viewer-3d", note=
        "Wireframe only: reads OBJ vertices and faces (no materials, textures or normals), four built-in shapes, "
        "bounding box, area, volume of closed meshes, STL and OBJ export. No shading or file import from disk.", graphical=True),
    app("Avatar Maker", lambda h, e: Avatar(h), "full", "", graphical=True, uses=["palettes"]),
    app("Animation Maker", lambda h, e: Animator(h), "partial",
        "One shape per moment: keyframes of shape, position, size and colour give an animated SVG (SMIL) and a stepped preview. "
        "No layers, easing curves, sound or video export; the preview is frame by frame, not played. Can colour keyframes from saved palettes.", graphical=True, uses=["palettes"]),
    app("Color Tools", make_colors, "partial",
        "Computes with colours you type (hex, RGB, HSL, HSV, CMYK, CSS names, contrast, palettes, colour-blindness, gradients). "
        "It cannot measure or pick colours from the screen, as KOS apps have no screen access.", owns=["palettes"]),
]
