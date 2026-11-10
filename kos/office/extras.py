"""Remaining engines: sync planning, SRT, recurrence, formula suggestions,
outline->slides, code checks, search library, hub, dashboard, ER/DDL designer,
API tester, script runner, channels, EDL export."""

from __future__ import annotations

import ast
import contextlib
import datetime as dt
import io
import json
import re
import signal
import time

from . import llm, tools
from .docs import Library
from .records import Data, Field, RecordList, Spec
from .search import Index
from .ui import (Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextInput, TextView, bar, now_stamp, slug, table, wrap)
from .workbench import Tool, TOOLS, table_tool


# ----------------------------------------------------------- pure tools ----
def sync_plan(text: str) -> list:
    """Three sections separated by a line '---': LEFT, RIGHT, and optionally
    the BASE (state at last sync). Lines: path,size,mtime. -> actions."""
    parts = [p for p in re.split(r"(?m)^---\s*$", text)]
    def load(s):
        d = {}
        for line in s.strip().split("\n"):
            f = [x.strip() for x in line.split(",")]
            if len(f) >= 3 and f[0]: d[f[0]] = (f[1], f[2])
        return d
    L, R = load(parts[0]), load(parts[1] if len(parts) > 1 else "")
    B = load(parts[2]) if len(parts) > 2 else None
    out = []
    for p in sorted(set(L) | set(R) | set(B or {})):
        l, r, b = L.get(p), R.get(p), (B or {}).get(p)
        if l == r and l: out.append(f"  same       {p}")
        elif l and not r:
            out.append(f"  delete ←   {p}   (deleted on right; left unchanged)" if b and b == l else
                       (f"  CONFLICT   {p}   (deleted on right but changed on left)" if b else f"  copy →     {p}"))
        elif r and not l:
            out.append(f"  delete →   {p}   (deleted on left; right unchanged)" if b and b == r else
                       (f"  CONFLICT   {p}   (deleted on left but changed on right)" if b else f"  copy ←     {p}"))
        elif l and r:
            if b and l == b: out.append(f"  update ←   {p}   (only right changed)")
            elif b and r == b: out.append(f"  update →   {p}   (only left changed)")
            elif b: out.append(f"  CONFLICT   {p}   (both changed since last sync)")
            else:
                lt, rt = float(l[1]), float(r[1])
                out.append(f"  update →   {p}   (left newer)" if lt > rt else f"  update ←   {p}   (right newer)" if rt > lt else f"  CONFLICT   {p}   (same time, different size)")
    n = lambda w: sum(1 for x in out if x.strip().startswith(w))
    return [f"{n('copy')} copy, {n('update')} update, {n('delete')} delete, {n('CONFLICT')} conflict, {n('same')} unchanged", ""] + out


def srt(text: str, fmt: str = "srt") -> list:
    rows = []
    for line in text.split("\n"):
        m = re.match(r"^\[?(?:(\d+):)?(\d{1,2}):(\d{2})\]?\s*(.*)$", line.strip())
        if m: rows.append((int(m.group(1) or 0) * 3600 + int(m.group(2)) * 60 + int(m.group(3)), m.group(4)))
    if not rows: return ["lines look like:  [00:01:23] Speaker: text   or   01:23 text"]
    def ts(s, sep): return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}{sep}000"
    sep = "," if fmt == "srt" else "."
    out = ["WEBVTT", ""] if fmt == "vtt" else []
    for i, (t, txt) in enumerate(rows):
        end = rows[i + 1][0] if i + 1 < len(rows) else t + 3
        out += ([str(i + 1)] if fmt == "srt" else []) + [f"{ts(t, sep)} --> {ts(max(end, t + 1), sep)}", txt, ""]
    return out


_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


def recur(text: str, days: int = 30, start: dt.date | None = None) -> list:
    """Rules: 'every weekday 09:00 Standup' | 'every monday 14:00 Review' |
    'every 2 weeks tuesday 10:00 Sync' | 'daily 08:00 Pills' | 'monthly on 15 09:00 Payroll'"""
    start = start or dt.date.today(); out, bad = [], []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        m = (re.match(r"^every\s+(weekday|day|" + "|".join(_DAYS) + r")\s+(\d{1,2}:\d{2})\s+(.+)$", line, re.I)
             or re.match(r"^(daily)\s+(\d{1,2}:\d{2})\s+(.+)$", line, re.I))
        m2 = re.match(r"^every\s+(\d+)\s+weeks?\s+(" + "|".join(_DAYS) + r")\s+(\d{1,2}:\d{2})\s+(.+)$", line, re.I)
        m3 = re.match(r"^monthly\s+on\s+(\d{1,2})\s+(\d{1,2}:\d{2})\s+(.+)$", line, re.I)
        for i in range(days):
            d = start + dt.timedelta(days=i); hit = None
            if m:
                w = m.group(1).lower()
                if w in ("day", "daily") or (w == "weekday" and d.weekday() < 5) or w == _DAYS[d.weekday()]: hit = (m.group(2), m.group(3))
            elif m2:
                if _DAYS[d.weekday()] == m2.group(2).lower() and ((d - start).days // 7) % int(m2.group(1)) == 0: hit = (m2.group(3), m2.group(4))
            elif m3 and d.day == int(m3.group(1)): hit = (m3.group(2), m3.group(3))
            if hit: out.append((d.isoformat(), hit[0].zfill(5), hit[1]))
        if not (m or m2 or m3): bad.append(line)
    return [f"{d} {t}  {title}" for d, t, title in sorted(out)] + ([""] + [f"? could not read: {b}" for b in bad] if bad else []) or ["no rules"]


def nl_formula(text: str, rows: int = 100) -> list:
    out = []
    for raw in text.split("\n"):
        s = raw.strip().lower()
        if not s: continue
        col = lambda m: m.group(1).upper()
        f = None
        if m := re.search(r"(sum|total|average|mean|max|maximum|min|minimum|count)\b.*?\b(?:of |in |for )?(?:column )?([a-z])\b(?!\d)", s):
            fn = {"sum": "SUM", "total": "SUM", "average": "AVERAGE", "mean": "AVERAGE", "max": "MAX", "maximum": "MAX", "min": "MIN", "minimum": "MIN", "count": "COUNT"}[m.group(1)]
            f = f"={fn}({m.group(2).upper()}1:{m.group(2).upper()}{rows})"
        if m := re.search(r"(sum|total|average|max|min|count)\b.*?\b([a-z]\d+)\s*(?:to|through|-|:)\s*([a-z]\d+)", s):
            f = f"={ {'total': 'SUM'}.get(m.group(1), m.group(1).upper()) }({m.group(2).upper()}:{m.group(3).upper()})"
        if m := re.search(r"percent(?:age)? (?:change|growth|increase) (?:between|from) ([a-z]\d+) (?:and|to) ([a-z]\d+)", s): f = f"=({m.group(2).upper()}-{m.group(1).upper()})/{m.group(1).upper()}"
        if m := re.search(r"if ([a-z]\d+) is (greater than|less than|equal to|at least|at most) (\S+) then ['\"]?(.+?)['\"]? else ['\"]?(.+?)['\"]?$", s):
            op = {"greater than": ">", "less than": "<", "equal to": "=", "at least": ">=", "at most": "<="}[m.group(2)]
            q = lambda v: v if re.match(r"^-?\d+(\.\d+)?$", v) or re.match(r"^[a-z]\d+$", v) else f'"{v}"'
            f = f"=IF({m.group(1).upper()}{op}{m.group(3)},{q(m.group(4))},{q(m.group(5))})"
        if m := re.search(r"(?:sum|total) (?:of )?(?:column )?([a-z]) where (?:column )?([a-z]) (?:is|equals|=) ['\"]?([^'\"]+?)['\"]?$", s):
            f = f'=SUMIF({m.group(2).upper()}1:{m.group(2).upper()}{rows},"{m.group(3)}",{m.group(1).upper()}1:{m.group(1).upper()}{rows})'
        if m := re.search(r"round ([a-z]\d+) to (\d+) decimal", s): f = f"=ROUND({m.group(1).upper()},{m.group(2)})"
        out.append(f"{raw.strip()}\n    {f or '? not understood - try: sum of column B / average of B2 to B9 / percent change between A1 and A2 / if A1 is greater than 10 then high else low'}")
    return out or ["describe a calculation, one per line"]


def outline_to_slides(text: str) -> list:
    lines = [l.rstrip() for l in text.split("\n") if l.strip()]
    if not lines: return ["write an outline: first line is the deck title; unindented lines are slides; indented lines are bullets"]
    out = [f"# {lines[0].strip()}", "", "> opening slide", "---"]
    cur = None
    for l in lines[1:]:
        if not l.startswith((" ", "\t")):
            if cur is not None: out.append("---")
            out += [f"## {l.strip()}", ""]; cur = l
        else: out.append(("  " if len(l) - len(l.lstrip()) > 4 else "") + "- " + l.strip().lstrip("-* "))
    return out


def code_check(text: str, lang: str = "") -> list:
    out = []
    lang = (lang or ("python" if re.search(r"^\s*(def |import |class |from \w+ import)", text, re.M) else "")).lower()
    todo = [f"line {i}: {l.strip()}" for i, l in enumerate(text.split("\n"), 1) if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", l)]
    if lang in ("python", "py"):
        try: tree = ast.parse(text)
        except SyntaxError as e: return [f"syntax error line {e.lineno}, col {e.offset}: {e.msg}"]
        out.append("syntax OK")
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for f in funcs:
            cx = 1 + sum(isinstance(n, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.BoolOp, ast.IfExp, ast.comprehension)) for n in ast.walk(f))
            ln = (f.end_lineno or f.lineno) - f.lineno + 1
            out.append(f"  def {f.name}: {ln} lines, complexity {cx}" + ("  <- consider splitting" if cx > 10 or ln > 50 else ""))
        imported = {(a.asname or a.name).split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
        if imported - used - {"*"}: out.append("  unused imports: " + ", ".join(sorted(imported - used - {"*"})))
        if any(isinstance(n, ast.ExceptHandler) and n.type is None for n in ast.walk(tree)): out.append("  bare 'except:' found")
        if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("eval", "exec") for n in ast.walk(tree)): out.append("  eval/exec used - review")
    else:
        pairs = {"(": ")", "[": "]", "{": "}"}; st = []
        for i, l in enumerate(text.split("\n"), 1):
            for ch in re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', "", l):
                if ch in pairs: st.append((ch, i))
                elif ch in pairs.values():
                    if not st or pairs[st[-1][0]] != ch: return [f"unbalanced '{ch}' on line {i}"]
                    st.pop()
        out.append("brackets balanced" if not st else f"unclosed '{st[-1][0]}' from line {st[-1][1]}")
    long_ = [i for i, l in enumerate(text.split("\n"), 1) if len(l) > 100]
    if long_: out.append(f"  {len(long_)} line(s) over 100 chars (first: {long_[0]})")
    out += (["", "TODO/FIXME:"] + ["  " + t for t in todo]) if todo else []
    return out + [f"", f"{len(text.splitlines())} lines"]


def to_model(text: str) -> tuple[list, list]:
    """Tiny ER DSL -> (SQL DDL lines, problems)."""
    tables, cur, problems = {}, None, []
    for raw in text.split("\n"):
        line = raw.split("#")[0].rstrip()
        if not line.strip(): continue
        if line.startswith("table "): cur = tables.setdefault(line[6:].strip(), {"cols": [], "fks": []}); continue
        if cur is None: problems.append("columns must come after a 'table NAME' line"); continue
        p = line.split()
        if len(p) >= 3 and p[1] == "->": ref = p[2]; cur["cols"].append((p[0], "INTEGER", "FK")); cur["fks"].append((p[0], ref))
        elif len(p) >= 2: cur["cols"].append((p[0], {"pk": "INTEGER", "text": "TEXT", "number": "REAL", "int": "INTEGER", "date": "TEXT", "bool": "INTEGER"}.get(p[1], p[1].upper()), "PK" if p[1] == "pk" else ""))
    out = []
    for name, t in tables.items():
        if not any(c[2] == "PK" for c in t["cols"]): problems.append(f"table {name} has no primary key (column with type pk)")
        cols = [f"  {c} {ty}" + (" PRIMARY KEY" if k == "PK" else "") for c, ty, k in t["cols"]]
        for c, ref in t["fks"]:
            rt, _, rc = ref.partition(".")
            if rt not in tables: problems.append(f"{name}.{c} references unknown table {rt}")
            elif rc and not any(x[0] == rc for x in tables[rt]["cols"]): problems.append(f"{name}.{c} references unknown column {ref}")
            cols.append(f"  FOREIGN KEY ({c}) REFERENCES {rt}({rc or 'id'})")
        out += [f"CREATE TABLE {name} (", ",\n".join(cols), ");", ""]
    rel = [f"{n}.{c} --> {r}" for n, t in tables.items() for c, r in t["fks"]]
    return out + (["-- relations", *("-- " + r for r in rel)] if rel else []), problems


def edl(items: list, fps: int = 25) -> list:
    def tc(f): return f"{f // (3600 * fps):02d}:{f // (60 * fps) % 60:02d}:{f // fps % 60:02d}:{f % fps:02d}"
    def fr(s):
        try: h, m, sec, f = (int(x) for x in s.split(":")); return ((h * 60 + m) * 60 + sec) * fps + f
        except ValueError: return None
    out, rec, n = ["TITLE: KOS EDIT", "FCM: NON-DROP FRAME", ""], 0, 0
    for r in items:
        a, b = fr(r.get("tc_in", "")), fr(r.get("tc_out", ""))
        if a is None or b is None or b <= a: out.append(f"* skipped '{r.get('clip', '?')}': bad in/out timecode"); continue
        n += 1; tr = {"V1": "V", "V2": "V", "A1": "A", "A2": "A"}.get(r.get("track", "V1"), "V")
        out.append(f"{n:03d}  {slug(r.get('source') or 'AX')[:8].upper():<8} {tr:<4} {'D 030' if r.get('transition') == 'dissolve' else 'C'}        {tc(a)} {tc(b)} {tc(rec)} {tc(rec + b - a)}")
        out.append(f"* FROM CLIP NAME: {r.get('clip', '')}"); rec += b - a
    return out + ["", f"* {n} events, running time {tc(rec)} at {fps} fps"]


# -------------------------------------------------------- registrations ----
TOOLS.update({
    "sync": Tool("sync", "Plan a two-way sync from listings", lambda t, p: sync_plan(t), sample="a.txt,10,100\nb.txt,5,200\nnew.txt,1,50\n---\na.txt,10,100\nb.txt,5,150\nold.txt,2,10\n---\na.txt,10,100\nb.txt,5,150\nold.txt,2,10\n",
                 help="LEFT --- RIGHT [--- LAST SYNC]; lines path,size,mtime"),
    "srt": Tool("srt", "Transcript → SRT / WebVTT", lambda t, p: srt(t, (p or "srt").lower()), "Format: srt or vtt", "[00:00:01] Ann: Welcome everyone.\n[00:00:04] Bob: Thanks for joining.\n[00:00:09] Ann: Let's begin.\n"),
    "recur": Tool("recur", "Expand recurring-event rules", lambda t, p: recur(t, int(p or 30)), "How many days ahead? (30)", "every weekday 09:00 Standup\nevery 2 weeks tuesday 10:00 Sync\nmonthly on 15 09:00 Payroll\n"),
    "formula": Tool("formula", "Describe a calculation → formula", lambda t, p: nl_formula(t), sample="sum of column B\npercent change between A1 and A2\nif A1 is greater than 10 then high else low\ntotal of column C where column A is east\n"),
    "outline": Tool("outline", "Outline → slide deck text", lambda t, p: outline_to_slides(t), sample="Quarterly review\nResults\n  Revenue up 12%\n  Costs down 3%\nPlans\n  Hire two engineers\n  Ship v2\n"),
    "code": Tool("code", "Code check (syntax, complexity, TODOs)", lambda t, p: code_check(t, p), "Language (blank = detect)", "import os\n\ndef f(x):\n    if x > 1:\n        return x\n    # TODO handle small x\n    return 0\n"),
    "scan": Tool("scan", "Scan pasted content (KOS scanner rules)", lambda t, p: _kos_scan(t)),
    "model": Tool("model", "Data model → SQL DDL", lambda t, p: (lambda ddl, pr: ddl + ([""] + ["! " + x for x in pr] if pr else []))(*to_model(t)),
                  sample="table customer\n  id pk\n  name text\ntable orders\n  id pk\n  customer_id -> customer.id\n  total number\n"),
})


def _kos_scan(text: str) -> list:
    from kos.scan import scan_bytes
    r = scan_bytes(text.encode(), label="pasted")
    return [f"[{f.severity}] {f.rule}: {f.note}" for f in r.findings] or ["clean by the KOS static rules (heuristic, not proof)"]


# -------------------------------------------------------------- screens ----
class PrefixHost:
    """Gives each component of a hub its own slice of the vault."""

    def __init__(self, host, prefix):
        self.h, self.p = host, prefix

    def __getattr__(self, n): return getattr(self.h, n)
    def get(self, k): return self.h.get(self.p + k)
    def put(self, k, v): return self.h.put(self.p + k, v)
    def delete(self, k): return self.h.delete(self.p + k)
    def keys(self): return [k[len(self.p):] for k in self.h.keys() if k.startswith(self.p)]


class Hub(Menu):
    def __init__(self, host, title, parts: list, intro: str = "", prefixed: bool = True):
        entries = []
        for i, (label, make) in enumerate(parts):
            entries.append((label, (lambda mk=make, pre=f"c{i}-": ("push", mk(PrefixHost(host, pre) if prefixed else host)))))
        super().__init__(title, entries, wrap(intro, 76) if intro else [])


class SearchLibrary(Library):
    """Documents you add, ranked search across them, optional legal hold and model answers."""

    def __init__(self, host, title, noun="document", ask=False, hold=False):
        super().__init__(host, title, noun, lambda n, t, s: Editor(n, t, s, hint="Ctrl-S save"), "", "doc-")
        self.ask, self.hold = ask, hold
        self.holds = set(Store(host).load("holds", []))
        self.help += ("  h legal hold  x hold report" if hold else "")

    def render(self, w, h):
        out = super().render(w, h)
        if self.hold: out = [l + ("  [HOLD]" if any(l.strip(" >").startswith(n) for n in self.holds) else "") for l in out]
        return out

    def key(self, k):
        ns = self.names(); cur = ns[self.nav.sel] if ns else None
        if self.hold and k == "h" and cur:
            self.holds ^= {cur}; self.st.save("holds", sorted(self.holds)); self.msg = f"legal hold {'ON' if cur in self.holds else 'off'} for {cur}"; return
        if self.hold and k == "x":
            return ("push", TextView("Legal hold report", [f"{len(self.holds)} document(s) on hold:", *sorted(self.holds)]))
        if self.hold and k == "d" and cur in self.holds:
            self.msg = "cannot delete: legal hold"; return
        return super().key(k)

    def _find(self, q):
        ix = Index({n: self.load(n) for n in self.idx}); res = ix.search(q)
        lines = [l for n, s, sn in res for l in (f"{n}  ({s:.1f})", f"   {sn}")] or ["no matches"]
        cfg = self.st.load("llm", {})
        if self.ask and res:
            if llm.configured(cfg):
                ctx = "\n\n".join(f"[{n}]\n{self.load(n)[:3000]}" for n, _s, _x in res[:3])
                try: lines = ["ANSWER:", *wrap(llm.ask(self.host, cfg, "Answer the question using only the context. Cite document names in [brackets]. Say so if the answer is not in the context.", [{"role": "user", "content": f"Question: {q}\n\nContext:\n{ctx}"}]), 74), "", "SOURCES:"] + lines
                except llm.LLMError as e: lines = [f"(model error: {e})", ""] + lines
            else: lines = ["(no model configured - showing ranked passages; connect one in the model settings of an assistant app)", ""] + lines
        return ("push", TextView(f"Search: {q}", lines))


class Dashboard(Screen):
    SAMPLE_DATA = "region,product,qty,price\nNorth,Widget,10,2.5\nSouth,Widget,4,2.5\nNorth,Gadget,3,10\nSouth,Gadget,8,10\nEast,Widget,15,2.5\n"
    SAMPLE_WIDGETS = "kpi sum qty\nkpi avg price\nbar region qty\nhist qty\nline price\ntable 3\n"

    def __init__(self, host, title="Dashboard"):
        self.host, self.title, self.st = host, title, Store(host)
        self.data = self.st.load("data", self.SAMPLE_DATA); self.widgets = self.st.load("widgets", self.SAMPLE_WIDGETS)
        self.top = 0
        self.help = "d edit data (CSV/JSON)  w edit widgets  up/down scroll  x export text"

    def lines(self) -> list:
        cols, rows = tools.parse_table(self.data); out = []
        if not cols: return ["no data - press d and paste a table"]
        for w in self.widgets.split("\n"):
            p = w.split()
            if not p: continue
            if p[0] == "kpi" and len(p) == 3 and p[2] in cols:
                vs = [tools.num(r[p[2]]) for r in rows if tools.num(r[p[2]]) is not None]
                v = {"sum": sum(vs), "avg": sum(vs) / len(vs) if vs else 0, "max": max(vs, default=0), "min": min(vs, default=0), "count": len(vs)}.get(p[1])
                val = f"{v:,.2f}" if v is not None else "?"
                out += ["┌" + "─" * 30 + "┐", "│" + f" {p[1].upper() + ' ' + p[2]:<16}{val:>12} " + "│", "└" + "─" * 30 + "┘", ""]
            elif p[0] in ("bar", "hist", "line"):
                spec = w.strip() if p[0] == "line" else " ".join(p[1:])
                out += [f"── {w.strip()} ──", *tools.chart(cols, rows, spec), ""]
            elif p[0] == "table":
                out += [f"── first {p[1] if len(p) > 1 else 5} rows ──", *table([[r.get(c, "") for c in cols] for r in rows[:int(p[1]) if len(p) > 1 else 5]], cols), ""]
            else: out.append(f"? unknown widget '{w}'")
        return out

    def render(self, w, h):
        ls = self.lines(); self.top = max(0, min(self.top, max(0, len(ls) - h))); return ls[self.top:self.top + h]

    def key(self, k):
        if k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "d": return ("push", Editor("Data", self.data, on_save=lambda t: (setattr(self, "data", t), self.st.save("data", t))))
        elif k == "w": return ("push", Editor("Widgets", self.widgets, on_save=lambda t: (setattr(self, "widgets", t), self.st.save("widgets", t)), hint="kpi sum COL | bar LABEL VALUE | hist COL | line COL | table N"))
        elif k == "x": self.host.put("export-dashboard.txt", "\n".join(self.lines()))
        elif k == "escape": return ("quit",)


API_SPEC = Spec("requests", "API requests", "request", [Field("name", "Name", required=True), Field("method", "Method", "choice", ("GET", "POST"), "GET"),
                Field("url", "URL", "url", required=True), Field("headers", "Headers (K: V per line)", "long"), Field("body", "Body", "long"), Field("pick", "Pick JSON path (a.b.0.c)")],
                list_cols=("name", "method", "url"), scope="Needs the network permission AND a firewall rule for this app. The OS sends exactly the request you wrote (https, GET/POST).")


def json_pick(obj, path: str):
    for part in [p for p in path.split(".") if p]:
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


def snippets(r: dict) -> list:
    hs = [h.split(":", 1) for h in r.get("headers", "").replace("\\n", "\n").split("\n") if ":" in h]
    body = r.get("body", "").replace("\\n", "\n")
    curl = f"curl -X {r['method']} '{r['url']}'" + "".join(f" -H '{k.strip()}: {v.strip()}'" for k, v in hs) + (f" --data '{body}'" if body else "")
    py = ["import urllib.request", f"req = urllib.request.Request({r['url']!r}, method={r['method']!r}" + (f", data={body.encode()!r}" if body else "") + (f", headers={ {k.strip(): v.strip() for k, v in hs} !r}" if hs else "") + ")",
          "print(urllib.request.urlopen(req).read().decode())"]
    return ["curl:", "  " + curl, "", "python:"] + ["  " + l for l in py]


class ApiTool(RecordList):
    def __init__(self, host, title="API"):
        super().__init__(Data(host, API_SPEC)); self.title = title; self.host = host
        self.help += "  S send  C code snippets"

    def key(self, k):
        cur = self.current()
        if k == "S" and cur: return ("push", TextView("Response", self.send(cur)))
        if k == "C" and cur: return ("push", TextView("Snippets", snippets(cur)))
        return super().key(k)

    def send(self, r: dict) -> list:
        if r["method"] not in ("GET", "POST"):
            return ["only GET and POST can be sent: the OS makes the request (https only) for this app"]
        hs = {k.strip(): v.strip() for k, v in (h.split(":", 1) for h in r.get("headers", "").replace("\\n", "\n").split("\n") if ":" in h)}
        body = r.get("body", "").replace("\\n", "\n")
        t = time.time()
        ok, got = self.host.fetch(r["url"], r["method"], hs, body)
        if not ok:
            why = {"blocked": "blocked by the firewall (the owner allows it with: kos firewall allow app:NAME HOST PORT --proto https)",
                   "refused": "refused (no network permission, or the certificate was not verified)",
                   "bad-url": "not allowed (https URL only; headers limited to accept, content-type, authorization, x-api-key, anthropic-version, user-agent)",
                   "redirect": "the server redirected (refused)", "too-big": "the reply was too big"}.get(got, "could not reach the server")
            return [f"request failed: {why}"]
        status, hdrs, raw = got["status"], {"content-type": got["content_type"]}, got["body"][:100_000]
        text = raw.decode("utf-8", "replace"); out = [f"HTTP {status}   {int((time.time() - t) * 1000)} ms   {len(raw)} bytes", ""] + [f"{k}: {v}" for k, v in list(hdrs.items())[:12]] + [""]
        try:
            data = json.loads(text)
            if r.get("pick"):
                try: out += ["picked " + r["pick"] + ":", json.dumps(json_pick(data, r["pick"]), indent=2)]
                except (KeyError, IndexError, ValueError, TypeError): out.append(f"path {r['pick']} not found")
            else: out += json.dumps(data, indent=2).split("\n")
        except ValueError: out += text.split("\n")
        return out[:400]


SAFE_MODULES = {"math", "random", "json", "re", "statistics", "datetime", "itertools", "collections", "string", "functools", "decimal", "fractions"}


def run_script(code: str, seconds: float = 5.0) -> tuple[str, str]:
    """Run Python with a time limit and a small import allowlist. This is NOT a
    security boundary - the app's sandbox is - it just keeps scripts honest."""
    real_import = __import__
    def imp(name, *a, **k):
        if name.split(".")[0] not in SAFE_MODULES: raise ImportError(f"import of '{name}' is not allowed here")
        return real_import(name, *a, **k)
    import builtins
    safe = {k: v for k, v in vars(builtins).items() if k not in ("open", "exec", "eval", "compile", "input", "breakpoint", "exit", "quit", "__import__", "help")}
    safe["__import__"] = imp
    out, err = io.StringIO(), ""
    def alarm(*_): raise TimeoutError(f"stopped after {seconds:g}s")
    old = signal.signal(signal.SIGALRM, alarm); signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(code, "<script>", "exec"), {"__builtins__": safe, "__name__": "__main__"})
    except BaseException as e:           # noqa: BLE001 - report everything a script can raise
        tb = e.__traceback__
        while tb and tb.tb_next: tb = tb.tb_next
        err = f"{type(e).__name__}: {e}" + (f"  (line {tb.tb_lineno})" if tb and tb.tb_frame.f_code.co_filename == "<script>" else "")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, old)
    return out.getvalue()[-20000:], err


def script_editor(host, name, text, save):
    def run(ed):
        ed.on_save(ed.area.text); o, e = run_script(ed.area.text)
        return ("push", TextView("Output", (o.split("\n") if o else ["(no output)"]) + (["", "ERROR: " + e] if e else [])))
    def check(ed): return ("push", TextView("Check", code_check(ed.area.text, "python")))
    return Editor(name, text or "# Python. Allowed imports: " + ", ".join(sorted(SAFE_MODULES)) + "\nprint('hello')\n", save, numbers=True, extra_keys={"ctrl-r": run, "ctrl-t": check}, hint="^R run  ^T check")


class Channels(Menu):
    """Local channels with @mentions, search and pins. Single device."""

    def __init__(self, host, title="Messages"):
        self.host, self.st = host, Store(host)
        self.chans: dict = self.st.load("channels", {"general": []})
        self.me = self.st.load("me", "me")
        super().__init__(title, [], [])
        self.rebuild()
        self.help = "Enter open  n new channel  u set my name  Esc quit"

    def rebuild(self):
        self.entries = [(f"#{c}  ({len(m)} msgs)", (lambda c=c: ("push", ChannelView(self, c)))) for c, m in sorted(self.chans.items())]
        self.nav.resize(len(self.entries))

    def on_enter(self): self.rebuild()

    def key(self, k):
        if k == "n": return ("push", Prompt("New channel", "Channel name:", "", self._new))
        if k == "u": return ("push", Prompt("Name", "Your display name:", self.me, self._me))
        if k == "escape": return ("quit",)
        return super().key(k)

    def _new(self, v):
        v = slug(v)
        if v: self.chans.setdefault(v, []); self.save(); self.rebuild()

    def _me(self, v):
        if v.strip(): self.me = v.strip()[:20]; self.st.save("me", self.me)

    def save(self): self.st.save("channels", self.chans)


class ChannelView(Screen):
    def __init__(self, hub: Channels, name):
        self.hub, self.name, self.title = hub, name, "#" + name
        self.inp = TextInput(); self.q = ""
        self.help = "Enter send  /find TEXT  /pin N  /del N  PgUp scroll  Esc back"

    def msgs(self): return self.hub.chans[self.name]

    def render(self, w, h):
        ms = [m for m in self.msgs() if self.q.lower() in m["t"].lower()] if self.q else self.msgs()
        lines = []
        for i, m in enumerate(ms, 1):
            body = wrap(m["t"], w - 24)
            tag = "📌" if m.get("pin") else "  "
            mention = f" (@{self.hub.me})" if f"@{self.hub.me}".lower() in m["t"].lower() else ""
            lines += [f"{tag}{i:>3} {m['at'][11:]} {m['who'][:8]:<8} {body[0]}{mention}"] + ["      " + " " * 15 + b for b in body[1:]]
        return lines[-(h - 3):] + ["", f"{self.hub.me}> " + self.inp.render()]

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "enter" and self.inp.value.strip():
            t = self.inp.value.strip(); self.inp = TextInput()
            m = re.match(r"^/(find|pin|del)\s*(.*)$", t)
            if m:
                a, arg = m.groups()
                if a == "find": self.q = arg
                elif arg.isdigit() and 0 < int(arg) <= len(self.msgs()):
                    if a == "pin": self.msgs()[int(arg) - 1]["pin"] = not self.msgs()[int(arg) - 1].get("pin")
                    else: self.msgs().pop(int(arg) - 1)
                self.hub.save(); return
            self.q = ""; self.msgs().append({"who": self.hub.me, "at": now_stamp(), "t": t}); self.hub.save()
        else: self.inp.key(k)
