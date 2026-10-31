"""A spec-driven record manager. One engine, many products.

A ``Spec`` says what a record looks like (typed fields), which field is its
workflow status, which is an amount, which is a due date. The engine gives
every spec the same real behaviour: add / edit / delete, typed validation,
search, sort, filter by status, a kanban board, a grouped summary, CSV export
and CSV import, and durable storage in the app's vault.

This is what the 'manager / register / tracker' products in the suite run on.
It is honest about being a record manager: a Backup System built on it keeps
the backup job register, it does not copy files (apps can't see your files).
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from typing import Optional

from .ui import (Confirm, Editor, ListNav, Message, Prompt, Screen, Store, TextInput, TextView,
                 bar, now_stamp, run, table, today, wrap)

KINDS = ("text", "long", "number", "money", "percent", "date", "choice", "bool", "email",
         "phone", "url", "tags")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PHONE = re.compile(r"^\+?[0-9 ()\-.]{5,20}$")


@dataclass
class Field:
    key: str
    label: str
    kind: str = "text"
    choices: tuple = ()
    default: str = ""
    required: bool = False

    def __post_init__(self):
        assert self.kind in KINDS, self.kind
        if self.kind == "choice":
            assert self.choices, f"{self.key}: choice field needs choices"


@dataclass
class Spec:
    id: str
    title: str
    item: str                         # singular noun: "contact"
    fields: list
    list_cols: tuple = ()             # field keys shown in the list (default: first 3)
    status: str = ""                  # key of a choice field = workflow state (board, cycling)
    done: tuple = ()                  # status values that mean "finished"
    amount: str = ""                  # key of a number/money field to total
    due: str = ""                     # key of a date field; past + not done = overdue
    group: str = ""                   # key to group the summary by (default: status)
    blurb: str = ""
    seed: tuple = ()                  # starter records (dicts) for first run
    calc: tuple = ()                  # ((field key, expression), ...) recomputed on every save
    start: str = ""                   # key of a date field: with `due` it enables the timeline (t)
    report: object = None             # callable(items) -> list[str]; shown with R
    report_label: str = "Report"
    scope: str = ""                   # honest one-line note on what this app is / is not

    def field(self, key: str) -> Field:
        return next(f for f in self.fields if f.key == key)

    def cols(self) -> tuple:
        return self.list_cols or tuple(f.key for f in self.fields[:3])


def validate(f: Field, raw: str) -> tuple[bool, str]:
    """-> (ok, normalised value or error message)"""
    v = raw.strip()
    if not v:
        return (not f.required, "required" if f.required else "")
    k = f.kind
    if k in ("number", "money", "percent"):
        try:
            n = float(v.replace(",", "").lstrip("$€£"))
        except ValueError:
            return False, "must be a number"
        if k == "percent" and not 0 <= n <= 100:
            return False, "must be 0-100"
        return True, (str(int(n)) if n == int(n) else f"{n:.2f}".rstrip("0").rstrip("."))
    if k == "date":
        if not _DATE.match(v):
            return False, "use YYYY-MM-DD"
        y, m, d = int(v[:4]), int(v[5:7]), int(v[8:])
        if not (1 <= m <= 12 and 1 <= d <= _dim(y, m)):
            return False, "not a real date"
        return True, v
    if k == "choice":
        for c in f.choices:
            if c.lower() == v.lower():
                return True, c
        return False, "one of: " + ", ".join(f.choices)
    if k == "bool":
        if v.lower() in ("y", "yes", "true", "1", "x"): return True, "yes"
        if v.lower() in ("n", "no", "false", "0"): return True, "no"
        return False, "yes or no"
    if k == "email":
        return (True, v) if _EMAIL.match(v) else (False, "not an email address")
    if k == "phone":
        return (True, v) if _PHONE.match(v) else (False, "not a phone number")
    if k == "url":
        return (True, v) if re.match(r"^https?://\S+$", v) else (False, "must start with http(s)://")
    if k == "tags":
        return True, ", ".join(sorted({t.strip().lower() for t in v.split(",") if t.strip()}))
    return True, v


def _dim(y: int, m: int) -> int:
    if m == 2:
        return 29 if (y % 4 == 0 and (y % 100 or y % 400 == 0)) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


class Data:
    """The records of one app, kept in the vault."""

    def __init__(self, host, spec: Spec, key: str = "records"):
        self.spec, self.store, self.key = spec, Store(host), key
        d = self.store.load(key) or None
        if d is None:
            d = {"next": 1, "items": []}
            for s in spec.seed:
                d["items"].append({**s, "_id": d["next"], "_at": now_stamp()}); d["next"] += 1
        self.d = d

    @property
    def items(self) -> list:
        return self.d["items"]

    def save(self) -> None:
        self.store.save(self.key, self.d)

    def derive(self, rec: dict) -> dict:
        if self.spec.calc:
            from .tools import _row_eval
            from .sheet import SheetError, to_str
            for key, expr in self.spec.calc:
                try: rec[key] = to_str(_row_eval(expr, rec))
                except SheetError as e: rec[key] = e.code
        return rec

    def add(self, rec: dict) -> dict:
        rec = self.derive({**rec, "_id": self.d["next"], "_at": now_stamp()})
        self.d["next"] += 1
        self.items.append(rec)
        self.save()
        return rec

    def update(self, rec: dict) -> None:
        self.derive(rec)
        for i, r in enumerate(self.items):
            if r["_id"] == rec["_id"]:
                self.items[i] = rec
        self.save()

    def remove(self, rec: dict) -> None:
        self.d["items"] = [r for r in self.items if r["_id"] != rec["_id"]]
        self.save()

    def is_overdue(self, r: dict) -> bool:
        s = self.spec
        if not s.due or not r.get(s.due):
            return False
        if s.status and r.get(s.status) in s.done:
            return False
        return r[s.due] < today()

    def to_csv(self, rows: Optional[list] = None) -> str:
        out = io.StringIO()
        w = csv.writer(out, lineterminator="\n")
        w.writerow([f.label for f in self.spec.fields])
        for r in (self.items if rows is None else rows):
            w.writerow([r.get(f.key, "") for f in self.spec.fields])
        return out.getvalue()

    def import_csv(self, text: str) -> tuple[int, list]:
        """Header row (labels or keys, any order) + rows. -> (added, errors)"""
        rows = list(csv.reader(io.StringIO(text.strip("\n"))))
        if not rows:
            return 0, ["empty"]
        names = {f.label.lower(): f for f in self.spec.fields}
        names.update({f.key.lower(): f for f in self.spec.fields})
        cols = [names.get(h.strip().lower()) for h in rows[0]]
        if not any(cols):
            return 0, ["first line must be a header with field names"]
        added, errs = 0, []
        for n, row in enumerate(rows[1:], 2):
            rec, bad = {}, None
            for f, v in zip(cols, row):
                if f is None:
                    continue
                ok, val = validate(f, v)
                if not ok:
                    bad = f"line {n}: {f.label} {val}"; break
                rec[f.key] = val
            if bad:
                errs.append(bad); continue
            for f in self.spec.fields:
                rec.setdefault(f.key, f.default)
            self.add(rec); added += 1
        return added, errs


# ------------------------------------------------------------- screens ----
class RecordForm(Screen):
    """Edit one record, one field at a time, with validation."""

    def __init__(self, data: Data, rec: Optional[dict], on_done):
        self.data, self.on_done = data, on_done
        self.new = rec is None
        self.rec = dict(rec) if rec else {f.key: f.default for f in data.spec.fields}
        self.title = ("New " if self.new else "Edit ") + data.spec.item
        self.nav = ListNav(len(data.spec.fields))
        self.inp: Optional[TextInput] = None
        self.err = ""
        self.help = "up/down field   Enter edit   Ctrl-S save   Esc cancel"

    def render(self, w, h):
        out = []
        for i, f in enumerate(self.data.spec.fields):
            cur = i == self.nav.sel
            val = self.rec.get(f.key, "")
            if cur and self.inp is not None:
                val = self.inp.render()
            hint = f"  ({'/'.join(f.choices)})" if f.kind == "choice" and cur else ""
            out.append(f"{'>' if cur else ' '} {f.label + ('*' if f.required else ''):<18} {val}{hint}")
        if self.err:
            out += ["", "  ! " + self.err]
        return out

    def key(self, k):
        f = self.data.spec.fields[self.nav.sel]
        if self.inp is not None:
            if k == "escape": self.inp = None; self.err = ""; return
            if k == "enter":
                ok, val = validate(f, self.inp.value)
                if ok: self.rec[f.key] = val; self.inp = None; self.err = ""; self.nav.key("down")
                else: self.err = f"{f.label}: {val}"
                return
            self.inp.key(k); return
        if self.nav.key(k): return
        if k == "ctrl-s":
            for g in self.data.spec.fields:
                ok, val = validate(g, self.rec.get(g.key, ""))
                if not ok:
                    self.err = f"{g.label}: {val}"; self.nav.sel = self.data.spec.fields.index(g); return
            return ("pop", lambda: self.on_done(self.rec))
        if k == "escape": return ("pop", None)
        if f.kind == "choice" and k in ("left", "right", " "):
            cs = list(f.choices); cur = self.rec.get(f.key, "")
            i = cs.index(cur) if cur in cs else -1
            self.rec[f.key] = cs[(i + (-1 if k == "left" else 1)) % len(cs)]
        elif f.kind == "bool" and k in ("left", "right", " "):
            self.rec[f.key] = "no" if self.rec.get(f.key) == "yes" else "yes"
        elif k == "enter" and f.kind in ("choice", "bool"):
            self.nav.key("down")
        elif k == "enter":
            if f.kind == "long":
                return ("push", Editor(f.label, self.rec.get(f.key, "").replace("\\n", "\n"),
                                       on_save=lambda t: self.rec.__setitem__(f.key, t.replace("\n", "\\n"))))
            self.inp = TextInput(self.rec.get(f.key, ""))


class RecordList(Screen):
    def __init__(self, data: Data):
        self.data, self.spec = data, data.spec
        self.title = data.spec.title
        self.nav = ListNav(0)
        self.query = ""
        self.sort_i = -1
        self.filt: Optional[str] = None
        self.msg = ""
        self.help = ("a add  Enter open  e edit  d delete  / search  s sort  f filter  "
                     + ("space status  b board  " if self.spec.status else "")
                     + ("t timeline  " if self.spec.start and self.spec.due else "") + ("R report  " if self.spec.report else "")
                     + "g summary  x export  i import  ? help")

    def rows(self) -> list:
        sp, rows = self.spec, self.data.items
        if self.query:
            q = self.query.lower()
            rows = [r for r in rows if any(q in str(v).lower() for k, v in r.items() if not k.startswith("_"))]
        if self.filt and sp.status:
            rows = [r for r in rows if r.get(sp.status) == self.filt]
        if self.sort_i >= 0:
            k = sp.fields[self.sort_i].key
            nk = sp.fields[self.sort_i].kind in ("number", "money", "percent")
            rows = sorted(rows, key=lambda r: num(r.get(k)) if nk else str(r.get(k, "")).lower())
        return rows

    def current(self) -> Optional[dict]:
        rows = self.rows()
        return rows[self.nav.sel] if rows else None

    def render(self, w, h):
        rows = self.rows()
        self.nav.resize(len(rows))
        sp = self.spec
        keys = sp.cols()
        heads = [sp.field(k).label for k in keys]
        out = []
        flt = [f"search='{self.query}'" if self.query else "",
               f"{sp.status}={self.filt}" if self.filt else "",
               f"sort={sp.fields[self.sort_i].label}" if self.sort_i >= 0 else ""]
        out.append(f" {len(rows)} of {len(self.data.items)} {sp.item}s   " + "  ".join(x for x in flt if x))
        if sp.blurb and not self.data.items:
            out += ["", *("  " + l for l in wrap(sp.blurb, w - 4)), "", f"  Press a to add the first {sp.item}."]
        top, end = self.nav.window(h - 4)
        shown = rows[top:end]
        tbl = table([[("! " if self.data.is_overdue(r) else "  ") + str(r.get(keys[0], ""))]
                     + [r.get(k, "") for k in keys[1:]] for r in shown], ["  " + heads[0], *heads[1:]],
                    maxw=w - 4)
        out += [tbl[0], tbl[1]]
        for i, line in enumerate(tbl[2:]):
            out.append(("> " if top + i == self.nav.sel else "  ") + line)
        if self.msg:
            out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        cur = self.current()
        sp = self.spec
        if k == "a":
            return ("push", RecordForm(self.data, None, self._added))
        if k in ("enter", "e") and cur:
            return ("push", RecordForm(self.data, cur, self._saved) if k == "e" else Detail(self.data, cur, self))
        if k == "d" and cur:
            return ("push", Confirm(f"Delete this {sp.item}?", lambda: self._deleted(cur)))
        if k == "/":
            return ("push", Prompt("Search", "Search for (empty clears):", self.query, self._search))
        if k == "s":
            self.sort_i = (self.sort_i + 1) % (len(sp.fields) + 1) - 1 if self.sort_i < len(sp.fields) - 1 else -1
            self.msg = "sorted by " + (sp.fields[self.sort_i].label if self.sort_i >= 0 else "entry order")
        elif k == "f" and sp.status:
            cs = [None, *sp.field(sp.status).choices]
            self.filt = cs[(cs.index(self.filt) + 1) % len(cs)]
        elif k == " " and cur and sp.status:
            f = sp.field(sp.status); cs = list(f.choices)
            i = cs.index(cur.get(sp.status)) if cur.get(sp.status) in cs else -1
            cur[sp.status] = cs[(i + 1) % len(cs)]; self.data.update(cur)
        elif k == "b" and sp.status:
            return ("push", Board(self.data))
        elif k == "g":
            return ("push", TextView(f"{sp.title} - summary", summary(self.data)))
        elif k == "t" and sp.start and sp.due:
            return ("push", TextView(f"{sp.title} - timeline", timeline(self.data)))
        elif k == "R" and sp.report:
            return ("push", TextView(sp.report_label, sp.report(self.data.items)))
        elif k == "x":
            self.data.store.host.put("export.csv", self.data.to_csv(self.rows()))
            self.msg = "exported to vault key 'export.csv'"
            return ("push", TextView("Export (CSV)", self.data.to_csv(self.rows()).split("\n")))
        elif k == "i":
            return ("push", Editor(f"Import {sp.item}s (CSV: header line, then rows)", "",
                                   on_save=self._import, hint="paste CSV, Ctrl-S"))
        elif k == "?":
            return ("push", TextView("Help", HELP.split("\n")))
        elif k == "escape":
            if self.query or self.filt:
                self.query, self.filt = "", None
            else:
                return ("quit",)

    def _search(self, v): self.query = v.strip(); self.nav.sel = 0
    def _added(self, rec): self.data.add(rec); self.msg = f"added {self.spec.item}"
    def _saved(self, rec): self.data.update(rec); self.msg = "saved"
    def _deleted(self, rec): self.data.remove(rec); self.msg = "deleted"

    def _import(self, text):
        n, errs = self.data.import_csv(text)
        self.msg = f"imported {n}" + (f"; {len(errs)} problems: {errs[0]}" if errs else "")


HELP = """a add    Enter details    e edit    d delete
/ search (Esc clears)    s cycle sort    f cycle status filter
space  advance the status of the selected record
b      board view (records grouped by status)
g      summary (counts, totals, progress)
x      export the shown records as CSV
i      import CSV (header line with field names, then rows)
Esc    back / quit"""


class Detail(Screen):
    def __init__(self, data: Data, rec: dict, parent: RecordList):
        self.data, self.rec, self.parent = data, rec, parent
        self.title = str(rec.get(data.spec.fields[0].key, ""))[:30]
        self.help = "e edit   d delete   Esc back"

    def render(self, w, h):
        out = []
        for f in self.data.spec.fields:
            v = str(self.rec.get(f.key, "")).replace("\\n", "\n")
            lines = wrap(v, w - 24) or [""]
            out.append(f"  {f.label:<18} {lines[0]}")
            out += [" " * 21 + l for l in lines[1:]]
        out += ["", f"  (record {self.rec['_id']}, added {self.rec.get('_at', '')})"]
        if self.data.is_overdue(self.rec):
            out.append("  ! OVERDUE")
        return out[:h]

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "e":
            return ("replace", RecordForm(self.data, self.rec, lambda r: self.parent._saved(r)))
        if k == "d":
            return ("push", Confirm("Delete?", lambda: (self.parent._deleted(self.rec), ("pop", None))[1]))


class Board(Screen):
    def __init__(self, data: Data):
        self.data, self.spec = data, data.spec
        self.title = "Board"
        self.col = 0
        self.nav = ListNav(0)
        self.help = "left/right column   up/down card   </> move card   Esc back"

    def cols(self): return list(self.spec.field(self.spec.status).choices)

    def cards(self):
        c = self.cols()[self.col]
        return [r for r in self.data.items if r.get(self.spec.status) == c]

    def render(self, w, h):
        cs = self.cols()
        self.nav.resize(len(self.cards()))
        cw = max(10, (w - 2) // max(1, min(len(cs), 5)))
        first = max(0, min(self.col - 2, len(cs) - 5))
        vis = cs[first:first + 5]
        cols = {c: [r for r in self.data.items if r.get(self.spec.status) == c] for c in vis}
        out = ["".join(f"{'[' if c == cs[self.col] else ' '}{c[:cw - 5]} ({len(cols[c])}){']' if c == cs[self.col] else ' '}".ljust(cw) for c in vis),
               "".join(("-" * (cw - 1)).ljust(cw) for _ in vis)]
        key0 = self.spec.fields[0].key
        for i in range(max(1, min(h - 4, max(len(v) for v in cols.values()) if cols else 1))):
            row = ""
            for c in vis:
                cell = ""
                if i < len(cols[c]):
                    mark = ">" if c == cs[self.col] and i == self.nav.sel else " "
                    cell = mark + str(cols[c][i].get(key0, ""))[:cw - 3]
                row += cell.ljust(cw)
            out.append(row)
        return out

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "left": self.col = max(0, self.col - 1); self.nav.sel = 0
        elif k == "right": self.col = min(len(self.cols()) - 1, self.col + 1); self.nav.sel = 0
        elif self.nav.key(k): pass
        elif k in ("<", ">") and self.cards():
            r = self.cards()[self.nav.sel]
            ni = max(0, min(len(self.cols()) - 1, self.col + (1 if k == ">" else -1)))
            r[self.spec.status] = self.cols()[ni]; self.data.update(r)


def timeline(data: Data) -> list:
    """Text Gantt chart from the start and due date fields."""
    import datetime as dt
    sp = data.spec
    rows = [(r, r.get(sp.start), r.get(sp.due)) for r in data.items if r.get(sp.start) and r.get(sp.due)]
    if not rows:
        return [f"No {sp.item}s with both {sp.field(sp.start).label} and {sp.field(sp.due).label} yet."]
    d0 = min(dt.date.fromisoformat(a) for _r, a, _b in rows)
    d1 = max(dt.date.fromisoformat(b) for _r, _a, b in rows)
    span = max(1, (d1 - d0).days + 1); width = 44
    out = [f"{d0} .. {d1}  ({span} days)", ""]
    for r, a, b in sorted(rows, key=lambda x: x[1]):
        s = (dt.date.fromisoformat(a) - d0).days * width // span
        e = max(s + 1, ((dt.date.fromisoformat(b) - d0).days + 1) * width // span)
        done = sp.status and r.get(sp.status) in sp.done
        out.append(f"{str(r.get(sp.fields[0].key, ''))[:20]:<20} " + " " * s + ("▒" if done else "█") * (e - s))
    return out


def summary(data: Data) -> list:
    sp = data.spec
    items = data.items
    out = [f"{len(items)} {sp.item}(s)", ""]
    gk = sp.group or sp.status
    if gk:
        f = sp.field(gk)
        groups: dict = {}
        for r in items:
            groups.setdefault(r.get(gk, "") or "(none)", []).append(r)
        mx = max([len(v) for v in groups.values()] or [1])
        out.append(f"By {f.label}:")
        for g in sorted(groups, key=lambda g: -len(groups[g])):
            line = f"  {g[:22]:<22} {len(groups[g]):>4}  {bar(len(groups[g]), mx, 24)}"
            if sp.amount:
                line += f"  {sum(num(r.get(sp.amount)) for r in groups[g]):,.2f}"
            out.append(line)
    if sp.amount:
        out += ["", f"Total {sp.field(sp.amount).label}: {sum(num(r.get(sp.amount)) for r in items):,.2f}"]
    if sp.status and sp.done and items:
        d = sum(1 for r in items if r.get(sp.status) in sp.done)
        out += ["", f"Done: {d}/{len(items)} ({100 * d // len(items)}%)  {bar(d, len(items), 30)}"]
    if sp.due:
        od = [r for r in items if data.is_overdue(r)]
        out += ["", f"Overdue: {len(od)}"] + [f"  ! {r.get(sp.fields[0].key)} ({r.get(sp.due)})" for r in od[:10]]
    return out


def make_root(host, spec: Spec) -> Screen:
    return RecordList(Data(host, spec))

