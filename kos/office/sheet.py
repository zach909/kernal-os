"""Spreadsheet engine: a real formula language (no eval), and a grid editor."""

from __future__ import annotations

import csv
import io
import math
import re
import time
from typing import Any

from .ui import (Confirm, Editor, ListNav, Message, Prompt, Screen, TextInput, TextView, table)


class SheetError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def col_name(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def col_index(name: str) -> int:
    n = 0
    for ch in name:
        n = n * 26 + ord(ch) - 64
    return n - 1


_REF = re.compile(r"^\$?([A-Z]{1,3})\$?(\d{1,5})$")
_TOK = re.compile(r"""\s*(?:
    (?P<num>\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+)|
    (?P<str>"(?:[^"]|"")*")|
    (?P<ref>\$?[A-Z]{1,3}\$?\d{1,5}(?::\$?[A-Z]{1,3}\$?\d{1,5})?)|
    (?P<name>[A-Za-z_][A-Za-z0-9_.]*)|
    (?P<op><=|>=|<>|[-+*/^&=<>(),%])
)""", re.X)


def tokenize(src: str) -> list:
    out, i = [], 0
    while i < len(src):
        m = _TOK.match(src, i)
        if not m or m.end() == i:
            if src[i:].strip() == "":
                break
            raise SheetError("#PARSE!")
        i = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def to_num(v: Any) -> float:
    if isinstance(v, bool): return 1.0 if v else 0.0
    if isinstance(v, (int, float)): return float(v)
    if v is None or v == "": return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        raise SheetError("#VALUE!") from None


def to_str(v: Any) -> str:
    if v is None: return ""
    if isinstance(v, bool): return "TRUE" if v else "FALSE"
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15: return str(int(v))
    if isinstance(v, float): return f"{v:.10g}"
    return str(v)


class Sheet:
    MAXR, MAXC = 500, 52

    def __init__(self, cells: dict | None = None):
        self.cells: dict = dict(cells or {})        # "A1" -> raw text
        self._cache: dict = {}
        self._busy: set = set()
        self.names: dict = {}           # optional named values for formulas (low-code fields)

    # ---- editing
    def set(self, ref: str, raw: str) -> None:
        if raw == "": self.cells.pop(ref, None)
        else: self.cells[ref] = raw
        self._cache.clear()

    def raw(self, ref: str) -> str: return self.cells.get(ref, "")

    def extent(self) -> tuple[int, int]:
        r = c = 0
        for ref in self.cells:
            m = _REF.match(ref)
            c = max(c, col_index(m.group(1)) + 1); r = max(r, int(m.group(2)))
        return r, c

    # ---- evaluation
    def value(self, ref: str) -> Any:
        if ref in self._cache: return self._cache[ref]
        if ref in self._busy: raise SheetError("#CYCLE!")
        raw = self.cells.get(ref, "")
        self._busy.add(ref)
        try:
            if raw.startswith("="):
                try: v = Parser(self, tokenize(raw[1:])).run()
                except SheetError as e: v = e
            else:
                v = self._literal(raw)
        finally:
            self._busy.discard(ref)
        if isinstance(v, SheetError) and v.code == "#CYCLE!" and self._busy:
            raise v                    # cycles poison every cell on the loop
        self._cache[ref] = v
        return v

    @staticmethod
    def _literal(raw: str) -> Any:
        if raw == "": return None
        try: return float(raw) if not raw.lstrip("+-").isdigit() else int(raw)
        except ValueError: return raw

    def display(self, ref: str) -> str:
        try: v = self.value(ref)
        except SheetError as e: return e.code
        if isinstance(v, SheetError): return v.code
        return to_str(v)

    # ---- csv
    def to_csv(self) -> str:
        r, c = self.extent(); out = io.StringIO(); w = csv.writer(out, lineterminator="\n")
        for i in range(1, r + 1):
            w.writerow([self.display(f"{col_name(j)}{i}") for j in range(c)])
        return out.getvalue()

    @classmethod
    def from_csv(cls, text: str) -> "Sheet":
        s = cls()
        for i, row in enumerate(csv.reader(io.StringIO(text)), 1):
            for j, v in enumerate(row[:cls.MAXC]):
                if v != "": s.cells[f"{col_name(j)}{i}"] = v
        return s


class Parser:
    def __init__(self, sheet: Sheet, toks: list):
        self.sh, self.t, self.i = sheet, toks, 0

    def run(self):
        if not self.t: return None
        v = self.expr()
        if self.i != len(self.t): raise SheetError("#PARSE!")
        return v

    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def eat(self, val=None):
        k, v = self.peek()
        if val is not None and v != val: raise SheetError("#PARSE!")
        self.i += 1
        return k, v

    def expr(self): return self.compare()

    def compare(self):
        a = self.concat()
        while self.peek()[1] in ("=", "<>", "<", ">", "<=", ">="):
            op = self.eat()[1]; b = self.concat()
            try: x, y = (to_num(a), to_num(b)) if not (isinstance(a, str) or isinstance(b, str)) else (to_str(a).lower(), to_str(b).lower())
            except SheetError: x, y = to_str(a), to_str(b)
            a = {"=": x == y, "<>": x != y, "<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
        return a

    def concat(self):
        a = self.add()
        while self.peek()[1] == "&":
            self.eat(); a = to_str(a) + to_str(self.add())
        return a

    def add(self):
        a = self.mul()
        while self.peek()[1] in ("+", "-"):
            op = self.eat()[1]; b = self.mul()
            a = to_num(a) + to_num(b) if op == "+" else to_num(a) - to_num(b)
        return a

    def mul(self):
        a = self.power()
        while self.peek()[1] in ("*", "/"):
            op = self.eat()[1]; b = self.power()
            if op == "*": a = to_num(a) * to_num(b)
            else:
                d = to_num(b)
                if d == 0: raise SheetError("#DIV/0!")
                a = to_num(a) / d
        return a

    def power(self):
        a = self.unary()
        if self.peek()[1] == "^":
            self.eat(); b = self.power()
            try: a = to_num(a) ** to_num(b)
            except (OverflowError, ZeroDivisionError): raise SheetError("#NUM!") from None
            if isinstance(a, complex): raise SheetError("#NUM!")
        return a

    def unary(self):
        if self.peek()[1] == "-": self.eat(); return -to_num(self.unary())
        if self.peek()[1] == "+": self.eat(); return to_num(self.unary())
        v = self.atom()
        while self.peek()[1] == "%":
            self.eat(); v = to_num(v) / 100
        return v

    def atom(self):
        k, v = self.eat()
        if k == "num": return float(v) if ("." in v or "e" in v.lower()) else int(v)
        if k == "str": return v[1:-1].replace('""', '"')
        if k == "ref":
            if ":" in v: return self.range(v)
            return self.sh.value(v.replace("$", ""))
        if k == "op" and v == "(":
            r = self.expr(); self.eat(")"); return r
        if k == "name":
            name = v.upper()
            if self.peek()[1] == "(":
                self.eat("(")
                args = []
                if self.peek()[1] != ")":
                    args.append(self.expr())
                    while self.peek()[1] == ",": self.eat(); args.append(self.expr())
                self.eat(")")
                return call(name, args)
            if name in ("TRUE", "FALSE"): return name == "TRUE"
            if v in self.sh.names: return self.sh.names[v]
            raise SheetError("#NAME?")
        raise SheetError("#PARSE!")

    def range(self, text: str) -> list:
        a, b = text.replace("$", "").split(":")
        ma, mb = _REF.match(a), _REF.match(b)
        c1, c2 = sorted((col_index(ma.group(1)), col_index(mb.group(1))))
        r1, r2 = sorted((int(ma.group(2)), int(mb.group(2))))
        if (r2 - r1 + 1) * (c2 - c1 + 1) > 20000: raise SheetError("#REF!")
        vals = []
        for r in range(r1, r2 + 1):
            for c in range(c1, c2 + 1):
                v = self.sh.value(f"{col_name(c)}{r}")
                if isinstance(v, SheetError): raise v
                vals.append(v)
        return vals


def _flat(args):
    for a in args:
        if isinstance(a, list):
            yield from a
        else:
            yield a


def _nums(args):
    out = []
    for a in args:
        if isinstance(a, list):
            out += [float(x) for x in a if isinstance(x, (int, float)) and not isinstance(x, bool)]
        else:
            out.append(to_num(a))
    return out


def call(name: str, a: list):
    n = _nums
    if name == "SUM": return sum(n(a))
    if name == "AVERAGE":
        v = n(a)
        if not v: raise SheetError("#DIV/0!")
        return sum(v) / len(v)
    if name == "MIN": return min(n(a) or [0])
    if name == "MAX": return max(n(a) or [0])
    if name == "COUNT": return len(n([x for x in _flat(a) if isinstance(x, (int, float))]))
    if name == "COUNTA": return sum(1 for x in _flat(a) if x not in (None, ""))
    if name == "PRODUCT":
        p = 1.0
        for x in n(a): p *= x
        return p
    if name == "MEDIAN":
        v = sorted(n(a))
        if not v: raise SheetError("#NUM!")
        m = len(v) // 2
        return v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2
    if name == "STDEV":
        v = n(a)
        if len(v) < 2: raise SheetError("#DIV/0!")
        mu = sum(v) / len(v)
        return math.sqrt(sum((x - mu) ** 2 for x in v) / (len(v) - 1))
    if name == "IF":
        if len(a) < 2: raise SheetError("#PARSE!")
        cond = a[0]
        truthy = bool(to_num(cond)) if not isinstance(cond, str) else cond.upper() == "TRUE"
        return a[1] if truthy else (a[2] if len(a) > 2 else False)
    if name == "AND": return all(bool(to_num(x)) for x in _flat(a))
    if name == "OR": return any(bool(to_num(x)) for x in _flat(a))
    if name == "NOT": return not bool(to_num(a[0]))
    if name == "ROUND":
        d = int(to_num(a[1])) if len(a) > 1 else 0
        x, f = to_num(a[0]), 10 ** d
        return math.floor(abs(x) * f + 0.5) / f * (1 if x >= 0 else -1)
    if name == "ABS": return abs(to_num(a[0]))
    if name == "SQRT":
        x = to_num(a[0])
        if x < 0: raise SheetError("#NUM!")
        return math.sqrt(x)
    if name == "POWER": return to_num(a[0]) ** to_num(a[1])
    if name == "MOD":
        if to_num(a[1]) == 0: raise SheetError("#DIV/0!")
        return to_num(a[0]) % to_num(a[1])
    if name in ("INT", "FLOOR"): return math.floor(to_num(a[0]))
    if name == "CEILING": return math.ceil(to_num(a[0]))
    if name == "LEN": return len(to_str(a[0]))
    if name == "UPPER": return to_str(a[0]).upper()
    if name == "LOWER": return to_str(a[0]).lower()
    if name == "TRIM": return " ".join(to_str(a[0]).split())
    if name in ("CONCAT", "CONCATENATE"): return "".join(to_str(x) for x in _flat(a))
    if name == "LEFT": return to_str(a[0])[:int(to_num(a[1])) if len(a) > 1 else 1]
    if name == "RIGHT":
        k = int(to_num(a[1])) if len(a) > 1 else 1
        return to_str(a[0])[-k:] if k else ""
    if name == "TODAY": return time.strftime("%Y-%m-%d")
    if name == "CONTAINS": return to_str(a[1]).strip().lower() in [x.strip().lower() for x in to_str(a[0]).replace(";", ",").split(",")] or to_str(a[1]).lower() in to_str(a[0]).lower()
    if name in ("DATEADD", "DAYS"):
        import datetime as _dt
        try:
            d0 = _dt.date.fromisoformat(to_str(a[0]))
            if name == "DATEADD": return (d0 + _dt.timedelta(days=int(to_num(a[1])))).isoformat()
            return (_dt.date.fromisoformat(to_str(a[1])) - d0).days
        except (ValueError, IndexError): raise SheetError("#VALUE!") from None
    if name == "SUMIF":
        rng, crit = a[0], a[1]
        tot = a[2] if len(a) > 2 else rng
        tot = tot if isinstance(tot, list) else [tot]
        rng = rng if isinstance(rng, list) else [rng]
        s = 0.0
        for x, t in zip(rng, tot):
            if _match(x, crit) and isinstance(t, (int, float)): s += t
        return s
    if name == "COUNTIF":
        rng = a[0] if isinstance(a[0], list) else [a[0]]
        return sum(1 for x in rng if _match(x, a[1]))
    raise SheetError("#NAME?")


def _match(x, crit) -> bool:
    c = to_str(crit)
    m = re.match(r"^(<=|>=|<>|<|>|=)(.*)$", c)
    if m:
        op, rhs = m.groups()
        try:
            l, r = to_num(x), float(rhs)
        except (SheetError, ValueError):
            l, r = to_str(x).lower(), rhs.lower()
        return {"<": l < r, ">": l > r, "<=": l <= r, ">=": l >= r, "<>": l != r, "=": l == r}[op]
    try: return to_num(x) == float(c)
    except (SheetError, ValueError): return to_str(x).lower() == c.lower()


def adjust_formula(raw: str, dr: int, dc: int) -> str:
    """Shift relative refs when copying a formula by (dr, dc)."""
    if not raw.startswith("="): return raw
    def sub(m):
        cabs, c, rabs, r = m.group(1), m.group(2), m.group(3), int(m.group(4))
        nc = c if cabs else col_name(max(0, col_index(c) + dc))
        nr = r if rabs else max(1, r + dr)
        return f"{cabs}{nc}{rabs}{nr}"
    parts = re.split(r'("(?:[^"]|"")*")', raw)
    return "".join(p if p.startswith('"') else re.sub(r"(\$?)([A-Z]{1,3})(\$?)(\d{1,5})", sub, p) for p in parts)


# ------------------------------------------------------------- the editor --
class SheetEditor(Screen):
    CW = 10

    def __init__(self, name: str, sheet: Sheet, on_save):
        self.title, self.sh, self.on_save = name, sheet, on_save
        self.r = self.c = 0
        self.top = self.left = 0
        self.inp: TextInput | None = None
        self.clip = ""
        self.clip_at = (0, 0)
        self.msg = ""
        self.dirty = False
        self.help = "arrows move  Enter/type edit  Del clear  ^C copy ^V paste  / menu  ^S save"

    @property
    def ref(self): return f"{col_name(self.c)}{self.r + 1}"

    def render(self, w, h):
        vis_c = max(1, (w - 5) // (self.CW + 1))
        vis_r = max(1, h - 4)
        if self.c < self.left: self.left = self.c
        if self.c >= self.left + vis_c: self.left = self.c - vis_c + 1
        if self.r < self.top: self.top = self.r
        if self.r >= self.top + vis_r: self.top = self.r - vis_r + 1
        raw = self.inp.render() if self.inp is not None else self.sh.raw(self.ref)
        out = [f" {self.ref}: {raw}" + (f"   = {self.sh.display(self.ref)}" if self.sh.raw(self.ref).startswith("=") and self.inp is None else "")]
        out.append("     " + "".join(f"{col_name(c):^{self.CW}} " for c in range(self.left, self.left + vis_c)))
        for r in range(self.top, self.top + vis_r):
            row = f"{r + 1:>4} "
            for c in range(self.left, self.left + vis_c):
                ref = f"{col_name(c)}{r + 1}"
                t = self.sh.display(ref)
                num = t.replace(".", "", 1).lstrip("-").isdigit()
                cell = (t[:self.CW].rjust(self.CW) if num else t[:self.CW].ljust(self.CW))
                if r == self.r and c == self.c:
                    cell = "[" + cell[1:-1] + "]" if len(cell) > 2 else cell
                row += cell + " "
            out.append(row)
        if self.msg: out.append(" " + self.msg)
        return out

    def commit(self):
        self.sh.set(self.ref, self.inp.value); self.inp = None; self.dirty = True

    def key(self, k):
        self.msg = ""
        if self.inp is not None:
            if k == "enter": self.commit(); self.r = min(self.r + 1, Sheet.MAXR - 1)
            elif k == "tab": self.commit(); self.c = min(self.c + 1, Sheet.MAXC - 1)
            elif k == "escape": self.inp = None
            else: self.inp.key(k)
            return
        if k == "up": self.r = max(0, self.r - 1)
        elif k == "down": self.r = min(Sheet.MAXR - 1, self.r + 1)
        elif k == "left": self.c = max(0, self.c - 1)
        elif k == "right" or k == "tab": self.c = min(Sheet.MAXC - 1, self.c + 1)
        elif k == "pageup": self.r = max(0, self.r - 15)
        elif k == "pagedown": self.r = min(Sheet.MAXR - 1, self.r + 15)
        elif k == "home": self.c = 0
        elif k == "enter": self.inp = TextInput(self.sh.raw(self.ref))
        elif k in ("delete", "backspace"): self.sh.set(self.ref, ""); self.dirty = True
        elif k == "ctrl-c": self.clip, self.clip_at = self.sh.raw(self.ref), (self.r, self.c); self.msg = "copied"
        elif k == "ctrl-v":
            self.sh.set(self.ref, adjust_formula(self.clip, self.r - self.clip_at[0], self.c - self.clip_at[1])); self.dirty = True
        elif k == "ctrl-d":      # fill down from the cell above
            if self.r:
                self.sh.set(self.ref, adjust_formula(self.sh.raw(f"{col_name(self.c)}{self.r}"), 1, 0)); self.dirty = True
        elif k == "ctrl-s": self.save()
        elif k == "/": return ("push", Prompt("Command", "goto REF | sort COL [desc] | csv | import | clear | stats", "", self.command))
        elif k == "escape":
            if self.dirty:
                return ("push", Confirm("Unsaved changes. Save?", lambda: (self.save(), ("pop", None))[1]))
            return ("pop", None)
        elif len(k) == 1 and k.isprintable():
            self.inp = TextInput(""); self.inp.key(k)

    def save(self):
        self.on_save(self.sh); self.dirty = False; self.msg = "saved"

    def command(self, text):
        p = text.split()
        if not p: return
        c = p[0].lower()
        if c == "goto" and len(p) > 1:
            m = _REF.match(p[1].upper())
            if m: self.c, self.r = col_index(m.group(1)), int(m.group(2)) - 1
        elif c == "sort" and len(p) > 1:
            return self.sort(col_index(p[1].upper()), len(p) > 2 and p[2].lower().startswith("d"))
        elif c == "csv": return ("push", TextView("CSV", self.sh.to_csv().split("\n")))
        elif c == "import":
            return ("push", Editor("Import CSV (replaces this sheet)", "", on_save=self._import))
        elif c == "clear": self.sh.cells.clear(); self.sh._cache.clear(); self.dirty = True
        elif c == "stats":
            vals = [to_num(self.sh.value(f"{col_name(self.c)}{i}")) for i in range(1, self.sh.extent()[0] + 1)
                    if isinstance(self.sh.value(f"{col_name(self.c)}{i}"), (int, float))]
            if vals:
                self.msg = (f"col {col_name(self.c)}: n={len(vals)} sum={sum(vals):g} mean={sum(vals) / len(vals):g} "
                            f"min={min(vals):g} max={max(vals):g}")
        else:
            self.msg = "unknown command"

    def _import(self, text):
        self.sh.cells = Sheet.from_csv(text).cells; self.sh._cache.clear(); self.dirty = True

    def sort(self, col: int, desc: bool):
        rows = self.sh.extent()[0]
        if rows < 2: return
        width = self.sh.extent()[1]
        grid = [[self.sh.raw(f"{col_name(j)}{i}") for j in range(width)] for i in range(1, rows + 1)]
        def key(row):
            v = self.sh.value(f"{col_name(col)}{grid.index(row) + 1}") if False else row[col] if col < width else ""
            try: return (0, float(v), "")
            except ValueError: return (1, 0.0, v.lower())
        grid.sort(key=key, reverse=desc)
        self.sh.cells = {f"{col_name(j)}{i + 1}": v for i, row in enumerate(grid) for j, v in enumerate(row) if v}
        self.sh._cache.clear(); self.dirty = True
        self.msg = f"sorted by {col_name(col)}"
