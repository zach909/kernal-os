"""A real SQL console on SQLite (in memory), persisted to the vault as a SQL
dump after every change. Saved queries double as an ordered pipeline."""

from __future__ import annotations

import csv
import io
import sqlite3

from .ui import ListNav, Screen, Store, TextInput, TextView, table

_DENY = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH}


def _auth(action, a, b, c, d):
    return sqlite3.SQLITE_DENY if action in _DENY else sqlite3.SQLITE_OK


def open_db(dump: str | None) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    if dump:
        con.executescript(dump)
    con.set_authorizer(_auth)          # after loading; no ATTACH of host files, ever
    return con


def statements(text: str):
    buf = ""
    for ch in text:
        buf += ch
        if ch == ";" and sqlite3.complete_statement(buf):
            yield buf.strip(); buf = ""
    if buf.strip():
        yield buf.strip()


class SqlConsole(Screen):
    def __init__(self, host, title="Database", extras: bool = True):
        self.host, self.title, self.st = host, title, Store(host)
        self.con = open_db(host.get("db"))
        self.saved: dict = self.st.load("queries", {})
        self.inp = TextInput()
        self.hist: list = []
        self.out: list = ["Type SQL and press Enter.  .help lists commands."]
        self.last: tuple = ([], [])
        self.top = 0
        self.help = "Enter run   up/down history   PageUp/PageDown scroll   Esc quit"
        self.hi = 0

    def persist(self):
        self.host.put("db", "\n".join(self.con.iterdump()))

    def render(self, w, h):
        lines = self.out
        body = max(3, h - 3)
        self.top = max(0, min(self.top, max(0, len(lines) - body))) if self.top >= 0 else max(0, len(lines) - body)
        return lines[self.top:self.top + body] + ["", "sql> " + self.inp.render()]

    def run_sql(self, text: str):
        res, changed = [], False
        for stmt in statements(text):
            try:
                cur = self.con.execute(stmt)
                if cur.description:
                    rows = cur.fetchmany(500)
                    cols = [d[0] for d in cur.description]
                    self.last = (cols, rows)
                    res += table(rows, cols, maxw=76) + [f"({len(rows)} row{'s' if len(rows) != 1 else ''})"]
                else:
                    changed = changed or not stmt.lower().startswith(("select", "pragma", "explain"))
                    res.append(f"ok ({max(cur.rowcount, 0)} row(s) affected)")
            except sqlite3.Error as e:
                res.append(f"error: {e}"); break
        if changed:
            self.con.commit(); self.persist()
        return res

    def command(self, line: str):
        p = line.split()
        c = p[0]
        if c == ".help":
            return [".tables   .schema [table]   .csv (last result to vault)   .save NAME SQL",
                    ".queries   .run NAME   .runall (every saved query, in order)   .drop NAME   .clear"]
        if c == ".tables":
            return [r[0] for r in self.con.execute("select name from sqlite_master where type in ('table','view') order by 1")] or ["(no tables)"]
        if c == ".schema":
            q = "select sql from sqlite_master where sql is not null" + (" and name=?" if len(p) > 1 else "")
            return [r[0] + ";" for r in self.con.execute(q, p[1:2])] or ["(nothing)"]
        if c == ".csv":
            cols, rows = self.last
            buf = io.StringIO(); w = csv.writer(buf, lineterminator="\n"); w.writerow(cols); w.writerows(rows)
            self.host.put("export.csv", buf.getvalue()); return [f"wrote {len(rows)} rows to vault key 'export.csv'"]
        if c == ".save" and len(p) > 2:
            self.saved[p[1]] = line.split(None, 2)[2]; self.st.save("queries", self.saved); return [f"saved {p[1]}"]
        if c == ".queries":
            return [f"{i + 1}. {k}: {v}" for i, (k, v) in enumerate(self.saved.items())] or ["(none saved)"]
        if c == ".run" and len(p) > 1:
            return self.run_sql(self.saved[p[1]]) if p[1] in self.saved else ["no such query"]
        if c == ".runall":
            out = []
            for k, v in self.saved.items():
                out += [f"-- {k}"] + self.run_sql(v)
            return out or ["(no saved queries)"]
        if c == ".drop" and len(p) > 1:
            self.saved.pop(p[1], None); self.st.save("queries", self.saved); return ["dropped"]
        if c == ".clear":
            self.out.clear(); return []
        return ["unknown command; .help"]

    def key(self, k):
        if k == "enter":
            line = self.inp.value.strip()
            if not line: return
            self.hist.append(line); self.hi = len(self.hist)
            self.out += ["sql> " + line] + (self.command(line) if line.startswith(".") else self.run_sql(line))
            self.inp = TextInput(); self.top = -1
        elif k == "up" and self.hist:
            self.hi = max(0, self.hi - 1); self.inp = TextInput(self.hist[self.hi])
        elif k == "down" and self.hist:
            self.hi = min(len(self.hist), self.hi + 1); self.inp = TextInput(self.hist[self.hi] if self.hi < len(self.hist) else "")
        elif k == "pageup": self.top = max(0, (self.top if self.top >= 0 else len(self.out)) - 10)
        elif k == "pagedown": self.top = (self.top if self.top >= 0 else len(self.out)) + 10
        elif k == "escape": return ("quit",)
        else: self.inp.key(k)
