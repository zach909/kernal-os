"""pack_biz2: Accounting, Invoicing, Inventory Management, Procurement, Human Resources, ERP.

Registers reuse RecordList/Spec; the only bespoke logic is the double-entry ledger, invoice maths, stock valuation,
the three-way match, leave accrual and the org chart. Money is integer cents or Decimal, never float. Single user,
local, no network. See docs/PACKS.md. Shared folders: Invoicing owns `invoices` (reads `contacts`), Inventory owns
`inventory`, HR owns `employees`; Accounting reads `invoices`; Procurement reads `inventory` and `employees`."""

from __future__ import annotations

import datetime as dt
import html
import json
import re
from dataclasses import replace
from decimal import Decimal as D, InvalidOperation, ROUND_HALF_UP
from types import SimpleNamespace as NS

from .packkit import app, none, shared_items  # noqa: F401
from .records import Board, Data, RecordList
from .specs import R
from .ui import Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, SpaceHost, Store, TextView, table, today, wrap

MAX_ITEMS, VAULT_CAP, BIG = 1000, 380_000, D(10) ** 12


# ------------------------------------------------------------------ helpers ----
def clean(s, n=200) -> str:
    return "".join(c for c in str(s) if c.isprintable())[:n]


def dec(v, what="value") -> D:
    try:
        d = D(str(v).replace(",", "").strip())
    except InvalidOperation:
        raise ValueError(f"{what} must be a number")
    if not d.is_finite() or abs(d) > BIG:
        raise ValueError(f"{what} must be a reasonable number")
    return d


def cs(d: D) -> int:
    """currency units (Decimal) -> integer cents, half up."""
    return int((d * 100).quantize(D(1), ROUND_HALF_UP))


def cents(v, what="amount") -> int:
    return cs(dec(v, what))


def plain(c: int) -> str:
    return f"{'-' if c < 0 else ''}{abs(c) // 100}.{abs(c) % 100:02d}"


def money(c: int) -> str:
    return f"{'-' if c < 0 else ''}{abs(c) // 100:,}.{abs(c) % 100:02d}"


def qty_s(d: D) -> str:
    s = format(d.normalize(), "f")
    return "0" if s in ("-0", "") else s


def day(s, what="date") -> dt.date:
    s = str(s).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise ValueError(f"{what} must be YYYY-MM-DD")
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        raise ValueError(f"{what} is not a real date")


def pick(names, v, what):
    """Customer / requester picker: if the shared list is visible the value must be on it, else free text."""
    v = clean(v).strip()
    if not v:
        raise ValueError(f"{what} is required")
    if not names:
        return v
    m = {n.lower(): n for n in names}
    if v.lower() in m:
        return m[v.lower()]
    raise ValueError(f"{what} must be one of: " + ", ".join(list(m.values())[:5]) + (" ..." if len(m) > 5 else ""))


def nogrant(space, app_name):
    return f"nothing visible in '{space}': it is empty, or not shared with this app (kos grant {app_name} space:{space} --level read)"


class PrefixHost:
    """Gives each app inside the ERP hub its own slice of the vault; shared spaces pass through untouched."""

    def __init__(self, host, prefix):
        self.h, self.p = host, prefix

    def __getattr__(self, n): return getattr(self.h, n)
    def get(self, k, space=None): return self.h.get(k, space) if space else self.h.get(self.p + k)
    def put(self, k, v, space=None): return self.h.put(k, v, space) if space else self.h.put(self.p + k, v)
    def delete(self, k, space=None): return self.h.delete(k, space) if space else self.h.delete(self.p + k)
    def keys(self, space=None): return self.h.keys(space) if space else [k[len(self.p):] for k in self.h.keys() if k.startswith(self.p)]


class GData(Data):
    """Data with a guard (business rules that refuse bad records), caps, optional sequential numbers, and a hook
    that runs after each successful change. A refused change leaves the record exactly as it was."""

    def __init__(self, host, spec, key="records", guard=None, seq=None, after=None):
        super().__init__(host, spec, key)
        self.guard, self.seq, self.after = guard, seq, after
        if not isinstance(self.d.get("seq"), int):
            self.d["seq"] = len(self.items) + 1
        self._snap()

    def _snap(self):
        self._orig = {r["_id"]: dict(r) for r in self.items}

    def _clean(self, rec):
        kinds = {f.key: f.kind for f in self.spec.fields}
        for k, v in list(rec.items()):
            if isinstance(v, str) and not k.startswith("_"):
                rec[k] = clean(v, 4000 if kinds.get(k) == "long" else 200)
        return rec

    def add(self, rec):
        if len(self.items) >= MAX_ITEMS:
            raise ValueError("register is full")
        rec = self._clean(dict(rec))
        n = self.d["seq"]
        if self.seq:
            rec[self.seq[0]] = f"{self.seq[1]}{n:04d}"
        if self.guard:
            self.guard("add", rec, self, None)
        if len(json.dumps(self.d, separators=(",", ":"))) + len(json.dumps(rec)) > VAULT_CAP:
            raise ValueError("register is full (storage limit)")
        if self.seq:
            self.d["seq"] = n + 1
        r = super().add(rec)
        self._snap()
        if self.after: self.after("add", r, self)
        return r

    def update(self, rec):
        old = self._orig.get(rec["_id"])
        try:
            self._clean(rec)
            if self.guard: self.guard("update", rec, self, old)
        except ValueError:
            if old is not None:
                rec.clear(); rec.update(old)
            raise
        super().update(rec)
        self._snap()
        if self.after: self.after("update", rec, self)

    def remove(self, rec):
        if self.guard: self.guard("remove", rec, self, rec)
        super().remove(rec)
        self._snap()
        if self.after: self.after("remove", rec, self)


class GBoard(Board):
    def key(self, k):
        try:
            return super().key(k)
        except ValueError as e:
            return ("push", Message("Refused", [str(e)]))


class GList(RecordList):
    """RecordList that shows refusals instead of failing, backs out to the menu, and has extra keys."""

    def __init__(self, data, title, host, extra=None):
        super().__init__(data)
        self.title, self.host, self.extra = title, host, extra or {}
        if self.extra:
            self.help += "  " + "  ".join(v[0] for v in self.extra.values())

    def _guarded(self, fn, *a):
        try: fn(self, *a)
        except ValueError as e: self.msg = "refused: " + str(e)

    def _added(self, r): self._guarded(RecordList._added, r)
    def _saved(self, r): self._guarded(RecordList._saved, r)
    def _deleted(self, r): self._guarded(RecordList._deleted, r)
    def _import(self, t): self._guarded(RecordList._import, t)

    def key(self, k):
        if k == "escape" and not (self.query or self.filt):
            return ("pop", None)
        if k == "b" and self.spec.status:
            return ("push", GBoard(self.data))
        if k in self.extra:
            self.msg = ""
            return self.extra[k][1](self)
        if k == "x":
            csv = self.data.to_csv(self.rows())
            self.host.put(f"export-{self.spec.id}.csv", csv)
            self.msg = f"exported to vault key 'export-{self.spec.id}.csv'"
            return ("push", TextView("Export (CSV)", csv.split("\n")))
        try:
            return super().key(k)
        except ValueError as e:
            self.msg = "refused: " + str(e)


def master(key, used=lambda v: False, norm=None):
    """Guard for master data: unique key (case-insensitive); it cannot change or be deleted while `used`."""
    def g(kind, rec, data, old=None):
        if kind == "remove":
            if used(rec.get(key, "")):
                raise ValueError(f"'{rec.get(key, '')}' is in use and cannot be deleted")
            return
        v = str(rec.get(key, "")).strip()
        if norm: v = norm(v)
        if not v: raise ValueError(f"{key} is required")
        rec[key] = v
        if old and old.get(key) != v and used(old.get(key, "")):
            raise ValueError(f"'{old.get(key)}' is in use; its {key} cannot change")
        for r in data.items:
            if r["_id"] != rec.get("_id") and str(r.get(key, "")).lower() == v.lower():
                raise ValueError(f"'{v}' already exists")
    return g


def regex_norm(pat, label, up=False):
    def f(v):
        v = v.upper() if up else v
        if not re.fullmatch(pat, v): raise ValueError(f"{label} is not valid")
        return v
    return f


def transition(table_, old, new, what):
    if old and new != old.get("status") and new not in table_.get(old.get("status"), ()):
        raise ValueError(f"{what} cannot go from {old.get('status')} to {new}")


class Act:
    def __init__(self, fn): self.fn = fn


def suite(title, intro, items):
    """A menu of registers (Screens), reports (callables returning lines) and actions (Act)."""
    ent = []
    for label, x in items:
        if isinstance(x, Screen): ent.append((label, lambda x=x: ("push", x)))
        elif isinstance(x, Act): ent.append((label, x.fn))
        else: ent.append((label, lambda x=x, l=label: ("push", TextView(l, x()))))
    return Menu(title, ent, wrap(intro, 76))


def view(title, lines): return ("push", TextView(title, lines))


def raw_items(host, key):
    d = Store(host).load(key, None)
    its = d.get("items") if isinstance(d, dict) else None
    return [r for r in its if isinstance(r, dict)] if isinstance(its, list) else []


def months_between(a: dt.date, b: dt.date) -> int:
    return max(0, (b.year - a.year) * 12 + b.month - a.month - (1 if b.day < a.day else 0))


# =========================================================== 1. ACCOUNTING ====
class LedgerError(ValueError):
    pass


NORMAL = {"asset": 1, "expense": 1, "liability": -1, "equity": -1, "income": -1}   # +1 = debit-normal
AR, CASH, SALES = "1100", "1000", "4000"
CHART_SPEC = R("chart", "Chart of accounts", "account", "code*; name*; type: choice(asset|liability|equity|income|expense)*",
               list_cols=("code", "name", "type"), group="type",
               seed=tuple({"code": c, "name": n, "type": t} for c, n, t in (
                   ("1000", "Cash", "asset"), ("1100", "Accounts Receivable", "asset"), ("1200", "Inventory", "asset"),
                   ("2000", "Accounts Payable", "liability"), ("3000", "Owner's Equity", "equity"),
                   ("4000", "Sales Revenue", "income"), ("5000", "Cost of Goods Sold", "expense"),
                   ("6000", "Operating Expenses", "expense"))))


def parse_entry(text: str) -> tuple:
    """'DATE memo' then lines 'ACCOUNT dr|cr AMOUNT' -> (date, memo, [(code, debit_cents, credit_cents)])"""
    rows = [l.strip() for l in text.splitlines() if l.strip()]
    if len(rows) < 3:
        raise LedgerError("first line: DATE memo; then one line per posting: ACCOUNT dr|cr AMOUNT (at least two)")
    head = rows[0].split(None, 1)
    lines = []
    for r in rows[1:]:
        p = r.split()
        if len(p) != 3 or p[1].lower() not in ("dr", "d", "debit", "cr", "c", "credit"):
            raise LedgerError(f"bad line '{clean(r, 40)}': use ACCOUNT dr|cr AMOUNT")
        c = cents(p[2])
        lines.append((p[0], c, 0) if p[1].lower() in ("dr", "d", "debit") else (p[0], 0, c))
    return head[0], (head[1] if len(head) > 1 else ""), lines


class Ledger:
    """Double-entry journal. Posted entries are never edited or deleted; a reversal entry undoes one."""

    def __init__(self, host, chart):
        self.store, self.chart = Store(host), chart
        d = self.store.load("journal") or {}
        es = d.get("entries") if isinstance(d, dict) else None
        self.d = {"next": d["next"] if isinstance(d, dict) and isinstance(d.get("next"), int) else 1,
                  "entries": [e for e in es if isinstance(e, dict)] if isinstance(es, list) else []}
        if self.d["entries"]:
            self.d["next"] = max(self.d["next"], max(e.get("id", 0) for e in self.d["entries"]) + 1)

    @property
    def entries(self): return self.d["entries"]

    def used(self, code): return any(l[0] == code for e in self.entries for l in e.get("lines", ()))

    def post(self, date, memo, lines, ref="", reverses=None) -> dict:
        day(date)
        types = {r["code"]: r["type"] for r in self.chart.items}
        if not 2 <= len(lines) <= 40:
            raise LedgerError("an entry needs 2 to 40 lines")
        for code, dr, cr in lines:
            if code not in types: raise LedgerError(f"unknown account {clean(code, 20)}")
            if dr < 0 or cr < 0 or (dr and cr) or not (dr or cr) or max(dr, cr) > 10 ** 14:
                raise LedgerError("each line needs one positive debit or credit amount")
        td, tc = sum(l[1] for l in lines), sum(l[2] for l in lines)
        if td != tc:
            raise LedgerError(f"unbalanced: debits {money(td)} != credits {money(tc)}; nothing posted")
        if len(self.entries) >= 3000 or len(json.dumps(self.d)) > VAULT_CAP:
            raise LedgerError("journal is full")
        e = {"id": self.d["next"], "date": date, "memo": clean(memo), "ref": clean(ref, 40),
             "lines": [list(l) for l in lines], "reverses": reverses, "reversed_by": None}
        orig = next((x for x in self.entries if x["id"] == reverses), None) if reverses else None
        self.entries.append(e); self.d["next"] += 1
        if orig: orig["reversed_by"] = e["id"]
        if not self.store.save("journal", self.d):
            self.entries.pop(); self.d["next"] -= 1
            if orig: orig["reversed_by"] = None
            raise LedgerError("could not save the journal")
        return e

    def reverse(self, eid, date=None) -> dict:
        e = next((x for x in self.entries if x["id"] == eid), None)
        if e is None: raise LedgerError("no such entry")
        if e.get("reverses"): raise LedgerError("a reversal cannot itself be reversed; post a new entry")
        if e.get("reversed_by"): raise LedgerError(f"entry {eid} was already reversed by #{e['reversed_by']}")
        return self.post(date or today(), f"Reversal of #{eid}: {e['memo']}"[:200], [(c, cr, dr) for c, dr, cr in e["lines"]], reverses=eid)


def balances(entries, start="", end="") -> dict:
    out: dict = {}
    for e in entries:
        if (start and e["date"] < start) or (end and e["date"] > end): continue
        for c, dr, cr in e["lines"]:
            b = out.setdefault(c, [0, 0]); b[0] += dr; b[1] += cr
    return out


def _rows(chart, bal):
    names = {r["code"]: (r["name"], r["type"]) for r in chart}
    codes = sorted(set(bal) | set(), key=lambda c: (c not in names, c))
    return [(c, *names.get(c, ("(not in chart)", "?")), bal[c]) for c in codes]


def trial_balance(chart, entries, end="") -> list:
    out = [f"Trial balance as at {end or 'latest'}", ""]
    rows, td, tc = [], 0, 0
    for c, n, t, (dr, cr) in _rows(chart, balances(entries, "", end)):
        net = dr - cr
        d_, c_ = (net, 0) if net > 0 else (0, -net)
        td += d_; tc += c_
        rows.append([c, n, money(d_) if d_ else "", money(c_) if c_ else ""])
    out += table(rows + [["", "TOTAL", money(td), money(tc)]], ["Code", "Account", "Debit", "Credit"])
    out += ["", "BALANCED" if td == tc else f"OUT OF BALANCE by {money(td - tc)}"]
    return out


def _sum(chart, bal, kind):
    rows = []
    for c, n, t, (dr, cr) in _rows(chart, bal):
        if t == kind: rows.append((c, n, (dr - cr) * NORMAL[t]))
    return rows


def sheet_totals(chart, entries, end="") -> dict:
    bal = balances(entries, "", end)
    t = {k: sum(r[2] for r in _sum(chart, bal, k)) for k in NORMAL}
    return {"assets": t["asset"], "liabilities": t["liability"], "equity": t["equity"], "earnings": t["income"] - t["expense"]}


def income_statement(chart, entries, start="", end="") -> list:
    bal = balances(entries, start, end)
    inc, exp = _sum(chart, bal, "income"), _sum(chart, bal, "expense")
    out = [f"Income statement {start or 'start'} to {end or 'latest'}", "", "Income"]
    out += [f"  {c:<8}{n:<30}{money(v):>14}" for c, n, v in inc]
    ti, te = sum(r[2] for r in inc), sum(r[2] for r in exp)
    out += [f"  {'Total income':<38}{money(ti):>14}", "", "Expenses"]
    out += [f"  {c:<8}{n:<30}{money(v):>14}" for c, n, v in exp]
    return out + [f"  {'Total expenses':<38}{money(te):>14}", "", f"  {'NET INCOME':<38}{money(ti - te):>14}"]


def balance_sheet(chart, entries, end="") -> list:
    bal, t = balances(entries, "", end), sheet_totals(chart, entries, end)
    out = [f"Balance sheet as at {end or 'latest'}", ""]
    for title, kind, tot in (("Assets", "asset", t["assets"]), ("Liabilities", "liability", t["liabilities"]), ("Equity", "equity", t["equity"])):
        out.append(title)
        out += [f"  {c:<8}{n:<30}{money(v):>14}" for c, n, v in _sum(chart, bal, kind)]
        if kind == "equity": out.append(f"  {'':<8}{'Earnings to date (not yet closed)':<30}{money(t['earnings']):>14}")
        out += [f"  {'Total ' + title.lower():<38}{money(tot + (t['earnings'] if kind == 'equity' else 0)):>14}", ""]
    le = t["liabilities"] + t["equity"] + t["earnings"]
    return out + [f"Assets {money(t['assets'])}  =  Liabilities + Equity {money(le)}", "BALANCED" if t["assets"] == le else "OUT OF BALANCE"]


def account_ledger(chart, entries, code, start="", end="") -> list:
    acct = next((r for r in chart if r["code"] == code), None)
    if not acct: return [f"unknown account {clean(code, 20)}"]
    s = NORMAL[acct["type"]]
    run = 0
    if start:
        b = balances(entries, "", (dt.date.fromisoformat(start) - dt.timedelta(days=1)).isoformat()).get(code, [0, 0])
        run = (b[0] - b[1]) * s
    out = [f"{code} {acct['name']} ({acct['type']})", ""]
    rows = [["", start or "", "opening balance", "", "", money(run)]]
    for e in entries:
        if (start and e["date"] < start) or (end and e["date"] > end): continue
        for c, dr, cr in e["lines"]:
            if c == code:
                run += (dr - cr) * s
                rows.append([e["id"], e["date"], e["memo"], money(dr) if dr else "", money(cr) if cr else "", money(run)])
    return out + table(rows, ["#", "Date", "Memo", "Debit", "Credit", "Balance"])


def inv_suggestions(led, invs):
    """Journal entries Invoicing implies and Accounting has not posted yet: [(ref, date, memo, lines)]."""
    posted = {e["ref"] for e in led.entries if e.get("ref")}
    out = []
    for r in invs:
        num, st = clean(r.get("number", ""), 40).strip(), r.get("status")
        try: c = cents(r.get("total"))
        except ValueError: continue
        if st not in ("sent", "paid") or not num or c <= 0: continue
        try: d = day(r.get("date", "")).isoformat()
        except ValueError: d = today()
        who = clean(r.get("customer", ""), 40)
        if num not in posted:
            out.append((num, d, f"Invoice {num} {who}", [(AR, c, 0), (SALES, 0, c)]))
        if st == "paid" and num + "/paid" not in posted:
            out.append((num + "/paid", today(), f"Payment of {num} {who}", [(CASH, c, 0), (AR, 0, c)]))
    return out


class Journal(Screen):
    title = "Journal"

    def __init__(self, led, ctx):
        self.led, self.ctx, self.nav, self.msg, self.draft = led, ctx, ListNav(0), "", ""
        self.help = "a post  r reverse  Enter lines  Esc back   (entries are never deleted)"

    def rows(self):
        a, b = self.ctx["from"], self.ctx["to"]
        return [e for e in self.led.entries if not (a and e["date"] < a) and not (b and e["date"] > b)]

    def render(self, w, h):
        rows = self.rows(); self.nav.resize(len(rows))
        top, end = self.nav.window(h - 5)
        t = table([[e["id"], e["date"], e["memo"], money(sum(l[1] for l in e["lines"])),
                    f"reversal of #{e['reverses']}" if e.get("reverses") else (f"reversed by #{e['reversed_by']}" if e.get("reversed_by") else "")]
                   for e in rows[top:end]], ["#", "Date", "Memo", "Amount", ""], maxw=w - 4)
        out = [f" period {self.ctx['from'] or 'start'} .. {self.ctx['to'] or 'latest'}   {len(rows)} entr{'y' if len(rows) == 1 else 'ies'}", t[0], t[1]]
        out += [("> " if top + i == self.nav.sel else "  ") + l for i, l in enumerate(t[2:])]
        return out + (["", " " + self.msg] if self.msg else [])

    def _post(self, text):
        self.draft = text
        try:
            d, m, lines = parse_entry(text)
            e = self.led.post(d, m, lines)
            self.draft, self.msg = "", f"posted entry #{e['id']}"
        except ValueError as ex:
            self.msg = "REFUSED: " + str(ex)
            return ("push", Message("Entry refused", [str(ex), "", "Your text is kept: press a to fix it."]))

    def key(self, k):
        self.msg = ""
        rows = self.rows()
        if self.nav.key(k): return
        cur = rows[self.nav.sel] if rows else None
        if k == "a":
            return ("push", Editor("Post entry", self.draft or f"{today()} ", on_save=self._post, hint="DATE memo / ACCOUNT dr|cr AMOUNT"))
        if k == "r" and cur:
            return ("push", Confirm(f"Post a reversal of entry #{cur['id']}?", lambda: self._rev(cur["id"])))
        if k == "enter" and cur:
            names = {r["code"]: r["name"] for r in self.led.chart.items}
            return view(f"Entry #{cur['id']}", [f"{cur['date']}  {cur['memo']}", f"ref: {cur.get('ref') or '-'}", ""]
                        + [f"  {c:<8}{names.get(c, '?'):<28}{money(dr) if dr else '':>14}{money(cr) if cr else '':>14}" for c, dr, cr in cur["lines"]])
        if k == "escape": return ("pop", None)

    def _rev(self, eid):
        try: self.msg = f"posted reversal #{self.led.reverse(eid)['id']}"
        except ValueError as e: self.msg = "REFUSED: " + str(e)


def make_accounting(host, e=None):
    ctx = {"from": "", "to": ""}
    ns = NS()
    ns.chart = GData(host, CHART_SPEC, "chart", guard=None)
    ns.led = Ledger(host, ns.chart)
    cm = master("code", ns.led.used, regex_norm(r"[A-Za-z0-9][A-Za-z0-9.-]{0,11}", "account code"))

    def chart_guard(kind, rec, data, old=None):
        cm(kind, rec, data, old)
        if kind != "remove" and old and old.get("type") != rec.get("type") and ns.led.used(old["code"]):
            raise ValueError("the type of an account with postings cannot change")
    ns.chart.guard = chart_guard

    def rep(fn): return lambda: fn(ns.chart.items, ns.led.entries)

    ns._open = lambda v: ns._stash.append(account_ledger(ns.chart.items, ns.led.entries, v.strip(), ctx["from"], ctx["to"]))
    ns._stash = []

    def prompt_ledger():
        def done(v):
            ns._stash.clear(); ns._open(v)
            return view("Account ledger", ns._stash[-1])
        return ("push", Prompt("Account ledger", "Account code:", "", done))

    def prompt_period():
        def done(v):
            a, _s, b = v.partition("..")
            try:
                a, b = a.strip(), b.strip()
                for x in (a, b):
                    if x: day(x)
                ctx["from"], ctx["to"] = a, b
            except ValueError as ex:
                return ("push", Message("Period", [str(ex), "Use YYYY-MM-DD..YYYY-MM-DD (either side may be empty)."]))
        return ("push", Prompt("Period", "From..To (YYYY-MM-DD..YYYY-MM-DD, empty = all):", f"{ctx['from']}..{ctx['to']}" if ctx["from"] or ctx["to"] else "", done))

    def invoices():
        its = shared_items(host, "invoices")
        if not its: return [nogrant("invoices", "accounting"), "", "Accounting works without it: post entries by hand."]
        out = [f"{len(its)} invoice(s) from Invoicing", ""]
        out += table([[r.get("number", ""), r.get("customer", ""), r.get("total", ""), r.get("status", ""), r.get("due", ""), ", ".join(f"#{e['id']}" for e in ns.led.entries if e.get("ref", "").split("/")[0] == r.get("number") and e.get("ref"))]
                      for r in its], ["Number", "Customer", "Total", "Status", "Due", "Posted"])
        rec = sum(cents(r.get("balance") or r.get("total") or 0) for r in its if r.get("status") == "sent" and _ok(r.get("balance") or r.get("total") or 0))
        out += ["", f"Receivables (sent, unpaid): {money(rec)}", f"Books: accounts receivable balance {money(_ar(ns.led))}"]
        voids = [r.get("number") for r in its if r.get("status") == "void" and any(e.get("ref") == r.get("number") and not e.get("reversed_by") for e in ns.led.entries)]
        sug = inv_suggestions(ns.led, its)
        out += [f"WARNING: posted but now void, reverse the entry: {', '.join(map(str, voids))}"] if voids else []
        return out + ["", f"{len(sug)} suggested entr{'y' if len(sug) == 1 else 'ies'} not yet posted:"] + [f"  {r}  Dr {AR if l[0][1] else CASH} / Cr {SALES if l[0][1] else AR}  {money(max(l[0][1], l[0][2]))}" for r, _d, _m, l in sug]

    def post_suggested():
        sug = inv_suggestions(ns.led, shared_items(host, "invoices"))
        if not sug: return ("push", Message("Post from invoices", ["Nothing to post (or invoices are not shared with this app)."]))

        def go():
            done, bad = 0, []
            for ref, d, m, lines in sug:
                try: ns.led.post(d, m, lines, ref=ref); done += 1
                except ValueError as ex: bad.append(f"{ref}: {ex}")
            return ("push", Message("Post from invoices", [f"posted {done} entr{'y' if done == 1 else 'ies'}"] + bad))
        return ("push", Confirm(f"Post {len(sug)} entr{'y' if len(sug) == 1 else 'ies'} (Dr {AR} Receivable / Cr {SALES} Sales; Dr {CASH} / Cr {AR} for paid)?", go))

    m = suite("Accounting", "Double-entry books. Debits must equal credits or the entry is refused; posted entries are reversed, never deleted. "
              "Trial balance and balance sheet are as at the period end; the income statement covers the period (set it with Period).", [
                  ("Chart of accounts", GList(ns.chart, "Chart of accounts", host)),
                  ("Journal (post and reverse entries)", Journal(ns.led, ctx)),
                  ("Trial balance", lambda: trial_balance(ns.chart.items, ns.led.entries, ctx["to"])),
                  ("Income statement", lambda: income_statement(ns.chart.items, ns.led.entries, ctx["from"], ctx["to"])),
                  ("Balance sheet", lambda: balance_sheet(ns.chart.items, ns.led.entries, ctx["to"])),
                  ("Account ledger", Act(prompt_ledger)),
                  ("Period filter", Act(prompt_period)),
                  ("Invoices from Invoicing (receivables)", invoices),
                  ("Post suggested entries from invoices", Act(post_suggested)),
              ])
    m.ns = ns
    return m


def _ok(v):
    try: cents(v); return True
    except ValueError: return False


def _ar(led): return sum(dr - cr for e in led.entries for c, dr, cr in e["lines"] if c == AR)


# ============================================================== 2. INVOICING ====
INV_SPEC = R("invoices", "Invoices", "invoice",
             "number; customer*; date: date*; due: date*; lines: long*; discount_pct: percent=0; tax_pct: percent=0; "
             "status: choice(draft|sent|paid|void)=draft; subtotal: money; total: money; paid: money; balance: money",
             list_cols=("number", "customer", "due", "total", "balance", "status"), status="status", done=("paid", "void"), due="due", amount="total",
             blurb="Lines go one per row as: description | quantity | unit price. Numbers are assigned in sequence. Press a.")
PAY_SPEC = R("payments", "Payments", "payment", "invoice*; date: date*; amount: money*; method; note",
             list_cols=("invoice", "date", "amount", "method"), amount="amount")
INV_OK = {"draft": {"sent", "void"}, "sent": {"paid", "void"}, "paid": set(), "void": set()}


def parse_lines(text: str) -> list:
    """'description | qty | unit price' per line -> [(desc, qty Decimal, price Decimal, amount_cents)]"""
    out = []
    for raw in str(text).replace("\\n", "\n").split("\n"):
        if not raw.strip(): continue
        p = [x.strip() for x in raw.split("|")]
        if len(p) != 3 or not p[0]:
            raise ValueError(f"bad line '{clean(raw, 30)}': use description | quantity | unit price")
        q, pr = dec(p[1], "quantity"), dec(p[2], "unit price")
        if q <= 0 or q > 10 ** 6 or pr < 0:
            raise ValueError("quantity must be positive and price not negative")
        out.append((clean(p[0], 80), q, pr, cs(q * pr)))
    if not out or len(out) > 50:
        raise ValueError("an invoice needs 1 to 50 lines")
    return out


def invoice_totals(lines, discount_pct, tax_pct) -> dict:
    sub = sum(l[3] for l in lines)
    dp, tp = dec(discount_pct or 0, "discount"), dec(tax_pct or 0, "tax")
    if not (0 <= dp <= 100 and 0 <= tp <= 100): raise ValueError("discount and tax are percentages 0-100")
    disc = cs(D(sub) * dp / 100 / 100)
    tax = cs(D(sub - disc) * tp / 100 / 100)
    return {"subtotal": sub, "discount": disc, "tax": tax, "total": sub - disc + tax}


def invoice_breakdown(inv):
    try:
        ls = parse_lines(inv.get("lines", ""))
        return ls, invoice_totals(ls, inv.get("discount_pct"), inv.get("tax_pct"))
    except ValueError:
        return [], {"subtotal": 0, "discount": 0, "tax": 0, "total": 0}


def invoice_text(inv, contact=None) -> list:
    ls, t = invoice_breakdown(inv)
    out = [f"INVOICE {inv.get('number', '')}    [{inv.get('status', '')}]", f"Date: {inv.get('date', '')}    Due: {inv.get('due', '')}",
           "", f"Bill to: {inv.get('customer', '')}"]
    if contact:
        out += [f"         {clean(contact.get(k, ''))}" for k in ("company", "email", "phone") if contact.get(k)]
    out += [""] + table([[d, qty_s(q), plain(cs(p)), plain(a)] for d, q, p, a in ls], ["Description", "Qty", "Unit", "Amount"], maxw=76)
    out += ["", f"{'Subtotal':>60}{plain(t['subtotal']):>14}", f"{'Discount ' + str(inv.get('discount_pct') or 0) + '%':>60}{'-' + plain(t['discount']):>14}",
            f"{'Tax ' + str(inv.get('tax_pct') or 0) + '%':>60}{plain(t['tax']):>14}", f"{'TOTAL':>60}{plain(t['total']):>14}"]
    if inv.get("paid"): out += [f"{'Paid':>60}{inv.get('paid'):>14}", f"{'BALANCE DUE':>60}{inv.get('balance', ''):>14}"]
    return out


def invoice_html(inv, contact=None) -> str:
    e = lambda v: html.escape(str(v), quote=True)
    ls, t = invoice_breakdown(inv)
    rows = "".join(f"<tr><td>{e(d)}</td><td>{e(qty_s(q))}</td><td>{e(plain(cs(p)))}</td><td>{e(plain(a))}</td></tr>" for d, q, p, a in ls)
    who = e(inv.get("customer", "")) + "".join(f"<br>{e(contact.get(k))}" for k in ("company", "email", "phone") if contact and contact.get(k))
    return ("<!doctype html><meta charset=utf-8><title>Invoice " + e(inv.get("number", "")) + "</title>"
            "<style>body{font-family:sans-serif;max-width:40em;margin:2em auto}td,th{padding:.3em .6em;text-align:left}table{border-collapse:collapse;width:100%}</style>"
            f"<h1>Invoice {e(inv.get('number', ''))}</h1><p>Status: {e(inv.get('status', ''))}<br>Date: {e(inv.get('date', ''))} Due: {e(inv.get('due', ''))}</p>"
            f"<p>Bill to: {who}</p><table border=1><tr><th>Description<th>Qty<th>Unit<th>Amount</tr>{rows}</table>"
            f"<p>Subtotal {e(plain(t['subtotal']))}<br>Discount {e(inv.get('discount_pct') or 0)}% -{e(plain(t['discount']))}<br>Tax {e(inv.get('tax_pct') or 0)}% {e(plain(t['tax']))}"
            f"<br><b>Total {e(plain(t['total']))}</b><br>Paid {e(inv.get('paid') or '0')} / Balance due {e(inv.get('balance') or '')}</p>")


BUCKETS = ("Current", "1-30", "31-60", "61-90", "90+")


def ageing(invs, asof: dt.date) -> list:
    by: dict = {}
    for r in invs:
        if r.get("status") != "sent": continue
        try: bal, due = cents(r.get("balance") or 0), day(r.get("due"))
        except ValueError: continue
        if bal <= 0: continue
        late = (asof - due).days
        i = 0 if late <= 0 else 1 if late <= 30 else 2 if late <= 60 else 3 if late <= 90 else 4
        by.setdefault(clean(r.get("customer", "?"), 30), [0] * 5)[i] += bal
    rows = [[c, *[money(x) if x else "" for x in v], money(sum(v))] for c, v in sorted(by.items())]
    tot = [sum(v[i] for v in by.values()) for i in range(5)]
    return [f"Receivables ageing as at {asof} (days past due)", ""] + table(rows + [["TOTAL", *[money(x) for x in tot], money(sum(tot))]], ["Customer", *BUCKETS, "Total"], maxw=100)


def make_invoicing(host, e=None):
    ns = NS()
    ns.contacts = lambda: [str(r.get("name")) for r in shared_items(host, "contacts") if r.get("name")]
    paid_for = lambda num: sum(cents(p.get("amount")) for p in ns.pay.items if p.get("invoice") == num)

    def sync(*_):
        changed = False
        for r in ns.inv.items:
            if r.get("status") == "void": continue
            try: c = cents(r.get("total"))
            except ValueError: continue
            p = paid_for(r.get("number"))
            new = {"paid": plain(p), "balance": plain(c - p)}
            st = "paid" if r.get("status") == "sent" and c > 0 and c - p <= 0 else "sent" if r.get("status") == "paid" and c - p > 0 else r.get("status")
            new["status"] = st
            if any(r.get(k) != v for k, v in new.items()): r.update(new); changed = True
        if changed: ns.inv.save(); ns.inv._snap()

    def inv_guard(kind, rec, data, old=None):
        if kind == "remove":
            if rec.get("status") != "draft": raise ValueError("only draft invoices can be deleted; void it instead (numbers are never reused)")
            return
        rec["customer"] = pick(ns.contacts(), rec.get("customer", ""), "customer")
        d, du = day(rec.get("date"), "date"), day(rec.get("due"), "due date")
        if du < d: raise ValueError("due date is before the invoice date")
        t = invoice_totals(parse_lines(rec.get("lines")), rec.get("discount_pct"), rec.get("tax_pct"))
        rec["subtotal"], rec["total"] = plain(t["subtotal"]), plain(t["total"])
        if kind == "add":
            rec["status"] = "draft"
        else:
            rec["number"] = old["number"]
            if old["status"] != "draft" and any(rec.get(k) != old.get(k) for k in ("customer", "date", "due", "lines", "discount_pct", "tax_pct")):
                raise ValueError("a sent invoice is locked; void it and issue a new one")
            transition(INV_OK, old, rec["status"], "invoice")
        p = paid_for(rec.get("number"))
        rec["paid"], rec["balance"] = plain(p), plain(t["total"] - p)
        if rec["status"] == "paid" and t["total"] - p > 0: raise ValueError("balance is still due: record the payment first")
        if rec["status"] == "void" and p: raise ValueError("the invoice has payments: delete them first")

    def pay_guard(kind, rec, data, old=None):
        if kind == "remove": return
        if kind == "update": raise ValueError("payments are not edited: delete and re-enter")
        inv = next((r for r in ns.inv.items if str(r.get("number", "")).upper() == str(rec.get("invoice", "")).strip().upper()), None)
        if not inv: raise ValueError("no such invoice number")
        if inv.get("status") != "sent": raise ValueError(f"invoice is {inv.get('status')}: only sent invoices take payments")
        day(rec.get("date"), "date")
        a = cents(rec.get("amount"))
        if a <= 0: raise ValueError("amount must be positive")
        if a > cents(inv["total"]) - paid_for(inv["number"]): raise ValueError("overpayment refused: more than the balance due")
        rec["invoice"], rec["amount"] = inv["number"], plain(a)

    ns.inv = GData(SpaceHost(host, "invoices"), INV_SPEC, "records", inv_guard, seq=("number", "INV-"))
    ns.pay = GData(host, PAY_SPEC, "payments", pay_guard, after=sync)
    ns.sync = sync

    def export(kind):
        def f(lst):
            r = lst.current()
            if not r: return None
            c = next((x for x in shared_items(host, "contacts") if x.get("name") == r.get("customer")), None)
            key = "invoice-" + re.sub(r"[^a-z0-9]+", "-", str(r.get("number", "x")).lower()) + "." + kind
            if kind == "txt":
                lines = invoice_text(r, c); host.put(key, "\n".join(lines))
            else:
                host.put(key, invoice_html(r, c)); lines = [f"HTML saved to vault key '{key}' (all text escaped)."]
            return view(f"Invoice {r.get('number')}", lines + (["", f"saved to vault key '{key}'"] if kind == "txt" else []))
        return f

    def contacts_view(lst):
        n = ns.contacts()
        return view("Contacts (customer picker)", n or [nogrant("contacts", "invoicing"), "Customer names are free text until contacts are shared."])

    ilist = GList(ns.inv, "Invoices", host, {"p": ("p print", export("txt")), "h": ("h html", export("html")), "c": ("c contacts", contacts_view)})
    ilist.on_enter = lambda: sync()
    sync()
    return suite("Invoicing", "Invoices with line items, discount and tax; sequential numbers; payments reduce the balance due. Customers come from "
                 "the shared Contacts when visible. Space on an invoice cycles its status (sent invoices are locked).", [
                     ("Invoices", ilist),
                     ("Payments", GList(ns.pay, "Payments", host)),
                     ("Ageing report", lambda: ageing(ns.inv.items, dt.date.today())),
                 ]), ns


# ================================================================ 3. INVENTORY ====
ITEM_SPEC = R("inventory", "Items", "item", "sku*; name*; on_hand: number=0; reorder_point: number=0; unit_cost: money; unit=ea; location",
              list_cols=("sku", "name", "on_hand", "reorder_point", "unit_cost"),
              blurb="on_hand is computed from the stock movements and written back; it cannot be edited.")
MOVE_SPEC = R("movements", "Stock movements", "movement", "sku*; date: date*; kind: choice(receipt|issue|adjust)*; qty: number*; unit_cost: money; note",
              list_cols=("date", "sku", "kind", "qty", "unit_cost"), status="kind", group="kind")


def valuate(moves, item_cost=D(0), method="wa"):
    """moves: [(kind, qty Decimal, unit cost Decimal|None)] in order -> (on_hand, value in currency units, Decimal).
    Weighted average ('wa') or FIFO ('fifo'). An adjust is signed (+ gains, - losses)."""
    qty, value, layers = D(0), D(0), []
    for kind, q, c in moves:
        if kind == "adjust": kind, q = ("receipt", q) if q > 0 else ("issue", -q)
        if kind == "receipt":
            unit = c if c is not None else (value / qty if method == "wa" and qty > 0 else item_cost)
            qty += q; value += q * unit; layers.append([q, unit])
        else:
            take = min(q, qty)
            if method == "wa":
                value -= value * take / qty if qty else D(0)
            else:
                left = take
                while left > 0 and layers:
                    used = min(left, layers[0][0]); value -= used * layers[0][1]; layers[0][0] -= used; left -= used
                    if layers[0][0] <= 0: layers.pop(0)
            qty -= take
    return qty, value


def _moves(movs, sku): return [(m["kind"], dec(m["qty"]), dec(m["unit_cost"]) if m.get("unit_cost") not in (None, "") else None) for m in movs if m.get("sku") == sku]


def _cost(it):
    try: return dec(it.get("unit_cost") or 0)
    except ValueError: return D(0)


def stock_table(items, movs) -> list:
    out = []
    for it in items:
        try: ms = _moves(movs, it.get("sku"))
        except ValueError: ms = []
        oh, wa = valuate(ms, _cost(it), "wa")
        _q, ff = valuate(ms, _cost(it), "fifo")
        try: rp = dec(it.get("reorder_point") or 0)
        except ValueError: rp = D(0)
        out.append({"sku": it.get("sku", ""), "name": it.get("name", ""), "on_hand": oh, "rp": rp, "wa": cs(wa), "fifo": cs(ff)})
    return out


def stock_report(items, movs) -> list:
    st = stock_table(items, movs)
    rows = [[s["sku"], s["name"], qty_s(s["on_hand"]), money(cs(D(s["wa"]) / 100 / s["on_hand"])) if s["on_hand"] > 0 else "", money(s["wa"]), money(s["fifo"]),
             "LOW" if s["on_hand"] <= s["rp"] else ""] for s in st]
    return table(rows, ["SKU", "Name", "On hand", "Avg cost", "Value (avg)", "Value (FIFO)", ""], maxw=100) + ["", f"Total value (weighted average): {money(sum(s['wa'] for s in st))}   (FIFO): {money(sum(s['fifo'] for s in st))}"]


def low_stock(items, movs) -> list:
    low = [s for s in stock_table(items, movs) if s["on_hand"] <= s["rp"]]
    return [f"{len(low)} item(s) at or below their reorder point", ""] + [f"  {s['sku']:<14}{s['name'][:28]:<30}on hand {qty_s(s['on_hand']):>8}  reorder at {qty_s(s['rp'])}{'  OUT' if s['on_hand'] <= 0 else ''}" for s in low]


def make_inventory(host, e=None):
    ns = NS()
    used = lambda sku: any(m.get("sku") == sku for m in ns.mov.items)
    mg = master("sku", used, regex_norm(r"[A-Z0-9][A-Z0-9._-]{0,31}", "SKU", up=True))

    def on_hand(sku): return valuate(_moves(ns.mov.items, sku), D(0))[0]

    def item_guard(kind, rec, data, old=None):
        mg(kind, rec, data, old)
        if kind == "remove": return
        if rec.get("unit_cost"): rec["unit_cost"] = plain(cents(rec["unit_cost"])) if dec(rec["unit_cost"]) >= 0 else (_ for _ in ()).throw(ValueError("unit cost cannot be negative"))
        rp = dec(rec.get("reorder_point") or 0, "reorder point")
        if rp < 0: raise ValueError("reorder point cannot be negative")
        rec["reorder_point"] = qty_s(rp)
        rec["on_hand"] = qty_s(on_hand(rec["sku"]))        # computed, never typed

    def sync(sku=None):
        ch = False
        for it in ns.items.items:
            if sku and it.get("sku") != sku: continue
            try: v = qty_s(on_hand(it.get("sku")))
            except ValueError: continue
            if it.get("on_hand") != v: it["on_hand"] = v; ch = True
        if ch: ns.items.save(); ns.items._snap()

    def mov_guard(kind, rec, data, old=None):
        if kind == "update": raise ValueError("movements are never edited: post an adjustment instead")
        if kind == "remove": raise ValueError("movements are never deleted: post an adjustment instead")
        it = next((i for i in ns.items.items if str(i.get("sku", "")).lower() == str(rec.get("sku", "")).strip().lower()), None)
        if not it: raise ValueError("no such SKU: add the item first")
        rec["sku"] = it["sku"]
        day(rec.get("date"), "date")
        q, k, oh = dec(rec.get("qty"), "quantity"), rec.get("kind"), on_hand(it["sku"])
        if q == 0 or (k != "adjust" and q < 0): raise ValueError("quantity must be positive (only adjustments may be negative)")
        if k == "issue" and q > oh: raise ValueError(f"cannot issue {qty_s(q)}: only {qty_s(oh)} on hand")
        if k == "adjust" and q < 0 and -q > oh: raise ValueError(f"cannot remove {qty_s(-q)}: only {qty_s(oh)} on hand")
        rec["qty"] = qty_s(q)
        if k == "receipt" or (k == "adjust" and q > 0):
            c = dec(rec.get("unit_cost") or it.get("unit_cost") or 0, "unit cost")
            if c < 0: raise ValueError("unit cost cannot be negative")
            rec["unit_cost"] = format(c.normalize(), "f") if c else "0"
        else:
            rec["unit_cost"] = ""

    ns.items = GData(SpaceHost(host, "inventory"), ITEM_SPEC, "records", item_guard)
    ns.mov = GData(host, MOVE_SPEC, "movements", mov_guard, after=lambda kind, rec, d: sync(rec.get("sku")))
    ns.items.spec = replace(ITEM_SPEC, report=lambda its: stock_report(its, ns.mov.items), report_label="Stock valuation")
    ns.sync = sync
    sync()
    return suite("Inventory Management", "Items with SKU and unit cost. Stock changes only through the movement ledger (receipt, issue, adjust); on-hand is "
                 "computed from it and written back to the shared 'inventory' items. Valuation: weighted average and FIFO.", [
                     ("Items", GList(ns.items, "Items", host)),
                     ("Stock movements", GList(ns.mov, "Stock movements", host)),
                     ("Stock levels and valuation", lambda: stock_report(ns.items.items, ns.mov.items)),
                     ("Low-stock report", lambda: low_stock(ns.items.items, ns.mov.items)),
                 ]), ns


# =============================================================== 4. PROCUREMENT ====
SUP_SPEC = R("suppliers", "Suppliers", "supplier", "name*; contact; email: email; phone: phone; terms", list_cols=("name", "contact", "email", "terms"))
REQ_SPEC = R("requests", "Purchase requests", "request", "number; item*; qty: number*; est_cost: money; requester*; status: choice(requested|approved|rejected|ordered)=requested; reason",
             list_cols=("number", "item", "qty", "requester", "status"), status="status", done=("ordered", "rejected"), amount="est_cost")
PO_SPEC = R("orders", "Purchase orders", "purchase order",
            "number; supplier*; request; item*; qty: number*; unit_price: money*; date: date*; status: choice(draft|sent|partial|received|closed|cancelled)=draft",
            list_cols=("number", "supplier", "item", "qty", "unit_price", "status"), status="status", done=("closed", "cancelled", "received"),
            blurb="One item per purchase order. Status partial/received follows the receipts automatically.")
REC_SPEC = R("receipts", "Receipts", "receipt", "po*; date: date*; qty: number*; note", list_cols=("po", "date", "qty", "note"))
BILL_SPEC = R("bills", "Supplier invoices", "supplier invoice", "ref*; po*; date: date*; qty: number*; unit_price: money*", list_cols=("ref", "po", "qty", "unit_price"))
REQ_OK = {"requested": {"approved", "rejected"}, "approved": {"requested", "rejected"}, "rejected": {"requested"}, "ordered": set()}
PO_OK = {"draft": {"sent", "cancelled"}, "sent": {"cancelled"}, "partial": {"closed"}, "received": {"closed"}, "closed": set(), "cancelled": set()}
LOW = "(low stock)"


def three_way(pos, receipts, bills) -> list:
    """-> [dict(number, supplier, item, ordered, received, invoiced, flags)] ; flags [] means a clean match."""
    out, known = [], set()
    for p in pos:
        if p.get("status") in ("draft", "cancelled"): continue
        n = p.get("number"); known.add(n)
        try:
            o, pr = dec(p.get("qty")), dec(p.get("unit_price"))
            got = sum((dec(r.get("qty")) for r in receipts if r.get("po") == n), D(0))
            bs = [b for b in bills if b.get("po") == n]
            inv = sum((dec(b.get("qty")) for b in bs), D(0))
            fl = []
            if got > o: fl.append("OVER-RECEIVED")
            if got < o: fl.append(f"SHORT-RECEIVED ({qty_s(got)} of {qty_s(o)})")
            if inv > got: fl.append("BILLED BUT NOT RECEIVED")
            if inv > o: fl.append("OVER-BILLED vs PO")
            if inv < got and inv > 0 or (inv == 0 and got > 0): fl.append("RECEIVED BUT NOT FULLY BILLED")
            if any(dec(b.get("unit_price")) != pr for b in bs): fl.append("PRICE MISMATCH")
        except ValueError:
            o = got = inv = D(0); fl = ["UNREADABLE DATA"]
        out.append({"number": n, "supplier": p.get("supplier", ""), "item": p.get("item", ""), "ordered": o, "received": got, "invoiced": inv, "flags": fl})
    for b in bills:
        if b.get("po") not in known: out.append({"number": b.get("po", "?"), "supplier": "", "item": "", "ordered": D(0), "received": D(0), "invoiced": D(0), "flags": [f"ORPHAN invoice {b.get('ref')}: PO not found or not issued"]})
    return out


def match_report(pos, receipts, bills) -> list:
    rows = three_way(pos, receipts, bills)
    bad = sum(1 for r in rows if r["flags"])
    return [f"Three-way match: {len(rows)} PO(s), {bad} with mismatches", ""] + table(
        [[r["number"], r["supplier"], qty_s(r["ordered"]), qty_s(r["received"]), qty_s(r["invoiced"]), "; ".join(r["flags"]) or "MATCH"] for r in rows],
        ["PO", "Supplier", "Ordered", "Received", "Invoiced", "Result"], maxw=110)


def reorder_suggestions(inv_items, requests) -> list:
    """Items at/below a positive reorder point with no open request: [(sku, name, suggested qty, est cost cents)]. Target stock = 2 x reorder point."""
    open_ = {str(r.get("item", "")).split(" - ")[0].upper() for r in requests if r.get("status") in ("requested", "approved")}
    out = []
    for it in inv_items:
        try: oh, rp = dec(it.get("on_hand") or 0), dec(it.get("reorder_point") or 0)
        except ValueError: continue
        sku = clean(it.get("sku", ""), 32).upper()
        if sku and rp > 0 and oh <= rp and sku not in open_:
            q = 2 * rp - oh
            out.append((sku, clean(it.get("name", ""), 60), q, cs(q * _cost(it))))
    return out


def open_po_value(pos, receipts) -> tuple:
    n, tot = 0, 0
    for p in pos:
        if p.get("status") in ("sent", "partial"):
            try:
                rem = max(dec(p["qty"]) - sum((dec(r["qty"]) for r in receipts if r.get("po") == p.get("number")), D(0)), D(0))
                tot += cs(rem * dec(p["unit_price"])); n += 1
            except (ValueError, KeyError): pass
    return n, tot


def make_procurement(host, e=None):
    ns = NS()
    people = lambda: [str(r.get("name")) for r in shared_items(host, "employees") if r.get("name")]
    sup_used = lambda n: any(p.get("supplier") == n for p in ns.po.items)
    po_used = lambda n: any(r.get("po") == n for r in ns.rec.items) or any(b.get("po") == n for b in ns.bill.items)

    def req_guard(kind, rec, data, old=None):
        if kind == "remove":
            if rec.get("status") == "ordered": raise ValueError("an ordered request is kept for the record")
            return
        if rec.get("requester") != LOW: rec["requester"] = pick(people(), rec.get("requester", ""), "requester")
        q = dec(rec.get("qty"), "quantity")
        if q <= 0: raise ValueError("quantity must be positive")
        if rec.get("est_cost"): rec["est_cost"] = plain(cents(rec["est_cost"]))
        if kind == "add": rec["status"] = "requested"
        else:
            rec["number"] = old["number"]
            if rec["status"] == "ordered" and old["status"] != "ordered": raise ValueError("a request becomes ordered when a purchase order is made from it")
            if old["status"] == "ordered": raise ValueError("this request already has a purchase order")
            transition(REQ_OK, old, rec["status"], "request")

    def po_guard(kind, rec, data, old=None):
        if kind == "remove":
            if rec.get("status") != "draft": raise ValueError("only draft orders can be deleted; cancel it instead")
            return
        rec["supplier"] = pick([s["name"] for s in ns.sup.items], rec.get("supplier", ""), "supplier")
        day(rec.get("date"), "date")
        q, p = dec(rec.get("qty"), "quantity"), cents(rec.get("unit_price"), "unit price")
        if q <= 0 or p < 0: raise ValueError("quantity must be positive and price not negative")
        rec["unit_price"] = plain(p)
        if kind == "add":
            rec["status"] = "draft"
            if rec.get("request"):
                r = next((x for x in ns.req.items if x.get("number") == rec["request"].strip().upper()), None)
                if not r or r.get("status") != "approved": raise ValueError("the request must exist and be approved")
                rec["request"] = r["number"]
        else:
            rec["number"] = old["number"]
            if old["status"] != "draft" and any(rec.get(k) != old.get(k) for k in ("supplier", "request", "item", "qty", "unit_price", "date")):
                raise ValueError("an issued order is locked: cancel it and raise a new one")
            transition(PO_OK, old, rec["status"], "order")

    def po_after(kind, rec, data):
        r = next((x for x in ns.req.items if x.get("number") == rec.get("request")), None)
        if r and kind == "add": r["status"] = "ordered"; ns.req.save(); ns.req._snap()
        if r and kind == "remove" and r.get("status") == "ordered": r["status"] = "approved"; ns.req.save(); ns.req._snap()

    def sync(*_):
        ch = False
        for p in ns.po.items:
            if p.get("status") in ("sent", "partial", "received"):
                try: got, o = sum((dec(r["qty"]) for r in ns.rec.items if r.get("po") == p["number"]), D(0)), dec(p["qty"])
                except (ValueError, KeyError): continue
                st = "received" if got >= o else "partial" if got > 0 else "sent"
                if st != p["status"]: p["status"] = st; ch = True
        if ch: ns.po.save(); ns.po._snap()

    def rec_guard(kind, rec, data, old=None):
        if kind == "remove": return
        if kind == "update": raise ValueError("receipts are not edited: delete and re-enter")
        p = next((x for x in ns.po.items if x.get("number") == str(rec.get("po", "")).strip().upper()), None)
        if not p: raise ValueError("no such purchase order")
        if p.get("status") not in ("sent", "partial", "received"): raise ValueError(f"order is {p.get('status')}: goods can be received only against an issued order")
        day(rec.get("date"), "date")
        q = dec(rec.get("qty"), "quantity")
        if q <= 0: raise ValueError("quantity must be positive")
        rec["po"], rec["qty"] = p["number"], qty_s(q)

    def bill_guard(kind, rec, data, old=None):
        if kind == "remove": return
        if not any(x.get("number") == str(rec.get("po", "")).strip().upper() for x in ns.po.items): raise ValueError("no such purchase order")
        rec["po"] = str(rec["po"]).strip().upper()
        day(rec.get("date"), "date")
        q, p = dec(rec.get("qty"), "quantity"), cents(rec.get("unit_price"), "unit price")
        if q <= 0 or p < 0: raise ValueError("quantity must be positive and price not negative")
        rec["qty"], rec["unit_price"] = qty_s(q), plain(p)

    ns.sup = GData(host, SUP_SPEC, "suppliers", master("name", sup_used))
    ns.req = GData(host, REQ_SPEC, "requests", req_guard, seq=("number", "PR-"))
    ns.po = GData(host, PO_SPEC, "orders", po_guard, seq=("number", "PO-"), after=po_after)
    ns.rec = GData(host, REC_SPEC, "receipts", rec_guard, after=sync)
    ns.bill = GData(host, BILL_SPEC, "bills", bill_guard)
    ns.sync = sync
    sync()

    def reorder():
        inv = shared_items(host, "inventory")
        if not inv: return [nogrant("inventory", "procurement"), "", "Everything else works without it."]
        s = reorder_suggestions(inv, ns.req.items)
        return [f"{len(s)} reorder suggestion(s) (target stock = 2 x reorder point)", ""] + [f"  {a:<14}{b[:28]:<30}order {qty_s(c):>8}  about {money(d)}" for a, b, c, d in s]

    def make_requests():
        s = reorder_suggestions(shared_items(host, "inventory"), ns.req.items)
        if not s: return ("push", Message("Reorder", ["No suggestions (or inventory is not shared with this app)."]))

        def go():
            n = 0
            for sku, name, q, c in s:
                try: ns.req.add({"item": f"{sku} - {name}", "qty": qty_s(q), "est_cost": plain(c), "requester": LOW, "reason": "below reorder point"}); n += 1
                except ValueError: pass
            return ("push", Message("Reorder", [f"created {n} purchase request(s) in 'requested' status"]))
        return ("push", Confirm(f"Create {len(s)} purchase request(s) from low stock?", go))

    return suite("Procurement", "Suppliers, purchase requests, purchase orders, receipts and supplier invoices, with a three-way match (PO vs received vs "
                 "invoiced). Requests and orders follow a status lifecycle; no payments are made here.", [
                     ("Suppliers", GList(ns.sup, "Suppliers", host)),
                     ("Purchase requests", GList(ns.req, "Purchase requests", host)),
                     ("Purchase orders", GList(ns.po, "Purchase orders", host)),
                     ("Receipts", GList(ns.rec, "Receipts", host)),
                     ("Supplier invoices", GList(ns.bill, "Supplier invoices", host)),
                     ("Three-way match report", lambda: match_report(ns.po.items, ns.rec.items, ns.bill.items)),
                     ("Reorder suggestions (from Inventory)", reorder),
                     ("Create requests from low stock", Act(make_requests)),
                 ]), ns


# ============================================================ 5. HUMAN RESOURCES ====
EMP_SPEC = R("employees", "Employees", "employee", "name*; title; department; manager; email: email; hire_date: date; status: choice(active|on leave|left)=active",
             list_cols=("name", "title", "department", "manager", "status"), status="status", done=("left",), group="department",
             blurb="Work contact details only. This app does not collect government ID numbers or bank details.")
LT_SPEC = R("leavetypes", "Leave types", "leave type", "name*; days_per_year: number*", list_cols=("name", "days_per_year"),
            seed=({"name": "Annual", "days_per_year": "20"}, {"name": "Sick", "days_per_year": "10"}))
LR_SPEC = R("leave", "Leave requests", "leave request", "employee*; type*; start: date*; end: date*; days: number; status: choice(requested|approved|rejected|cancelled)=requested; note",
            list_cols=("employee", "type", "start", "end", "days", "status"), status="status", done=("approved", "rejected", "cancelled"))
LR_OK = {"requested": {"approved", "rejected", "cancelled"}, "approved": {"cancelled"}, "rejected": set(), "cancelled": set()}


def accrued(hire, days_per_year: D, asof: dt.date) -> D:
    """Leave earned this calendar year: days_per_year/12 per full month since max(hire date, 1 Jan). No carry-over."""
    try: h = dt.date.fromisoformat(str(hire))
    except ValueError: return D(0)
    if h > asof: return D(0)
    return days_per_year * min(12, months_between(max(h, dt.date(asof.year, 1, 1)), asof)) / 12


def weekdays(a: dt.date, b: dt.date) -> int:
    if (b - a).days > 365: raise ValueError("a leave request covers at most one year")
    return sum(1 for i in range((b - a).days + 1) if (a + dt.timedelta(days=i)).weekday() < 5)


def taken(reqs, emp, typ, year, status="approved", skip=None) -> D:
    t = D(0)
    for r in reqs:
        if r.get("employee") == emp and r.get("type") == typ and r.get("status") == status and r.get("start", "")[:4] == str(year) and r.get("_id") != skip:
            try: t += dec(r.get("days"))
            except ValueError: pass
    return t


def org_chart(emps) -> list:
    by = {str(e.get("name", "")).lower(): e for e in emps if e.get("name")}
    kids: dict = {}
    roots = []
    for e in emps:
        m = str(e.get("manager", "")).strip().lower()
        if m and m in by and m != str(e.get("name", "")).lower(): kids.setdefault(m, []).append(e)
        else: roots.append(e)
    label = lambda e: f"{e.get('name')}" + (f" - {e.get('title')}" if e.get("title") else "") + (f" ({e.get('department')})" if e.get("department") else "") + (" [left]" if e.get("status") == "left" else "")
    out, seen = [], set()
    stack = [(e, 0) for e in reversed(sorted(roots, key=lambda e: str(e.get("name")).lower()))]
    while stack and len(out) < 500:
        e, d = stack.pop()
        k = str(e.get("name", "")).lower()
        if k in seen: continue
        seen.add(k)
        miss = " (manager not found)" if str(e.get("manager", "")).strip() and str(e.get("manager")).strip().lower() not in by else ""
        out.append("  " * d + "- " + label(e) + miss)
        stack += [(c, d + 1) for c in reversed(sorted(kids.get(k, []), key=lambda c: str(c.get("name")).lower()))]
    cyc = [e.get("name") for e in emps if str(e.get("name", "")).lower() not in seen and e.get("name")]
    return out + ([""] + [f"CYCLE in manager links among: {', '.join(map(str, cyc[:20]))}. Fix the manager fields."] if cyc else []) or ["no employees yet"]


def headcount(emps) -> list:
    d: dict = {}
    for e in emps:
        c = d.setdefault(clean(e.get("department") or "(none)", 30), [0, 0, 0])
        c[0 if e.get("status", "active") == "active" else 1 if e.get("status") == "on leave" else 2] += 1
    rows = [[k, v[0], v[1], v[2]] for k, v in sorted(d.items())]
    return [f"Headcount: {sum(v[0] + v[1] for v in d.values())} current ({sum(v[0] for v in d.values())} active)", ""] + table(
        rows + [["TOTAL", sum(v[0] for v in d.values()), sum(v[1] for v in d.values()), sum(v[2] for v in d.values())]], ["Department", "Active", "On leave", "Left"])


def make_hr(host, e=None):
    ns = NS()
    names = lambda: {str(x.get("name", "")).lower(): x for x in ns.emp.items}
    used = lambda n: any(r.get("employee") == n for r in ns.lr.items) or any(x.get("manager") == n and x.get("name") != n for x in ns.emp.items)
    mg = master("name", used)

    def emp_guard(kind, rec, data, old=None):
        mg(kind, rec, data, old)
        if kind == "remove": return
        if rec.get("hire_date"): day(rec["hire_date"], "hire date")
        m = str(rec.get("manager", "")).strip()
        rec["manager"] = ""
        if m:
            by = names()
            if m.lower() not in by: raise ValueError(f"manager '{clean(m, 30)}' is not an employee")
            cur, hops = m.lower(), 0
            while cur and hops <= len(by) + 1:
                if cur == rec["name"].lower(): raise ValueError("that manager link would make a loop in the org chart")
                cur = str(by.get(cur, {}).get("manager", "")).strip().lower(); hops += 1
            rec["manager"] = by[m.lower()]["name"]

    def lr_guard(kind, rec, data, old=None):
        if kind == "remove":
            if rec.get("status") == "approved": raise ValueError("an approved request must be cancelled, not deleted")
            return
        emp = names().get(str(rec.get("employee", "")).strip().lower())
        lt = next((t for t in ns.lt.items if t["name"].lower() == str(rec.get("type", "")).strip().lower()), None)
        if not emp: raise ValueError("no such employee")
        if not lt: raise ValueError("no such leave type")
        rec["employee"], rec["type"] = emp["name"], lt["name"]
        a, b = day(rec.get("start"), "start"), day(rec.get("end"), "end")
        if b < a or a.year != b.year: raise ValueError("end must not precede start, and a request stays within one calendar year")
        n = weekdays(a, b)
        if n == 0: raise ValueError("no working days (Mon-Fri) in that range")
        rec["days"] = str(n)
        if kind == "add": rec["status"] = "requested"; return
        if old["status"] != "requested" and any(rec.get(k) != old.get(k) for k in ("employee", "type", "start", "end", "note")): raise ValueError("only a requested leave can be edited")
        transition(LR_OK, old, rec["status"], "leave request")
        if rec["status"] == "approved" and old["status"] != "approved":
            have = accrued(emp.get("hire_date"), dec(lt["days_per_year"]), a) - taken(ns.lr.items, rec["employee"], rec["type"], a.year, skip=rec["_id"])
            if n > have: raise ValueError(f"insufficient balance: {qty_s(have.quantize(D('0.01')))} day(s) accrued by the start date, {n} requested")
            for o in ns.lr.items:
                if o.get("employee") == rec["employee"] and o.get("status") == "approved" and o["_id"] != rec["_id"] and o["start"] <= rec["end"] and rec["start"] <= o["end"]:
                    raise ValueError("overlaps an approved leave of the same employee")

    ns.emp = GData(SpaceHost(host, "employees"), EMP_SPEC, "records", emp_guard)
    ns.lt = GData(host, LT_SPEC, "leavetypes", master("name", lambda n: any(r.get("type") == n for r in ns.lr.items)))
    ns.lr = GData(host, LR_SPEC, "leave", lr_guard)

    def balances_report(asof=None):
        a = asof or dt.date.today()
        rows = []
        for em in ns.emp.items:
            if em.get("status") == "left": continue
            for t in ns.lt.items:
                try: acc = accrued(em.get("hire_date"), dec(t["days_per_year"]), a)
                except ValueError: continue
                tk, pend = taken(ns.lr.items, em["name"], t["name"], a.year), taken(ns.lr.items, em["name"], t["name"], a.year, "requested")
                rows.append([em["name"], t["name"], f"{acc:.2f}", qty_s(tk), qty_s(pend), f"{acc - tk:.2f}"])
        return [f"Leave balances for {a.year} as at {a} (accrues monthly from hire date or 1 Jan; no carry-over; Mon-Fri days)", ""] + table(rows, ["Employee", "Type", "Accrued", "Taken", "Pending", "Balance"], maxw=100)
    ns.balances = balances_report
    return suite("Human Resources", "Employee records (work details only: no government ID or bank numbers), leave types with accrual, leave requests with "
                 "approval against the accrued balance, org chart from manager links, headcount by department.", [
                     ("Employees", GList(ns.emp, "Employees", host)),
                     ("Leave types", GList(ns.lt, "Leave types", host)),
                     ("Leave requests", GList(ns.lr, "Leave requests", host)),
                     ("Leave balances", balances_report),
                     ("Org chart", lambda: org_chart(ns.emp.items)),
                     ("Headcount by department", lambda: headcount(ns.emp.items)),
                 ]), ns


# ======================================================================= 6. ERP ====
def erp_summary(host) -> list:
    """Cross-app summary. `host` is the ERP host; each app's private data sits under its own prefix."""
    out = ["ERP summary (read-only; the modules are not auto-posted to each other)", ""]
    try:
        inv = [r for r in shared_items(host, "invoices") if r.get("status") == "sent"]
        out.append(f"Receivables: {money(sum(cents(r.get('balance') or r.get('total') or 0) for r in inv if _ok(r.get('balance') or r.get('total') or 0)))} across {len(inv)} sent invoice(s)")
    except Exception as ex:  # noqa: BLE001 - one bad section must not hide the others
        out.append(f"Receivables: unavailable ({type(ex).__name__})")
    try:
        n, v = open_po_value(raw_items(PrefixHost(host, "pro-"), "orders"), raw_items(PrefixHost(host, "pro-"), "receipts"))
        out.append(f"Open purchase orders: {n}, value still to receive {money(v)}")
    except Exception as ex:  # noqa: BLE001
        out.append(f"Open purchase orders: unavailable ({type(ex).__name__})")
    try:
        its = shared_items(host, "inventory")
        out.append(f"Stock value (weighted average): {money(sum(s['wa'] for s in stock_table(its, raw_items(PrefixHost(host, 'stk-'), 'movements'))))} over {len(its)} item(s)")
    except Exception as ex:  # noqa: BLE001
        out.append(f"Stock value: unavailable ({type(ex).__name__})")
    try:
        es = shared_items(host, "employees")
        out.append(f"Headcount: {sum(1 for e in es if e.get('status', 'active') != 'left')} current employee(s)")
    except Exception as ex:  # noqa: BLE001
        out.append(f"Headcount: unavailable ({type(ex).__name__})")
    try:
        es = raw_items(PrefixHost(host, "acc-"), "journal") or []
        d = Store(PrefixHost(host, "acc-")).load("journal", {})
        ents = d.get("entries", []) if isinstance(d, dict) else []
        b = balances(ents)
        out.append(f"Books: {len(ents)} journal entr{'y' if len(ents) == 1 else 'ies'}, debits {money(sum(v[0] for v in b.values()))} / credits {money(sum(v[1] for v in b.values()))}")
    except Exception as ex:  # noqa: BLE001
        out.append(f"Books: unavailable ({type(ex).__name__})")
    if not any(shared_items(host, s) for s in ("invoices", "inventory", "employees")):
        out += ["", "Some figures are empty because there is no data yet, or the shared folders are not granted to this app."]
    return out


class ErpHost:
    """The ERP hub keeps its OWN copy of the invoices / inventory / employees data, shared only among its own five
    modules, and never touches the shared folders of the standalone Invoicing / Inventory / Human Resources apps (an
    app that `owns` a folder can be the only one to: two owners would lock each other out). `contacts` passes through."""
    PRIVATE = ("invoices", "inventory", "employees")

    def __init__(self, host):
        self.h = host

    def __getattr__(self, n): return getattr(self.h, n)
    def _k(self, k, space): return f"erp-{space}-{k}"
    def get(self, k, space=None): return self.h.get(self._k(k, space)) if space in self.PRIVATE else self.h.get(k, space)
    def put(self, k, v, space=None): return self.h.put(self._k(k, space), v) if space in self.PRIVATE else self.h.put(k, v, space)
    def delete(self, k, space=None): return self.h.delete(self._k(k, space)) if space in self.PRIVATE else self.h.delete(k, space)
    def keys(self, space=None):
        if space not in self.PRIVATE: return self.h.keys(space)
        pre = f"erp-{space}-"
        return [k[len(pre):] for k in self.h.keys() if k.startswith(pre)]


def make_erp(host, e=None):
    host = ErpHost(host)
    def sub(mk, prefix):
        def f():
            r = mk(PrefixHost(host, prefix))
            return ("push", r[0] if isinstance(r, tuple) else r)
        return f
    return Menu("ERP", [("Accounting", sub(make_accounting, "acc-")), ("Invoicing", sub(make_invoicing, "inv-")),
                        ("Inventory Management", sub(make_inventory, "stk-")), ("Procurement", sub(make_procurement, "pro-")),
                        ("Human Resources", sub(make_hr, "hr-")), ("Summary (receivables, open POs, stock, headcount)", lambda: view("ERP summary", erp_summary(host)))],
                wrap("One module, five apps, each with its own storage prefix. Inside the hub they share the invoices, inventory and employees data, so Accounting "
                     "can see Invoicing and Procurement can see stock. Nothing is posted between them automatically except what you confirm in "
                     "Accounting ('post suggested entries').", 76))


def _first(f): return lambda host, e: (lambda r: r[0] if isinstance(r, tuple) else r)(f(host, e))


ENTRIES: list = [
    app("Accounting", _first(make_accounting), "partial",
        "Double-entry journal (unbalanced entries refused; reversals, no deletes), chart, trial balance, income statement, balance sheet, account ledger, "
        "period filter. Single currency, no closing entries, no bank feeds, no tax filing, no multi-user approval.", uses=["invoices"]),
    app("Invoicing", _first(make_invoicing), "partial",
        "Invoices with lines, discount and tax, sequential numbers, status, payments, balance due, ageing, text/HTML export. Single currency; no payment "
        "processing, no emailing or sending, no recurring invoices, no network.", owns=["invoices"], uses=["contacts"]),
    app("Inventory Management", _first(make_inventory), "partial",
        "Items, an immutable movement ledger, computed on-hand, reorder points, low-stock report, weighted-average and FIFO valuation. Single location; no "
        "barcode scanning, no lots or serials, no automatic posting to Accounting.", owns=["inventory"]),
    app("Procurement", _first(make_procurement), "partial",
        "Suppliers, requests, purchase orders (one item per order), receipts, supplier invoices, status lifecycle and a three-way match report, plus reorder "
        "suggestions from Inventory. No approvals workflow, no payments, no sending orders to suppliers.", uses=["inventory", "employees"]),
    app("Human Resources", _first(make_hr), "partial",
        "Employee records (no government ID or bank numbers collected), leave types with monthly accrual, requests with approval, org chart with cycle "
        "detection, headcount. No payroll, no holidays calendar (Mon-Fri days), no carry-over, no documents.", owns=["employees"]),
    app("ERP", _first(make_erp), "partial",
        "A hub that opens the five apps with separate storage prefixes plus a read-only summary. It keeps its own copy of the data (it does not share with the standalone Invoicing, Inventory or HR apps). Single user; the only cross-module posting is "
        "Accounting's confirmed 'post suggested entries' from invoices; no automatic postings for stock, purchasing or payroll.",
        uses=["contacts"]),
]
