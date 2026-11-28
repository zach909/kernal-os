"""pack_personal: Market Watchlist, Tickets and Passes, Budget Tracker, Personal Information Manager,
Password Generator. Plain stdlib; nothing runs in the background; every input is bounded."""

from __future__ import annotations

import datetime as dt
import json
import math
import re
import secrets
from decimal import Decimal, InvalidOperation

from .packkit import app, none  # noqa: F401
from .records import Data, RecordList
from .specs import R
from .ui import Menu, Message, Prompt, Screen, SpaceHost, TextView, bar, table, today, wrap

MAXN = 5000          # most shared records read
ZERO = Decimal(0)


def dec(v) -> Decimal:
    """A finite Decimal from user text, or 0."""
    try:
        d = Decimal(str(v).replace(",", "").strip())
    except (InvalidOperation, ValueError):
        return ZERO
    return d if d.is_finite() and abs(d) < Decimal(10) ** 15 else ZERO


def money(d: Decimal) -> str:
    return f"{d.quantize(Decimal('0.01')):,.2f}"


def pct(d: Decimal) -> str:
    return f"{d.quantize(Decimal('0.01')):+.2f}%"


def valid_date(s: str):
    try:
        return dt.date.fromisoformat(str(s))
    except ValueError:
        return None


# ------------------------------------------------------------ Market Watchlist ----
WATCH = R("watchlist", "Market Watchlist", "symbol",
          "symbol*; name; price: number*; prev_close: number; shares: number; cost_per_share: number; "
          "alert_above: number; alert_below: number; updated: date",
          list_cols=("symbol", "price", "shares", "alert_above", "alert_below"),
          blurb="Prices are typed by you (there is no live market data). Add a symbol, its price, and optionally shares and cost "
                "per share; press R for profit/loss, flags and allocation.",
          report_label="Portfolio", scope="Prices are typed in by hand; no live data.")


def analyse(items: list) -> dict:
    rows, tv, tc = [], ZERO, ZERO
    for r in items[:MAXN]:
        price, sh, cps, prev = dec(r.get("price")), dec(r.get("shares")), dec(r.get("cost_per_share")), dec(r.get("prev_close"))
        value, cost = price * sh, cps * sh
        row = {"symbol": str(r.get("symbol", ""))[:12], "price": price, "shares": sh, "value": value, "cost": cost,
               "pl": value - cost if cost else None,
               "pl_pct": (price - cps) / cps * 100 if cps > 0 else None,
               "day_pct": (price - prev) / prev * 100 if prev > 0 else None, "flags": []}
        up, lo = dec(r.get("alert_above")), dec(r.get("alert_below"))
        if up and price >= up: row["flags"].append(f"ABOVE {up.normalize():f}")
        if lo and price <= lo: row["flags"].append(f"BELOW {lo.normalize():f}")
        tv += value; tc += cost
        rows.append(row)
    return {"rows": rows, "value": tv, "cost": tc, "pl": tv - tc, "pl_pct": (tv - tc) / tc * 100 if tc > 0 else None}


def watch_report(items: list) -> list:
    a = analyse(items)
    if not a["rows"]: return ["no symbols yet"]
    fmt = lambda x, f: "-" if x is None else f(x)
    out = table([[r["symbol"], money(r["price"]), f"{r['shares'].normalize():f}", money(r["value"]), fmt(r["pl"], money),
                  fmt(r["pl_pct"], pct), fmt(r["day_pct"], pct), " ".join(r["flags"])] for r in a["rows"]],
                ["Symbol", "Price", "Shares", "Value", "P/L", "P/L %", "Day %", "Flag"])
    out += ["", f"Total value {money(a['value'])}   cost {money(a['cost'])}   P/L {money(a['pl'])}" + (f" ({pct(a['pl_pct'])})" if a["pl_pct"] is not None else ""),
            "", "Allocation by value (prices as you last typed them):"]
    held = sorted((r for r in a["rows"] if r["value"] > 0), key=lambda r: -r["value"])
    for r in held:
        out.append(f"  {r['symbol']:<12} {bar(float(r['value']), float(a['value']), 24):<24} {r['value'] / a['value'] * 100:5.1f}%")
    return out + ([] if held else ["  (no holdings: add shares to see allocation)"])


WATCH.report = watch_report


class SubList(RecordList):
    """A RecordList opened from a menu: Esc goes back instead of quitting the app."""
    def key(self, k):
        act = super().key(k)
        return ("pop", None) if act == ("quit",) else act


def _records(host, entry, spec, key="records"):
    r = RecordList(Data(host, spec, key)); r.title = entry.title
    return r


def make_watch(host, entry): return _records(host, entry, WATCH)


# ----------------------------------------------------------- Tickets and Passes ----
def expiring(items: list, on: str, days: int = 30) -> list:
    d0 = valid_date(on)
    rows = []
    for r in items[:MAXN]:
        for label, key in (("event/travel", "date"), ("expires", "expiry")):
            d = valid_date(r.get(key, ""))
            if d and d0 and (d - d0).days <= days:
                rows.append(((d - d0).days, str(r.get("title", ""))[:30], str(r.get("kind", "")), label, d.isoformat()))
    rows.sort()
    if not rows: return [f"nothing in the next {days} days"]
    return table([[("PAST" if n < 0 else "today" if n == 0 else f"in {n}d"), t, k, lab, d] for n, t, k, lab, d in rows],
                 ["When", "Title", "Kind", "What", "Date"])


def _tickets_spec():
    s = R("tickets", "Tickets and Passes", "ticket",
          "title*; kind: choice(train|flight|bus|event|id-card|other)=event; date: date; seat; reference; expiry: date; notes: long",
          due="expiry", list_cols=("title", "kind", "date", "seat", "expiry"),
          blurb="Keep ticket, boarding pass, event pass and ID-card details as plain text. Press R for what is coming up or expired.",
          report_label="Expiring soon (30 days) and past", scope="Text records only; no payments, scanning or digital identity.")
    s.report = lambda items: expiring(items, today())
    return s


def make_tickets(host, entry): return _records(host, entry, _tickets_spec())


# --------------------------------------------------------------- Budget Tracker ----
BUDGETS = R("budgets", "Budgets", "budget", "category*; limit: money*", list_cols=("category", "limit"),
            blurb="One line per category with its monthly limit.")
TXNS = R("transactions", "Transactions", "transaction",
         "date: date*; kind: choice(expense|income)=expense; category*; amount: money*; note",
         list_cols=("date", "kind", "category", "amount", "note"), amount="amount", group="category",
         blurb="Record income and expenses. Dates are YYYY-MM-DD; amounts are positive.")


def month_summary(budgets: list, txns: list, month: str) -> list:
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month or ""): return ["month must look like 2026-03"]
    limits, spent, income, skipped = {}, {}, ZERO, 0
    names = {}
    for b in budgets[:MAXN]:
        c = str(b.get("category", "")).strip()
        if c: names.setdefault(c.lower(), c[:20]); limits[c.lower()] = limits.get(c.lower(), ZERO) + dec(b.get("limit"))
    for t in txns[:MAXN]:
        if not str(t.get("date", "")).startswith(month): continue
        amt = dec(t.get("amount"))
        if amt <= 0: skipped += 1; continue
        if t.get("kind") == "income": income += amt; continue
        c = str(t.get("category", "")).strip()
        names.setdefault(c.lower(), c[:20]); spent[c.lower()] = spent.get(c.lower(), ZERO) + amt
    out, tot_spent, tot_limit = [f"Month {month}", ""], sum(spent.values(), ZERO), sum(limits.values(), ZERO)
    rows, top = [], max([float(max(limits.get(k, ZERO), spent.get(k, ZERO))) for k in names] or [0])
    for k in sorted(names):
        lim, sp = limits.get(k), spent.get(k, ZERO)
        flag = "no budget" if lim is None else ("OVER by " + money(sp - lim) if sp > lim else "")
        rows.append([names[k], money(lim) if lim is not None else "-", money(sp), money(lim - sp) if lim is not None else "-", flag])
    out += table(rows, ["Category", "Budget", "Spent", "Left", "Flag"]) if rows else ["no categories yet"]
    out += ["", "Spent (#) against budget (.):"]
    for k in sorted(names):
        sp, lim = float(spent.get(k, ZERO)), float(limits.get(k, ZERO))
        out.append(f"  {names[k]:<20} {bar(sp, top, 30, '#'):<30}")
        out.append(f"  {'':<20} {bar(lim, top, 30, '.'):<30}")
    out += ["", f"Income {money(income)}   Expenses {money(tot_spent)}   Net {money(income - tot_spent)}",
            f"Budgeted {money(tot_limit)}   Left of budget {money(tot_limit - tot_spent)}"]
    if skipped: out.append(f"{skipped} transaction(s) with zero or negative amounts were ignored.")
    return out


class BudgetMenu(Menu):
    def __init__(self, host, title):
        self.host = host
        super().__init__(title, [
            ("Transactions", lambda: ("push", SubList(Data(host, TXNS, "txns")))),
            ("Budgets by category", lambda: ("push", SubList(Data(host, BUDGETS, "budgets")))),
            ("Month summary (this month)", lambda: self.show(today()[:7])),
            ("Month summary (choose month)", lambda: ("push", Prompt("Month", "Month (YYYY-MM):", today()[:7], lambda v: self.show(v.strip())))),
        ], ["Monthly budget, income and expenses. Amounts are typed in; nothing is linked to a bank."])

    def show(self, month):
        lines = month_summary(Data(self.host, BUDGETS, "budgets").items, Data(self.host, TXNS, "txns").items, month)
        return ("push", TextView("Summary " + month, lines))


def make_budget(host, entry): return BudgetMenu(host, entry.title)


# ----------------------------------------------- Personal Information Manager ----
def read_shared(host, space: str, uses) -> tuple:
    """-> (items, why_empty). Only reads; empty with a reason when the folder is not granted or empty."""
    if space not in uses: return [], f"this app does not declare '{space}'"
    sh = SpaceHost(host, space)
    ks = sh.keys()
    if getattr(sh, "error", ""): return [], f"not granted: {sh.error}"
    if "records" not in ks: return [], f"'{space}' is empty or not shared with this app (kos grant APP space:{space} --level read)"
    try:
        items = json.loads(sh.get("records") or "{}").get("items", [])
    except (ValueError, AttributeError):
        return [], f"'{space}' could not be read"
    return [i for i in items[:MAXN] if isinstance(i, dict)], ""


def occurs(ev: dict, day: dt.date) -> bool:
    d0 = valid_date(ev.get("date", ""))
    if not d0 or day < d0: return False
    u = valid_date(ev.get("until", "")) if ev.get("until") else None
    if u and day > u: return False
    r = ev.get("repeat", "none")
    return (day == d0 if r in ("none", "", None) else True if r == "daily" else (day - d0).days % 7 == 0 if r == "weekly"
            else day.day == d0.day if r == "monthly" else (day.month, day.day) == (d0.month, d0.day) if r == "yearly" else False)


def agenda(events: list, tasks: list, start: dt.date, days: int = 14) -> list:
    out = []
    for i in range(max(1, min(days, 60))):
        d = start + dt.timedelta(days=i)
        todays = sorted((e for e in events if occurs(e, d)), key=lambda e: str(e.get("start", "")))
        due = [t for t in tasks if t.get("status") != "done" and t.get("due") == d.isoformat()]
        if not todays and not due: continue
        out.append(f"{d.isoformat()} {d.strftime('%a')}")
        out += [f"   {str(e.get('start', '')):<6}{str(e.get('title', ''))[:60]}" for e in todays]
        out += [f"   task  {str(t.get('title', ''))[:60]} ({t.get('priority', '')})" for t in due]
    od = [t for t in tasks if t.get("status") != "done" and valid_date(t.get("due", "")) and t["due"] < start.isoformat()]
    if od: out += ["", "Overdue tasks:"] + [f"   {t['due']}  {str(t.get('title', ''))[:60]}" for t in od[:50]]
    open_nodue = [t for t in tasks if t.get("status") != "done" and not t.get("due")]
    if open_nodue: out += ["", "Open tasks without a date:"] + [f"   {str(t.get('title', ''))[:60]}" for t in open_nodue[:30]]
    return out or ["nothing scheduled"]


NOTES = R("quick_notes", "Quick notes", "note", "title*; text: long", list_cols=("title", "text"),
          blurb="Your own quick notes, kept only in this app.")


class PIM(Menu):
    def __init__(self, host, entry):
        self.host, self.uses = host, list(entry.uses)
        super().__init__(entry.title, [
            ("Agenda: next 14 days", lambda: ("push", TextView("Agenda", self.agenda()))),
            ("Contacts", lambda: ("push", TextView("Contacts", self.contacts()))),
            ("Quick notes", lambda: ("push", SubList(Data(host, NOTES, "notes")))),
        ], ["One agenda over the Calendar, Task and Contact folders you have granted this app (read only).",
            "Edit them in their own apps; notes here are this app's own."])

    def agenda(self):
        ev, why1 = read_shared(self.host, "calendar", self.uses)
        tk, why2 = read_shared(self.host, "tasks", self.uses)
        lines = agenda(ev, tk, dt.date.today())
        notes = [w for w in (why1, why2) if w]
        return lines + ([""] + [f"! {w}" for w in notes] if notes else [])

    def contacts(self):
        cs, why = read_shared(self.host, "contacts", self.uses)
        if not cs: return [why or "no contacts"]
        return table([[c.get("name", ""), c.get("email", ""), c.get("phone", "")] for c in sorted(cs, key=lambda c: str(c.get("name", "")).lower())[:300]],
                     ["Name", "Email", "Phone"])


def make_pim(host, entry): return PIM(host, entry)


# ----------------------------------------------------------- Password Generator ----
AMBIG = set("Il1O0o")
CLASSES = {"lower": "abcdefghijklmnopqrstuvwxyz", "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "digits": "0123456789",
           "symbols": "!@#$%^&*()-_=+[]{};:,.?/"}
WORDS = """able acid aged also area army atom aunt back bake bald band bank barn base bath bead beam bean bear beef bell belt bend bike bird
blue boat bold bolt bone book boot born bowl brim bulb burn cafe cake calm camp cane card cart cave chef chip city clay clip club coal coat
code coin cold cook cool cord corn cost crab crew crop cube curl dark dash dawn deck deep deer desk dice dish dive dock door dove down draw
drum dust duty each earn east easy edge fair farm fast fawn fern film fish flag flat flax flip foam fold folk food ford fork form fort frog
fuel gale game gate gear gift glad glow goat gold golf gown grab gray grid grin gulf hail half hall hand harp hawk heap helm herb hill hint
home hood hook hope horn hull hunt idea inch iron isle jade jazz jolly jump keen kelp kind king kite knit lace lake lamp land lane lark leaf
lend lens lily lime line lion list loaf lock loft long loop lost loud luck lump lush mail main male malt mane maps mark mast meal melt mesh
mild mill mint mist moat moon moss moth nail navy neat nest nine node note oath oats oval oven pace pack page palm park path peak pear pine
pink plum pond pool port pump quay quiz race rain ramp reed ribs rice ride ring rock roof root rope rose ruby rush sage sail salt sand seal
seed shed ship silk slim snow soap sock soil song soup spin spur star stem swan tail tank tape teal tent tide tile tint toad tool tour tree
trim tuba tune twin vase veil vest vine wade wake wall warm wave west wind wing wolf wood wool yarn yoke zero zest zinc""".split()
SEPS = ("-", ".", "_", " ")


def pool_of(lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False) -> dict:
    return {k: "".join(c for c in v if not (avoid_ambiguous and c in AMBIG))
            for k, v in CLASSES.items() if {"lower": lower, "upper": upper, "digits": digits, "symbols": symbols}[k]}


def password_entropy(sizes: list, length: int) -> float:
    """Exact bits when every class must appear at least once: log2 of the number of strings of this length over the
    union of the classes that contain at least one character of each class (inclusion-exclusion)."""
    total, n = 0, len(sizes)
    for mask in range(1 << n):
        left = sum(sizes) - sum(s for i, s in enumerate(sizes) if mask >> i & 1)
        total += (-1) ** bin(mask).count("1") * left ** length
    return math.log2(total) if total > 0 else 0.0


def gen_password(length=16, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False) -> tuple:
    classes = pool_of(lower, upper, digits, symbols, avoid_ambiguous)
    if not classes: raise ValueError("choose at least one character class")
    if not isinstance(length, int) or not len(classes) <= length <= 128: raise ValueError(f"length must be {len(classes)}-128")
    union = "".join(classes.values())
    chars = [secrets.choice(v) for v in classes.values()] + [secrets.choice(union) for _ in range(length - len(classes))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), password_entropy([len(v) for v in classes.values()], length)


def gen_passphrase(words=5, sep="-", capitalize=False) -> tuple:
    if not isinstance(words, int) or not 3 <= words <= 12: raise ValueError("words must be 3-12")
    if sep not in SEPS: raise ValueError("bad separator")
    ws = [secrets.choice(WORDS) for _ in range(words)]
    return sep.join(w.capitalize() if capitalize else w for w in ws), words * math.log2(len(WORDS))


COMMON = set("""password 123456 123456789 12345678 12345 1234567 qwerty qwertyuiop abc123 letmein welcome admin login iloveyou monkey dragon
sunshine princess football baseball master shadow superman trustno1 passw0rd p@ssw0rd changeme default secret hello freedom whatever
starwars computer michael jessica charlie donald zaq12wsx qazwsx 111111 000000 654321 666666 121212 123123 1q2w3e4r 1qaz2wsx asdfgh asdfghjkl
zxcvbnm mustang access batman ninja pass test guest root user hunter2 summer winter spring autumn""".split())


def check_strength(pw: str) -> dict:
    """Offline estimate. Every character costs log2(pool) bits, except one that repeats the previous character, extends an
    ascending/descending run, or was already used (those cost 1 bit). A common password is capped at 10 bits."""
    pw = pw[:256]
    reasons = []
    if not pw: return {"bits": 0.0, "rating": "very weak", "reasons": ["empty"]}
    pool = (26 if any(c.islower() and c.isascii() for c in pw) else 0) + (26 if any(c.isupper() and c.isascii() for c in pw) else 0) \
        + (10 if any(c.isdigit() and c.isascii() for c in pw) else 0) + (33 if any(c.isascii() and not c.isalnum() for c in pw) else 0) \
        + (100 if any(not c.isascii() for c in pw) else 0)
    per, bits, seen, runs = math.log2(pool), 0.0, set(), 0
    for i, c in enumerate(pw):
        adj = bool(i) and abs(ord(c) - ord(pw[i - 1])) <= 1
        cheap = adj or c in seen
        runs += adj
        bits += 1 if cheap else per
        seen.add(c)
    if len(pw) < 8: reasons.append("shorter than 8 characters")
    elif len(pw) < 12: reasons.append("shorter than 12 characters")
    if pool and pool <= 36 and not (any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw)): reasons.append("uses a single kind of character")
    if len(set(pw)) < len(pw) * 0.6: reasons.append("many repeated characters")
    if runs: reasons.append("contains repeats or sequences like aaa / abc / 123")
    if pw.lower().rstrip("0123456789!@#$%^&*.?") in COMMON or pw.lower() in COMMON:
        reasons.append("is a very common password"); bits = min(bits, 10.0)
    rating = "very weak" if bits < 28 else "weak" if bits < 36 else "fair" if bits < 60 else "good" if bits < 80 else "strong"
    return {"bits": round(bits, 1), "rating": rating, "reasons": reasons or ["no problems found"]}


class PasswordGen(Screen):
    def __init__(self, title):
        self.title = title
        self.o = {"mode": "password", "length": 16, "lower": True, "upper": True, "digits": True, "symbols": True,
                  "ambig": False, "words": 5, "sep": 0, "cap": False}
        self.help = "g new  up/down length  l u d s classes  a no-ambiguous  p phrase  w words  e sep  c check  Esc quit"
        self.value, self.bits = "", 0.0
        self.new()

    def new(self):
        o = self.o
        try:
            if o["mode"] == "password": self.value, self.bits = gen_password(o["length"], o["lower"], o["upper"], o["digits"], o["symbols"], o["ambig"])
            else: self.value, self.bits = gen_passphrase(o["words"], SEPS[o["sep"]], o["cap"])
        except ValueError as e:
            self.value, self.bits = f"({e})", 0.0

    def render(self, w, h):
        o = self.o
        yn = lambda k: "x" if o[k] else " "
        opts = (f"  length {o['length']}   [{yn('lower')}] lower  [{yn('upper')}] UPPER  [{yn('digits')}] digits  [{yn('symbols')}] symbols  [{yn('ambig')}] avoid Il1O0o"
                if o["mode"] == "password" else f"  words {o['words']}   separator '{SEPS[o['sep']]}'   [{yn('cap')}] Capitalise")
        return ["", f"  Mode: {o['mode']}", opts, "", f"  {self.value}", "", f"  Entropy: {self.bits:.1f} bits (from the choices made, not from looking at the result)",
                "", "  Generated with the operating system's secure random source. Shown once and never saved.",
                "  A password vault needs encryption KOS does not have yet, so this app keeps no passwords."][:h]

    def key(self, k):
        o = self.o
        if k == "escape": return ("pop", None)
        if k == "c": return \
            ("push", Prompt("Strength check", "Type a password to check (hidden, not saved):", "", self._check, secret=True))
        if k == "up": o["length"] = min(128, o["length"] + 1); o["words"] = min(12, o["words"] + (o["mode"] != "password"))
        elif k == "down": o["length"] = max(4, o["length"] - 1); o["words"] = max(3, o["words"] - (o["mode"] != "password"))
        elif k == "pageup": o["length"] = min(128, o["length"] + 8)
        elif k == "pagedown": o["length"] = max(4, o["length"] - 8)
        elif k in ("l", "u", "d", "s"):
            name = {"l": "lower", "u": "upper", "d": "digits", "s": "symbols"}[k]
            if not o[name] or sum(o[x] for x in CLASSES) > 1: o[name] = not o[name]
        elif k == "a": o["ambig"] = not o["ambig"]
        elif k == "p": o["mode"] = "passphrase" if o["mode"] == "password" else "password"
        elif k == "w": o["words"] = 3 + (o["words"] - 2) % 10
        elif k == "e": o["sep"] = (o["sep"] + 1) % len(SEPS)
        elif k == "C": o["cap"] = not o["cap"]
        elif k not in ("g", "enter", " "): return None
        self.new()

    def _check(self, pw):
        r = check_strength(pw)
        return ("push", Message("Strength", [f"Rating: {r['rating']}   Estimated {r['bits']} bits", "", *("- " + x for x in r["reasons"]), "",
                                              "An offline estimate: length, character mix, repeats, sequences and a small list of common passwords. It cannot know if a password leaked."]))


def make_pw(host, entry): return PasswordGen(entry.title)


ENTRIES = [
    app("Market Watchlist", make_watch, "partial",
        "Prices are typed in by you; there is no live market data. Holdings, cost basis, P/L, % change, alert thresholds and allocation are computed from those prices."),
    app("Tickets and Passes", make_tickets, "partial",
        "Stores ticket, boarding pass, event pass and ID-card details as plain text with an expiring-soon list. It does not pay, scan, show QR codes or act as a digital identity; do not store card or secret numbers."),
    app("Budget Tracker", make_budget, "full",
        "Monthly category budgets, income and expense transactions typed in by you, remaining per category, overspend flags, month summary with bar charts. Not linked to any bank."),
    app("Personal Information Manager", make_pim, "partial",
        "Read-only agenda over the calendar, tasks and contacts folders you have granted it (empty and explained if not), plus its own quick notes. Edit calendar, tasks and contacts in their own apps.",
        uses=["calendar", "tasks", "contacts"]),
    app("Password Generator", make_pw, "partial",
        "Random passwords and passphrases (secrets module), exact entropy, and an offline strength check. It never stores or shows saved passwords: a vault needs encryption KOS does not have yet.")
]
