"""pack_biz1: CRM, Sales Management, Support Desk, Advertising Campaign Manager.

All four are register apps on the RecordList/Spec engine with a real `report=` over the records.
Single user, local: no email, telephony, payments, ad platforms or network."""

from __future__ import annotations

import datetime as dt
import time
from collections import defaultdict

from .packkit import app, shared_items
from .records import Data, RecordList, RecordForm
from .specs import R
from .ui import ListNav, Menu, Screen, SpaceHost

# ----------------------------------------------------------------- helpers ----
def _n(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _date(s):
    s = str(s or "")
    if len(s) < 10:
        return None
    try:
        return dt.date.fromisoformat(s[:10])
    except ValueError:
        return None


def _time(s):
    """'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD' -> datetime, or None."""
    s = str(s or "").strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def _money(x) -> str:
    return f"{x:,.2f}"


def _today() -> dt.date:
    return dt.date.fromisoformat(time.strftime("%Y-%m-%d"))


def _list(host, spec, key, title):
    r = RecordList(Data(host, spec, key))
    r.title = title
    return r


def _menu(host, title, parts, intro):
    """parts: (label, vault key, spec) registers."""
    ents = []
    for label, key, spec in parts:
        ents.append((label, (lambda k=key, s=spec, l=label: ("push", _list(host, s, k, l)))))
    return Menu(title, ents, intro)


class Pick(Screen):
    """Choose a record from a shared folder; Enter opens a new-record form prefilled from it."""

    def __init__(self, title, rows, labels, make_form):
        self.title, self.rows, self.labels, self.make_form = title, rows, labels, make_form
        self.nav = ListNav(len(rows))
        self.help = "up/down   Enter pick   Esc back"

    def render(self, w, h):
        if not self.rows:
            return ["", "  Nothing to pick: the shared folder is empty, or this app has not been granted it.",
                    "  (kos grant APP space:NAME --level read). The app works without it."]
        top, end = self.nav.window(h - 1)
        return [("> " if i == self.nav.sel else "  ") + self.labels[i][:w - 4] for i in range(top, end)]

    def key(self, k):
        if self.nav.key(k): return None
        if k == "escape": return ("pop", None)
        if k == "enter" and self.rows: return ("replace", self.make_form(self.rows[self.nav.sel]))


def _picker(host, data, space, label, fill):
    """Menu entry: pick from shared `space`; fill(rec) -> {field: value} prefilled into a new record of `data`."""
    rows = shared_items(host, space)
    labels = [str(r.get("name", "?")) + (f"  ({r.get('company') or r.get('department')})" if r.get("company") or r.get("department") else "") for r in rows]

    def form(r):
        rec = {f.key: f.default for f in data.spec.fields}
        rec.update({k: str(v)[:200] for k, v in fill(r).items() if k in rec})
        f = RecordForm(data, rec, lambda x: data.add(x))
        f.title = "New " + data.spec.item
        return f
    n = f"{len(rows)} available" if rows else "none: empty or not granted"
    return (f"{label} ({n})", lambda: ("push", Pick(label, rows, labels, form)))


# --------------------------------------------------------------------- CRM ----
STAGES = ("lead", "qualified", "proposal", "negotiation", "won", "lost")
PROB = {"lead": 10, "qualified": 25, "proposal": 50, "negotiation": 75, "won": 100, "lost": 0}
_W = 'weighted=value*IF(stage="lead",10,IF(stage="qualified",25,IF(stage="proposal",50,IF(stage="negotiation",75,IF(stage="won",100,0)))))/100'


def crm_report(deals, acts, on=None, stale_days=30) -> list:
    on = on or _today()
    open_ = [d for d in deals if d.get("stage") not in ("won", "lost")]
    out = ["PIPELINE VALUE BY STAGE", ""]
    for st in STAGES:
        ds = [d for d in deals if d.get("stage") == st]
        out.append(f"  {st:<12} {len(ds):>3} deal(s) {_money(sum(_n(d.get('value')) for d in ds)):>14}  ({PROB[st]}%)")
    fc = sum(_n(d.get("value")) * PROB.get(d.get("stage"), 0) / 100 for d in open_)
    out += ["", f"FORECAST (open deals x stage probability): {_money(fc)}",
            f"Won to date: {_money(sum(_n(d.get('value')) for d in deals if d.get('stage') == 'won'))}", ""]
    last = {}
    for a in acts:
        d = _date(a.get("date"))
        k = str(a.get("deal", "")).strip().lower()
        if d and k and (k not in last or d > last[k]):
            last[k] = d
    out.append(f"STALE DEALS (no activity for {stale_days}+ days, as of {on})")
    stale = []
    for d in open_:
        seen = last.get(str(d.get("name", "")).strip().lower())
        opened = _date(d.get("opened"))
        ref = max([x for x in (seen, opened) if x], default=None)
        if ref is None:
            stale.append((10 ** 6, d, "no date at all")); continue
        age = (on - ref).days
        if age >= stale_days:
            stale.append((age, d, f"last activity {ref}"))
    for age, d, why in sorted(stale, key=lambda x: -x[0]):
        out.append(f"  {str(d.get('name', ''))[:26]:<26} {str(d.get('stage')):<12} {_money(_n(d.get('value'))):>12}  {why}" + (f" ({age} days)" if age < 10 ** 6 else ""))
    return out + ([] if stale else ["  none"])


def overdue_followups(acts, on=None) -> list:
    on = (on or _today()).isoformat()
    od = [a for a in acts if a.get("follow_up") and _date(a["follow_up"]) and a["follow_up"] < on and a.get("done") != "yes"]
    return [f"OVERDUE FOLLOW-UPS as of {on}: {len(od)}", ""] + [
        f"  {a['follow_up']}  {str(a.get('deal') or a.get('contact') or '?')[:24]:<24} {a.get('kind', '')}: {str(a.get('note', ''))[:30]}"
        for a in sorted(od, key=lambda a: a["follow_up"])]


CRM_CONTACTS = R("crm_contacts", "CRM contacts", "contact", "name*; account; role; email: email; phone: phone; notes: long", list_cols=("name", "account", "email"))
CRM_ACCOUNTS = R("crm_accounts", "Accounts", "account", "name*; industry; owner; website: url; notes: long", list_cols=("name", "industry", "owner"))
CRM_ACTS = R("crm_acts", "Activities", "activity", "deal*; contact; kind: choice(call|email|meeting|note|task)=note; date: date*; follow_up: date; done: bool=no; note",
             due="follow_up", report=overdue_followups, report_label="Overdue follow-ups", list_cols=("deal", "kind", "date", "follow_up", "done"))


def _crm(host, e):
    acts = Data(host, CRM_ACTS, "acts")
    deals = R("crm_deals", "Deals", "deal", "name*; account; contact; stage: choice(" + "|".join(STAGES) + ")=lead; value: money; opened: date; close_date: date; owner; weighted: money",
              calc=(_W,), status="stage", done=("won", "lost"), amount="value", due="close_date", list_cols=("name", "account", "stage", "value", "weighted"),
              report=lambda items: crm_report(items, acts.items), report_label="Pipeline, forecast, stale deals")
    dd = Data(SpaceHost(host, "deals"), deals)          # shared: Sales Management reads these
    parts = [("Deals", "deals", deals), ("Accounts", "accounts", CRM_ACCOUNTS), ("Contacts", "contacts", CRM_CONTACTS), ("Activities and follow-ups", "acts", CRM_ACTS)]
    m = _menu(host, "CRM", parts, ["Press R inside Deals for pipeline, forecast and stale deals; R inside Activities for overdue follow-ups.", ""])
    m.entries[0] = ("Deals", lambda: ("push", _titled(RecordList(dd), "Deals")))
    m.entries.append(_picker(host, dd, "contacts", "New deal for a shared contact", lambda r: {"contact": r.get("name"), "account": r.get("company")}))
    m.entries.append(_picker(host, dd, "employees", "New deal owned by an employee", lambda r: {"owner": r.get("name")}))
    m.nav.resize(len(m.entries))
    return m


# ------------------------------------------------------------------- Sales ----
SALES_TARGETS = R("sales_targets", "Targets", "target", "rep*; month*; target: money*", amount="target", group="rep", list_cols=("rep", "month", "target"),
                  scope="month is YYYY-MM")


def sales_report(quotes, targets, deals=None, invoices=None) -> list:
    won = [q for q in quotes if q.get("status") == "won"]
    lost = [q for q in quotes if q.get("status") == "lost"]
    open_ = [q for q in quotes if q.get("status") in ("draft", "sent")]
    out = [f"Open pipeline (draft + sent): {_money(sum(_n(q.get('total')) for q in open_))} in {len(open_)} quote(s)"]
    out.append(f"Won: {len(won)}  Lost: {len(lost)}  Win rate: " + (f"{100 * len(won) / (len(won) + len(lost)):.1f}%" if won or lost else "n/a"))
    out.append("Average won deal size: " + (_money(sum(_n(q.get('total')) for q in won) / len(won)) if won else "n/a"))
    act, tgt = defaultdict(float), defaultdict(float)
    for q in won:
        act[(str(q.get("rep", "?")), str(q.get("date", ""))[:7])] += _n(q.get("total"))
    for t in targets:
        tgt[(str(t.get("rep", "?")), str(t.get("month", ""))[:7])] += _n(t.get("target"))
    out += ["", "TARGET VS ACTUAL (won totals)", f"  {'rep':<14} {'month':<8} {'target':>12} {'actual':>12}  attainment"]
    for k in sorted(set(act) | set(tgt)):
        t, a = tgt.get(k, 0.0), act.get(k, 0.0)
        out.append(f"  {str(k[0])[:14]:<14} {k[1]:<8} {_money(t):>12} {_money(a):>12}  " + (f"{100 * a / t:.0f}%" if t else "no target"))
    out += ["", "CRM DEALS (shared 'deals' folder)"]
    od = [d for d in (deals or []) if d.get("stage") not in ("won", "lost")]
    if not deals:
        out.append("  none: empty, or this app has not been granted 'deals'")
    for st in STAGES[:4]:
        ds = [d for d in od if d.get("stage") == st]
        if ds:
            out.append(f"  {st:<12} {len(ds):>3} deal(s) {_money(sum(_n(d.get('value')) for d in ds)):>14}")
    out += ["", "BILLED VS TARGET (shared 'invoices' folder; paid + sent, by due month)"]
    if not invoices:
        return out + ["  none: empty, or this app has not been granted 'invoices'"]
    billed, mt = defaultdict(float), defaultdict(float)
    for i in invoices:
        if i.get("status") in ("paid", "sent"):
            billed[str(i.get("due", ""))[:7]] += _n(i.get("total"))
    for (_r, m), v in tgt.items():
        mt[m] += v
    for m in sorted(set(billed) | set(mt)):
        out.append(f"  {m:<8} target {_money(mt.get(m, 0)):>12}  billed {_money(billed.get(m, 0)):>12}")
    return out


def _sales(host, e):
    tg = Data(host, SALES_TARGETS, "targets")
    q = R("sales_quotes", "Quotes and orders", "quote", "number*; customer*; rep*; date: date*; kind: choice(quote|order)=quote; status: choice(draft|sent|won|lost)=draft; "
          "qty: number*=1; unit_price: money*=0; discount_pct: percent*=0; tax_pct: percent*=0; subtotal: money; total: money",
          calc=("subtotal=qty*unit_price", "total=ROUND(qty*unit_price*(1-discount_pct/100)*(1+tax_pct/100),2)"),
          status="status", done=("won", "lost"), amount="total", group="rep", list_cols=("number", "customer", "rep", "status", "total"),
          report=lambda items: sales_report(items, tg.items, shared_items(host, "deals"), shared_items(host, "invoices")), report_label="Pipeline, win rate, targets")
    return _menu(host, "Sales Management", [("Quotes and orders (R = report)", "quotes", q), ("Targets per rep and month", "targets", SALES_TARGETS)], [])


# ----------------------------------------------------------------- Support ----
SLA = {"urgent": (1, 4), "high": (4, 24), "normal": (8, 72), "low": (24, 120)}   # hours: (first response, resolution)


def support_report(tickets, now=None) -> list:
    now = now or dt.datetime.now()
    out, breaches, bad = [], [], []
    frs, ress, age_b, load = [], [], defaultdict(int), defaultdict(int)
    for t in tickets:
        op = _time(t.get("opened"))
        if op is None:
            bad.append(t.get("subject", "?")); continue
        t1, t2 = SLA.get(t.get("priority"), SLA["normal"])
        fr, rs = _time(t.get("first_response")), _time(t.get("resolved"))
        unresolved = t.get("status") in ("open", "pending")
        age = (now - op).total_seconds() / 3600
        if fr:
            frs.append((fr - op).total_seconds() / 3600)
            if frs[-1] > t1: breaches.append(f"{t.get('subject', '')[:28]}: first response {frs[-1]:.1f}h > {t1}h ({t.get('priority')})")
        elif unresolved and age > t1:
            breaches.append(f"{t.get('subject', '')[:28]}: no first response after {age:.1f}h > {t1}h ({t.get('priority')})")
        if rs:
            ress.append((rs - op).total_seconds() / 3600)
            if ress[-1] > t2: breaches.append(f"{t.get('subject', '')[:28]}: resolved in {ress[-1]:.1f}h > {t2}h ({t.get('priority')})")
        elif unresolved and age > t2:
            breaches.append(f"{t.get('subject', '')[:28]}: unresolved after {age:.1f}h > {t2}h ({t.get('priority')})")
        if unresolved:
            load[str(t.get("agent") or "(unassigned)")] += 1
            age_b["under 1 day" if age < 24 else "1-3 days" if age < 72 else "3-7 days" if age < 168 else "over 7 days"] += 1
    out.append("SLA TARGETS (hours first response / resolution): " + ", ".join(f"{p} {a}/{b}" for p, (a, b) in SLA.items()))
    out += ["", f"SLA BREACHES: {len(breaches)}"] + ["  " + b for b in breaches]
    out += ["", "Average first response: " + (f"{sum(frs) / len(frs):.1f} h" if frs else "n/a"),
            "Average resolution: " + (f"{sum(ress) / len(ress):.1f} h" if ress else "n/a"), "", "AGING OF OPEN TICKETS"]
    out += [f"  {b:<14} {age_b.get(b, 0)}" for b in ("under 1 day", "1-3 days", "3-7 days", "over 7 days")]
    out += ["", "OPEN LOAD PER AGENT"] + [f"  {a:<20} {n}" for a, n in sorted(load.items(), key=lambda x: (-x[1], x[0]))]
    if bad:
        out += ["", "UNREADABLE 'opened' time (use YYYY-MM-DD HH:MM): " + ", ".join(str(b)[:20] for b in bad[:10])]
    return out


SUPPORT = R("support", "Support Desk", "ticket", "subject*; customer; agent; priority: choice(low|normal|high|urgent)=normal; status: choice(open|pending|resolved|closed)=open; "
            "opened*; first_response; resolved; channel: choice(email|phone|chat|web|other)=web; notes: long",
            status="status", done=("resolved", "closed"), group="agent", list_cols=("subject", "priority", "agent", "status", "opened"),
            report=support_report, report_label="SLA breaches, aging, agent load",
            scope="times are typed as YYYY-MM-DD HH:MM; the SLA clock does not pause on 'pending'")


# --------------------------------------------------------------------- Ads ----
def ads_report(items) -> list:
    ch = defaultdict(lambda: defaultdict(float))
    for r in items:
        c = ch[str(r.get("channel") or "other")]
        for k in ("budget", "spend", "impressions", "clicks", "conversions", "revenue"):
            c[k] += _n(r.get(k))
    rows = []
    for name, c in ch.items():
        roas = c["revenue"] / c["spend"] if c["spend"] else 0.0
        rows.append((roas, name, c))
    out = ["CHANNELS RANKED BY ROAS", f"  {'channel':<10} {'spend':>11} {'revenue':>11} {'ROAS':>6} {'CTR%':>6} {'CPC':>7} {'CPA':>8}"]
    for roas, name, c in sorted(rows, key=lambda x: (-x[0], x[1])):
        ctr = 100 * c["clicks"] / c["impressions"] if c["impressions"] else 0
        cpc = c["spend"] / c["clicks"] if c["clicks"] else 0
        cpa = c["spend"] / c["conversions"] if c["conversions"] else 0
        out.append(f"  {name:<10} {_money(c['spend']):>11} {_money(c['revenue']):>11} {roas:>6.2f} {ctr:>6.2f} {cpc:>7.2f} {cpa:>8.2f}")
    over = [r for r in items if _n(r.get("spend")) > _n(r.get("budget"))]
    return out + ["", f"OVER BUDGET: {len(over)}"] + [f"  {r.get('campaign')}: spent {_money(_n(r.get('spend')))} of {_money(_n(r.get('budget')))}" for r in over]


ADS = R("ads", "Campaigns", "campaign", "campaign*; channel: choice(search|social|display|video|email|affiliate|other)=other; status: choice(planned|active|paused|done)=planned; "
        "budget: money*=0; spend: money*=0; impressions: number*=0; clicks: number*=0; conversions: number*=0; revenue: money*=0; "
        "ctr: number; cpc: money; cpa: money; roas: number; flag",
        calc=("ctr=IF(impressions>0,ROUND(clicks/MAX(impressions,0.000001)*100,2),0)", "cpc=IF(clicks>0,ROUND(spend/MAX(clicks,0.000001),2),0)", "cpa=IF(conversions>0,ROUND(spend/MAX(conversions,0.000001),2),0)",
              "roas=IF(spend>0,ROUND(revenue/MAX(spend,0.000001),2),0)", 'flag=IF(spend>budget,"OVER BUDGET","ok")'),
        status="status", done=("done",), amount="spend", group="channel", list_cols=("campaign", "channel", "spend", "roas", "flag"),
        report=ads_report, report_label="Channel ranking")


def _single(spec):
    return lambda host, e: _titled(RecordList(Data(host, spec)), e.title)


def _support(host, e):
    d = Data(host, SUPPORT)
    m = Menu("Support Desk", [("Tickets (R = SLA report)", lambda: ("push", _titled(RecordList(d), "Tickets")))], [])
    m.entries.append(_picker(host, d, "contacts", "New ticket from a shared contact", lambda r: {"customer": r.get("name")}))
    m.entries.append(_picker(host, d, "employees", "New ticket assigned to an employee", lambda r: {"agent": r.get("name")}))
    m.nav.resize(len(m.entries))
    return m


def _titled(r, title):
    r.title = title
    return r


ENTRIES: list = [
    app("CRM", _crm, "partial", "Accounts, contacts, deals with stages and values, activities and follow-ups; pipeline, forecast, stale-deal and overdue reports. Does not send email, place calls or sync with anything.", owns=["deals"], uses=["contacts", "employees"]),
    app("Sales Management", _sales, "partial", "Quotes and orders with discount and tax, pipeline, win rate, average deal size, targets vs actual. No invoicing, payments, e-signature or sending.", uses=["deals", "invoices"]),
    app("Support Desk", _support, "partial", "Tickets, priorities, status workflow, SLA breaches, aging and agent load. Does not receive email or chat, or answer customers; single user.", uses=["contacts", "employees"]),
    app("Advertising Campaign Manager", _single(ADS), "partial", "Campaign register with CTR, CPC, CPA, ROAS, over-budget flags and a channel ranking. You type the numbers in; it does not publish ads or fetch platform data."),
]
