"""pack_health: Health Records, Fitness Tracker, Meditation Timer (see docs/PACKS.md).

Manual-entry apps. No sensors, devices, network or audio. Data lives unencrypted in
each app's private vault (KOS has no encryption yet). Pure functions take the date/time
as an argument so tests are deterministic."""

from __future__ import annotations

import datetime as dt
import math
import time

from .packkit import app, none, shared_items  # noqa: F401
from .records import Data, RecordForm, RecordList
from .specs import R
from .ui import Menu, Prompt, Screen, SpaceHost, Store, TextView, bar, table, today, wrap

CAP = 2000          # records per list
TEXT, LONG = 200, 2000


# ------------------------------------------------------------ small helpers ----
def d_of(s):
    """ISO date string -> date, or None."""
    try:
        return dt.date.fromisoformat(s) if isinstance(s, str) and len(s) == 10 else None
    except ValueError:
        return None


def n_of(v, lo=-1e9, hi=1e9):
    """Any value -> finite float within [lo, hi], else None."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return n if math.isfinite(n) and lo <= n <= hi else None


def fmt(n) -> str:
    return str(int(n)) if n == int(n) else f"{n:.2f}".rstrip("0").rstrip(".")


def week_start(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())


def streak(dates, today_s: str) -> int:
    """Consecutive days ending today (or yesterday, if today is still empty) that are in `dates`."""
    have = {x for x in dates if d_of(x)}
    d = d_of(today_s)
    if d is None:
        return 0
    if d.isoformat() not in have:
        d -= dt.timedelta(days=1)
    n = 0
    while d.isoformat() in have and n < 100000:
        n += 1
        d -= dt.timedelta(days=1)
    return n


class Vault(Data):
    """Data with bounds: printable text only, length caps, numbers clamped, a record cap."""

    def __init__(self, host, spec, key):
        super().__init__(host, spec, key)
        if not isinstance(self.d, dict) or not isinstance(self.d.get("items"), list) or not isinstance(self.d.get("next"), int):
            self.d = {"next": 1, "items": []}
        self.d["items"] = [r for r in self.d["items"] if isinstance(r, dict) and isinstance(r.get("_id"), int)][:CAP]

    def extra(self, rec: dict) -> None:
        pass

    def derive(self, rec: dict) -> dict:
        for f in self.spec.fields:
            v = "".join(c for c in str(rec.get(f.key, "")) if c.isprintable())
            v = v[:LONG if f.kind == "long" else TEXT]
            if f.kind == "number" and v:
                n = n_of(v, 0, 1e6)
                v = fmt(n) if n is not None else ""
            if f.key == "date" and not v:
                v = today()
            rec[f.key] = v
        self.extra(rec)
        return rec

    def add(self, rec):
        if len(self.items) >= CAP:
            self.error = f"limit of {CAP} records reached"
            return rec
        return super().add(rec)


class SubList(RecordList):
    """RecordList that goes back (not quits) on Esc, so it can sit under a menu."""

    def key(self, k):
        if k == "escape" and not (self.query or self.filt):
            return ("pop", None)
        return super().key(k)


class RootMenu(Menu):
    def key(self, k):
        if k == "escape":
            return ("quit",)
        return super().key(k)


def items_of(host, key):
    d = Store(host).load(key) or {}
    it = d.get("items") if isinstance(d, dict) else None
    return [r for r in it if isinstance(r, dict)] if isinstance(it, list) else []


def push(screen):
    return lambda: ("push", screen)


# ============================================================ HEALTH RECORDS ====
KINDS = ("blood pressure", "weight", "height", "glucose", "temperature", "heart rate", "oxygen saturation", "other")
DEFAULT_UNIT = {"blood pressure": "mmHg", "weight": "kg", "height": "cm", "glucose": "mg/dL",
                "temperature": "C", "heart rate": "bpm", "oxygen saturation": "%"}
# editable normal ranges [low, high] in the default unit; blood pressure has two parts
DEFAULT_RANGES = {"systolic": [90, 120], "diastolic": [60, 80], "glucose": [70, 99],
                  "temperature": [36.1, 37.2], "heart rate": [60, 100], "oxygen saturation": [95, 100]}
RANGE_UNIT = {"systolic": "mmHg", "diastolic": "mmHg", "glucose": "mg/dL (fasting)", "temperature": "C",
              "heart rate": "bpm", "oxygen saturation": "%"}


def parse_bp(v):
    """'120/80' -> (120.0, 80.0) or None."""
    parts = str(v).replace(" ", "").split("/")
    if len(parts) != 2:
        return None
    s, d = n_of(parts[0], 30, 300), n_of(parts[1], 20, 200)
    return (s, d) if s is not None and d is not None else None


def _judge(x, rng):
    if not rng:
        return ""
    return "LOW" if x < rng[0] else "HIGH" if x > rng[1] else "ok"


def classify(kind, value, unit="", ranges=None) -> str:
    """'ok' | 'LOW' | 'HIGH' | '' (no range for this kind) | '?' (unreadable value)."""
    ranges = ranges or DEFAULT_RANGES
    if kind == "blood pressure":
        bp = parse_bp(value)
        if bp is None:
            return "?"
        j = [_judge(bp[0], ranges.get("systolic")), _judge(bp[1], ranges.get("diastolic"))]
        return "HIGH" if "HIGH" in j else "LOW" if "LOW" in j else j[0]
    if kind not in ("glucose", "temperature", "heart rate", "oxygen saturation"):
        return ""
    x = n_of(value, 0, 10000)
    if x is None:
        return "?"
    u = (unit or "").strip().lower().lstrip("°")
    if kind == "temperature" and u == "f":
        x = (x - 32) * 5 / 9
    elif kind == "glucose" and u.startswith("mmol"):
        x = x * 18.0182
    return _judge(x, ranges.get(kind))


def bmi(weight, wunit, height, hunit):
    """-> BMI rounded to 0.1, or None. Units: kg|lb and cm|in|m."""
    w, h = n_of(weight, 0, 1e5), n_of(height, 0, 1e5)
    if not w or not h:
        return None
    w *= 0.45359237 if (wunit or "kg").strip().lower() in ("lb", "lbs") else 1
    hu = (hunit or "cm").strip().lower()
    h *= {"in": 0.0254, "inch": 0.0254, "m": 1.0}.get(hu, 0.01)
    if not (1 <= w <= 700 and 0.3 <= h <= 2.6):
        return None
    return round(w / (h * h), 1)


def bmi_category(b) -> str:
    return "underweight" if b < 18.5 else "normal" if b < 25 else "overweight" if b < 30 else "obese"


def latest(items, kind):
    rows = [r for r in items if r.get("kind") == kind and d_of(r.get("date"))]
    return max(rows, key=lambda r: (r["date"], r.get("_id", 0))) if rows else None


def readings_report(items) -> list:
    out = ["Latest reading of each kind:", ""]
    for k in KINDS:
        r = latest(items, k)
        if r:
            out.append(f"  {k:<18} {r.get('value', '')} {r.get('unit', '')}  ({r['date']})  {r.get('flag', '')}")
    if len(out) == 2:
        out.append("  none yet")
    w, h = latest(items, "weight"), latest(items, "height")
    out.append("")
    b = bmi(w.get("value"), w.get("unit"), h.get("value"), h.get("unit")) if w and h else None
    out.append(f"BMI: {b} ({bmi_category(b)})  - adult screening figure only, not a diagnosis" if b else
               "BMI: needs a weight and a height reading")
    flagged = [r for r in items if r.get("flag") in ("HIGH", "LOW")]
    out += ["", f"Out of range readings: {len(flagged)}"]
    for r in sorted(flagged, key=lambda r: r.get("date", ""), reverse=True)[:10]:
        out.append(f"  {r['date']}  {r.get('kind')}  {r.get('value')} {r.get('unit', '')}  {r.get('flag')}")
    return out


def refills_due(items, today_s, days=7) -> list:
    t = d_of(today_s)
    out = []
    for r in items:
        d = d_of(r.get("refill_date"))
        if t is None or d is None or r.get("status") == "stopped":
            continue
        left = (d - t).days
        if left <= days:
            out.append((left, f"{r.get('name', '')}: " + (f"refill {-left} day(s) overdue ({d})" if left < 0 else f"refill due in {left} day(s) ({d})")))
    return [s for _l, s in sorted(out)] or [f"no refills due within {days} days"]


def adherence(items, today_s, days=30) -> dict:
    """{medicine: (taken, missed, percent or None)} over the last `days` days; 'skipped' is not counted."""
    t, out = d_of(today_s), {}
    if t is None:
        return out
    for r in items:
        d = d_of(r.get("date"))
        if d is None or not 0 <= (t - d).days < days:
            continue
        a = out.setdefault(str(r.get("medication", "")).strip().lower(), [0, 0])
        if r.get("status") == "taken": a[0] += 1
        elif r.get("status") == "missed": a[1] += 1
    return {m: (a, b, round(100 * a / (a + b)) if a + b else None) for m, (a, b) in out.items()}


def adherence_report(items, today_s=None) -> list:
    res = adherence(items, today_s or today())
    return [f"{m[:24]:<24} taken {a:>3}  missed {b:>3}  " + (f"{p}%" if p is not None else "-") for m, (a, b, p) in sorted(res.items())] \
        or ["no log entries in the last 30 days"]


def emergency_card(profile, allergies, conditions, meds) -> list:
    p = profile or {}
    def g(k): return str(p.get(k) or "-")
    out = ["EMERGENCY INFORMATION", "=" * 21, f"Name: {g('name')}    Date of birth: {g('dob')}    Blood type: {g('blood_type')}", "", "ALLERGIES"]
    out += [f"  {a.get('allergen', '')} - {a.get('reaction') or 'reaction not noted'} ({a.get('severity', '')})" for a in allergies] or ["  none recorded"]
    out += ["", "CONDITIONS"]
    out += [f"  {c.get('condition', '')}" + (f" (since {c['since']})" if c.get("since") else "") for c in conditions if c.get("status") != "resolved"] or ["  none recorded"]
    out += ["", "MEDICATIONS"]
    out += [f"  {m.get('name', '')} {m.get('dose', '')} {m.get('schedule', '')}".rstrip() for m in meds if m.get("status") != "stopped"] or ["  none recorded"]
    out += ["", "CONTACTS", f"  Emergency contact: {g('emergency_contact')}  {p.get('contact_phone', '')}".rstrip(),
            f"  Doctor: {g('doctor')}", f"  Insurance: {g('insurance')}"]
    if p.get("notes"):
        out += ["", "NOTES"] + ["  " + l for l in wrap(str(p["notes"]).replace("\\n", " "), 74)]
    return out + ["", "Entered by the owner and not verified. Not medical advice."]


class Measures(Vault):
    """Measurements live in the shared 'health' space (self.store.host); ranges stay in the app's private vault."""

    def __init__(self, host, spec, key, private=None):
        super().__init__(host, spec, key)
        self.private = private or host

    def extra(self, rec):
        rec["unit"] = rec.get("unit") or DEFAULT_UNIT.get(rec.get("kind"), "")
        rec["flag"] = classify(rec.get("kind"), rec.get("value"), rec["unit"], load_ranges(self.private))


def load_ranges(host) -> dict:
    out = {k: list(v) for k, v in DEFAULT_RANGES.items()}
    saved = Store(host).load("ranges", {})
    if isinstance(saved, dict):
        for k, v in saved.items():
            if k in out and (v is None or (isinstance(v, list) and len(v) == 2 and all(n_of(x) is not None for x in v))):
                out[k] = v
    return out


def parse_range(text):
    """'70-99' -> [70.0, 99.0]; '' -> None (no range); bad -> False."""
    t = text.strip()
    if not t:
        return None
    parts = t.replace("–", "-").split("-")
    if len(parts) != 2:
        return False
    lo, hi = n_of(parts[0], 0, 10000), n_of(parts[1], 0, 10000)
    return [lo, hi] if lo is not None and hi is not None and lo <= hi else False


def ranges_menu(host) -> Menu:
    rng = load_ranges(host)

    def edit(k):
        def done(v):
            r = parse_range(v)
            if r is False:
                return ("push", TextView("Not saved", ["Use low-high, e.g. 70-99 (empty = no range)."]))
            saved = Store(host).load("ranges", {})
            saved = saved if isinstance(saved, dict) else {}
            saved[k] = r
            Store(host).save("ranges", saved)
            return ("replace", ranges_menu(host))
        return lambda: ("push", Prompt("Range", f"{k} normal range in {RANGE_UNIT[k]} (low-high):",
                                       "-".join(fmt(x) for x in rng[k]) if rng[k] else "", done))
    ents = [(f"{k:<18} " + ("-".join(fmt(x) for x in rng[k]) + " " + RANGE_UNIT[k] if rng[k] else "(none)"), edit(k)) for k in DEFAULT_RANGES]
    return Menu("Normal ranges", ents, ["Editable. Defaults are common adult reference values, which vary by person:", "ask your clinician what is normal for you.", ""])


class Profile(Screen):
    title = "Profile"
    help = "e edit   Esc back"

    def __init__(self, data):
        self.data = data

    def rec(self):
        return self.data.items[0] if self.data.items else None

    def render(self, w, h):
        r = self.rec()
        if not r:
            return ["", "  No profile yet. Press e to enter one."]
        return [f"  {f.label:<18} {r.get(f.key, '')}" for f in self.data.spec.fields]

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "e": return ("push", RecordForm(self.data, self.rec(), self.save))

    def save(self, rec):
        if self.rec():
            self.data.update(rec)
        else:
            self.data.add(rec)


S_PROFILE = R("profile", "Profile", "profile", "name*; dob: date; blood_type: choice(A+|A-|B+|B-|AB+|AB-|O+|O-|unknown)=unknown; emergency_contact; contact_phone: phone; doctor; insurance; notes: long")
S_ALLERGY = R("allergies", "Allergies", "allergy", "allergen*; reaction; severity: choice(mild|moderate|severe)=mild; noted: date", list_cols=("allergen", "reaction", "severity"))
S_COND = R("conditions", "Conditions", "condition", "condition*; since; status: choice(active|resolved)=active; notes: long", status="status", done=("resolved",), list_cols=("condition", "since", "status"))
S_MEAS = R("measurements", "Measurements", "measurement", "kind: choice(" + "|".join(KINDS) + ")=blood pressure; value*; unit; date: date; note; flag",
           list_cols=("date", "kind", "value", "unit", "flag"), report=readings_report, report_label="Latest, BMI, out of range")
S_MED = R("medications", "Medications", "medication", "name*; dose; schedule: choice(daily|twice daily|three times daily|weekly|as needed)=daily; refill_date: date; status: choice(active|stopped)=active; notes",
          status="status", done=("stopped",), due="refill_date", list_cols=("name", "dose", "schedule", "refill_date", "status"),
          report=lambda items: refills_due(items, today()), report_label="Refills due (7 days)")
S_ADH = R("adherence", "Adherence log", "dose entry", "date: date; medication*; status: choice(taken|missed|skipped)=taken; note",
          list_cols=("date", "medication", "status"), report=adherence_report, report_label="Adherence, last 30 days")

HEALTH_NOTE = ("Sensitive: health data is stored UNENCRYPTED in this app's private vault because KOS has no encryption yet. "
               "Manual entry only: no devices, sensors or cloud. Reference ranges are generic and editable. "
               "This is not medical advice.")


def make_health(host, entry):
    def lst(spec, key, cls=Vault):
        return lambda: ("push", SubList(cls(host, spec, key)))
    prof = Vault(host, S_PROFILE, "profile")

    def card():
        L = lambda k: [r for r in items_of(host, k)]
        return ("push", TextView("Emergency card", emergency_card(prof.items[0] if prof.items else None, L("allergies"), L("conditions"), L("medications"))))
    ents = [("Profile", push(Profile(prof))), ("Allergies", lst(S_ALLERGY, "allergies")), ("Conditions", lst(S_COND, "conditions")),
            ("Measurements (BP, weight, glucose, ...)", lambda: ("push", SubList(Measures(SpaceHost(host, "health"), S_MEAS, "records", host)))),
            ("Normal ranges", lambda: ("push", ranges_menu(host))),
            ("Medications", lst(S_MED, "medications")), ("Adherence log", lst(S_ADH, "adherence")),
            ("Emergency information card", card)]
    return RootMenu("Health Records", ents, ["  Stored unencrypted in this app's vault. Not medical advice.", ""])


# =========================================================== FITNESS TRACKER ====
def sleep_hours(bed, wake):
    """'23:30','07:00' -> 7.5 (wraps past midnight). None if unreadable or zero."""
    def hm(s):
        p = str(s).strip().split(":")
        if len(p) != 2 or not all(x.isdigit() and len(x) <= 2 for x in p):
            return None
        h, m = int(p[0]), int(p[1])
        return h * 60 + m if h < 24 and m < 60 else None
    a, b = hm(bed), hm(wake)
    if a is None or b is None or a == b:
        return None
    return round(((b - a) % 1440) / 60, 2)


def _in(rows, start, end):
    return [r for r in rows if (d := d_of(r.get("date"))) is not None and start <= d <= end]


def _sum(rows, k):
    return sum(n_of(r.get(k), 0, 1e6) or 0 for r in rows)


def weekly_totals(acts, today_s, weeks=4) -> list:
    """[(monday, sessions, minutes, km, kcal)] newest first; weeks start Monday."""
    t = d_of(today_s)
    if t is None:
        return []
    out = []
    for i in range(weeks):
        m = week_start(t) - dt.timedelta(days=7 * i)
        rows = _in(acts, m, m + dt.timedelta(days=6))
        out.append((m.isoformat(), len(rows), fmt(_sum(rows, "minutes")), fmt(round(_sum(rows, "distance_km"), 2)), fmt(_sum(rows, "calories"))))
    return out


def sleep_average(sleeps, today_s, days=7):
    """Average hours/night over the last `days` days, or None."""
    t = d_of(today_s)
    if t is None:
        return None
    hs = [h for r in _in(sleeps, t - dt.timedelta(days=days - 1), t) if (h := n_of(r.get("hours"), 0.01, 24)) is not None]
    return round(sum(hs) / len(hs), 2) if hs else None


def goal_progress(g, acts, sleeps, today_s):
    """-> (value, target, percent) for this day/week (week starts Monday)."""
    t = d_of(today_s)
    start = t if g.get("period") == "day" else week_start(t)
    A, Z = _in(acts, start, t), _in(sleeps, start, t)
    m = g.get("metric")
    if m == "active_minutes": v = _sum(A, "minutes")
    elif m == "distance_km": v = _sum(A, "distance_km")
    elif m == "calories": v = _sum(A, "calories")
    elif m == "sessions": v = len(A)
    elif m == "sleep_hours":
        hs = [n_of(r.get("hours"), 0.01, 24) for r in Z]
        hs = [h for h in hs if h is not None]
        v = sum(hs) / len(hs) if hs else 0
    else: v = 0
    tg = n_of(g.get("target"), 0, 1e6) or 0
    return round(v, 2), tg, (round(100 * v / tg) if tg > 0 else 0)


def health_context(health) -> list:
    """Latest weight, heart rate and BMI from the shared 'health' space (read-only context)."""
    w, hr, h = latest(health, "weight"), latest(health, "heart rate"), latest(health, "height")
    if not (w or hr):
        return ["Health Records context: none available (nothing recorded there, or this app has not been granted",
                "  read access: kos grant APP space:health --level read). Everything else works without it."]
    out = ["From Health Records (read only):"]
    if w: out.append(f"  latest weight {w.get('value')} {w.get('unit', '')} ({w['date']})")
    if hr: out.append(f"  latest heart rate {hr.get('value')} {hr.get('unit', '')} ({hr['date']})")
    b = bmi(w.get("value"), w.get("unit"), h.get("value"), h.get("unit")) if w and h else None
    if b: out.append(f"  BMI {b} ({bmi_category(b)})")
    return out


def fitness_report(acts, sleeps, goals, today_s, health=()) -> list:
    if d_of(today_s) is None:
        return ["bad date"]
    out = ["Weekly totals (weeks start Monday)", ""]
    out += table([list(w) for w in weekly_totals(acts, today_s)], ["Week of", "Sessions", "Minutes", "km", "kcal"])
    avg = sleep_average(sleeps, today_s)
    out += ["", f"Activity streak: {streak([r.get('date') for r in acts], today_s)} day(s)",
            "Sleep, 7-day average: " + (f"{avg} h/night" if avg is not None else "no data"), "", "Goals (this day/week)"]
    for g in goals[:50]:
        v, tg, pct = goal_progress(g, acts, sleeps, today_s)
        out.append(f"  {str(g.get('goal', ''))[:22]:<22} {fmt(v)}/{fmt(tg)} {str(g.get('metric', ''))}  {pct}%  {bar(min(pct, 100), 100, 16)}")
    if not goals:
        out.append("  none set")
    return out + ["", *health_context(list(health)), "", "Entered by hand. Connected health devices and trackers are not supported."]


class Sleeps(Vault):
    def extra(self, rec):
        h = sleep_hours(rec.get("bed"), rec.get("wake"))
        rec["hours"] = fmt(h) if h is not None else ""


S_ACT = R("activity", "Activity log", "activity", "date: date; type: choice(walk|run|cycle|swim|strength|yoga|other)=walk; minutes: number*; distance_km: number; calories: number; note",
          list_cols=("date", "type", "minutes", "distance_km", "calories"))
S_SLEEP = R("sleep", "Sleep log", "night", "date: date; bed*; wake*; hours; note", list_cols=("date", "bed", "wake", "hours"))
S_GOAL = R("goals", "Goals", "goal", "goal*; metric: choice(active_minutes|distance_km|sessions|calories|sleep_hours)=active_minutes; period: choice(week|day)=week; target: number*",
           list_cols=("goal", "metric", "period", "target"))


def make_fitness(host, entry):
    def summary():
        return ("push", TextView("Fitness summary", fitness_report(items_of(host, "acts"), items_of(host, "sleep"), items_of(host, "goals"), today(), shared_items(host, "health"))))
    def lst(spec, key, cls=Vault):
        return lambda: ("push", SubList(cls(host, spec, key)))
    ents = [("Weekly summary, goals and streak", summary), ("Activity log", lst(S_ACT, "acts")),
            ("Sleep log", lst(S_SLEEP, "sleep", Sleeps)), ("Goals", lst(S_GOAL, "goals"))]
    return RootMenu("Fitness Tracker", ents, ["  Manual entry. Connected health devices are not supported.", ""])


# ========================================================== MEDITATION TIMER ====
# (label, seconds, level at start, level at end); level 0 = lungs empty, 1 = full
PATTERNS = {
    "Box breathing (4-4-4-4)": [("Inhale", 4, 0, 1), ("Hold", 4, 1, 1), ("Exhale", 4, 1, 0), ("Hold", 4, 0, 0)],
    "4-7-8 breathing": [("Inhale", 4, 0, 1), ("Hold", 7, 1, 1), ("Exhale", 8, 1, 0)],
    "Coherent breathing (5-5)": [("Inhale", 5, 0, 1), ("Exhale", 5, 1, 0)],
}


def phase_at(phases, elapsed):
    """-> (phase index, seconds into phase, cycle number from 1, lung level 0..1)."""
    total = sum(p[1] for p in phases)
    e = max(0.0, float(elapsed))
    cycle, r = int(e // total) + 1, e % total
    for i, (_n, s, lo, hi) in enumerate(phases):
        if r < s:
            return i, r, cycle, lo + (hi - lo) * r / s
        r -= s
    return 0, 0.0, cycle, phases[0][2]


def load_sessions(host) -> list:
    s = Store(host).load("sessions", [])
    return [x for x in s if isinstance(x, dict) and d_of(x.get("d")) and n_of(x.get("s"), 0, 86400) is not None][-CAP:] if isinstance(s, list) else []


def add_session(host, day, pattern, seconds) -> bool:
    s = load_sessions(host)
    s.append({"d": day, "p": str(pattern)[:40], "s": int(max(0, min(seconds, 14400)))})
    return Store(host).save("sessions", s[-CAP:])


def session_report(sessions, today_s) -> list:
    days = {x["d"] for x in sessions}
    mins = sum(x["s"] for x in sessions) // 60
    out = [f"Streak: {streak(days, today_s)} day(s)   Sessions: {len(sessions)}   Total: {mins} min", ""]
    out += [f"  {x['d']}  {x['s'] // 60:>3}:{x['s'] % 60:02d}  {x.get('p', '')}" for x in reversed(sessions[-30:])] or ["  none yet"]
    return out


class Breath(Screen):
    """Text breathing guide. No timer thread: the screen reads the clock whenever it is drawn,
    so it updates on each key press (any key refreshes). Space steps manually."""

    def __init__(self, host, name, clock=time.time):
        self.host, self.name, self.phases, self.clock = host, name, PATTERNS[name], clock
        self.title = name
        self.minutes, self.t0, self.manual, self.step, self.msg = 5, None, False, 0, ""
        self.mark = self.clock()

    def elapsed(self):
        return 0 if self.t0 is None else max(0, self.clock() - self.t0)

    @property
    def help(self):
        return ("space next phase   m clock/manual   f finish+log   Esc discard" if self.t0 is not None
                else "+/- minutes   m clock/manual   Enter start   Esc back")

    def render(self, w, h):
        out = ["", "  " + "  ".join(f"{n} {s}s" for n, s, _a, _b in self.phases), ""]
        if self.t0 is None:
            return out + [f"  Length {self.minutes} min, mode: {'manual (space steps)' if self.manual else 'clock'}.", "",
                          "  Press Enter to start. Sit comfortably; breathe through the nose.", self.msg and "  " + self.msg]
        e, total = self.elapsed(), self.minutes * 60
        if self.manual:
            i, cyc, lvl, left = self.step % len(self.phases), self.step // len(self.phases) + 1, self.phases[self.step % len(self.phases)][3], None
        else:
            i, into, cyc, lvl = phase_at(self.phases, e)
            left = math.ceil(self.phases[i][1] - into)
        n = self.phases[i][0]
        out += [f"  {n.upper():<8}" + (f" {left} s" if left is not None else ""), "", "  [" + "#" * round(lvl * 30) + "." * (30 - round(lvl * 30)) + "]", "",
                f"  cycle {cyc}    time {int(e) // 60:02d}:{int(e) % 60:02d} of {self.minutes:02d}:00"]
        if e >= total:
            out += ["", "  Time is up. Press f to finish and log the session."]
        out += ["", "  The screen redraws when you press a key (no background timer)."]
        return out

    def key(self, k):
        self.msg = ""
        if k == "escape": return ("pop", None)
        if k == "m": self.manual = not self.manual
        elif self.t0 is None:
            if k in ("+", "="): self.minutes = min(60, self.minutes + 1)
            elif k in ("-", "_"): self.minutes = max(1, self.minutes - 1)
            elif k == "enter": self.t0, self.step = self.clock(), 0
        elif k == " ": self.step += 1
        elif k == "f":
            secs = int(self.elapsed())
            ok = add_session(self.host, time.strftime("%Y-%m-%d", time.localtime(self.clock())), self.name, secs)
            return ("pop", None) if ok else ("push", TextView("Not saved", ["Could not save: " + (self.host.error or "storage refused")]))


def make_meditation(host, entry, clock=time.time):
    def log_hand(v):
        n = n_of(v.strip(), 1, 600)
        if n is None:
            return ("push", TextView("Not saved", ["Enter minutes, 1 to 600."]))
        add_session(host, today(), "by hand", int(n * 60))
    ents = [(n, push(Breath(host, n, clock))) for n in PATTERNS]
    ents += [("Session log and streak", lambda: ("push", TextView("Sessions", session_report(load_sessions(host), today())))),
             ("Log a session by hand", lambda: ("push", Prompt("Log session", "Minutes meditated:", "", log_hand)))]
    return RootMenu("Meditation Timer", ents, ["  A text guide for breathing. No audio.", ""])


# ===================================================================== ENTRIES ====
ENTRIES: list = [
    app("Health Records", make_health, "partial",
        "Manual-entry records: profile, allergies, conditions, measurements with editable ranges and flags, BMI, medications, adherence log, emergency card. "
        "No devices, labs or cloud sync, no reminders. Measurements are kept in the shared 'health' folder for Fitness Tracker. " + HEALTH_NOTE,
        owns=["health"]),
    app("Fitness Tracker", make_fitness, "partial",
        "Manual activity and sleep logs, goals with progress, weekly totals and streak. Connected health devices and wearables are NOT supported "
        "(no device access); no heart-rate or step import, no maps. Data is stored unencrypted in this app's private vault. Reads latest weight/heart rate from Health Records only if you grant it."
        , uses=["health"]),
    app("Meditation Timer", make_meditation, "partial",
        "Text breathing guide (box, 4-7-8, coherent), stepped by key or by the wall clock when a key is pressed, with a session log and streak. "
        "No audio or chimes, and it cannot run or alert in the background. Not medical advice."),
]
