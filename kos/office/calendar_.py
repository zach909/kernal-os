"""Calendar: events with recurrence, a month grid, agenda, and an appointment
scheduler with working hours, slots and double-booking prevention."""

from __future__ import annotations

import calendar as cal
import datetime as dt

from .records import Data, Field, RecordForm, Spec, validate
from .ui import Confirm, ListNav, Message, Prompt, Screen, Store, TextView, now_stamp

REPEATS = ("none", "daily", "weekly", "monthly", "yearly")
EVENT_SPEC = Spec("calendar", "Calendar", "event", [
    Field("title", "Title", required=True), Field("date", "Date", "date", required=True),
    Field("start", "Start HH:MM"), Field("end", "End HH:MM"),
    Field("repeat", "Repeats", "choice", REPEATS, "none"), Field("until", "Repeat until", "date"),
    Field("notes", "Notes", "long")], list_cols=("date", "start", "title"))


def parse_day(s: str) -> dt.date: return dt.date.fromisoformat(s)


def occurs(ev: dict, day: dt.date) -> bool:
    try:
        d0 = parse_day(ev["date"])
    except (KeyError, ValueError):
        return False
    if day < d0: return False
    if ev.get("until") and day > parse_day(ev["until"]): return False
    r = ev.get("repeat", "none")
    if r == "none": return day == d0
    if r == "daily": return True
    if r == "weekly": return (day - d0).days % 7 == 0
    if r == "monthly": return day.day == d0.day
    if r == "yearly": return (day.month, day.day) == (d0.month, d0.day)
    return False


def on_day(events: list, day: dt.date) -> list:
    return sorted((e for e in events if occurs(e, day)), key=lambda e: e.get("start") or "")


def mins(hhmm: str) -> int | None:
    try:
        h, m = hhmm.split(":"); v = int(h) * 60 + int(m)
        return v if 0 <= v < 1440 else None
    except (ValueError, AttributeError):
        return None


def overlaps(a: dict, b: dict) -> bool:
    s1, e1, s2, e2 = mins(a.get("start", "")), mins(a.get("end", "")), mins(b.get("start", "")), mins(b.get("end", ""))
    if None in (s1, s2): return False
    e1 = e1 if e1 is not None else s1 + 30
    e2 = e2 if e2 is not None else s2 + 30
    return s1 < e2 and s2 < e1


class CalendarView(Screen):
    def __init__(self, host, title="Calendar"):
        self.title = title
        self.data = Data(host, EVENT_SPEC)
        self.day = dt.date.fromisoformat(__import__("time").strftime("%Y-%m-%d"))
        self.nav = ListNav(0)
        self.msg = ""
        self.help = "arrows day  PgUp/PgDn month  t today  a add  Enter pick event  d delete  l list  Esc quit"

    def render(self, w, h):
        d = self.day
        out = [f"  {cal.month_name[d.month]} {d.year}", "   Mo  Tu  We  Th  Fr  Sa  Su"]
        for week in cal.Calendar().monthdatescalendar(d.year, d.month):
            row = "  "
            for x in week:
                if x.month != d.month: row += "    "; continue
                mark = "*" if on_day(self.data.items, x) else " "
                row += f"[{x.day:>2}]" if x == d else f" {x.day:>2}{mark}"
            out.append(row)
        evs = on_day(self.data.items, d)
        self.nav.resize(len(evs))
        out += ["", f"  {d.isoformat()} {d.strftime('%A')}  -  {len(evs)} event(s)"]
        for i, e in enumerate(evs):
            clash = any(o is not e and overlaps(e, o) for o in evs)
            out.append(f"{'>' if i == self.nav.sel else ' '} {e.get('start', ''):>5}-{e.get('end', ''):<5} {e['title']}"
                       + ("  (repeats " + e["repeat"] + ")" if e.get("repeat", "none") != "none" else "") + ("  ! overlaps" if clash else ""))
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        D = dt.timedelta
        if k == "left": self.day -= D(days=1)
        elif k == "right": self.day += D(days=1)
        elif k == "up": self.nav.key("up")
        elif k == "down": self.nav.key("down")
        elif k in ("pageup", "pagedown"):
            m = self.day.month - 1 + (1 if k == "pagedown" else -1)
            y, m = self.day.year + m // 12, m % 12 + 1
            self.day = self.day.replace(year=y, month=m, day=min(self.day.day, cal.monthrange(y, m)[1]))
        elif k == "t": self.day = dt.date.fromisoformat(__import__("time").strftime("%Y-%m-%d"))
        elif k == "a":
            rec = {f.key: f.default for f in EVENT_SPEC.fields}; rec["date"] = self.day.isoformat()
            return ("push", _prefilled(self.data, rec, self._add))
        elif k == "d":
            evs = on_day(self.data.items, self.day)
            if evs: ev = evs[min(self.nav.sel, len(evs) - 1)]; return ("push", Confirm(f"Delete '{ev['title']}'?", lambda: self.data.remove(ev)))
        elif k == "enter":
            evs = on_day(self.data.items, self.day)
            if evs: return ("push", RecordForm(self.data, evs[min(self.nav.sel, len(evs) - 1)], self.data.update))
        elif k == "l":
            return ("push", TextView("Upcoming 30 days", self.agenda(30)))
        elif k == "escape": return ("quit",)

    def _add(self, rec): self.data.add(rec); self.msg = "event added"

    def agenda(self, days: int) -> list:
        out, d0 = [], self.day
        for i in range(days):
            day = d0 + dt.timedelta(days=i)
            for e in on_day(self.data.items, day):
                out.append(f"{day.isoformat()} {e.get('start', ''):>5} {e['title']}")
        return out or ["nothing scheduled"]


def _prefilled(data: Data, rec: dict, on_done) -> Screen:
    f = RecordForm(data, None, on_done)
    f.rec.update(rec)
    return f


# ----------------------------------------------------------- scheduler ----
class SlotScheduler(Screen):
    """Working hours + slot length; pick a free slot and book it. Double
    booking is impossible: a booked slot is not offered and is re-checked."""

    CFG = {"days": [0, 1, 2, 3, 4], "open": "09:00", "close": "17:00", "slot": 30, "horizon": 14}

    def __init__(self, host, title="Appointments"):
        self.title, self.st = title, Store(host)
        self.cfg = {**self.CFG, **self.st.load("config", {})}
        self.book = self.st.load("bookings", [])
        self.nav = ListNav(0)
        self.msg = ""
        self.help = "up/down slot  Enter book  c cancel booking  o hours  b bookings  Esc quit"

    def slots(self) -> list:
        today = dt.date.fromisoformat(__import__("time").strftime("%Y-%m-%d"))
        taken = {(b["date"], b["time"]) for b in self.book}
        o, c, step = mins(self.cfg["open"]), mins(self.cfg["close"]), int(self.cfg["slot"])
        out = []
        for i in range(int(self.cfg["horizon"])):
            d = today + dt.timedelta(days=i)
            if d.weekday() not in self.cfg["days"]: continue
            t = o
            while t + step <= c:
                hhmm = f"{t // 60:02d}:{t % 60:02d}"
                if (d.isoformat(), hhmm) not in taken: out.append((d.isoformat(), hhmm))
                t += step
        return out

    def render(self, w, h):
        s = self.slots(); self.nav.resize(len(s))
        top, end = self.nav.window(h - 4)
        out = [f" Free slots ({self.cfg['open']}-{self.cfg['close']}, {self.cfg['slot']} min) - {len(self.book)} booked"]
        out += [f"{'>' if i == self.nav.sel else ' '} {s[i][0]} {dt.date.fromisoformat(s[i][0]).strftime('%a')} {s[i][1]}" for i in range(top, end)]
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        s = self.slots()
        if k == "enter" and s:
            d, t = s[self.nav.sel]
            return ("push", Prompt("Book", f"Name for {d} {t}:", "", lambda v: self._book(d, t, v)))
        if k == "b":
            return ("push", TextView("Bookings", [f"{b['date']} {b['time']}  {b['who']}" for b in sorted(self.book, key=lambda b: (b['date'], b['time']))] or ["none"]))
        if k == "c":
            return ("push", Prompt("Cancel", "Cancel booking at (YYYY-MM-DD HH:MM):", "", self._cancel))
        if k == "o":
            return ("push", Prompt("Hours", "open-close slotMinutes (e.g. 08:00-16:00 20):", f"{self.cfg['open']}-{self.cfg['close']} {self.cfg['slot']}", self._hours))
        if k == "escape": return ("quit",)

    def _book(self, d, t, who):
        who = who.strip()
        if not who: return
        if any(b["date"] == d and b["time"] == t for b in self.book): self.msg = "slot already taken"; return
        self.book.append({"date": d, "time": t, "who": who, "at": now_stamp()}); self.st.save("bookings", self.book)
        self.msg = f"booked {d} {t} for {who}"

    def _cancel(self, v):
        n = len(self.book); p = v.split()
        self.book = [b for b in self.book if not (len(p) == 2 and b["date"] == p[0] and b["time"] == p[1])]
        self.st.save("bookings", self.book); self.msg = "cancelled" if len(self.book) < n else "no such booking"

    def _hours(self, v):
        try:
            span, step = v.split(); a, b = span.split("-")
            if mins(a) is None or mins(b) is None or mins(a) >= mins(b) or not 5 <= int(step) <= 480: raise ValueError
            self.cfg.update(open=a, close=b, slot=int(step)); self.st.save("config", self.cfg); self.msg = "hours updated"
        except ValueError:
            self.msg = "format: 08:00-16:00 20"
