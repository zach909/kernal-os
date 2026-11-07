"""pack_time: Clock, Reminders, Sticky Notes, Journal, Habit Tracker, Focus Manager.

Small and plain on purpose. Every piece of logic is a pure function that is handed `now` / `today`, so tests are
exact. Nothing runs in the background: state is kept as timestamps/dates and is evaluated when the app is open."""

from __future__ import annotations

import calendar
import datetime as dt
import re
import time

from .packkit import app, shared_items
from .ui import Confirm, Editor, ListNav, Menu, Prompt, Screen, Store, TextView, bar, wrap

# ------------------------------------------------------------- helpers ----
MAX_TEXT = 200          # one-line text
MAX_LONG = 4000         # journal entry
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def clean(s, n: int = MAX_TEXT, keep_nl: bool = False) -> str:
    """Printable text only (control characters dropped), bounded."""
    if not isinstance(s, str):
        return ""
    ok = (lambda c: c.isprintable() or (keep_nl and c == "\n"))
    return "".join(c for c in s if ok(c))[:n].strip()


def day_of(now: float, off=None) -> str:
    if off is None:
        return time.strftime("%Y-%m-%d", time.localtime(now))
    return dt.datetime.fromtimestamp(now, dt.timezone(dt.timedelta(seconds=off))).strftime("%Y-%m-%d")


def to_date(s):
    if not isinstance(s, str) or not _ISO.match(s):
        return None
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        return None


def parse_date(s, today: str):
    """'', today, tomorrow, +N, or YYYY-MM-DD -> ISO string, or None if not understood."""
    t = clean(s, 20).lower()
    base = to_date(today)
    if base is None:
        return None
    if t in ("", "today"):
        return today
    if t == "tomorrow":
        return (base + dt.timedelta(days=1)).isoformat()
    if re.fullmatch(r"\+\d{1,4}", t):
        return (base + dt.timedelta(days=int(t[1:]))).isoformat()
    d = to_date(t)
    return d.isoformat() if d else None


def parse_hm(s):
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", s.strip()) if isinstance(s, str) else None
    if m and int(m[1]) < 24 and int(m[2]) < 60:
        return int(m[1]), int(m[2])
    return None


def parse_dur(s):
    """'25' (minutes), '90s', '5m', '1h30m', '1:30' (m:ss) -> seconds, or None. Bounded to 24 hours."""
    t = s.strip().lower() if isinstance(s, str) else ""
    if re.fullmatch(r"\d{1,4}", t):
        n = int(t) * 60
    elif (m := re.fullmatch(r"(\d{1,3}):(\d{2})", t)) and int(m[2]) < 60:
        n = int(m[1]) * 60 + int(m[2])
    elif (m := re.fullmatch(r"(?:(\d{1,3})h)?(?:(\d{1,4})m)?(?:(\d{1,6})s)?", t)) and t:
        n = int(m[1] or 0) * 3600 + int(m[2] or 0) * 60 + int(m[3] or 0)
    else:
        return None
    return n if 0 < n <= 86400 else None


def fmt_hms(secs: float) -> str:
    n = int(abs(secs))
    return ("-" if secs < 0 and n else "") + f"{n // 3600}:{n % 3600 // 60:02d}:{n % 60:02d}"


def streaks(days, today: str) -> tuple:
    """(current, longest) run of consecutive days. The current run still counts if it ended yesterday."""
    t = to_date(today)
    ords = sorted({d.toordinal() for d in map(to_date, days or ()) if d and t and d <= t})
    longest = run = 0
    prev = None
    for o in ords:
        run = run + 1 if prev is not None and o == prev + 1 else 1
        longest, prev = max(longest, run), o
    cur = run if ords and t and ords[-1] >= t.toordinal() - 1 else 0
    return cur, longest


def last_days(days, today: str, n: int = 7) -> int:
    """How many distinct days of the last n (ending today) are in `days`."""
    t = to_date(today)
    if not t:
        return 0
    lo = t - dt.timedelta(days=n - 1)
    return len({d for d in map(to_date, days or ()) if d and lo <= d <= t})


def lst(d: dict, key: str, cap: int) -> list:
    v = d.get(key)
    return [x for x in v if isinstance(x, dict)][:cap] if isinstance(v, list) else []


class _App(Screen):
    """Vault-backed screen with one JSON document. `now` is a function so tests can freeze time."""
    KEY = "data"

    def __init__(self, host, default: dict):
        self.host, self.st, self.now = host, Store(host), time.time
        d = self.st.load(self.KEY, None)
        d = d if isinstance(d, dict) else {}
        for k, v in default.items():
            if not isinstance(d.get(k), type(v)):
                d[k] = v
        self.d, self.nav, self.msg = d, ListNav(0), ""

    def save(self) -> None:
        if not self.st.save(self.KEY, self.d):
            self.msg = "NOT SAVED: " + (getattr(self.host, "error", "") or "could not save")

    def today(self) -> str:
        return day_of(self.now())

    def tail(self) -> list:
        return ["", " " + self.msg] if self.msg else []

    def next_id(self, key: str) -> int:
        return max([int(x.get("id", 0)) for x in self.d[key] if isinstance(x.get("id", 0), int)] + [0]) + 1


# --------------------------------------------------------------- Clock ----
# City -> (IANA zone, standard-time offset in minutes). The offsets are only used when zoneinfo data is missing.
ZONES = {
    "UTC": ("UTC", 0), "London": ("Europe/London", 0), "Paris": ("Europe/Paris", 60), "Berlin": ("Europe/Berlin", 60),
    "Cairo": ("Africa/Cairo", 120), "Johannesburg": ("Africa/Johannesburg", 120), "Lagos": ("Africa/Lagos", 60),
    "Nairobi": ("Africa/Nairobi", 180), "Istanbul": ("Europe/Istanbul", 180), "Moscow": ("Europe/Moscow", 180),
    "Dubai": ("Asia/Dubai", 240), "Karachi": ("Asia/Karachi", 300), "Delhi": ("Asia/Kolkata", 330),
    "Dhaka": ("Asia/Dhaka", 360), "Bangkok": ("Asia/Bangkok", 420), "Singapore": ("Asia/Singapore", 480),
    "Shanghai": ("Asia/Shanghai", 480), "Tokyo": ("Asia/Tokyo", 540), "Seoul": ("Asia/Seoul", 540),
    "Sydney": ("Australia/Sydney", 600), "Auckland": ("Pacific/Auckland", 720), "Honolulu": ("Pacific/Honolulu", -600),
    "Anchorage": ("America/Anchorage", -540), "Los Angeles": ("America/Los_Angeles", -480),
    "Denver": ("America/Denver", -420), "Chicago": ("America/Chicago", -360), "Mexico City": ("America/Mexico_City", -360),
    "New York": ("America/New_York", -300), "Toronto": ("America/Toronto", -300), "Sao Paulo": ("America/Sao_Paulo", -180),
}


def zone_time(city: str, now: float, use_zoneinfo: bool = True):
    """-> (datetime in that zone, offset minutes, source) or None for an unknown city.
    source is 'zoneinfo' (real tz data, daylight saving applied) or 'fixed' (built-in standard-time table)."""
    if city not in ZONES:
        return None
    iana, mins = ZONES[city]
    if use_zoneinfo:
        try:
            from zoneinfo import ZoneInfo
            t = dt.datetime.fromtimestamp(now, ZoneInfo(iana))
            return t, int(t.utcoffset().total_seconds() // 60), "zoneinfo"
        except Exception:
            pass
    t = dt.datetime.fromtimestamp(now, dt.timezone(dt.timedelta(minutes=mins)))
    return t, mins, "fixed"


def find_city(s: str):
    q = clean(s, 40).lower()
    return next((c for c in ZONES if c.lower() == q), None) or next((c for c in ZONES if q and c.lower().startswith(q)), None)


def alarm_next(hm: tuple, now: float, off: int) -> float:
    """Epoch of the next HH:MM strictly after `now` in a clock that is `off` seconds ahead of UTC."""
    base = int(now + off)
    t = base - base % 86400 + hm[0] * 3600 + hm[1] * 60
    return float((t if t > base else t + 86400) - off)


def sw_elapsed(sw: dict, now: float) -> float:
    run = sw.get("run")
    return max(0.0, float(sw.get("acc", 0)) + (now - run if isinstance(run, (int, float)) else 0))


def sw_toggle(sw: dict, now: float) -> None:
    if isinstance(sw.get("run"), (int, float)):
        sw["acc"], sw["run"] = sw_elapsed(sw, now), None
    else:
        sw["run"] = now


def sw_lap(sw: dict, now: float) -> bool:
    if not isinstance(sw.get("run"), (int, float)) or len(sw.setdefault("laps", [])) >= 200:
        return False
    sw["laps"].append(sw_elapsed(sw, now))
    return True


def lap_rows(laps: list) -> list:
    """[(lap number, split, total)]"""
    return [(i + 1, t - (laps[i - 1] if i else 0), t) for i, t in enumerate(laps)]


def when(due: float, now: float) -> str:
    left = due - now
    return f"in {fmt_hms(left)}" if left > 0 else f"DUE {fmt_hms(-left)} ago"


class Clock(_App):
    KEY = "clock"
    TABS = ("Alarms", "Stopwatch", "Timer", "World")

    def __init__(self, host, entry=None):
        super().__init__(host, {"alarms": [], "timers": [], "zones": ["UTC", "London", "New York", "Tokyo"], "sw": {"run": None, "acc": 0, "laps": []}})
        self.title, self.tab, self.zoneinfo = "Clock", 0, True
        self.d["alarms"], self.d["timers"] = lst(self.d, "alarms", 20), lst(self.d, "timers", 10)
        self.d["zones"] = [z for z in self.d["zones"] if z in ZONES][:12]
        if not isinstance(self.d["sw"].get("laps"), list):
            self.d["sw"]["laps"] = []
        self.help = "1-4 or left/right tab   a add   d delete   Stopwatch: space start/stop, l lap, r reset   Alarms: r re-arm"

    def items(self) -> list:
        return [self.d["alarms"], [], self.d["timers"], self.d["zones"]][self.tab]

    def render(self, w, h):
        now = self.now()
        self.nav.resize(len(self.items()))
        out = [" " + "  ".join(f"[{i + 1} {t}]" if i == self.tab else f" {i + 1} {t} " for i, t in enumerate(self.TABS)), ""]
        if self.tab == 0:
            off = time.localtime(now).tm_gmtoff or 0
            out.append(f" now {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}   (a: add alarm as HH:MM [label])")
            for i, a in enumerate(self.d["alarms"]):
                out.append(f"{'>' if i == self.nav.sel else ' '} {a.get('hm', '?')}  {when(a.get('due', 0), now):<22} {a.get('label', '')}")
            del off
        elif self.tab == 1:
            sw = self.d["sw"]
            out += [f"  {fmt_hms(sw_elapsed(sw, now))}   {'running' if sw.get('run') else 'stopped'}", ""]
            for n, split, total in reversed(lap_rows(sw["laps"])[-(h - 6):]):
                out.append(f"  lap {n:<3} {fmt_hms(split):>9}   total {fmt_hms(total)}")
        elif self.tab == 2:
            out.append(" a: add a timer, e.g. 5   90s   1h30m   1:30 (m:ss)")
            for i, t in enumerate(self.d["timers"]):
                left = t.get("end", 0) - now
                out.append(f"{'>' if i == self.nav.sel else ' '} {t.get('label', '')[:24]:<24} {'DONE ' + fmt_hms(-left) + ' ago' if left <= 0 else fmt_hms(left) + ' left'}")
        else:
            out.append(" a: add a city (type a name from the list: " + ", ".join(list(ZONES)[:6]) + ", ...)")
            for i, c in enumerate(self.d["zones"]):
                r = zone_time(c, now, self.zoneinfo)
                t, mins, src = r
                out.append(f"{'>' if i == self.nav.sel else ' '} {c:<14} {t:%a %H:%M}   UTC{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}  ({src})")
        out += ["", " Nothing rings: there is no sound and no background timer. Due items show when this app is open."]
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        if k in ("1", "2", "3", "4"):
            self.tab, self.nav.sel = int(k) - 1, 0
        elif k in ("left", "right"):
            self.tab, self.nav.sel = (self.tab + (1 if k == "right" else -1)) % 4, 0
        elif self.nav.key(k):
            pass
        elif k == "escape":
            return ("quit",)
        elif self.tab == 1:
            sw, now = self.d["sw"], self.now()
            if k == " ": sw_toggle(sw, now)
            elif k == "l": self.msg = "" if sw_lap(sw, now) else "start the stopwatch first (max 200 laps)"
            elif k == "r": sw.update({"run": None, "acc": 0, "laps": []})
            self.save()
        elif k == "a":
            return ("push", Prompt(self.TABS[self.tab], ["", "Alarm HH:MM [label]", "Timer length [label]", "City name"][self.tab], "", self.add))
        elif k == "d" and self.items():
            del self.items()[self.nav.sel]
            self.save()
        elif k == "r" and self.tab == 0 and self.items():
            a = self.items()[self.nav.sel]
            hm = parse_hm(a.get("hm", ""))
            if hm:
                a["due"] = alarm_next(hm, self.now(), time.localtime(self.now()).tm_gmtoff or 0)
                self.save()

    def add(self, text):
        now, parts = self.now(), clean(text, 80).split(None, 1)
        if not parts:
            return
        label = parts[1] if len(parts) > 1 else ""
        if self.tab == 0 and parse_hm(parts[0]) and len(self.d["alarms"]) < 20:
            self.d["alarms"].append({"hm": parts[0], "label": label, "due": alarm_next(parse_hm(parts[0]), now, time.localtime(now).tm_gmtoff or 0)})
        elif self.tab == 2 and parse_dur(parts[0]) and len(self.d["timers"]) < 10:
            secs = parse_dur(parts[0])
            self.d["timers"].append({"label": label or parts[0], "secs": secs, "end": now + secs})
        elif self.tab == 3 and find_city(clean(text, 40)) and len(self.d["zones"]) < 12:
            self.d["zones"].append(find_city(clean(text, 40)))
        else:
            self.msg = "not understood (or list full)"
            return
        self.save()


# ----------------------------------------------------------- Reminders ----
REPEATS = ("none", "daily", "weekly", "weekdays", "monthly")


def add_months(d: dt.date, n: int, dom: int) -> dt.date:
    y, m = divmod(d.year * 12 + d.month - 1 + n, 12)
    return dt.date(y, m + 1, min(dom, calendar.monthrange(y, m + 1)[1]))


def next_due(due: str, rep: str, dom: int = 0):
    d = to_date(due)
    if d is None:
        return None
    if rep == "daily": return (d + dt.timedelta(days=1)).isoformat()
    if rep == "weekly": return (d + dt.timedelta(days=7)).isoformat()
    if rep == "weekdays":
        d += dt.timedelta(days=1)
        while d.weekday() > 4:
            d += dt.timedelta(days=1)
        return d.isoformat()
    if rep == "monthly": return add_months(d, 1, dom or d.day).isoformat()
    return None


def rem_done(r: dict, today: str) -> None:
    """Finish a reminder. A repeating one moves to its first occurrence after today instead of closing."""
    nd, n = next_due(r.get("due", ""), r.get("rep", "none"), r.get("dom", 0)), 0
    while nd and nd <= today and n < 400:
        nd, n = next_due(nd, r["rep"], r.get("dom", 0)), n + 1
    if nd:
        r["due"], r["done_n"] = nd, r.get("done_n", 0) + 1
    else:
        r["done"] = True


def rem_snooze(r: dict, today: str, days: int = 1) -> None:
    base = max(to_date(r.get("due", "")) or to_date(today), to_date(today))
    r["due"] = (base + dt.timedelta(days=max(1, min(days, 365)))).isoformat()
    r["done"] = False


def rem_class(r: dict, today: str) -> str:
    if r.get("done"): return "done"
    due = r.get("due", "")
    return "overdue" if due < today else "today" if due == today else "upcoming"


def rem_sorted(rems: list, today: str, query: str = "", show_done: bool = False) -> list:
    order = {"overdue": 0, "today": 1, "upcoming": 2, "done": 3}
    q = query.lower()
    rows = [r for r in rems if (show_done or not r.get("done")) and (not q or q in str(r.get("t", "")).lower())]
    return sorted(rows, key=lambda r: (order[rem_class(r, today)], str(r.get("due", "")), str(r.get("t", ""))))


TASKS_GONE = "Tasks folder: nothing shared with this app (the owner grants it with: kos grant APP space:tasks)."


def open_tasks(host) -> list:
    """Tasks from the shared `tasks` folder that are not finished: [(title, due)]. [] without a grant."""
    out = []
    for r in shared_items(host, "tasks"):
        if str(r.get("status", "")).strip().lower() in ("done", "completed", "cancelled", "closed"):
            continue
        title = clean(str(r.get("title", "")), 60)
        if title:
            out.append((title, str(r.get("due", "")) if to_date(r.get("due")) else ""))
    return out


def task_due(tasks: list, today: str, days: int = 7) -> list:
    """Open tasks that are overdue, due today or due within `days`: [(class, due, title)], soonest first."""
    t = to_date(today)
    if not t: return []
    hi = (t + dt.timedelta(days=days)).isoformat()
    rows = [("overdue" if d < today else "today" if d == today else "upcoming", d, n) for n, d in tasks if d and d <= hi]
    return sorted(rows, key=lambda r: (r[1], r[2]))


class Reminders(_App):
    KEY = "reminders"

    def __init__(self, host, entry=None):
        super().__init__(host, {"items": []})
        self.title, self.query, self.show_done = "Reminders", "", False
        self.d["items"] = [r for r in lst(self.d, "items", 500) if to_date(r.get("due")) and r.get("rep", "none") in REPEATS]
        self.help = "a add  space done  s snooze 1 day  S snooze 7  d delete  / search  v show done"

    def rows(self):
        return rem_sorted(self.d["items"], self.today(), self.query, self.show_done)

    def render(self, w, h):
        rows, today = self.rows(), self.today()
        self.nav.resize(len(rows))
        cnt = {k: sum(1 for r in self.d["items"] if rem_class(r, today) == k) for k in ("overdue", "today", "upcoming")}
        out = [f" {cnt['overdue']} overdue   {cnt['today']} today   {cnt['upcoming']} upcoming" + (f"   search='{self.query}'" if self.query else ""), ""]
        if not rows:
            out.append("  Nothing here. Press a to add a reminder. (They show when this app is open; nothing pops up on its own.)")
        top, end = self.nav.window(h - 13)
        for i in range(top, end):
            r = rows[i]
            out.append(f"{'>' if i == self.nav.sel else ' '} {rem_class(r, today).upper():<8} {r['due']}  {str(r.get('t', ''))[:44]}" + ("" if r.get("rep", "none") == "none" else f"  [{r['rep']}]"))
        tasks = open_tasks(self.host)
        due = task_due(tasks, today)
        out += ["", " Tasks (from the shared tasks folder, due within 7 days):"]
        out += [f"   {c.upper():<8} {d}  {n[:44]}" for c, d, n in due[:8]] if due else [("   none due" if tasks else "   " + TASKS_GONE)]
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        rows = self.rows()
        cur = rows[self.nav.sel] if rows else None
        if self.nav.key(k):
            return None
        if k == "a" and len(self.d["items"]) < 500:
            return ("push", Prompt("New reminder", "What?", "", self.ask_date))
        if k == "/":
            return ("push", Prompt("Search", "Search for (empty clears):", self.query, lambda v: setattr(self, "query", clean(v, 60))))
        if k == "v": self.show_done = not self.show_done
        elif k == "escape":
            if self.query: self.query = ""
            else: return ("quit",)
        elif cur and k == " ": rem_done(cur, self.today()); self.save()
        elif cur and k in ("s", "S"): rem_snooze(cur, self.today(), 1 if k == "s" else 7); self.save()
        elif cur and k == "d": return ("push", Confirm("Delete this reminder?", lambda: (self.d["items"].remove(cur), self.save())[0]))

    def ask_date(self, text):
        t = clean(text, MAX_TEXT)
        return ("push", Prompt("When", "Date (YYYY-MM-DD, today, tomorrow, +N):", "today", lambda v: self.ask_rep(t, v))) if t else None

    def ask_rep(self, t, v):
        due = parse_date(v, self.today())
        if not due:
            self.msg = "date not understood"
            return None
        return ("push", Prompt("Repeat", "Repeat (none/daily/weekly/weekdays/monthly):", "none", lambda r: self.create(t, due, r)))

    def create(self, t, due, rep):
        rep = clean(rep, 12).lower() or "none"
        if rep not in REPEATS:
            self.msg = "repeat must be one of: " + ", ".join(REPEATS)
            return
        self.d["items"].append({"id": self.next_id("items"), "t": t, "due": due, "rep": rep, "dom": to_date(due).day, "done": False})
        self.save()


# -------------------------------------------------------- Sticky Notes ----
COLORS = ("yellow", "pink", "blue", "green", "white")


def note_order(notes: list) -> list:
    return sorted(notes, key=lambda n: (not n.get("p"), -int(n.get("id", 0))))


def box(n: dict, cw: int, selected: bool = False) -> list:
    """One note as 5 lines of exactly cw characters: a header (colour, pin), 3 text lines, a footer."""
    cw = max(10, cw)
    inner, fill = cw - 2, "=" if selected else "-"
    head = (("*" if n.get("p") else "") + str(n.get("c", "yellow")))[:inner].ljust(inner, fill)
    body = wrap(str(n.get("t", "")), inner)
    if len(body) > 3:
        body = body[:3]
        body[2] = body[2][:inner - 1] + "~"
    body += [""] * (3 - len(body))
    return ["+" + head + "+", *("|" + b[:inner].ljust(inner) + "|" for b in body), "+" + fill * inner + "+"]


def grid(notes: list, w: int, sel: int, first_row: int = 0, rows: int = 99) -> tuple:
    """-> (lines, columns). Notes are laid out in columns of equal width."""
    cols = max(1, min(4, (w - 2) // 22))
    cw = (w - 2) // cols
    out = []
    for r in range(first_row, min(first_row + rows, (len(notes) + cols - 1) // cols)):
        boxes = [box(notes[i], cw, i == sel) for i in range(r * cols, min(len(notes), r * cols + cols))]
        out += ["".join(b[j] for b in boxes) for j in range(5)]
    return out, cols


class Sticky(_App):
    KEY = "notes"

    def __init__(self, host, entry=None):
        super().__init__(host, {"items": []})
        self.title = "Sticky Notes"
        self.d["items"] = lst(self.d, "items", 200)
        self.help = "a quick add  e edit  c colour  p pin  d delete  arrows move"
        self.cols = 1

    def notes(self): return note_order(self.d["items"])

    def render(self, w, h):
        notes = self.notes()
        self.nav.resize(len(notes))
        _, self.cols = grid([], w, 0)
        per = max(1, (h - 3) // 5)
        row = self.nav.sel // self.cols
        first = max(0, row - per + 1) if row >= per else 0
        out, _ = grid(notes, w, self.nav.sel, first, per)
        if not notes:
            out = ["", "  No notes yet. Press a, type a few words, Enter."]
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        notes = self.notes()
        cur = notes[self.nav.sel] if notes else None
        step = {"left": -1, "right": 1, "up": -self.cols, "down": self.cols}.get(k)
        if step is not None:
            self.nav.sel = max(0, min(len(notes) - 1, self.nav.sel + step))
        elif k == "a" and len(self.d["items"]) < 200:
            return ("push", Prompt("New note", "Note (max 140 characters):", "", self.add))
        elif k == "escape": return ("quit",)
        elif cur and k == "e": return ("push", Prompt("Edit note", "Note:", cur.get("t", ""), lambda v: self.edit(cur, v)))
        elif cur and k == "c": cur["c"] = COLORS[(COLORS.index(cur["c"]) + 1) % len(COLORS)] if cur.get("c") in COLORS else COLORS[0]; self.save()
        elif cur and k == "p": cur["p"] = not cur.get("p"); self.save()
        elif cur and k == "d": return ("push", Confirm("Delete this note?", lambda: (self.d["items"].remove(cur), self.save())[0]))

    def add(self, text):
        t = clean(text, 140)
        if t and len(self.d["items"]) < 200:
            self.d["items"].append({"id": self.next_id("items"), "t": t, "c": COLORS[self.next_id("items") % len(COLORS)], "p": False})
            self.save()

    def edit(self, n, text):
        t = clean(text, 140)
        if t:
            n["t"] = t
            self.save()


# ------------------------------------------------------------- Journal ----
MOODS = ("great", "good", "ok", "low", "bad")


def j_search(entries: list, q: str) -> list:
    q = q.lower()
    return [e for e in entries if not q or q in (str(e.get("x", "")) + " " + str(e.get("m", "")) + " " + str(e.get("d", ""))).lower()]


def j_sorted(entries: list) -> list:
    return sorted(entries, key=lambda e: (str(e.get("d", "")), str(e.get("tm", "")), int(e.get("id", 0))), reverse=True)


def on_this_day(entries: list, today: str) -> list:
    """Entries written on the same month and day in an earlier year (a 29 Feb entry only matches 29 Feb)."""
    return [e for e in j_sorted(entries) if to_date(e.get("d")) and str(e["d"])[5:] == today[5:] and str(e["d"])[:4] < today[:4]]


def j_export(entries: list) -> str:
    out, last = ["# Journal", ""], None
    for e in reversed(j_sorted(entries)):
        if e.get("d") != last:
            out += [f"## {e.get('d')}", ""]
            last = e.get("d")
        out += [f"### {e.get('tm', '')}" + (f" - {e['m']}" if e.get("m") else ""), "", str(e.get("x", "")), ""]
    return "\n".join(out)


def j_parse_head(s: str, today: str):
    """'good 2026-11-05' -> (mood, date); tokens in any order, both optional. None if a token is not understood."""
    mood, day = "", today
    for tok in clean(s, 40).lower().split():
        if tok in MOODS: mood = tok
        elif to_date(tok) and tok <= today: day = tok
        else: return None
    return mood, day


class Journal(_App):
    KEY = "journal"

    def __init__(self, host, entry=None):
        super().__init__(host, {"items": []})
        self.title, self.query = "Journal", ""
        self.d["items"] = [e for e in lst(self.d, "items", 2000) if to_date(e.get("d"))]
        self.help = "a new entry  Enter read  e edit  d delete  / search  o on this day  s streak  x export Markdown"

    def rows(self): return j_sorted(j_search(self.d["items"], self.query))

    def render(self, w, h):
        rows = self.rows()
        self.nav.resize(len(rows))
        cur, best = streaks([e["d"] for e in self.d["items"]], self.today())
        out = [f" {len(self.d['items'])} entries   writing streak {cur} day(s), best {best}" + (f"   search='{self.query}'" if self.query else ""), ""]
        if not rows: out.append("  Press a to write the first entry.")
        top, end = self.nav.window(h - 5)
        for i in range(top, end):
            e = rows[i]
            out.append(f"{'>' if i == self.nav.sel else ' '} {e['d']} {str(e.get('tm', '')):<5} {str(e.get('m', '')):<5} {str(e.get('x', '')).splitlines()[0][:40] if e.get('x') else ''}")
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        rows = self.rows()
        cur = rows[self.nav.sel] if rows else None
        if self.nav.key(k): return None
        if k == "a" and len(self.d["items"]) < 2000:
            return ("push", Prompt("New entry", "Mood (great/good/ok/low/bad) and optional date YYYY-MM-DD, or empty:", "", self.start))
        if k == "/": return ("push", Prompt("Search", "Search for (empty clears):", self.query, lambda v: setattr(self, "query", clean(v, 60))))
        if k == "escape":
            if self.query: self.query = ""
            else: return ("quit",)
        elif k == "s":
            days = [e["d"] for e in self.d["items"]]
            c, b = streaks(days, self.today())
            return ("push", TextView("Streak", [f"Current streak: {c} day(s)", f"Longest streak: {b} day(s)", f"Days written in the last 7: {last_days(days, self.today())}/7", f"Entries: {len(days)} on {len(set(days))} day(s)"]))
        elif k == "o":
            ot = on_this_day(self.d["items"], self.today())
            lines = [f"{e['d']}  {e.get('m', '')}" for e in ot for _ in [0]] and [x for e in ot for x in (f"{e['d']} {e.get('tm', '')} {e.get('m', '')}", *wrap(str(e.get('x', '')), 70), "")]
            return ("push", TextView("On this day", lines or ["No entries from earlier years on this date."]))
        elif k == "x":
            md = j_export(self.d["items"])
            self.host.put("journal.md", md)
            return ("push", TextView("Export (Markdown, also saved as vault key journal.md)", md.split("\n")))
        elif cur and k == "enter": return ("push", TextView(cur["d"], wrap(str(cur.get("x", "")), 74)))
        elif cur and k == "e": return ("push", self.editor(cur))
        elif cur and k == "d": return ("push", Confirm("Delete this entry?", lambda: (self.d["items"].remove(cur), self.save())[0]))

    def start(self, text):
        p = j_parse_head(text, self.today())
        if p is None:
            self.msg = "use a mood word and/or a date YYYY-MM-DD (not in the future)"
            return None
        e = {"id": self.next_id("items"), "d": p[1], "tm": time.strftime("%H:%M", time.localtime(self.now())), "m": p[0], "x": ""}
        return ("push", self.editor(e))

    def editor(self, e):
        def on_save(text):
            x = clean(text, MAX_LONG, keep_nl=True)
            if not x: return
            e["x"] = x
            if e not in self.d["items"] and len(self.d["items"]) < 2000: self.d["items"].append(e)
            self.save()
        return Editor("Entry " + e["d"], str(e.get("x", "")), on_save=on_save)


# ------------------------------------------------------------- Habits -----
def h_toggle(h: dict, day: str) -> bool:
    """Check or un-check one day. Bounded to 800 stored days. False if `day` is not a real date."""
    if not to_date(day): return False
    days = [d for d in h.get("days", []) if to_date(d)]
    days = [d for d in days if d != day] if day in days else sorted({*days, day})[-800:]
    h["days"] = days
    return True


def h_line(h: dict, today: str) -> str:
    cur, best = streaks(h.get("days", []), today)
    pct = round(100 * last_days(h.get("days", []), today) / 7)
    return f"[{'x' if today in h.get('days', []) else ' '}] {str(h.get('n', ''))[:22]:<22} streak {cur:>3}  best {best:>3}  week {pct:>3}% {bar(pct, 100, 10)}"


class Habits(_App):
    KEY = "habits"

    def __init__(self, host, entry=None):
        super().__init__(host, {"items": []})
        self.title = "Habit Tracker"
        self.d["items"] = lst(self.d, "items", 50)
        self.help = "a add habit  space check today  y check yesterday  d delete  s weekly summary"

    def render(self, w, h):
        self.nav.resize(len(self.d["items"]))
        t = self.today()
        out = [f" {t}   today's check-offs: {sum(1 for x in self.d['items'] if t in x.get('days', []))}/{len(self.d['items'])}", ""]
        if not self.d["items"]: out.append("  Press a to add a habit.")
        out += [f"{'>' if i == self.nav.sel else ' '} {h_line(x, t)}" for i, x in enumerate(self.d["items"][:h - 4])]
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        cur = self.d["items"][self.nav.sel] if self.d["items"] else None
        if self.nav.key(k): return None
        if k == "a" and len(self.d["items"]) < 50: return ("push", Prompt("New habit", "Habit name:", "", self.add))
        if k == "escape": return ("quit",)
        if cur and k in (" ", "y"):
            day = self.today() if k == " " else (to_date(self.today()) - dt.timedelta(days=1)).isoformat()
            h_toggle(cur, day); self.save()
        elif cur and k == "d": return ("push", Confirm("Delete this habit and its history?", lambda: (self.d["items"].remove(cur), self.save())[0]))
        elif k == "s": return ("push", TextView("Weekly summary", self.summary()))

    def add(self, text):
        n = clean(text, 40)
        if n and len(self.d["items"]) < 50:
            self.d["items"].append({"id": self.next_id("items"), "n": n, "days": []})
            self.save()

    def summary(self) -> list:
        t, out = self.today(), []
        for x in self.d["items"]:
            cells = "".join("#" if (to_date(t) - dt.timedelta(days=6 - i)).isoformat() in x.get("days", []) else "." for i in range(7))
            out.append(f"{str(x.get('n', ''))[:22]:<22} {cells}  {last_days(x.get('days', []), t)}/7")
        tot = sum(last_days(x.get("days", []), t) for x in self.d["items"])
        n = 7 * len(self.d["items"])
        return [f"Last 7 days, oldest to today ({t})", "", *out, "", f"Overall completion: {round(100 * tot / n) if n else 0}%  {bar(tot, n, 30)}"]


# --------------------------------------------------------------- Focus ----
WORK, SHORT, LONG, EVERY, MAX_SESSION = 25 * 60, 5 * 60, 15 * 60, 4, 12 * 3600


def pomo_plan(work=WORK, short=SHORT, long=LONG, every=EVERY) -> list:
    """One full cycle: work, short break, ... and a long break after the `every`-th work phase."""
    return [p for i in range(1, every + 1) for p in (("work", work), ("long break" if i == every else "break", long if i == every else short))]


def pomo_at(elapsed: float, **cfg) -> dict:
    """Where a session is `elapsed` seconds after it started: phase, seconds left in it, work phases finished,
    and seconds of focused (work-phase) time so far."""
    plan = pomo_plan(**cfg)
    cyc = sum(s for _p, s in plan)
    elapsed = max(0.0, min(float(elapsed), MAX_SESSION))
    full, rest = divmod(elapsed, cyc)
    works = sum(1 for p, _s in plan if p == "work")
    wsecs = [s for p, s in plan if p == "work"][0]
    done, focused = int(full) * works, int(full) * works * wsecs
    for p, s in plan:
        if rest < s:
            if p == "work": focused += rest
            return {"phase": p, "left": s - rest, "pomodoros": done, "focused": focused}
        rest -= s
        if p == "work": done, focused = done + 1, focused + s
    return {"phase": plan[0][0], "left": plan[0][1], "pomodoros": done, "focused": focused}


def sum_days(rows: dict, today: str, n: int) -> int:
    t = to_date(today)
    if not t: return 0
    return sum(int(rows.get((t - dt.timedelta(days=i)).isoformat(), 0)) for i in range(n))


def per_task(log: list) -> dict:
    """Focused minutes per task title."""
    out: dict = {}
    for e in log:
        t, m = e.get("task"), e.get("min", 0)
        if isinstance(t, str) and t and isinstance(m, int):
            out[t] = out.get(t, 0) + m
    return out


def day_sums(entries: list, key: str) -> dict:
    out: dict = {}
    for e in entries:
        if to_date(e.get("d")) and isinstance(e.get(key, 0), (int, float)):
            out[e["d"]] = out.get(e["d"], 0) + e.get(key, 0)
    return out


class Focus(_App):
    KEY = "focus"

    def __init__(self, host, entry=None):
        super().__init__(host, {"log": [], "dist": [], "screen": {}, "run": None, "task": ""})
        self.title = "Focus Manager"
        self.d["log"], self.d["dist"] = lst(self.d, "log", 1000), lst(self.d, "dist", 1000)
        if not isinstance(self.d["run"], (int, float)): self.d["run"] = None
        self.help = "s start/stop session  x log a distraction  m report screen time (self-reported)  k pick a task  t totals"

    def stop(self) -> str:
        now = self.now()
        info = pomo_at(now - self.d["run"])
        n = sum(1 for e in self.d["dist"] if e.get("at", 0) >= self.d["run"])
        self.d["log"].append({"d": day_of(now), "min": int(info["focused"] // 60), "pomo": info["pomodoros"], "dist": n, "task": clean(self.d.get("task", ""), 60)})
        del self.d["log"][:-1000]
        self.d["run"] = None
        self.save()
        return f"logged {int(info['focused'] // 60)} focused minute(s), {info['pomodoros']} pomodoro(s)"

    def totals(self) -> list:
        t = self.today()
        mins, pomo = day_sums(self.d["log"], "min"), day_sums(self.d["log"], "pomo")
        dist = {}
        for e in self.d["dist"]:
            d = day_of(e.get("at", 0))
            dist[d] = dist.get(d, 0) + 1
        scr = {k: v for k, v in self.d["screen"].items() if isinstance(v, int)}
        return [f"Today:     focus {sum_days(mins, t, 1)} min, {sum_days(pomo, t, 1)} pomodoro(s), {sum_days(dist, t, 1)} distraction(s), screen time {sum_days(scr, t, 1)} min",
                f"7 days:    focus {sum_days(mins, t, 7)} min, {sum_days(pomo, t, 7)} pomodoro(s), {sum_days(dist, t, 7)} distraction(s), screen time {sum_days(scr, t, 7)} min",
                *[f"Task {n[:40]:<40} {m} min" for n, m in sorted(per_task(self.d["log"]).items(), key=lambda x: -x[1])[:10]],
                "", "Screen time is what you typed in: KOS apps cannot measure other apps or your device."]

    def render(self, w, h):
        out = [""]
        if self.d["run"] is None:
            out.append("  No session running. Press s to start (25 min work, 5 min break, 15 min break after 4 rounds).")
        else:
            i = pomo_at(self.now() - self.d["run"])
            out.append(f"  {i['phase'].upper()}  {fmt_hms(i['left'])} left   pomodoros done {i['pomodoros']}   focused {int(i['focused'] // 60)} min")
            out.append("  The phase is worked out from the start time whenever you look; nothing beeps.")
        out.insert(1, f"  Task: {self.d.get('task') or '(none picked, press k)'}")
        if not open_tasks(self.host): out.append("  " + TASKS_GONE)
        out += ["", *("  " + x for x in self.totals())]
        return (out + self.tail())[:h]

    def key(self, k):
        self.msg = ""
        if k == "s":
            if self.d["run"] is None:
                self.d["run"] = self.now(); self.save()
            else:
                self.msg = self.stop()
        elif k == "x":
            return ("push", Prompt("Distraction", "What distracted you? (optional)", "", self.distract))
        elif k == "m":
            return ("push", Prompt("Screen time", "Minutes of screen time today (self-reported):", "", self.screen_time))
        elif k == "k":
            ts = open_tasks(self.host)[:15]
            return ("push", Menu("Pick a task", [("(no task)", lambda: self.pick("")), *((n, lambda n=n: self.pick(n)) for n, _d in ts)]))
        elif k == "t":
            return ("push", TextView("Totals", self.totals()))
        elif k == "escape":
            return ("quit",)

    def pick(self, name):
        self.d["task"] = name
        self.save()
        return ("pop", None)

    def distract(self, text):
        if len(self.d["dist"]) >= 1000: del self.d["dist"][:100]
        self.d["dist"].append({"at": self.now(), "t": clean(text, 80)})
        self.save()

    def screen_time(self, text):
        t = text.strip()
        if not re.fullmatch(r"\d{1,4}", t) or int(t) > 1440:
            self.msg = "enter minutes, 0-1440"
            return
        self.d["screen"][self.today()] = int(t)
        for old in sorted(self.d["screen"])[:-60]: del self.d["screen"][old]
        self.save()


# ------------------------------------------------------------- entries ----
ENTRIES = [
    app("Clock", lambda host, e: Clock(host, e), "partial",
        "Alarms, stopwatch with laps, countdown timers and a world clock, stored as timestamps so they stay correct between key presses and restarts. "
        "KOS apps have no background tasks and no audio: nothing rings or notifies; an alarm or timer is shown as DUE only when this app is open. "
        "World clock uses the system zoneinfo data when readable (daylight saving applied), otherwise a built-in table of fixed standard-time offsets (no daylight saving)."),
    app("Reminders", lambda host, e: Reminders(host, e), "partial",
        "Due list (overdue / today / upcoming), repeat rules (daily, weekly, weekdays, monthly), snooze, done and search. "
        "No notifications: KOS apps cannot run in the background, so reminders are only shown when you open the app. Dates only, no time of day. Also lists due tasks from the shared tasks folder once it is granted to this app.", uses=["tasks"]),
    app("Sticky Notes", lambda host, e: Sticky(host, e), "full",
        "Short notes (140 characters) in a grid, with quick add, pin, edit and a colour label (shown as a word, the text screen has no real colours)."),
    app("Journal", lambda host, e: Journal(host, e), "full",
        "Dated entries (several per day, backdating allowed), mood tag, search, writing streak, entries from this date in earlier years, and export to one Markdown text (also saved to the vault as journal.md)."),
    app("Habit Tracker", lambda host, e: Habits(host, e), "full",
        "Habits with daily check-off (today or yesterday), current and longest streak, 7-day completion percentage and a bar summary."),
    app("Focus Manager", lambda host, e: Focus(host, e), "partial",
        "Pomodoro sessions (25/5, long break after 4), self-logged distractions and daily/weekly totals. Screen time and wellbeing numbers are SELF-REPORTED: "
        "an app cannot measure other apps or the device. Phases are computed from the start time when you look; there is no sound or background timer. A session can be tied to a task from the shared tasks folder (once granted) and time per task is totalled.", uses=["tasks"]),
]
