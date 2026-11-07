"""Tests for kos/office/pack_time.py: exact values for the pure logic, hostile input, and FakeHost runs."""

import calendar
import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_time as P  # noqa: E402
from kos.office.packkit import shared_add  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def ts(y, mo, d, h=0, mi=0, s=0):
    return calendar.timegm((y, mo, d, h, mi, s))


def drive(make, keys, host=None, now=None):
    host = host or FakeHost(keys)
    host.script = [c for k in (keys if not isinstance(keys, str) else FakeHost.tokens(keys)) for c in FakeHost.expand(k)]
    scr = make(host)
    if now: scr.now = lambda: now
    run(host, scr)
    return host, scr


class TestHelpers(unittest.TestCase):
    def test_parse_dur(self):
        for s, n in [("25", 1500), ("90s", 90), ("5m", 300), ("1h30m", 5400), ("1:30", 90), (" 2m30s ", 150)]:
            self.assertEqual(P.parse_dur(s), n, s)
        for s in ["", "0", "abc", "-5", "99999", "1:75", "25h", None, 5, "5\x00"]:
            self.assertIsNone(P.parse_dur(s), s)

    def test_parse_date_and_hm(self):
        self.assertEqual(P.parse_date("tomorrow", "2026-11-07"), "2026-11-08")
        self.assertEqual(P.parse_date("+30", "2026-11-07"), "2026-12-07")
        self.assertEqual(P.parse_date("", "2026-11-07"), "2026-11-07")
        self.assertEqual(P.parse_date("2026-02-30", "2026-11-07"), None)
        self.assertIsNone(P.parse_date("soon", "2026-11-07"))
        self.assertEqual(P.parse_hm("7:05"), (7, 5))
        for bad in ["24:00", "7:60", "7", "ab:cd", None]:
            self.assertIsNone(P.parse_hm(bad))

    def test_clean_bounds_and_control_chars(self):
        self.assertEqual(P.clean("a\x00b\x1b[31mc\n", 50), "ab[31mc")
        self.assertEqual(len(P.clean("x" * 10 ** 6, 200)), 200)
        self.assertEqual(P.clean(123), "")
        self.assertEqual(P.clean("a\nb", 10, keep_nl=True), "a\nb")

    def test_fmt_hms(self):
        self.assertEqual(P.fmt_hms(3725), "1:02:05")
        self.assertEqual(P.fmt_hms(-61), "-0:01:01")
        self.assertEqual(P.fmt_hms(0), "0:00:00")

    def test_streaks(self):
        days = ["2026-11-01", "2026-11-02", "2026-11-03", "2026-11-05", "2026-11-06", "2026-11-07", "2026-11-07", "junk"]
        self.assertEqual(P.streaks(days, "2026-11-07"), (3, 3))
        self.assertEqual(P.streaks(days, "2026-11-08"), (3, 3))      # ended yesterday: still alive
        self.assertEqual(P.streaks(days, "2026-11-09"), (0, 3))      # a gap of one full day breaks it
        self.assertEqual(P.streaks([], "2026-11-07"), (0, 0))
        self.assertEqual(P.streaks(["2026-12-01"], "2026-11-07"), (0, 0))   # future days ignored
        self.assertEqual(P.last_days(days, "2026-11-07"), 6)           # 11-01..11-07 are all inside the 7 days
        self.assertEqual(P.last_days(days, "2026-11-07", 3), 3)


class TestClock(unittest.TestCase):
    def test_alarm_next(self):
        now = ts(2026, 1, 1, 10, 0)
        self.assertEqual(P.alarm_next((9, 0), now, 0), ts(2026, 1, 2, 9, 0))
        self.assertEqual(P.alarm_next((10, 30), now, 0), ts(2026, 1, 1, 10, 30))
        self.assertEqual(P.alarm_next((10, 0), now, 0), ts(2026, 1, 2, 10, 0))   # strictly after now
        # a clock that is 2 h ahead of UTC: 13:00 local is the same instant as 11:00 UTC
        self.assertEqual(P.alarm_next((13, 0), now, 7200), ts(2026, 1, 1, 11, 0))
        self.assertEqual(P.alarm_next((12, 0), now, 7200), ts(2026, 1, 2, 10, 0))     # 12:00 local is now: next is tomorrow
        self.assertEqual(P.alarm_next((11, 0), now, 7200), ts(2026, 1, 2, 9, 0))

    def test_stopwatch_and_laps(self):
        sw = {"run": None, "acc": 0, "laps": []}
        self.assertFalse(P.sw_lap(sw, 100))
        P.sw_toggle(sw, 100)
        self.assertEqual(P.sw_elapsed(sw, 112.5), 12.5)
        P.sw_lap(sw, 110); P.sw_lap(sw, 125)
        P.sw_toggle(sw, 130)
        self.assertEqual(P.sw_elapsed(sw, 999), 30)                 # stopped: frozen
        P.sw_toggle(sw, 200)
        self.assertEqual(P.sw_elapsed(sw, 210), 40)                 # resumes from 30
        self.assertEqual(P.lap_rows(sw["laps"]), [(1, 10, 10), (2, 15, 25)])
        for _ in range(300): P.sw_lap(sw, 300)
        self.assertEqual(len(sw["laps"]), 200)
        self.assertEqual(P.sw_elapsed({"run": 100, "acc": 0}, 50), 0)   # clock went backwards: never negative

    def test_when(self):
        self.assertEqual(P.when(100, 40), "in 0:01:00")
        self.assertEqual(P.when(100, 160), "DUE 0:01:00 ago")

    def test_world_clock_both_sources(self):
        now = ts(2026, 1, 15, 12, 0)
        t, mins, src = P.zone_time("Tokyo", now, use_zoneinfo=False)
        self.assertEqual(( t.hour, mins, src), (21, 540, "fixed"))
        t, mins, src = P.zone_time("Delhi", now, use_zoneinfo=False)
        self.assertEqual((t.hour, t.minute, mins), (17, 30, 330))
        t, mins, src = P.zone_time("New York", now)
        if src == "zoneinfo":
            self.assertEqual((t.hour, mins), (7, -300))
            self.assertEqual(P.zone_time("New York", ts(2026, 7, 15, 12, 0))[1], -240)     # daylight saving applied
        self.assertEqual(P.zone_time("New York", ts(2026, 7, 15, 12, 0), False)[1], -300)   # fixed table has none
        self.assertIsNone(P.zone_time("Atlantis", now))
        self.assertEqual(P.find_city("tok"), "Tokyo")
        self.assertEqual(P.find_city("los angeles"), "Los Angeles")
        self.assertIsNone(P.find_city("zzz"))
        self.assertIsNone(P.find_city(""))

    def test_screen_runs_and_saves(self):
        now = ts(2026, 3, 3, 8, 0)
        host, scr = drive(P.Clock, "a07:30 wake<enter>2 l<enter>3a5 tea<enter>1", now=now)
        self.assertIn("wake", host.text)
        self.assertEqual(len(scr.d["alarms"]), 1)
        self.assertEqual(scr.d["timers"][0]["secs"], 300)
        self.assertIn("clock", host.data)
        host2, scr2 = drive(P.Clock, "3", host=FakeHost(data=host.data), now=now + 400)
        self.assertIn("DONE", host2.text)
        self.assertIn("Nothing rings", host2.text)

    def test_stopwatch_screen(self):
        host, scr = drive(P.Clock, "2 l r<escape>", now=1000.0)
        self.assertEqual(scr.d["sw"]["laps"], [])
        host, scr = drive(P.Clock, "2 ", now=1000.0)
        self.assertIsNotNone(scr.d["sw"]["run"])

    def test_bad_input_is_refused(self):
        host, scr = drive(P.Clock, "a99:99<enter>", now=1000.0)
        self.assertEqual(scr.d["alarms"], [])
        self.assertIn("not understood", host.text)
        host, scr = drive(P.Clock, "3a0<enter>3a" + "9" * 300 + "<enter>", now=1000.0)
        self.assertEqual(scr.d["timers"], [])

    def test_corrupt_vault_data_does_not_crash(self):
        host = FakeHost("1234", data={"clock": '{"alarms": [1, "x", {"hm": 5}], "sw": 7, "zones": ["Nope", "Tokyo"]}'})
        drive(P.Clock, "1234", host=host, now=1000.0)
        self.assertIn("Clock", host.frames[-1][0])


class TestReminders(unittest.TestCase):
    def test_next_due(self):
        self.assertEqual(P.next_due("2026-11-07", "daily"), "2026-11-08")
        self.assertEqual(P.next_due("2026-11-07", "weekly"), "2026-11-14")
        self.assertEqual(P.next_due("2026-11-06", "weekdays"), "2026-11-09")      # Fri -> Mon
        self.assertEqual(P.next_due("2026-11-09", "weekdays"), "2026-11-10")
        self.assertEqual(P.next_due("2026-01-31", "monthly", 31), "2026-02-28")
        self.assertEqual(P.next_due("2026-02-28", "monthly", 31), "2026-03-31")   # original day is remembered
        self.assertEqual(P.next_due("2026-12-15", "monthly"), "2027-01-15")
        self.assertIsNone(P.next_due("2026-11-07", "none"))
        self.assertIsNone(P.next_due("garbage", "daily"))

    def test_done_snooze_classify(self):
        r = {"due": "2026-11-01", "rep": "none", "t": "x"}
        self.assertEqual(P.rem_class(r, "2026-11-07"), "overdue")
        P.rem_done(r, "2026-11-07")
        self.assertTrue(r["done"]); self.assertEqual(P.rem_class(r, "2026-11-07"), "done")
        r = {"due": "2026-11-01", "rep": "daily", "t": "x", "dom": 1}
        P.rem_done(r, "2026-11-07")
        self.assertEqual((r["due"], r.get("done")), ("2026-11-08", None))       # skips the missed days
        r = {"due": "2026-11-10", "rep": "weekly", "dom": 10}
        P.rem_done(r, "2026-11-07")
        self.assertEqual(r["due"], "2026-11-17")
        r = {"due": "2026-11-01", "rep": "none", "done": True}
        P.rem_snooze(r, "2026-11-07")
        self.assertEqual((r["due"], r["done"]), ("2026-11-08", False))
        P.rem_snooze(r, "2026-11-07", 7)                                        # due 11-08 (future): from the later date
        self.assertEqual(r["due"], "2026-11-15")
        self.assertEqual(P.rem_class({"due": "2026-11-07"}, "2026-11-07"), "today")
        self.assertEqual(P.rem_class({"due": "2026-11-08"}, "2026-11-07"), "upcoming")

    def test_sort_and_search(self):
        rems = [{"t": "c", "due": "2026-11-09"}, {"t": "b", "due": "2026-11-07"}, {"t": "a", "due": "2026-11-01"},
                {"t": "Dentist", "due": "2026-11-20"}, {"t": "old", "due": "2026-10-01", "done": True}]
        self.assertEqual([r["t"] for r in P.rem_sorted(rems, "2026-11-07")], ["a", "b", "c", "Dentist"])
        self.assertEqual([r["t"] for r in P.rem_sorted(rems, "2026-11-07", show_done=True)][-1], "old")
        self.assertEqual([r["t"] for r in P.rem_sorted(rems, "2026-11-07", "dent")], ["Dentist"])

    def test_task_due(self):
        tasks = [("late", "2026-11-01"), ("now", "2026-11-07"), ("soon", "2026-11-10"), ("far", "2026-12-25"), ("nodate", "")]
        self.assertEqual(P.task_due(tasks, "2026-11-07"), [("overdue", "2026-11-01", "late"), ("today", "2026-11-07", "now"), ("upcoming", "2026-11-10", "soon")])

    def test_screen_flow(self):
        host, scr = drive(P.Reminders, "aPay rent<enter>+1<enter>monthly<enter>", now=ts(2026, 11, 7, 9))
        self.assertEqual(scr.d["items"][0]["rep"], "monthly")
        self.assertEqual(scr.d["items"][0]["due"], "2026-11-08")
        self.assertIn("Pay rent", host.text)
        host, scr = drive(P.Reminders, "aX<enter><enter>bogus<enter>", now=ts(2026, 11, 7, 9))
        self.assertEqual(scr.d["items"], [])
        self.assertIn("repeat must be", host.text)
        host, scr = drive(P.Reminders, "aX<enter>nope<enter>", now=ts(2026, 11, 7, 9))
        self.assertIn("date not understood", host.text)

    def test_screen_done_snooze_search(self):
        now = ts(2026, 11, 7, 9)
        host, scr = drive(P.Reminders, "aone<enter><enter>daily<enter> ", now=now)
        self.assertEqual(scr.d["items"][0]["due"], "2026-11-08")
        host, scr = drive(P.Reminders, "aone<enter><enter><enter>s", now=now)
        self.assertEqual(scr.d["items"][0]["due"], "2026-11-08")                  # empty date = today, snoozed one day
        host, scr = drive(P.Reminders, "aone<enter><enter><enter>/zzz<enter>", now=now)
        self.assertEqual(scr.rows(), [])

    def test_tasks_folder_two_hosts(self):
        shared = {}
        owner, user = FakeHost(), FakeHost()
        owner.spaces = user.spaces = shared
        self.assertTrue(shared_add(owner, "tasks", {"title": "Write report", "status": "open", "due": "2026-11-06"}))
        shared_add(owner, "tasks", {"title": "Finished", "status": "done", "due": "2026-11-06"})
        shared_add(owner, "tasks", {"title": "Plan trip", "status": "todo", "due": "2026-11-09"})
        shared_add(owner, "tasks", {"title": "Odd", "due": 5})
        self.assertEqual(P.open_tasks(user), [("Write report", "2026-11-06"), ("Plan trip", "2026-11-09"), ("Odd", "")])
        host, scr = drive(P.Reminders, "", host=user, now=ts(2026, 11, 7, 9))
        self.assertIn("OVERDUE  2026-11-06  Write report", host.text)
        self.assertIn("UPCOMING 2026-11-09  Plan trip", host.text)
        self.assertNotIn("Finished", host.text)

    def test_tasks_folder_missing_is_said(self):
        host, _ = drive(P.Reminders, "", now=ts(2026, 11, 7, 9))
        self.assertIn("nothing shared with this app", host.text)
        host, _ = drive(P.Focus, "", now=ts(2026, 11, 7, 9))
        self.assertIn("nothing shared with this app", host.text)


class TestSticky(unittest.TestCase):
    def test_box_exact(self):
        self.assertEqual(P.box({"t": "buy milk", "c": "pink", "p": True}, 14), [
            "+*pink-------+", "|buy milk    |", "|            |", "|            |", "+------------+"])
        b = P.box({"t": "word " * 40, "c": "blue"}, 12, selected=True)
        self.assertEqual(len(b), 5)
        self.assertTrue(all(len(x) == 12 for x in b))
        self.assertTrue(b[3].rstrip("|").rstrip().endswith("~"))
        self.assertEqual(b[0][0], "+")
        self.assertTrue(b[4].startswith("+==="))

    def test_order_and_grid(self):
        notes = [{"id": 1, "t": "a", "c": "yellow"}, {"id": 2, "t": "b", "c": "pink", "p": True}, {"id": 3, "t": "c", "c": "blue"}]
        self.assertEqual([n["t"] for n in P.note_order(notes)], ["b", "c", "a"])
        lines, cols = P.grid(P.note_order(notes), 80, 0)
        self.assertEqual((len(lines), cols), (5, 3))
        self.assertTrue(all(len(l) == 78 for l in lines))
        lines, cols = P.grid(notes, 30, 0)
        self.assertEqual((len(lines), cols), (15, 1))

    def test_screen(self):
        host, scr = drive(P.Sticky, "aHello world<enter>aSecond\x07<enter>pc", now=1.0)
        texts = [n["t"] for n in scr.d["items"]]
        self.assertEqual(texts, ["Hello world", "Second"])
        self.assertIn("Hello world", host.text)
        self.assertIn("notes", host.data)
        host, scr = drive(P.Sticky, "a" + "x" * 500 + "<enter>", now=1.0)
        self.assertEqual(len(scr.d["items"][0]["t"]), 140)
        host, scr = drive(P.Sticky, "a<enter>", now=1.0)
        self.assertEqual(scr.d["items"], [])


class TestJournal(unittest.TestCase):
    E = [{"id": 1, "d": "2025-11-07", "tm": "08:00", "m": "good", "x": "a year ago"},
         {"id": 2, "d": "2024-11-07", "tm": "09:00", "m": "", "x": "two years ago"},
         {"id": 3, "d": "2026-11-07", "tm": "07:00", "m": "ok", "x": "today one"},
         {"id": 4, "d": "2026-11-07", "tm": "21:00", "m": "great", "x": "today two"},
         {"id": 5, "d": "2026-11-06", "tm": "10:00", "m": "low", "x": "Dentist visit"}]

    def test_on_this_day(self):
        self.assertEqual([e["id"] for e in P.on_this_day(self.E, "2026-11-07")], [1, 2])
        self.assertEqual(P.on_this_day(self.E, "2026-03-01"), [])

    def test_search_and_sort(self):
        self.assertEqual([e["id"] for e in P.j_search(self.E, "dentist")], [5])
        self.assertEqual([e["id"] for e in P.j_search(self.E, "GREAT")], [4])
        self.assertEqual([e["id"] for e in P.j_sorted(self.E)], [4, 3, 5, 1, 2])

    def test_export_exact(self):
        out = P.j_export(self.E[:1] + self.E[2:4])
        self.assertEqual(out, "# Journal\n\n## 2025-11-07\n\n### 08:00 - good\n\na year ago\n\n## 2026-11-07\n\n### 07:00 - ok\n\ntoday one\n\n### 21:00 - great\n\ntoday two\n")

    def test_head_parse(self):
        self.assertEqual(P.j_parse_head("good 2026-11-05", "2026-11-07"), ("good", "2026-11-05"))
        self.assertEqual(P.j_parse_head("", "2026-11-07"), ("", "2026-11-07"))
        self.assertIsNone(P.j_parse_head("happy", "2026-11-07"))
        self.assertIsNone(P.j_parse_head("2027-01-01", "2026-11-07"))

    def test_streak_over_entries(self):
        self.assertEqual(P.streaks([e["d"] for e in self.E], "2026-11-07"), (2, 2))

    def test_screen_new_entry_and_export(self):
        now = ts(2026, 11, 7, 9)
        host, scr = drive(P.Journal, "agood<enter>Dear diary<enter>x", now=now)
        host, scr = drive(P.Journal, ["a", *"good", "enter", *"Dear diary", "ctrl-s", "ctrl-s", "escape"], now=now)
        self.assertEqual(len(scr.d["items"]), 1)             # saving twice updates, never duplicates
        self.assertEqual(scr.d["items"][0]["x"], "Dear diary")
        self.assertEqual(scr.d["items"][0]["m"], "good")
        host, scr = drive(P.Journal, "x", host=FakeHost(data=host.data), now=now)
        self.assertIn("Dear diary", host.text)
        self.assertIn("### ", host.data["journal.md"])
        host, scr = drive(P.Journal, "ahappy<enter>", now=now)
        self.assertIn("mood word", host.text)
        host, scr = drive(P.Journal, "s", host=FakeHost(data={"journal": '{"items": %s}' % str(self.E).replace("'", '"')}), now=now)
        self.assertIn("Current streak: 2", host.text)


class TestHabits(unittest.TestCase):
    def test_toggle_and_line(self):
        h = {"n": "Read", "days": []}
        for d in ["2026-11-05", "2026-11-06", "2026-11-07"]:
            self.assertTrue(P.h_toggle(h, d))
        self.assertEqual(P.h_line(h, "2026-11-07"), "[x] Read                   streak   3  best   3  week  43% ████")
        P.h_toggle(h, "2026-11-07")
        self.assertEqual(h["days"], ["2026-11-05", "2026-11-06"])
        self.assertFalse(P.h_toggle(h, "bogus"))
        for i in range(1000):
            P.h_toggle(h, (dt.date(2020, 1, 1) + dt.timedelta(days=i)).isoformat())
        self.assertEqual(len(h["days"]), 800)

    def test_screen(self):
        now = ts(2026, 11, 7, 9)
        host, scr = drive(P.Habits, "aRun<enter> yd", now=now)       # d opens a confirm, the run ends
        self.assertEqual(scr.d["items"][0]["days"], ["2026-11-06", "2026-11-07"])
        host, scr = drive(P.Habits, "s", host=FakeHost(data=host.data), now=now)
        self.assertIn("Run", host.text)
        self.assertIn(".....##  2/7", host.text.replace("\n", ""))
        self.assertIn("Overall completion: 29%", host.text)


class TestFocus(unittest.TestCase):
    def test_plan(self):
        p = P.pomo_plan()
        self.assertEqual(len(p), 8)
        self.assertEqual(p[0], ("work", 1500)); self.assertEqual(p[1], ("break", 300))
        self.assertEqual(p[-1], ("long break", 900)); self.assertEqual(p[-2], ("work", 1500))

    def test_pomo_at(self):
        r = P.pomo_at(600)
        self.assertEqual((r["phase"], r["left"], r["pomodoros"], r["focused"]), ("work", 900, 0, 600))
        r = P.pomo_at(1500 + 100)
        self.assertEqual((r["phase"], r["left"], r["pomodoros"], r["focused"]), ("break", 200, 1, 1500))
        r = P.pomo_at(3 * 1800 + 1500 + 60)             # in the long break after the 4th work phase
        self.assertEqual((r["phase"], r["pomodoros"], r["focused"]), ("long break", 4, 6000))
        self.assertEqual(r["left"], 840)
        cyc = 4 * 1500 + 3 * 300 + 900
        r = P.pomo_at(cyc + 10)                          # the second cycle begins
        self.assertEqual((r["phase"], r["pomodoros"], r["focused"]), ("work", 4, 6010))
        self.assertEqual(P.pomo_at(-5)["focused"], 0)
        self.assertEqual(P.pomo_at(10 ** 9)["pomodoros"], P.pomo_at(P.MAX_SESSION)["pomodoros"])   # capped
        r = P.pomo_at(100, work=10, short=5, long=5, every=2)
        self.assertEqual((r["pomodoros"], r["phase"], r["left"]), (7, "break", 5))   # 3 full cycles + the work phase ending exactly at 100

    def test_totals_helpers(self):
        log = [{"d": "2026-11-07", "min": 25, "task": "A"}, {"d": "2026-11-07", "min": 10, "task": "A"}, {"d": "2026-11-01", "min": 50, "task": "B"}, {"d": "2026-10-01", "min": 99}, {"d": "bad", "min": 5}]
        rows = P.day_sums(log, "min")
        self.assertEqual(P.sum_days(rows, "2026-11-07", 1), 35)
        self.assertEqual(P.sum_days(rows, "2026-11-07", 7), 85)
        self.assertEqual(P.per_task(log), {"A": 35, "B": 50})

    def test_screen_session_distraction_screen_time(self):
        t0 = ts(2026, 11, 7, 9)
        host = FakeHost("sxtea<enter>m120<enter>")
        scr = P.Focus(host)
        scr.now = lambda: t0
        run(host, scr)
        self.assertEqual(scr.d["run"], t0)
        self.assertEqual(len(scr.d["dist"]), 1)
        self.assertEqual(scr.d["screen"], {P.day_of(t0): 120})
        host2 = FakeHost("s", data=host.data)
        scr2 = P.Focus(host2)
        scr2.now = lambda: t0 + 1700
        run(host2, scr2)
        self.assertIsNone(scr2.d["run"])
        self.assertEqual(scr2.d["log"][0]["min"], 25 + 0)       # 1500 s work + 200 s of break: only work counts
        self.assertEqual((scr2.d["log"][0]["pomo"], scr2.d["log"][0]["dist"]), (1, 1))
        self.assertIn("screen time 120 min", "\n".join(scr2.totals()))
        self.assertIn("self-reported", host2.text.lower() + "\n".join(scr2.totals()).lower())

    def test_pick_task_and_time_per_task(self):
        shared = {}
        owner, user = FakeHost(), FakeHost("k<down><enter>s", data={})
        owner.spaces = user.spaces = shared
        shared_add(owner, "tasks", {"title": "Write report", "status": "open", "due": ""})
        scr = P.Focus(user)
        scr.now = lambda: 5000.0
        run(user, scr)
        self.assertEqual(scr.d["task"], "Write report")
        scr.now = lambda: 5000.0 + 1500
        scr.key("s")
        self.assertEqual(scr.d["log"][-1]["task"], "Write report")
        self.assertIn("Task Write report", "\n".join(scr.totals()))
        self.assertIn("25 min", "\n".join(scr.totals()))

    def test_regression_missing_run_key_and_battery_with_carried_data(self):
        """A vault that holds JSON without the 'run' key (or {} at all) used to raise KeyError in Focus Manager."""
        for data in ({}, {"focus": "{}"}, {"focus": '{"log": 5, "run": "x"}'}):
            scr = P.Focus(FakeHost(data=data))
            self.assertIsNone(scr.d["run"])
        data = {}
        for k in ["enter", "a", "n", "t", "g", "x", "/", "b", "?", "e", "c", "h", "r", "i", "s", "d", "R", "f", " ", "l", "o", "p", "u", "m", "w", "1"]:
            host = FakeHost([k, "a", "enter", "s", "t", "escape", "escape"], data=data)
            run(host, P.Focus(host))
            data = host.data

    def test_bad_screen_time_refused(self):
        for bad in ["abc", "-5", "99999", ""]:
            host = FakeHost("m" + bad + "<enter>")
            scr = P.Focus(host)
            run(host, scr)
            self.assertEqual(scr.d["screen"], {}, bad)


class TestEntriesAndKeys(unittest.TestCase):
    def test_entries(self):
        self.assertEqual([e.title for e in P.ENTRIES], ["Clock", "Reminders", "Sticky Notes", "Journal", "Habit Tracker", "Focus Manager"])
        for e in P.ENTRIES:
            self.assertIn(e.scope, ("full", "partial"))
            if e.scope == "partial": self.assertGreater(len(e.note), 20)
            self.assertEqual(e.uses, ["tasks"] if e.title in ("Reminders", "Focus Manager") else [])
            self.assertEqual(e.owns, [])
        self.assertIn("no audio", P.ENTRIES[0].note)
        self.assertIn("SELF-REPORTED", P.ENTRIES[5].note)

    def test_every_app_survives_a_key_battery(self):
        keys = ["enter", "a", "n", "t", "g", "x", "/", "b", "?", "e", "c", "h", "r", "i", "s", "d", "R", "f", " ", "l", "o", "p", "u", "m", "w", "1",
                "2", "3", "4", "k", "y", "up", "down", "left", "right", "home", "end", "pageup", "pagedown", "backspace", "tab", "\x00", "ctrl-s", "escape"]
        for e in P.ENTRIES:
            for width, height in ((80, 22), (20, 6)):
                host = FakeHost(keys + keys[::-1], width=width, height=height)
                run(host, e.args["make"](host, e))
                self.assertTrue(host.frames, e.title)
                for _t, lines, _s in host.frames:
                    self.assertLessEqual(len(lines), max(5, height - 1))


if __name__ == "__main__":
    unittest.main()
