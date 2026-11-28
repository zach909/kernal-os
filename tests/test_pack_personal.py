import datetime as dt
import json
import math
import sys
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_personal as P  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def entry(title): return next(e for e in P.ENTRIES if e.title == title)
def runapp(title, keys, data=None, **kw):
    h = FakeHost(keys, data=data, width=100, height=30, **kw)
    run(h, entry(title).args["make"](h, entry(title))); return h


class TestWatch(unittest.TestCase):
    def test_exact_pl_and_flags(self):
        a = P.analyse([{"symbol": "AAA", "price": "120", "prev_close": "100", "shares": "10", "cost_per_share": "80", "alert_above": "110"},
                       {"symbol": "BBB", "price": "50", "shares": "20", "cost_per_share": "100", "alert_below": "60"}])
        r = a["rows"]
        self.assertEqual((r[0]["value"], r[0]["pl"], r[0]["pl_pct"], r[0]["day_pct"]), (1200, 400, 50, 20))
        self.assertEqual(r[0]["flags"], ["ABOVE 110"]); self.assertEqual(r[1]["flags"], ["BELOW 60"])
        self.assertEqual((a["value"], a["cost"], a["pl"], a["pl_pct"]), (2200, 2800, -600, Decimal(-600) / 2800 * 100))

    def test_report_and_hostile(self):
        lines = P.watch_report([{"symbol": "A", "price": "1e999", "shares": "x"}, {"symbol": "B\x1b", "price": "nan"}, {}])
        self.assertTrue(lines)
        self.assertEqual(P.watch_report([]), ["no symbols yet"])
        rep = P.watch_report([{"symbol": "A", "price": "30", "shares": "1"}, {"symbol": "B", "price": "10", "shares": "1"}])
        self.assertTrue(any("75.0%" in l for l in rep))


class TestTickets(unittest.TestCase):
    def test_expiring(self):
        out = P.expiring([{"title": "Pass", "kind": "event", "expiry": "2026-03-10"}, {"title": "Old", "expiry": "2026-02-01"},
                          {"title": "Far", "expiry": "2027-01-01"}, {"title": "bad", "expiry": "nope"}], "2026-03-01")
        txt = "\n".join(out)
        self.assertIn("in 9d", txt); self.assertIn("PAST", txt); self.assertNotIn("Far", txt); self.assertNotIn("bad", txt)
        self.assertEqual(P.expiring([], "2026-03-01"), ["nothing in the next 30 days"])
        self.assertTrue(P.expiring([{"title": "x"}], "garbage"))


class TestBudget(unittest.TestCase):
    def test_summary_exact(self):
        b = [{"category": "Food", "limit": "200"}, {"category": "Fun", "limit": "50"}]
        t = [{"date": "2026-03-02", "kind": "expense", "category": "food", "amount": "150.50"},
             {"date": "2026-03-09", "kind": "expense", "category": "Fun", "amount": "75"},
             {"date": "2026-03-10", "kind": "income", "category": "Pay", "amount": "1000"},
             {"date": "2026-04-01", "kind": "expense", "category": "Food", "amount": "999"},
             {"date": "2026-03-11", "kind": "expense", "category": "Taxi", "amount": "-5"},
             {"date": "2026-03-12", "kind": "expense", "category": "Rent", "amount": "10"}]
        txt = "\n".join(P.month_summary(b, t, "2026-03"))
        self.assertIn("Income 1,000.00   Expenses 235.50   Net 764.50", txt)
        self.assertIn("OVER by 25.00", txt); self.assertIn("49.50", txt); self.assertIn("no budget", txt)
        self.assertIn("Budgeted 250.00   Left of budget 14.50", txt); self.assertIn("1 transaction", txt)
        self.assertEqual(P.month_summary([], [], "2026-13"), ["month must look like 2026-03"])
        self.assertEqual(P.month_summary([], [], "x" * 10000), ["month must look like 2026-03"])


class TestPim(unittest.TestCase):
    def test_agenda(self):
        ev = [{"title": "Standup", "date": "2026-03-01", "start": "09:00", "repeat": "weekly"}, {"title": "Once", "date": "2026-03-03"}, {"title": "bad", "date": "x"}]
        tk = [{"title": "File", "due": "2026-03-02", "status": "todo", "priority": "high"}, {"title": "Done", "due": "2026-03-02", "status": "done"},
              {"title": "Late", "due": "2026-02-20", "status": "todo"}, {"title": "Someday", "status": "todo"}]
        txt = "\n".join(P.agenda(ev, tk, dt.date(2026, 3, 1), 14))
        self.assertIn("2026-03-08", txt); self.assertIn("task  File", txt); self.assertNotIn("Done", txt)
        self.assertIn("Late", txt); self.assertIn("Someday", txt); self.assertNotIn("bad", txt)
        self.assertEqual(P.agenda([], [], dt.date(2026, 3, 1)), ["nothing scheduled"])

    def test_not_granted_is_explained_and_granted_is_read(self):
        h = FakeHost(width=100, height=30)
        items, why = P.read_shared(h, "calendar", ["calendar"]); self.assertEqual(items, []); self.assertIn("empty or not shared", why)
        items, why = P.read_shared(h, "calendar", []); self.assertIn("does not declare", why)
        h.spaces["tasks"] = {"records": json.dumps({"items": [{"title": "T1", "due": "2026-03-02"}, "junk"]})}
        items, why = P.read_shared(h, "tasks", ["tasks"]); self.assertEqual((len(items), why), (1, ""))
        h.spaces["contacts"] = {"records": "{not json"}
        self.assertEqual(P.read_shared(h, "contacts", ["contacts"])[0], [])

    def test_screen_runs(self):
        h = runapp("Personal Information Manager", ["enter", "escape", "down", "enter", "escape", "down", "enter", "a", "T", "enter", "escape", "escape"])
        self.assertTrue(any("not shared" in "\n".join(l) for _t, l, _s in h.frames))


class TestPassword(unittest.TestCase):
    def test_entropy_math(self):
        self.assertAlmostEqual(P.password_entropy([26], 10), 10 * math.log2(26))
        self.assertAlmostEqual(P.password_entropy([10, 26], 2), math.log2(520))   # 2 * 10 * 26 strings with both classes
        self.assertAlmostEqual(P.password_entropy([26, 26, 10], 1), 0.0)           # cannot hold three classes in one char
        self.assertAlmostEqual(P.gen_passphrase(6)[1], 6 * math.log2(len(P.WORDS)))

    def test_generated_honours_options(self):
        for _ in range(200):
            for length in (4, 5, 16, 128):
                pw, bits = P.gen_password(length, True, True, True, True, True)
                self.assertEqual(len(pw), length); self.assertFalse(set(pw) & P.AMBIG)
                for k, v in P.pool_of(True, True, True, True, True).items(): self.assertTrue(set(pw) & set(v), (k, pw))
                self.assertTrue(set(pw) <= set("".join(P.pool_of(avoid_ambiguous=True).values())))
        pw, _ = P.gen_password(30, False, False, True, False); self.assertTrue(pw.isdigit())
        pw, _ = P.gen_password(30, True, False, False, False); self.assertTrue(pw.islower())
        for bad in ((3, True, True, True, True), (0, True, True, True, True), (129,), (16, False, False, False, False), ("9",)):
            with self.assertRaises(ValueError): P.gen_password(*bad)
        self.assertNotEqual(P.gen_password(40)[0], P.gen_password(40)[0])

    def test_passphrase(self):
        self.assertEqual(len(P.WORDS), len(set(P.WORDS))); self.assertTrue(all(w.isalpha() and w.islower() for w in P.WORDS))
        ph, _ = P.gen_passphrase(7, ".", True)
        parts = ph.split("."); self.assertEqual(len(parts), 7)
        self.assertTrue(all(p[0].isupper() and p.lower() in P.WORDS for p in parts))
        for bad in ((2,), (13,), (5, "x"), ("5",)):
            with self.assertRaises(ValueError): P.gen_passphrase(*bad)

    def test_strength(self):
        self.assertEqual(P.check_strength("password")["rating"], "very weak")
        self.assertEqual(P.check_strength("Password123!")["bits"] <= 10, True)
        self.assertEqual(P.check_strength("")["rating"], "very weak")
        self.assertAlmostEqual(P.check_strength("aaaa")["bits"], math.log2(26) + 3 or 0, places=1)   # 1 char + 3 repeats at 1 bit
        self.assertAlmostEqual(P.check_strength("abc")["bits"], math.log2(26) + 2, places=1)
        self.assertEqual(P.check_strength(P.gen_password(24)[0])["rating"], "strong")
        weak = P.check_strength("kQ7#x"); self.assertIn("shorter than 8 characters", weak["reasons"])
        self.assertTrue(P.check_strength("\x00" * 100000 + "é")["reasons"])

    def test_screen_keys_and_nothing_saved(self):
        h = runapp("Password Generator", ["g", "l", "u", "d", "s", "a", "up", "down", "pageup", "p", "w", "e", "C", "g", "p", "c", *"hunter2", "enter", "escape", "escape"])
        self.assertTrue(any("Rating" in "\n".join(l) for _t, l, _s in h.frames))
        self.assertEqual(h.data, {})
        h = runapp("Password Generator", ["l", "u", "d", "s", "s", "ctrl-q"]); self.assertEqual(h.data, {})   # last class cannot be switched off


class TestScreens(unittest.TestCase):
    def test_watchlist_saves_and_reports(self):
        h = runapp("Market Watchlist", ["a", *"ABC", "enter", "enter", "ctrl-s"] + ["escape"] * 3)
        self.assertTrue(h.frames)
        d = {"records": json.dumps({"next": 2, "items": [{"_id": 1, "symbol": "ABC", "price": "10", "shares": "3", "cost_per_share": "5"}]})}
        h = runapp("Market Watchlist", ["R", "escape", "escape"], data=d)
        self.assertTrue(any("P/L" in "\n".join(l) for _t, l, _s in h.frames))

    def test_tickets_and_budget_run(self):
        h = runapp("Tickets and Passes", ["R", "escape", "escape"]); self.assertTrue(h.frames)
        h = runapp("Budget Tracker", ["enter", "escape", "down", "enter", "escape", "down", "enter", "escape", "escape"])
        self.assertTrue(any("Income" in "\n".join(l) for _t, l, _s in h.frames))
        h = runapp("Budget Tracker", ["down", "down", "down", "enter", *"bad", "enter", "escape", "escape"])
        self.assertTrue(any("month must look like" in "\n".join(l) for _t, l, _s in h.frames))

    def test_entries(self):
        self.assertEqual([e.title for e in P.ENTRIES], ["Market Watchlist", "Tickets and Passes", "Budget Tracker", "Personal Information Manager", "Password Generator"])


if __name__ == "__main__":
    unittest.main()
