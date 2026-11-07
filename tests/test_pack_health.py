"""pack_health: exact values for the engines, hostile input, and a FakeHost run of each app."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_health as H  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def drive(entry, keys, host=None):
    host = host or FakeHost(keys)
    run(host, entry.args["make"](host, entry))
    return host


def E(title):
    return next(e for e in H.ENTRIES if e.title == title)


class Health(unittest.TestCase):
    def test_bmi(self):
        self.assertEqual(H.bmi("70", "kg", "175", "cm"), 22.9)
        self.assertEqual(H.bmi("154", "lb", "69", "in"), 22.7)
        self.assertEqual(H.bmi("70", "kg", "1.75", "m"), 22.9)
        self.assertIsNone(H.bmi("0", "kg", "175", "cm"))
        self.assertIsNone(H.bmi("abc", "kg", "175", "cm"))
        self.assertIsNone(H.bmi("70", "kg", "nan", "cm"))
        self.assertEqual([H.bmi_category(x) for x in (18.4, 18.5, 24.9, 25, 30)], ["underweight", "normal", "normal", "overweight", "obese"])

    def test_classify(self):
        c = H.classify
        self.assertEqual(c("blood pressure", "118/76"), "ok")
        self.assertEqual(c("blood pressure", "135/76"), "HIGH")
        self.assertEqual(c("blood pressure", "118/95"), "HIGH")
        self.assertEqual(c("blood pressure", "85/70"), "LOW")
        self.assertEqual(c("blood pressure", "abc"), "?")
        self.assertEqual(c("blood pressure", "1/2/3"), "?")
        self.assertEqual(c("glucose", "99", "mg/dL"), "ok")
        self.assertEqual(c("glucose", "100", "mg/dL"), "HIGH")
        self.assertEqual(c("glucose", "5.0", "mmol/L"), "ok")      # 90 mg/dL
        self.assertEqual(c("glucose", "7.0", "mmol/L"), "HIGH")
        self.assertEqual(c("temperature", "98.6", "F"), "ok")
        self.assertEqual(c("temperature", "39", "C"), "HIGH")
        self.assertEqual(c("heart rate", "50"), "LOW")
        self.assertEqual(c("weight", "70"), "")
        self.assertEqual(c("heart rate", "fast"), "?")
        self.assertEqual(c("heart rate", "110", ranges={"heart rate": [60, 120]}), "ok")   # editable range
        self.assertEqual(c("heart rate", "110", ranges={"heart rate": None}), "")

    def test_range_parse(self):
        self.assertEqual(H.parse_range("70-99"), [70, 99])
        self.assertIsNone(H.parse_range(""))
        for bad in ("99-70", "a-b", "1-2-3", "5", "-5"):
            self.assertIs(H.parse_range(bad), False, bad)

    def test_refills_and_adherence(self):
        meds = [{"name": "A", "refill_date": "2026-11-05", "status": "active"},
                {"name": "B", "refill_date": "2026-11-10", "status": "active"},
                {"name": "C", "refill_date": "2026-12-25", "status": "active"},
                {"name": "D", "refill_date": "2026-11-01", "status": "stopped"}, {"name": "E", "refill_date": "junk"}]
        self.assertEqual(H.refills_due(meds, "2026-11-07"), ["A: refill 2 day(s) overdue (2026-11-05)", "B: refill due in 3 day(s) (2026-11-10)"])
        self.assertEqual(H.refills_due([], "2026-11-07"), ["no refills due within 7 days"])
        log = [{"date": "2026-11-06", "medication": "A", "status": "taken"}, {"date": "2026-11-05", "medication": "a", "status": "taken"},
               {"date": "2026-11-04", "medication": "A", "status": "missed"}, {"date": "2026-11-03", "medication": "A", "status": "skipped"},
               {"date": "2026-09-01", "medication": "A", "status": "missed"}, {"date": "bad", "medication": "A", "status": "taken"}]
        self.assertEqual(H.adherence(log, "2026-11-07"), {"a": (2, 1, 67)})

    def test_emergency_card(self):
        card = H.emergency_card({"name": "Ann", "blood_type": "O+", "emergency_contact": "Bob", "contact_phone": "555 0100"},
                                [{"allergen": "Penicillin", "reaction": "rash", "severity": "severe"}],
                                [{"condition": "Asthma", "since": "2010", "status": "active"}, {"condition": "Old", "status": "resolved"}],
                                [{"name": "Ventolin", "dose": "100mcg", "schedule": "as needed"}, {"name": "Gone", "status": "stopped"}])
        text = "\n".join(card)
        for s in ("Name: Ann", "Blood type: O+", "Penicillin - rash (severe)", "Asthma (since 2010)", "Ventolin 100mcg as needed", "Emergency contact: Bob  555 0100"):
            self.assertIn(s, text)
        self.assertNotIn("Old", text)
        self.assertNotIn("Gone", text)
        self.assertIn("none recorded", "\n".join(H.emergency_card(None, [], [], [])))

    def test_hostile_input_is_bounded(self):
        host = FakeHost()
        d = H.Measures(host, H.S_MEAS, "measurements")
        r = d.add({"kind": "heart rate", "value": "7\x00\x1b" + "9" * 5000, "unit": "", "date": "", "note": "x" * 9999})
        self.assertLessEqual(len(r["value"]), 200)
        self.assertNotIn("\x00", r["value"])
        self.assertEqual(r["flag"], "?")
        self.assertEqual(r["date"], H.today())
        for i in range(H.CAP + 5):
            d.items.append({"_id": i + 10})
        n = len(d.items)
        d.add({"kind": "weight", "value": "70"})
        self.assertEqual(len(d.items), n)
        self.assertIn("limit", d.error)
        host.data["bad"] = "not json {"
        host.data["junk"] = json.dumps([1, 2])
        self.assertEqual(H.items_of(host, "junk"), [])
        self.assertEqual(H.items_of(host, "bad"), [])
        self.assertEqual(H.Measures(host, H.S_MEAS, "junk").items, [])

    def test_screen_run_saves_and_draws(self):
        host = drive(E("Health Records"), "<down><down><down><enter>a<enter><enter>120/80<enter><ctrl-s>", FakeHost("<down><down><down><enter>a<enter><enter>120/80<enter><ctrl-s>"))
        d = json.loads(host.spaces["health"]["records"])
        self.assertEqual(len(d["items"]), 1)
        self.assertEqual((d["items"][0]["value"], d["items"][0]["flag"], d["items"][0]["unit"]), ("120/80", "ok", "mmHg"))
        self.assertIn("Measurements", host.text)
        # emergency card draws
        h2 = drive(E("Health Records"), "<down><down><down><down><down><down><down><enter>")
        self.assertIn("EMERGENCY INFORMATION", h2.text)
        h3 = drive(E("Health Records"), "<down><down><down><down><enter><enter>")     # edit a range
        self.assertIn("Range", h3.text)


class Fitness(unittest.TestCase):
    def test_sleep_hours(self):
        self.assertEqual(H.sleep_hours("23:30", "07:00"), 7.5)
        self.assertEqual(H.sleep_hours("01:00", "08:15"), 7.25)
        for bad in (("07:00", "07:00"), ("25:00", "07:00"), ("a", "b"), ("7", "8"), ("23:60", "1:00")):
            self.assertIsNone(H.sleep_hours(*bad), bad)

    def test_streak(self):
        days = ["2026-11-07", "2026-11-06", "2026-11-05", "2026-11-03", "junk"]
        self.assertEqual(H.streak(days, "2026-11-07"), 3)
        self.assertEqual(H.streak(days, "2026-11-08"), 3)      # today still empty: count from yesterday
        self.assertEqual(H.streak(days, "2026-11-09"), 0)
        self.assertEqual(H.streak([], "2026-11-07"), 0)
        self.assertEqual(H.streak(days, "bad"), 0)

    ACTS = [{"date": "2026-11-02", "minutes": "30", "distance_km": "3", "calories": "200"},   # Monday
            {"date": "2026-11-05", "minutes": "45", "distance_km": "5.5"},
            {"date": "2026-11-07", "minutes": "x"},
            {"date": "2026-10-28", "minutes": "60", "calories": "400"}, {"date": "junk", "minutes": "99"}]
    SLEEP = [{"date": "2026-11-07", "hours": "7.5"}, {"date": "2026-11-06", "hours": "6.5"}, {"date": "2026-10-20", "hours": "9"}]

    def test_weekly_totals(self):
        w = H.weekly_totals(self.ACTS, "2026-11-07", 2)       # 2026-11-07 is a Saturday
        self.assertEqual(w, [("2026-11-02", 3, "75", "8.5", "200"), ("2026-10-26", 1, "60", "0", "400")])

    def test_sleep_average(self):
        self.assertEqual(H.sleep_average(self.SLEEP, "2026-11-07"), 7.0)
        self.assertIsNone(H.sleep_average([], "2026-11-07"))

    def test_goals(self):
        g = lambda m, p, t: {"metric": m, "period": p, "target": t}
        self.assertEqual(H.goal_progress(g("active_minutes", "week", "150"), self.ACTS, self.SLEEP, "2026-11-07"), (75, 150, 50))
        self.assertEqual(H.goal_progress(g("sessions", "week", "3"), self.ACTS, self.SLEEP, "2026-11-07"), (3, 3, 100))
        self.assertEqual(H.goal_progress(g("distance_km", "day", "5"), self.ACTS, self.SLEEP, "2026-11-05"), (5.5, 5, 110))
        self.assertEqual(H.goal_progress(g("sleep_hours", "week", "8"), self.ACTS, self.SLEEP, "2026-11-07"), (7.0, 8, 88))
        self.assertEqual(H.goal_progress(g("calories", "week", "0"), self.ACTS, self.SLEEP, "2026-11-07")[2], 0)

    def test_report_text(self):
        out = "\n".join(H.fitness_report(self.ACTS, self.SLEEP, [{"goal": "Move", "metric": "active_minutes", "period": "week", "target": "150"}], "2026-11-07"))
        self.assertIn("Activity streak: 1 day(s)", out)
        self.assertIn("7.0 h/night", out)
        self.assertIn("Move", out)
        self.assertIn("not supported", out)

    def test_hostile(self):
        host = FakeHost()
        d = H.Sleeps(host, H.S_SLEEP, "sleep")
        r = d.add({"bed": "23:00", "wake": "06:30", "date": "2026-11-07"})
        self.assertEqual(r["hours"], "7.5")
        self.assertEqual(d.add({"bed": "zz", "wake": "06:30"})["hours"], "")
        a = H.Vault(host, H.S_ACT, "acts").add({"minutes": "-5", "distance_km": "1e99", "calories": "nan"})
        self.assertEqual((a["minutes"], a["distance_km"], a["calories"]), ("", "", ""))

    def test_screen_run(self):
        keys = "<down><enter>a<down><down><enter>45<enter><ctrl-s><escape><up><enter>"
        host = drive(E("Fitness Tracker"), keys, FakeHost(keys))
        items = json.loads(host.data["acts"])["items"]
        self.assertEqual((len(items), items[0]["minutes"]), (1, "45"))      # first field is date; Enter keeps default, then minutes
        self.assertIn("Fitness summary", host.text)
        self.assertIn("Weekly totals", host.text)


class Meditation(unittest.TestCase):
    BOX = H.PATTERNS["Box breathing (4-4-4-4)"]

    def test_phase_at(self):
        self.assertEqual(H.phase_at(self.BOX, 0), (0, 0.0, 1, 0.0))
        self.assertEqual(H.phase_at(self.BOX, 2), (0, 2.0, 1, 0.5))
        self.assertEqual(H.phase_at(self.BOX, 5), (1, 1.0, 1, 1.0))
        self.assertEqual(H.phase_at(self.BOX, 10), (2, 2.0, 1, 0.5))
        self.assertEqual(H.phase_at(self.BOX, 16), (0, 0.0, 2, 0.0))
        p478 = H.PATTERNS["4-7-8 breathing"]
        self.assertEqual(H.phase_at(p478, 11)[:3], (2, 0.0, 1))
        self.assertEqual(H.phase_at(p478, 19)[:3], (0, 0.0, 2))
        self.assertEqual(H.phase_at(p478, -5)[:3], (0, 0.0, 1))
        self.assertEqual(sum(p[1] for p in H.PATTERNS["Coherent breathing (5-5)"]), 10)

    def test_session_report_and_streak(self):
        s = [{"d": "2026-11-06", "p": "x", "s": 300}, {"d": "2026-11-07", "p": "y", "s": 125}]
        out = H.session_report(s, "2026-11-07")
        self.assertEqual(out[0], "Streak: 2 day(s)   Sessions: 2   Total: 7 min")
        self.assertIn("2026-11-07    2:05  y", out[2])

    def test_bad_stored_sessions(self):
        host = FakeHost(data={"sessions": json.dumps([{"d": "bad", "s": 1}, {"d": "2026-11-07", "s": "x"}, 5, {"d": "2026-11-07", "s": 60}])})
        self.assertEqual(len(H.load_sessions(host)), 1)
        self.assertTrue(H.add_session(host, "2026-11-07", "p" * 100, 10 ** 9))
        self.assertEqual(H.load_sessions(host)[-1]["s"], 14400)

    def test_clock_driven_guide_and_log(self):
        t = [1000.0]
        clock = lambda: t[0]
        host = FakeHost()
        scr = H.Breath(host, "4-7-8 breathing", clock)
        self.assertIn("Press Enter to start", "\n".join(scr.render(80, 20)))
        scr.key("+"); scr.key("enter")
        self.assertEqual(scr.minutes, 6)
        t[0] += 6                                   # 6 s in: hold phase, 5 s left
        txt = "\n".join(scr.render(80, 20))
        self.assertIn("HOLD", txt)
        self.assertIn("5 s", txt)
        self.assertIn("00:06 of 06:00", txt)
        t[0] += 400
        self.assertIn("Time is up", "\n".join(scr.render(80, 20)))
        self.assertEqual(scr.key("f"), ("pop", None))
        s = H.load_sessions(host)
        self.assertEqual((len(s), s[0]["s"], s[0]["p"]), (1, 406, "4-7-8 breathing"))

    def test_manual_mode(self):
        scr = H.Breath(FakeHost(), "Coherent breathing (5-5)", lambda: 5.0)
        scr.key("m"); scr.key("enter")
        self.assertIn("INHALE", "\n".join(scr.render(80, 20)))
        scr.key(" ")
        self.assertIn("EXHALE", "\n".join(scr.render(80, 20)))
        scr.key(" ")
        self.assertIn("cycle 2", "\n".join(scr.render(80, 20)))

    def test_screen_run(self):
        keys = "<enter><enter>   f<enter>"          # box breathing: start, step, finish
        host = drive(E("Meditation Timer"), "<enter><enter> f<down><down><down><enter>", FakeHost("<enter><enter> f<down><down><down><enter>"))
        self.assertEqual(len(json.loads(host.data["sessions"])), 1)
        self.assertIn("Streak: 1 day(s)", host.text)
        h2 = drive(E("Meditation Timer"), "<down><down><down><down><enter>10<enter>")
        self.assertEqual(json.loads(h2.data["sessions"])[0]["s"], 600)
        h3 = drive(E("Meditation Timer"), "<down><down><down><down><enter>abc<enter>")
        self.assertIn("1 to 600", h3.text)
        self.assertNotIn("sessions", h3.data)


class Shared(unittest.TestCase):
    def test_permissions_declared(self):
        self.assertEqual((E("Health Records").owns, E("Health Records").uses), (["health"], []))
        self.assertEqual((E("Fitness Tracker").uses, E("Fitness Tracker").owns), (["health"], []))
        self.assertEqual((E("Meditation Timer").owns, E("Meditation Timer").uses), ([], []))

    def test_health_to_fitness_through_shared_space(self):
        keys = "<down><down><down><enter>a<enter><enter>70<enter><ctrl-s>"
        h1 = drive(E("Health Records"), keys)
        a = H.Measures(H.SpaceHost(h1, "health"), H.S_MEAS, "records", h1)       # add a height and a heart rate too
        a.add({"kind": "height", "value": "175", "unit": "cm", "date": "2026-11-01"})
        a.add({"kind": "heart rate", "value": "62", "unit": "", "date": "2026-11-02"})
        self.assertNotIn("records", h1.data)                      # shared, not private
        h2 = FakeHost("<down><down><down><down><escape>")
        h2.spaces = h1.spaces                                     # a second app, same shared folder
        self.assertEqual(len(H.shared_items(h2, "health")), 3)
        out = "\n".join(H.fitness_report([], [], [], "2026-11-07", H.shared_items(h2, "health")))
        self.assertIn("latest heart rate 62 bpm (2026-11-02)", out)
        self.assertIn("BMI", out)
        h3 = FakeHost("<enter>")
        h3.spaces = h1.spaces
        run(h3, E("Fitness Tracker").args["make"](h3, E("Fitness Tracker")))
        self.assertIn("heart rate", h3.text)

    def test_missing_grant_still_works(self):
        out = "\n".join(H.fitness_report([], [], [], "2026-11-07", H.shared_items(FakeHost(), "health")))
        self.assertIn("none available", out)
        self.assertIn("Weekly totals", out)


class Entries(unittest.TestCase):
    def test_entries(self):
        self.assertEqual([e.title for e in H.ENTRIES], ["Health Records", "Fitness Tracker", "Meditation Timer"])
        for e in H.ENTRIES:
            self.assertGreater(len(e.note), 20)
        self.assertIn("unencrypted", E("Health Records").note.lower())
        self.assertIn("not medical advice", E("Health Records").note.lower())

    def test_key_battery(self):
        keys = ["up", "down", "enter", "escape", "a", "e", "d", "x", "i", "g", "R", "/", "tab", "backspace", " ", "+", "-", "m", "f", "ctrl-s", "left", "right", "home", "end", "\x00", "é"]
        for e in H.ENTRIES:
            for seq in (keys, keys[::-1], ["enter"] * 5 + keys):
                host = FakeHost(seq)
                run(host, e.args["make"](host, e))
                self.assertTrue(host.frames)


if __name__ == "__main__":
    unittest.main()
