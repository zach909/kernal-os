"""Tests for kos/office/pack_more.py: RFC vectors, exact figures, hostile input, and FakeHost runs."""

import sys
import unittest
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_more as P  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

SECRET = b"12345678901234567890"


def drive(scr, keys, host=None):
    host = host or FakeHost(keys)
    host.script = [c for k in (FakeHost.tokens(keys) if isinstance(keys, str) else keys) for c in FakeHost.expand(k)]
    run(host, scr)
    return host


class TestAuthenticator(unittest.TestCase):
    def test_rfc4226_vectors(self):
        want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([P.hotp(SECRET, i) for i in range(10)], want)

    def test_rfc6238_vectors_for_all_three_hashes(self):
        s256, s512 = b"12345678901234567890123456789012", b"1234567890123456789012345678901234567890123456789012345678901234"
        for t, a, b, c in [(59, "94287082", "46119246", "90693936"), (1111111109, "07081804", "68084774", "25091201"),
                           (20000000000, "65353130", "77737706", "47863826")]:
            self.assertEqual(P.totp(SECRET, t, 30, 8, "sha1"), a)
            self.assertEqual(P.totp(s256, t, 30, 8, "sha256"), b)
            self.assertEqual(P.totp(s512, t, 30, 8, "sha512"), c)

    def test_hostile_settings_refused(self):
        for args in [(b"", 0), (SECRET, -1), (SECRET, 0, 0), (SECRET, 0, 11), (SECRET, 0, 6, "md5")]:
            with self.assertRaises(ValueError): P.hotp(*args)
        with self.assertRaises(ValueError): P.totp(SECRET, 1, 0)

    def test_base32_as_pasted(self):
        self.assertEqual(P.b32("jbsw y3dp-ehpk 3pxp"), b"Hello!\xde\xad\xbe\xef")
        for bad in ["", "1189", "!!!!", None, "A" * 201]:
            with self.assertRaises(ValueError): P.b32(bad)

    def test_screen_shows_code_and_does_not_save_the_secret(self):
        host = FakeHost("")
        scr = P.AuthScreen(host, now=lambda: 59)
        scr._set("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")        # base32 of the RFC secret
        self.assertEqual(scr.code(), ("287082", 1))
        drive(scr, ["escape"], host)
        self.assertEqual(host.data, {})                      # nothing was stored


class TestMahjong(unittest.TestCase):
    def test_every_deal_is_solvable_and_pairs_up(self):
        for seed in range(40):
            b = P.mj_deal(seed)
            self.assertEqual(sorted(t for t in b), sorted(b))
            for f in set(b): self.assertEqual(b.count(f) % 2, 0)
            while any(t is not None for t in b):
                scr = P.MahjongScreen(FakeHost(""), seed=seed); scr.board = b
                m = scr.moves()
                self.assertTrue(m, f"seed {seed} stuck")
                b[m[0][0]] = b[m[0][1]] = None

    def test_blocked_and_free(self):
        b = ["A", "B", "A"] + [None] * (P.ROWS * P.COLS - 3)
        self.assertTrue(P.mj_free(b, 0)); self.assertFalse(P.mj_free(b, 1)); self.assertTrue(P.mj_free(b, 2))
        self.assertFalse(P.mj_free(b, 5))

    def test_screen_runs_and_survives_any_key(self):
        host = drive(P.MahjongScreen(FakeHost(""), seed=3), ["right", "down", " ", "h", "n", "x", "left", "up", "escape"])
        self.assertIsNotNone(host.frames)


class TestBlackjack(unittest.TestCase):
    def test_values(self):
        self.assertEqual(P.hand_value([1, 13]), 21)
        self.assertEqual(P.hand_value([1, 1, 9]), 21)
        self.assertEqual(P.hand_value([13, 12, 5]), 25)
        self.assertEqual(P.hand_value([1, 1, 1, 1]), 14)

    def test_hit_until_bust_scores_a_loss(self):
        host = FakeHost("")
        scr = P.BlackjackScreen(host, seed=2)
        scr.me, scr.over, scr.deck = [10, 10], False, [5]
        drive(scr, ["h", "escape"], host)
        self.assertTrue(scr.over and "Bust" in scr.result and scr.losses == 1)
        self.assertEqual(P.BlackjackScreen(host, seed=1).losses, 1)       # saved and reloaded


class TestKeyboard(unittest.TestCase):
    def test_types_and_saves(self):
        host = FakeHost("")
        scr = P.KeyboardScreen(host)
        drive(scr, ["enter", "right", "enter", "tab", "enter", "escape"], host)   # q, w, E(shifted w? r=1 c=1 -> 'w')
        self.assertTrue(scr.text.startswith("qw"))
        self.assertEqual(P.KeyboardScreen(host).text, scr.text)

    def test_hostile_saved_buffer_is_ignored(self):
        host = FakeHost("", data={"buffer": "[1,2]"})
        self.assertEqual(P.KeyboardScreen(host).text, "")


class TestTrends(unittest.TestCase):
    def test_exact_report(self):
        t = "\n".join(P.trend_report(P.parse_series("10, 20, 15, 30"), 2))
        self.assertIn("first 10   last 30   high 30 (#4)   low 10 (#1)", t)
        self.assertIn("mean 75/4   total change 20   growth 200%", t)
        self.assertIn("moving average: 15, 35/2, 45/2", t)
        self.assertNotIn(".", t.split("moving average")[0].replace("...", "").split("\n", 3)[1])

    def test_labels_and_hostile(self):
        self.assertEqual(P.parse_series("jan 5\nfeb 7"), [5, 7])
        for bad in ["", "abc", "1 2 x", "nan", " ".join(["1"] * 501)]:
            with self.assertRaises(ValueError): P.parse_series(bad)
        self.assertEqual(P.parse_series("1\x00 2"), [1, 2])

    def test_zero_first_point_does_not_divide(self):
        self.assertTrue(P.trend_report([Fraction(0), Fraction(5)]))


class TestBooksAndCitations(unittest.TestCase):
    def test_isbn(self):
        for ok in ["978-0-306-40615-7", "0306406152", "080442957X", "9780306406157"]: self.assertTrue(P.isbn13_ok(ok), ok)
        for bad in ["978-0-306-40615-8", "0306406153", "", "abc", None, "9" * 14]: self.assertFalse(P.isbn13_ok(bad), bad)

    def test_report_flags_bad_isbn(self):
        t = "\n".join(P.books_report([{"title": "A", "isbn": "123"}, {"title": "B", "isbn": "9780306406157", "shelf": "x"}]))
        self.assertIn("fail their check digit: 1", t)

    def test_citation_leaves_missing_parts_out(self):
        self.assertEqual(P.cite({"authors": "Lee, A.", "year": "2020", "title": "T", "venue": "J"}), "Lee, A. (2020). T. J.")
        self.assertEqual(P.cite({"title": "Only"}), "(n.d.). Only.")
        self.assertEqual(P.cite({"title": "x\x00y"}), "(n.d.). xy.")


class TestExactFigures(unittest.TestCase):
    def test_numbers(self):
        self.assertEqual(P.fr("1,250.50"), Fraction(2501, 2))
        for bad in ["", "nan", "inf", "x", None, "9" * 30]: self.assertEqual(P.fr(bad), 0)
        self.assertEqual(P.money(Fraction(1, 3)), "0.33")
        self.assertEqual(P.money(Fraction(-5, 2)), "-2.50")
        self.assertEqual(P.rnd(Fraction(5, 2)), 3)
        self.assertEqual(P.pct(1, 8), "13% (125 per 1000)")
        self.assertEqual(P.pct(1, 0), "-")

    def test_ad_reports(self):
        t = "\n".join(P.ads_site_report([{"site": "a", "impressions": "1000", "clicks": "20", "revenue": "5.5"},
                                         {"site": "b", "impressions": "x", "clicks": "", "revenue": "-"}]))
        self.assertIn("CTR 2% (20 per 1000)", t.replace("Click-through rate ", "CTR "))
        self.assertIn("(RPM) 5.50", t)
        a = "\n".join(P.ads_app_report([{"app": "z", "requests": "200", "impressions": "150", "revenue": "3"}]))
        self.assertIn("Fill rate 75%", a)
        self.assertIn("eCPM) 20.00", a)

    def test_registers(self):
        self.assertIn("Total 150.00", "\n".join(P.trip_report([{"trip": "A", "kind": "stay", "cost": "100"}, {"trip": "B", "cost": "50"}])))
        f = "\n".join(P.flight_report([{"route": "X-Y", "price": "100", "minutes": "130", "stops": "1"}, {"route": "X-Z", "price": "150", "minutes": "90", "stops": "0"}]))
        self.assertIn("Cheapest: X-Y", f); self.assertIn("Shortest: X-Z 1h30", f); self.assertIn("Non-stop options: 1", f)
        self.assertIn("4.00 at S2", "\n".join(P.compare_report([{"product": "p", "store": "S1", "price": "5"}, {"product": "p", "store": "S2", "price": "4"}])))
        self.assertIn("balance 30", "\n".join(P.rewards_report([{"kind": "earned", "points": "100"}, {"kind": "redeemed", "points": "70"}])))
        self.assertIn("OVERLAP", "\n".join(P.guide_report([{"channel": "1", "date": "d", "program": "A", "start": "10:00", "end": "11:00"},
                                                          {"channel": "1", "date": "d", "program": "B", "start": "10:30", "end": "12:00"}])))
        self.assertIn("duplicates 1", "\n".join(P.tag_report([{"name": "a", "site": "s", "trigger": "t", "vendor": "v"}, {"name": "b", "site": "s", "trigger": "t", "vendor": "v"}])))

    def test_hostile_records_never_crash_a_report(self):
        junk = [{"revenue": "\x00", "clicks": None, "price": [1], "minutes": {}, "stops": "zz", "date": 5, "child": 7, "kind": None}, {}, {"approved": "yes", "min_age": "x"}]
        for name in ("trip_report", "flight_report", "compare_report", "ads_site_report", "ads_app_report", "search_perf_report", "tag_report",
                     "policy_report", "screen_time_report", "cloud_report", "rewards_report", "gaming_report", "channel_report", "release_report",
                     "completeness", "blog_index", "experiment_report", "kids_report", "watch_report", "guide_report", "lost_report", "art_report",
                     "font_report", "accessory_report", "bibliography", "books_report"):
            try:
                self.assertTrue(getattr(P, name)(junk), name)
            except (TypeError, AttributeError) as e:
                self.fail(f"{name}: {e}")


class TestEntries(unittest.TestCase):
    def test_every_built_entry_draws_and_survives_keys(self):
        for e in P.ENTRIES:
            if e.scope == "none": continue
            host = FakeHost("")
            scr = e.args["make"](host, e)
            drive(scr, ["down", "enter", "escape", "x", "ctrl-s", "escape"], host)
            self.assertTrue(scr.render(80, 22) is not None, e.title)

    def test_none_entries_say_why(self):
        for e in P.ENTRIES:
            if e.scope == "none": self.assertGreater(len(e.note), 40, e.title)


if __name__ == "__main__":
    unittest.main()
