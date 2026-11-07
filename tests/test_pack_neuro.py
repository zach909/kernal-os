"""pack_neuro: DSP against known vectors, hostile input, FakeHost runs, none entries, named commands."""
import cmath
import math
import os
import random
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kos.office import pack_neuro as N  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def sine(f, fs, n, a=1.0):
    return [a * math.sin(2 * math.pi * f * i / fs) for i in range(n)]


def gain(y, x, skip=150):
    r = lambda s: math.sqrt(sum(v * v for v in s[skip:-skip]) / len(s[skip:-skip]))
    return r(y) / r(x)


def drive(title, keys, host=None):
    e = next(e for e in N.ENTRIES if e.title == title)
    host = host or FakeHost(keys)
    run(host, e.args["make"](host, e))
    return host


class Dsp(unittest.TestCase):
    def test_fft_vs_dft(self):
        r = random.Random(1)
        x = [r.uniform(-1, 1) for _ in range(64)]
        got = N.fft(x)
        for k in range(64):
            d = sum(x[n] * cmath.exp(-2j * math.pi * k * n / 64) for n in range(64))
            self.assertAlmostEqual(abs(got[k] - d), 0, places=9)

    def test_fft_sine_and_parseval(self):
        x = sine(8, 64, 64)
        X = N.fft(x)
        self.assertAlmostEqual(abs(X[8]), 32, places=9)
        self.assertAlmostEqual(abs(X[7]), 0, places=9)
        self.assertAlmostEqual(sum(v * v for v in x), sum(abs(v) ** 2 for v in X) / 64, places=9)

    def test_fft_refuses_bad_length(self):
        for n in (0, 3, 100):
            with self.assertRaises(ValueError):
                N.fft([1.0] * n)

    def test_filter_responses(self):
        fs, n = 250, 1500
        g = lambda h, f: gain(N.fir_apply(sine(f, fs, n), h), sine(f, fs, n))
        lp = N.fir_design("lowpass", fs, 20)
        self.assertGreater(g(lp, 5), 0.97)
        self.assertLess(g(lp, 60), 0.05)
        hp = N.fir_design("highpass", fs, 20)
        self.assertLess(g(hp, 3), 0.05)
        self.assertGreater(g(hp, 60), 0.95)
        bp = N.fir_design("bandpass", fs, 8, 13)
        self.assertGreater(g(bp, 10), 0.95)
        self.assertLess(g(bp, 2), 0.05)
        self.assertLess(g(bp, 40), 0.05)

    def test_notch_and_ma(self):
        fs, n = 250, 1500
        y = N.notch_apply(sine(50, fs, n), fs, 50)
        self.assertLess(gain(y, sine(50, fs, n)), 0.05)
        self.assertGreater(gain(N.notch_apply(sine(10, fs, n), fs, 50), sine(10, fs, n)), 0.97)
        self.assertEqual(N.moving_average([1, 2, 3, 4, 5], 3), [1.5, 2, 3, 4, 4.5])
        for bad in ((0, 250, 1500), (125, 250, 1500)):
            with self.assertRaises(ValueError):
                N.notch_apply([0.0] * 10, bad[1], bad[0])
        with self.assertRaises(ValueError):
            N.fir_design("bandpass", 250, 20, 10)

    def test_band_power_alpha(self):
        bp = N.band_powers(sine(10, 250, 1024, 5), 250)
        self.assertEqual(max(bp, key=bp.get), "alpha")
        self.assertAlmostEqual(sum(bp.values()), 1.0, places=9)
        self.assertAlmostEqual(N.dominant_freq(sine(10, 250, 1024), 250), 10, delta=0.5)
        self.assertEqual(max((b := N.band_powers(sine(20, 250, 1024), 250)), key=b.get), "beta")

    def test_dc_and_gaps(self):
        self.assertEqual(N.remove_dc([1, 2, 3]), [-1, 0, 1])
        self.assertEqual(N.interpolate_gaps([0, None, None, 3, None]), ([0, 1, 2, 3, 3], 3))
        with self.assertRaises(ValueError):
            N.interpolate_gaps([None, None])

    def test_epochs(self):
        x = [0.0] * 100
        for e in (20, 50, 80):
            x[e] = 6.0
        x = [v + 10 for v in x]
        avg, used, skipped = N.epochs_average(x, [20, 50, 80, 99], 5, 5)
        self.assertEqual((used, skipped), (3, 1))
        self.assertEqual(avg[5], 6.0)           # baseline of 10 removed, peak at the event
        self.assertEqual(avg[0], 0.0)
        with self.assertRaises(ValueError):
            N.epochs_average(x, [1], 5, 5)

    def test_artifacts(self):
        fs = 250
        good = sine(10, fs, 500, 10)
        a = N.artifacts(good, fs, thr=50)
        self.assertFalse(a["flatline"] or a["clipped"] or a["noisy"])
        self.assertEqual(a["over_thr"], 0)
        self.assertTrue(N.artifacts(good[:200] + [3.0] * 100 + good[:200], fs)["flatline"])
        clip = [max(-5, min(5, v)) for v in sine(10, fs, 500, 10)]
        self.assertTrue(N.artifacts(clip, fs)["clipped"])
        r = random.Random(2)
        self.assertTrue(N.artifacts([r.uniform(-1, 1) for _ in range(512)], fs)["noisy"])
        self.assertEqual(N.artifacts(good, fs, thr=5)["over_thr"] > 0, True)


class Parse(unittest.TestCase):
    def test_ok(self):
        names, ch = N.parse_csv("a,b\n1,2\n3,\n5,nan\n")
        self.assertEqual((names, ch), (["a", "b"], [[1, 3, 5], [2, None, None]]))
        self.assertEqual(N.parse_csv("1\n2\n3")[0], ["ch1"])

    def test_hostile(self):
        bad = ["", "a,b\n", "1,2\n3", "1,x", "1,inf", "1\x00", "a,b\n1,2\n3,4,5", None, 5,
               ",".join(["1"] * 9), "\n".join(["1"] * (N.MAX_N + 1)), "9" * (N.MAX_CHARS + 1), "1e999"]
        for b in bad:
            with self.assertRaises(ValueError, msg=repr(b)[:30]):
                N.parse_csv(b)

    def test_events(self):
        self.assertEqual(N.parse_events("30, 10;10", 100), [10, 30])
        for b in ("100", "-1", "x", "1.5"):
            with self.assertRaises(ValueError):
                N.parse_events(b, 100)
        with self.assertRaises(ValueError):
            N.parse_events(",".join(map(str, range(300))), 1000)

    def test_quality_lines(self):
        txt = "\n".join(N.quality_lines(["a", "b"], [sine(10, 250, 400, 5), [1.0] * 400], 250))
        self.assertIn("BAD", txt)
        self.assertIn("flat", txt)


class Screens(unittest.TestCase):
    def test_lab_demo_flow(self):
        h = drive("Signal Lab", ["down", "enter", "escape", "6", "escape", "7", "escape", "8", "enter", "escape", "escape"]
                  + ["down"] * 15 + ["5", "0", "enter", "escape", "ctrl-q"])
        # after the notch the working copy has the 50 Hz component removed
        self.assertTrue(any("Applied" in f[0] for f in h.frames))
        self.assertIn("lab", h.keys())
        self.assertTrue(h.frames)

    def test_lab_hostile_keys(self):
        keys = ["enter", "x" * 50, "ctrl-s", "escape", "n", "escape"] + ["enter", "down", "ctrl-z", "escape"] * 10
        drive("Signal Lab", keys)
        drive("Signal Lab", ["7", "enter", "6", "enter", "9", "enter", "ctrl-q"])

    def test_lab_paste_refused(self):
        host = FakeHost(["enter", "a", "ctrl-s", "ctrl-q"])
        drive("Signal Lab", None, host)
        self.assertIsNone(host.get("lab"))

    def test_ndm_runs_and_report(self):
        items = [{"session": "S1", "subject": "P01", "consent": "yes", "retention_until": "2000-01-01", "duration_min": "90"},
                 {"session": "S2", "subject": "P02", "consent": "no", "duration_min": "bad"}, {}]
        txt = "\n".join(N.ndm_report(items))
        self.assertIn("S1", txt)
        self.assertIn("S2", txt)
        self.assertIn("3 session(s), 1.5 h", txt)
        h = drive("Neural Data Manager", ["a", "S1", "enter", "P01", "enter", "ctrl-s", "ctrl-q"])
        self.assertTrue(h.frames)
        drive("Neural Data Manager", ["R", "escape", "ctrl-q"])


class Entries(unittest.TestCase):
    def test_titles_and_none(self):
        self.assertEqual([e.title for e in N.ENTRIES], ["Signal Lab", "Neural Data Manager", "Neural Interface Devices", "Assistive and Clinical Control"])
        self.assertEqual([e.scope for e in N.ENTRIES], ["partial", "partial", "none", "none"])
        for e in N.ENTRIES[2:]:
            self.assertTrue(60 <= len(e.note) <= 320, (e.title, len(e.note)))
        for e in N.ENTRIES[:2]:
            self.assertGreater(len(e.note), 20)
        self.assertIn("unencrypted", N.ENTRIES[1].note.lower())
        self.assertIn("does not acquire", N.ENTRIES[0].note)

    def test_named_things_exist(self):
        from kos.cli import COMMANDS
        with open(os.path.join(os.path.dirname(__file__), "..", "docs", "REQUESTED2.txt")) as f:
            titles = f.read()
        for e in N.ENTRIES:
            for c in re.findall(r"`kos (\w+)`", e.note):
                self.assertIn(c, COMMANDS)
            if "Signal Lab" in e.note:
                self.assertIn("Signal Lab", titles)


if __name__ == "__main__":
    unittest.main()
