"""Pixels -> rects and lines (kos/vectorize.py). Run with: python3 -m unittest discover -s tests"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import protocol, vectorize as V  # noqa: E402
from kos.display import Framebuffer, parse_color  # noqa: E402
from kos.sdk import Canvas  # noqa: E402


def hexpix(c):
    return "#%02x%02x%02x" % c


def render(ops, w, h):
    fb = Framebuffer(w, h)
    fb.clear(parse_color("#010203"))      # a colour the pictures below never use
    fb.apply(ops)
    return fb


def picture(w, h, colours, seed=1):
    rnd = random.Random(seed)
    return [[hexpix(rnd.choice(colours)) for _ in range(w)] for _ in range(h)]


class TestVectorize(unittest.TestCase):
    def assertSame(self, pixels, ops, x=0, y=0, scale=1, w=None, h=None):
        ph, pw = len(pixels), len(pixels[0])
        fb = render(ops, (w or pw * scale + x), (h or ph * scale + y))
        for j in range(ph):
            for i in range(pw):
                want = tuple(int(pixels[j][i][k:k + 2], 16) for k in (1, 3, 5))
                for dy in range(scale):
                    for dx in range(scale):
                        self.assertEqual(fb.pixel(x + i * scale + dx, y + j * scale + dy), want, (i, j))

    def test_exact_roundtrip_through_the_real_framebuffer(self):
        for seed in range(5):
            pix = picture(23, 17, [(255, 0, 0), (0, 255, 0), (0, 0, 255), (250, 250, 250)], seed)
            r = V.vectorize(pix)
            self.assertTrue(r.lossless)
            self.assertSame(pix, r.ops)

    def test_scale_and_offset(self):
        pix = picture(9, 6, [(200, 10, 10), (10, 200, 10), (10, 10, 200)], 7)
        r = V.vectorize(pix, x=5, y=3, scale=3)
        self.assertSame(pix, r.ops, x=5, y=3, scale=3)

    def test_solid_shapes_are_boxes_not_a_line_per_row(self):
        white, red = "#ffffff", "#ff0000"
        pix = [[white] * 40 for _ in range(40)]
        for j in range(10, 30):
            for i in range(10, 30):
                pix[j][i] = red
        r = V.vectorize(pix)
        self.assertEqual(r.ops, [["rect", 0, 0, 40, 40, "#ffffff"], ["rect", 10, 10, 20, 20, "#ff0000"]])

    def test_flat_picture_is_one_op_and_thin_features_are_lines(self):
        self.assertEqual(len(V.vectorize([["#123456"] * 8] * 8).ops), 1)
        pix = [["#000000"] * 5 for _ in range(5)]
        for j in range(5):
            pix[j][2] = "#ffffff"
        r = V.vectorize(pix)
        self.assertEqual(r.ops[1], ["line", 2, 0, 2, 4, "#ffffff"])
        self.assertSame(pix, r.ops)

    def test_rgb_triples_and_hex_strings_agree(self):
        a = V.vectorize([[(1, 2, 3), (255, 255, 255)]])
        b = V.vectorize([["#010203", "#ffffff"]])
        self.assertEqual(a.ops, b.ops)

    def test_noise_degrades_to_fit_the_budget(self):
        rnd = random.Random(3)
        pix = [[hexpix((rnd.randrange(256),) * 3) for _ in range(64)] for _ in range(64)]
        exact = V.vectorize(pix, max_ops=V.MAX_OPS)
        self.assertGreater(len(exact.ops), 300)
        r = V.vectorize(pix, max_ops=300)
        self.assertLessEqual(len(r.ops), 300)
        self.assertFalse(r.lossless)
        self.assertTrue(r.step > 1 or r.downscale > 1)

    def test_every_budget_is_met_even_for_the_worst_picture(self):
        rnd = random.Random(9)
        pix = [[hexpix(tuple(rnd.randrange(256) for _ in range(3))) for _ in range(61)] for _ in range(47)]
        for budget in (1, 2, 10, 100, 1000):
            r = V.vectorize(pix, x=3, y=4, scale=2, max_ops=budget)
            self.assertLessEqual(len(r.ops), budget)
            for op in r.ops:        # partial edge cells must stay inside the picture
                if op[0] == "rect":
                    self.assertLessEqual(op[1] + op[3], 3 + 61 * 2)
                    self.assertLessEqual(op[2] + op[4], 4 + 47 * 2)

    def test_downscaled_picture_keeps_its_average_colour(self):
        pix = [["#000000", "#ffffff"] * 8 for _ in range(8)]
        r = V.vectorize(pix, max_ops=1)
        self.assertEqual(r.ops[0][:5], ["rect", 0, 0, 16, 8])
        self.assertEqual(r.downscale, 2)          # 2x2 blocks already average to one grey
        self.assertFalse(r.lossless)
        self.assertEqual(r.ops[0][5], "#7f7f7f")  # (0 + 255) // 2

    def test_the_ops_pass_the_os_validator(self):
        pix = picture(30, 30, [(i * 8, 255 - i * 8, i) for i in range(30)], 5)
        for budget in (V.MAX_OPS, 200):
            ops = V.vectorize(pix, x=-4, y=2, scale=2, max_ops=budget).ops
            clean = protocol.validate_app_message({"cmd": "frame", "ops": ops}, "graphical")
            self.assertEqual(clean["ops"], ops)

    def test_constants_match_the_protocol(self):
        self.assertEqual(V.MAX_OPS, protocol.MAX_OPS)
        self.assertEqual(V.MAX_COORD, protocol.MAX_COORD)

    def test_hostile_input_is_a_value_error_and_nothing_else(self):
        ok = "#000000"
        bad = [
            None, 5, "abc", [], [[]], [[ok], []], [[ok, ok], [ok]], [ok], [[ok]] * (V.MAX_SIDE + 1),
            [[1]], [[None]], [["#12"]], [["red"]], [["#gggggg"]], [["#000000\n"]], [["javascript:alert(1)"]],
            [[(1, 2)]], [[(1, 2, 3, 4)]], [[(256, 0, 0)]], [[(-1, 0, 0)]], [[(1.5, 0, 0)]], [[(True, 0, 0)]],
            [[(1, 2, "3")]], [[{"r": 1}]], [[["#000000"]]],
            [[ok] * 600] * 600,                                   # over the pixel cap
        ]
        for pix in bad:
            with self.assertRaises(ValueError, msg=repr(pix)[:60]):
                V.vectorize(pix)
        pic = [[ok] * 4] * 4
        for kw in ({"scale": 0}, {"scale": V.MAX_SCALE + 1}, {"scale": 1.5}, {"scale": True},
                   {"x": V.MAX_COORD}, {"y": -V.MAX_COORD - 1}, {"x": "1"}, {"x": None},
                   {"max_ops": 0}, {"max_ops": V.MAX_OPS + 1}, {"max_ops": 1.0},
                   {"scale": V.MAX_SCALE, "x": V.MAX_COORD - 10}):
            with self.assertRaises(ValueError, msg=repr(kw)):
                V.vectorize(pic, **kw)

    def test_bad_input_never_reaches_a_frame(self):
        c = Canvas()
        c.rect(0, 0, 1, 1, "#000000")
        with self.assertRaises(ValueError):
            c.image([["#nope00"]])
        self.assertEqual(len(c.ops), 1)             # a refused picture adds nothing


class TestCanvasImage(unittest.TestCase):
    def test_image_appends_and_reports(self):
        c = Canvas()
        c.clear("#000000")
        v = c.image([["#ff0000", "#00ff00"]], x=2, y=2, scale=2)
        self.assertTrue(v.lossless)
        self.assertEqual(c.ops[0], ["clear", "#000000"])
        self.assertEqual(c.ops[1:], v.ops)

    def test_image_stays_inside_the_frames_op_budget(self):
        rnd = random.Random(2)
        pix = [[hexpix(tuple(rnd.randrange(256) for _ in range(3))) for _ in range(40)] for _ in range(40)]
        c = Canvas()
        for _ in range(4950):
            c.rect(0, 0, 1, 1, "#000000")
        c.image(pix, max_ops=V.MAX_OPS)
        self.assertLessEqual(len(c.ops), protocol.MAX_OPS)
        protocol.validate_app_message({"cmd": "frame", "ops": c.ops}, "graphical")

    def test_a_full_frame_has_no_room_for_a_picture(self):
        c = Canvas()
        c.ops = [["rect", 0, 0, 1, 1, "#000000"]] * protocol.MAX_OPS
        with self.assertRaises(ValueError):
            c.image([["#ffffff"]])
        self.assertEqual(len(c.ops), protocol.MAX_OPS)


if __name__ == "__main__":
    unittest.main()
