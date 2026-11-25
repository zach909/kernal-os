"""kos.ui: GPUI-style elements -> layout -> the same draw ops. Includes hostile input."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.display import Framebuffer  # noqa: E402
from kos.protocol import validate_app_message  # noqa: E402
from kos.sdk import Canvas, div, text  # noqa: E402


def shot(root, w, h):
    c = Canvas()
    frame = c.paint(root, w, h)
    fb = Framebuffer(w, h)
    fb.apply(validate_app_message({"cmd": "frame", "ops": c.ops}, "graphical")["ops"])   # via the real validator
    return frame, fb


class TestLayout(unittest.TestCase):
    def test_row_flex_1_splits_exactly(self):
        a, b, c = div().id("a").flex_1(), div().id("b").flex_1(), div().id("c").flex_1()
        f, _ = shot(div().flex_row().size_full().children([a, b, c]), 100, 10)
        ws = [f.bounds(i)[2] for i in "abc"]
        self.assertEqual(sum(ws), 100)                     # the remainder is not lost
        self.assertEqual(ws, [33, 33, 34])
        self.assertEqual(f.bounds("b")[0], 33)

    def test_col_padding_gap_fixed_and_grow(self):
        root = div().flex_col().size_full().p(5).gap(2).children([
            div().id("top").h(10), div().id("mid").flex_1(), div().id("bot").h(10)])
        f, _ = shot(root, 50, 100)
        self.assertEqual(f.bounds("top"), (5, 5, 40, 10))
        self.assertEqual(f.bounds("bot"), (5, 85, 40, 10))
        self.assertEqual(f.bounds("mid"), (5, 17, 40, 66))

    def test_justify_and_items(self):
        k = div().id("k").size(10, 10)
        f, _ = shot(div().flex_row().size_full().justify_center().items_center().child(k), 100, 50)
        self.assertEqual(f.bounds("k"), (45, 20, 10, 10))
        ks = [div().id(n).size(10, 10) for n in "xy"]
        f, _ = shot(div().flex_row().size_full().justify_between().children(ks), 100, 50)
        self.assertEqual((f.bounds("x")[0], f.bounds("y")[0]), (0, 90))

    def test_text_is_its_natural_size(self):
        f, _ = shot(div().id("r").flex_col().items_start().child(text("HI").id("t")), 100, 100)
        self.assertEqual(f.bounds("t")[2:], (12, 9))

    def test_overflow_shrinks_not_overlaps(self):
        a, b = div().id("a").w(80), div().id("b").w(80)
        f, _ = shot(div().flex_row().size_full().children([a, b]), 100, 10)
        self.assertEqual(f.bounds("a")[2] + f.bounds("b")[2], 100)


class TestPaint(unittest.TestCase):
    def test_background_border_pixels(self):
        root = div().size_full().bg("#102030").border(2, "#ff0000")
        _, fb = shot(root, 20, 20)
        self.assertEqual(fb.pixel(0, 0), (255, 0, 0))
        self.assertEqual(fb.pixel(1, 10), (255, 0, 0))
        self.assertEqual(fb.pixel(2, 10), (0x10, 0x20, 0x30))
        self.assertEqual(fb.pixel(10, 10), (0x10, 0x20, 0x30))

    def test_rounded_corners_cut_the_corner_only(self):
        _, fb = shot(div().size_full().bg("#00ff00").rounded(6), 30, 30)
        self.assertEqual(fb.pixel(0, 0), (0, 0, 0))        # corner is empty
        self.assertEqual(fb.pixel(15, 0), (0, 255, 0))     # edge middle is filled
        self.assertEqual(fb.pixel(15, 15), (0, 255, 0))

    def test_rounded_is_few_ops(self):
        c = Canvas()
        c.paint(div().size_full().bg("#00ff00").rounded(8), 200, 200)
        self.assertLess(len(c.ops), 20)

    def test_overflow_hidden_clips_children(self):
        root = div().size(20, 20).overflow_hidden().child(div().size(100, 100).bg("#ffffff"))
        _, fb = shot(div().size_full().child(root), 40, 40)
        self.assertEqual(fb.pixel(19, 19), (255, 255, 255))
        self.assertEqual(fb.pixel(20, 20), (0, 0, 0))

    def test_clipped_text_never_leaves_the_box(self):
        c = Canvas()
        c.paint(div().child(div().size(30, 20).overflow_hidden().child(text("HELLO WORLD"))), 100, 100)
        for op in c.ops:
            if op[0] == "text":
                self.assertLessEqual(op[1] + len(op[3]) * 6 - 1, 30)

    def test_text_with_controls_is_made_safe(self):
        c = Canvas()
        c.paint(text("a\x1b[2Jb"), 100, 20)
        self.assertNotIn("\x1b", c.ops[0][3])

    def test_long_text_is_split_under_the_protocol_limit(self):
        c = Canvas()
        c.paint(text("A" * 700), 5000, 20)
        self.assertTrue(c.ops and all(len(o[3]) <= 256 for o in c.ops))
        validate_app_message({"cmd": "frame", "ops": c.ops}, "graphical")


class TestHit(unittest.TestCase):
    def test_topmost_id_wins_and_misses_are_none(self):
        root = div().flex_row().size_full().children([
            div().id("left").flex_1().child(div().id("inner").size(5, 5)),
            div().id("right").flex_1()])
        f, _ = shot(root, 100, 100)
        self.assertEqual(f.hit(2, 2), "inner")
        self.assertEqual(f.hit(20, 20), "left")
        self.assertEqual(f.hit(70, 20), "right")
        self.assertIsNone(f.hit(-1, 5))

    def test_clipped_part_is_not_clickable(self):
        root = div().size(20, 20).overflow_hidden().child(div().id("big").size(100, 100))
        f, _ = shot(div().size_full().child(root), 100, 100)
        self.assertEqual(f.hit(10, 10), "big")
        self.assertIsNone(f.hit(50, 50))


class TestHostile(unittest.TestCase):
    def test_bad_values_are_refused(self):
        for bad in (lambda: div().bg("red"), lambda: div().bg("#12345"), lambda: div().w(-1),
                    lambda: div().w(1.5), lambda: div().w(True), lambda: div().p(10**9),
                    lambda: div().id(""), lambda: text(5), lambda: div().child("x"),
                    lambda: text("a").scale(9), lambda: div().rounded(10**6)):
            with self.assertRaises(ValueError):
                bad()

    def test_deep_tree_is_refused_not_recursed(self):
        el = div()
        for _ in range(200):
            el = div().child(el)
        with self.assertRaises(ValueError):
            Canvas().paint(el, 10, 10)

    def test_duplicate_id_and_huge_window_refused(self):
        with self.assertRaises(ValueError):
            Canvas().paint(div().children([div().id("a"), div().id("a")]), 10, 10)
        with self.assertRaises(ValueError):
            Canvas().paint(div(), 10**9, 10)

    def test_frame_over_budget_raises_not_truncates(self):
        root = div().flex_col().size_full().children([div().h(1).bg("#ffffff") for _ in range(30)])
        c = Canvas()
        c.ops = [["clear", "#000000"]] * 4990
        with self.assertRaises(ValueError):
            c.paint(root, 10, 100)

    def test_rounded_dropped_before_failing(self):
        # 10 rounded boxes cost more ops than 10 square ones; room for squares only still renders
        root = div().flex_col().size_full().children([div().h(20).bg("#fff000").rounded(8) for _ in range(5)])
        sq = Canvas(); sq.paint(div().flex_col().size_full().children([div().h(20).bg("#fff000") for _ in range(5)]), 50, 100)
        c = Canvas(); c.ops = [["clear", "#000000"]] * (5000 - len(sq.ops))
        c.paint(root, 50, 100)
        self.assertEqual(len(c.ops), 5000 - len(sq.ops) + len(sq.ops))


if __name__ == "__main__":
    unittest.main()
