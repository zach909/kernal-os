"""Atlas core (suite/atlas_core.py): the map maker's brain, tested on scenes whose answer is known.

Every claim is checked against a truth the test builds itself (a texture shifted by a known number of pixels,
sensors around a known source, a room made of voxels), and each check has a case built to make it fail:
a blank wall, a lying camera, a hostile record, a full chunk."""

import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite"))

import atlas_core as a  # noqa: E402
from kos import proof  # noqa: E402

W, H = 96, 72


def rng(seed):
    s = seed
    while True:
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        yield (s >> 8) & 255


def texture(seed, w=W + 80, h=H):
    g = rng(seed)
    return [[next(g) for _ in range(w)] for _ in range(h)]


def two_layer_pair(d_bg=4, d_fg=12, rect=(30, 70, 20, 52)):
    """A left and right picture of a flat background (disparity d_bg) with a nearer square (d_fg)."""
    bg, fg = texture(1), texture(2)
    left, right = [], []
    for y in range(H):
        for x in range(W):
            inrect = rect[0] <= x < rect[1] and rect[2] <= y < rect[3]
            left.append(fg[y][x] if inrect else bg[y][x])
    for y in range(H):
        row = [bg[y][x + d_bg] for x in range(W)]
        for x in range(rect[0], rect[1]):
            if rect[2] <= y < rect[3] and 0 <= x - d_fg < W:
                row[x - d_fg] = fg[y][x]
        right.extend(row)
    return left, right


def region(d, x0, x1, y0, y1):
    vals = [d[y * W + x] for y in range(y0, y1) for x in range(x0, x1)]
    got = [v for v in vals if v]
    return len(got), len(vals), (a.median(got) if got else None)


class TestWholeNumbers(unittest.TestCase):
    def test_the_core_passes_the_proof_gate(self):
        src = (ROOT / "suite" / "atlas_core.py").read_bytes()
        self.assertEqual(proof.violations(src, "atlas_core.py"), [])

    def test_the_gate_would_catch_a_decimal_in_it(self):
        self.assertTrue(proof.violations(b"x = 1 / 2\n", "bad.py"))      # the negative control


class TestTrig(unittest.TestCase):
    def test_known_angles_and_symmetry(self):
        self.assertEqual((a.sin1024(0), a.sin1024(90), a.sin1024(180), a.sin1024(270)), (0, 1024, 0, -1024))
        self.assertEqual((a.cos1024(0), a.cos1024(90), a.cos1024(180)), (1024, 0, -1024))
        self.assertEqual(a.sin1024(30), 512)
        self.assertEqual(a.sin1024(-30), -512)
        self.assertEqual(a.sin1024(390), a.sin1024(30))

    def test_asin_round_trips(self):
        for deg in range(-90, 91, 5):
            self.assertLessEqual(abs(a.asin_deg(a.sin1024(deg)) - deg), 1)


class TestStereo(unittest.TestCase):
    def test_nearer_things_differ_more_and_depth_comes_out_right(self):
        left, right = two_layer_pair(d_bg=4, d_fg=12)
        t = time.monotonic_ns()
        d = a.disparity(left, right, W, H, max_disp=20)
        took = (time.monotonic_ns() - t) // 1_000_000
        n, tot, fg = region(d, 36, 64, 26, 46)
        _, _, bg = region(d, 75, 92, 5, 15)
        self.assertGreater(n * 100, tot * 90, "nearly every pixel of the textured square gets an answer")
        self.assertLessEqual(abs(fg - 12 * 16), 8)
        self.assertLessEqual(abs(bg - 4 * 16), 8)
        self.assertGreater(fg, bg, "the nearer square differs more between the two views")
        # f = 100 px, baseline 60 mm: Z = f B / d  -> 500 mm and 1500 mm
        self.assertLessEqual(abs(a.depth_mm(fg, 100, 60) - 500), 25)
        self.assertLessEqual(abs(a.depth_mm(bg, 100, 60) - 1500), 75)
        self.assertLess(took, 3000, f"one pair took {took} ms")

    def test_half_pixel_shift_is_found_to_a_sixteenth(self):
        raw = texture(7)
        t = [[(r[i] + r[i + 1] + r[i + 2]) // 3 for i in range(len(r) - 2)] for r in raw]     # a photo is smooth
        left = [t[y][x + 5] for y in range(H) for x in range(W)]
        right = [(t[y][x + 10] + t[y][x + 11]) // 2 for y in range(H) for x in range(W)]   # shifted 5.5 px
        # left[x] = t[x+5]; right[x - 5.5] = t[x+5]  =>  disparity 5.5 pixels = 88 sixteenths
        d = a.disparity(left, right, W, H, max_disp=12, max_avg_diff=40)
        n, tot, med = region(d, 20, 70, 10, 60)
        self.assertGreater(n * 100, tot * 70)
        self.assertLessEqual(abs(med - 88), 10)

    def test_a_blank_wall_gets_no_answer_rather_than_a_guess(self):
        flat = [128] * (W * H)
        self.assertEqual(sum(1 for v in a.disparity(flat, flat, W, H, max_disp=16) if v), 0)

    def test_unrelated_pictures_get_almost_no_answers(self):
        l = [v for row in texture(3)[:H] for v in row[:W]]
        r = [v for row in texture(4)[:H] for v in row[:W]]
        got = sum(1 for v in a.disparity(l, r, W, H, max_disp=16) if v)
        self.assertLess(got * 100, W * H * 3, "noise against noise must be refused, not matched")

    def test_bad_input_is_refused(self):
        with self.assertRaises(ValueError):
            a.disparity([0] * 10, [0] * 10, W, H)
        with self.assertRaises(ValueError):
            a.disparity([0] * (W * H), [0] * (W * H), W, H, max_disp=W)
        self.assertEqual(a.depth_mm(0, 100, 60), 0)

    def test_a_pattern_seen_twice_on_the_left_but_once_on_the_right_is_matched_once(self):
        """Two identical stickers in the left picture, one in the right: both match the same right-hand patch
        perfectly, but a patch can only be one place. The left-right check keeps one claim and drops the other."""
        bg, patch = texture(21), [row[:8] for row in texture(22)]
        left, right = [], []
        for y in range(H):
            lrow = [bg[y][x] for x in range(W)]
            rrow = [bg[y][x + 4] for x in range(W)]
            if 20 <= y < 50:
                for k in range(8):
                    lrow[44 + k] = lrow[52 + k] = patch[y][k]       # copy A at x 44..51 (d=8), copy B at 52..59 (d=16)
                    rrow[36 + k] = patch[y][k]
            left.extend(lrow)
            right.extend(rrow)
        checked = a.disparity(left, right, W, H, max_disp=20)
        unchecked = a.disparity(left, right, W, H, max_disp=20, lr_tol=100)
        def got(d, x0, x1):
            return sum(1 for y in range(24, 46) for x in range(x0, x1) if d[y * W + x])
        self.assertGreater(got(unchecked, 54, 58), 20, "without the check both copies claim the patch")
        self.assertLessEqual(got(checked, 54, 58), got(checked, 46, 50), "one claim kept, and it is the first copy")
        self.assertLess(got(checked, 54, 58), got(unchecked, 54, 58) // 2, "the check dropped the second claim")

    def test_nearest_measurable_distance(self):
        self.assertEqual(a.nearest_mm(100, 60, 20), 300)


class TestSeveralCameras(unittest.TestCase):
    """Three cameras on a rail at x = 0 (the reference), +60 and -40 mm. A flat card at 500 mm, a wall at 1500."""

    def render(self):
        bg, fg = texture(11), texture(12)
        f, rect = 100, (30, 70, 20, 52)
        d_fg_r, d_bg_r = f * 60 // 500, f * 60 // 1500          # right camera: 12 and 4
        d_fg_l, d_bg_l = f * 40 // 500, f * 40 // 1500          # left camera: 8 and 2
        ref = []
        for y in range(H):
            for x in range(W):
                ref.append(fg[y][x] if rect[0] <= x < rect[1] and rect[2] <= y < rect[3] else bg[y][x])
        right, left = [], []
        for y in range(H):
            row = [bg[y][x + d_bg_r] for x in range(W)]
            for x in range(rect[0], rect[1]):
                if rect[2] <= y < rect[3] and 0 <= x - d_fg_r < W:
                    row[x - d_fg_r] = fg[y][x]
            right.extend(row)
            # a camera on the LEFT sees things further RIGHT in its picture: other[x + d] = ref[x]
            row = [bg[y][max(0, x - d_bg_l)] for x in range(W)]
            for x in range(rect[0], rect[1]):
                if rect[2] <= y < rect[3] and 0 <= x + d_fg_l < W:
                    row[x + d_fg_l] = fg[y][x]
            left.extend(row)
        return ref, right, left

    def test_two_pairs_agree_and_a_camera_on_the_other_side_works(self):
        ref, right, left = self.render()
        zs, votes = a.fuse_depth({"f": 100, "xs": [0, 60, -40]}, [ref, right, left], W, H, max_disp=20)
        n, tot, z = region(zs, 38, 62, 28, 44)
        self.assertGreater(n * 100, tot * 80)
        self.assertLessEqual(abs(z - 500), 40)
        agree = [votes[y * W + x] for y in range(28, 44) for x in range(38, 62) if zs[y * W + x]]
        self.assertGreater(sum(1 for v in agree if v == 2) * 100, len(agree) * 60,
                           "most pixels are confirmed by both pairs")

    def test_a_pair_alone_still_works_with_the_other_camera_on_the_left(self):
        ref, _, left = self.render()
        zs, votes = a.fuse_depth({"f": 100, "xs": [0, -40]}, [ref, left], W, H, max_disp=20)
        n, tot, z = region(zs, 38, 62, 28, 44)
        self.assertGreater(n * 100, tot * 60)
        self.assertLessEqual(abs(z - 500), 50)
        self.assertEqual(max(votes), 1)

    def test_a_camera_that_lies_is_outvoted_not_averaged_in(self):
        ref, right, _ = self.render()
        junk = [v for row in texture(99)[:H] for v in row[:W]]
        zs, votes = a.fuse_depth({"f": 100, "xs": [0, 60, 20]}, [ref, right, junk], W, H, max_disp=20)
        n, tot, z = region(zs, 38, 62, 28, 44)
        self.assertLessEqual(abs(z - 500), 40)

    def test_two_pairs_that_disagree_do_not_crash_and_the_longer_baseline_wins(self):
        ref, right, _ = self.render()
        wrong = list(ref)                      # the "other" camera sees exactly what the reference sees: disparity 0
        zs, votes = a.fuse_depth({"f": 100, "xs": [0, 60, 20]}, [ref, right, wrong], W, H, max_disp=20)
        n, tot, z = region(zs, 38, 62, 28, 44)
        self.assertLessEqual(abs(z - 500), 40)
        self.assertEqual(votes[40 * W + 50], 1)

    def test_refuses_what_cannot_work(self):
        with self.assertRaises(ValueError):
            a.fuse_depth({"f": 100, "xs": [0]}, [[0] * (W * H)], W, H)
        with self.assertRaises(ValueError):
            a.fuse_depth({"f": 100, "xs": [5, 5]}, [[0] * (W * H)] * 2, W, H)


class TestProject(unittest.TestCase):
    def test_straight_ahead_and_the_pose(self):
        zs, votes, grey = [2000], [1], [9]
        rig = {"f": 100, "cx": 0, "cy": 0}
        self.assertEqual(a.project(zs, votes, grey, 1, 1, rig, (0, 0, 0, 0)), [(0, 2000, 0, 9, 1)])
        self.assertEqual(a.project(zs, votes, grey, 1, 1, rig, (1000, 0, 0, 90)), [(-1000, 0, 0, 9, 1)])
        self.assertEqual(a.project(zs, votes, grey, 1, 1, rig, (0, 0, 1500, 0))[0][2], 1500)

    def test_right_is_positive_x_and_up_is_positive_z(self):
        # pixel 10 right of and 10 above the centre, 1000 mm away, f = 100 px -> 100 mm right, 100 mm up
        w, h = 21, 21
        zs, votes, grey = [0] * (w * h), [0] * (w * h), [0] * (w * h)
        i = 0 * w + 20
        zs[i], votes[i] = 1000, 1
        p = a.project(zs, votes, grey, w, h, {"f": 100}, stride=1)
        self.assertEqual(p, [(100, 1000, 100, 0, 1)])

    def test_pixels_without_an_answer_make_no_point(self):
        self.assertEqual(a.project([0, 0], [0, 0], [1, 1], 2, 1, {"f": 100}, stride=1), [])


class TestMarks(unittest.TestCase):
    def test_a_good_mark_is_kept_whole(self):
        m = a.mark("smell", (1, 2, 3), v=42, t=100, label="coffee", ref="nose-1", unit="ohm")
        self.assertEqual(m["p"], [1, 2, 3])
        self.assertEqual(a.clean_mark(m), m)

    def test_real_unix_times_are_accepted(self):
        """The tests use small made-up times; the OS hands out real ones (about 1.8 billion seconds)."""
        now = 1_763_900_000
        self.assertEqual(a.mark("smell", (0, 0, 0), v=12345, t=now)["t"], now)
        self.assertEqual(a.ingest("note", "espresso grinder notes", t=now)["t"], now)
        self.assertEqual(a.data_mark("espresso grinder notes", t=now)["t"], now)
        s = a.MarkStore(Mem())
        s.add([a.mark("likes", None, v=100 + 150 * i, t=now + 3600 * i, ref="v", unit="likes") for i in range(5)])
        s.consolidate(now=now + 20000)
        self.assertEqual(len(s.search(kind="trend")), 1)
        self.assertEqual(a.trends([a.mark("x", None, v=i * 50, t=now + 3600 * i, ref="r") for i in range(5)])[0]["n"], 5)

    def test_hostile_marks_are_refused(self):
        good = {"k": "x", "p": [0, 0, 0], "v": 1, "t": 1}
        for bad in ({**good, "v": 1.5}, {**good, "v": float("inf")}, {**good, "p": [0, 0]}, {**good, "p": [0, 0, 10 ** 13]}, {**good, "t": 10 ** 13},
                    {**good, "k": "Bad Kind"}, {**good, "k": 7}, {**good, "n": 0}, {**good, "v": True},
                    {**good, "l": 5}, {**good, "s": "../x"}, "text", None, [], {**good, "p": "abc"}):
            self.assertIsNone(a.clean_mark(bad), bad)
        with self.assertRaises(ValueError):
            a.mark("x", v=1.5)

    def test_control_characters_never_survive(self):
        m = a.clean_mark({"k": "note", "l": "hello\x1b[2Jworld‮!", "r": "a\x00b"})
        self.assertNotIn("\x1b", m["l"])
        self.assertNotIn("‮", m["l"])
        self.assertNotIn("\x00", m["r"])

    def test_loading_counts_what_it_refuses(self):
        text = json.dumps([{"k": "a", "v": 1}, {"k": "A"}, 5, {"k": "b", "v": 2.5}])
        marks, bad = a.load_marks(text)
        self.assertEqual((len(marks), bad), (1, 3))
        for hostile in ("not json", "[" * 100000, '{"k":"a"}', "1e999", "null"):
            self.assertEqual(a.load_marks(hostile)[0], [])


class Mem:
    """A key-value backend in memory (what a KOS space or a folder looks like to the store)."""

    def __init__(self, fail=False):
        self.d, self.fail = {}, fail

    def keys(self):
        return sorted(self.d)

    def get(self, k):
        return self.d.get(k)

    def put(self, k, v):
        if self.fail:
            return False
        self.d[k] = v
        return True

    def delete(self, k):
        return self.d.pop(k, None) is not None


class TestStore(unittest.TestCase):
    def test_the_same_thing_seen_twice_is_added_not_piled_up(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("sight", (110, 110, 110), v=100, t=1000, n=1)])
        s.add([a.mark("sight", (140, 160, 190), v=200, t=1010, n=3)])          # same 100 mm cell, same minute
        hits = s.search(kind="sight")
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0]["n"], hits[0]["v"]), (4, 175))

    def test_readings_in_different_minutes_stay_separate_in_time(self):
        s = a.MarkStore(Mem())
        for i, v in enumerate((10, 20, 30)):
            s.add([a.mark("smell", (0, 0, 0), v=v, t=1000 + 120 * i, ref="nose-1")])
        got = s.search(kind="smell")
        self.assertEqual(sorted(m["v"] for m in got), [10, 20, 30])
        self.assertEqual([m["v"] for m in got], [30, 20, 10], "newest first")

    def test_search_by_words_kind_time_and_place(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("file", (0, 0, 0), label="notes.md  coffee brewing", ref="notes.md", t=10, space="files"),
               a.mark("file", (1000, 0, 0), label="beans.txt  coffee roast", ref="beans.txt", t=20, space="files"),
               a.mark("smell", (5000, 5000, 0), v=7, label="coffee", t=30),
               a.mark("event", (100, 100, 900), label="person-sized movement", t=40)])
        self.assertEqual(len(s.search(text="coffee")), 3)
        self.assertEqual(len(s.search(text="coffee roast")), 1, "every word must match")
        self.assertEqual(len(s.search(text="COFFEE", kind="file")), 2)
        self.assertEqual([m["r"] for m in s.search(text="coffee", space="files")], ["beans.txt", "notes.md"])
        self.assertEqual(len(s.search(since=25)), 2)
        self.assertEqual(len(s.search(until=15)), 1)
        near = s.search(near=(0, 0, 0), radius=1500, space="files")
        self.assertEqual([m["r"] for m in near], ["notes.md", "beans.txt"], "nearest first")
        self.assertEqual(near[0]["d"] <= near[1]["d"], True)
        self.assertEqual(s.search(near=(0, 0, 0), radius=200, space="files")[0]["r"], "notes.md")

    def test_a_mark_with_no_place_is_never_near_anything(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("note", None, label="remember the milk", t=5)])
        self.assertEqual(s.search(near=(0, 0, 0), radius=10 ** 8), [])
        self.assertEqual(len(s.search(text="milk")), 1)

    def test_the_oldest_chunk_is_forgotten_when_the_map_is_full(self):
        mem = Mem()
        s = a.MarkStore(mem, max_chunks=3)
        for i in range(5):
            s.add([a.mark("sight", (i * 3000, 0, 0), v=1, t=100 * (i + 1))])
        chunks = [k for k in mem.keys() if k.startswith("c.")]
        self.assertEqual(len(chunks), 3)
        self.assertEqual(sorted(m["t"] for m in s.search(kind="sight", limit=10)), [300, 400, 500])

    def test_a_chunk_never_outgrows_what_one_item_may_hold(self):
        mem = Mem()
        s = a.MarkStore(mem)
        s.add([a.mark("note", None, label="n" * 150, ref=f"r{i}", t=i) for i in range(3000)])
        for k, v in mem.d.items():
            if k.startswith("c."):
                self.assertLessEqual(len(v), a.MAX_CHUNK_CHARS)

    def test_what_the_backend_hands_back_is_not_trusted(self):
        mem = Mem()
        s = a.MarkStore(mem)
        s.add([a.mark("note", None, label="hi", ref="x", t=1)])
        key = [k for k in mem.keys() if k.startswith("c.")][0]
        mem.d[key] = json.dumps([{"k": "note", "l": "ok", "v": 1}, {"k": "note", "v": 1.5}, {"k": "!!"}, 9])
        self.assertEqual(len(s.search(kind="note")), 1)
        self.assertEqual(s.dropped, 3)
        mem.d["index"] = "garbage"
        s.add([a.mark("note", None, label="again", ref="y", t=2)])           # a broken index does not break writes

    def test_a_failed_save_is_an_error_not_a_silent_loss(self):
        with self.assertRaises(OSError):
            a.MarkStore(Mem(fail=True)).add([a.mark("note", None, label="x", t=1)])

    def test_refused_marks_are_counted_not_stored(self):
        s = a.MarkStore(Mem())
        self.assertEqual(s.add([{"k": "x", "v": 1.5}, a.mark("note", None, label="ok", t=1)]), 1)
        self.assertEqual(s.stats()["refused"], 1)


class TestWhoPassed(unittest.TestCase):
    def column(self, x0, y0, wv, dv, hv):
        return {(x, y, z) for x in range(x0, x0 + wv) for y in range(y0, y0 + dv) for z in range(hv)}

    def test_only_what_is_new_stands_out(self):
        bg = a.Background(keep=3)
        room = self.column(0, 0, 30, 2, 25) | self.column(0, 0, 30, 30, 1)
        for _ in range(4):
            bg.update(room)
        self.assertEqual(bg.new(room), set(), "an unchanged room has nothing new in it")
        person = self.column(10, 12, 4, 3, 17)                              # 400 x 300 x 1700 mm at 100 mm voxels
        found = a.blobs(bg.new(room | person))
        self.assertEqual(len(found), 1)
        ev = a.event_marks(found, 100, 5000)[0]
        self.assertIn("person-sized", ev["l"])
        self.assertEqual(ev["k"], "event")
        self.assertTrue(1000 <= ev["p"][0] <= 1500 and 1200 <= ev["p"][1] <= 1600, ev["p"])

    def test_something_big_and_flat_is_movement_not_a_person(self):
        found = a.blobs(self.column(0, 0, 30, 20, 3))
        self.assertNotIn("person", a.event_marks(found, 100, 1)[0]["l"])

    def test_specks_are_ignored(self):
        self.assertEqual(a.blobs({(0, 0, 0), (1, 0, 0)}), [])

    def test_two_people_far_apart_are_two_events(self):
        found = a.blobs(self.column(0, 0, 4, 3, 17) | self.column(60, 60, 4, 3, 17))
        self.assertEqual(len(found), 2)

    def test_a_slowly_moved_chair_settles_into_the_background(self):
        bg = a.Background(keep=3)
        chair = self.column(5, 5, 3, 3, 5)
        for _ in range(4):
            bg.update(chair)
        self.assertEqual(bg.new(chair), set())


class TestSource(unittest.TestCase):
    CORNERS = [(0, 0, 0), (2000, 0, 0), (0, 2000, 0), (2000, 2000, 0)]

    def readings(self, src, power=2, ambient=0, k=4_000_000_000):
        out = []
        for p in self.CORNERS:
            d2 = sum((p[i] - src[i]) ** 2 for i in range(3)) or 1
            out.append((p, ambient + k // (d2 if power == 2 else a.isqrt(d2) * 1000)))
        return out

    def err(self, got, want):
        return a.isqrt(sum((got[i] - want[i]) ** 2 for i in range(3)))

    def test_the_nearer_the_sensor_the_stronger_and_that_places_the_source(self):
        src = (500, 1500, 0)
        r = a.locate_source(self.readings(src), power=2, floor=0)
        self.assertLessEqual(self.err(r["at"], src), 300, r)
        self.assertLessEqual(r["spread"], 5)

    def test_with_a_background_level_given(self):
        src = (1500, 500, 0)
        r = a.locate_source(self.readings(src, ambient=100), power=2, floor=100)
        self.assertLessEqual(self.err(r["at"], src), 300, r)

    def test_a_source_outside_the_ring_is_one_of_two_places_and_both_are_reported(self):
        src = (3000, 1000, 0)
        r = a.locate_source(self.readings(src), power=2, floor=0)
        self.assertLessEqual(r["spread"], 5, "both fits are perfect: the ratios cannot tell them apart")
        self.assertIsNotNone(r["alt"])
        best = min(self.err(r["at"], src), self.err(r["alt"], src))
        self.assertLessEqual(best, 450, r)
        self.assertLess(r["at"][0], r["alt"][0], "the nearer fit is the one it names; the further one is alt")

    def test_a_source_inside_the_ring_is_not_confused_with_its_mirror(self):
        src = (700, 900, 0)
        r = a.locate_source(self.readings(src), power=2, floor=0)
        self.assertLessEqual(self.err(r["at"], src), 300, r)

    def test_a_slowly_fading_smell_uses_power_one(self):
        src = (1500, 1500, 0)
        r = a.locate_source(self.readings(src, power=1), power=1, floor=0)
        self.assertLessEqual(self.err(r["at"], src), 400, r)

    def test_nothing_stands_out_means_no_source(self):
        self.assertIsNone(a.locate_source([(p, 50) for p in self.CORNERS]))

    def test_sensors_that_disagree_report_it(self):
        bad = [(self.CORNERS[0], 1000), (self.CORNERS[1], 1000), (self.CORNERS[2], 5), (self.CORNERS[3], 900)]
        r = a.locate_source(bad, power=2, floor=0)
        self.assertGreater(r["spread"], 20, "two near readings at opposite ends cannot be one point source")

    def test_three_sensors_in_three_dimensions(self):
        src = (700, 800, 600)
        pts = [(0, 0, 0), (2000, 0, 0), (0, 2000, 0), (0, 0, 2000)]
        rd = [(p, 4_000_000_000 // (sum((p[i] - src[i]) ** 2 for i in range(3)))) for p in pts]
        r = a.locate_source(rd, power=2, floor=0)
        self.assertLessEqual(self.err(r["at"], src), 700, r)

    def test_too_few_sensors_is_refused(self):
        with self.assertRaises(ValueError):
            a.locate_source([((0, 0, 0), 5), ((1, 0, 0), 6)])


class TestSound(unittest.TestCase):
    def burst(self, n=400):
        g = rng(5)
        return [next(g) - 128 for _ in range(n)]

    def test_delay_between_two_microphones(self):
        s = self.burst()
        late = [0, 0, 0] + s[:-3]                    # b hears it 3 samples after a
        self.assertEqual(a.tdoa(s, late, 10), 3)
        self.assertEqual(a.tdoa(late, s, 10), -3)
        self.assertEqual(a.tdoa(s, s, 10), 0)

    def test_bearing(self):
        b = a.bearing_from_delay(3, 48000, 200)
        self.assertTrue(4 <= b <= 8, b)
        self.assertEqual(a.bearing_from_delay(-3, 48000, 200), -b)
        self.assertEqual(a.bearing_from_delay(0, 48000, 200), 0)
        self.assertIsNone(a.bearing_from_delay(40, 48000, 200), "longer than sound takes to cross the gap")

    def test_bad_recordings_are_refused(self):
        with self.assertRaises(ValueError):
            a.tdoa([1, 2, 3], [1, 2], 1)


ENTRIES = [
    {"path": "app", "dir": True, "size": 0},
    {"path": "app/main.py", "size": 100},
    {"path": "app/util.py", "size": 50},
    {"path": "app/sound.py", "size": 70},
    {"path": "docs", "dir": True, "size": 0},
    {"path": "docs/coffee.md", "size": 300},
    {"path": "docs/beans.md", "size": 310},
    {"path": "docs/roast.md", "size": 320},
    {"path": "docs/brew.md", "size": 330},
]
TEXTS = {
    "app/main.py": "from util import helper\nimport sound\nimport os\n" + "printer scanner printer scanner driver " * 3,
    "app/util.py": "def helper(): pass\n",
    "app/sound.py": "from util import helper\n" + "mixer speaker mixer speaker volume " * 3,
    "docs/coffee.md": "coffee espresso grinder coffee espresso grinder extraction crema " * 3,
    "docs/beans.md": "coffee espresso grinder beans roast crema extraction " * 3,
    "docs/roast.md": "coffee espresso grinder roast beans crema extraction " * 3,
    "docs/brew.md": "coffee espresso grinder brewing crema extraction " * 3,
}


class TestFiles(unittest.TestCase):
    def test_layout_gives_every_entry_its_own_place_and_is_stable(self):
        p1, p2 = a.layout(ENTRIES), a.layout(list(reversed(ENTRIES)))
        self.assertEqual(p1, p2, "the same tree gives the same town")
        self.assertEqual(len(p1), len(ENTRIES))
        self.assertEqual(len(set(p1.values())), len(ENTRIES), "no two things share a place")
        self.assertEqual(p1["app/main.py"][2], 1000, "one level down")
        self.assertEqual(p1["app"][2], 0)

    def test_words_and_references(self):
        self.assertEqual(a.keywords("the coffee coffee coffee roast roast and a", 2), ["coffee", "roast"])
        self.assertIn("util", a.references("from util import helper"))
        self.assertIn("./x.js", a.references("import y from './x.js'"))
        self.assertIn("a.h", a.references('#include "a.h"'))
        self.assertIn("doc.md", a.references("see [doc](doc.md)"))

    def test_file_marks_have_places_links_and_only_real_targets(self):
        marks = a.file_marks(ENTRIES, 100, texts=TEXTS)
        files = [m for m in marks if m["k"] == "file"]
        self.assertEqual(len(files), len(ENTRIES))
        self.assertTrue(all(m["p"] is not None and m["s"] == "files" for m in files))
        refs = {(m["r"], m["o"]) for m in marks if m["k"] == "link" and m["l"] == "references"}
        self.assertIn(("app/main.py", "app/util.py"), refs)
        self.assertIn(("app/main.py", "app/sound.py"), refs)
        self.assertFalse(any(o.endswith("os") or o == "os" for _, o in refs), "`import os` points at no file here")
        self.assertIn(("app", "app/main.py"), {(m["r"], m["o"]) for m in marks if m["l"] == "contains"})

    def test_the_whole_is_more_than_the_parts(self):
        marks = a.file_marks(ENTRIES, 100, texts=TEXTS)
        got = {m["k"]: m for m in a.themes(marks)}
        self.assertEqual(set(got), {"theme"})
        th = a.themes(marks)
        self.assertEqual(len(th), 1, "four coffee notes are one theme; the code files are not part of it")
        self.assertEqual(th[0]["v"], 4)
        self.assertIn("coffee", th[0]["l"])
        self.assertTrue(th[0]["p"][0] >= 2000, "placed among the docs, not at the origin")

    def test_hubs_and_look_alikes(self):
        marks = a.file_marks(ENTRIES + [{"path": "app/more.py", "size": 5}, {"path": "app/more2.py", "size": 5}], 1,
                             texts={**TEXTS, "app/more.py": "from util import helper\n", "app/more2.py": "import util\n"})
        hub = a.hubs(marks)
        self.assertEqual([(h["r"], h["v"]) for h in hub], [("app/util.py", 4)])
        marks = a.file_marks([{"path": "x.txt", "size": 9}, {"path": "y.txt", "size": 9}, {"path": "z.txt", "size": 8}], 1,
                             texts={"x.txt": "alpha beta gamma alpha", "y.txt": "alpha beta gamma alpha",
                                    "z.txt": "alpha beta gamma alpha"})
        tw = a.twins(marks)
        self.assertEqual([(t["v"], t["r"]) for t in tw], [(2, "x.txt")], "z.txt has another size")


class TestConsolidate(unittest.TestCase):
    def room(self, t):
        """A 4 m x 4 m floor, a wall 3 m wide and 2 m tall at y = 4 m, and a 600 x 500 x 900 mm object."""
        vx, out = 100, []
        for x in range(40):
            for y in range(40):
                out.append(a.mark("sight", (x * 100, y * 100, -1500), v=90, t=t))
        for x in range(30):
            for z in range(20):
                out.append(a.mark("sight", (x * 100, 4200, -1500 + z * 100 + 100), v=200, t=t))
        for x in range(6):
            for y in range(5):
                for z in range(9):
                    out.append(a.mark("sight", (1500 + x * 100, 1500 + y * 100, -1400 + z * 100), v=40, t=t))
        return out

    def test_thousands_of_voxels_become_a_floor_a_wall_and_an_object(self):
        s = a.MarkStore(Mem())
        s.add(self.room(1000))
        raw = s.stats()["marks"]
        before = s.chars()
        rep = s.consolidate(now=1000 + 7200, keep_s=3600)
        regs = s.search(kind="region", limit=50)
        names = sorted(m["l"].rsplit(" ", 3)[0] if False else m["l"] for m in regs)
        self.assertEqual(rep["regions"], 3, names)
        self.assertTrue(any(l.startswith("floor-like surface 4000x4000") for l in names), names)
        self.assertTrue(any(l.startswith("wall-like surface") for l in names), names)
        self.assertTrue(any(l.startswith("object") for l in names), names)
        self.assertEqual(s.search(kind="sight"), [], "the raw voxels are gone")
        self.assertGreater(raw, 2000)
        self.assertLess(rep["after"] * 20, before, f"{before} -> {rep['after']} characters")
        self.assertEqual(rep["voxels_digested"], raw)

    def test_recent_looks_are_left_alone(self):
        s = a.MarkStore(Mem())
        s.add(self.room(1000))
        rep = s.consolidate(now=1000 + 10, keep_s=3600)
        self.assertEqual(rep["voxels_digested"], 0)
        self.assertEqual(rep["regions"], 0)

    def test_doing_it_twice_changes_nothing(self):
        s = a.MarkStore(Mem())
        s.add(self.room(1000))
        s.consolidate(now=10_000)
        first = sorted(m["l"] for m in s.search(kind="region", limit=50))
        s.consolidate(now=20_000)
        self.assertEqual(sorted(m["l"] for m in s.search(kind="region", limit=50)), first)

    def test_a_second_look_at_the_same_floor_merges_into_it(self):
        s = a.MarkStore(Mem())
        s.add(self.room(1000))
        s.consolidate(now=10_000)
        s.add(self.room(20_000))
        s.consolidate(now=40_000)
        regs = s.search(kind="region", limit=50)
        self.assertEqual(len(regs), 3, [m["l"] for m in regs])

    def test_a_lone_speck_is_not_a_region(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("sight", (0, 0, 0), v=1, t=1), a.mark("sight", (100, 0, 0), v=1, t=1)])
        self.assertEqual(s.consolidate(now=99999)["regions"], 0)

    def test_movement_that_comes_back_becomes_a_routine(self):
        s = a.MarkStore(Mem())
        door = (1000, 2000, 900)
        day = 86400
        for d, jitter in enumerate((0, 420, -300, 600, -120)):          # five mornings, around 08:30 UTC
            s.add([a.mark("event", door, v=40, t=(100 + d) * day + 8 * 3600 + 1800 + jitter, label="person-sized movement")])
        s.add([a.mark("event", (9000, 9000, 900), v=40, t=100 * day + 15 * 3600, label="person-sized movement"),
               a.mark("event", (9000, 9000, 900), v=40, t=101 * day + 15 * 3600, label="person-sized movement")])
        s.consolidate(now=200 * day)
        r = s.search(kind="routine")
        self.assertEqual(len(r), 1, "two afternoons are not yet a habit")
        self.assertEqual(r[0]["n"], 5)
        self.assertTrue(8 * 60 + 25 <= r[0]["v"] <= 8 * 60 + 40, r[0]["v"])
        self.assertIn("08:", r[0]["l"])
        s.consolidate(now=201 * day)
        self.assertEqual(s.search(kind="routine")[0]["n"], 5, "recomputed, not added up again")

    def test_several_noses_find_where_the_smell_comes_from(self):
        s = a.MarkStore(Mem())
        src = (500, 1500, 0)
        for i, p in enumerate(TestSource.CORNERS):
            d2 = sum((p[j] - src[j]) ** 2 for j in range(3))
            s.add([a.mark("smell", p, v=4_000_000_000 // d2 + 100, ref=f"nose-{i}", t=1000, unit="ohm")])
        s.consolidate(now=5000, floors={"smell": 100})              # clean air reads 100
        found = s.search(kind="source")
        self.assertEqual(len(found), 1)
        self.assertIn("smell source", found[0]["l"])
        self.assertLessEqual(a.isqrt(sum((found[0]["p"][i] - src[i]) ** 2 for i in range(3))), 400)
        # without being told what clean air reads, the lowest sensor is the floor: still close, less exact
        s2 = a.MarkStore(Mem())
        s2.add(s.search(kind="smell"))
        s2.consolidate(now=5000)
        rough = s2.search(kind="source")[0]
        self.assertLessEqual(a.isqrt(sum((rough["p"][i] - src[i]) ** 2 for i in range(3))), 800)

    def test_files_become_themes_hubs_and_twins_in_the_store(self):
        s = a.MarkStore(Mem())
        s.add(a.file_marks(ENTRIES, 50, texts=TEXTS))
        rep = s.consolidate(now=99)
        self.assertEqual(rep["theme"], 1)
        self.assertEqual([m["v"] for m in s.search(kind="theme")], [4])
        found = s.search(text="coffee", kind="theme")
        self.assertEqual(len(found), 1)

    def test_a_hostile_shared_folder_cannot_break_consolidation(self):
        mem = Mem()
        s = a.MarkStore(mem)
        s.add(self.room(1000)[:50])
        key = [k for k in mem.keys() if k.startswith("c.")][0]
        mem.d[key] = json.dumps([{"k": "sight", "p": [0, 0, 0], "v": 1, "t": 1, "n": 1}, {"k": "sight", "p": [1.5, 0, 0]},
                                 {"k": "region", "r": "box:1,2,x", "p": [0, 0, 0], "v": 3, "t": 1, "l": "object"}])
        s.consolidate(now=99999)                                              # does not raise


class TestAnything(unittest.TestCase):
    """The map is not about pictures. A number about anything, in any space, is a mark."""

    DAY = 86400

    def test_how_many_people_liked_a_video_is_a_mark_and_the_map_sees_the_trend(self):
        s = a.MarkStore(Mem())
        for i, likes in enumerate((100, 180, 300, 520, 900)):             # an hour apart, growing
            s.add([a.mark("likes", None, v=likes, t=1000 + 3600 * i, ref="video:cats", unit="likes", space="videos")])
        s.consolidate(now=99999)
        tr = s.search(kind="trend")
        self.assertEqual(len(tr), 1)
        self.assertIn("rising", tr[0]["l"])
        self.assertGreater(tr[0]["v"], 100, "per hour")
        self.assertEqual(tr[0]["r"], "video:cats")

    def test_a_steady_count_has_no_trend_and_a_sudden_jump_is_a_spike(self):
        s = a.MarkStore(Mem())
        for i in range(5):
            s.add([a.mark("likes", None, v=100, t=1000 + 3600 * i, ref="video:flat", unit="likes")])
            s.add([a.mark("likes", None, v=100 if i < 4 else 400, t=1000 + 3600 * i, ref="video:spike", unit="likes")])
        s.consolidate(now=99999)
        got = {m["r"]: m["l"] for m in s.search(kind="trend")}
        self.assertNotIn("video:flat", got)
        self.assertIn("spiked", got["video:spike"])

    def test_falling_works_the_same_for_a_smell(self):
        s = a.MarkStore(Mem())
        for i, ohm in enumerate((50000, 41000, 33000, 26000, 20000)):
            s.add([a.mark("smell", (0, 0, 0), v=ohm, t=1000 + 1800 * i, ref="nose-1", unit="ohm")])
        s.consolidate(now=99999)
        self.assertIn("falling", s.search(kind="trend")[0]["l"])

    def test_too_few_readings_are_not_a_trend(self):
        marks = [a.mark("likes", None, v=v, t=1000 + 3600 * i, ref="x") for i, v in enumerate((1, 50, 900))]
        self.assertEqual(a.trends(marks), [])

    def test_everything_about_one_thing_in_one_place(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("likes", None, v=900, t=5000, ref="video:cats", unit="likes", space="videos"),
               a.mark("likes", None, v=100, t=1000, ref="video:cats", unit="likes", space="videos"),
               a.mark("sight", (0, 0, 0), v=120, t=3000, ref="video:cats", space="videos"),
               a.mark("note", None, label="my favourite", t=4000, ref="video:cats", space="videos"),
               a.mark("likes", None, v=7, t=4000, ref="video:dogs", unit="likes", space="videos")])
        card = s.about("video:cats")
        self.assertEqual(set(card), {"likes", "sight", "note"})
        self.assertEqual((card["likes"]["latest"], card["likes"]["marks"]), (900, 2), "the newest value, over both readings")
        self.assertEqual(s.about("video:nothing"), {})

    def test_a_place_in_any_space_not_only_the_world(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("likes", (10, 20, 0), v=5, t=1, ref="a", space="videos"),
               a.mark("likes", (10, 20, 0), v=9, t=1, ref="b", space="people")])
        self.assertEqual([m["r"] for m in s.search(kind="likes", space="videos")], ["a"])
        mid = (50, 50, 50)                              # marks sit in the middle of their 100 mm cell
        self.assertEqual(len(s.search(near=mid, radius=5)), 2)
        self.assertEqual(len(s.search(near=mid, radius=5, space="people")), 1)
        self.assertEqual(s.search(near=(10, 20, 0), radius=5), [], "the query is not where the cell's middle is")


class TestPutDataInSpace(unittest.TestCase):
    A = ("The espresso machine needs descaling every month. Descale with citric acid, rinse the boiler, "
         "then flush the group head. Skipping descaling ruins the pump and the thermostat.")
    A2 = ("The espresso machine needs descaling every month. Descale with citric acid, rinse the boiler, "
          "then flush the group head. Skipping descaling ruins the pump and the heating element.")     # one phrase changed
    B = ("Quarterly tax filing deadlines: submit the estimated payment, reconcile invoices, archive receipts, "
         "and confirm the accountant received the signed forms before the filing window closes.")

    def test_a_text_has_a_place_and_the_same_words_give_the_same_place(self):
        p = a.embed(self.A)
        self.assertEqual(len(p), 3)
        self.assertEqual(p, a.embed(self.A))
        self.assertEqual(a.embed("coffee grinder espresso"), a.embed("espresso   GRINDER, coffee!"), "order and case do not matter")
        self.assertIsNone(a.embed("the and of"))
        self.assertIsNone(a.embed(""))

    def test_similar_texts_land_near_each_other_and_unrelated_ones_far_away(self):
        d = lambda p, q: a.isqrt(sum((x - y) ** 2 for x, y in zip(p, q)))
        near = d(a.embed(self.A), a.embed(self.A2))
        far = d(a.embed(self.A), a.embed(self.B))
        self.assertLess(near * 3, far, (near, far))
        self.assertLessEqual(a.hamming(a.simhash(self.A), a.simhash(self.A2)), 8)
        self.assertGreaterEqual(a.hamming(a.simhash(self.A), a.simhash(self.B)), 16)

    def test_redundant_data_goes_and_nothing_is_lost_but_the_repetition(self):
        s = a.MarkStore(Mem())
        marks = [a.data_mark(self.A, ref="notes/a.txt", t=100, n=3),
                 a.data_mark(self.A, ref="backup/a.txt", t=200, n=1),                   # an exact copy somewhere else
                 a.data_mark(self.A2, ref="notes/a-v2.txt", t=300, n=2),               # an edited copy
                 a.data_mark(self.B, ref="tax.txt", t=150, n=1)]
        s.add(marks)
        before = sum(m["n"] for m in s.search(kind="data", limit=50))
        chars = s.chars()
        rep = s.consolidate(now=1000)
        left = s.search(kind="data", limit=50)
        self.assertEqual(len(left), 2, "the three copies are one; the tax note stays")
        self.assertEqual(rep["duplicates_merged"], 2)
        self.assertEqual(sum(m["n"] for m in left), before, "every observation is still counted")
        best = [m for m in left if "descal" in m["l"].lower() or m["r"].startswith(("notes", "backup"))][0]
        self.assertEqual(best["n"], 6)
        self.assertEqual(best["t"], 300, "the newest time")
        self.assertEqual(best["r"], "notes/a.txt", "the most corroborated copy is the one kept")
        self.assertLess(s.chars(), chars)

    def test_unrelated_data_is_never_merged(self):
        s = a.MarkStore(Mem())
        s.add([a.data_mark(self.A, ref="a", t=1), a.data_mark(self.B, ref="b", t=1)])
        self.assertEqual(s.consolidate(now=100)["duplicates_merged"], 0)
        self.assertEqual(len(s.search(kind="data")), 2)

    def test_data_in_different_spaces_is_not_merged(self):
        s = a.MarkStore(Mem())
        s.add([a.data_mark(self.A, ref="a", t=1, space="work"), a.data_mark(self.A, ref="b", t=1, space="home")])
        s.consolidate(now=100)
        self.assertEqual(len(s.search(kind="data")), 2)

    def test_finding_what_is_like_this_even_in_new_words(self):
        s = a.MarkStore(Mem())
        s.add([a.data_mark(self.A, ref="a", t=1), a.data_mark(self.B, ref="b", t=1)])
        got = s.similar(self.A2)
        self.assertEqual([m["r"] for m in got], ["a"])
        self.assertEqual(s.similar("zzz qqq xxx"), [])
        self.assertEqual(s.similar("the and"), [])

    def test_a_forged_fingerprint_cannot_break_it(self):
        bad = a.clean_mark({"k": "data", "p": [1, 2, 3], "v": 1, "t": 1, "o": "sig:zzzzzzzzzzzzzzzz", "r": "x"})
        short = a.clean_mark({"k": "data", "p": [1, 2, 3], "v": 1, "t": 1, "o": "sig:12", "r": "y"})
        self.assertEqual(a.dedupe([bad, short]), ([], []))


class TestGoodDataIsKept(unittest.TestCase):
    def test_a_full_chunk_forgets_the_uncorroborated_not_the_oldest(self):
        with unittest.mock.patch.object(a, "MAX_CHUNK_MARKS", 40):
            s = a.MarkStore(Mem())
            s.add([a.mark("smell", (0, 0, 0), v=1, t=10, ref="proven", n=50, unit="x")])           # old, seen 50 times
            s.add([a.mark("smell", (0, 0, 0), v=1, t=1000 + i * 120, ref=f"once-{i}", unit="x") for i in range(120)])
            refs = {m["r"] for m in s.search(kind="smell", limit=200)}
        self.assertIn("proven", refs, "seen fifty times, so kept although it is the oldest by far")
        self.assertLess(len(refs), 100)

    def test_what_was_worked_out_outlives_raw_readings(self):
        with unittest.mock.patch.object(a, "MAX_CHUNK_MARKS", 20):
            s = a.MarkStore(Mem())
            s.add([a.mark("region", (0, 0, 0), v=1, t=1, label="object 1x1x1 mm", ref="box:0,0,0,1,1,1")])
            s.add([a.mark("smell", (0, 0, 0), v=1, t=500 + i * 120, ref=f"r{i}", unit="x") for i in range(60)])
            self.assertEqual(len(s.search(kind="region")), 1)

    def test_lone_old_specks_are_dropped_as_noise_but_repeated_ones_stay(self):
        s = a.MarkStore(Mem())
        s.add([a.mark("sight", (50, 50, 50), v=9, t=10, n=1),                     # a speck, seen once
               a.mark("sight", (5050, 5050, 5050), v=9, t=10, n=1),
               a.mark("sight", (9050, 50, 50), v=9, t=10, n=4)])                   # seen four times, but alone
        rep = s.consolidate(now=100_000)
        self.assertEqual(rep["noise_dropped"], 2)
        left = s.search(kind="sight")
        self.assertEqual([m["n"] for m in left], [4])


class TestIngestAnything(unittest.TestCase):
    """Random files, random text, random bytes: all of it gets a place, and what repeats collapses."""

    @staticmethod
    def noise(n, seed):
        import random
        r = random.Random(seed)
        return bytes(r.getrandbits(8) for _ in range(n))

    def test_nothing_is_refused_for_being_strange(self):
        weird = [b"", b"\x00", b"\xff" * 10, "   ", "\n", "日本語のテキストです", "emoji \U0001f600\U0001f680", self.noise(5000, 1),
                 b"\x89PNG\r\n\x1a\n" + self.noise(300, 2), "x" * 500_000, b"%PDF-1.4 " + self.noise(100, 3),
                 "the and of it", "\x1b[2J\x00weird", bytes(range(256)) * 50]
        for i, data in enumerate(weird):
            m = a.ingest(f"thing{i}", data, t=5)
            self.assertEqual(m["k"], "data")
            self.assertEqual(len(m["p"]), 3, i)
            self.assertTrue(m["o"].startswith("sig:") and len(m["o"]) == 20)
            self.assertGreater(m["v"], 0)
            for c in m["l"]:
                self.assertTrue(c.isprintable(), (i, m["l"]))

    def test_it_says_what_it_is_without_pretending_to_understand_it(self):
        self.assertIn("binary", a.ingest("r.bin", self.noise(2000, 4))["l"])
        self.assertIn("png image", a.ingest("p", b"\x89PNG\r\n\x1a\n" + self.noise(50, 5))["l"])
        self.assertIn("text", a.ingest("n.txt", "Hello there\nsecond line")["l"])
        self.assertIn("Hello there", a.ingest("n.txt", "Hello there\nsecond line")["l"], "a text gets its first line as a title")
        for head, want in ((b"%PDF-1.7", "pdf"), (b"PK\x03\x04xx", "zip"), (b"\x7fELFxx", "program"), (b"RIFF\0\0\0\0WAVEfmt ", "wav"),
                           (b"\0\0\0\x20ftypisom", "mp4"), (b"GIF89a", "gif"), (b"\xff\xd8\xff\xe0", "jpeg")):
            self.assertIn(want, a.sniff(head))
        self.assertEqual(a.sniff(self.noise(100, 6)), "binary")

    def test_the_real_size_is_used_when_only_the_start_of_a_file_is_at_hand(self):
        m = a.ingest("movie.mp4", b"\0\0\0\x20ftypisom" + self.noise(100, 20), size=7_000_000)
        self.assertIn("7000000 bytes", m["l"])
        self.assertIn("mp4 video", m["l"])

    def test_text_or_not(self):
        for ok in (b"plain ascii", "café crème".encode(), "日本語".encode(), b"tabs\tand\nnewlines\r\n", b""):
            self.assertTrue(a.is_text(ok), ok)
        for bad in (b"a\x00b", self.noise(500, 7), bytes(range(32)) * 4):
            self.assertFalse(a.is_text(bad))

    def test_two_different_random_files_stay_two_and_far_apart(self):
        s = a.MarkStore(Mem())
        s.add([a.ingest("a.bin", self.noise(20000, 10), t=1), a.ingest("b.bin", self.noise(20000, 11), t=1)])
        self.assertEqual(s.consolidate(now=100)["duplicates_merged"], 0)
        got = s.search(kind="data")
        d = a.isqrt(sum((x - y) ** 2 for x, y in zip(got[0]["p"], got[1]["p"])))
        self.assertGreater(d, 20000)

    def test_copies_collapse_whatever_they_are_called_and_wherever_they_sit(self):
        blob = self.noise(30000, 12)
        s = a.MarkStore(Mem())
        s.add([a.ingest("holiday.jpg", b"\xff\xd8\xff" + blob, t=1, ref="photos/holiday.jpg"),
               a.ingest("copy of holiday.jpg", b"\xff\xd8\xff" + blob, t=2, ref="backup/holiday.jpg"),
               a.ingest("other.jpg", b"\xff\xd8\xff" + self.noise(30000, 13), t=3, ref="photos/other.jpg")])
        rep = s.consolidate(now=100)
        self.assertEqual(rep["duplicates_merged"], 1)
        got = s.search(kind="data")
        self.assertEqual(sorted(m["n"] for m in got), [1, 2], "the copy is counted, not lost")

    def test_a_slightly_changed_copy_and_a_copy_with_something_added_in_front_collapse_too(self):
        blob = self.noise(100000, 14)
        edited = bytearray(blob)
        for i in range(0, len(edited), 100):
            edited[i] ^= 0xFF                                   # one byte in a hundred changed
        s = a.MarkStore(Mem())
        s.add([a.ingest("a.bin", blob, t=1), a.ingest("a-edited.bin", bytes(edited), t=2),
               a.ingest("a-with-header.bin", b"A HEADER ADDED" + blob, t=3), a.ingest("z.bin", self.noise(100000, 15), t=4)])
        self.assertEqual(s.consolidate(now=100)["duplicates_merged"], 2)
        self.assertEqual(sorted(m["n"] for m in s.search(kind="data")), [1, 3])

    def test_text_typed_in_and_the_same_text_in_a_file_collapse(self):
        s = a.MarkStore(Mem())
        note = TestPutDataInSpace.A
        s.add([a.ingest("pasted note", note, t=1), a.ingest("notes.txt", note.encode(), t=2)])
        self.assertEqual(s.consolidate(now=100)["duplicates_merged"], 1)

    def test_a_megabyte_of_noise_is_quick_and_too_big_is_refused(self):
        t = time.monotonic_ns()
        a.ingest("big.bin", self.noise(1 << 20, 16))
        self.assertLess((time.monotonic_ns() - t) // 1_000_000, 3000)
        with unittest.mock.patch.object(a, "MAX_INGEST", 100):
            with self.assertRaises(ValueError):
                a.ingest("x", bytes(101))

    def test_a_name_places_what_has_nothing_else_to_place_it_by(self):
        one, two, again = (a.ingest("quarterly-report.txt", b""), a.ingest("holiday-photos.txt", b""),
                           a.ingest("quarterly-report.txt", b""))
        self.assertEqual(one["p"], again["p"], "the same name gives the same place")
        self.assertNotEqual(one["p"], two["p"], "two empty files with different names are not the same place")
        self.assertNotEqual(one["o"], two["o"])

    def test_the_map_holds_all_kinds_of_things_together_and_finds_each(self):
        s = a.MarkStore(Mem())
        s.add([a.ingest("recipe.txt", "Espresso: grind fine, tamp firmly, pull a thirty second shot.", t=1),
               a.ingest("photo.png", b"\x89PNG\r\n\x1a\n" + self.noise(4000, 17), t=2),
               a.mark("likes", None, v=900, t=3, ref="photo.png", unit="likes", space="mind"),
               a.mark("smell", (100, 100, 100), v=12000, t=4, ref="nose-1", unit="ohm", label="coffee", space="mind")])
        self.assertEqual({m["k"] for m in s.search(text="")} , {"data", "likes", "smell"})
        self.assertEqual([m["k"] for m in s.search(text="photo.png")].count("likes"), 1)
        card = s.about("photo.png")
        self.assertEqual(set(card), {"data", "likes"}, "the file and its likes are one thing")
        self.assertEqual(card["likes"]["latest"], 900)


class Flaky(Mem):
    """A store whose Nth write fails (and every one after it), as a full or read-only folder would."""

    def __init__(self, fail_from):
        super().__init__()
        self.fail_from, self.puts = fail_from, 0

    def put(self, k, v):
        self.puts += 1
        if self.puts >= self.fail_from:
            return False
        return super().put(k, v)


class TestAFailedWriteNeverLosesData(unittest.TestCase):
    def test_whichever_write_fails_every_observation_is_still_on_the_map(self):
        notes = [a.ingest("a.txt", TestPutDataInSpace.A, t=100, n=3, ref="notes/a.txt"),
                 a.ingest("a.txt", TestPutDataInSpace.A, t=200, n=1, ref="backup/a.txt"),
                 a.ingest("a2.txt", TestPutDataInSpace.A2, t=300, n=2, ref="notes/a-v2.txt"),
                 a.ingest("tax.txt", TestPutDataInSpace.B, t=150, n=1, ref="tax.txt")]
        raw = [a.mark("sight", (x * 100, y * 100, -1500), v=90, t=1000) for x in range(40) for y in range(40)]
        probes = []
        for fail_from in range(1, 40):
            m = Flaky(10 ** 9)
            s = a.MarkStore(m)
            s.add(notes + raw + [a.mark("note", None, label="later", t=1000 + 7200, ref="n")])
            total = sum(x["n"] for x in s.search(kind="data", limit=50))
            m.fail_from, m.puts = fail_from, 0
            try:
                s.consolidate(now=1000 + 7200)
                failed = False
            except OSError:
                failed = True
            probes.append(failed)
            if failed:
                after = sum(x["n"] for x in s.search(kind="data", limit=50))
                self.assertGreaterEqual(after, total, f"a failure at write {fail_from} lost observations")
                refs = {x["r"] for x in s.search(kind="data", limit=50)}
                self.assertIn("tax.txt", refs)
                self.assertTrue(refs & {"notes/a.txt", "backup/a.txt", "notes/a-v2.txt"}, f"the note vanished at write {fail_from}")
                raw_left = len(s.search(kind="sight", limit=200)) + len(s.search(kind="region", limit=200))
                self.assertGreater(raw_left, 0, f"the room vanished at write {fail_from}")
        self.assertTrue(any(probes), "the failures were really injected")
        self.assertTrue(any(not p for p in probes), "and consolidation completes once enough writes are allowed")

    def test_a_failed_write_is_an_error_everywhere_not_a_quiet_skip(self):
        s = a.MarkStore(Flaky(10 ** 9))
        s.add([a.mark("note", None, label="x", t=1, ref="x")])
        s.b.fail_from, s.b.puts = 1, 0
        with self.assertRaises(OSError):
            s.consolidate(now=100)
        with self.assertRaises(OSError):
            s.add([a.mark("note", None, label="y", t=2, ref="y")])


import unittest.mock  # noqa: E402


if __name__ == "__main__":
    unittest.main()
