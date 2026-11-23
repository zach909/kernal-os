"""The load effect (kos/reveal.py): arrival (point -> bounding box -> hull -> unblur) and 3D layers.
Run with: python3 -m unittest discover -s tests

Nothing here is a Z3 proof: the hull and the band are checked by trying to break them on random shapes."""

import importlib.util
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import protocol, reveal as R, vectorize as V  # noqa: E402
from kos.display import Framebuffer, parse_color  # noqa: E402
from kos.sdk import App, Canvas  # noqa: E402

BG, A, B, C = "#2a3a52", "#d05050", "#50c070", "#e8d040"


def blank(w, h, c=BG):
    return [[c] * w for _ in range(h)]


def fill(g, x0, y0, x1, y1, c):
    for y in range(y0, y1):
        for x in range(x0, x1):
            g[y][x] = c


def demo(w=60, h=40):
    g = blank(w, h)
    fill(g, 4, 4, 56, 36, "#6a7fa0")
    fill(g, 9, 9, 30, 20, A)
    fill(g, 35, 10, 50, 30, B)
    fill(g, 12, 12, 20, 17, "#f0f0f0")
    for y in range(22, 34):
        for x in range(8, 28):
            if (x - 17) ** 2 + (y - 28) ** 2 <= 25:
                g[y][x] = C
    return g


def ok_frame(test, ops):
    protocol.validate_app_message({"cmd": "frame", "ops": ops}, "graphical")
    test.assertLessEqual(len(ops), protocol.MAX_OPS)


def render(ops, w, h, ui="#101820"):
    fb = Framebuffer(w, h)
    fb.clear(parse_color(ui))
    fb.apply(ops)
    return fb


def inside(poly, p):
    n = len(poly)
    return all(R._cross(poly[i], poly[(i + 1) % n], p) >= 0 for i in range(n))


class TestHull(unittest.TestCase):
    def test_hull_holds_every_point_and_is_convex_counter_clockwise(self):
        rnd = random.Random(3)
        for _ in range(200):
            pts = [(rnd.randrange(-20, 20), rnd.randrange(-20, 20)) for _ in range(rnd.randrange(3, 40))]
            h = R.hull(pts)
            if len(h) < 3:
                continue
            self.assertTrue(all(inside(h, p) for p in pts))
            n = len(h)
            self.assertTrue(all(R._cross(h[i], h[(i + 1) % n], h[(i + 2) % n]) > 0 for i in range(n)))

    def test_a_thing_hull_holds_all_its_pixels_and_is_pressed_on_every_extreme(self):
        rnd = random.Random(5)
        for _ in range(30):
            g = blank(24, 24)
            for _ in range(rnd.randrange(1, 6)):
                x, y = rnd.randrange(0, 18), rnd.randrange(0, 18)
                fill(g, x, y, x + rnd.randrange(1, 7), y + rnd.randrange(1, 7), rnd.choice([A, B, C]))
            for th in R.Scene(g).things:
                for px, py in th.pixels:
                    for cx, cy in ((px, py), (px + 1, py), (px, py + 1), (px + 1, py + 1)):
                        self.assertTrue(inside(th.hull, (cx, cy)))
                x0, y0, x1, y1 = th.bbox
                for edge in (min(p[0] for p in th.hull) == x0, max(p[0] for p in th.hull) == x1 + 1,
                             min(p[1] for p in th.hull) == y0, max(p[1] for p in th.hull) == y1 + 1):
                    self.assertTrue(edge)           # the band touches all four sides of the box
                self.assertTrue(inside(th.hull, th.center))


class TestBand(unittest.TestCase):
    def setUp(self):
        self.scene = R.Scene(demo(), 20, 20, 3)

    def test_the_band_starts_on_the_box_ends_on_the_hull_and_stays_on_its_ray(self):
        for th in self.scene.things:
            x0, y0, x1, y1 = th.bbox[0], th.bbox[1], th.bbox[2] + 1, th.bbox[3] + 1
            self.assertGreaterEqual(len(th.band), 4)
            for start, end in th.band:
                self.assertTrue(x0 <= start[0] <= x1 and y0 <= start[1] <= y1)
                self.assertTrue(start[0] in (x0, x1) or start[1] in (y0, y1), "start is on the box edge")
                n = len(th.hull)
                for i in range(n):          # on or inside the hull, to within the rounding of one pixel
                    p, q = th.hull[i], th.hull[(i + 1) % n]
                    self.assertGreaterEqual(R._cross(p, q, end), -(abs(q[0] - p[0]) + abs(q[1] - p[1])))
                # collinear with the centre, up to the whole-number rounding of one pixel
                cross = abs(R._cross(th.center, start, end))
                self.assertLessEqual(cross, 2 * max(x1 - x0, y1 - y0))

    def test_the_band_never_grows_back_out_while_it_shrinks(self):
        for th in self.scene.things:
            for a, b in th.band:
                prev = None
                for t in range(0, 9):
                    p = (R._lerp(a[0], b[0], t, 8), R._lerp(a[1], b[1], t, 8))
                    d = abs(p[0] - th.center[0]) + abs(p[1] - th.center[1])
                    self.assertTrue(prev is None or d <= prev + 1)
                    prev = d

    def test_a_round_thing_band_ends_tighter_than_its_box(self):
        circle = [t for t in self.scene.things if t.color == 0xe8d040][0]
        x0, y0, x1, y1 = circle.bbox
        box_area = (x1 - x0 + 1) * (y1 - y0 + 1)
        h = circle.hull
        area2 = abs(sum(h[i][0] * h[(i + 1) % len(h)][1] - h[(i + 1) % len(h)][0] * h[i][1] for i in range(len(h))))
        self.assertLess(area2, 2 * box_area)
        self.assertGreaterEqual(area2, 2 * len(circle.pixels))


class TestArrival(unittest.TestCase):
    def test_every_frame_passes_the_protocol_and_the_last_is_the_exact_picture(self):
        s = R.Scene(demo(), 20, 20, 3)
        frames = s.frames()
        self.assertGreater(len(frames), 8)
        for f in frames:
            ok_frame(self, f)
        self.assertEqual(frames[-1], s.flat().ops)
        pix = demo()
        fb = render(frames[-1], 240, 180)
        for j in range(40):
            for i in range(60):
                want = tuple(int(pix[j][i][k:k + 2], 16) for k in (1, 3, 5))
                self.assertEqual(fb.pixel(20 + i * 3 + 1, 20 + j * 3 + 1), want)

    def test_it_starts_blurred_into_the_interface_background_and_sharpens(self):
        s = R.Scene(demo(), 0, 0, 1, ui_color="#000000")
        first = render(s._blurred(*s.levels()[0], 4000), 60, 40, "#000000")
        last = render(s.frames()[-1], 60, 40, "#000000")
        # the red button is dimmer at the start (mixed with black) and exactly red at the end
        r0, r1 = first.pixel(25, 15)[0], last.pixel(25, 15)[0]
        self.assertLess(r0, r1)
        self.assertEqual(r1, 0xd0)
        for lv in zip(s.levels()[:-1], s.levels()[1:]):                  # blur falls, blend rises
            self.assertGreaterEqual(lv[0][0], lv[1][0])
            self.assertLessEqual(lv[0][1], lv[1][1])
        self.assertEqual(s.levels()[-1], (1, R.MIX))

    def test_seed_then_bands_grow_to_the_box_then_shrink_to_the_hull(self):
        s = R.Scene(demo(), 0, 0, 1)
        n = 4
        fr = s.frames(steps=n)
        bands = lambda ops: [o for o in ops if o[-1] == R.BAND_COLOR]   # noqa: E731
        self.assertTrue(all(o[0] == "rect" and o[3] == 3 for o in bands(fr[0])))      # a point each
        last_expand = bands(fr[n])                                       # the biggest box
        th = s.things[0]
        xs = [o[1] for o in last_expand if o[0] == "line"] + [o[3] for o in last_expand if o[0] == "line"]
        self.assertEqual((min(xs), max(xs)), (0, 60))                    # the biggest thing spans the picture
        self.assertTrue(bands(fr[2 * n]))                                # still wrapping on the last vacuum step
        self.assertEqual(len(bands(fr[-1])), 0)                          # the band is gone at the end
        self.assertTrue(th.band)

    def test_budget_is_kept_for_a_busy_picture_and_the_big_things_win(self):
        rnd = random.Random(9)
        g = blank(80, 80)
        for _ in range(60):
            x, y = rnd.randrange(0, 70), rnd.randrange(0, 70)
            fill(g, x, y, x + rnd.randrange(1, 9), y + rnd.randrange(1, 9), "#%06x" % rnd.randrange(1 << 24))
        s = R.Scene(g)
        for budget in (50, 300, 1500, 4000):
            for f in s.frames(max_ops=budget):
                self.assertLessEqual(len(f), budget)
                ok_frame(self, f)

    def test_the_same_picture_gives_the_same_frames(self):
        self.assertEqual(R.Scene(demo(), 5, 5, 2).frames(), R.Scene(demo(), 5, 5, 2).frames())


class TestVectorizeBlur(unittest.TestCase):
    def test_min_downscale_forces_a_blur(self):
        pix = demo()
        self.assertTrue(V.vectorize(pix).lossless)
        r = V.vectorize(pix, min_downscale=4)
        self.assertFalse(r.lossless)
        self.assertGreaterEqual(r.downscale, 4)
        for bad in (0, -1, 1.5, "2", None, V.MAX_SIDE + 1, True):
            with self.assertRaises(ValueError):
                V.vectorize(pix, min_downscale=bad)


class TestStandingUp(unittest.TestCase):
    def setUp(self):
        self.pix = demo()
        self.scene = R.Scene(self.pix, 20, 20, 3, layer_height=8)

    def test_layers_are_by_containment(self):
        by = {t.color: t.layer for t in self.scene.things}
        self.assertEqual(by[0xe8d040], 1)
        self.assertEqual(by[0xd05050], 1)
        self.assertEqual(by[0xf0f0f0], 2)                 # the white label sits on the red button

    def test_every_render_passes_the_protocol_for_any_mouse_and_any_sun(self):
        for vp in ((0, 0), (120, 90), (239, 179), (-500, 900), (16384, -16384)):
            for light in ((-1, -1), (0, -1), (1, 0), (9, -9), (-3, 2)):
                self.scene.set_light(light)
                for rise in ((0, 1), (1, 5), (1, 1)):
                    r = self.scene.render(vp, rise)
                    ok_frame(self, r.ops)

    def test_nothing_is_lifted_at_zero_rise(self):
        r = self.scene.render((100, 100), (0, 1))
        self.assertEqual(r.ops, self.scene.flat().ops)

    def test_the_picture_moves_away_from_the_vanishing_point_as_it_rises(self):
        # a single red box: with the mouse left of it, its raised top lands further right
        g = blank(20, 20)
        fill(g, 8, 8, 14, 14, A)
        s = R.Scene(g, 0, 0, 4, layer_height=8)
        left, right = s.render((0, 40)), s.render((200, 40))
        top = lambda r: [o for o in r.ops if o[0] == "rect" and o[-1] == "#" + "%06x" % R.shade(0xd05050, 105)]  # noqa: E731
        self.assertGreater(top(left)[0][1], top(right)[0][1])
        self.assertGreater(top(left)[0][1], 8 * 4)             # raised towards the viewer: pushed out
        self.assertLess(top(right)[0][1], 8 * 4)

    def test_only_walls_that_face_the_vanishing_point_are_drawn(self):
        g = blank(20, 20)
        fill(g, 8, 8, 14, 14, A)
        s = R.Scene(g, 0, 0, 4, layer_height=8)
        thin_v = lambda r: [o for o in r.ops if o[0] == "rect" and o[3] == 1 and o[4] > 1]    # noqa: E731
        thin_h = lambda r: [o for o in r.ops if o[0] == "rect" and o[4] == 1 and o[3] > 1]    # noqa: E731
        left = s.render((0, 44))                                    # level with the box, to its left
        self.assertTrue(thin_v(left) and not thin_h(left))          # only its left wall faces the mouse
        centre = s.render((44, 44))                                 # inside the box: nothing faces it
        self.assertFalse(thin_h(centre) or thin_v(centre))
        self.assertEqual(len(s._edges(s.things[0])), 4)

    def test_the_sun_shades_the_walls_and_moves_the_shadow(self):
        g = blank(20, 20)
        fill(g, 8, 8, 14, 14, A)
        s = R.Scene(g, 0, 0, 4, layer_height=8)
        shadow = "#" + "%06x" % R.shade(0x2a3a52, 55)
        for light, sign in (((-1, -1), 1), ((1, 1), -1)):
            s.set_light(light)
            sh = [o for o in s.render((10, 10)).ops if o[-1] == shadow][0]
            self.assertEqual((sh[1] - 32) * sign > 0, True)           # sun top-left: shadow falls right/down
            self.assertEqual((sh[2] - 32) * sign > 0, True)
        s.set_light((-1, 0))
        walls_lit = {o[-1] for o in s.render((0, 44)).ops if o[0] == "rect" and o[3] == 1 and o[4] > 1}
        s.set_light((1, 0))
        walls_dark = {o[-1] for o in s.render((0, 44)).ops if o[0] == "rect" and o[3] == 1 and o[4] > 1}
        self.assertNotEqual(walls_lit, walls_dark)
        self.assertGreater(int(sorted(walls_lit)[0][1:3], 16), int(sorted(walls_dark)[0][1:3], 16))

    def test_a_busy_picture_gives_up_walls_then_shadows_then_lifting_never_the_budget(self):
        rnd = random.Random(4)
        g = blank(60, 60)
        for _ in range(40):
            x, y = rnd.randrange(0, 52), rnd.randrange(0, 52)
            fill(g, x, y, x + rnd.randrange(2, 9), y + rnd.randrange(2, 9), "#%06x" % rnd.randrange(1 << 24))
        s = R.Scene(g, 0, 0, 3, layer_height=20)
        seen = set()
        for budget in (4000, 600, 200, 60, 5):
            r = s.render((90, 90), max_ops=budget)
            self.assertLessEqual(len(r.ops), budget)
            ok_frame(self, r.ops)
            seen.add(r.note)
        self.assertTrue(any("left out" in n or "flat" in n for n in seen))
        self.assertEqual(s.render((90, 90), max_ops=5).note, "too busy to lift; drawn flat")

    def test_the_rise_ends_on_the_full_render(self):
        fr = self.scene.rise_frames((100, 80), steps=4)
        self.assertEqual(len(fr), 4)
        self.assertEqual(fr[-1], self.scene.render((100, 80)).ops)

    def test_a_ragged_thing_stays_flat_instead_of_failing(self):
        g = blank(120, 120)
        for y in range(120):                      # a comb: far more boxes than MAX_BOX_PIECES
            for x in range(0, 120, 2):
                if (x // 2 + y) % 3 == 0:
                    g[y][x] = A
        s = R.Scene(g)
        r = s.render((10, 10))
        ok_frame(self, r.ops)


class TestHostile(unittest.TestCase):
    def test_bad_inputs_are_a_value_error_and_nothing_else(self):
        good = demo()
        bads = [dict(pixels=[]), dict(pixels=[[]]), dict(pixels=[["#12"]]), dict(pixels=[[1.5]]),
                dict(pixels=good, x=1.5), dict(pixels=good, scale=0), dict(pixels=good, scale=65),
                dict(pixels=good, x=10 ** 9), dict(pixels=good, ui_color="red"), dict(pixels=good, ui_color=None),
                dict(pixels=good, layer_height=0), dict(pixels=good, layer_height="8"),
                dict(pixels=good, light=(0, 0)), dict(pixels=good, light=(10, 0)), dict(pixels=good, light=(1,)),
                dict(pixels=good, light=(1.5, 1)), dict(pixels=good, light="up"), dict(pixels=good, max_things=0),
                dict(pixels=good, max_things=99), dict(pixels=[[BG] * 600] * 600)]
        for kw in bads:
            with self.assertRaises(ValueError, msg=str(kw)[:80]):
                R.Scene(**kw)
        s = R.Scene(good)
        for vp in ((1,), (1, 2, 3), ("a", "b"), (1.5, 2), (10 ** 9, 0), "xy", 7):
            with self.assertRaises(ValueError):
                s.render(vp)
        for rise in ((2, 1), (-1, 1), (1, 0), (1,), "x", (1.5, 2), (0.5, 1)):
            with self.assertRaises(ValueError):
                s.render((1, 1), rise)
        for kw in (dict(max_ops=0), dict(max_ops=5001), dict(distance=1), dict(distance="x")):
            with self.assertRaises(ValueError):
                s.render((1, 1), **kw)
        for kw in (dict(steps=0), dict(steps=61), dict(levels=1), dict(levels=9), dict(max_ops=0)):
            with self.assertRaises(ValueError):
                s.frames(**kw)

    def test_a_hostile_saved_setting_means_off_never_an_error(self):
        default = dict(R.DEFAULT_SETTING)
        for raw in (None, 5, [], "", "x", "1 1", "1 1 -1 -1", "1 1 -1 -1 40 9", "2 1 -1 -1 40", "1 2 -1 -1 40",
                    "1 1 0 0 40", "1 1 10 0 40", "1 1 -1 -1 9", "1 1 -1 -1 501", "1 1 -1 -1 4e1", "1 1 -1 -1 ٤٠",
                    "1 1 -1 -1 40\n; rm -rf /", "1 1 -1 -1 " + "9" * 5000, "٣ 1 -1 -1 40", "1 1 -1 -1 -40"):
            self.assertEqual(R.parse_setting(raw), default, repr(raw)[:40])
        self.assertEqual(R.parse_setting("1 0 1 -1 120"),
                         {"on": True, "three_d": False, "light": (1, -1), "ms": 120})


class TestSettingsApp(unittest.TestCase):
    def load(self, rel, name):
        spec = importlib.util.spec_from_file_location(name, ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_what_the_settings_app_saves_is_what_the_effect_reads(self):
        app = self.load("apps/load-effect/app.py", "load_effect_app")
        for on in (False, True):
            for d3 in (False, True):
                for sun in range(len(app.SUN)):
                    for ms in (10, 40, 500):
                        st = {"on": on, "d3": d3, "sun": sun, "ms": ms}
                        got = R.parse_setting(app.encode(st))
                        self.assertEqual(got, {"on": on, "three_d": d3, "light": app.SUN[sun][1], "ms": ms})
                        self.assertEqual(app.decode(app.encode(st)), st)

    def test_the_settings_app_ignores_a_corrupt_saved_value(self):
        app = self.load("apps/load-effect/app.py", "load_effect_app2")
        for raw in (None, "", "junk", "1 1 5 5 40", "1 1 -1 -1 forty"):
            self.assertEqual(app.decode(raw), {"on": False, "d3": False, "sun": 0, "ms": 40})

    def test_both_apps_pack_through_the_proof_gate_and_only_ask_for_their_own_space(self):
        import tempfile
        from kos.kapp import pack
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(list(pack(ROOT / "apps" / "load-effect", Path(tmp) / "a.kapp").permissions),
                             ["owns:load-effect"])
            self.assertEqual(list(pack(ROOT / "apps" / "load-preview", Path(tmp) / "b.kapp").permissions),
                             ["uses:load-effect"])


class FakeChannel:
    """Just enough of the OS for App.load_effect: answers vault reads, records frames."""

    def __init__(self, value):
        import socket
        import threading
        self.a, self.b = socket.socketpair()
        self.value, self.frames = value, []
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        import json
        f = self.b.makefile("rb")
        for line in f:
            m = json.loads(line)
            if m["cmd"] == "vault":
                r = {"cmd": "vault", "id": m["id"], "ok": self.value is not None}
                if self.value is not None:
                    r["value"] = self.value
                else:
                    r["detail"] = "no access"
                self.b.sendall(json.dumps(r).encode() + b"\n")
            elif m["cmd"] == "frame":
                protocol.validate_app_message(m, "graphical")
                self.frames.append(m["ops"])

    def close(self):
        import socket
        self.a.shutdown(socket.SHUT_RDWR)
        self.t.join(5)


class TestShowScene(unittest.TestCase):
    def run_it(self, value, **kw):
        ch = FakeChannel(value)
        app = App(ch.a)
        scene = app.scene(demo(), 20, 20, 3)
        base = Canvas().clear("#101820")
        out = app.show_scene(base, scene, (100, 80), **kw)
        ch.close()
        app._rfile.close()
        ch.a.close()
        ch.b.close()
        return out, ch.frames

    def test_off_by_default_draws_the_picture_once_with_no_animation(self):
        for value in (None, "junk"):
            out, frames = self.run_it(value)
            self.assertIsNone(out)
            self.assertEqual(len(frames), 1)
            self.assertEqual(frames[0][0], ["clear", "#101820"])

    def test_arrival_on_plays_every_frame_and_ends_on_the_exact_picture(self):
        out, frames = self.run_it("1 0 -1 -1 10")
        self.assertIsNone(out)
        self.assertGreater(len(frames), 10)
        self.assertEqual(frames[-1][1:], R.Scene(demo(), 20, 20, 3).flat().ops)

    def test_three_d_on_rises_then_stands_for_the_mouse(self):
        out, frames = self.run_it("1 1 -1 -1 10")
        self.assertIsInstance(out, R.Rendered)
        self.assertEqual(frames[-1][1:], out.ops)
        out2, frames2 = self.run_it("0 1 1 1 10")
        self.assertEqual(len(frames2), 1)                      # no arrival, straight to 3D
        self.assertEqual(frames2[0][1:], R.Scene(demo(), 20, 20, 3, light=(1, 1)).render((100, 80)).ops)

    def test_a_pointer_event_can_skip_the_arrival(self):
        out, frames = self.run_it("1 1 -1 -1 10", effect={"on": False, "three_d": True, "light": (-1, -1), "ms": 10})
        self.assertEqual(len(frames), 1)


if __name__ == "__main__":
    unittest.main()
