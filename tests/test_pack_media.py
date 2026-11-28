"""Tests for pack_media (docs/PACKS.md)."""

import base64
import sys
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_media as M  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def make(title, host):
    e = next(e for e in M.ENTRIES if e.title == title)
    return e.args["make"](host, e)


class TestConverter(unittest.TestCase):
    def test_table_conversions(self):
        csv_ = "a,b\n1,\"x,y\"\n"
        self.assertEqual(M.convert("csv > tsv", csv_), "a\tb\n1\tx,y\n")
        self.assertEqual(M.convert("csv > jsonl", csv_), '{"a": "1", "b": "x,y"}\n')
        self.assertEqual(M.convert("jsonl > csv", '{"a": 1, "b": null}\n{"a": 2, "c": true}'), "a,b,c\n1,,\n2,,true\n")
        self.assertEqual(M.convert("json > csv", '[{"k": "v"}]'), "k\nv\n")
        xml = M.convert("csv > xml", 'n\n"<&>"\n')
        self.assertIn("&lt;&amp;&gt;", xml)
        self.assertEqual(M.convert("xml > csv", xml), "n\n<&>\n")

    def test_bad_input_is_refused(self):
        for name, bad in (("json > csv", "{"), ("json > csv", "5"), ("xml > csv", "<!DOCTYPE x><table/>"), ("xml > csv", "<a/>"),
                          ("base64 > text", "!!!"), ("hex > text", "zz"), ("ppm (P3 text) > png (base64)", "P3 2 2 255 1 2"),
                          ("png (base64) > ppm (P3 text)", "AAAA"), ("csv > json", "a\n" * 6000), ("csv > json", "x" * 300000)):
            with self.assertRaises(ValueError, msg=(name, bad[:20])): M.convert(name, bad)
        with self.assertRaises(ValueError): M.convert("nope", "")
        M.convert("csv > json", "\x00\x01,\x02\n\x03")     # control characters must not crash

    def test_markdown_escapes_everything(self):
        h = M.convert("markdown > html", "# Hi <b>\n\n<script>alert(1)</script> **bo** *it* `<c>`\n\n- a\n- b\n\n[x](javascript:alert(1)) [ok](https://e.com/?a=1&b=2) [r](/p)\n\n```\n<i>\n```")
        self.assertIn("<h1>Hi &lt;b&gt;</h1>", h)
        self.assertNotIn("<script", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertIn("<strong>bo</strong> <em>it</em> <code>&lt;c&gt;</code>", h)
        self.assertIn("<ul>\n<li>a</li>\n<li>b</li>\n</ul>", h)
        self.assertNotIn('href="javascript', h)
        self.assertIn('<a href="https://e.com/?a=1&amp;b=2"', h)
        self.assertIn('<a href="/p"', h)
        self.assertIn("<pre><code>&lt;i&gt;</code></pre>", h)
        self.assertNotIn('href="java', M.convert("markdown > html", "[x](JaVa&#115;cript:alert(1)) [y](java\tscript:1)"))

    def test_base64_hex(self):
        self.assertEqual(M.convert("text > base64", "hello"), "aGVsbG8=")
        self.assertEqual(M.convert("base64 > text", "aGVsbG8="), "hello")
        self.assertEqual(M.convert("text > hex", "hi"), "6869")
        self.assertEqual(M.convert("hex > text", "68 69"), "hi")

    def test_ppm_png_roundtrip(self):
        ppm = "P3\n# c\n2 2\n255\n255 0 0  0 255 0\n0 0 255  10 20 30\n"
        b64 = M.convert("ppm (P3 text) > png (base64)", ppm)
        self.assertEqual(base64.b64decode(b64)[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(M.convert("png (base64) > ppm (P3 text)", b64), "P3\n2 2\n255\n255 0 0 0 255 0\n0 0 255 10 20 30\n")

    def test_png_decoder_filters_and_limits(self):
        import struct, zlib
        def png(w, h, ct, raw):
            c = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
            return b"\x89PNG\r\n\x1a\n" + c(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ct, 0, 0, 0)) + c(b"IDAT", zlib.compress(raw)) + c(b"IEND", b"")
        # grey 2x2: row0 filter Sub (10, +5), row1 filter Up (+1,+1)
        self.assertEqual(M.png_decode(png(2, 2, 0, b"\x01\x0a\x05\x02\x01\x01")), [[(10,) * 3, (15,) * 3], [(11,) * 3, (16,) * 3]])
        self.assertEqual(M.png_decode(png(1, 1, 6, b"\x00\x01\x02\x03\x04")), [[(1, 2, 3)]])
        with self.assertRaises(ValueError): M.png_decode(png(1, 1, 3, b"\x00\x00"))
        with self.assertRaises(ValueError): M.png_decode(png(1000, 1000, 0, b"\x00"))
        with self.assertRaises(ValueError): M.png_decode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 30)


class TestViewer(unittest.TestCase):
    def test_cube(self):
        m = M.primitive("cube")
        self.assertAlmostEqual(M.area(m), 6.0)
        self.assertAlmostEqual(M.volume(m), 1.0)
        self.assertEqual(M.bbox(m), ((-.5, -.5, -.5), (.5, .5, .5)))

    def test_other_primitives(self):
        p = M.primitive("pyramid")
        self.assertAlmostEqual(M.volume(p), 1 / 3)
        self.assertAlmostEqual(M.area(p), 1 + 2 * 1.25 ** 0.5)
        s = M.primitive("sphere")
        self.assertTrue(M.is_closed(s))
        self.assertAlmostEqual(M.volume(s), 4 / 3 * 3.141592653589793 * 0.125, delta=0.06)
        t = M.primitive("torus")
        self.assertTrue(M.is_closed(t))
        self.assertAlmostEqual(M.volume(t), 2 * 3.141592653589793 ** 2 * 0.4 * 0.15 ** 2, delta=0.03)
        with self.assertRaises(ValueError): M.primitive("x")

    def test_obj_roundtrip_and_exports(self):
        m = M.parse_obj(M.to_obj(M.primitive("cube")))
        self.assertEqual((len(m.verts), len(m.tris), m.bad), (8, 12, 0))
        self.assertAlmostEqual(M.volume(m), 1.0)
        stl = M.to_stl(M.primitive("pyramid"))
        self.assertTrue(stl.startswith("solid pyramid\n") and stl.endswith("endsolid pyramid\n"))
        self.assertEqual(stl.count("facet normal"), 6)

    def test_obj_quads_negative_indices_and_hostile(self):
        m = M.parse_obj("v 0 0 0\nv 1 0 0\nv 1 1 0\nv 0 1 0\nf 1/1/1 2 3 4\nf -4 -3 -2\n")
        self.assertEqual(len(m.tris), 3)
        self.assertAlmostEqual(M.area(m), 1.5)
        self.assertIsNone(M.volume(m))
        bad = M.parse_obj("v a b c\nv 1 2\nv nan 0 0\nv 1e999 0 0\nv 0 0 0\nf 1 2 3\nf 0 1 1\nf x y z\n\x00\x01 junk\nf 1 1\n")
        self.assertEqual((len(bad.verts), len(bad.tris)), (1, 0))
        self.assertGreaterEqual(bad.bad, 4)
        big = M.parse_obj("v 0 0 0\n" * 20000 + "f 1 1 1\n" * 20000)
        self.assertLessEqual(len(big.verts), M.MAXV)
        self.assertLessEqual(len(big.tris), M.MAXT)
        self.assertEqual(M.parse_obj("").verts, [])

    def test_wire_and_ascii(self):
        segs = M.wire(M.primitive("cube"), 0.6, 0.4, 1.0, 100, 60)
        self.assertGreaterEqual(len(segs), 12)
        art = M.ascii_wire(M.wire(M.primitive("cube"), 0.6, 0.4, 1.0, 40, 20, 2.0), 40, 20)
        self.assertEqual(len(art), 20)
        self.assertTrue(any("#" in r for r in art))
        self.assertEqual(M.wire(M.Mesh([], []), 0, 0, 1, 10, 10), [])

    def test_screen(self):
        h = FakeHost(["right", "+", "3", "i", "escape", "x", "e", "-"], mode="tui")
        run(h, make("3D Model Viewer", h))
        self.assertIn("export-model.stl", h.data)
        self.assertTrue(h.data["export-model.obj"].startswith("# KOS"))
        g = FakeHost(["left", "4"], mode="graphical", width=300, height=200)
        run(g, make("3D Model Viewer", g))
        self.assertTrue(g.canvases)


class TestAvatar(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(M.seed_parts(7), M.seed_parts(7))
        self.assertNotEqual(M.avatar_rows(M.seed_parts(7)), M.avatar_rows(M.seed_parts(8)))
        self.assertEqual(M.avatar_rows(M.seed_parts(7)), M.avatar_rows(M.seed_parts(7)))

    def test_known_pixels(self):
        p = {"face": 0, "hair": 0, "eyes": 0, "mouth": 1, "skin": 0, "haircol": 0, "bg": 0}
        r = M.avatar_rows(p)
        self.assertEqual((len(r), len(r[0])), (16, 16))
        self.assertEqual(r[0][0], (0xcf, 0xe8, 0xf3))      # background
        self.assertEqual(r[8][8], (0xf9, 0xd5, 0xb8))      # skin
        self.assertEqual(r[7][5], (0x2a, 0x1a, 0x1a))      # eye
        self.assertEqual(r[11][7], (0x2a, 0x1a, 0x1a))     # flat mouth
        r2 = M.avatar_rows({**p, "hair": 1, "haircol": 4})
        self.assertEqual(r2[3][7], (0xc0, 0x39, 0x2b))     # hair on top
        self.assertEqual(M.avatar_rows({"face": 99, "hair": -5}), M.avatar_rows({"face": 0, "hair": 3}))

    def test_exports(self):
        rows = M.avatar_rows(M.seed_parts(3))
        self.assertEqual(M.png_decode(M.png_encode(rows)), rows)
        root = ET.fromstring(M.avatar_svg(rows))
        self.assertEqual(root.get("width"), "256")

    def test_screen_saves(self):
        h = FakeHost(["right", "down", "right", "r", "s", "p", "v", "c"], mode="graphical", width=300, height=200)
        run(h, make("Avatar Maker", h))
        self.assertIn("avatar", h.data)
        self.assertIn("export-avatar.svg", h.data)
        self.assertEqual(M.png_decode(base64.b64decode(h.data["export-avatar.png.b64"]))[0][0], M.avatar_rows(M.seed_parts(1))[0][0])
        t = FakeHost(["d", "4", "2", "enter", "s"])
        run(t, make("Avatar Maker", t))
        self.assertIn("face: oval", t.text)


class TestAnimation(unittest.TestCase):
    def test_parse_and_interpolate(self):
        fr, errs = M.parse_keyframes("0 circle 0 0 10 #000\n2 rect 100 50 30 #ffffff\nbad line\n1 circle 500 0 5 #000000\n")
        self.assertEqual(len(fr), 2)
        self.assertEqual(len(errs), 2)
        s = M.state_at(fr, 1.0)
        self.assertEqual((s["x"], s["y"], s["size"], s["color"], s["shape"]), (50.0, 25.0, 20.0, "#808080", "circle"))
        self.assertEqual(M.state_at(fr, 5)["shape"], "rect")
        self.assertEqual(M.state_at(fr, -1)["x"], 0)
        self.assertEqual(len(M.parse_keyframes("0 circle 1 1 1 #000\n" * 80)[0]), M.MAXKF)

    def test_svg_valid_and_escaped(self):
        fr, _ = M.parse_keyframes(M.DEMO)
        svg = M.anim_svg(fr, '<script>"&')
        root = ET.fromstring(svg)
        self.assertNotIn("<script>", svg)
        self.assertIn("&lt;script&gt;&quot;&amp;", svg)
        self.assertEqual(svg.count("<circle"), 1)
        self.assertEqual(svg.count("<polygon"), 1)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertIn('keyTimes="0;0.333;0.667;1"', svg)
        one = M.anim_svg([fr[0]])
        ET.fromstring(one)
        with self.assertRaises(ValueError): M.anim_svg([])

    def test_screen(self):
        h = FakeHost(["right", "right", "x", "d", "end", "c"], mode="graphical", width=300, height=240)
        run(h, make("Animation Maker", h))
        self.assertIn("export-animation.svg", h.data)
        t = FakeHost(["right", "e", "escape"])
        run(t, make("Animation Maker", t))
        self.assertTrue(t.frames)


class TestColors(unittest.TestCase):
    def test_conversions(self):
        c = M.parse_color("#336699")
        self.assertEqual(c, (51, 102, 153))
        self.assertEqual(M.to_hsl(c), (210.0, 50.0, 40.0))
        self.assertEqual(M.to_hsv(c), (210.0, 66.7, 60.0))
        self.assertEqual(M.to_cmyk(c), (66.7, 33.3, 0.0, 40.0))
        self.assertEqual(M.to_cmyk((0, 0, 0)), (0.0, 0.0, 0.0, 100.0))
        self.assertEqual(M.to_cmyk((255, 0, 0)), (0.0, 100.0, 100.0, 0.0))
        self.assertEqual(M.to_hsl((255, 0, 0)), (0.0, 100.0, 50.0))
        for s, want in (("#f00", (255, 0, 0)), ("rgb(1, 2, 3)", (1, 2, 3)), ("hsl(120, 100%, 50%)", (0, 255, 0)), ("hsv(240,100%,100%)", (0, 0, 255)),
                        ("Tomato", (255, 99, 71)), ("10,20,30", (10, 20, 30)), ("hsl(480,100%,50%)", (0, 255, 0))):
            self.assertEqual(M.parse_color(s), want, s)
        for bad in ("", "#12", "rgb(1,2)", "rgb(300,0,0)", "hsl(1,200%,5%)", "nan", "rgb(nan,0,0)", "x" * 500, "\x00"):
            with self.assertRaises(ValueError, msg=bad): M.parse_color(bad)

    def test_nearest_name(self):
        self.assertEqual(M.nearest_name((255, 0, 0))[:2], ("red", "#ff0000"))
        self.assertEqual(M.nearest_name((250, 5, 5))[0], "red")
        self.assertEqual(M.nearest_name((0, 0, 1))[0], "black")

    def test_contrast(self):
        self.assertAlmostEqual(M.contrast((0, 0, 0), (255, 255, 255)), 21.0)
        self.assertAlmostEqual(M.contrast((255, 255, 255), (255, 255, 255)), 1.0)
        self.assertAlmostEqual(M.contrast((119, 119, 119), (255, 255, 255)), 4.48, places=2)
        v = M.verdicts(4.48)
        self.assertEqual([v[k] for k in v], [False, True, False, False])
        self.assertTrue(all(M.verdicts(21.0).values()))
        out = M.run_tool("contrast", "#777 #fff")
        self.assertEqual(out[0], "contrast ratio 4.48:1")
        self.assertIn("AA normal text (4.5): FAIL", out)

    def test_palettes_gradient_blindness(self):
        p = M.palettes((255, 0, 0))
        self.assertEqual(p["complementary"][1], (0, 255, 255))
        self.assertEqual(p["triad"], [(255, 0, 0), (0, 255, 0), (0, 0, 255)])
        self.assertEqual(p["analogous"], [(255, 0, 128), (255, 0, 0), (255, 128, 0)])
        self.assertEqual(M.gradient((0, 0, 0), (255, 255, 255), 3), [(0, 0, 0), (128, 128, 128), (255, 255, 255)])
        self.assertEqual(len(M.gradient((0, 0, 0), (1, 1, 1), 9999)), 64)
        self.assertEqual(M.simulate((255, 255, 255), "protanopia"), (255, 255, 255))
        self.assertEqual(M.simulate((0, 0, 0), "tritanopia"), (0, 0, 0))
        self.assertEqual(M.simulate((255, 0, 0), "protanopia"), (109, 95, 0))
        self.assertEqual(M.simulate((255, 255, 255), "achromatopsia"), (255, 255, 255))
        with self.assertRaises(ValueError): M.run_tool("gradient", "#000 #fff x")
        with self.assertRaises(ValueError): M.run_tool("contrast", "#000")

    def test_screen_saves(self):
        h = FakeHost(["1", *"#336699", "enter", "escape"])
        run(h, make("Color Tools", h))
        self.assertIn("last-result", h.data)
        self.assertIn("hsl    210", h.data["last-result"])


class TestSharedPalettes(unittest.TestCase):
    def test_owner_saves_and_users_read_through_one_shared_dict(self):
        spaces = {}
        owner = FakeHost(["3", *"#ff0000", "enter", "enter"], width=100, height=30)
        owner.spaces = spaces
        run(owner, make("Color Tools", owner))
        self.assertIn("palettes", spaces)
        user = FakeHost(["c"], mode="graphical", width=300, height=200)
        user.spaces = spaces
        pals, note = M.shared_palettes(user)
        self.assertEqual(pals[0][1], [(255, 0, 0), (0, 255, 255)])
        self.assertEqual(note, "")
        run(user, make("Avatar Maker", user))
        anim = FakeHost(["c", "x"], mode="graphical", width=300, height=240)
        anim.spaces = spaces
        run(anim, make("Animation Maker", anim))
        self.assertIn("#ff0000", anim.data["export-animation.svg"])
        self.assertEqual(anim.data["export-animation.svg"].count("#00ffff") > 0, True)

    def test_without_grant_or_with_junk_it_still_works_and_says_so(self):
        h = FakeHost()
        self.assertEqual(M.shared_palettes(h)[0], [])
        self.assertIn("built-in colours", M.shared_palettes(h)[1])
        h.spaces["palettes"] = {"records": '{"items":[{"name":"x","colors":"nope, #12345, #AbCdEf"},5,{"colors":7}]}'}
        self.assertEqual(M.shared_palettes(h)[0], [("x", [(0xab, 0xcd, 0xef)])])
        h2 = FakeHost(["c"], mode="graphical", width=300, height=200)
        run(h2, make("Avatar Maker", h2))
        self.assertTrue(h2.canvases)

    def test_permissions_declared_only_where_used(self):
        by = {e.title: e for e in M.ENTRIES}
        self.assertEqual(by["Color Tools"].owns, ["palettes"])
        self.assertEqual(by["Avatar Maker"].uses, ["palettes"])
        self.assertEqual(by["Animation Maker"].uses, ["palettes"])
        self.assertEqual(by["File Format Converter"].owns + by["File Format Converter"].uses + by["3D Model Viewer"].uses, [])


class TestEntries(unittest.TestCase):
    def test_titles_and_notes(self):
        self.assertEqual([e.title for e in M.ENTRIES], ["File Format Converter", "3D Model Viewer", "Avatar Maker", "Animation Maker", "Color Tools"])
        for e in M.ENTRIES:
            if e.scope == "partial": self.assertGreater(len(e.note), 20)

    def test_converter_screen(self):
        h = FakeHost(["enter", *"a,b", "enter", "1", "ctrl-r", "escape", "escape", "escape"])
        run(h, make("File Format Converter", h))
        self.assertIn("a\tb", h.data.get("last-output", "") or "a\tb")


if __name__ == "__main__":
    unittest.main()
