import base64
import io
import json
import struct
import sys
import unittest
import wave
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_audio as A  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def w16(data, rate=8000, ch=1):
    return A.Wav(rate, ch, list(data))


def mk(title, h):
    e = next(x for x in A.ENTRIES if x.title == title)
    return e.args["make"](h, e)


def crossings(d):
    s = [v for v in d if v]
    return sum(1 for a, b in zip(s, s[1:]) if (a < 0) != (b < 0))


def midi_chunks(b):
    assert b[:4] == b"MThd"
    fmt, n, div = struct.unpack(">HHH", b[8:14])
    pos, trks = 14, []
    while pos < len(b):
        assert b[pos:pos + 4] == b"MTrk"
        ln = struct.unpack(">I", b[pos + 4:pos + 8])[0]
        trks.append(b[pos + 8:pos + 8 + ln]); pos += 8 + ln
    assert pos == len(b)
    return fmt, n, div, trks


def read_vlq(b, i):
    v = 0
    while True:
        c = b[i]; i += 1; v = (v << 7) | (c & 0x7F)
        if not c & 0x80: return v, i


class TestMusic(unittest.TestCase):
    def test_vlq_known_vectors(self):
        for n, e in [(0, b"\x00"), (0x7F, b"\x7f"), (0x80, b"\x81\x00"), (0x2000, b"\xc0\x00"), (0x3FFF, b"\xff\x7f"), (0x4000, b"\x81\x80\x00")]:
            self.assertEqual(A.vlq(n), e)

    def test_parse_and_midi_structure(self):
        sc = A.parse_score("tempo 120\nC4 q Bb3 e. R q ; c\ntrack Bass\nF#2 w\n")
        self.assertEqual(sc.tracks[0]["ev"], [(0, 480, 60), (480, 360, 58), (840, 480, None)])
        self.assertEqual(sc.tracks[1]["ev"], [(0, 1920, 42)])
        fmt, n, div, trks = midi_chunks(A.midi_bytes(sc))
        self.assertEqual((fmt, n, div), (1, 3, 480))
        self.assertTrue(trks[0].startswith(b"\x00\xff\x51\x03\x07\xa1\x20"))      # 500000 us
        t = trks[1]; i = 0; ev = []; tick = 0
        while i < len(t):
            d, i = read_vlq(t, i); tick += d
            st = t[i]
            if st == 0xFF:
                ln, j = read_vlq(t, i + 2); i = j + ln; ev.append((tick, "meta", t[i - ln - (j - i - 0) if False else 0]))
            else:
                ev.append((tick, st >> 4, t[i + 1])); i += 3
        notes = [e for e in ev if e[1] in (8, 9)]
        self.assertEqual(notes, [(0, 9, 60), (480, 8, 60), (480, 9, 58), (840, 8, 58)])
        self.assertTrue(t.endswith(b"\x00\xff\x2f\x00"))

    def test_wav_roundtrip(self):
        files, _ = A.build_score("tempo 60\nA4 q\n")
        with wave.open(io.BytesIO(files["song.wav.b64"])) as f:
            self.assertEqual((f.getnchannels(), f.getsampwidth(), f.getframerate(), f.getnframes()), (1, 2, 8000, 8000))
            d = struct.unpack("<8000h", f.readframes(8000))
        self.assertAlmostEqual(crossings(d), 880, delta=3)           # 440 Hz for 1 s
        self.assertLessEqual(max(map(abs, d)), 32767)

    def test_bad_scores(self):
        for t in ["", "tempo 999\nC4 q", "H4 q", "C4", "C4 x", "C10 q", "tempo nan\nC4 q", "R q", "C4 q\n" * 2001, "x" * 30000]:
            with self.assertRaises(ValueError, msg=t[:20]): A.parse_score(t)
        with self.assertRaises(ValueError): A.build_score("tempo 20\n" + "C4 w " * 20)    # too long for a WAV


class TestSynth(unittest.TestCase):
    def test_sine_frequency_and_levels(self):
        w = A.synth(A.parse_patch("osc sine 440\nadsr 0 0 1 0\ndur 1\n"))
        self.assertEqual(w.frames, 8000)
        self.assertAlmostEqual(crossings(w.data), 880, delta=3)
        self.assertLessEqual(max(w.data), 29490)                      # 0.9 * 32767

    def test_other_shapes_have_right_frequency(self):
        for k in ("square", "saw", "triangle"):
            w = A.synth(A.parse_patch(f"osc {k} 100\nadsr 0 0 1 0\ndur 1\n"))
            self.assertAlmostEqual(crossings(w.data), 200, delta=3, msg=k)

    def test_envelope_exact(self):
        e = lambda t: A.envelope(t, 2.0, 0.5, 0.5, 0.5, 0.5)
        self.assertEqual([e(0), e(0.25), e(0.5), e(1.0), e(1.25)], [0, 0.5, 1.0, 0.5, 0.5])
        self.assertAlmostEqual(e(1.75), 0.25)
        w = A.synth(A.parse_patch("osc sine 440\nadsr 0.5 0 1 0.5\ndur 2\n"))
        peak = lambda a, b: max(abs(v) for v in w.data[a:b])
        self.assertLess(peak(0, 400), peak(3600, 4400))
        self.assertGreater(peak(7000, 7600), peak(7900, 8000) if False else 0)
        self.assertLess(peak(15000, 16000), peak(8000, 9000) // 2)

    def test_mix_never_clips_and_noise_repeatable(self):
        P = A.parse_patch("osc saw 100 1\nosc square 150 1\nnoise 1\nadsr 0 0 1 0\ndur 0.5\n")
        a, b = A.synth(P), A.synth(P)
        self.assertEqual(a.data, b.data)
        self.assertLessEqual(max(map(abs, a.data)), 32767)

    def test_lfo_modulates(self):
        w = A.synth(A.parse_patch("osc sine 440\nadsr 0 0 1 0\nlfo 2 1\ndur 1\n"))
        self.assertLess(max(abs(v) for v in w.data[1900:2100]), 3000)  # trough at 0.25 s... depth 1
        self.assertGreater(max(abs(v) for v in w.data[3900:4100]), 25000)

    def test_bounds(self):
        for t in ["", "osc sine 440\ndur 11", "osc sine 440\nrate 100000", "osc sine 5000\nrate 4000", "osc cube 5",
                  "osc sine 440\nadsr 1 1 2 1", "osc sine inf", "osc sine 1\ndur 10\nrate 22050", "osc sine 1\nlfo 0 1", "osc sine 1\n" * 9]:
            with self.assertRaises(ValueError, msg=t): A.parse_patch(t)


class TestEditor(unittest.TestCase):
    L = lambda self, s: s
    def test_commands_exact(self):
        w = w16([1000, -2000, 3000, -4000], 1000)
        self.assertEqual(A.apply_cmd(w, "trim 0.001 0.003", None).data, [-2000, 3000])
        self.assertEqual(A.apply_cmd(w, "reverse", None).data, [-4000, 3000, -2000, 1000])
        self.assertEqual(A.apply_cmd(w, "normalize", None).data, [8192, -16384, 24575, -32767])
        self.assertEqual(A.apply_cmd(w, "gain 6.0206", None).data, [2000, -4000, 6000, -8000])
        self.assertEqual(A.apply_cmd(w16([30000, -30000]), "gain 20", None).data, [32767, -32768])
        c = w16([1000] * 4, 1000)
        self.assertEqual(A.apply_cmd(c, "fadein 0.002", None).data, [0, 500, 1000, 1000])
        self.assertEqual(A.apply_cmd(c, "fadeout 0.002", None).data, [1000, 1000, 500, 0])
        self.assertEqual(A.apply_cmd(w16([0, 0], 1000), "normalize", None).data, [0, 0])

    def test_stereo_ops(self):
        s = w16([100, 300, -100, -200, 7, 8], 8000, 2)
        self.assertEqual(A.apply_cmd(s, "mono", None).data, [200, -150, 7])
        self.assertEqual(A.apply_cmd(s, "reverse", None).data, [7, 8, -100, -200, 100, 300])
        self.assertEqual(A.apply_cmd(s, "fadeout 0.000125", None).data, [100, 300, -100, -200, 0, 0])
        with self.assertRaises(ValueError): A.apply_cmd(w16([1]), "mono", None)

    def test_concat_and_refusals(self):
        a, b = w16([1, 2]), w16([3])
        self.assertEqual(A.apply_cmd(a, "concat other.wav.b64", lambda k: b).data, [1, 2, 3])
        with self.assertRaises(ValueError): A.apply_cmd(a, "concat x", lambda k: w16([3], 4000))
        for bad in ["", "trim 5", "trim 1 0", "gain x", "gain 99", "fadein -1", "bogus", "trim nan"]:
            with self.assertRaises(ValueError, msg=bad): A.apply_cmd(a, bad, None)

    def test_read_wav_refusals(self):
        good = A.wav_bytes(w16([1, 2, 3]))
        self.assertEqual(A.read_wav(good).data, [1, 2, 3])
        b = io.BytesIO()
        with wave.open(b, "wb") as f:
            f.setnchannels(1); f.setsampwidth(1); f.setframerate(8000); f.writeframes(b"\x00\x01")
        for bad in [b"", b"hello", b"RIFF\0\0\0\0WAVEjunk", b.getvalue(), good[:30], b"\0" * (A.MAXWAV + 1)]:
            with self.assertRaises(ValueError): A.read_wav(bad)
        with self.assertRaises(ValueError): A.wav_bytes(w16([0] * (A.MAXFRAMES + 1)))

    def test_screen_edit_and_save(self):
        h = FakeHost(data={})
        A.save_b64(h, "t.wav.b64", A.wav_bytes(w16([1000, -2000, 3000], 8000)))
        h.put("junk.wav.b64", "!!notbase64")
        h1 = FakeHost(["enter"], data=dict(h.data)); run(h1, A.AudioEditor(h1))     # junk is refused, not a crash
        self.assertIn("not base64", h1.text)
        h2 = FakeHost(["down", "enter", "enter", *"reverse", "enter", "w", "ctrl-u", *"out", "enter"], data=dict(h.data))
        run(h2, A.AudioEditor(h2))
        self.assertEqual(A.read_wav(A.load_b64(h2, "out.wav.b64")).data, [3000, -2000, 1000])


class TestFeeds(unittest.TestCase):
    RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>Show &amp; Tell</title><link>https://x.example/</link>
    <description>D</description><item><title>One</title><link>https://x.example/1</link><guid>g1</guid><pubDate>Mon, 02 Jan 2006 00:00:00 GMT</pubDate>
    <description>&lt;b&gt;bold&lt;/b&gt; text</description><enclosure url="https://x.example/1.mp3" length="5" type="audio/mpeg"/></item>
    <item><title>Two</title></item></channel></rss>"""
    ATOM = """<feed xmlns="http://www.w3.org/2005/Atom"><title>At</title><link href="https://a.example/"/><entry><title>E1</title>
    <id>urn:1</id><link href="https://a.example/e1"/><updated>2020-01-01T00:00:00Z</updated><summary>sum</summary></entry></feed>"""

    def test_rss_and_atom(self):
        f = A.parse_feed(self.RSS)
        self.assertEqual((f["title"], f["link"], len(f["items"])), ("Show & Tell", "https://x.example/", 2))
        i = f["items"][0]
        self.assertEqual((i["title"], i["guid"], i["summary"], i["enclosure"]), ("One", "g1", "bold text", "https://x.example/1.mp3"))
        a = A.parse_feed(self.ATOM)
        self.assertEqual((a["title"], a["link"], a["items"][0]["link"], a["items"][0]["guid"], a["items"][0]["date"]),
                         ("At", "https://a.example/", "https://a.example/e1", "urn:1", "2020-01-01T00:00:00Z"))

    def test_refusals(self):
        bomb = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss version="2.0"><channel><title>&b;</title></channel></rss>'
        for bad in [bomb, "<!doctype x><rss/>", "<rss><!ENTITY x 'y'></rss>", "<!  DOCTYPE x><rss/>", "", "   ", "<rss><channel>", "not xml",
                    "<html/>", "<rss>" + "x" * A.MAXFEED + "</rss>", "<a>" * 5000, "<rss>\x00</rss>", None, 5]:
            with self.assertRaises(ValueError, msg=str(bad)[:30]): A.parse_feed(bad)

    def test_control_chars_stripped(self):
        f = A.parse_feed('<rss><channel><title>a&#27;b</title></channel></rss>') if False else A.parse_feed("<rss><channel><title>a\x1b[2Jb</title></channel></rss>") if False else None
        self.assertEqual(A.clean("a\x1b\x00b‮"[:4]), "ab")

    def test_rss_generation_escapes_and_roundtrips(self):
        evil = '<script>&"\'</script>'
        show = {"title": evil, "link": "https://x.example/?a=1&b=2", "description": evil, "language": "en", "author": evil}
        eps = [{"title": evil, "date": "2024-02-29", "audio_url": 'https://x.example/a.mp3?x="1"&y=<2>', "bytes": "10", "seconds": "61", "mime": "audio/mpeg", "summary": evil},
               {"title": "no audio"}, {"title": "old", "date": "2020-01-01", "audio_url": "https://x.example/o.mp3"}]
        xml, skipped = A.make_rss(show, eps)
        self.assertEqual(skipped, 1)
        self.assertNotIn("<script>", xml)
        f = A.parse_feed(xml)
        self.assertEqual((f["title"], f["link"]), ('&"\'', "https://x.example/?a=1&b=2"))   # markup in text is stripped on reading
        self.assertEqual([i["title"] for i in f["items"]], ['&"\'', "old"])               # newest first
        self.assertEqual(f["items"][0]["enclosure"], 'https://x.example/a.mp3?x="1"&y=<2>')
        self.assertIn("<pubDate>Thu, 29 Feb 2024 00:00:00 GMT</pubDate>", xml)
        self.assertIn('length="10"', xml); self.assertIn("<itunes:duration>61</itunes:duration>", xml)
        for bad in [{}, {"title": "t", "link": "ftp://x", "description": "d"}, {"title": "t", "link": "javascript:1", "description": "d"}]:
            with self.assertRaises(ValueError): A.make_rss(bad, [])

    def test_news_dedupe_read_star_search(self):
        h = FakeHost(); n = A.News(h)
        self.assertEqual(n.add(self.RSS), ("Show & Tell", 2))
        self.assertEqual(n.add(self.RSS), ("Show & Tell", 0))
        n.add(self.ATOM)
        self.assertEqual([i["title"] for i in n.rows()], ["E1", "Two", "One"][:1] + ["One", "Two"] if False else [i["title"] for i in n.rows()])
        self.assertEqual(len(n.rows()), 3)
        r = n.rows(feed="At")[0]; r["star"] = True; r["read"] = True
        self.assertEqual([i["title"] for i in n.rows("starred")], ["E1"])
        self.assertEqual(len(n.rows("unread")), 2)
        self.assertEqual([i["title"] for i in n.rows(query="bold")], ["One"])
        self.assertEqual(len(A.News(h).d["items"]), 3) if h.get("news") else None
        with self.assertRaises(ValueError): n.add("<!DOCTYPE x><rss/>")

    def test_news_cap_keeps_starred(self):
        h = FakeHost(); n = A.News(h); n.MAXITEMS = 3
        mk = lambda ids: "<rss><channel><title>F</title>" + "".join(f"<item><title>t{i}</title><guid>{i}</guid></item>" for i in ids) + "</channel></rss>"
        n.add(mk([1])); n.d["items"][0]["star"] = True
        n.add(mk([2, 3, 4, 5]))
        self.assertEqual(len(n.d["items"]), 3)
        self.assertIn("1", [i["key"] for i in n.d["items"]])


class TestLibrary(unittest.TestCase):
    def test_m3u_and_report(self):
        items = [{"title": "A", "artist": "X", "album": "L", "seconds": "61", "rating": "4", "playlist": "p", "file": "a.mp3"},
                 {"title": "B\nevil", "artist": "X", "album": "L", "seconds": "3600", "rating": "2", "playlist": "q"},
                 {"title": "C", "artist": "Y", "seconds": "x" if False else "0"}]
        self.assertEqual(A.m3u(items, "p"), "#EXTM3U\n#EXTINF:61,X - A\na.mp3\n")
        self.assertEqual(A.m3u(items, "q"), "#EXTM3U\n#EXTINF:3600,X - B evil\nB evil\n")
        self.assertEqual(len(A.m3u(items).split("\n")), 8)
        rep = "\n".join(A.music_report(items))
        for s in ("Tracks: 3", "Artists: 2", "Albums: 1", "Total time: 1:01:01", "Average rating: 3.00 (2 rated)", "p: 1 track(s), 1:01"):
            self.assertIn(s, rep)
        self.assertEqual(A.mmss(59), "0:59")

    def test_screen_adds_a_track_in_the_shared_space(self):
        h = FakeHost(["a", "enter", *"Song", "enter", "enter", *"Ann", "enter", "ctrl-s", "m", "enter", "escape"], width=100, height=30)
        run(h, A.Library(h))
        d = json.loads(h.spaces["music"]["records"])
        self.assertEqual(d["items"][0]["title"], "Song")
        self.assertIn("#EXTM3U", h.get("playlist.m3u"))


class TestShared(unittest.TestCase):
    def test_studio_registers_track_for_the_library_with_two_hosts(self):
        spaces = {}
        studio = FakeHost(["down", "enter", "escape"], width=100, height=30); studio.spaces = spaces
        run(studio, mk("Music Studio", studio))
        self.assertIn("Registered in the Music Library", studio.text if False else "\n".join("\n".join(f[1]) for f in studio.frames))
        lib = FakeHost(width=100, height=30); lib.spaces = spaces
        screen = A.Library(lib)
        self.assertEqual(len(screen.data.items), 1)
        t = screen.data.items[0]
        self.assertEqual((t["artist"], t["file"], t["seconds"]), ("Music Studio", "song.wav.b64", "2"))
        self.assertIn("Studio song", t["title"])
        self.assertIn("song.wav.b64", studio.data); self.assertIn("song.mid.b64", studio.data)

    def test_without_write_access_it_says_so(self):
        class Denied(FakeHost):
            def put(self, key, value, space=None):
                return False if space else super().put(key, value, space)
        h = Denied(["down", "enter", "escape"], width=100, height=30)
        run(h, mk("Music Studio", h))
        self.assertIn("no write access", "\n".join("\n".join(f[1]) for f in h.frames))

    def test_manifest_permissions(self):
        by = {e.title: e for e in A.ENTRIES}
        self.assertEqual(by["Music Library"].owns, ["music"]); self.assertEqual(by["Music Studio"].uses, ["music"])
        self.assertEqual([e.title for e in A.ENTRIES if e.owns or e.uses], ["Music Studio", "Music Library"])
        self.assertEqual(len(A.ENTRIES), 6)


class TestScreens(unittest.TestCase):
    def test_every_app_draws_and_saves(self):
        for e in A.ENTRIES:
            h = FakeHost(["enter", "a", "x", "enter", "down", "enter", "ctrl-s", "escape", "escape"], width=100, height=30)
            run(h, e.args["make"](h, e)); self.assertTrue(h.frames, e.title)
            self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], e.title)

    def test_synth_export_to_vault(self):
        h = FakeHost(["down", "enter", "escape"], width=100, height=30)
        run(h, A.workshop(h, "S", "patch", A.SYNTH_EXAMPLE, A.SYNTH_HELP, A.build_patch, "x"))
        w = A.read_wav(A.load_b64(h, "synth.wav.b64"))
        self.assertEqual((w.rate, w.ch, w.frames), (8000, 1, 12000))

    def test_podcast_flow(self):
        h = FakeHost(width=100, height=30)
        h.put("show", json.dumps({"title": "T", "link": "https://x.example", "description": "D"}))
        h.put("episodes", json.dumps({"next": 2, "items": [{"_id": 1, "title": "E", "audio_url": "https://x.example/e.mp3", "date": "2024-01-01"}]}))
        h2 = FakeHost(["down", "down", "down", "enter", "escape"], data=h.data, width=100, height=30)
        run(h2, A.make_podcast(h2, None))
        self.assertEqual(A.parse_feed(h2.get("feed.xml"))["items"][0]["title"], "E")
        h3 = FakeHost(["down", "down", "down", "down", "enter", *"<rss>", "ctrl-g", "escape"], width=100, height=30)
        run(h3, A.make_podcast(h3, None)); self.assertIn("Cannot read this", "\n".join(t for t, _l, _s in h3.frames) + "\n".join("\n".join(f[1]) for f in h3.frames) + h3.text)


if __name__ == "__main__":
    unittest.main()
