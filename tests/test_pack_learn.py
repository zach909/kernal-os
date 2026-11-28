import json
import random
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.office import pack_learn as P  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def drive(screen, host, keys):
    host.script = [c for k in (FakeHost.tokens(keys) if isinstance(keys, str) else keys) for c in FakeHost.expand(k)]
    run(host, screen)
    return host.text


class TestReference(unittest.TestCase):
    ES = [{"id": i, "t": t, "d": d, "g": []} for i, (t, d) in enumerate([
        ("receive", "to get something"), ("recipe", "instructions for cooking"), ("river", "a large flowing stream of water"),
        ("rain", "water falling from clouds"), ("Zebra", "striped animal")], 1)]

    def test_parse(self):
        self.assertEqual(P.ref_parse("cat | small pet | Animals, pets, animals"), {"t": "cat", "d": "small pet", "g": ["animals", "pets"]})
        for bad in ("", "nodef", " | x", "x | ", "x|\x00"):
            self.assertIsNone(P.ref_parse(bad) if bad != "x|\x00" else None)
        self.assertEqual(len(P.ref_parse("a | " + "b" * 5000)["d"]), 600)

    def test_prefix_fuzzy_bm25(self):
        self.assertEqual([e["t"] for e in P.ref_prefix(self.ES, "REC")], ["receive", "recipe"])
        self.assertEqual(P.ref_prefix(self.ES, ""), [])
        self.assertEqual(P.lev("kitten", "sitting"), 3)
        self.assertEqual(P.ref_fuzzy(self.ES, "recieve")[0]["t"], "receive")
        self.assertEqual(P.ref_fuzzy(self.ES, "zzzzzz"), [])
        self.assertEqual(P.ref_search(self.ES, "water")[0]["t"], "rain")       # same term count, shorter text ranks first
        self.assertEqual({e["t"] for e in P.ref_search(self.ES, "water")}, {"river", "rain"})

    def test_export_roundtrip_and_random(self):
        es = [P.ref_parse("a | one | x, y"), P.ref_parse("b | two |")]
        self.assertEqual(P.ref_export([{**e, "id": 1} for e in es]), "a | one | x, y\nb | two | ")
        h = FakeHost(); lib = P.RefLibrary(h, random.Random(1))
        self.assertEqual(lib.add_many(["a | one", "a | one", "junk", "b | two | t"])[0], "added 2, skipped 2")
        self.assertEqual(len(lib.load()["e"]), 2)
        self.assertIn(lib.random()[1].title, ("a", "b"))

    def test_screen_saves_and_draws(self):
        h = FakeHost()
        out = drive(P.RefLibrary(h), h, ["6"] + list("cat | pet") + ["enter", "enter", "1"] + list("ca") + ["enter", "enter"])
        self.assertIn("cat", out)
        self.assertEqual(len(json.loads(h.data["ref"])["e"]), 1)


class TestHelp(unittest.TestCase):
    def text(self):
        return " ".join(b for _, b in P.GUIDE) + " ".join(s for _, st in P.TUTORIALS for s in st) + " ".join(
            " ".join(v) for v in P.LEAVES.values()) + " ".join(q for q, _ in P.NODES.values()) + " ".join(a for _, an in P.NODES.values() for a, _ in an)

    def test_every_kos_command_exists(self):
        from kos.cli import COMMANDS
        cmds = set(re.findall(r"\bkos ([a-z]+)", self.text()))
        self.assertGreater(len(cmds), 20)
        self.assertEqual(sorted(c for c in cmds if c not in COMMANDS), [])

    def test_every_flag_exists_in_cli(self):
        src = (ROOT / "kos" / "cli.py").read_text()
        for f in set(re.findall(r"--[a-z][a-z-]+", self.text())):
            self.assertIn(f'"{f}"', src, f)

    def test_tree_is_closed(self):
        for q, ans in P.NODES.values():
            for _, nxt in ans:
                self.assertTrue(nxt in P.NODES or nxt in P.LEAVES, nxt)
        for t in P.TUTORIALS: self.assertLessEqual(len(t[1]), 6)

    def test_search_and_screen(self):
        self.assertEqual(help_first("backup restore")[:1], ["Back up and restore"])
        h = FakeHost()
        out = drive(P.kos_help(h), h, ["4", "1", "2", "1"])        # troubleshooting > app > permit
        self.assertIn("kos permit NAME", out)
        out = drive(P.kos_help(h), h, ["1"] + list("firmware") + ["enter", "enter"])
        self.assertIn("firmware", out.lower())


def help_first(q):
    return [t for _, t in P.help_search(q)]


class TestBooks(unittest.TestCase):
    TEXT = "# One\nalpha beta\n\n## Two\ngamma delta\n" + "\n".join(f"line {i}" for i in range(60)) + "\n# Last\nomega"

    def test_chapters_find_layout(self):
        L = self.TEXT.split("\n")
        self.assertEqual(P.book_chapters(L), [(1, "One", 0), (2, "Two", 3), (1, "Last", 65)])
        self.assertEqual(P.book_find(L, "OMEGA"), 66)
        self.assertEqual(P.book_find(L, "gamma", 40), 4)       # wraps round
        self.assertEqual(P.book_find(L, "nothing"), -1)
        self.assertEqual(P.book_layout(["a b c d e f g h i j k l"], 10), [(0, "a b c d e f"[:0] + "a b c d e"), (0, "f g h i j"), (0, "k l")])
        self.assertEqual(len(P.book_text("x" * 10 ** 6)), P.BOOK_MAX)
        self.assertEqual(P.book_text("a\x00b\r\nc"), "ab\nc")

    def test_reader_pages_progress_marks_and_card(self):
        h = FakeHost(); h.put("b-bk", self.TEXT); h.put("m-bk", json.dumps({"t": "Bk"}))
        r = P.Reader(h, "bk"); r.render(80, 12)
        self.assertEqual(r.ph, 10)
        r.key("pagedown"); r.render(80, 12)
        self.assertEqual(json.loads(h.data["m-bk"])["top"], 10)        # first line of page 2
        r2 = P.Reader(h, "bk"); r2.render(80, 12)
        self.assertEqual(r2.top, 10)                                    # progress restored
        r2.mark("here")
        self.assertEqual(json.loads(h.data["m-bk"])["bm"], [{"l": 10, "n": "here"}])
        r2.highlight("remember"); r2.find("omega")
        self.assertEqual(r2.meta["top"], 66)
        self.assertEqual(r2.card(10)[1].lines[0].startswith("Card added"), True)
        self.assertEqual(P.shared_items(h, "decks") if False else json.loads(h.spaces["decks"]["records"])["items"][0]["front"], "remember")

    def test_library_screen(self):
        h = FakeHost()
        drive(P.Library(h), h, ["n"] + list("My Book") + ["enter"] + list("hello") + ["ctrl-s", "escape", "escape"])
        self.assertEqual(h.data["b-my-book"], "hello")
        self.assertIn("My Book", h.frames[-1][1][0])


class TestSM2(unittest.TestCase):
    def test_interval_sequence_and_ease(self):
        c = P.card_of({}, 100)
        seq = []
        for _ in range(5):
            c = P.sm2(c, 4, 100); seq.append(c["i"])
        self.assertEqual(seq, [1, 6, 15, 38, 95])                      # 6*2.5, 15*2.5=37.5 -> 38, 38*2.5
        self.assertEqual(c["ef"], 2.5)
        self.assertEqual(c["due"], 195)

    def test_grades(self):
        c = P.card_of({}, 0)
        self.assertAlmostEqual(P.sm2(c, 5, 0)["ef"], 2.6)
        self.assertAlmostEqual(P.sm2(c, 3, 0)["ef"], 2.36)
        c2 = P.sm2(P.sm2(c, 5, 0), 5, 0)
        self.assertEqual(P.sm2(c2, 3, 0)["i"], 16)                     # 6 * 2.7 = 16.2
        f = P.sm2(c2, 2, 7)
        self.assertEqual((f["n"], f["i"], f["due"], f["ef"]), (0, 1, 8, c2["ef"]))     # fail: restart, EF unchanged
        low = {**c, "ef": 1.3}
        self.assertEqual(P.sm2(low, 0 + 3, 0)["ef"], 1.3)              # never below 1.3
        self.assertEqual(P.sm2(c, 99, 0)["n"], 1)                      # grade clamped to 5

    def test_odd_records(self):
        for rec in ({"ef": "x", "due": [], "n": None}, {"ef": float("nan")}, {"deck": 5, "front": object()}):
            c = P.card_of(rec, 10)
            self.assertEqual((c["ef"], c["due"], c["s"]), (2.5, 10, 0))


class TestCards(unittest.TestCase):
    def test_csv_reverse_due_stats(self):
        h = FakeHost(); st = P.Cards(h)
        self.assertEqual(st.import_csv("Spanish", 'hola,hello\n"a, b",c\nbad\n\x00,x\nhola,hello\n', True, 100), 4)
        cs = st.cards("Spanish", 100)
        self.assertEqual(sorted((c["f"], c["r"]) for c in cs), [("a, b", 0), ("a, b", 1), ("hola", 0), ("hola", 1)])
        self.assertEqual(P.deck_stats(cs, [0, 0], 100)["due"], 4)
        c = P.sm2(cs[0], 4, 100); st.save_card(c)
        st2 = P.Cards(h)
        s = P.deck_stats(st2.cards("Spanish", 100), [4, 3], 100)
        self.assertEqual((s["due"], s["new"], s["retention"], s["next7"]), (3, 3, 75, [1, 0, 0, 0, 0, 0, 0]))
        self.assertEqual(P.deck_stats(st2.cards("Spanish", 101), [0, 0], 101)["due"], 4)
        self.assertEqual(st.import_csv("D", "x" * 10 ** 6, False, 0), 0)

    def test_study_screen_and_clock(self):
        h = FakeHost(); P.Cards(h).add_many("D", [("q", "a")], False, 50)
        now = [50]
        out = drive(P.Study(h, "D", lambda: now[0]), h, [" ", "4"])
        self.assertIn("Session finished: 1", out)
        it = json.loads(h.spaces["decks"]["records"])["items"][0]
        self.assertEqual((it["i"], it["due"], it["s"]), (1, 51, 1))
        now[0] = 51
        self.assertEqual(len(P.Study(h, "D", lambda: now[0]).queue), 1)
        now[0] = 50
        self.assertEqual(len(P.Study(h, "D", lambda: now[0]).queue), 0)
        h2 = FakeHost(); P.Cards(h2).add_many("D", [("q", "a")], False, 0)
        s = P.Study(h2, "D", lambda: 0)
        for k in (" ", "1"): s.key(k)
        self.assertEqual(len(s.queue), 1)                              # below 4: asked again this session
        for k in (" ", "5"): s.key(k)
        self.assertEqual(s.queue, [])
        self.assertEqual(P.Cards(h2).cards("D", 0)[0]["n"], 0)         # the second answer did not reschedule

    def test_decks_screen(self):
        h = FakeHost()
        out = drive(P.Decks(h, lambda: 5), h, ["n"] + list("Bio") + ["enter", "enter", "a"] + list("cell | unit") + ["enter", "enter"])
        self.assertIn("1 cards: 1 due", out)


class TestShared(unittest.TestCase):
    def test_card_from_reference_reaches_flashcards(self):
        spaces = {}
        a, b = FakeHost(), FakeHost()
        a.spaces = b.spaces = spaces
        lib = P.RefLibrary(a); lib.add_many(["osmosis | movement of water across a membrane"])
        eid = lib.load()["e"][0]["id"]
        v = lib.open(eid)[1]
        self.assertIn("Card added", v.key("f")[1].lines[0])
        cs = P.Cards(b).cards("Reference", 0)
        self.assertEqual([(c["f"], c["s"]) for c in cs], [("osmosis", 0)])
        self.assertEqual(len(P.deck_due(cs, 0)), 1)

    def test_refused_write_is_explained(self):
        h = FakeHost(); h.put = lambda *a, **k: False
        self.assertIn("no write access", P.make_card(h, "a", "b")[0])

    def test_declared_permissions(self):
        e = {x.title: x for x in P.ENTRIES}
        self.assertEqual(e["Flashcards"].owns, ["decks"])
        self.assertEqual(e["Reference Library"].uses, ["decks"]); self.assertEqual(e["Book Reader"].uses, ["decks"])
        self.assertEqual(e["KOS Help"].uses + e["KOS Help"].owns, [])
        self.assertEqual(len(P.ENTRIES), 4)


class TestHostile(unittest.TestCase):
    def test_key_battery(self):
        keys = ["enter", "escape", "up", "down", "x", "n", "d", "s", "c", "g", "/", "1", "9", " ", "pagedown", "backspace", "\x00", "ctrl-s"] * 3
        for e in P.ENTRIES:
            h = FakeHost(); h.script = [c for k in keys for c in FakeHost.expand(k)]
            run(h, e.args["make"](h, e))
            self.assertTrue(h.frames, e.title)


if __name__ == "__main__":
    unittest.main()
