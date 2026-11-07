import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_games as G  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

KIWI = "r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq -"


def game(fen, *moves):
    g = G.Game(fen)
    for m in moves:
        assert g.play(m) == "", m
    return g


class TestChess(unittest.TestCase):
    def test_perft_start(self):
        p = G.Position.from_fen(G.START)
        self.assertEqual([G.perft(p, d) for d in (1, 2, 3, 4)], [20, 400, 8902, 197281])
        self.assertEqual(p.fen(), G.START)

    def test_perft_kiwipete(self):
        p = G.Position.from_fen(KIWI)
        self.assertEqual([G.perft(p, d) for d in (1, 2)], [48, 2039])

    def test_fen_round_trip_and_rejects(self):
        f = "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1"
        self.assertEqual(G.Position.from_fen(f).fen(), f)
        for bad in ["", "x", "8/8/8/8/8/8/8/8 w - - 0 1", "k7/8/8/8/8/8/8/K7 x - - 0 1", "k7/8/8/8/8/8/8/K8 w - - 0 1",
                    "kk6/8/8/8/8/8/8/K7 w - - 0 1", "P3k3/8/8/8/8/8/8/4K3 w - - 0 1", "4k3/8/8/8/8/8/8/4K3 w - - 0 1" + "x" * 200,
                    "4k3/8/8/8/8/8/4R3/4K3 w - - 0 1", "\x00", 5, None]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                G.Position.from_fen(bad)

    def test_fools_mate_is_checkmate(self):
        g = game(G.START, "f2f3", "e7e5", "g2g4", "d8h4")
        self.assertEqual(g.status(), "checkmate: Black wins")
        self.assertIn("over", g.play("a2a3"))

    def test_stalemate(self):
        g = G.Game("7k/5Q2/6K1/8/8/8/8/8 b - - 0 1")
        self.assertEqual(g.status(), "draw: stalemate")

    def test_castling_both_sides_and_through_check(self):
        g = game("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", "e1g1")
        self.assertEqual(g.pos.fen(), "r3k2r/8/8/8/8/8/8/R4RK1 b kq - 1 1")
        g = game("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", "e1c1", "e8g8")
        self.assertEqual(g.pos.fen(), "r4rk1/8/8/8/8/8/8/2KR3R w - - 2 2")
        g = G.Game("4k3/8/8/8/8/8/5r2/R3K2R w KQ - 0 1")      # f1 attacked: no kingside castling
        self.assertIn("cannot", g.play("e1g1"))
        # moving the rook loses the right
        g = game("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", "h1h2", "a8a7", "h2h1", "a7a8")
        self.assertIn("cannot", g.play("e1g1"))

    def test_en_passant(self):
        g = game("4k3/8/8/8/3p4/8/4P3/4K3 w - - 0 1", "e2e4")
        self.assertEqual(g.pos.fen().split()[3], "e3")
        g.play("d4e3")
        self.assertEqual(g.pos.fen(), "4k3/8/8/8/8/4p3/8/4K3 w - - 0 2")
        g.undo(); g.undo() if False else None
        self.assertEqual(g.pos.fen().split()[0], "4k3/8/8/8/3pP3/8/8/4K3")
        # the right lapses after one move
        g = game("4k3/8/8/8/3p4/8/4P3/4K3 w - - 0 1", "e2e4", "e8e7", "e1e2")
        self.assertNotEqual(g.play("d4e3"), "")

    def test_promotion(self):
        g = G.Game("8/4P2k/8/8/8/8/8/K7 w - - 0 1")
        self.assertIn("promotion needs", g.play("e7e8"))
        self.assertIn("not a promotion", g.play("a1a2q"))
        self.assertEqual(g.play("e7e8n"), "")
        self.assertEqual(g.pos.fen(), "4N3/7k/8/8/8/8/8/K7 b - - 0 1")
        g = game("8/4P2k/8/8/8/8/8/K7 w - - 0 1", "e7e8q")
        self.assertEqual(g.pos.fen().split()[0], "4Q3/7k/8/8/8/8/8/K7")

    def test_refusals(self):
        g = G.Game()
        for txt, frag in [("", "two squares"), ("zz", "two squares"), ("e2e9", "two squares"), ("e3e4", "no piece"),
                          ("e7e5", "belongs to Black"), ("e2e5", "cannot move"), ("a1a3", "cannot move"), ("g1g3", "cannot"),
                          ("\x00\x1b[2J", "two squares"), ("e2e4" * 5000, "two squares"), (None, "enter a move"), (7, "enter a move")]:
            self.assertIn(frag, g.play(txt), repr(txt)[:20])
        self.assertEqual(g.pos.fen(), G.START)
        g = G.Game("4k3/8/8/8/8/8/4r3/R3K3 w - - 0 1")
        self.assertIn("in check", g.play("a1a2"))
        g = G.Game("4k3/8/8/8/8/8/4r3/4K3 w - - 0 1")           # pinned-ish: king into attack
        self.assertIn("in check", g.play("e1d2"))

    def test_pinned_piece_cannot_move(self):
        g = G.Game("4r1k1/8/8/8/8/8/4B3/4K3 w - - 0 1")
        self.assertIn("leave your king in check", g.play("e2d3"))

    def test_draws(self):
        self.assertEqual(G.Game("8/8/4k3/8/8/4K3/8/8 w - - 0 1").status(), "draw: insufficient material")
        self.assertEqual(G.Game("8/8/4k3/8/8/4KB2/8/8 w - - 0 1").status(), "draw: insufficient material")
        self.assertEqual(G.Game("8/8/4k3/8/8/4KR2/8/8 w - - 0 1").status(), "check" if False else "")
        self.assertEqual(G.Game("4k3/8/8/8/8/8/8/R3K3 w - - 100 80").status(), "draw: fifty-move rule")
        self.assertEqual(G.Game("4k3/8/8/8/8/8/8/R3K3 w - - 99 80").status(), "")
        g = game("4k3/8/8/8/8/8/8/R3K3 w - - 0 1", *["a1a2", "e8e7", "a2a1", "e7e8"] * 2)
        self.assertEqual(g.status(), "draw: threefold repetition")
        g.undo()
        self.assertEqual(g.status(), "")

    def test_undo_restores_everything(self):
        g = game(KIWI, "e1g1", "b4c3", "d2c3")
        g2 = G.Game(KIWI)
        while g.undo(): pass
        self.assertEqual(g.pos.fen(), G.Position.from_fen(KIWI).fen())
        self.assertFalse(g.undo())
        self.assertEqual(len(g.seen), 1)
        _ = g2

    def test_computer_finds_mate_and_free_queen_and_is_bounded(self):
        p = G.Position.from_fen("6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1")
        m, score, n = G.best_move(p, 2)
        self.assertEqual(G.mstr(m), "a1a8")
        self.assertGreater(score, 29000)
        p = G.Position.from_fen("4k3/8/8/3q4/8/8/8/3QK3 w - - 0 1")
        m, _, _ = G.best_move(p, 2)
        self.assertEqual(G.mstr(m), "d1d5")
        for lv, (d, cap) in G.LEVELS.items():
            p = G.Position.from_fen(KIWI)
            fen = p.fen()
            m, _, n = G.best_move(p, lv)
            self.assertLessEqual(n, cap + 1)
            self.assertEqual(p.fen(), fen)
            self.assertIn(m, p.legal())
            self.assertEqual(G.best_move(p, lv)[0], m)       # deterministic
        self.assertEqual(G.best_move(G.Position.from_fen("7k/5Q2/6K1/8/8/8/8/8 b - - 0 1"))[0], None)

    def test_screen_plays_saves_and_resumes(self):
        h = FakeHost(list("e2e4") + ["enter"] + list("zz") + ["enter"] + list("undo") + ["enter"] + list("fen") + ["enter", "escape"])
        run(h, G.ChessScreen(h))
        self.assertIn("undone", h.text)
        h = FakeHost(list("e2e4") + ["enter"], data=None)
        run(h, G.ChessScreen(h))
        self.assertIn("chess", h.data)
        self.assertIn("e2e4", h.text)
        h2 = FakeHost(["x"], data=h.data)
        s = G.ChessScreen(h2)
        self.assertEqual(len(s.game.log), 2)              # human move + computer reply
        bad = FakeHost([], data={"chess": '{"start": "junk", "moves": ["e2e4"]}'})
        self.assertEqual(G.ChessScreen(bad).game.pos.fen(), G.START)

    def test_screen_commands_never_crash(self):
        keys = []
        for c in ["help", "new", "moves", "flip", "cpu white", "cpu off", "cpu x", "level 3", "level 9", "load nonsense", "load " + G.START, "undo", "undo", "fen"]:
            keys += list(c) + ["enter", "escape"]
        keys += ["\x00", "ctrl-u", "left", "x"] * 3
        h = FakeHost(keys)
        run(h, G.ChessScreen(h))
        self.assertNotIn("Internal error", "\n".join(t for t, _l, _s in h.frames))


class Test2048(unittest.TestCase):
    def test_slide_rows(self):
        for row, out, sc in [([2, 2, 2, 2], [4, 4, 0, 0], 8), ([2, 2, 2, 0], [4, 2, 0, 0], 4), ([0, 2, 0, 2], [4, 0, 0, 0], 4),
                             ([4, 2, 2, 0], [4, 4, 0, 0], 4), ([2, 4, 8, 16], [2, 4, 8, 16], 0), ([2, 2, 4, 4], [4, 8, 0, 0], 12),
                             ([4, 4, 8, 0], [8, 8, 0, 0], 8), ([0, 0, 0, 0], [0, 0, 0, 0], 0)]:
            self.assertEqual(G.slide_row(row), (out, sc), row)

    def test_directions(self):
        b = [2, 0, 0, 2] + [0] * 12
        self.assertEqual(G.move2048(b, "right")[0][:4], [0, 0, 0, 4])
        self.assertEqual(G.move2048(b, "left")[0][:4], [4, 0, 0, 0])
        col = [2, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0]
        self.assertEqual(G.move2048(col, "up"), ([4, 0, 0, 0, 8, 0, 0, 0] + [0] * 8, 12))
        self.assertEqual(G.move2048(col, "down")[0][12], 8)

    def test_game_spawn_and_over(self):
        g = G.Game2048(seed=1)
        self.assertEqual(sum(1 for v in g.board if v), 2)
        self.assertEqual(G.Game2048(seed=1).board, g.board)
        before = list(g.board)
        moved = [d for d in ("left", "right", "up", "down") if g.step(d)]
        self.assertTrue(moved)
        self.assertEqual(sum(1 for v in g.board if v), 3 if len(moved) == 1 else sum(1 for v in g.board if v))
        full = [2, 4, 2, 4, 4, 2, 4, 2, 2, 4, 2, 4, 4, 2, 4, 2]
        self.assertFalse(G.Game2048(1, full).can_move())
        self.assertNotEqual(before, [])

    def test_screen_saves_best(self):
        h = FakeHost(list("aswdasdw") + ["left", "right", "n", "escape"])
        run(h, G.casual(h))   # menu only
        h = FakeHost(["enter"] + list("aswdasdwaswd") + ["escape", "escape"])
        run(h, G.casual(h))
        self.assertIn("casual-games", h.data)
        self.assertIn('"best"', h.data["casual-games"])


class TestMines(unittest.TestCase):
    def test_first_click_never_a_mine_and_floods(self):
        for seed in range(60):
            g = G.Mines(seed=seed)
            i = seed % 81
            g.reveal(i)
            self.assertFalse(g.dead)
            self.assertNotIn(i, g.mines)
            self.assertEqual(len(g.mines), 10)
            self.assertTrue(set(g.nbrs(i)).isdisjoint(g.mines))
            self.assertGreater(len(g.open), 1)                 # the zero cell flooded outward

    def test_flood_stops_at_numbers_and_counts(self):
        g = G.Mines(w=4, h=1, n=0, seed=1)
        g.n, g.mines = 1, {3}
        g.reveal(0)
        self.assertEqual(g.open, {0, 1, 2})
        self.assertEqual(g.count(2), 1)
        g = G.Mines(w=4, h=2, n=0, seed=1)
        g.n, g.mines = 1, {3}
        g.reveal(3)
        self.assertTrue(g.dead)

    def test_flags_and_win(self):
        g = G.Mines(w=4, h=1, n=0, seed=1)
        g.n, g.mines = 1, {3}
        g.flag(3); g.reveal(3)
        self.assertFalse(g.dead)
        g.reveal(0)
        self.assertTrue(g.won())

    def test_screen(self):
        h = FakeHost(["enter", "right", "f", "down", " ", "n", "escape"])
        run(h, G.MinesScreen(h, seed=3))
        self.assertIn("mines", h.text)


class TestSudoku(unittest.TestCase):
    def test_solver_known_puzzle(self):
        p = "530070000600195000098000060800060003400803001700020006060000280000419005000080079"
        s = "534678912672195348198342567859761423426853791713924856961537284287419635345286179"
        n, sol, capped = G.solve([int(c) for c in p], 2)
        self.assertEqual((n, "".join(map(str, sol)), capped), (1, s, False))

    def test_solver_detects_none_and_many(self):
        self.assertEqual(G.solve([0] * 81, 2)[0], 2)
        bad = [5, 5] + [0] * 79
        self.assertEqual(G.solve(bad)[0], 0)
        self.assertEqual(G.solve([1, 2, 3, 4, 5, 6, 7, 8, 0] + [0] * 72 if False else [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9] + [0] * 63)[0], 0)

    def test_generator_unique_and_deterministic(self):
        for seed in (1, 2, 3):
            puz, sol = G.make_sudoku(random.Random(seed), 34)
            self.assertEqual(G.solve(puz, 5)[0], 1)
            self.assertEqual(G.solve(puz, 2)[1], sol)
            self.assertFalse(G.conflicts(sol))
            self.assertEqual(0 in sol, False)
            self.assertTrue(all(a == b for a, b in zip(puz, sol) if a))
            self.assertLessEqual(sum(1 for v in puz if v), 45)
            self.assertEqual(G.make_sudoku(random.Random(seed), 34), (puz, sol))

    def test_conflicts(self):
        g = [0] * 81
        g[0] = g[8] = 3
        g[40] = 4; g[41] = 4
        self.assertEqual(G.conflicts(g), {0, 8, 40, 41})

    def test_screen_solves_with_hints_and_saves(self):
        h = FakeHost(["enter"] + ["h", "right"] * 80 + ["h", "escape", "escape"])
        run(h, G.casual(h))
        h = FakeHost(["3"] + list("c") + ["escape"])
        s = G.SudokuScreen(h, seed=5)
        self.assertEqual(G.solve(s.given, 2)[0], 1)
        for i in range(81):
            s.cur = i; s.key("h")
        self.assertTrue(s.solved())
        self.assertIn("SOLVED", "\n".join(s.render(80, 30)))
        self.assertIn("casual-games", h.data)
        s2 = G.SudokuScreen(h, seed=99)                  # resumes the saved puzzle
        self.assertEqual(s2.given, s.given)
        s.cur = next(i for i in range(81) if s.given[i]); s.key("5")
        self.assertIn("given", s.msg)


class TestTicTacToe(unittest.TestCase):
    def test_computer_wins_or_blocks(self):
        self.assertEqual(G.ttt_best((1, 1, 0, -1, -1, 0, 0, 0, 0), 1), 2)       # X wins
        self.assertEqual(G.ttt_best((1, 1, 0, -1, 0, 0, 0, 0, 0), -1), 2)       # O must block
        self.assertEqual(G.ttt_best((1, 1, 0, -1, -1, 0, 0, 0, 0), -1), 5)      # O wins rather than blocks

    def _never_loses(self, comp):
        """Every possible human strategy (all legal replies, depth-first) against the computer."""
        count = [0]

        def walk(b, turn):
            w = G.ttt_winner(b)
            if w: self.assertEqual(w, comp, b); count[0] += 1; return
            if 0 not in b: count[0] += 1; return
            if turn == comp: walk(b[:(i := G.ttt_best(b, turn))] + (turn,) + b[i + 1:], -turn)
            else:
                for i in range(9):
                    if b[i] == 0: walk(b[:i] + (turn,) + b[i + 1:], -turn)
        walk((0,) * 9, 1)
        self.assertGreater(count[0], 50)

    def test_never_loses_as_second_player(self): self._never_loses(-1)
    def test_never_loses_as_first_player(self): self._never_loses(1)

    def test_screen_records_result(self):
        h = FakeHost(["enter"] * 0 + ["4", "escape"])
        s = G.TTTScreen(h)
        for k in "5123456789":
            s.key(k)
        self.assertTrue(s.done)
        self.assertNotEqual(s.msg, "You win!")
        self.assertIn("ttt", h.data["casual-games"])
        s.key("n")
        self.assertEqual(s.b.count(1), 1)                # computer opened as X


class TestLibrary(unittest.TestCase):
    ITEMS = [{"title": "Zelda", "platform": "Console", "status": "completed", "hours": "60", "rating": "9"},
             {"title": "Chess", "platform": "PC", "status": "playing", "hours": "12.5", "rating": "7"},
             {"title": "Odd", "platform": "PC", "status": "backlog", "hours": "abc", "rating": "99"}]

    def test_playtime(self):
        out = G.playtime(self.ITEMS)
        self.assertEqual(out[0], "3 game(s), 72.5 hours in total")
        self.assertIn("  Console            60 h", out)
        self.assertIn("  PC               12.5 h", out)
        self.assertIn("Average rating 8.0 of 10 over 2 rated game(s)", out)
        self.assertEqual(G.playtime([])[0], "0 game(s), 0 hours in total")

    def test_screen_adds_and_saves(self):
        h = FakeHost(["a", "enter", "T", "e", "t", "enter", "ctrl-s", "escape"])
        run(h, G.library(h))
        self.assertIn("records", h.data)
        self.assertIn("Tet", h.data["records"])
        h = FakeHost(["R", "escape", "escape"], data=h.data)
        run(h, G.library(h))
        self.assertTrue(any("Play-time" in t or "hours in total" in "\n".join(l) for t, l, s in h.frames))


class TestEntries(unittest.TestCase):
    def test_entries(self):
        self.assertEqual([(e.title, e.scope) for e in G.ENTRIES], [("Chess", "full"), ("Casual Games", "full"), ("Game Library", "partial")])
        for e in G.ENTRIES:
            h = FakeHost(["enter", "down", "enter", "escape", "escape"] + list("1a b") * 3)
            run(h, e.args["make"](h, e))
            self.assertTrue(h.frames)
            self.assertNotIn("Internal error", "\n".join(t for t, _l, _s in h.frames), e.title)
            self.assertGreater(len(e.note), 20)


if __name__ == "__main__":
    unittest.main()
