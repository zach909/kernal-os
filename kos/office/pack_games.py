"""pack_games: Chess, Casual Games, Game Library. See docs/PACKS.md.

Light by design: turn-based only (a key press advances a game), no timers, no background work, and every
search is bounded by a fixed depth and a node cap, never by the clock."""

from __future__ import annotations

import json
import random
import re

from .packkit import app
from .records import Data, RecordList
from .specs import R
from .ui import Menu, Message, Screen, Store, TextInput, TextView

# ===================================================================== chess ==
START = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
SQS = [r * 16 + c for r in range(8) for c in range(8)]
KN = (33, 31, 18, 14, -33, -31, -18, -14)
KG = (1, -1, 16, -16, 15, -15, 17, -17)
DIAG, ORTH = (15, -15, 17, -17), (1, -1, 16, -16)
MASK = {0: 13, 7: 14, 4: 12, 112: 7, 119: 11, 116: 3}      # castling rights kept when a piece leaves/enters
VAL = (0, 100, 320, 330, 500, 900, 0)
MATE = 30000
MAX_PLIES = 600


def sqname(s): return "abcdefgh"[s & 7] + str((s >> 4) + 1)


class Position:
    """Board in 0x88 layout. Pieces: 1..6 = P N B R Q K, positive white, negative black."""

    def __init__(self):
        self.b = [0] * 128
        self.side, self.castle, self.ep, self.half, self.full = 1, 0, -1, 0, 1
        self.k = {1: -1, -1: -1}

    # ---- FEN
    @classmethod
    def from_fen(cls, fen: str) -> "Position":
        if not isinstance(fen, str) or len(fen) > 100 or not fen.isprintable():
            raise ValueError("not a FEN")
        f = fen.split()
        if len(f) == 4: f += ["0", "1"]
        if len(f) != 6: raise ValueError("FEN needs 6 fields (or the first 4)")
        p = cls()
        rows = f[0].split("/")
        if len(rows) != 8: raise ValueError("FEN needs 8 ranks")
        for i, row in enumerate(rows):
            rank, file = 7 - i, 0
            for ch in row:
                if ch.isdigit() and ch != "0" and ch != "9":
                    file += int(ch)
                elif ch.lower() in "pnbrqk" and ch.isalpha():
                    if file > 7: raise ValueError("rank too long")
                    t = "pnbrqk".index(ch.lower()) + 1
                    p.b[rank * 16 + file] = t if ch.isupper() else -t
                    file += 1
                else:
                    raise ValueError("bad character in FEN board")
            if file != 8: raise ValueError("each rank needs 8 squares")
        if f[1] not in ("w", "b"): raise ValueError("side to move must be w or b")
        p.side = 1 if f[1] == "w" else -1
        for s in SQS:
            if abs(p.b[s]) == 6:
                if p.k[1 if p.b[s] > 0 else -1] >= 0: raise ValueError("more than one king")
                p.k[1 if p.b[s] > 0 else -1] = s
            if abs(p.b[s]) == 1 and (s >> 4) in (0, 7): raise ValueError("pawn on the first or last rank")
        if p.k[1] < 0 or p.k[-1] < 0: raise ValueError("each side needs a king")
        if f[2] != "-" and not re.fullmatch(r"K?Q?k?q?", f[2]): raise ValueError("bad castling field")
        cs = 0
        for ch, bit, kq, rk in (("K", 1, 4, 7), ("Q", 2, 4, 0), ("k", 4, 116, 119), ("q", 8, 116, 112)):
            if ch in f[2] and f[2] != "-" and p.b[kq] == (6 if ch.isupper() else -6) and p.b[rk] == (4 if ch.isupper() else -4):
                cs |= bit
        p.castle = cs
        if f[3] != "-":
            if not re.fullmatch(r"[a-h][36]", f[3]): raise ValueError("bad en passant square")
            e = "abcdefgh".index(f[3][0]) + (int(f[3][1]) - 1) * 16
            if (e >> 4) == (5 if p.side == 1 else 2) and p.b[e] == 0 and p.b[e - 16 * p.side] == -p.side and p.b[e + 16 * p.side] == 0:
                p.ep = e
        if not (f[4].isdigit() and f[5].isdigit() and len(f[4]) < 5 and len(f[5]) < 5): raise ValueError("bad move counters")
        p.half, p.full = int(f[4]), max(1, int(f[5]))
        if p.attacked(p.k[-p.side], p.side): raise ValueError("the side not to move is in check")
        return p

    def fen(self) -> str:
        rows = []
        for r in range(7, -1, -1):
            s, n = "", 0
            for c in range(8):
                v = self.b[r * 16 + c]
                if v == 0: n += 1; continue
                if n: s += str(n); n = 0
                ch = "pnbrqk"[abs(v) - 1]
                s += ch.upper() if v > 0 else ch
            rows.append(s + (str(n) if n else ""))
        cs = "".join(ch for ch, bit in (("K", 1), ("Q", 2), ("k", 4), ("q", 8)) if self.castle & bit) or "-"
        return f"{'/'.join(rows)} {'w' if self.side == 1 else 'b'} {cs} {sqname(self.ep) if self.ep >= 0 else '-'} {self.half} {self.full}"

    # ---- attacks and moves
    def attacked(self, sq, by) -> bool:
        b = self.b
        d = -16 if by == 1 else 16
        for o in (d - 1, d + 1):
            s = sq + o
            if not s & 0x88 and b[s] == by: return True
        for o in KN:
            s = sq + o
            if not s & 0x88 and b[s] == by * 2: return True
        for o in KG:
            s = sq + o
            if not s & 0x88 and b[s] == by * 6: return True
        for dirs, q in ((DIAG, by * 3), (ORTH, by * 4)):
            for o in dirs:
                s = sq + o
                while not s & 0x88:
                    v = b[s]
                    if v:
                        if v == q or v == by * 5: return True
                        break
                    s += o
        return False

    def in_check(self) -> bool:
        return self.attacked(self.k[self.side], -self.side)

    def pseudo(self) -> list:
        b, side, out = self.b, self.side, []
        for sq in SQS:
            p = b[sq]
            if p * side <= 0: continue
            t = abs(p)
            if t == 1:
                fw, last = 16 * side, (6 if side == 1 else 1)
                to = sq + fw
                if not to & 0x88 and b[to] == 0:
                    if (sq >> 4) == last: out += [(sq, to, pr) for pr in (5, 4, 3, 2)]
                    else:
                        out.append((sq, to, 0))
                        if (sq >> 4) == (1 if side == 1 else 6) and b[to + fw] == 0: out.append((sq, to + fw, 0))
                for o in (fw - 1, fw + 1):
                    to = sq + o
                    if to & 0x88: continue
                    if b[to] * side < 0 or (to == self.ep and b[to] == 0):
                        if (sq >> 4) == last: out += [(sq, to, pr) for pr in (5, 4, 3, 2)]
                        else: out.append((sq, to, 0))
            elif t in (2, 6):
                for o in (KN if t == 2 else KG):
                    to = sq + o
                    if not to & 0x88 and b[to] * side <= 0: out.append((sq, to, 0))
            else:
                for o in (DIAG if t == 3 else ORTH if t == 4 else KG):
                    to = sq + o
                    while not to & 0x88:
                        if b[to] * side > 0: break
                        out.append((sq, to, 0))
                        if b[to]: break
                        to += o
        ks = 4 if side == 1 else 116
        if b[ks] == side * 6 and self.castle & (3 if side == 1 else 12):
            en = -side
            if self.castle & (1 if side == 1 else 4) and b[ks + 1] == 0 and b[ks + 2] == 0 and b[ks + 3] == side * 4 \
                    and not self.attacked(ks, en) and not self.attacked(ks + 1, en) and not self.attacked(ks + 2, en):
                out.append((ks, ks + 2, 0))
            if self.castle & (2 if side == 1 else 8) and b[ks - 1] == 0 and b[ks - 2] == 0 and b[ks - 3] == 0 and b[ks - 4] == side * 4 \
                    and not self.attacked(ks, en) and not self.attacked(ks - 1, en) and not self.attacked(ks - 2, en):
                out.append((ks, ks - 2, 0))
        return out

    def legal(self) -> list:
        side, out = self.side, []
        for m in self.pseudo():
            u = self.make(m)
            if not self.attacked(self.k[side], -side): out.append(m)
            self.unmake(m, u)
        return out

    def make(self, m):
        f, t, pr = m
        b, side = self.b, self.side
        p, cap = b[f], b[t]
        capsq = t if cap else -1
        u = (p, cap, capsq, self.castle, self.ep, self.half)
        a = abs(p)
        if a == 1 and t == self.ep and not cap and (f & 7) != (t & 7):
            capsq = t - 16 * side; cap = b[capsq]; b[capsq] = 0
            u = (p, cap, capsq, self.castle, self.ep, self.half)
        b[t] = side * pr if pr else p
        b[f] = 0
        if a == 6:
            self.k[side] = t
            if t - f == 2: b[f + 1] = b[f + 3]; b[f + 3] = 0
            elif f - t == 2: b[f - 1] = b[f - 4]; b[f - 4] = 0
        self.castle &= MASK.get(f, 15) & MASK.get(t, 15)
        self.ep = (f + t) // 2 if a == 1 and abs(t - f) == 32 else -1
        self.half = 0 if a == 1 or cap else self.half + 1
        if side == -1: self.full += 1
        self.side = -side
        return u

    def unmake(self, m, u):
        f, t, pr = m
        p, cap, capsq, self.castle, self.ep, self.half = u
        b = self.b
        self.side = side = -self.side
        if side == -1: self.full -= 1
        b[f] = p; b[t] = 0
        if capsq >= 0: b[capsq] = cap
        if abs(p) == 6:
            self.k[side] = f
            if t - f == 2: b[f + 3] = b[f + 1]; b[f + 1] = 0
            elif f - t == 2: b[f - 4] = b[f - 1]; b[f - 1] = 0

    def key(self):
        """Repetition key: the en passant square counts only if a pawn could actually take."""
        ep = -1
        if self.ep >= 0:
            for o in (-1, 1):
                s = self.ep - 16 * self.side + o
                if not s & 0x88 and self.b[s] == self.side: ep = self.ep
        return (tuple(self.b), self.side, self.castle, ep)

    def insufficient(self) -> bool:
        minors = []
        for s in SQS:
            v = abs(self.b[s])
            if v in (1, 4, 5): return False
            if v in (2, 3): minors.append((v, ((s & 7) + (s >> 4)) & 1))
        return len(minors) <= 1 or (all(v == 3 for v, _ in minors) and len({c for _, c in minors}) == 1)

    def text(self, flip=False) -> list:
        ranks = range(8) if flip else range(7, -1, -1)
        files = range(7, -1, -1) if flip else range(8)
        out = []
        for r in ranks:
            out.append(f" {r + 1}  " + " ".join(("." if not self.b[r * 16 + c] else
                       ("PNBRQK"[abs(self.b[r * 16 + c]) - 1] if self.b[r * 16 + c] > 0 else "pnbrqk"[abs(self.b[r * 16 + c]) - 1])) for c in files))
        out.append("    " + " ".join("abcdefgh"[c] for c in files))
        return out


def perft(pos: Position, depth: int) -> int:
    if depth == 0: return 1
    ms = pos.legal()
    if depth == 1: return len(ms)
    n = 0
    for m in ms:
        u = pos.make(m); n += perft(pos, depth - 1); pos.unmake(m, u)
    return n


def mstr(m) -> str:
    return sqname(m[0]) + sqname(m[1]) + ({5: "q", 4: "r", 3: "b", 2: "n"}[m[2]] if m[2] else "")


class Game:
    """A game in progress: the position, the move list (for undo), and the positions seen (for repetition)."""

    def __init__(self, fen=START):
        self.start = fen
        self.pos = Position.from_fen(fen)
        self.log: list = []           # (text, move, undo)
        self.seen = [self.pos.key()]

    def parse(self, text):
        """-> (move, error). A refusal says why."""
        if not isinstance(text, str): return None, "enter a move like e2e4"
        s = re.sub(r"[\s\-]", "", text.lower())
        m = re.fullmatch(r"([a-h][1-8])([a-h][1-8])([qrbn]?)", s)
        if not m: return None, "a move is two squares, like e2e4 (promotion: e7e8q)"
        f = "abcdefgh".index(m.group(1)[0]) + (int(m.group(1)[1]) - 1) * 16
        t = "abcdefgh".index(m.group(2)[0]) + (int(m.group(2)[1]) - 1) * 16
        pr = {"q": 5, "r": 4, "b": 3, "n": 2}.get(m.group(3), 0)
        pos = self.pos
        p = pos.b[f]
        if not p: return None, f"there is no piece on {m.group(1)}"
        if p * pos.side < 0: return None, f"the piece on {m.group(1)} belongs to {'Black' if pos.side == 1 else 'White'}, not you"
        match = [x for x in pos.legal() if x[0] == f and x[1] == t]
        if match:
            if match[0][2] and not pr: return None, "promotion needs a piece: add q, r, b or n (e7e8q)"
            if pr and not match[0][2]: return None, "that move is not a promotion"
            return (f, t, pr), ""
        if any(x[0] == f and x[1] == t for x in pos.pseudo()):
            return None, ("your king is in check and that move does not end the check" if pos.in_check()
                          else "illegal: that would leave your king in check")
        return None, f"a {'pnbrqk'[abs(p) - 1].upper()} cannot move from {m.group(1)} to {m.group(2)}"

    def play(self, text) -> str:
        if self.over(): return "the game is over: " + self.status()
        if len(self.log) >= MAX_PLIES: return f"game limit of {MAX_PLIES} half-moves reached"
        m, err = self.parse(text)
        if err: return err
        self.push(m)
        return ""

    def push(self, m):
        self.log.append((mstr(m), m, self.pos.make(m)))
        self.seen.append(self.pos.key())

    def undo(self) -> bool:
        if not self.log: return False
        _, m, u = self.log.pop()
        self.pos.unmake(m, u); self.seen.pop()
        return True

    def status(self) -> str:
        pos = self.pos
        if not pos.legal():
            return ("checkmate: " + ("Black" if pos.side == 1 else "White") + " wins") if pos.in_check() else "draw: stalemate"
        if pos.insufficient(): return "draw: insufficient material"
        if self.seen.count(self.seen[-1]) >= 3: return "draw: threefold repetition"
        if pos.half >= 100: return "draw: fifty-move rule"
        return "check" if pos.in_check() else ""

    def over(self) -> bool:
        return self.status().startswith(("checkmate", "draw"))


# ---- computer opponent: iterative alpha-beta, fixed depth and a node cap (no clock)
def evaluate(pos: Position) -> int:
    s = 0
    for sq in SQS:
        v = pos.b[sq]
        if not v: continue
        a, c = abs(v), 3 - max(abs((sq & 7) * 2 - 7), abs((sq >> 4) * 2 - 7)) // 2
        x = VAL[a] + (6 * c if a in (2, 3) else 0)
        if a == 1: x += 4 * c + 3 * ((sq >> 4) if v > 0 else 7 - (sq >> 4))
        s += x if v > 0 else -x
    return s * pos.side


def _order(pos, ms, first=None):
    b = pos.b
    def sc(m):
        v = 10 * VAL[abs(b[m[1]])] - VAL[abs(b[m[0]])] if b[m[1]] else 0
        return v + (VAL[m[2]] if m[2] else 0) + (1000000 if m == first else 0)
    return sorted(ms, key=sc, reverse=True)


class Searcher:
    def __init__(self, cap):
        self.cap, self.nodes, self.abort = cap, 0, False

    def go(self, pos, depth, alpha, beta, ply):
        self.nodes += 1
        if self.nodes > self.cap: self.abort = True; return 0
        if depth == 0: return evaluate(pos)
        ms = pos.legal()
        if not ms: return -MATE + ply if pos.in_check() else 0
        for m in _order(pos, ms):
            u = pos.make(m); v = -self.go(pos, depth - 1, -beta, -alpha, ply + 1); pos.unmake(m, u)
            if self.abort: return 0
            if v > alpha:
                alpha = v
                if alpha >= beta: break
        return alpha


LEVELS = {1: (1, 400), 2: (2, 4000), 3: (3, 12000)}      # level -> (depth, node cap)


def best_move(pos: Position, level: int = 2):
    """-> (move, score, nodes). Deterministic: same position, same answer."""
    depth, cap = LEVELS.get(level, LEVELS[2])
    ms = pos.legal()
    if not ms: return None, 0, 0
    se, best, bscore = Searcher(cap), _order(pos, ms)[0], 0
    for d in range(1, depth + 1):
        cur, cscore, alpha = None, -MATE * 2, -MATE * 2
        for m in _order(pos, ms, best):
            u = pos.make(m); v = -se.go(pos, d - 1, -MATE * 2, -alpha, 1); pos.unmake(m, u)
            if se.abort: break
            if v > cscore: cur, cscore = m, v
            alpha = max(alpha, v)
        if se.abort: break
        best, bscore = cur, cscore
        if abs(bscore) > MATE - 100: break
    return best, bscore, se.nodes


class ChessScreen(Screen):
    title = "Chess"
    help = "type a move (e2e4, e7e8q) + Enter   commands: help"
    KEY = "chess"

    def __init__(self, host):
        self.host, self.store = host, Store(host)
        self.inp, self.msg, self.flip = TextInput(), "", False
        self.cpu, self.level = -1, 2           # computer plays Black by default
        self.game = Game()
        d = self.store.load(self.KEY)
        if isinstance(d, dict):
            try:
                g = Game(d["start"])
                for t in d["moves"][:MAX_PLIES]:
                    m, err = g.parse(t)
                    if err: raise ValueError(err)
                    g.push(m)
                self.game = g
                self.cpu = d["cpu"] if d.get("cpu") in (-1, 0, 1) else -1
                self.level = d["level"] if d.get("level") in LEVELS else 2
            except (KeyError, ValueError, TypeError, AttributeError):
                self.game = Game()

    def save(self):
        self.store.save(self.KEY, {"start": self.game.start, "moves": [t for t, _, _ in self.game.log], "cpu": self.cpu, "level": self.level})

    def reply(self):
        g = self.game
        if self.cpu and g.pos.side == self.cpu and not g.over() and len(g.log) < MAX_PLIES:
            m, _, n = best_move(g.pos, self.level)
            if m:
                g.push(m); self.msg = f"computer plays {mstr(m)} ({n} nodes searched)"

    def render(self, w, h):
        g = self.game
        out = [""] + ["  " + l for l in g.pos.text(self.flip)] + [""]
        mv = [t for t, _, _ in g.log]
        pairs = [f"{i // 2 + 1}. " + " ".join(mv[i:i + 2]) for i in range(0, len(mv), 2)][-4:]
        st = g.status()
        out.append(f"  {'White' if g.pos.side == 1 else 'Black'} to move" + (f" - {st}" if st else "") + f"   (computer: {'off' if not self.cpu else 'Black' if self.cpu == -1 else 'White'}, level {self.level})")
        out.append("  moves: " + (" ".join(pairs) if pairs else "-"))
        out.append("  " + self.msg)
        out += ["", "  move> " + self.inp.render()[:60]]
        return out

    def command(self, text):
        g, w = self.game, text.split()
        c = w[0].lower() if w else ""
        if c == "help":
            return ("push", Message("Chess help", ["Type a move: from-square then to-square (e2e4). Promotion: add q, r, b or n (e7e8q). Castle by moving the king two squares (e1g1).",
                    "Commands: undo, new, fen, load <FEN>, moves (legal moves), flip, cpu off|white|black, level 1|2|3.",
                    "The computer searches to a fixed depth with a node cap (no clock), so level 3 can still be beaten. Draws by stalemate, insufficient material, threefold repetition and the fifty-move rule are applied automatically."]))
        if c == "undo":
            n = 0
            while g.undo():
                n += 1
                if not self.cpu or g.pos.side != self.cpu: break
            self.msg = "undone" if n else "nothing to undo"
        elif c == "new": self.game = Game(); self.msg = "new game"
        elif c == "fen": return ("push", Message("FEN", [g.pos.fen()]))
        elif c == "load":
            try: self.game = Game(text[4:].strip()); self.msg = "position loaded"
            except ValueError as e: self.msg = f"refused: {e}"
        elif c == "moves": return ("push", TextView("Legal moves", ["  " + " ".join(sorted(mstr(m) for m in g.pos.legal()))]))
        elif c == "flip": self.flip = not self.flip
        elif c == "cpu" and len(w) == 2 and w[1].lower() in ("off", "white", "black"):
            self.cpu = {"off": 0, "white": 1, "black": -1}[w[1].lower()]; self.msg = "computer: " + w[1].lower(); self.reply()
        elif c == "level" and len(w) == 2 and w[1] in ("1", "2", "3"): self.level = int(w[1]); self.msg = f"level {self.level}"
        else:
            err = g.play(text)
            if err: self.msg = "refused: " + err
            else: self.msg = f"played {g.log[-1][0]}"; self.reply()
        self.save()

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "enter":
            text, self.inp = self.inp.value.strip()[:100], TextInput()
            return self.command(text) if text else None
        self.inp.key(k)


# ============================================================ casual games ==
def _rng(seed): return random.Random(seed)


# ---- 2048
def _lines(d):
    rows = [[r * 4 + c for c in range(4)] for r in range(4)]
    cols = [[r * 4 + c for r in range(4)] for c in range(4)]
    return {"left": rows, "right": [x[::-1] for x in rows], "up": cols, "down": [x[::-1] for x in cols]}[d]


def slide_row(row):
    """Slide a row toward index 0. Each tile merges at most once per move; the pair nearest the wall merges first."""
    tiles, out, score, i = [x for x in row if x], [], 0, 0
    while i < len(tiles):
        if i + 1 < len(tiles) and tiles[i] == tiles[i + 1]:
            out.append(tiles[i] * 2); score += tiles[i] * 2; i += 2
        else:
            out.append(tiles[i]); i += 1
    return out + [0] * (len(row) - len(out)), score


def move2048(board, d):
    nb, gained = list(board), 0
    for idx in _lines(d):
        row, s = slide_row([board[i] for i in idx])
        gained += s
        for i, v in zip(idx, row): nb[i] = v
    return nb, gained


class Game2048:
    def __init__(self, seed=None, board=None, score=0):
        self.rng, self.score = _rng(seed), score
        self.board = list(board) if board else [0] * 16
        if not board: self.spawn(); self.spawn()

    def spawn(self):
        empty = [i for i, v in enumerate(self.board) if v == 0]
        if empty: self.board[self.rng.choice(empty)] = 4 if self.rng.random() < 0.1 else 2

    def can_move(self):
        return any(move2048(self.board, d)[0] != self.board for d in ("left", "right", "up", "down"))

    def step(self, d) -> bool:
        nb, g = move2048(self.board, d)
        if nb == self.board: return False
        self.board, self.score = nb, self.score + g
        self.spawn()
        return True


def _valid2048(b):
    return isinstance(b, list) and len(b) == 16 and all(isinstance(v, int) and not isinstance(v, bool) and (v == 0 or (v >= 2 and v & (v - 1) == 0 and v <= 1 << 17)) for v in b)


class Screen2048(Screen):
    title = "2048"
    help = "arrows or w/a/s/d slide   n new game   Esc back"
    DIRS = {"left": "left", "right": "right", "up": "up", "down": "down", "a": "left", "d": "right", "w": "up", "s": "down"}

    def __init__(self, host, seed=None):
        self.st, self.seed, self.msg = Progress(host), seed, ""
        d = self.st.get("2048")
        if _valid2048(d.get("board")) and isinstance(d.get("score"), int) and any(d["board"]):
            self.g = Game2048(seed, d["board"], d["score"])
        else:
            self.g = Game2048(seed)

    def render(self, w, h):
        g = self.g
        out = ["", f"  score {g.score}   best {self.st.get('2048').get('best', 0)}", ""]
        for r in range(4):
            out.append("  " + "".join(f"{(g.board[r * 4 + c] or '.'):>6}" for c in range(4)))
            out.append("")
        if max(g.board) >= 2048: out.append("  You made 2048! Keep going if you like.")
        if not g.can_move(): out.append("  No moves left. Press n for a new game.")
        return out + ["  " + self.msg]

    def key(self, k):
        self.msg = ""
        if k == "escape": return ("pop", None)
        if k == "n": self.g = Game2048(self.seed); self.save(); return
        if k in self.DIRS:
            if self.g.step(self.DIRS[k]): self.save()
            else: self.msg = "nothing moved"

    def save(self):
        d = self.st.get("2048")
        d.update(board=self.g.board, score=self.g.score, best=max(d.get("best", 0), self.g.score))
        self.st.put("2048", d)


# ---- Minesweeper
class Mines:
    def __init__(self, w=9, h=9, n=10, seed=None):
        self.w, self.h, self.n, self.rng = w, h, min(n, w * h - 9), _rng(seed)
        self.mines, self.open, self.flags, self.dead = None, set(), set(), False

    def nbrs(self, i):
        r, c = divmod(i, self.w)
        return [(r + a) * self.w + c + b for a in (-1, 0, 1) for b in (-1, 0, 1)
                if (a or b) and 0 <= r + a < self.h and 0 <= c + b < self.w]

    def count(self, i): return sum(1 for j in self.nbrs(i) if j in self.mines)

    def reveal(self, i):
        if self.dead or self.won() or i in self.flags or i in self.open: return
        if self.mines is None:       # first click: place mines away from the clicked cell and its neighbours
            safe = {i, *self.nbrs(i)}
            self.mines = set(self.rng.sample([x for x in range(self.w * self.h) if x not in safe], self.n))
        if i in self.mines: self.dead = True; return
        stack = [i]
        while stack:
            j = stack.pop()
            if j in self.open or j in self.flags: continue
            self.open.add(j)
            if self.count(j) == 0: stack += [x for x in self.nbrs(j) if x not in self.open]

    def flag(self, i):
        if self.dead or self.won() or i in self.open: return
        self.flags ^= {i}

    def won(self): return self.mines is not None and not self.dead and len(self.open) == self.w * self.h - self.n


class MinesScreen(Screen):
    title = "Minesweeper"
    help = "arrows move   Space/Enter reveal   f flag   n new   Esc back"

    def __init__(self, host, seed=None):
        self.st, self.seed = Progress(host), seed
        self.new(); self.counted = False

    def new(self): self.g, self.cur, self.counted = Mines(seed=self.seed), 40, False

    def render(self, w, h):
        g = self.g
        out = ["", f"  mines {g.n}   flags {len(g.flags)}   " + ("YOU WON" if g.won() else "BOOM - you hit a mine" if g.dead else ""), ""]
        for r in range(g.h):
            row = ""
            for c in range(g.w):
                i = r * g.w + c
                ch = ("*" if g.dead and i in g.mines else "F" if i in g.flags else "#" if i not in g.open else (str(g.count(i)) if g.count(i) else " "))
                row += f"[{ch}]" if i == self.cur else f" {ch} "
            out.append("  " + row)
        s = self.st.get("mines")
        return out + ["", f"  won {s.get('won', 0)}  lost {s.get('lost', 0)}   (no clock: nothing here runs on a timer)"]

    def key(self, k):
        g = self.g
        r, c = divmod(self.cur, g.w)
        if k == "escape": return ("pop", None)
        if k == "up": r = max(0, r - 1)
        elif k == "down": r = min(g.h - 1, r + 1)
        elif k == "left": c = max(0, c - 1)
        elif k == "right": c = min(g.w - 1, c + 1)
        elif k in (" ", "enter"): g.reveal(self.cur)
        elif k == "f": g.flag(self.cur)
        elif k == "n": self.new(); return
        self.cur = r * g.w + c
        if (g.dead or g.won()) and not self.counted:
            self.counted = True
            s = self.st.get("mines"); s["won" if g.won() else "lost"] = s.get("won" if g.won() else "lost", 0) + 1
            self.st.put("mines", s)


# ---- Sudoku
def solve(grid, limit=2, rng=None, cap=60000):
    """Backtracking with fewest-candidates-first. -> (solutions found up to `limit`, first solution, hit_cap)."""
    g = list(grid)
    rows, cols, box = [0] * 9, [0] * 9, [0] * 9
    for i, v in enumerate(g):
        if v:
            r, c = divmod(i, 9); bit = 1 << v
            if rows[r] & bit or cols[c] & bit or box[r // 3 * 3 + c // 3] & bit: return 0, None, False
            rows[r] |= bit; cols[c] |= bit; box[r // 3 * 3 + c // 3] |= bit
    st = {"n": 0, "nodes": 0, "sol": None, "cap": False}

    def rec():
        st["nodes"] += 1
        if st["nodes"] > cap: st["cap"] = True; return
        best, bm, bn = -1, 0, 10
        for i in range(81):
            if g[i] == 0:
                r, c = divmod(i, 9)
                m = ~(rows[r] | cols[c] | box[r // 3 * 3 + c // 3]) & 0x3FE
                n = bin(m).count("1")
                if n < bn:
                    best, bm, bn = i, m, n
                    if n <= 1: break
        if best < 0:
            st["n"] += 1
            if st["sol"] is None: st["sol"] = list(g)
            return
        if bn == 0: return
        r, c = divmod(best, 9); b = r // 3 * 3 + c // 3
        ds = [d for d in range(1, 10) if bm >> d & 1]
        if rng: rng.shuffle(ds)
        for d in ds:
            bit = 1 << d
            g[best] = d; rows[r] |= bit; cols[c] |= bit; box[b] |= bit
            rec()
            g[best] = 0; rows[r] &= ~bit; cols[c] &= ~bit; box[b] &= ~bit
            if st["n"] >= limit or st["cap"]: return
    rec()
    return st["n"], st["sol"], st["cap"]


def make_sudoku(rng, clues=36):
    """-> (puzzle, solution). The puzzle has exactly one solution (checked); it may keep more clues than asked if removing more would break that."""
    full = solve([0] * 81, 1, rng)[1]
    puz, left = list(full), 81
    for i in rng.sample(range(81), 81):
        if left <= clues: break
        v, puz[i] = puz[i], 0
        n, _, capped = solve(puz, 2)
        if n != 1 or capped: puz[i] = v
        else: left -= 1
    return puz, full


def conflicts(g):
    bad = set()
    for unit in [[r * 9 + c for c in range(9)] for r in range(9)] + [[r * 9 + c for r in range(9)] for c in range(9)] + \
                [[(br * 3 + r) * 9 + bc * 3 + c for r in range(3) for c in range(3)] for br in range(3) for bc in range(3)]:
        seen = {}
        for i in unit:
            if g[i]:
                if g[i] in seen: bad |= {i, seen[g[i]]}
                seen[g[i]] = i
    return bad


LEVELS_SUDOKU = {"easy": 40, "medium": 32, "hard": 26}


def _valid_grid(g): return isinstance(g, list) and len(g) == 81 and all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 9 for v in g)


class SudokuScreen(Screen):
    title = "Sudoku"
    help = "arrows move  1-9 set  0/Backspace clear  c check  h hint  n new  l level  Esc back"

    def __init__(self, host, seed=None):
        self.st, self.rng, self.cur, self.msg, self.level = Progress(host), _rng(seed), 0, "", "easy"
        d = self.st.get("sudoku")
        if all(_valid_grid(d.get(k)) for k in ("given", "grid", "sol")) and solve(d["given"], 2)[0] == 1:
            self.given, self.grid, self.sol = d["given"], d["grid"], d["sol"]
            self.level = d.get("level") if d.get("level") in LEVELS_SUDOKU else "easy"
        else:
            self.new()

    def new(self):
        self.given, self.sol = make_sudoku(self.rng, LEVELS_SUDOKU[self.level])
        self.grid = list(self.given); self.save()

    def save(self):
        d = self.st.get("sudoku")
        d.update(given=self.given, grid=self.grid, sol=self.sol, level=self.level)
        self.st.put("sudoku", d)

    def solved(self): return 0 not in self.grid and not conflicts(self.grid)

    def render(self, w, h):
        out = ["", f"  level {self.level}   solved so far: {self.st.get('sudoku').get('solved', 0)}   ([x] cursor, x' = your entry)", ""]
        for r in range(9):
            row = ""
            for c in range(9):
                i = r * 9 + c; v = self.grid[i] or "."
                row += f"[{v}]" if i == self.cur else f" {v}" + ("'" if self.grid[i] and not self.given[i] else " ")
                if c in (2, 5): row += "|"
            out.append("  " + row)
            if r in (2, 5): out.append("  " + "-" * 29)
        return out + ["", "  " + ("SOLVED!" if self.solved() else self.msg)]

    def key(self, k):
        self.msg = ""
        r, c = divmod(self.cur, 9)
        if k == "escape": return ("pop", None)
        if k == "up": r = max(0, r - 1)
        elif k == "down": r = min(8, r + 1)
        elif k == "left": c = max(0, c - 1)
        elif k == "right": c = min(8, c + 1)
        elif k == "n": self.new(); return
        elif k == "l":
            names = list(LEVELS_SUDOKU); self.level = names[(names.index(self.level) + 1) % 3]; self.new(); return
        elif k == "c":
            bad = conflicts(self.grid); wrong = [i for i in range(81) if self.grid[i] and self.grid[i] != self.sol[i]]
            self.msg = "no mistakes so far" if not wrong else f"{len(wrong)} cell(s) are wrong" + (f", {len(bad)} clash" if bad else "")
        elif k == "h" and not self.given[self.cur]:
            self.grid[self.cur] = self.sol[self.cur]; self.msg = "hint filled in"
        elif len(k) == 1 and k in "0123456789" or k in ("backspace", "delete"):
            if self.given[self.cur]: self.msg = "that is a given number"
            else: self.grid[self.cur] = int(k) if k.isdigit() else 0
        self.cur = r * 9 + c
        if self.solved():
            d = self.st.get("sudoku")
            if not d.get("counted") or d.get("counted") != self.given:
                d["solved"] = d.get("solved", 0) + 1; d["counted"] = list(self.given); self.st.put("sudoku", d)
        self.save()


# ---- Tic-Tac-Toe with a perfect opponent
_LINES = ((0, 1, 2), (3, 4, 5), (6, 7, 8), (0, 3, 6), (1, 4, 7), (2, 5, 8), (0, 4, 8), (2, 4, 6))
_memo: dict = {}


def ttt_winner(b):
    for x, y, z in _LINES:
        if b[x] and b[x] == b[y] == b[z]: return b[x]
    return 0


def _nega(b, turn):
    """Value for the player to move: positive wins (sooner is bigger), 0 draws."""
    key = (b, turn)
    if key in _memo: return _memo[key]
    if ttt_winner(b): v = -(b.count(0) + 1)
    elif 0 not in b: v = 0
    else:
        v = max(-_nega(b[:i] + (turn,) + b[i + 1:], -turn) for i in range(9) if b[i] == 0)
    _memo[key] = v
    return v


def ttt_best(b, turn):
    """The best cell (0-8) for `turn` (1 = X, -1 = O) on board tuple `b`; the first best cell on ties."""
    best, bv = -1, -99
    for i in range(9):
        if b[i] == 0:
            v = -_nega(b[:i] + (turn,) + b[i + 1:], -turn)
            if v > bv: best, bv = i, v
    return best


class TTTScreen(Screen):
    title = "Tic-Tac-Toe"
    help = "1-9 place your mark   n new game (alternates who starts)   Esc back"

    def __init__(self, host):
        self.st, self.first, self.msg = Progress(host), 1, ""
        self.reset()

    def reset(self):
        self.b, self.done = (0,) * 9, False
        if self.first == -1: self.b = self.put(ttt_best(self.b, 1), 1)   # computer is X and starts

    def put(self, i, who): return self.b[:i] + (who,) + self.b[i + 1:]

    def render(self, w, h):
        me = "O" if self.first == -1 else "X"
        ch = {0: ".", 1: "X", -1: "O"}
        out = ["", f"  you are {me}; the computer plays perfectly - the best you can do is draw", ""]
        for r in range(3):
            out.append("   " + " ".join(ch[self.b[r * 3 + c]] if self.b[r * 3 + c] else str(r * 3 + c + 1) for c in range(3)))
        s = self.st.get("ttt")
        return out + ["", "  " + self.msg, f"  you: won {s.get('w', 0)} drew {s.get('d', 0)} lost {s.get('l', 0)}"]

    def finish(self):
        w = ttt_winner(self.b)
        if not w and 0 in self.b: return
        self.done = True
        me = 1 if self.first == 1 else -1
        key = "d" if not w else "w" if w == me else "l"
        self.msg = {"d": "Draw.", "w": "You win!", "l": "The computer wins."}[key]
        s = self.st.get("ttt"); s[key] = s.get(key, 0) + 1; self.st.put("ttt", s)

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "n":
            self.first = -self.first; self.msg = ""; self.reset(); return
        if self.done or not (len(k) == 1 and k in "123456789"): return
        i, me = int(k) - 1, (1 if self.first == 1 else -1)
        if self.b[i]: self.msg = "that cell is taken"; return
        self.b = self.put(i, me); self.msg = ""; self.finish()
        if not self.done:
            self.b = self.put(ttt_best(self.b, -me), -me); self.finish()


class Progress:
    """Best scores and saved progress for Casual Games: one small JSON document in the vault."""
    KEY = "casual-games"

    def __init__(self, host): self.store = Store(host)

    def _all(self):
        d = self.store.load(self.KEY)
        return d if isinstance(d, dict) else {}

    def get(self, name):
        d = self._all().get(name)
        return d if isinstance(d, dict) else {}

    def put(self, name, value):
        d = self._all(); d[name] = value
        self.store.save(self.KEY, d)


def casual(host, entry=None):
    return Menu("Casual Games", [
        ("2048", lambda: ("push", Screen2048(host))),
        ("Minesweeper (9x9, 10 mines)", lambda: ("push", MinesScreen(host))),
        ("Sudoku (unique-solution puzzles)", lambda: ("push", SudokuScreen(host))),
        ("Tic-Tac-Toe (perfect opponent)", lambda: ("push", TTTScreen(host))),
    ], intro=["", "  Turn-based: a key press moves the game on. Nothing runs on a timer."])


# ============================================================ game library ==
def playtime(items):
    def num(v):
        try: return max(0.0, float(v))
        except (TypeError, ValueError): return 0.0
    tot = sum(num(r.get("hours")) for r in items)
    out = [f"{len(items)} game(s), {tot:g} hours in total", ""]
    for key, label in (("platform", "By platform"), ("status", "By status")):
        by = {}
        for r in items: by[r.get(key, "?")] = by.get(r.get(key, "?"), 0) + num(r.get("hours"))
        out += [label + ":"] + [f"  {k:<12} {v:>8g} h" for k, v in sorted(by.items(), key=lambda x: (-x[1], x[0]))] + [""]
    top = sorted(items, key=lambda r: -num(r.get("hours")))[:5]
    out += ["Most played:"] + [f"  {str(r.get('title', ''))[:30]:<30} {num(r.get('hours')):>7g} h" for r in top if num(r.get("hours"))]
    rated = [num(r.get("rating")) for r in items if 0 < num(r.get("rating")) <= 10]
    if rated: out += ["", f"Average rating {sum(rated) / len(rated):.1f} of 10 over {len(rated)} rated game(s)"]
    return out


LIBRARY = R("gamelib", "Game Library", "game",
            "title*; platform: choice(PC|Console|Handheld|Mobile|Tabletop|Other)=PC; status: choice(wishlist|backlog|playing|completed|dropped)=backlog; hours: number; rating: number; notes: long",
            status="status", done=("completed", "dropped"), amount="hours", group="platform", report=playtime,
            report_label="Play-time summary", list_cols=("title", "platform", "status", "hours", "rating"),
            scope="A register of your games with play-time totals. It cannot launch games or other apps.")


def library(host, entry=None):
    r = RecordList(Data(host, LIBRARY)); r.title = "Game Library"; return r


ENTRIES = [
    app("Chess", lambda host, e: ChessScreen(host), "full",
        "Full rules: castling, en passant, promotion, check, mate, stalemate, fifty-move, threefold repetition, FEN, undo. "
        "Text board, no graphics. The computer uses alpha-beta to depth 1-3 with a node cap: modest strength, no opening book, no clock."),
    app("Casual Games", casual, "full",
        "2048, Minesweeper, Sudoku and Tic-Tac-Toe, turn-based with best scores saved. No timers, so no speed scores; "
        "Minesweeper keeps win/loss counts but does not resume a half-played board."),
    app("Game Library", library, "partial",
        "A register of games with play-time totals. It cannot launch games or other apps and does not read any game's own play-time."),
]
