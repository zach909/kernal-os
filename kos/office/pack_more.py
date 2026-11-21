"""pack_more: the apps of the third request (docs/REQUESTED3.txt), as far as sandboxed, offline, single-user apps can go.

What is real here: an authenticator that computes RFC 4226 / 6238 codes, Sudoku and Minesweeper as their own apps,
a tile-matching Mahjong that is always solvable, a Blackjack table, an on-screen keyboard, a trend analyzer, an ISBN
checker, a citation formatter, and a set of registers whose reports are exact (whole numbers and fractions only).

What is not here, said plainly: anything that needs a network, a camera, a microphone, a speaker, a telephone line,
a location, a 3D engine or a model is an entry marked `none` with the reason. A register never pretends to control
the thing it lists (parental controls are rules you wrote down, not rules a device enforces).

Pure standard library. Nothing runs in the background. Every input and stored item is bounded. Numbers are whole
numbers or `Fraction`; nothing is shown with a decimal point."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import random
import re
import struct
import time
from fractions import Fraction

from kos.exact import div

from .packkit import app, none
from .records import Data, RecordList
from .specs import R
from .ui import Editor, Message, Prompt, Screen, Store, TextView

MAX_TEXT = 200
BIG = 10 ** 12


def clean(s, n: int = MAX_TEXT) -> str:
    """Printable text only (control characters dropped), bounded."""
    return "".join(c for c in s if c.isprintable())[:n].strip() if isinstance(s, str) else ""


def fr(v, default=Fraction(0)) -> Fraction:
    """A stored number as an exact Fraction; anything odd (empty, text, NaN, huge) is `default`."""
    try:
        x = Fraction(str(v).strip().replace(",", ""))
    except (ValueError, ZeroDivisionError, TypeError):
        return default
    return x if abs(x) <= BIG else default


def rnd(x: Fraction) -> int:
    """Round half up to a whole number (exact)."""
    return (x * 2 + 1) // 2 if x >= 0 else -((-x * 2 + 1) // 2)


def money(x: Fraction) -> str:
    c = rnd(x * 100)
    sign = "-" if c < 0 else ""
    c = abs(c)
    return f"{sign}{c // 100:,}.{c % 100:02d}"


def K(v, n: int = 40) -> str:
    """A record value as a short printable group key."""
    return clean(str(v), n) or "?" if v not in (None, "") else "?"


def hm(x) -> str:
    """Whole minutes as 1h05 (anything odd counts as 0)."""
    m = max(0, int(fr(x)))
    return f"{m // 60}h{m % 60:02d}"


def pct(a, b) -> str:
    """a/b as a whole percent plus the exact per-1000 figure; '-' when b is zero."""
    a, b = fr(a), fr(b)
    return "-" if b == 0 else f"{rnd(div(a * 100, b))}% ({rnd(div(a * 1000, b))} per 1000)"


# ================================================================== authenticator ==
def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    """RFC 4226. `algo` is sha1, sha256 or sha512 (RFC 6238 allows all three)."""
    if algo not in ("sha1", "sha256", "sha512") or not 1 <= digits <= 10 or counter < 0 or not secret:
        raise ValueError("bad code settings")
    mac = hmac.new(secret, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    o = mac[-1] & 15
    return str((int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp(secret: bytes, now: int, period: int = 30, digits: int = 6, algo: str = "sha1") -> str:
    if period < 1 or period > 3600 or now < 0:
        raise ValueError("bad code settings")
    return hotp(secret, now // period, digits, algo)


def b32(text: str) -> bytes:
    """A base32 secret as people paste it (spaces, dashes, lower case, missing padding)."""
    if not isinstance(text, str) or len(text) > 200:
        raise ValueError("not a base32 secret")
    t = re.sub(r"[\s-]", "", clean(text, 200)).upper()
    if not t or not re.fullmatch(r"[A-Z2-7]+=*", t):
        raise ValueError("not a base32 secret")
    try:
        return base64.b32decode(t + "=" * (-len(t) % 8))
    except (binascii.Error, ValueError):
        raise ValueError("not a base32 secret")


class AuthScreen(Screen):
    title = "Authenticator Codes"
    help = "s new secret   + / - digits   p period   a algorithm   Esc back"

    def __init__(self, host, now=time.time):
        self.now, self.secret, self.digits, self.period, self.algo, self.msg = now, None, 6, 30, "sha1", ""
        self.label = ""

    def code(self):
        t = int(self.now())
        return totp(self.secret, t, self.period, self.digits, self.algo), self.period - t % self.period

    def render(self, w, h):
        out = ["", "  Codes are worked out here from a secret you type. The secret is NOT saved anywhere", "  (a clear-text vault must not hold one) and is forgotten when you leave.", ""]
        if self.secret is None:
            out.append("  No secret yet. Press s and type the base32 key from the site.")
        else:
            c, left = self.code()
            out += [f"  {self.label or 'account'}", "", f"      {c[:len(c) // 2]} {c[len(c) // 2:]}", "",
                    f"  changes in {left} s   ({self.digits} digits, {self.period} s, {self.algo})"]
        return out + ["", "  " + self.msg]

    def key(self, k):
        self.msg = ""
        if k == "escape": return ("pop", None)
        if k == "s":
            return ("push", Prompt("Secret", "Base32 secret (e.g. JBSWY3DPEHPK3PXP):", "", self._set, secret=True))
        if k == "+": self.digits = min(10, self.digits + 1)
        elif k == "-": self.digits = max(6, self.digits - 1)
        elif k == "a": self.algo = {"sha1": "sha256", "sha256": "sha512", "sha512": "sha1"}[self.algo]
        elif k == "p": self.period = {30: 60, 60: 15, 15: 30}.get(self.period, 30)

    def _set(self, text):
        try:
            self.secret = b32(text)
            self.label = "account " + hashlib.sha256(self.secret).hexdigest()[:4]
        except ValueError as e:
            self.msg = str(e)


# ============================================================== mahjong solitaire ==
ROWS, COLS = 4, 9                                   # 36 tiles = 18 pairs
TILES = "ABCDEFGHIJKLMNOPQR"


def mj_free(board, i) -> bool:
    """A tile is free when it is there and its left or right neighbour in the row is gone (or it is at the edge)."""
    if board[i] is None: return False
    c = i % COLS
    left = c == 0 or board[i - 1] is None
    right = c == COLS - 1 or board[i + 1] is None
    return left or right


def mj_deal(seed) -> list:
    """Always solvable: the tiles are laid by undoing a play - pick two free places, give them one face, take them out."""
    rng = random.Random(seed)
    shape = [True] * (ROWS * COLS)                  # True = a tile will go here
    order = []
    while any(shape):
        free = [i for i in range(len(shape)) if shape[i] and ((i % COLS == 0 or not shape[i - 1]) or (i % COLS == COLS - 1 or not shape[i + 1]))]
        if len(free) < 2:                           # a lone free place cannot happen with an even count, but never loop
            break
        a, b = rng.sample(free, 2)
        shape[a] = shape[b] = False
        order.append((a, b))
    faces = list(TILES)
    rng.shuffle(faces)
    board = [None] * (ROWS * COLS)
    for n, (a, b) in enumerate(order):
        board[a] = board[b] = faces[n % len(faces)]
    return board


class MahjongScreen(Screen):
    title = "Mahjong Solitaire"
    help = "arrows move   Space pick / drop   h hint   n new deal   Esc back"

    def __init__(self, host, seed=None):
        self.st, self.seed, self.msg = Store(host), seed, ""
        self.new()

    def new(self):
        self.seed = (self.seed + 1) if isinstance(self.seed, int) else random.randrange(10 ** 9)
        self.board, self.cur, self.pick, self.msg = mj_deal(self.seed), 0, None, ""

    def moves(self):
        free = [i for i in range(len(self.board)) if mj_free(self.board, i)]
        return [(a, b) for n, a in enumerate(free) for b in free[n + 1:] if self.board[a] == self.board[b]]

    def render(self, w, h):
        out = ["", f"  tiles left {sum(t is not None for t in self.board)}   (a free tile has an empty side: [x] cursor, * picked)", ""]
        for r in range(ROWS):
            row = ""
            for c in range(COLS):
                i = r * COLS + c
                t = self.board[i]
                ch = " " if t is None else t
                mark = "*" if i == self.pick else (" " if mj_free(self.board, i) else "-")
                row += f"[{ch}{mark}]" if i == self.cur else f" {ch}{mark} "
            out.append("  " + row)
        done = all(t is None for t in self.board)
        stuck = not done and not self.moves()
        return out + ["", "  " + ("You cleared the board!" if done else "No moves left: press n for a new deal." if stuck else self.msg)]

    def key(self, k):
        self.msg = ""
        r, c = divmod(self.cur, COLS)
        if k == "escape": return ("pop", None)
        if k == "up": r = max(0, r - 1)
        elif k == "down": r = min(ROWS - 1, r + 1)
        elif k == "left": c = max(0, c - 1)
        elif k == "right": c = min(COLS - 1, c + 1)
        elif k == "n": self.new(); return
        elif k == "h":
            m = self.moves()
            self.msg = f"try {divmod(m[0][0], COLS)} and {divmod(m[0][1], COLS)} (row, column)" if m else "no pair is free"
        elif k in (" ", "enter"):
            i = self.cur
            if not mj_free(self.board, i): self.msg = "that tile is blocked"
            elif self.pick is None: self.pick = i
            elif self.pick == i: self.pick = None
            elif self.board[self.pick] == self.board[i]:
                self.board[self.pick] = self.board[i] = None; self.pick = None
            else: self.msg = "those do not match"; self.pick = i
        self.cur = r * COLS + c


# ================================================================== blackjack ==
def hand_value(cards) -> int:
    """Cards are ranks 1..13 (1 = ace, 11-13 = court). Best total not over 21."""
    t = sum(min(c, 10) for c in cards)
    return t + 10 if 1 in cards and t + 10 <= 21 else t


def card_name(c) -> str: return {1: "A", 11: "J", 12: "Q", 13: "K"}.get(c, str(c))


class BlackjackScreen(Screen):
    title = "Digital Card Games - Blackjack"
    help = "h hit   s stand   n new hand   Esc back"

    def __init__(self, host, seed=None):
        self.st, self.rng, self.wins, self.losses, self.pushes = Store(host), random.Random(seed), 0, 0, 0
        d = self.st.load("score", {})
        if isinstance(d, dict):
            self.wins, self.losses, self.pushes = (d.get(k, 0) if isinstance(d.get(k), int) and 0 <= d.get(k) < 10 ** 9 else 0 for k in ("w", "l", "p"))
        self.deal()

    def deal(self):
        self.deck = [r for r in range(1, 14) for _ in range(4)]
        self.rng.shuffle(self.deck)
        self.me, self.dealer, self.over, self.result = [self.deck.pop(), self.deck.pop()], [self.deck.pop(), self.deck.pop()], False, ""
        if hand_value(self.me) == 21: self.stand()

    def stand(self):
        while hand_value(self.dealer) < 17: self.dealer.append(self.deck.pop())
        self.finish()

    def finish(self):
        m, d = hand_value(self.me), hand_value(self.dealer)
        if m > 21: self.result, self.losses = "Bust. Dealer wins.", self.losses + 1
        elif d > 21 or m > d: self.result, self.wins = "You win.", self.wins + 1
        elif m < d: self.result, self.losses = "Dealer wins.", self.losses + 1
        else: self.result, self.pushes = "Push.", self.pushes + 1
        self.over = True
        self.st.save("score", {"w": self.wins, "l": self.losses, "p": self.pushes})

    def render(self, w, h):
        show = self.dealer if self.over else [self.dealer[0]]
        return ["", "  Dealer: " + " ".join(card_name(c) for c in show) + ("" if self.over else " ?") + (f"  = {hand_value(self.dealer)}" if self.over else ""),
                "  You:    " + " ".join(card_name(c) for c in self.me) + f"  = {hand_value(self.me)}", "",
                "  " + (self.result or "Hit or stand?"), "", f"  won {self.wins}  lost {self.losses}  push {self.pushes}   (no money: this is a card game, not gambling)",
                "  Solitaire and other card games are not built."]

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "n": self.deal(); return
        if self.over: return
        if k == "h":
            self.me.append(self.deck.pop())
            if hand_value(self.me) >= 21: self.stand() if hand_value(self.me) == 21 else self.finish()
        elif k == "s": self.stand()


# ============================================================= virtual keyboard ==
KB_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl;", "zxcvbnm,./"]


class KeyboardScreen(Screen):
    title = "Virtual Keyboard"
    help = "arrows move   Enter press key   Tab shift   Esc back"

    def __init__(self, host):
        self.st = Store(host)
        t = self.st.load("buffer", "")
        self.text, self.r, self.c, self.shift = (t[:2000] if isinstance(t, str) else ""), 1, 0, False
        self.keys = [("SPACE", " "), ("DEL", None), ("NEWLINE", "\n"), ("CLEAR", "")]

    def render(self, w, h):
        out = ["", "  This composes text here. It cannot type into other apps: an app may not send keys elsewhere.", ""]
        for ri, row in enumerate(KB_ROWS):
            line = ""
            for ci, ch in enumerate(row):
                s = ch.upper() if self.shift else ch
                line += f"[{s}]" if (ri, ci) == (self.r, self.c) else f" {s} "
            out.append("   " + line)
        line = ""
        for ci, (n, _) in enumerate(self.keys):
            line += f"[{n}]" if (4, ci) == (self.r, self.c) else f" {n} "
        out += ["   " + line, "", "  text:"] + ["    " + l for l in (self.text.split("\n")[-6:])]
        return out

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "up": self.r = max(0, self.r - 1)
        elif k == "down": self.r = min(4, self.r + 1)
        elif k == "left": self.c -= 1
        elif k == "right": self.c += 1
        elif k == "tab": self.shift = not self.shift
        self.c = max(0, min(self.c, (len(self.keys) if self.r == 4 else 10) - 1))
        if k == "enter":
            if self.r == 4:
                n, v = self.keys[self.c]
                if n == "DEL": self.text = self.text[:-1]
                elif n == "CLEAR": self.text = ""
                else: self.text += v
            else:
                ch = KB_ROWS[self.r][self.c]
                self.text += ch.upper() if self.shift else ch
            self.text = self.text[:2000]
            self.st.save("buffer", self.text)


# ================================================================ trend analyzer ==
def parse_series(text: str) -> list:
    """Whole or fractional numbers separated by spaces, commas or newlines; 'label value' lines use the last token."""
    out = []
    if not isinstance(text, str) or len(text) > 20000: raise ValueError("too much text: give at most 500 numbers")
    for line in clean_lines(text):
        tok = re.split(r"[,\s]+", line.strip())
        for t in ([tok[-1]] if len(tok) > 1 and not re.fullmatch(r"[-\d./]+", tok[0]) else tok):
            if t:
                v = fr(t, None)
                if v is None: raise ValueError(f"not a number: {t[:20]}")
                out.append(v)
    if not 1 <= len(out) <= 500: raise ValueError("give between 1 and 500 numbers")
    return out


def clean_lines(text):
    return [clean(l, 20000) for l in (text or "").splitlines()[:600] if clean(l, 20000)]


def trend_report(xs, window: int = 3) -> list:
    n = len(xs)
    window = max(1, min(window, n))
    ma = [div(sum(xs[i - window + 1:i + 1]), window) for i in range(window - 1, n)]
    hi, lo = max(xs), min(xs)
    out = [f"points {n}   first {xs[0]}   last {xs[-1]}   high {hi} (#{xs.index(hi) + 1})   low {lo} (#{xs.index(lo) + 1})",
           f"mean {div(sum(xs), n)}   total change {xs[-1] - xs[0]}" + (f"   growth {rnd(div((xs[-1] - xs[0]) * 100, xs[0]))}%" if xs[0] != 0 else "")]
    out.append(f"direction: " + ("rising" if xs[-1] > xs[0] else "falling" if xs[-1] < xs[0] else "flat") + f"   up steps {sum(b > a for a, b in zip(xs, xs[1:]))}  down steps {sum(b < a for a, b in zip(xs, xs[1:]))}")
    out += ["", f"index (first point = 100) and {window}-point moving average:"]
    span = hi - lo
    for i, x in enumerate(xs[:60]):
        idx = rnd(div(x * 100, xs[0])) if xs[0] != 0 else 0
        bar = "#" * (1 + (rnd(div((x - lo) * 30, span)) if span else 15))
        out.append(f"  {i + 1:>3} {str(x):>10} idx {idx:>5} {bar}")
    if len(xs) > 60: out.append(f"  ... {len(xs) - 60} more point(s) not drawn")
    out += ["", "moving average: " + ", ".join(str(m) for m in ma[:30])]
    return out


def _trend(host, e):
    st = Store(host)

    def run(ed):
        try:
            return ("push", TextView("Trend report", trend_report(parse_series(ed.area.text))))
        except ValueError as err:
            return ("push", Message("Trend Analyzer", [str(err)]))

    def saved(text):
        st.save("series", text[:20000])

    text = st.load("series", "")
    return Editor("Trend Analyzer", text if isinstance(text, str) else "", saved, extra_keys={"ctrl-r": run},
                  hint="Ctrl-R analyse   one number per line or comma separated")


# ====================================================================== ISBN / books ==
def isbn13_ok(s: str) -> bool:
    d = re.sub(r"[\s-]", "", s or "")
    if len(d) == 13 and d.isdigit():
        return sum(int(c) * (1 if i % 2 == 0 else 3) for i, c in enumerate(d)) % 10 == 0
    if len(d) == 10 and re.fullmatch(r"\d{9}[\dXx]", d):
        return sum((10 - i) * (10 if c in "Xx" else int(c)) for i, c in enumerate(d)) % 11 == 0
    return False


def books_report(items):
    bad = [r for r in items if r.get("isbn") and not isbn13_ok(r["isbn"])]
    out = [f"{len(items)} book(s) in the catalogue", ""]
    by = {}
    for r in items: by[K(r.get("shelf") or "unshelved")] = by.get(K(r.get("shelf") or "unshelved"), 0) + 1
    out += ["By shelf:"] + [f"  {k:<18} {v}" for k, v in sorted(by.items())]
    out += ["", f"ISBNs that fail their check digit: {len(bad)}"] + [f"  {r.get('title', '?')}: {r.get('isbn')}" for r in bad[:20]]
    return out


# ================================================================ citations ==
def cite(r) -> str:
    """One reference in a plain author-year style. Missing parts are left out, never invented."""
    a, y, t, v = (clean(str(r.get(k, "")), 160) for k in ("authors", "year", "title", "venue"))
    return " ".join(p for p in (a if a.endswith(".") else f"{a}." if a else "", f"({y})." if y else "(n.d.).", f"{t}." if t else "", f"{v}." if v else "") if p)


def bibliography(items):
    rows = sorted((cite(r) for r in items), key=str.lower)
    return [f"{len(rows)} reference(s), sorted by author:", ""] + (rows or ["(none yet)"])


# ==================================================================== report helpers ==
def _sum_by(items, key, val):
    t = {}
    for r in items:
        k = clean(str(r.get(key) or "?"), 40) or "?"
        t[k] = t.get(k, Fraction(0)) + fr(r.get(val))
    return t


def trip_report(items):
    t = _sum_by(items, "trip", "cost")
    out = ["Cost by trip (booked and planned):", ""] + [f"  {k:<26} {money(v):>12}" for k, v in sorted(t.items())]
    k = _sum_by(items, "kind", "cost")
    out += ["", "By kind:"] + [f"  {a:<26} {money(b):>12}" for a, b in sorted(k.items())]
    return out + ["", f"Total {money(sum(t.values(), Fraction(0)))}", "Prices are what you typed; nothing is looked up or booked."]


def flight_report(items):
    ok = [r for r in items if fr(r.get("price"), None) is not None and r.get("price", "") != ""]
    out = [f"{len(items)} itinerary(ies) saved; {len(ok)} with a price", ""]
    if ok:
        c = min(ok, key=lambda r: fr(r["price"]))
        out.append(f"Cheapest: {c.get('route', '?')} {c.get('date', '')} {money(fr(c['price']))}")
        s = min(ok, key=lambda r: (fr(r.get("minutes"), BIG), fr(r["price"])))
        out.append(f"Shortest: {s.get('route', '?')} {hm(s.get('minutes'))}")
        d = [r for r in ok if fr(r.get("stops")) == 0]
        out.append(f"Non-stop options: {len(d)}")
    return out + ["", "Fares are typed in by you; this app does not search airlines."]


def compare_report(items):
    by = {}
    for r in items: by.setdefault(clean(str(r.get("product") or "?"), 40), []).append(r)
    out = []
    for p, rs in sorted(by.items()):
        priced = [r for r in rs if r.get("price") not in (None, "")]
        if not priced: continue
        c = min(priced, key=lambda r: fr(r["price"]))
        out.append(f"{p:<28} best {money(fr(c['price'])):>10} at {c.get('store', '?')}   ({len(priced)} offer(s))")
    return out or ["add two or more offers for the same product to compare them"]


def ads_site_report(items):
    imp, clk, rev = (sum((fr(r.get(k)) for r in items), Fraction(0)) for k in ("impressions", "clicks", "revenue"))
    out = [f"Impressions {imp}   clicks {clk}   revenue {money(rev)}", f"Click-through rate {pct(clk, imp)}",
           f"Revenue per 1000 impressions (RPM) {money(div(rev * 1000, imp)) if imp else '-'}", ""]
    t = _sum_by(items, "site", "revenue")
    return out + ["By site:"] + [f"  {k:<28} {money(v):>12}" for k, v in sorted(t.items(), key=lambda x: -x[1])]


def ads_app_report(items):
    req, imp, rev = (sum((fr(r.get(k)) for r in items), Fraction(0)) for k in ("requests", "impressions", "revenue"))
    out = [f"Requests {req}   shown {imp}   revenue {money(rev)}", f"Fill rate {pct(imp, req)}",
           f"Revenue per 1000 shown (eCPM) {money(div(rev * 1000, imp)) if imp else '-'}", ""]
    return out + ["By app:"] + [f"  {k:<28} {money(v):>12}" for k, v in sorted(_sum_by(items, "app", "revenue").items(), key=lambda x: -x[1])]


def search_perf_report(items):
    imp, clk = (sum((fr(r.get(k)) for r in items), Fraction(0)) for k in ("impressions", "clicks"))
    out = [f"{len(items)} row(s)   impressions {imp}   clicks {clk}   CTR {pct(clk, imp)}", "", "Top queries by clicks:"]
    for r in sorted(items, key=lambda r: -fr(r.get("clicks")))[:10]:
        out.append(f"  {clean(str(r.get('query', '?')), 40):<40} {fr(r.get('clicks')):>6} clicks  CTR {pct(r.get('clicks'), r.get('impressions'))}")
    near = [r for r in items if 10 < fr(r.get("position")) <= 20]
    return out + ["", f"Close to page one (average position 11-20): {len(near)}"] + [f"  {r.get('query')}" for r in near[:10]]


def tag_report(items):
    seen, out = {}, []
    for r in items: seen.setdefault((K(r.get("site")), K(r.get("trigger")), K(r.get("vendor"))), []).append(K(r.get("name")))
    dup = {k: v for k, v in seen.items() if len(v) > 1}
    out.append(f"{len(items)} tag(s); paused {sum(r.get('status') == 'paused' for r in items)}; duplicates {len(dup)}")
    return out + [f"  duplicate: {', '.join(map(str, v))} (same site, trigger and vendor)" for v in dup.values()]


def policy_report(items):
    by = {}
    for r in items: by.setdefault(K(r.get("child")), []).append(r)
    out = ["Rules written down per child (nothing here is enforced on a device):", ""]
    for k, rs in sorted(by.items()):
        on = [r for r in rs if r.get("status") == "on"]
        out.append(f"{k}: {len(on)} active of {len(rs)}")
        out += [f"    {r.get('kind')}: {r.get('value')}" for r in on]
    return out


def screen_time_report(items):
    days = _sum_by(items, "date", "minutes")
    goal = 120
    out = [f"{len(items)} entr(ies). Daily goal {goal} minutes (change nothing here: it is a fixed reading line).", ""]
    for d, m in sorted(days.items())[-14:]:
        out.append(f"  {d:<12} {hm(m)}  " + ("OVER" if m > goal else "ok"))
    return out + ["", "By app/device:"] + [f"  {k:<24} {v} min" for k, v in sorted(_sum_by(items, "app", "minutes").items(), key=lambda x: -x[1])[:10]]


def cloud_report(items):
    live = [r for r in items if r.get("status") != "deleted"]
    t = _sum_by(live, "kind", "monthly_cost")
    return [f"{len(live)} resource(s) not deleted; monthly cost {money(sum(t.values(), Fraction(0)))}", ""] + \
           [f"  {k:<20} {money(v):>12}" for k, v in sorted(t.items(), key=lambda x: -x[1])] + ["", "Costs are your own figures; no cloud account is read."]


def rewards_report(items):
    earned = sum((fr(r.get("points")) for r in items if r.get("kind") == "earned"), Fraction(0))
    spent = sum((fr(r.get("points")) for r in items if r.get("kind") == "redeemed"), Fraction(0))
    return [f"Earned {earned}   redeemed {spent}   balance {earned - spent}", "", "Nothing here earns or redeems points on any service; it counts the ones you type in."]


def gaming_report(items):
    t = _sum_by(items, "child", "minutes")
    return [f"{len(items)} session(s)", ""] + [f"  {k:<20} {hm(v)}" for k, v in sorted(t.items())] + ["", "Typed in by hand: no console or game reports to this app."]


def channel_report(items):
    c = {}
    for r in items: c[K(r.get("status") or "idea")] = c.get(K(r.get("status") or "idea"), 0) + 1
    out = ["By stage: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())), ""]
    pub = [r for r in items if r.get("status") == "published"]
    return out + ["Most viewed:"] + [f"  {clean(str(r.get('title', '?')), 40):<40} {fr(r.get('views'))} views" for r in sorted(pub, key=lambda r: -fr(r.get("views")))[:5]]


def release_report(items):
    t = {}
    for r in items: t.setdefault(K(r.get("app")), []).append(r)
    return [f"{a}: latest {max(rs, key=lambda r: K(r.get('date') or '')).get('version', '?')} on {max(rs, key=lambda r: K(r.get('date') or '')).get('track', '?')}  ({len(rs)} release(s))" for a, rs in sorted(t.items())] or ["no releases yet"]


def completeness(items):
    out = []
    for r in items:
        miss = [k for k in ("phone", "hours", "address") if not r.get(k)]
        if miss: out.append(f"  {r.get('name', '?')}: missing {', '.join(miss)}")
    return [f"{len(items)} listing(s); {len(out)} incomplete"] + out


def blog_index(items):
    live = sorted((r for r in items if r.get("status") == "published"), key=lambda r: r.get("date") or "", reverse=True)
    return [f"{len(live)} published of {len(items)} post(s):", ""] + [f"  {r.get('date', '          ')}  {r.get('title', '?')}" for r in live]


def experiment_report(items):
    rated = [r for r in items if fr(r.get("rating")) > 0]
    best = max(rated, key=lambda r: fr(r.get("rating")), default=None)
    return [f"{len(items)} run(s) logged; {len(rated)} rated"] + ([f"Best: {best.get('model')} / {best.get('title')} rated {fr(best.get('rating'))} of 10"] if best else []) + \
           ["", "This logs runs you did elsewhere; it runs no model."]


def kids_report(items):
    ok = [r for r in items if r.get("approved") == "yes"]
    return [f"{len(ok)} approved of {len(items)} video(s)", ""] + [f"  age {r.get('min_age', '?'):>2}+  {r.get('title')}" for r in sorted(ok, key=lambda r: int(fr(r.get("min_age"))))[:30]]


def watch_report(items):
    c = {}
    for r in items: c[K(r.get("status"))] = c.get(K(r.get("status")), 0) + 1
    done = [fr(r.get("rating")) for r in items if fr(r.get("rating")) > 0]
    return [", ".join(f"{k} {v}" for k, v in sorted(c.items())) or "nothing yet"] + ([f"Mean rating {div(sum(done, Fraction(0)), len(done))} of 10 over {len(done)}"] if done else [])


def guide_report(items):
    out = []
    by = {}
    for r in items: by.setdefault((K(r.get("channel")), K(r.get("date"))), []).append(r)
    for (ch, d), rs in sorted(by.items(), key=lambda x: str(x[0])):
        for i, a in enumerate(rs):
            for b in rs[i + 1:]:
                if K(a.get("start") or "") < K(b.get("end") or "99:99") and K(b.get("start") or "") < K(a.get("end") or "99:99"):
                    out.append(f"OVERLAP {ch} {d}: {a.get('program')} and {b.get('program')}")
    return out or ["no overlapping programmes"]


def lost_report(items):
    lost = [r for r in items if r.get("status") == "lost"]
    return [f"{len(lost)} item(s) still lost of {len(items)}"] + [f"  {r.get('item')}: last seen {r.get('last_seen') or '?'} on {r.get('date') or '?'}" for r in lost]


def art_report(items):
    by = {}
    for r in items: by[K(r.get("museum"))] = by.get(K(r.get("museum")), 0) + 1
    return ["Works by collection:"] + [f"  {k:<30} {v}" for k, v in sorted(by.items())]


def font_report(items):
    return [f"{len(items)} font(s); without a licence noted: {sum(not r.get('licence') for r in items)}"] + \
           [f"  {r.get('font')}: no licence recorded" for r in items if not r.get("licence")][:15]


def accessory_report(items):
    return [f"{len(items)} profile(s) for {len({r.get('accessory') for r in items})} accessory(ies)", "", "A profile is a note of the bindings you want. No device is configured."]


# ================================================================== specs ==
def _spec(id, title, item, f, **kw):
    kw.setdefault("report_label", "Report")
    return R(id, title, item, f, **kw)


TRIPS = _spec("trips", "Trip Planner", "booking", "trip*; kind: choice(flight|stay|activity|transport|food|other)=activity; date: date; place; cost: money; status: choice(idea|booked|done)=idea; notes: long",
              status="status", done=("done",), amount="cost", group="trip", list_cols=("trip", "kind", "date", "cost", "status"), report=trip_report, report_label="Cost by trip")
FLIGHTS = _spec("flights", "Flight Planner", "itinerary", "route*; date: date; airline; price: money; minutes: number; stops: number=0; notes: long",
                list_cols=("route", "date", "price", "stops"), amount="price", report=flight_report, report_label="Compare")
COMPARE = _spec("compare", "Product Comparison", "offer", "product*; store; price: money; rating: number; link: url; notes: long",
                list_cols=("product", "store", "price", "rating"), group="product", report=compare_report, report_label="Best price")
BLOG = _spec("blog", "Blog Manager", "post", "title*; date: date; status: choice(draft|scheduled|published)=draft; tags: tags; body: long",
             status="status", done=("published",), list_cols=("title", "date", "status"), report=blog_index, report_label="Published index")
LISTINGS = _spec("listings", "Business Listings", "listing", "name*; category; address; phone: phone; hours; website: url; status: choice(draft|verified)=draft",
                 status="status", done=("verified",), report=completeness, report_label="Completeness")
ADSITE = _spec("adsite", "Site Ad Revenue", "day", "date: date; site*; impressions: number; clicks: number; revenue: money",
               amount="revenue", group="site", list_cols=("date", "site", "impressions", "clicks", "revenue"), report=ads_site_report, report_label="Earnings")
ADAPP = _spec("adapp", "App Ad Revenue", "day", "date: date; app*; requests: number; impressions: number; revenue: money",
              amount="revenue", group="app", list_cols=("date", "app", "requests", "impressions", "revenue"), report=ads_app_report, report_label="Earnings")
TAGS = _spec("tags", "Tag Manager", "tag", "name*; site; trigger; vendor; status: choice(active|paused|retired)=active; notes: long",
             status="status", done=("retired",), list_cols=("name", "site", "trigger", "status"), report=tag_report, report_label="Duplicates")
SEARCHPERF = _spec("searchperf", "Search Performance", "row", "query*; page; impressions: number; clicks: number; position: number",
                   list_cols=("query", "impressions", "clicks", "position"), report=search_perf_report, report_label="Top queries")
PARENTAL = _spec("parental", "Parental Controls", "rule", "child*; device; kind: choice(time limit|blocked app|bedtime|content filter|other)=time limit; value; status: choice(on|off)=on",
                 list_cols=("child", "kind", "value", "status"), group="child", report=policy_report, report_label="Rules per child")
SCREENTIME = _spec("screentime", "Screen Time Log", "entry", "date: date; app*; minutes: number",
                   list_cols=("date", "app", "minutes"), amount="minutes", group="app", report=screen_time_report, report_label="Daily totals")
LOST = _spec("lost", "Lost and Found Registry", "item", "item*; last_seen; date: date; status: choice(lost|found)=lost; notes: long",
             status="status", done=("found",), report=lost_report, report_label="Still lost")
ART = _spec("art", "Art and Culture Collection", "work", "title*; artist; year; museum; period; notes: long",
            list_cols=("title", "artist", "year", "museum"), report=art_report, report_label="By collection")
WATCH = _spec("watch", "Movies and TV Watchlist", "title", "title*; kind: choice(movie|series|documentary)=movie; where; status: choice(to watch|watching|watched)=to watch; rating: number; notes: long",
              status="status", done=("watched",), list_cols=("title", "kind", "status", "rating"), report=watch_report, report_label="Summary")
KIDS = _spec("kidsvideo", "Kids Video Lists", "video", "title*; channel; min_age: number=0; approved: choice(yes|no)=no; notes: long",
             list_cols=("title", "channel", "min_age", "approved"), report=kids_report, report_label="Approved list")
CHANNEL = _spec("channel", "Video Channel Manager", "video", "title*; status: choice(idea|filmed|edited|published)=idea; date: date; views: number; notes: long",
                status="status", done=("published",), list_cols=("title", "status", "date", "views"), report=channel_report, report_label="Pipeline")
GUIDE = _spec("tvguide", "Live TV Guide", "programme", "program*; channel; date: date; start; end; record: choice(yes|no)=no",
              list_cols=("program", "channel", "date", "start"), report=guide_report, report_label="Overlaps")
CLOUD = _spec("cloudres", "Cloud Resource Inventory", "resource", "name*; kind: choice(compute|storage|database|network|other)=compute; region; monthly_cost: money; status: choice(running|stopped|deleted)=running",
              status="status", done=("deleted",), amount="monthly_cost", group="kind", list_cols=("name", "kind", "region", "monthly_cost", "status"), report=cloud_report, report_label="Monthly cost")
EXPERIMENTS = _spec("aiexp", "AI Experiment Log", "run", "title*; model; params; rating: number; result: long",
                    list_cols=("title", "model", "rating"), report=experiment_report, report_label="Best run")
RELEASES = _spec("releases", "App Release Tracker", "release", "app*; version*; track: choice(internal|beta|production)=internal; status: choice(draft|in review|live)=draft; date: date; notes: long",
                 status="status", done=("live",), list_cols=("app", "version", "track", "status"), report=release_report, report_label="Latest per app")
REWARDS = _spec("rewards", "Rewards Tracker", "entry", "activity*; kind: choice(earned|redeemed)=earned; points: number; date: date",
                list_cols=("activity", "kind", "points", "date"), report=rewards_report, report_label="Balance")
ACCESS = _spec("accessories", "Gaming Accessory Profiles", "profile", "accessory*; game; profile; bindings: long",
               list_cols=("accessory", "game", "profile"), report=accessory_report, report_label="Summary")
GAMING = _spec("kidgaming", "Children's Gaming Log", "session", "child*; game; date: date; minutes: number",
               list_cols=("child", "game", "date", "minutes"), amount="minutes", group="child", report=gaming_report, report_label="Time per child")
FONTS = _spec("fonts", "Font Catalogue", "font", "font*; family; style: choice(serif|sans|mono|script|display)=sans; licence; used_for",
              list_cols=("font", "family", "style", "licence"), report=font_report, report_label="Licence check")
SCHOLAR = _spec("scholar", "Academic Reference Library", "reference", "title*; authors; year; venue; tags: tags; abstract: long",
                list_cols=("title", "authors", "year"), report=bibliography, report_label="Bibliography")
BOOKS = _spec("bookcat", "Book Catalogue", "book", "title*; author; isbn; shelf; read: choice(unread|reading|read)=unread",
              status="read", done=("read",), list_cols=("title", "author", "shelf", "read"), report=books_report, report_label="ISBN check")


def _reg(spec):
    def make(host, e):
        r = RecordList(Data(host, spec))
        r.title = e.title
        return r
    return make


def _sudoku(host, e):
    from .pack_games import SudokuScreen
    return SudokuScreen(host)


def _mines(host, e):
    from .pack_games import MinesScreen
    return MinesScreen(host)


def _scope(spec): return spec.scope


NOTE_OFFLINE = "Single-user and offline: it keeps what you type in your own vault and calculates from it."


def _r(title, spec, scope, note, **kw):
    return app(title, _reg(spec), scope, note, **kw)


ENTRIES = [
    # ---- working apps with their own logic
    app("Authenticator Codes", lambda host, e: AuthScreen(host), "partial",
        "Works out one-time codes (RFC 4226 / 6238: SHA-1, SHA-256, SHA-512, 6-10 digits) from a base32 secret you type. It never saves a "
        "secret, because the vault is not encrypted yet (rule 8), so you type it each time. No QR scanning and no sync."),
    app("Sudoku Puzzles", _sudoku, "full", "Unique-solution puzzles at three levels, conflict marking and a solved counter. Turn-based; no timer."),
    app("Minesweeper Puzzles", _mines, "full", "9x9 board with 10 mines, a safe first click, flags, and win/loss counts. Turn-based; no timer."),
    app("Mahjong Solitaire", lambda host, e: MahjongScreen(host), "partial",
        "Tile matching on a flat 4x9 board: a tile is free when a side is open, and every deal is solvable. No stacked layers and no tile artwork; letters stand for tiles."),
    app("Digital Card Games", lambda host, e: BlackjackScreen(host), "partial",
        "Blackjack against a dealer who stands on 17, with win/loss counts and no money. Solitaire and other card games are not built."),
    app("Virtual Keyboard", lambda host, e: KeyboardScreen(host), "partial",
        "An on-screen keyboard that composes text inside this app. It cannot type into other apps: an app may not send keys elsewhere."),
    app("Trend Analyzer", _trend, "partial",
        "Analyses a series of numbers you paste: change, growth, index, moving average. It cannot fetch search or market data; that needs the network."),
    # ---- registers with exact reports
    _r("Trip Planner", TRIPS, "partial", "Bookings, places and costs per trip with exact totals. " + NOTE_OFFLINE + " It books nothing."),
    _r("Flight Planner", FLIGHTS, "partial", "Compares itineraries you type in (price, duration, stops). It does not search airlines or prices; that needs the network."),
    _r("Product Comparison", COMPARE, "partial", "Compares offers you typed in and shows the best price per product. It does not look prices up online."),
    _r("Blog Manager", BLOG, "partial", "Drafts, schedules and a published index. It does not host or publish a blog; the Website Builder turns text into static pages."),
    _r("Business Listings", LISTINGS, "partial", "Keeps your business details and flags missing fields. It does not publish to any directory or verify you with anyone."),
    _r("Site Ad Revenue", ADSITE, "partial", "Impressions, clicks and revenue you copy in, with exact click-through rate and revenue per 1000. It reads no ad network."),
    _r("App Ad Revenue", ADAPP, "partial", "Requests, impressions and revenue you copy in, with exact fill rate and eCPM. It reads no ad network."),
    _r("Tag Manager", TAGS, "partial", "A register of tracking tags with duplicate detection. It cannot inject or fire tags on any site."),
    _r("Search Performance", SEARCHPERF, "partial", "Queries, impressions, clicks and positions you import, with exact click-through rates. It reads no search engine's data."),
    _r("Parental Controls", PARENTAL, "partial", "Rules for each child written down. It enforces nothing on any device: only the OS can limit apps, and KOS apps cannot manage other devices."),
    _r("Screen Time Log", SCREENTIME, "partial", "Daily totals from minutes you log, against a fixed 120-minute line. It cannot measure other apps' usage: an app cannot see another app."),
    _r("Lost and Found Registry", LOST, "partial", "Records where you last saw an item. It cannot locate anything: it has no radio, no location and no network."),
    _r("Art and Culture Collection", ART, "partial", "A register of works, artists and museums you want to remember. It holds no images and does not browse any museum's collection."),
    _r("Movies and TV Watchlist", WATCH, "partial", "What to watch, what you watched and your ratings. It plays nothing and finds nothing online."),
    _r("Kids Video Lists", KIDS, "partial", "An approved list of videos by minimum age. It plays no video and filters nothing on any site."),
    _r("Video Channel Manager", CHANNEL, "partial", "Plans videos from idea to published with view counts you type in. It uploads nothing and reads no channel."),
    _r("Live TV Guide", GUIDE, "partial", "A programme guide you fill in, with overlap checks for what you want to record. It streams and records nothing."),
    _r("Cloud Resource Inventory", CLOUD, "partial", "A register of cloud resources and their monthly cost you typed in. It reads no cloud account and manages nothing remotely."),
    _r("AI Experiment Log", EXPERIMENTS, "partial", "Logs model runs you did elsewhere with params, ratings and results. It runs no model; for a local model see the AI Assistant."),
    _r("App Release Tracker", RELEASES, "partial", "Versions, tracks and review status for your apps. It publishes nothing to any store."),
    _r("Rewards Tracker", REWARDS, "partial", "Counts points you earned and redeemed. It earns or redeems nothing on any service."),
    _r("Gaming Accessory Profiles", ACCESS, "partial", "Notes of the key bindings you want per accessory and game. It cannot configure any device: apps get no device access."),
    _r("Children's Gaming Log", GAMING, "partial", "Minutes per child and game you log. It cannot see what any console records."),
    _r("Font Catalogue", FONTS, "partial", "A register of fonts with style and licence, flagging missing licences. It holds no font files and renders no specimen."),
    _r("Academic Reference Library", SCHOLAR, "partial", "Keeps references and formats a sorted author-year bibliography. It does not search papers; that needs the network."),
    _r("Book Catalogue", BOOKS, "partial", "Your books by shelf, with ISBN-10 and ISBN-13 check-digit validation. It does not search a library or bookshop."),
    # ---- not built, with the reason
    none("Web Search", "Needs the network, and every connection is blocked until a firewall rule allows it. The browser app (examples/web) opens pages once its firewall rule exists; there is no search engine inside KOS."),
    none("Web Browser", "Not in the suite: the browser is its own sandboxed app under examples/web, https only, and only reaches hosts the firewall allows."),
    none("Voice Assistant", "Needs a microphone, speech recognition and a speaker. Apps get no audio device. The AI Assistant answers typed questions only."),
    none("Earth Explorer", "A 3D globe needs map tiles from the network, a 3D renderer and the GPU. The command protocol carries text and pixels only."),
    none("Street Imagery Viewer", "Needs panoramic photos from a server and the network. There is no imagery on this device."),
    none("Image Recognition", "Needs a camera and a trained vision model. No model ships with KOS and apps get no camera."),
    none("Text Messaging", "Needs a cellular modem and a carrier. KOS apps have no telephony, and the Messaging Platform keeps messages on this device only."),
    none("Phone Calls", "Needs a modem and real-time audio. See Calls and Conferencing: the command protocol carries no audio."),
    none("Virtual Phone Number", "Needs a telephone service provider and network access. Nothing local can own a phone number."),
    none("Handwriting Input", "Needs a pen or touch device and a recognition model. Apps get only the pointer events the OS forwards, and no model ships."),
    none("Earth Timelapse", "Needs years of satellite images from a server and video rendering. The Animation Maker draws your own frames."),
    none("Satellite Imagery Analysis", "Needs large image archives and compute from a remote service. Nothing local holds them."),
    none("Python Notebooks", "Would run code a user typed. Apps may not eval, exec or compile user text (kos-rules). The Script Editor edits scripts; it does not run them in an app."),
    none("Flight Simulator", "Needs a 3D engine, physics and a real-time loop. KOS apps are turn-based text and pixels; nothing runs on a timer."),
    none("Block World Game", "Needs a 3D engine and real-time play. KOS apps are turn-based; no 3D renderer exists."),
    none("Movie and TV Streaming", "Needs the network, a video decoder and licensed content. The Movies and TV Watchlist records what you want to watch."),
    none("Music Streaming", "Needs the network, an audio device and a licensed catalogue. The Music Library keeps a register of your own tracks."),
    none("Audiobook Player", "Needs an audio device. The Book Reader reads text; no app can play sound."),
    none("Live TV Streaming", "Needs the network and a video decoder. The Live TV Guide is a schedule you fill in; it plays nothing."),
    none("Find My Device", "Needs location, a radio and the network, held by the OS. A register of lost items exists (Lost and Found Registry)."),
]
