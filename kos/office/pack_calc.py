"""pack_calc: Calculator, Graphing Calculator, Equation Editor, Unit Converter, Finance Calculator.

One small safe expression parser (no eval/exec) serves the calculator, the graph and the finance fields.
Standard library only; nothing runs in the background; every input is length-bounded."""

from __future__ import annotations

import html
import math
import re
import unicodedata
from decimal import Decimal
from fractions import Fraction

from .packkit import app
from .ui import ListNav, Menu, Prompt, Screen, Store, TextInput, TextView, table

MAXLEN = 200
MAXDEPTH = 40
MAXBITS = 200000


class CalcError(Exception):
    pass


# ------------------------------------------------------------ expression engine ----
CONSTS = {"pi": math.pi, "e": math.e, "tau": math.tau, "phi": (1 + math.sqrt(5)) / 2}
FUNCS = frozenset("sin cos tan asin acos atan atan2 sinh cosh tanh asinh acosh atanh sqrt cbrt ln log log2 exp abs "
                  "floor ceil round fact ncr npr deg rad sign min max hypot mod pow gcd numerator denominator".split())
ARITY = {"atan2": (2, 2), "hypot": (2, 2), "mod": (2, 2), "pow": (2, 2), "ncr": (2, 2), "npr": (2, 2), "gcd": (2, 2),
         "log": (1, 2), "round": (1, 2), "min": (1, 20), "max": (1, 20)}
_NUM = re.compile(r"(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
_ID = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_WORD = re.compile(r"[0-9A-Za-z_]+")
_OP = re.compile(r"\*\*|//|<<|>>|[-+*/%^&|~(),!]")


def wrap_int(v: int, w: int) -> int:
    """Two's-complement wraparound to w bits."""
    v &= (1 << w) - 1
    return v - (1 << w) if v >> (w - 1) else v


def _lit(text, mode):
    if mode == "float":
        return float(text)
    m = re.search(r"[eE]([+-]?\d+)", text)
    if m and len(m.group(1)) > 4 or (m and abs(int(m.group(1))) > 300):
        raise CalcError("exponent too large")
    return Fraction(text)


def lex(src, mode, base):
    if not isinstance(src, str) or len(src) > MAXLEN:
        raise CalcError(f"expression too long (max {MAXLEN} characters)")
    out, i = [], 0
    while i < len(src):
        ch = src[i]
        if ch in " \t":
            i += 1
            continue
        if mode == "int":
            m = _WORD.match(src, i)
            if m:
                w = m.group().lower()
                try:
                    v = int(w, 0) if w[:2] in ("0x", "0b", "0o") else int(w, base)
                    out.append(("n", v))
                except ValueError:
                    if w in ("ans", "m"):
                        out.append(("i", w))
                    else:
                        raise CalcError(f"bad number {w}")
                i = m.end()
                continue
        else:
            m = _NUM.match(src, i)
            if m:
                out.append(("n", _lit(m.group(), mode)))
                i = m.end()
                continue
            m = _ID.match(src, i)
            if m:
                out.append(("i", m.group().lower()))
                i = m.end()
                continue
        m = _OP.match(src, i)
        if m:
            out.append(("o", m.group()))
            i = m.end()
            continue
        raise CalcError(f"unexpected character {ch!r}")
    return out


_LV_INT = [("|",), ("^",), ("&",), ("<<", ">>"), ("+", "-"), ("*", "/", "//", "%")]
_LV_NUM = [("+", "-"), ("*", "/", "//", "%")]


class _P:
    def __init__(s, toks, mode, names):
        s.t, s.i, s.mode, s.names, s.depth = toks, 0, mode, names, 0
        s.lv = _LV_INT if mode == "int" else _LV_NUM

    def peek(s):
        return s.t[s.i] if s.i < len(s.t) else ("e", "")

    def op(s, *ops):
        k, v = s.peek()
        if k == "o" and v in ops:
            s.i += 1
            return v
        return None

    def enter(s):
        s.depth += 1
        if s.depth > MAXDEPTH:
            raise CalcError("expression nested too deeply")

    def binary(s, lvl):
        if lvl == len(s.lv):
            return s.unary()
        a = s.binary(lvl + 1)
        while True:
            o = s.op(*s.lv[lvl])
            if o is None and lvl == len(s.lv) - 1 and s.mode != "int" and (s.peek()[0] == "i" or s.peek() == ("o", "(")):
                o = "*"
            if o is None:
                return a
            a = ("b", o, a, s.binary(lvl + 1))

    def unary(s):
        s.enter()
        try:
            o = s.op("-", "+", "~")
            if o:
                if o == "~" and s.mode != "int":
                    raise CalcError("~ is only in programmer mode")
                a = s.unary()
                return a if o == "+" else ("u", o, a)
            return s.power()
        finally:
            s.depth -= 1

    def power(s):
        a = s.postfix()
        if s.op(*(("**",) if s.mode == "int" else ("^", "**"))):
            return ("b", "**", a, s.unary())
        return a

    def postfix(s):
        a = s.atom()
        while s.op("!"):
            if s.mode == "int":
                raise CalcError("! is not available in programmer mode")
            a = ("f", "fact", [a])
        return a

    def atom(s):
        k, v = s.peek()
        if k == "n":
            s.i += 1
            return ("n", v)
        if k == "i":
            s.i += 1
            if s.mode != "int" and v in FUNCS and s.op("("):
                args = []
                if not s.op(")"):
                    while True:
                        s.enter()
                        args.append(s.binary(0))
                        s.depth -= 1
                        if s.op(")"):
                            break
                        if not s.op(",") or len(args) >= 20:
                            raise CalcError("expected , or )")
                lo, hi = ARITY.get(v, (1, 1))
                if not lo <= len(args) <= hi:
                    raise CalcError(f"{v} takes {lo} argument(s)" if lo == hi else f"{v} takes {lo} to {hi} arguments")
                return ("f", v, args)
            if v in s.names:
                return ("v", v)
            raise CalcError(f"unknown name {v}")
        if (k, v) == ("o", "("):
            s.i += 1
            s.enter()
            a = s.binary(0)
            s.depth -= 1
            if not s.op(")"):
                raise CalcError("missing )")
            return a
        raise CalcError("expected a value" if k == "e" else f"unexpected {v}")


def parse(src, mode="float", names=(), base=10):
    toks = lex(src, mode, base)
    if not toks:
        raise CalcError("empty expression")
    p = _P(toks, mode, set(names))
    ast = p.binary(0)
    if p.i != len(toks):
        raise CalcError(f"unexpected {toks[p.i][1]}")
    return ast


class Ctx:
    def __init__(s, mode="float", deg=False, width=64, vars=None):
        s.mode, s.deg, s.width, s.vars = mode, deg, width, vars if vars is not None else {}


def _chk(r, c):
    if c.mode == "float":
        if r != r or r in (math.inf, -math.inf):
            raise CalcError("overflow or undefined")
    elif c.mode == "exact" and r.numerator.bit_length() + r.denominator.bit_length() > MAXBITS:
        raise CalcError("number too large")
    return r


def _tdiv(a, b):
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _bin(o, a, b, c):
    m = c.mode
    if m == "int":
        w = c.width
        if o in "+-*" and len(o) == 1:
            r = a + b if o == "+" else a - b if o == "-" else a * b
        elif o == "/":
            r = _tdiv(a, b)
        elif o == "//":
            r = a // b
        elif o == "%":
            r = a - _tdiv(a, b) * b
        elif o == "&": r = a & b
        elif o == "|": r = a | b
        elif o == "^": r = a ^ b
        elif o in ("<<", ">>"):
            if b < 0:
                raise CalcError("negative shift")
            r = a << min(b, w) if o == "<<" else a >> min(b, w)
        else:  # **
            if b < 0:
                raise CalcError("negative exponent in integer mode")
            r = pow(a, b, 1 << w)
        return wrap_int(r, w)
    if m == "exact":
        if o == "+": r = a + b
        elif o == "-": r = a - b
        elif o == "*": r = a * b
        elif o == "/": r = a / b
        elif o == "//": r = Fraction(a // b)
        elif o == "%": r = a % b
        else:
            if b.denominator != 1:
                raise CalcError("exact mode needs a whole-number exponent (sqrt() for roots)")
            if abs(b) > 10000 or max(a.numerator.bit_length(), a.denominator.bit_length()) * abs(b) > MAXBITS:
                raise CalcError("exponent too large")
            r = a ** int(b)
        return _chk(Fraction(r), c)
    if o == "+": r = a + b
    elif o == "-": r = a - b
    elif o == "*": r = a * b
    elif o == "/": r = a / b
    elif o == "//": r = float(math.floor(a / b))
    elif o == "%": r = a % b
    else: r = math.pow(a, b)
    return _chk(r, c)


def _whole(x, lim):
    if isinstance(x, float):
        ok = x.is_integer()
    else:
        ok = x.denominator == 1
    if not ok or not 0 <= x <= lim:
        raise CalcError(f"needs a whole number from 0 to {lim}")
    return int(x)


def _half_up(x, d):
    s = 10 ** d
    v = Fraction(x) * s
    r = math.floor(abs(v) + Fraction(1, 2))
    return Fraction(-r if v < 0 else r, s)


def _cbrt(x):
    y = math.copysign(abs(x) ** (1 / 3), x)
    r = round(y)
    return float(r) if r ** 3 == x else y


def _fn(name, a, c):
    x = a[0]
    if name in ("min", "max"):
        return (min if name == "min" else max)(a)
    if name == "fact":
        return _chk((Fraction if c.mode == "exact" else float)(math.factorial(_whole(x, 1000 if c.mode == "exact" else 170))), c)
    if name in ("ncr", "npr"):
        n, k = _whole(x, 1000), _whole(a[1], 1000)
        r = (math.comb if name == "ncr" else math.perm)(n, k)
        return _chk(Fraction(r) if c.mode == "exact" else float(r), c)
    if name == "gcd":
        r = math.gcd(_whole(x, 10 ** 15), _whole(a[1], 10 ** 15))
        return Fraction(r) if c.mode == "exact" else float(r)
    if c.mode == "exact":
        if name == "abs": return abs(x)
        if name == "floor": return Fraction(math.floor(x))
        if name == "ceil": return Fraction(math.ceil(x))
        if name == "sign": return Fraction((x > 0) - (x < 0))
        if name == "numerator": return Fraction(x.numerator)
        if name == "denominator": return Fraction(x.denominator)
        if name == "round":
            d = _whole(a[1], 30) if len(a) > 1 else 0
            return _half_up(x, d)
        if name == "mod": return _bin("%", x, a[1], c)
        if name == "pow": return _bin("**", x, a[1], c)
        if name == "sqrt":
            if x < 0:
                raise CalcError("sqrt of a negative number")
            n, d = math.isqrt(x.numerator), math.isqrt(x.denominator)
            if n * n == x.numerator and d * d == x.denominator:
                return Fraction(n, d)
            raise CalcError("sqrt is not exact here (use sci mode)")
        raise CalcError(f"{name} is not exact (use sci mode)")
    deg = c.deg
    if name in ("sin", "cos", "tan"):
        t = math.radians(x) if deg else x
        s, co = math.sin(t), math.cos(t)
        s, co = (0.0 if abs(s) < 1e-15 else s), (0.0 if abs(co) < 1e-15 else co)
        if name == "sin": return s
        if name == "cos": return co
        if co == 0:
            raise CalcError("tan is undefined here")
        return _chk(s / co, c)
    if name in ("asin", "acos", "atan"):
        r = getattr(math, name)(x)
        return math.degrees(r) if deg else r
    if name == "atan2":
        r = math.atan2(x, a[1])
        return math.degrees(r) if deg else r
    if name in ("sinh", "cosh", "tanh", "asinh", "acosh", "atanh", "sqrt", "exp", "log2", "hypot"):
        return _chk(math.hypot(x, a[1]) if name == "hypot" else getattr(math, name)(x), c)
    if name == "cbrt": return _cbrt(x)
    if name == "ln": return math.log(x)
    if name == "log": return math.log(x) / math.log(a[1]) if len(a) > 1 else math.log10(x)
    if name == "abs": return abs(x)
    if name == "floor": return float(math.floor(x))
    if name == "ceil": return float(math.ceil(x))
    if name == "sign": return float((x > 0) - (x < 0))
    if name == "deg": return math.degrees(x)
    if name == "rad": return math.radians(x)
    if name == "mod": return x % a[1]
    if name == "pow": return _chk(math.pow(x, a[1]), c)
    if name == "round":
        d = _whole(a[1], 15) if len(a) > 1 else 0
        return float(_half_up(Fraction(x), d))
    raise CalcError(f"{name} is not available in this mode")


def ev(n, c):
    k = n[0]
    if k == "n":
        v = n[1]
        return wrap_int(v, c.width) if c.mode == "int" else _chk(v, c)
    if k == "v":
        return c.vars[n[1]] if n[1] in c.vars else CONSTS[n[1]]
    if k == "u":
        a = ev(n[2], c)
        if c.mode == "int":
            return wrap_int(-a if n[1] == "-" else ~a, c.width)
        return _chk(-a, c)
    if k == "b":
        return _bin(n[1], ev(n[2], c), ev(n[3], c), c)
    return _fn(n[1], [ev(x, c) for x in n[2]], c)


def run(ast, c):
    try:
        return ev(ast, c)
    except CalcError:
        raise
    except ZeroDivisionError:
        raise CalcError("division by zero")
    except OverflowError:
        raise CalcError("result too large")
    except (ValueError, ArithmeticError, RecursionError, TypeError):
        raise CalcError("undefined (outside the function's domain)")


def evaluate(src, mode="float", deg=False, width=64, base=10, vars=None):
    vars = dict(vars or {})
    names = set(vars) | (set(CONSTS) if mode == "float" else set())
    return run(parse(src, mode, names, base), Ctx(mode, deg, width, vars))


def dec(f, sig=12):
    """A Fraction as a decimal string with at most sig significant digits."""
    if f.denominator == 1 and abs(f.numerator) < 10 ** sig:
        return str(f.numerator)
    s = format(Decimal(f.numerator) / Decimal(f.denominator), f".{sig}g")
    return "0" if s in ("-0", "0E+0") else s


def fmt_float(v):
    if v == int(v) and abs(v) < 1e15:
        return str(int(v))
    return f"{v:.12g}"


def fmt_lines(v, mode="float", width=64):
    if mode == "float":
        return [fmt_float(v)]
    if mode == "exact":
        return [str(v)] + (["~ " + dec(v)] if v.denominator != 1 else [])
    u = v & ((1 << width) - 1)
    bits = format(u, f"0{width}b")
    groups = [bits[i:i + 4] for i in range(0, width, 4)]
    out = [f"DEC {v}", f"HEX {u:0{width // 4}X}", f"OCT {u:o}"]
    out += ["BIN " + " ".join(groups[i:i + 8]) for i in range(0, len(groups), 8)]
    return out


def to_frac(v):
    return v if isinstance(v, Fraction) else Fraction(v) if isinstance(v, int) else Fraction(repr(v))


def conv(fr, mode, width=64):
    if mode == "float":
        try:
            return float(fr)
        except OverflowError:
            return 0.0
    if mode == "exact":
        return fr
    return wrap_int(int(fr), width)


# ------------------------------------------------------------------ Calculator ----
MODES = ("sci", "exact", "prog")
MODEVAL = {"sci": "float", "exact": "exact", "prog": "int"}
BASES = (10, 16, 8, 2)
BASENAME = {10: "dec", 16: "hex", 8: "oct", 2: "bin"}


class Calc(Screen):
    title = "Calculator"
    help = "Enter =   Tab mode   Ctrl-G deg/rad   Ctrl-W bits   Ctrl-B base   Up/Down history   ms m+ m- mc clear"

    def __init__(s, host):
        s.host, s.st = host, Store(host)
        d = s.st.load("calc", {})
        d = d if isinstance(d, dict) else {}
        s.mode = d.get("mode") if d.get("mode") in MODES else "sci"
        s.deg = d.get("deg") is True
        s.width = d.get("width") if d.get("width") in (8, 16, 32, 64) else 64
        s.base = d.get("base") if d.get("base") in BASES else 10
        h = d.get("hist")
        s.hist = [[str(a)[:MAXLEN], str(b)[:80]] for a, b in h[-50:] if isinstance(a, str) and isinstance(b, str)] if isinstance(h, list) and all(isinstance(x, list) and len(x) == 2 for x in h) else []
        s.mem, s.ans = Fraction(0), Fraction(0)
        for k in ("mem", "ans"):
            try:
                v = d.get(k)
                if isinstance(v, str) and len(v) < 400:
                    setattr(s, k, Fraction(v))
            except (ValueError, ZeroDivisionError):
                pass
        s.inp, s.out, s.err, s.hpos = TextInput(), [], "", None

    def save(s):
        s.st.save("calc", {"mode": s.mode, "deg": s.deg, "width": s.width, "base": s.base, "hist": s.hist[-50:],
                           "mem": str(s.mem), "ans": str(s.ans)})

    def vars(s):
        return {"ans": conv(s.ans, MODEVAL[s.mode], s.width), "m": conv(s.mem, MODEVAL[s.mode], s.width)}

    def header(s):
        if s.mode == "sci": return f"sci  {'deg' if s.deg else 'rad'}"
        if s.mode == "exact": return "exact (fractions)"
        return f"programmer  {s.width}-bit  input {BASENAME[s.base]}"

    def render(s, w, h):
        out = [f" {s.header()}   M={dec(s.mem)}", ""]
        room = max(0, h - 8 - len(s.out))
        for a, b in (s.hist[-room:] if room else []):
            out.append(f"  {a} = {b}"[:w - 1])
        out += ["", "  > " + s.inp.render()[:w - 6]]
        out += ["    " + l for l in s.out]
        if s.err:
            out.append("  error: " + s.err)
        return out

    def key(s, k):
        s.err = ""
        if k == "enter": s.run_line()
        elif k == "tab": s.mode = MODES[(MODES.index(s.mode) + 1) % 3]; s.out = []; s.save()
        elif k == "ctrl-g": s.deg = not s.deg; s.save()
        elif k == "ctrl-w": s.width = {8: 16, 16: 32, 32: 64, 64: 8}[s.width]; s.save()
        elif k == "ctrl-b": s.base = BASES[(BASES.index(s.base) + 1) % 4]; s.save()
        elif k in ("up", "down") and s.hist:
            s.hpos = (len(s.hist) if s.hpos is None else s.hpos) + (-1 if k == "up" else 1)
            s.hpos = max(0, min(len(s.hist) - 1, s.hpos))
            s.inp = TextInput(s.hist[s.hpos][0])
        else:
            s.inp.key(k)
            s.inp.value = s.inp.value[:MAXLEN]
            s.inp.pos = min(s.inp.pos, len(s.inp.value))

    def run_line(s):
        src, s.hpos = s.inp.value.strip(), None
        if not src:
            return
        low = src.lower()
        if low in ("ms", "m+", "m-", "mc", "clear"):
            if low == "ms": s.mem = s.ans
            elif low == "m+": s.mem += s.ans
            elif low == "m-": s.mem -= s.ans
            elif low == "mc": s.mem = Fraction(0)
            else: s.hist = []
            s.inp, s.out = TextInput(), []
            s.save()
            return
        try:
            v = evaluate(src, MODEVAL[s.mode], s.deg, s.width, s.base, s.vars())
        except CalcError as e:
            s.err = str(e)
            return
        s.ans = to_frac(v)
        s.out = fmt_lines(v, MODEVAL[s.mode], s.width)
        s.hist.append([src, s.out[0].replace("DEC ", "")])
        del s.hist[:-50]
        s.inp = TextInput()
        s.save()


# ------------------------------------------------------------ Graphing Calculator ----
COLORS = ["#d33333", "#2277cc", "#22aa44", "#aa33cc"]
SYMS = "*o#x"
DEFAULT_VIEW = [-10.0, 10.0, -10.0, 10.0]


def compile_fn(src, deg=False):
    src = re.sub(r"^\s*(?:y|f\(x\))\s*=", "", src)
    ast = parse(src, "float", {"x"})
    c = Ctx("float", deg, 64, {"x": 0.0})

    def f(x):
        c.vars["x"] = x
        try:
            return run(ast, c)
        except CalcError:
            return None
    return f


def roots_in(f, lo, hi, n=400):
    """Sign-change scan plus bisection. A sign change at a pole is rejected because |f| stays huge there.
    Roots that touch zero without crossing it are not found."""
    xs = [lo + (hi - lo) * i / n for i in range(n + 1)]
    ys = [f(x) for x in xs]
    found = []
    for i in range(n + 1):
        if ys[i] == 0:
            found.append(xs[i])
        if i < n and ys[i] and ys[i + 1] and ys[i] * ys[i + 1] < 0:
            a, b, fa = xs[i], xs[i + 1], ys[i]
            for _ in range(60):
                m = (a + b) / 2
                fm = f(m)
                if fm is None:
                    break
                if fm == 0:
                    a = b = m
                    break
                if fa * fm < 0: b = m
                else: a, fa = m, fm
            r = (a + b) / 2
            fr = f(r)
            if fr is not None and abs(fr) <= 1e-6 * max(1.0, abs(ys[i]), abs(ys[i + 1])):
                found.append(r)
    found.sort()
    out = []
    for r in found:
        if not out or abs(r - out[-1]) > 1e-9 * max(1.0, abs(r)):
            out.append(r)
    return out[:20]


def jumps(f, lo, hi, span, n=400):
    """x positions where adjacent samples differ by more than the view height (poles, jumps)."""
    out, prev = [], None
    for i in range(n + 1):
        x = lo + (hi - lo) * i / n
        y = f(x)
        if prev is not None and y is not None and abs(y - prev[1]) > span:
            out.append((prev[0] + x) / 2)
        prev = (x, y) if y is not None else None
    return out[:10]


def _diff(f, g):
    def d(x):
        a, b = f(x), g(x)
        return None if a is None or b is None else a - b
    return d


class Graph(Screen):
    title = "Graphing Calculator"
    help = "1-4 edit y1..y4   arrows pan   + - zoom   0 reset   f fit y   r roots   d deg/rad"

    def __init__(s, host):
        s.host, s.st = host, Store(host)
        d = s.st.load("graph", {})
        d = d if isinstance(d, dict) else {}
        fs = d.get("f") if isinstance(d.get("f"), list) else []
        s.src = [(str(x)[:MAXLEN] if isinstance(x, str) else "") for x in fs[:4]]
        s.src += [""] * (4 - len(s.src))
        if not any(s.src):
            s.src[0] = "sin(x)"
        v = d.get("view")
        s.view = [float(x) for x in v] if isinstance(v, list) and len(v) == 4 and all(type(x) in (int, float) and math.isfinite(x) for x in v) and v[0] < v[1] and v[2] < v[3] else list(DEFAULT_VIEW)
        s.deg = d.get("deg") is True
        s.msg = ""
        s.build()

    def build(s):
        s.fns, s.errs = [], []
        for t in s.src:
            if not t.strip():
                s.fns.append(None); s.errs.append("")
                continue
            try:
                s.fns.append(compile_fn(t, s.deg)); s.errs.append("")
            except CalcError as e:
                s.fns.append(None); s.errs.append(str(e))

    def save(s):
        s.st.save("graph", {"f": s.src, "view": s.view, "deg": s.deg})

    def pan(s, fx, fy):
        x0, x1, y0, y1 = s.view
        dx, dy = (x1 - x0) * fx, (y1 - y0) * fy
        if max(abs(x0 + dx), abs(x1 + dx), abs(y0 + dy), abs(y1 + dy)) < 1e9:
            s.view = [x0 + dx, x1 + dx, y0 + dy, y1 + dy]

    def zoom(s, k):
        x0, x1, y0, y1 = s.view
        cx, cy, hx, hy = (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) / 2 * k, (y1 - y0) / 2 * k
        if 1e-6 <= hx * 2 <= 1e9 and 1e-6 <= hy * 2 <= 1e9:
            s.view = [cx - hx, cx + hx, cy - hy, cy + hy]

    def fit(s):
        vals = []
        for f in s.fns:
            if f:
                for i in range(200):
                    y = f(s.view[0] + (s.view[1] - s.view[0]) * i / 199)
                    if y is not None and abs(y) <= 1e6:
                        vals.append(y)
        if len(vals) < 2:
            return
        vals.sort()
        lo, hi = vals[int(len(vals) * 0.02)], vals[max(0, int(len(vals) * 0.98) - 1)]
        if hi - lo < 1e-9:
            lo, hi = lo - 1, hi + 1
        pad = (hi - lo) * 0.1
        s.view[2], s.view[3] = lo - pad, hi + pad

    def key(s, k):
        s.msg = ""
        if k in ("left", "right"): s.pan(-0.1 if k == "left" else 0.1, 0)
        elif k in ("up", "down"): s.pan(0, 0.1 if k == "up" else -0.1)
        elif k in ("+", "="): s.zoom(0.5)
        elif k in ("-", "_"): s.zoom(2)
        elif k == "0": s.view = list(DEFAULT_VIEW)
        elif k == "f": s.fit()
        elif k == "d": s.deg = not s.deg; s.build()
        elif k in ("1", "2", "3", "4"):
            i = int(k) - 1
            return ("push", Prompt(f"y{i + 1}", f"y{i + 1} = (blank to remove)", s.src[i], lambda t, i=i: s.set_fn(i, t)))
        elif k == "r":
            return ("push", TextView("Roots and intersections", s.report()))
        else:
            return None
        s.save()

    def set_fn(s, i, t):
        s.src[i] = t.strip()[:MAXLEN]
        s.build()
        s.msg = s.errs[i]
        s.save()
        return None

    def report(s):
        x0, x1, y0, y1 = s.view
        span = y1 - y0
        out = [f"View x {x0:.6g}..{x1:.6g}, y {y0:.6g}..{y1:.6g}. Bisection on 400 samples; "
               "roots that only touch zero are missed.", ""]
        live = [(i, f) for i, f in enumerate(s.fns) if f]
        for i, f in live:
            r = roots_in(f, x0, x1)
            out.append(f"y{i + 1}: roots at x = " + (", ".join(f"{v:.8g}" for v in r) if r else "none in view"))
            j = jumps(f, x0, x1, span)
            if j:
                out.append(f"    possible discontinuity near x = " + ", ".join(f"{v:.5g}" for v in j[:5]))
        for a in range(len(live)):
            for b in range(a + 1, len(live)):
                (i, f), (j, g) = live[a], live[b]
                r = roots_in(_diff(f, g), x0, x1)
                out.append(f"y{i + 1} = y{j + 1} at " + ("; ".join(f"({v:.8g}, {f(v):.8g})" for v in r) if r else "no crossing in view"))
        for i, e in enumerate(s.errs):
            if e: out.append(f"y{i + 1} error: {e}")
        return out

    def legend(s):
        return [f"y{i + 1}={t}" + (f" [{s.errs[i]}]" if s.errs[i] else "") for i, t in enumerate(s.src) if t]

    def render(s, w, h):
        x0, x1, y0, y1 = s.view
        cols, rows = max(10, min(w - 10, 120)), max(5, h - 5)
        g = [[" "] * cols for _ in range(rows)]
        ar = round((y1 / (y1 - y0)) * (rows - 1)) if y0 <= 0 <= y1 else None
        ac = round((-x0 / (x1 - x0)) * (cols - 1)) if x0 <= 0 <= x1 else None
        for c in range(cols):
            if ar is not None: g[ar][c] = "-"
        for r in range(rows):
            if ac is not None: g[r][ac] = "+" if r == ar else "|"
        span = y1 - y0
        for i, f in enumerate(s.fns):
            if not f:
                continue
            prev = None
            for c in range(cols):
                y = f(x0 + (x1 - x0) * c / (cols - 1))
                if y is None:
                    prev = None
                    continue
                r = max(-10 ** 6, min(10 ** 6, round((y1 - y) / span * (rows - 1))))
                lo, hi = r, r
                if prev is not None and abs(y - prev[1]) <= span:
                    lo, hi = min(r, prev[0]), max(r, prev[0])
                for rr in range(max(0, lo), min(rows - 1, hi) + 1):
                    g[rr][c] = SYMS[i]
                prev = (r, y)
        out = ["  ".join(f"{SYMS[int(l[1]) - 1]} {l}" for l in s.legend())[:w - 1]]
        for r in range(rows):
            lab = f"{y1:>8.3g}" if r == 0 else f"{y0:>8.3g}" if r == rows - 1 else " " * 8
            out.append(lab + " " + "".join(g[r]))
        out.append(f"{'':9}x {x0:.4g} .. {x1:.4g}   {'deg' if s.deg else 'rad'}   {s.msg}")
        return out

    def canvas(s, w, h):
        from kos.sdk import Canvas
        c = Canvas().clear("#ffffff")
        x0, x1, y0, y1 = s.view
        top, ph, pw = 16, max(20, h - 32), max(40, w)
        span = y1 - y0
        c.rect(0, 0, w, 14, "#222222")
        c.text(3, 3, ("  ".join(s.legend()))[:120], "#ffffff", 1)
        if y0 <= 0 <= y1:
            ay = top + round(y1 / span * ph)
            c.line(0, ay, pw, ay, "#999999")
        if x0 <= 0 <= x1:
            ax = round(-x0 / (x1 - x0) * pw)
            c.line(ax, top, ax, top + ph, "#999999")
        c.text(3, top + ph + 4, f"x {x0:.4g}..{x1:.4g}   y {y0:.4g}..{y1:.4g}   {'deg' if s.deg else 'rad'}  {s.msg}"[:120], "#222222", 1)
        step = max(1, pw // 400)

        def py(y):
            return top + (y1 - y) / span * ph
        for i, f in enumerate(s.fns):
            if not f:
                continue
            prev = None
            for px in range(0, pw + 1, step):
                y = f(x0 + (x1 - x0) * px / pw)
                if y is None:
                    prev = None
                    continue
                if prev is not None and abs(y - prev[1]) <= span and not (y > y1 and prev[1] > y1) and not (y < y0 and prev[1] < y0):
                    ya = int(max(top - 2, min(top + ph + 2, py(prev[1]))))
                    yb = int(max(top - 2, min(top + ph + 2, py(y))))
                    c.line(prev[0], ya, px, yb, COLORS[i])
                prev = (px, y)
        return c


# ---------------------------------------------------------------- Equation Editor ----
GREEK = ("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi pi rho sigma tau upsilon phi chi "
         "psi omega Gamma Delta Theta Lambda Xi Pi Sigma Phi Psi Omega").split()
UNI = {g: unicodedata.lookup(f"GREEK {'CAPITAL' if g[0].isupper() else 'SMALL'} LETTER {g.upper().replace('LAMBDA', 'LAMDA')}") for g in GREEK}
UNI.update({"inf": "∞", "infinity": "∞", "partial": "∂"})
TEXN = {**{g: "\\" + g for g in GREEK}, "inf": "\\infty", "infinity": "\\infty", "partial": "\\partial"}
FNAMES = {"sin", "cos", "tan", "cot", "sec", "csc", "arcsin", "arccos", "arctan", "sinh", "cosh", "tanh", "ln", "log", "exp", "min", "max", "det", "lim"}
OPTEX = {"*": "\\cdot ", "+-": "\\pm ", "<=": "\\le ", ">=": "\\ge ", "!=": "\\ne ", "->": "\\to ", "==": "="}
OPUNI = {"*": "⋅", "+-": "±", "<=": "≤", ">=": "≥", "!=": "≠", "->": "→", "==": "=", "-": "−"}
EQMAX = 300
_EQ = re.compile(r"\s*(?:(\d+\.?\d*|\.\d+)|([A-Za-z]+)|(<=|>=|!=|==|->|\+-|[-+*/^_(),=<>!]))")


class EqError(Exception):
    pass


def eq_lex(src):
    if not isinstance(src, str) or len(src) > EQMAX:
        raise EqError(f"too long (max {EQMAX} characters)")
    out, i = [], 0
    while src[i:].strip():
        m = _EQ.match(src, i)
        if not m:
            raise EqError(f"unsupported character {src[i:].lstrip()[0]!r}")
        out.append(("n", m.group(1)) if m.group(1) else ("i", m.group(2)) if m.group(2) else ("o", m.group(3)))
        i = m.end()
    return out


class _EP:
    def __init__(s, t):
        s.t, s.i, s.d = t, 0, 0

    def peek(s):
        return s.t[s.i] if s.i < len(s.t) else ("e", "")

    def op(s, *o):
        k, v = s.peek()
        if k == "o" and v in o:
            s.i += 1
            return v

    def deeper(s):
        s.d += 1
        if s.d > MAXDEPTH:
            raise EqError("nested too deeply")

    def rel(s):
        a = s.add()
        while True:
            o = s.op("=", "<", ">", "<=", ">=", "!=", "==", "->")
            if not o: return a
            a = ("bin", o, a, s.add())

    def add(s):
        a = s.mul()
        while True:
            o = s.op("+", "-", "+-")
            if not o: return a
            a = ("bin", o, a, s.mul())

    def mul(s):
        a = s.unary()
        while True:
            if s.op("/"): a = ("frac", a, s.unary())
            elif s.op("*"): a = ("bin", "*", a, s.unary())
            elif s.peek()[0] == "i" or s.peek() == ("o", "("): a = ("juxt", a, s.unary())
            else: return a

    def unary(s):
        s.deeper()
        try:
            if s.op("-"): return ("neg", s.unary())
            s.op("+")
            return s.postfix()
        finally:
            s.d -= 1

    def postfix(s):
        a = s.atom()
        while s.op("!"): a = ("fact", a)
        sub = sup = None
        if s.op("_"): sub = s.atom()
        if s.op("^"): sup = s.unary()
        return ("subsup", a, sub, sup) if sub and sup else ("sub", a, sub) if sub else ("pow", a, sup) if sup else a

    def args(s):
        out = []
        if s.op(")"): return out
        while True:
            s.deeper()
            out.append(s.rel())
            s.d -= 1
            if s.op(")"): return out
            if not s.op(",") or len(out) >= 6: raise EqError("expected , or )")

    def atom(s):
        k, v = s.peek()
        if k == "n":
            s.i += 1
            return ("num", v)
        if k == "i":
            s.i += 1
            if s.op("("):
                return s.call(v, s.args())
            return ("sym", v) if v in UNI else ("id", v)
        if (k, v) == ("o", "("):
            s.i += 1
            s.deeper()
            a = s.rel()
            s.d -= 1
            if not s.op(")"): raise EqError("missing )")
            return ("paren", a)
        raise EqError("expected a value" if k == "e" else f"unexpected {v}")

    def call(s, name, a):
        n = len(a)

        def need(*c):
            if n not in c: raise EqError(f"{name} takes {' or '.join(map(str, c))} argument(s)")
        if name == "sqrt": need(1); return ("sqrt", a[0])
        if name == "root": need(2); return ("root", a[0], a[1])
        if name == "abs": need(1); return ("abs", a[0])
        if name == "frac": need(2); return ("frac", a[0], a[1])
        if name in ("sum", "prod"): need(3); return ("big", name, a[0], a[1], a[2])
        if name == "int":
            need(2, 4)
            return ("int", None, None, a[0], a[1]) if n == 2 else ("int", a[0], a[1], a[2], a[3])
        if name == "lim": need(2); return ("lim", a[0], a[1])
        return ("call", name, a)


def eq_parse(src):
    t = eq_lex(src)
    if not t: raise EqError("type an expression, e.g. sum(i=1,n,i^2) = n(n+1)/2")
    p = _EP(t)
    ast = p.rel()
    if p.i != len(t): raise EqError(f"unexpected {t[p.i][1]}")
    return ast


def _strip(n):
    return n[1] if n[0] == "paren" else n


def _tname(n):
    return n if len(n) == 1 else ("\\" + n if n in FNAMES else "\\mathrm{" + n + "}")


def tex(n):
    k = n[0]
    if k == "num": return n[1]
    if k == "id": return n[1] if len(n[1]) == 1 else "\\mathrm{" + n[1] + "}"
    if k == "sym": return TEXN[n[1]]
    if k == "neg": return "-" + tex(n[1])
    if k == "bin": return f"{tex(n[2])} {OPTEX.get(n[1], n[1])} {tex(n[3])}"
    if k == "juxt": return tex(n[1]) + " " + tex(n[2])
    if k == "frac": return "\\frac{" + tex(_strip(n[1])) + "}{" + tex(_strip(n[2])) + "}"
    if k == "pow": return tex(n[1]) + "^{" + tex(_strip(n[2])) + "}"
    if k == "sub": return tex(n[1]) + "_{" + tex(_strip(n[2])) + "}"
    if k == "subsup": return tex(n[1]) + "_{" + tex(_strip(n[2])) + "}^{" + tex(_strip(n[3])) + "}"
    if k == "sqrt": return "\\sqrt{" + tex(_strip(n[1])) + "}"
    if k == "root": return "\\sqrt[" + tex(_strip(n[1])) + "]{" + tex(_strip(n[2])) + "}"
    if k == "abs": return "\\left|" + tex(_strip(n[1])) + "\\right|"
    if k == "paren": return "\\left(" + tex(n[1]) + "\\right)"
    if k == "fact": return tex(n[1]) + "!"
    if k == "call": return _tname(n[1]) + "\\left(" + ", ".join(tex(x) for x in n[2]) + "\\right)"
    if k == "big": return ("\\sum" if n[1] == "sum" else "\\prod") + "_{" + tex(n[2]) + "}^{" + tex(n[3]) + "} " + tex(n[4])
    if k == "int":
        lim = "" if n[1] is None else "_{" + tex(n[1]) + "}^{" + tex(n[2]) + "}"
        return "\\int" + lim + " " + tex(n[3]) + " \\, d" + tex(n[4])
    return "\\lim_{" + tex(n[1]) + "} " + tex(n[2])  # lim


def _mi(name):
    if name in UNI: return f"<mi>{UNI[name]}</mi>"
    return f"<mi>{name}</mi>" if len(name) == 1 else f'<mi mathvariant="normal">{name}</mi>'


def mml(n):
    k = n[0]
    g = lambda x: mml(_strip(x))
    if k == "num": return f"<mn>{n[1]}</mn>"
    if k == "id": return _mi(n[1])
    if k == "sym": return _mi(n[1])
    if k == "neg": return f"<mrow><mo>−</mo>{mml(n[1])}</mrow>"
    if k == "bin": return f"<mrow>{mml(n[2])}<mo>{html.escape(OPUNI.get(n[1], n[1]))}</mo>{mml(n[3])}</mrow>"
    if k == "juxt": return f"<mrow>{mml(n[1])}<mo>&#x2062;</mo>{mml(n[2])}</mrow>"
    if k == "frac": return f"<mfrac>{g(n[1])}{g(n[2])}</mfrac>"
    if k == "pow": return f"<msup>{mml(n[1])}{g(n[2])}</msup>"
    if k == "sub": return f"<msub>{mml(n[1])}{g(n[2])}</msub>"
    if k == "subsup": return f"<msubsup>{mml(n[1])}{g(n[2])}{g(n[3])}</msubsup>"
    if k == "sqrt": return f"<msqrt>{g(n[1])}</msqrt>"
    if k == "root": return f"<mroot>{g(n[2])}{g(n[1])}</mroot>"
    if k == "abs": return f"<mrow><mo>|</mo>{g(n[1])}<mo>|</mo></mrow>"
    if k == "paren": return f"<mrow><mo>(</mo>{mml(n[1])}<mo>)</mo></mrow>"
    if k == "fact": return f"<mrow>{mml(n[1])}<mo>!</mo></mrow>"
    if k == "call":
        inner = "<mo>,</mo>".join(mml(x) for x in n[2])
        return f"<mrow>{_mi(n[1])}<mo>&#x2061;</mo><mrow><mo>(</mo>{inner}<mo>)</mo></mrow></mrow>"
    if k == "big":
        sym = "∑" if n[1] == "sum" else "∏"
        return f"<mrow><munderover><mo>{sym}</mo>{mml(n[2])}{mml(n[3])}</munderover>{mml(n[4])}</mrow>"
    if k == "int":
        head = "<mo>∫</mo>" if n[1] is None else f"<msubsup><mo>∫</mo>{mml(n[1])}{mml(n[2])}</msubsup>"
        return f"<mrow>{head}{mml(n[3])}<mo>d</mo>{mml(n[4])}</mrow>"
    return f"<mrow><munder><mo>lim</mo>{mml(n[1])}</munder>{mml(n[2])}</mrow>"


def mathml(ast):
    return f'<math xmlns="http://www.w3.org/1998/Math/MathML" display="block">{mml(ast)}</math>'


# 2-D text: a box is (lines, baseline row)
def _w(b): return max(len(l) for l in b[0])
def _tb(t): return ([t], 0)


def _hcat(*bs):
    up = max(b[1] for b in bs)
    down = max(len(b[0]) - b[1] for b in bs)
    rows = []
    for r in range(up + down):
        row = ""
        for lines, base in bs:
            i = r - (up - base)
            row += (lines[i] if 0 <= i < len(lines) else "").ljust(max(len(l) for l in lines))
        rows.append(row)
    return (rows, up)


def _center(lines, w):
    return [l.center(w) for l in lines]


def _stack(parts, base_idx):
    w = max(_w(p) for p in parts)
    lines, base = [], 0
    for i, p in enumerate(parts):
        if i == base_idx: base = len(lines) + p[1]
        lines += _center(p[0], w)
    return (lines, base)


def _side(l1, l2):
    w = max(len(l) for l in l1)
    return [a.ljust(w) + b for a, b in zip(l1, l2)]


def _brackets(b, lt, rt, mids):
    lines, base = b
    if len(lines) == 1:
        return _hcat(_tb(lt), b, _tb(rt))
    n = len(lines)
    L = [mids[0]] + [mids[1]] * (n - 2) + [mids[2]]
    R = [mids[3]] + [mids[4]] * (n - 2) + [mids[5]]
    return _hcat((L, base), b, (R, base))


def tb2(n):
    k = n[0]
    if k == "num": return _tb(n[1])
    if k == "id": return _tb(n[1])
    if k == "sym": return _tb(UNI[n[1]])
    if k == "neg": return _hcat(_tb("-"), tb2(n[1]))
    if k == "bin": return _hcat(tb2(n[2]), _tb(" " + OPUNI.get(n[1], n[1]) + " " if n[1] != "*" else " ⋅ "), tb2(n[3]))
    if k == "juxt": return _hcat(tb2(n[1]), tb2(n[2]))
    if k == "frac":
        a, b = tb2(_strip(n[1])), tb2(_strip(n[2]))
        w = max(_w(a), _w(b)) + 2
        return (_center(a[0], w) + ["─" * w] + _center(b[0], w), len(a[0]))
    if k == "pow":
        b, e = tb2(n[1]), tb2(_strip(n[2]))
        return (_side([""] * len(e[0]) + b[0], e[0] + [""] * len(b[0])), len(e[0]) + b[1])
    if k == "sub":
        b, e = tb2(n[1]), tb2(_strip(n[2]))
        return (_side(b[0] + [""] * len(e[0]), [""] * len(b[0]) + e[0]), b[1])
    if k == "subsup":
        b, s_, e = tb2(n[1]), tb2(_strip(n[2])), tb2(_strip(n[3]))
        return (_side([""] * len(e[0]) + b[0] + [""] * len(s_[0]), e[0] + [""] * len(b[0]) + s_[0]), len(e[0]) + b[1])
    if k in ("sqrt", "root"):
        i = tb2(_strip(n[1] if k == "sqrt" else n[2]))
        lines = [" " + "_" * _w(i)] + [("√" if r == i[1] else "│") + l for r, l in enumerate(i[0])]
        box = (lines, i[1] + 1)
        if k == "root":
            idx = tb2(_strip(n[1]))
            box = _hcat((idx[0] + [""] * (len(lines) - len(idx[0])), 0), box) if len(idx[0]) <= len(lines) else box
        return box
    if k == "abs": return _brackets(tb2(_strip(n[1])), "|", "|", "│" * 6)
    if k == "paren": return _brackets(tb2(n[1]), "(", ")", "⎛⎜⎝⎞⎟⎠")
    if k == "fact": return _hcat(tb2(n[1]), _tb("!"))
    if k == "call":
        parts = [_tb(n[1] + "(")]
        for i, x in enumerate(n[2]):
            parts += ([_tb(", ")] if i else []) + [tb2(x)]
        return _hcat(*parts, _tb(")"))
    if k == "big":
        st = _stack([tb2(n[3]), _tb("Σ" if n[1] == "sum" else "Π"), tb2(n[2])], 1)
        return _hcat(st, _tb(" "), tb2(n[4]))
    if k == "int":
        if n[1] is None:
            return _hcat(_tb("∫ "), tb2(n[3]), _tb(" d"), tb2(n[4]))
        st = _stack([tb2(n[2]), _tb("∫"), tb2(n[1])], 1)
        return _hcat(st, _tb(" "), tb2(n[3]), _tb(" d"), tb2(n[4]))
    return _hcat(_stack([_tb("lim"), tb2(n[1])], 0), _tb(" "), tb2(n[2]))


def text2d(ast):
    return [l.rstrip() for l in tb2(ast)[0]]


class Equation(Screen):
    title = "Equation Editor"
    VIEWS = ("2-D text", "LaTeX", "MathML")
    help = "type plain math   Tab view   Ctrl-S save to vault   Up/Down history   Ctrl-U clear"
    EXAMPLE = "sum(i=1,n,i^2) = n(n+1)(2n+1)/6"

    def __init__(s, host):
        s.host, s.st = host, Store(host)
        h = s.st.load("equation", {})
        s.hist = [x[:EQMAX] for x in h.get("hist", [])[-30:] if isinstance(x, str)] if isinstance(h, dict) and isinstance(h.get("hist"), list) else []
        s.inp, s.view, s.msg, s.hpos = TextInput(s.hist[-1] if s.hist else s.EXAMPLE), 0, "", None

    def outputs(s):
        ast = eq_parse(s.inp.value)
        return text2d(ast), tex(ast), mathml(ast)

    def render(s, w, h):
        out = ["", "  > " + s.inp.render()[:w - 6], f"  view: {s.VIEWS[s.view]}   {s.msg}", ""]
        try:
            o = s.outputs()
        except EqError as e:
            return out + ["  error: " + str(e),
                          "  names: sqrt root abs frac sum prod int lim, greek names (alpha, Omega), inf, x_1, x^2, a/b, <= >= != ->"]
        body = o[0] if s.view == 0 else [o[s.view]]
        out += ["  " + l for l in body]
        if s.view:
            out += ["", "  (long lines are cut on screen; Ctrl-S saves the full text)"]
        return [l[:w - 1] for l in out] if s.view else out

    def key(s, k):
        s.msg = ""
        if k == "tab": s.view = (s.view + 1) % 3
        elif k in ("up", "down") and s.hist:
            s.hpos = (len(s.hist) if s.hpos is None else s.hpos) + (-1 if k == "up" else 1)
            s.hpos = max(0, min(len(s.hist) - 1, s.hpos))
            s.inp = TextInput(s.hist[s.hpos])
        elif k == "ctrl-s":
            try:
                o = s.outputs()
            except EqError as e:
                s.msg = "cannot save: " + str(e)
                return
            ok = s.host.put("export-equation.tex", "$$" + o[1] + "$$\n") and s.host.put("export-equation.mathml", o[2] + "\n")
            s.hist = (s.hist + [s.inp.value])[-30:]
            ok = ok and s.st.save("equation", {"hist": s.hist})
            s.msg = "saved export-equation.tex and .mathml to the vault" if ok else "not saved: " + (s.host.error or "storage refused")
        else:
            s.inp.key(k)
            s.inp.value = s.inp.value[:EQMAX]
            s.inp.pos = min(s.inp.pos, len(s.inp.value))


# ------------------------------------------------------------------ Unit Converter ----
F = Fraction
_GAL = F("0.003785411784")
_LB = F("0.45359237")
_G = F("9.80665")
_IN = F("0.0254")
_FT = F("0.3048")


def _u(*rows):
    return [(n, F(sc), F(off)) for n, sc, off in rows]


UNITS = {
    "Length": _u(("m", 1, 0), ("km", 1000, 0), ("cm", "0.01", 0), ("mm", "0.001", 0), ("um", "0.000001", 0), ("nm", "0.000000001", 0),
                 ("in", _IN, 0), ("ft", _FT, 0), ("yd", "0.9144", 0), ("mi", "1609.344", 0), ("nmi", 1852, 0)),
    "Mass": _u(("kg", 1, 0), ("g", "0.001", 0), ("mg", "0.000001", 0), ("ug", "0.000000001", 0), ("t", 1000, 0),
               ("lb", _LB, 0), ("oz", _LB / 16, 0), ("st", _LB * 14, 0)),
    "Temperature": _u(("C", 1, "273.15"), ("F", F(5, 9), F("459.67") * F(5, 9)), ("K", 1, 0), ("R", F(5, 9), 0)),
    "Volume": _u(("m3", 1, 0), ("L", "0.001", 0), ("mL", "0.000001", 0), ("gal", _GAL, 0), ("qt", _GAL / 4, 0), ("pt", _GAL / 8, 0),
                 ("cup", _GAL / 16, 0), ("floz", _GAL / 128, 0), ("tbsp", _GAL / 256, 0), ("tsp", _GAL / 768, 0), ("gal_uk", "0.00454609", 0)),
    "Area": _u(("m2", 1, 0), ("km2", 1000000, 0), ("cm2", "0.0001", 0), ("mm2", "0.000001", 0), ("ha", 10000, 0), ("in2", _IN ** 2, 0),
               ("ft2", _FT ** 2, 0), ("yd2", F("0.9144") ** 2, 0), ("acre", _FT ** 2 * 43560, 0), ("mi2", F("1609.344") ** 2, 0)),
    "Speed": _u(("m/s", 1, 0), ("km/h", F(1000, 3600), 0), ("mph", F("1609.344") / 3600, 0), ("kn", F(1852, 3600), 0), ("ft/s", _FT, 0)),
    "Time": _u(("ns", "0.000000001", 0), ("us", "0.000001", 0), ("ms", "0.001", 0), ("s", 1, 0), ("min", 60, 0), ("h", 3600, 0),
               ("day", 86400, 0), ("week", 604800, 0), ("year", 31557600, 0)),
    "Data": _u(("bit", 1, 0), ("byte", 8, 0), ("kB", 8000, 0), ("MB", 8 * 10 ** 6, 0), ("GB", 8 * 10 ** 9, 0), ("TB", 8 * 10 ** 12, 0), ("PB", 8 * 10 ** 15, 0),
               ("KiB", 8 * 2 ** 10, 0), ("MiB", 8 * 2 ** 20, 0), ("GiB", 8 * 2 ** 30, 0), ("TiB", 8 * 2 ** 40, 0), ("PiB", 8 * 2 ** 50, 0)),
    "Energy": _u(("J", 1, 0), ("kJ", 1000, 0), ("cal", "4.184", 0), ("kcal", 4184, 0), ("Wh", 3600, 0), ("kWh", 3600000, 0),
                 ("eV", "0.0000000000000000001602176634", 0), ("BTU", "1055.05585262", 0), ("ft_lbf", _FT * _LB * _G, 0)),
    "Pressure": _u(("Pa", 1, 0), ("kPa", 1000, 0), ("MPa", 1000000, 0), ("bar", 100000, 0), ("mbar", 100, 0), ("atm", 101325, 0),
                   ("torr", F(101325, 760), 0), ("mmHg", "133.322387415", 0), ("psi", _LB * _G / _IN ** 2, 0)),
}
CATS = list(UNITS) + ["Currency"]
_Q = re.compile(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d{1,3})?(?:/\d{1,30})?$")
MAXRATES = 30


def parse_q(text):
    t = text.strip()
    if len(t) > 40 or not _Q.match(t):
        raise CalcError("enter a number like 12, 3.5, 1e3 or 1/3")
    try:
        return F(t)
    except ZeroDivisionError:
        raise CalcError("division by zero")


def convert(q, units, frm, to):
    d = {n: (sc, off) for n, sc, off in units}
    base = q * d[frm][0] + d[frm][1]
    return (base - d[to][1]) / d[to][0]


def currency_units(rates):
    return [("USD", F(1), F(0))] + [(c, 1 / r, F(0)) for c, r in rates.items()]


class Units(Screen):
    title = "Unit Converter"
    help = "type a value   Tab category   Up/Down from-unit   Currency: Ctrl-R add rate, Ctrl-D delete"

    def __init__(s, host):
        s.host, s.st = host, Store(host)
        d = s.st.load("units", {})
        d = d if isinstance(d, dict) else {}
        s.cat = CATS.index(d["cat"]) if d.get("cat") in CATS else 0
        s.rates = {}
        r = d.get("rates")
        if isinstance(r, dict):
            for c, t in list(r.items())[:MAXRATES]:
                try:
                    q = parse_q(str(t))
                    if re.fullmatch(r"[A-Z]{2,6}", str(c)) and q > 0 and c != "USD":
                        s.rates[c] = q
                except CalcError:
                    pass
        s.inp = TextInput(str(d.get("value", "1"))[:40])
        s.nav = ListNav(len(s.units()))
        names = [n for n, _, _ in s.units()]
        if d.get("unit") in names:
            s.nav.sel = names.index(d["unit"])
        s.msg = ""

    def units(s):
        return currency_units(s.rates) if CATS[s.cat] == "Currency" else UNITS[CATS[s.cat]]

    def save(s):
        s.st.save("units", {"cat": CATS[s.cat], "unit": s.units()[s.nav.sel][0], "value": s.inp.value,
                            "rates": {c: dec(r, 15) for c, r in s.rates.items()}})

    def render(s, w, h):
        u = s.units()
        s.nav.resize(len(u))
        out = [f" Category: {CATS[s.cat]}", f" Value: {s.inp.render()}  {u[s.nav.sel][0]}", ""]
        if CATS[s.cat] == "Currency":
            out[2] = " No live rates (no network): only the rates you type. Ctrl-R: 'EUR 0.92' = 1 USD buys 0.92 EUR."
        try:
            q = parse_q(s.inp.value)
        except CalcError as e:
            q, s.msg = None, str(e)
        top, end = s.nav.window(h - 5)
        for i in range(top, end):
            val = dec(convert(q, u, u[s.nav.sel][0], u[i][0])) if q is not None else ""
            out.append(("> " if i == s.nav.sel else "  ") + f"{u[i][0]:<8} {val}")
        return out + [" " + s.msg]

    def key(s, k):
        s.msg = ""
        if k == "tab":
            s.cat = (s.cat + 1) % len(CATS)
            s.nav = ListNav(len(s.units()))
        elif k in ("up", "down"): s.nav.resize(len(s.units())); s.nav.key(k)
        elif k == "ctrl-r" and CATS[s.cat] == "Currency":
            return ("push", Prompt("Currency rate", "CODE rate  (units of CODE per 1 USD, e.g. EUR 0.92)", "", s.add_rate))
        elif k == "ctrl-d" and CATS[s.cat] == "Currency":
            name = s.units()[s.nav.sel][0]
            if name in s.rates:
                del s.rates[name]
                s.nav.resize(len(s.units()))
        elif k != "enter":
            s.inp.key(k)
            s.inp.value = s.inp.value[:40]
            s.inp.pos = min(s.inp.pos, len(s.inp.value))
            return None
        s.save()

    def add_rate(s, text):
        p = text.split()
        try:
            if len(p) != 2 or not re.fullmatch(r"[A-Za-z]{2,6}", p[0]) or p[0].upper() == "USD":
                raise CalcError("type a code and a rate, e.g. EUR 0.92 (USD is the reference)")
            q = parse_q(p[1])
            if q <= 0:
                raise CalcError("rate must be positive")
            if p[0].upper() not in s.rates and len(s.rates) >= MAXRATES:
                raise CalcError("too many currencies")
            s.rates[p[0].upper()] = q
            s.save()
        except CalcError as e:
            s.msg = str(e)
        return None


# ------------------------------------------------------------ Finance Calculator ----
class FinError(Exception):
    pass


def money(v):
    return f"{v:,.2f}"


def loan(P, rate, years, ppy):
    n = round(years * ppy)
    if not (P > 0 and 0 <= rate <= 1000 and 0 < years <= 100 and 1 <= ppy <= 366 and float(ppy).is_integer() and 1 <= n <= 1200):
        raise FinError("need amount > 0, rate 0-1000 %, years 0-100, 1-366 payments per year, at most 1200 payments")
    r = rate / 100 / ppy
    pay = round(P / n if r == 0 else P * r / (1 - (1 + r) ** -n), 2)
    bal, rows, tot_int, tot_paid = round(P * 100), [], 0, 0
    pc = round(pay * 100)
    for i in range(1, n + 1):
        interest = math.floor(bal * r + 0.5)
        princ = bal if (i == n or pc - interest > bal) else pc - interest
        bal -= princ
        tot_int += interest
        tot_paid += princ + interest
        rows.append([i, f"{(princ + interest) / 100:,.2f}", f"{interest / 100:,.2f}", f"{princ / 100:,.2f}", f"{bal / 100:,.2f}"])
        if bal <= 0:
            break
    return {"payment": pay, "interest": tot_int / 100, "paid": tot_paid / 100, "rows": rows}


def compound(P, rate, years, m, contrib):
    if not (0 < years <= 100 and 1 <= m <= 366 and float(m).is_integer() and -100 <= rate <= 1000):
        raise FinError("need years 0-100, 1-366 periods per year, rate -100 to 1000 %")
    i = rate / 100 / m
    out = []
    for y in range(1, math.ceil(years) + 1):
        n = min(round(y * m), round(years * m))
        a = (1 + i) ** n
        out.append((y, P * a + (contrib * (a - 1) / i if i else contrib * n)))
    n = round(years * m)
    return out[-1][1], P + contrib * n, out


def goal(target, rate, years, m, initial):
    if not (0 < years <= 100 and 1 <= m <= 366 and float(m).is_integer() and -100 < rate <= 1000):
        raise FinError("need years 0-100, 1-366 periods per year, rate over -100 %")
    n, i = round(years * m), rate / 100 / m
    if n < 1:
        raise FinError("period count rounds to zero")
    a = (1 + i) ** n
    return (target - initial * a) * i / (a - 1) if i else (target - initial) / n


def npv(rate, flows):
    if rate <= -100:
        raise FinError("rate must be above -100 %")
    return sum(cf / (1 + rate / 100) ** t for t, cf in enumerate(flows))


def irr(flows):
    """All rates (percent) in -99..1000 where NPV changes sign; first is the usual answer."""
    if len(flows) < 2 or not (any(f < 0 for f in flows) and any(f > 0 for f in flows)):
        raise FinError("cash flows need at least one negative and one positive amount")

    def f(r):
        try:
            return sum(cf / (1 + r) ** t for t, cf in enumerate(flows))
        except (OverflowError, ZeroDivisionError):
            return None
    rs = [-0.99 + 0.01 * k for k in range(1100)]
    out = []
    for a, b in zip(rs, rs[1:]):
        fa, fb = f(a), f(b)
        if fa is None or fb is None: continue
        if fa == 0: out.append(a)
        elif fa * fb < 0:
            lo, hi = a, b
            for _ in range(80):
                mid = (lo + hi) / 2
                fm = f(mid)
                if fm is None: break
                if fa * fm <= 0: hi = mid
                else: lo, fa = mid, fm
            out.append((lo + hi) / 2)
    return [r * 100 for r in out[:5]]


def tvm(pv, fv, pmt, rate, n):
    """Exactly one of the five is None; payments at period end: pv*A + pmt*B + fv = 0."""
    missing = [k for k, v in (("pv", pv), ("fv", fv), ("pmt", pmt), ("rate", rate), ("n", n)) if v is None]
    if len(missing) != 1:
        raise FinError("leave exactly one field blank - that is the one solved for")
    k = missing[0]
    if k == "rate":
        def g(r):
            A = (1 + r) ** n
            return pv * A + pmt * ((A - 1) / r if r else n) + fv
        rs = [-0.99 + 0.005 * j for j in range(2200)]
        for a, b in zip(rs, rs[1:]):
            try:
                ga, gb = g(a), g(b)
            except (OverflowError, ZeroDivisionError):
                continue
            if ga == 0: return "rate", a * 100
            if ga * gb < 0:
                for _ in range(80):
                    m = (a + b) / 2
                    gm = g(m)
                    if ga * gm <= 0: b = m
                    else: a, ga = m, gm
                return "rate", (a + b) / 2 * 100
        raise FinError("no rate found between -99 % and 1000 % per period")
    r = rate / 100
    if r <= -1:
        raise FinError("rate must be above -100 %")
    if k == "n":
        if r == 0:
            if pmt == 0: raise FinError("payment is zero")
            return "n", -(pv + fv) / pmt
        x, y = pmt - fv * r, pmt + pv * r
        if x == 0 or y == 0 or x / y <= 0:
            raise FinError("these numbers never reach the target")
        return "n", math.log(x / y) / math.log(1 + r)
    A = (1 + r) ** n
    B = (A - 1) / r if r else n
    if k == "fv": return "fv", -(pv * A + pmt * B)
    if k == "pv": return "pv", -(fv + pmt * B) / A
    if B == 0: raise FinError("zero periods")
    return "pmt", -(fv + pv * A) / B


class Form(Screen):
    help = "Up/Down/Tab field   Enter calculate   Esc back"

    def __init__(s, host, key, title, fields, compute, intro=()):
        s.host, s.st, s.key_, s.title, s.fields, s.compute, s.intro = host, Store(host), key, title, fields, compute, list(intro)
        d = s.st.load("fin-" + key, {})
        d = d if isinstance(d, dict) else {}
        s.vals = [TextInput(str(d.get(k, dflt))[:400]) for k, _l, dflt in fields]
        s.sel, s.msg = 0, ""

    def render(s, w, h):
        out = list(s.intro) + [""]
        for i, (k, label, _d) in enumerate(s.fields):
            out.append(f"{'>' if i == s.sel else ' '} {label}: " + (s.vals[i].render() if i == s.sel else s.vals[i].value))
        return [l[:w - 1] for l in out] + ["", " " + s.msg]

    def key(s, k):
        s.msg = ""
        if k in ("up",): s.sel = (s.sel - 1) % len(s.fields)
        elif k in ("down", "tab"): s.sel = (s.sel + 1) % len(s.fields)
        elif k == "enter":
            vals = {f[0]: s.vals[i].value.strip() for i, f in enumerate(s.fields)}
            try:
                lines = s.compute(vals)
            except FinError as e:
                s.msg = str(e)
                return None
            except (OverflowError, ValueError, ZeroDivisionError):
                s.msg = "numbers out of range"
                return None
            s.st.save("fin-" + s.key_, vals)
            return ("push", TextView(s.title, lines))
        else:
            v = s.vals[s.sel]
            v.key(k)
            v.value = v.value[:400]
            v.pos = min(v.pos, len(v.value))
        return None


def _n(vals, key, label, blank=False):
    if not vals[key]:
        if blank: return None
        raise FinError(f"{label} is empty")
    try:
        x = evaluate(vals[key], "float")
    except CalcError as e:
        raise FinError(f"{label}: {e}")
    if abs(x) > 1e12:
        raise FinError(f"{label} is too large")
    return x


def _flows(text):
    parts = [p for p in text.split(",") if p.strip()]
    if not 2 <= len(parts) <= 100:
        raise FinError("give 2 to 100 comma-separated cash flows (first is today)")
    return [_n({"x": p.strip()}, "x", "cash flow") for p in parts]


def f_loan(v):
    P, rate, yrs, ppy = _n(v, "P", "Amount"), _n(v, "r", "Rate"), _n(v, "y", "Years"), _n(v, "m", "Payments per year")
    L = loan(P, rate, yrs, ppy)
    head = [f"Payment each period: {money(L['payment'])}", f"Total interest: {money(L['interest'])}",
            f"Total paid: {money(L['paid'])}   payments: {len(L['rows'])}", "(last payment adjusted so the balance ends at 0)", ""]
    return head + table(L["rows"], ["#", "payment", "interest", "principal", "balance"])


def f_compound(v):
    fv, put, rows = compound(_n(v, "P", "Principal"), _n(v, "r", "Rate"), _n(v, "y", "Years"), _n(v, "m", "Compounds per year"), _n(v, "c", "Contribution"))
    return [f"Future value: {money(fv)}", f"Money put in: {money(put)}", f"Interest earned: {money(fv - put)}",
            "(contributions are made at the end of each compounding period)", ""] + table([[y, money(b)] for y, b in rows], ["year", "balance"])


def f_goal(v):
    c = goal(_n(v, "T", "Target"), _n(v, "r", "Rate"), _n(v, "y", "Years"), _n(v, "m", "Deposits per year"), _n(v, "i", "Starting balance"))
    return [f"Deposit needed each period: {money(c)}", "(deposits at the end of each period, interest compounded per period)"]


def f_npv(v):
    r, fl = _n(v, "r", "Rate"), _flows(v["f"])
    return [f"NPV at {r:g} %: {money(npv(r, fl))}", "(first cash flow is at time 0 and is not discounted)"]


def f_irr(v):
    r = irr(_flows(v["f"]))
    if not r:
        raise FinError("no IRR between -99 % and 1000 %")
    return [f"IRR: {r[0]:.6f} %"] + ([f"Other IRRs: " + ", ".join(f"{x:.4f} %" for x in r[1:])] if len(r) > 1 else [])


def f_tvm(v):
    k, x = tvm(*[_n(v, key, key, True) for key in ("pv", "fv", "pmt", "rate", "n")])
    return [f"{k} = {x:,.6f}".replace(" = ", " = "), "", "pv*(1+r)^n + pmt*((1+r)^n-1)/r + fv = 0, payments at period end.",
            "Money you receive is positive, money you pay is negative."]


def finance(host):
    def form(key, title, fields, fn, intro=()):
        return lambda: ("push", Form(host, key, title, fields, fn, intro))
    entries = [
        ("Loan / mortgage amortization", form("loan", "Loan", [("P", "Amount", "200000"), ("r", "Annual rate %", "6"), ("y", "Years", "30"), ("m", "Payments per year", "12")], f_loan)),
        ("Compound interest", form("comp", "Compound interest", [("P", "Principal", "1000"), ("r", "Annual rate %", "5"), ("y", "Years", "10"), ("m", "Compounds per year", "12"), ("c", "Contribution per period", "0")], f_compound)),
        ("Savings goal", form("goal", "Savings goal", [("T", "Target amount", "100000"), ("r", "Annual rate %", "5"), ("y", "Years", "10"), ("m", "Deposits per year", "12"), ("i", "Starting balance", "0")], f_goal)),
        ("Net present value (NPV)", form("npv", "NPV", [("r", "Discount rate %", "10"), ("f", "Cash flows (t=0 first)", "-1000, 300, 400, 500, 600")], f_npv)),
        ("Internal rate of return (IRR)", form("irr", "IRR", [("f", "Cash flows (t=0 first)", "-1000, 300, 400, 500, 600")], f_irr)),
        ("Payment / PV / FV / periods / rate", form("tvm", "Time value of money", [("pv", "Present value", "200000"), ("fv", "Future value", "0"), ("pmt", "Payment", ""), ("rate", "Rate % per period", "0.5"), ("n", "Periods", "360")], f_tvm,
                                                    ["Leave ONE field blank to solve for it."])),
    ]
    return Menu("Finance Calculator", entries)


ENTRIES = [
    app("Calculator", lambda h, e: Calc(h), "full",
        "Scientific, exact-fraction and programmer (8/16/32/64-bit) modes with a safe parser."),
    app("Graphing Calculator", lambda h, e: Graph(h), "full",
        "Plots up to four y=f(x) curves with roots and intersections; no parametric, polar or implicit plots.", graphical=True),
    app("Equation Editor", lambda h, e: Equation(h), "partial",
        "Turns typed plain math into LaTeX, MathML and 2-D text; no WYSIWYG editing, matrices or multi-line layouts."),
    app("Unit Converter", lambda h, e: Units(h), "partial",
        "Exact unit conversion; currency uses only rates you type because there are no live rates (no network)."),
    app("Finance Calculator", lambda h, e: finance(h), "full",
        "Loan amortization, compound interest, savings goal, NPV, IRR and PV/FV/payment solver; no taxes or fees."),
]
