"""pack_devutil: Developer Utilities, Log Viewer, Debug Helper, Scheduled Task Planner, Website Analytics.

Every app works on TEXT the user pastes (and the vault saves). Pick a tool, type or paste text, press Ctrl-R to run.
Standard library only; nothing runs in the background; every input is capped. See docs/PACKS.md."""

from __future__ import annotations

import base64
import binascii
import calendar
import difflib
import hashlib
import json
import re
import secrets
import time
import uuid
from bisect import bisect_left, bisect_right
from collections import Counter
from datetime import datetime, timedelta

from .packkit import app
from .ui import Editor, Menu, Store, TextView, bar, table, wrap

CAP = 100_000          # characters of input a tool looks at
MAXLINES = 5000        # lines of a log / list a tool looks at
EPOCH = datetime(1970, 1, 1)


# ------------------------------------------------------------ shared bits ----
def clean(s: str) -> str:
    """Pasted text may hold control / escape characters: never put them on the screen."""
    return "".join(c if c.isprintable() else (" " * 4 if c == "\t" else "?") for c in s)


def lines_of(text: str, n: int = MAXLINES) -> list:
    return [l[:2000] for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")][:n]


def _render(fn, text: str) -> list:
    try:
        out = fn(text[:CAP])
    except ValueError as e:
        out = [f"error: {e}"]
    except RecursionError:
        out = ["error: input is nested too deeply"]
    except Exception as e:                       # hostile input must never crash a tool
        out = [f"error: could not process this input ({type(e).__name__})"]
    res = []
    for l in out[:2000]:
        res += wrap(clean(str(l)), 78)
    return res[:2000] or ["(nothing to show)"]


def _suite(title: str, key: str, tools: list, intro: list):
    """tools: (label, fn(text) -> lines, sample text, hint). One Menu; each tool is an Editor and Ctrl-R shows the result."""
    def make(host, entry):
        store = Store(host)

        def opener(i):
            label, fn, sample, hint = tools[i]

            def go():
                saved = store.load(f"{key}.{i}", None)
                text = saved if isinstance(saved, str) else sample

                def save(t):
                    store.save(f"{key}.{i}", t[:CAP])

                def run(ed):
                    return ("push", TextView(label, _render(fn, ed.area.text)))
                return ("push", Editor(label, text, on_save=save, extra_keys={"ctrl-r": run},
                                       hint="Ctrl-R run   " + hint))
            return go
        return Menu(title, [(t[0], opener(i)) for i, t in enumerate(tools)], intro)
    return make


def _iso(s: str):
    """'2024-03-05', '2024-03-05T10:20[:30][.5][Z|+01:00]' -> naive UTC datetime, or None."""
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d))?)?(?:[.,]\d+)?\s*(Z|[+-]\d\d:?\d\d)?", s.strip())
    if not m:
        return None
    y, mo, d, h, mi, sec, tz = m.groups()
    try:
        t = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(sec or 0))
    except ValueError:
        return None
    return t - timedelta(minutes=_off(tz))


def _off(tz) -> int:
    if not tz or tz == "Z":
        return 0
    sign = -1 if tz[0] == "-" else 1
    d = tz[1:].replace(":", "")
    return sign * (int(d[:2]) * 60 + int(d[2:4]))


def _stamp(t) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S") if t else "-"


# ------------------------------------------------------ developer utilities ----
_Q = re.compile(r"\{(\d*)(,?)(\d*)\}")


def regex_risk(p: str) -> str:
    """'' if the pattern looks safe to run, else why not. `re` cannot be interrupted, so this is deliberately
    conservative: it refuses a repeated group that itself repeats or alternates (the classic (a+)+$ shape),
    backreferences, more than two unbounded repeats and patterns over 200 characters."""
    if len(p) > 200:
        return "pattern is longer than 200 characters"
    st, prev, unb_total, i, n = [[0, 0, 0]], None, 0, 0, len(p)       # per group: has quantifier, has unbounded, has |
    while i < n:
        c = p[i]
        if c == "\\":
            if i + 1 < n and p[i + 1] in "123456789":
                return "backreferences are refused"
            i += 2; prev = None; continue
        if c == "[":
            j = i + 1
            if p[j:j + 1] == "^": j += 1
            if p[j:j + 1] == "]": j += 1
            while j < n and p[j] != "]":
                j += 2 if p[j] == "\\" else 1
            i = j + 1; prev = None; continue
        if c == "(":
            st.append([0, 0, 0]); i += 1
            if p[i:i + 1] == "?": i += 2
            prev = None; continue
        if c == ")":
            if len(st) > 1:
                prev = st.pop()
                st[-1] = [st[-1][0] | prev[0], st[-1][1] | prev[1], st[-1][2] | prev[2]]
            i += 1; continue
        if c == "|":
            st[-1][2] = 1; prev = None; i += 1; continue
        m = _Q.match(p, i) if c == "{" else None
        if c in "*+?" or (m and (m.group(1) or m.group(3))):
            if m:
                lo, comma, hi = m.group(1), m.group(2), m.group(3)
                unb = bool(comma and (not hi or int(hi) > 50)) or (not comma and int(lo or 0) > 50)
                width = m.end() - i
            else:
                unb, width = c in "*+", 1
            if prev is not None:
                if unb and (prev[0] or prev[2]):
                    return "a repeated group that itself repeats or alternates (catastrophic backtracking risk)"
                if c != "?" and prev[1]:
                    return "a repeated group that contains an unbounded repeat (catastrophic backtracking risk)"
            st[-1][0] = 1
            if unb:
                st[-1][1] = 1; unb_total += 1
            i += width
            if p[i:i + 1] in ("?", "+"): i += 1
            prev = None; continue
        prev = None; i += 1
    if unb_total > 2:
        return "more than 2 unbounded repeats (*, +, {n,}); be more specific"
    return ""


def t_regex(text: str) -> list:
    ls = lines_of(text, 21)
    pat, body = ls[0], ls[1:21]
    if not pat:
        raise ValueError("first line is the pattern; the lines below are the text to test")
    why = regex_risk(pat)
    if why:
        raise ValueError("pattern refused: " + why)
    try:
        rx = re.compile(pat)
    except re.error as e:
        raise ValueError(f"invalid pattern: {e}")
    out, total = [f"pattern: {pat}  ({len(body)} line(s) tested, each cut to 200 characters)"], 0
    for n, line in enumerate(body, 1):
        for m in rx.finditer(line[:200]):
            total += 1
            if total > 100:
                break
            g = f"  groups={list(m.groups())}" if m.groups() else ""
            out.append(f"line {n} at {m.start()}-{m.end()}: {m.group(0)!r}{g}")
    return out + [f"{min(total, 100)} match(es)" + (" (stopped at 100)" if total > 100 else "")]


def _bytes_text(b: bytes) -> list:
    try:
        s = b.decode("utf-8")
        if all(c.isprintable() or c in "\n\t" for c in s):
            return s.split("\n")
    except UnicodeDecodeError:
        pass
    return [f"(binary, {len(b)} bytes) hex: {b[:200].hex()}"]


def t_b64e(text): return [base64.b64encode(text.encode()).decode()]


def t_b64d(text):
    s = "".join(text.split()).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return _bytes_text(base64.b64decode(s, validate=True))
    except (binascii.Error, ValueError):
        raise ValueError("not valid base64")


def t_hexe(text): return [text.encode().hex()]


def t_hexd(text):
    s = re.sub(r"0x|[\s:,-]", "", text)
    try:
        return _bytes_text(bytes.fromhex(s))
    except ValueError:
        raise ValueError("not valid hex (an even number of 0-9 a-f digits)")


_UNRES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def t_urle(text): return ["".join(chr(b) if b in _UNRES else "%%%02X" % b for b in text.encode())]


def t_urld(text):
    b = re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), text.encode())
    return [b.decode("utf-8", "replace"), "", "(only %XX is decoded; '+' is left as it is)"]


def t_hash(text):
    b = text.encode()
    return [f"input: {len(b)} byte(s), exactly as typed (no trailing newline)", ""] + [
        f"{n:<7}{hashlib.new(n, b).hexdigest()}" + ("   NOT for security (broken)" if n in ("md5", "sha1") else "")
        for n in ("md5", "sha1", "sha256", "sha512")]


def t_uuid(text):
    return [str(uuid.UUID(bytes=secrets.token_bytes(16), version=4)) for _ in range(5)] + ["", "random version-4 UUIDs (secrets)"]


_DAY = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def epoch_of(t) -> int:
    return calendar.timegm(t.timetuple())


def t_time(text):
    out = []
    for line in lines_of(text, 50):
        s = line.strip()
        if not s:
            continue
        if s.lower() == "now":
            s = str(int(time.time()))
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            v = float(s)
            secs = v / 1000 if abs(v) >= 1e11 else v
            try:
                t = EPOCH + timedelta(seconds=secs)
            except OverflowError:
                out.append(f"{s} -> out of range"); continue
            out.append(f"{s} -> {t.strftime('%Y-%m-%dT%H:%M:%S')}Z ({_DAY[t.weekday()]})" + ("  [read as milliseconds]" if abs(v) >= 1e11 else ""))
        else:
            t = _iso(s)
            out.append(f"{s} -> {epoch_of(t)}  (UTC, {_DAY[t.weekday()]})" if t else f"{s} -> not a number or YYYY-MM-DD[THH:MM[:SS]][Z|+HH:MM]")
    return out or ["type epoch seconds/milliseconds, a date, or 'now', one per line"]


def _json(text):
    try:
        return json.loads(text)
    except ValueError as e:
        raise ValueError(f"invalid JSON: {e}")


def t_jpretty(text): return json.dumps(_json(text), indent=2, ensure_ascii=False).split("\n")
def t_jmin(text): return [json.dumps(_json(text), separators=(",", ":"), ensure_ascii=False)]


_PATH = re.compile(r'(?:\.[\w-]+|\[(?:\d+|\*|"[^"]*")\])*')


def json_query(obj, path: str) -> list:
    p = path.strip()
    p = p[1:] if p.startswith("$") else p
    if p and not p.startswith((".", "[")):
        p = "." + p
    if not _PATH.fullmatch(p):
        raise ValueError("path syntax: $.key[0].other  or  $.list[*].name  or  $[\"odd key\"]")
    nodes = [obj]
    for m in re.finditer(r'\.([\w-]+)|\[(\d+|\*|"[^"]*")\]', p):
        key, nxt = m.group(1) or m.group(2), []
        for n in nodes:
            if key == "*":
                nxt += n if isinstance(n, list) else list(n.values()) if isinstance(n, dict) else []
            elif m.group(1) is None and key.startswith('"'):
                if isinstance(n, dict) and key[1:-1] in n: nxt.append(n[key[1:-1]])
            elif key.isdigit() and m.group(1) is None:
                if isinstance(n, list) and int(key) < len(n): nxt.append(n[int(key)])
            elif isinstance(n, dict) and key in n:
                nxt.append(n[key])
        nodes = nxt
    return nodes


def t_jpath(text):
    path, _, body = text.partition("\n")
    found = json_query(_json(body), path)
    return [json.dumps(f, ensure_ascii=False) for f in found[:200]] + [f"{len(found)} match(es)"]


def t_diff(text):
    ls = lines_of(text, 1001)
    if "---" not in ls:
        raise ValueError("put the old text, a line containing only ---, then the new text")
    i = ls.index("---")
    a, b = ls[:i][:500], ls[i + 1:][:500]
    d = list(difflib.unified_diff(a, b, "old", "new", lineterm="", n=2))
    return d + ([] if d else ["identical"]) 


def t_base(text):
    out = []
    for line in lines_of(text, 50):
        parts = line.split()
        if not parts:
            continue
        s, base = parts[0].lower(), None
        try:
            if len(parts) > 1:
                base = int(parts[1])
            elif s.lstrip("-").startswith(("0x", "0b", "0o")):
                base = 0
            else:
                base = 10
            if len(s) > 200 or not 0 <= base <= 36 or base == 1:
                raise ValueError
            v = int(s, base)
        except ValueError:
            out.append(f"{line[:40]}: not a number (use 255, 0xff, 0b1010, 0o17, or 'zz 36')")
            continue
        out.append(f"{s} = dec {v} | hex {v:#x} | oct {v:#o} | bin {v:#b} | base36 " + _b36(v))
    return out or ["one number per line; optional base after it"]


def _b36(v: int) -> str:
    if v == 0:
        return "0"
    d, s, n = "0123456789abcdefghijklmnopqrstuvwxyz", "", abs(v)
    while n:
        n, r = divmod(n, 36); s = d[r] + s
    return ("-" if v < 0 else "") + s


def _b64url_json(part: str):
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    return json.loads(raw.decode("utf-8"))


def t_jwt(text):
    parts = text.strip().split(".")
    if len(parts) not in (2, 3) or len(text) > 8000:
        raise ValueError("a JWT is header.payload.signature (three dot-separated parts)")
    try:
        head, pay = _b64url_json(parts[0]), _b64url_json(parts[1])
    except (ValueError, binascii.Error):
        raise ValueError("header or payload is not base64url JSON")
    out = ["SIGNATURE NOT VERIFIED - this only decodes. Never trust a token because it decodes.", "", "HEADER"]
    out += json.dumps(head, indent=2).split("\n") + ["", "PAYLOAD"] + json.dumps(pay, indent=2).split("\n") + [""]
    if isinstance(pay, dict):
        for k in ("iat", "nbf", "exp"):
            if isinstance(pay.get(k), (int, float)) and not isinstance(pay[k], bool):
                try:
                    out.append(f"{k}: {(EPOCH + timedelta(seconds=pay[k])).strftime('%Y-%m-%dT%H:%M:%S')}Z")
                except (OverflowError, ValueError):
                    out.append(f"{k}: out of range")
    if isinstance(head, dict) and str(head.get("alg", "")).lower() == "none":
        out.append("WARNING: alg is 'none' - an unsigned token.")
    if len(parts) == 2 or not parts[2]:
        out.append("WARNING: no signature part.")
    return out


def t_sort(text): return sorted(lines_of(text), key=lambda s: (s.casefold(), s))


def t_dedupe(text):
    seen, out = set(), []
    for l in lines_of(text):
        if l not in seen:
            seen.add(l); out.append(l)
    return out + ["", f"{len(out)} unique line(s) kept (first occurrence, original order)"]


def t_count(text):
    ls = lines_of(text)
    c = Counter(l for l in ls if l.strip())
    out = [f"lines {len(ls)}   non-empty {sum(c.values())}   unique {len(c)}   words {sum(len(l.split()) for l in ls)}   characters {len(text)}", ""]
    return out + [f"{n:>6}  {l}" for l, n in c.most_common(10)]


DEV_TOOLS = [
    ("Regex tester", t_regex, "(\\w+)@(\\w+)\\.com\nwrite to ann@example.com or bob@test.com", "line 1 = pattern, below = text"),
    ("Base64 encode", t_b64e, "hello", ""), ("Base64 decode", t_b64d, "aGVsbG8=", ""),
    ("Hex encode", t_hexe, "hello", ""), ("Hex decode", t_hexd, "68 65 6c 6c 6f", ""),
    ("URL encode", t_urle, "a b&c=d/é", ""), ("URL decode", t_urld, "a%20b%26c", ""),
    ("Hashes (md5 sha1 sha256 sha512)", t_hash, "abc", "md5/sha1 are broken"),
    ("UUID v4 generator", t_uuid, "(press Ctrl-R)", ""),
    ("Timestamp <-> date", t_time, "1700000000\n2024-03-05T10:20:00Z\nnow", "one per line"),
    ("JSON pretty-print", t_jpretty, '{"a":[1,2,{"b":null}]}', ""),
    ("JSON minify", t_jmin, '{ "a": [1, 2],\n "b": true }', ""),
    ("JSON path query", t_jpath, '$.users[*].name\n{"users":[{"name":"ann"},{"name":"bob"}]}', "line 1 = path"),
    ("Text diff", t_diff, "one\ntwo\nthree\n---\none\n2\nthree", "old --- new"),
    ("Number base conversion", t_base, "255\n0xff\n0b1010\nzz 36", ""),
    ("JWT decode (not verified)", t_jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.sig", "decode only"),
    ("Sort lines", t_sort, "pear\nApple\nfig", ""), ("Remove duplicate lines", t_dedupe, "a\nb\na", ""),
    ("Count lines / words / frequency", t_count, "a\nb\na", ""),
]


# ------------------------------------------------------------- log parsing ----
_MON = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
_LV = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "NOTICE": 2, "WARN": 3, "WARNING": 3, "ERR": 4, "ERROR": 4,
       "CRIT": 5, "CRITICAL": 5, "FATAL": 5, "ALERT": 5, "EMERG": 5, "PANIC": 5}
LEVELS = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]
_LVRX = re.compile(r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRIT(?:ICAL)?|FATAL|ALERT|EMERG|PANIC)\b", re.I)
_BADRX = re.compile(r"\b(fail(?:ed|ure)?|denied|exception|traceback|refused)\b", re.I)
_ACC = re.compile(r'^(\S+) \S+ \S+ \[(\d{1,2})/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?')
_ISOL = re.compile(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s*(.*)$")
_SYS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$")


def _level(text: str) -> int:
    m = _LVRX.search(text)
    if m:
        return _LV[m.group(1).upper()]
    return 4 if _BADRX.search(text) else 2


def _jlevel(v, fallback: str) -> int:
    if isinstance(v, bool):
        return _level(fallback)
    if isinstance(v, (int, float)):                       # pino style: 10 trace .. 60 fatal
        return 0 if v <= 10 else 1 if v <= 20 else 2 if v <= 30 else 3 if v <= 40 else 4 if v <= 50 else 5
    return _LV.get(str(v).upper(), _level(fallback))


def parse_line(line: str, n: int = 0, year: int = 1970) -> dict | None:
    s = line.strip()
    if not s:
        return None
    r = dict(n=n, ts=None, level=2, msg=s, fmt="text", raw=s, ip="", ua="", status=0, bytes=0, path="", ref="", method="")
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            o = None
        if isinstance(o, dict):
            g = lambda *ks: next((o[k] for k in ks if k in o), None)
            msg = g("message", "msg", "event", "text")
            msg = str(msg) if msg is not None else s
            tv = g("time", "timestamp", "ts", "@timestamp", "datetime")
            ts = None
            if isinstance(tv, str):
                ts = _iso(tv)
            elif isinstance(tv, (int, float)) and not isinstance(tv, bool):
                try:
                    ts = EPOCH + timedelta(seconds=tv / 1000 if abs(tv) >= 1e11 else tv)
                except OverflowError:
                    ts = None
            r.update(fmt="json", ts=ts, msg=msg[:500], level=_jlevel(g("level", "severity", "lvl", "levelname"), msg))
            return r
    m = _ACC.match(s)
    if m:
        ip, d, mon, y, h, mi, sec, tz, req, st, by, ref, ua = m.groups()
        try:
            ts = datetime(int(y), _MON.get(mon.lower(), 0) or 99, int(d), int(h), int(mi), int(sec)) - timedelta(minutes=_off(tz))
        except ValueError:
            ts = None
        parts = req.split()
        status = int(st)
        r.update(fmt="access", ts=ts, ip=ip, status=status, bytes=0 if by == "-" else int(by), ref=ref or "", ua=ua or "",
                 method=parts[0] if len(parts) > 1 else "", path=parts[1] if len(parts) > 1 else req,
                 level=4 if status >= 500 else 3 if status >= 400 else 2, msg=f"{req} -> {status}")
        return r
    m = _ISOL.match(s)
    if m:
        r.update(fmt="iso", ts=_iso(m.group(1)), msg=m.group(2) or s, level=_level(m.group(2)))
        return r
    m = _SYS.match(s)
    if m and m.group(1).lower() in _MON:
        mon, d, h, mi, sec, host, prog, msg = m.groups()
        try:
            ts = datetime(year, _MON[mon.lower()], int(d), int(h), int(mi), int(sec))
        except ValueError:
            ts = None
        r.update(fmt="syslog", ts=ts, msg=f"{prog}: {msg}", level=_level(msg))
        return r
    r["level"] = _level(s)
    return r


def parse_log(text: str, year: int | None = None) -> tuple:
    """-> (records, count of lines that matched no known format). Syslog lines carry no year: `year` (default: this one)."""
    year = year or time.gmtime().tm_year
    recs = [r for n, l in enumerate(lines_of(text), 1) if (r := parse_line(l, n, year))]
    return recs, sum(1 for r in recs if r["fmt"] == "text")


_SIG = [(re.compile(p, re.I), s) for p, s in (
    (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>"), (r"\b0x[0-9a-f]+\b", "<hex>"),
    (r"\b(?=[0-9a-f]*\d)[0-9a-f]{8,}\b", "<hex>"), (r"\d+", "<n>"))]


def signature(msg: str) -> str:
    for rx, s in _SIG:
        msg = rx.sub(s, msg)
    return " ".join(msg.split())[:120]


NOTE_LOG = "KOS cannot read /var/log or the console itself: paste the lines here (or save them in this tool)."


def _span(recs):
    ts = [r["ts"] for r in recs if r["ts"]]
    return (min(ts), max(ts)) if ts else (None, None)


def _lvl_table(recs):
    c = Counter(r["level"] for r in recs)
    return [f"  {LEVELS[k]:<6}{c[k]:>6}  {bar(c[k], max(c.values()), 24)}" for k in sorted(c)]


def top_messages(recs, n=15):
    return Counter(r["msg"][:100] for r in recs).most_common(n)


def error_groups(recs):
    g: dict = {}
    for r in recs:
        if r["level"] >= 4:
            e = g.setdefault(signature(r["msg"]), dict(count=0, first=None, last=None, line=r["n"]))
            e["count"] += 1
            if r["ts"]:
                e["first"] = min(e["first"] or r["ts"], r["ts"]); e["last"] = max(e["last"] or r["ts"], r["ts"])
    return sorted(g.items(), key=lambda kv: -kv[1]["count"])


def timeline(recs):
    ts = [r["ts"] for r in recs if r["ts"]]
    if not ts:
        raise ValueError("no timestamps found in these lines")
    lo, hi = min(ts), max(ts)
    span = (hi - lo).total_seconds()
    step = next((s for s in (60, 300, 900, 3600, 21600, 86400, 604800) if span / s < 30), 604800)
    key = lambda t: int((t - EPOCH).total_seconds()) // step * step
    tot, err = Counter(), Counter()
    for r in recs:
        if r["ts"]:
            tot[key(r["ts"])] += 1
            err[key(r["ts"])] += r["level"] >= 4
    out, b, mx = [f"bucket = {step // 60} minute(s)   '!' = errors", ""], key(lo), max(tot.values())
    while b <= key(hi) and len(out) < 130:
        out.append(f"{_stamp(EPOCH + timedelta(seconds=b))[:16]} {tot[b]:>5} {err[b]:>4}! {bar(tot[b], mx, 30)}")
        b += step
    return out


def t_log_summary(text):
    recs, bad = parse_log(text)
    if not recs:
        raise ValueError("no lines found")
    lo, hi = _span(recs)
    fm = Counter(r["fmt"] for r in recs)
    out = [NOTE_LOG, "", f"{len(recs)} line(s): " + ", ".join(f"{k} {v}" for k, v in fm.most_common()) + (f"   ({bad} unrecognised; treated as plain text)" if bad else ""),
           f"time range: {_stamp(lo)} to {_stamp(hi)} (UTC)" if lo else "time range: no timestamps", "", "LEVELS"] + _lvl_table(recs) + ["", "TOP MESSAGES"]
    return out + [f"  {n:>5}  {m}" for m, n in top_messages(recs, 10)]


def parse_filter(spec: str) -> dict:
    spec = spec.strip()
    if spec.lower().startswith("filter:"):
        spec = spec[7:]
    f = {}
    m = re.search(r"\btext=(.*)$", spec)
    if m:
        f["text"] = m.group(1).strip().lower(); spec = spec[:m.start()]
    for tok in spec.split():
        k, _, v = tok.partition("=")
        if k in ("level>", "level"):                       # level>=WARN  is  "level>" "=WARN"
            pass
        if tok.lower().startswith("level>="):
            f["min"] = _lv(tok[7:])
        elif tok.lower().startswith("level="):
            f["eq"] = _lv(tok[6:])
        elif k in ("from", "to"):
            t = _iso(v)
            if t is None:
                raise ValueError(f"cannot read {k}= date (use 2024-03-05 or 2024-03-05T10:00)")
            f[k] = t
        else:
            raise ValueError(f"unknown filter word {tok[:20]!r}: use level>=WARN level=ERROR from= to= text=...")
    return f


def _lv(s: str) -> int:
    if s.upper() not in _LV:
        raise ValueError(f"unknown level {s[:12]!r}")
    return _LV[s.upper()]


def apply_filter(recs, f):
    out = []
    for r in recs:
        if "min" in f and r["level"] < f["min"]: continue
        if "eq" in f and r["level"] != f["eq"]: continue
        if ("from" in f or "to" in f) and not r["ts"]: continue
        if "from" in f and r["ts"] < f["from"]: continue
        if "to" in f and r["ts"] > f["to"]: continue
        if "text" in f and f["text"] not in r["raw"].lower(): continue
        out.append(r)
    return out


def t_log_filter(text):
    spec, _, body = text.partition("\n")
    f = parse_filter(spec)
    recs, _bad = parse_log(body)
    hit = apply_filter(recs, f)
    return [f"{len(hit)} of {len(recs)} line(s) match" + (" (first 200 shown)" if len(hit) > 200 else ""), ""] + \
        [f"{r['n']:>5} {_stamp(r['ts'])[5:]:<14} {LEVELS[r['level']]:<5} {r['msg'][:90]}" for r in hit[:200]]


def t_log_top(text):
    recs, _bad = parse_log(text)
    return [f"{n:>6}  {m}" for m, n in top_messages(recs, 25)] or ["no lines"]


def t_log_time(text): return timeline(parse_log(text)[0])


def t_log_errors(text):
    g = error_groups(parse_log(text)[0])
    out = ["Errors grouped by signature: numbers, ids, IPs and hex are replaced so repeats fall together.", ""]
    for sig, e in g[:30]:
        out.append(f"{e['count']:>5}x  {sig}")
        out.append(f"        first {_stamp(e['first'])}  last {_stamp(e['last'])}  first at line {e['line']}")
    return out + ([] if g else ["no ERROR/FATAL lines"])


LOG_SAMPLE = ("2024-03-05T10:00:01Z INFO server started\n2024-03-05T10:00:09Z ERROR db timeout after 30s for user 1042\n"
              "Mar  5 10:01:00 host sshd[811]: Failed password for root from 10.0.0.9\n"
              '{"time":"2024-03-05T10:02:00Z","level":"error","msg":"db timeout after 45s for user 77"}\n'
              '203.0.113.9 - - [05/Mar/2024:10:03:00 +0000] "GET /missing HTTP/1.1" 404 153 "-" "curl/8.0"')
LOG_TOOLS = [
    ("Summary (formats, levels, top messages)", t_log_summary, LOG_SAMPLE, "paste log lines"),
    ("Filter by level / time / text", t_log_filter, "level>=WARN from=2024-03-05T10:00 text=timeout\n" + LOG_SAMPLE, "line 1 = filter"),
    ("Top messages", t_log_top, LOG_SAMPLE, ""), ("Timeline", t_log_time, LOG_SAMPLE, ""),
    ("Errors grouped by signature", t_log_errors, LOG_SAMPLE, ""),
]


# ----------------------------------------------------------- debug helper ----
_FRAME = re.compile(r'^\s*File "(.*)", line (\d+)(?:, in (.*))?$')
_CHAIN = {"During handling of the above exception, another exception occurred:": "raised while handling the one above",
          "The above exception was the direct cause of the following exception:": "caused by the one above"}


def _is_lib(path: str) -> bool:
    return any(k in path for k in ("site-packages", "dist-packages", "/lib/python", "<frozen", "node_modules", "node:", "internal/"))


def parse_py(text: str) -> list:
    """Python tracebacks (also chained) -> [{type, msg, link, frames:[{file,line,func,code}]}] in the order printed (root cause first)."""
    exs, cur, link = [], None, ""
    for raw in lines_of(text):
        s = raw.rstrip()
        if s.strip() in _CHAIN:
            link = _CHAIN[s.strip()]; continue
        if s.startswith("Traceback (most recent call last):"):
            cur = dict(frames=[], type="", msg="", link=link); link = ""; exs.append(cur); continue
        m = _FRAME.match(s)
        if m:
            if cur is None or cur["type"]:
                cur = dict(frames=[], type="", msg="", link=link); link = ""; exs.append(cur)
            cur["frames"].append(dict(file=m.group(1), line=int(m.group(2)), func=m.group(3) or "", code=""))
            continue
        if cur is None or not s.strip():
            continue
        if s[0] in " \t":
            t = s.strip()
            if cur["frames"] and not cur["frames"][-1]["code"] and set(t) - set("^~ "):
                cur["frames"][-1]["code"] = t
        elif not cur["type"]:
            m = re.match(r"^([A-Za-z_][\w.]*)(?::\s?(.*))?$", s)
            if m:
                cur["type"], cur["msg"] = m.group(1), m.group(2) or ""
    return [e for e in exs if e["type"] or e["frames"]]


_JSF = re.compile(r"^\s*at (?:async )?(?:(.+?) \()?(.+?):(\d+):(\d+)\)?\s*$")
_FFF = re.compile(r"^\s*(.*?)@(.+?):(\d+):(\d+)\s*$")


def parse_js(text: str) -> dict:
    ex = dict(type="", msg="", frames=[])
    for raw in lines_of(text, 500):
        m = _JSF.match(raw) or _FFF.match(raw)
        if m:
            ex["frames"].append(dict(file=m.group(2), line=int(m.group(3)), col=int(m.group(4)), func=m.group(1) or "(anonymous)"))
            continue
        h = re.match(r"^\s*(?:Uncaught )?([A-Za-z_$][\w$]*(?:Error|Exception))\b:?\s*(.*)$", raw)
        if h and not ex["type"]:
            ex["type"], ex["msg"] = h.group(1), h.group(2)
    return ex


_HINTS = [
    (r"KeyError", "", "The dict has no such key. Check the spelling, print d.keys(), or use d.get(key, default)."),
    (r"IndexError", "", "An index is past the end of the list/string. Check len(...) first; an empty list is a common cause."),
    (r"AttributeError", r"NoneType", "Something you expected to be an object is None: a function returned nothing, or a lookup found nothing. Check what was assigned just before this line."),
    (r"AttributeError", "", "That object has no such attribute. Check the spelling and the object's real type (print(type(x)))."),
    (r"TypeError", r"not subscriptable", "You indexed something that is not a list/dict (often None or a function you forgot to call)."),
    (r"TypeError", r"NoneType", "A value is None where a real value was needed."),
    (r"TypeError", r"argument", "Wrong number or kind of arguments in a call. Compare the call with the function's definition."),
    (r"TypeError", r"unsupported operand|can only concatenate", "Mixed types in an operator, such as str + int. Convert one side (int(), str())."),
    (r"ValueError", r"invalid literal", "A string could not be turned into a number. Strip spaces and check the input."),
    (r"ValueError", "", "The right kind of value but not an acceptable one. Print the value just before this line."),
    (r"NameError", "", "A name is used before it is defined or is misspelled (or an import is missing)."),
    (r"UnboundLocalError", "", "A local variable is read before it is assigned on that path."),
    (r"(ModuleNotFound|Import)Error", "", "The module is not installed or the name is wrong. Check the spelling and that the package is available."),
    (r"ZeroDivisionError", "", "Dividing by zero: guard the divisor, or check why it is 0."),
    (r"FileNotFoundError", "", "The path does not exist from where the program runs. Check the working directory and spelling."),
    (r"PermissionError", "", "The program is not allowed to use that file or port."),
    (r"RecursionError", "", "A function keeps calling itself. Look for a missing or unreachable base case."),
    (r"UnicodeDecodeError", "", "Bytes are not in the encoding assumed. Open the file with the right encoding= or in binary mode."),
    (r"JSONDecodeError", "", "The text is not valid JSON (empty response, trailing comma or single quotes are common)."),
    (r"(Connection|Timeout)\w*Error", "", "The other side refused or did not answer. Check the address, port and that the service is up."),
    (r"MemoryError", "", "Out of memory: process in chunks or avoid building the whole thing in memory."),
    (r"AssertionError", "", "An assert failed: the condition on that line was false."),
    (r"StopIteration", "", "An iterator ran out. Check for next() on an empty iterator."),
    (r"(Syntax|Indentation|Tab)Error", "", "The code is malformed at or just before the line shown: look for a missing colon, bracket or quote, or mixed tabs and spaces."),
    (r"ReferenceError", "", "A JavaScript name is not defined in this scope (typo, missing import, or used before let/const)."),
    (r"TypeError", r"Cannot read propert", "A value is undefined or null where you read a property. Check what produced it, or use optional chaining (a?.b)."),
    (r"TypeError", r"is not a function", "The thing called is not a function: wrong name, missing import, or it is undefined."),
    (r"RangeError", "", "A value is out of its allowed range, or recursion is too deep."),
]


def hint(etype: str, msg: str) -> str:
    base = etype.rsplit(".", 1)[-1]
    for t, m, h in _HINTS:
        if re.fullmatch(t, base) and (not m or re.search(m, msg, re.I)):
            return h
    return "No stock hint. Read the message, then look at the failing line and the values it uses."


def explain_error(text: str) -> list:
    if "Traceback (most recent call last)" in text or re.search(r'^\s*File ".*", line \d+', text, re.M):
        exs = parse_py(text)
        if not exs:
            raise ValueError("no Python traceback found")
        last, out = exs[-1], ["PYTHON TRACEBACK", ""]
        out.append(f"Failed with: {last['type']}: {last['msg']}".rstrip(": "))
        fr = last["frames"]
        if fr:
            f = fr[-1]
            out.append(f"Raised at:   {f['file']}:{f['line']} in {f['func'] or '?'}")
            if f["code"]: out.append(f"Failing line: {f['code']}")
            mine = [x for x in fr if not _is_lib(x["file"])]
            if mine and mine[-1] is not f:
                g = mine[-1]
                out += [f"Last of YOUR code: {g['file']}:{g['line']} in {g['func'] or '?'}"] + ([f"  {g['code']}"] if g["code"] else [])
        out += ["", "HINT: " + hint(last["type"], last["msg"])]
        if len(exs) > 1:
            out += ["", f"CHAIN ({len(exs)} exceptions, root cause first):"]
            for i, e in enumerate(exs, 1):
                out.append(f"  {i}. {e['type']}: {e['msg']}" + (f"   [{e['link']}]" if e["link"] else ""))
            out.append(f"Root cause: {exs[0]['type']} - " + hint(exs[0]["type"], exs[0]["msg"]))
        out += ["", "FRAMES (oldest call first)"]
        for f in fr[:60]:
            out.append(f"  {'lib ' if _is_lib(f['file']) else 'code'} {f['file']}:{f['line']} {f['func']}" + (f"  | {f['code']}" if f["code"] else ""))
        return out
    ex = parse_js(text)
    if not ex["frames"] and not ex["type"]:
        raise ValueError("no Python traceback or JavaScript stack found")
    out = ["JAVASCRIPT STACK", "", f"Failed with: {ex['type']}: {ex['msg']}".rstrip(": ")]
    if ex["frames"]:
        f = ex["frames"][0]
        out.append(f"Thrown at:   {f['file']}:{f['line']}:{f['col']} in {f['func']}")
        mine = [x for x in ex["frames"] if not _is_lib(x["file"])]
        if mine and mine[0] is not f:
            out.append(f"First of YOUR code: {mine[0]['file']}:{mine[0]['line']}:{mine[0]['col']} in {mine[0]['func']}")
    out += ["", "HINT: " + hint(ex["type"], ex["msg"]), "", "FRAMES (newest call first)"]
    return out + [f"  {'lib ' if _is_lib(f['file']) else 'code'} {f['file']}:{f['line']}:{f['col']} {f['func']}" for f in ex["frames"][:60]]


_PROW = re.compile(r"^\s*(\d+(?:/\d+)?)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(.+?)\s*$")
_PHEAD = re.compile(r"(\d+) function calls(?: \((\d+) primitive calls\))? in ([\d.]+) seconds")


def parse_pstats(text: str) -> dict:
    rows = []
    for l in lines_of(text, 3000):
        m = _PROW.match(l)
        if m:
            rows.append(dict(calls=m.group(1), tot=float(m.group(2)), cum=float(m.group(4)), fn=m.group(6)))
    if not rows:
        raise ValueError("no pstats rows found; paste the output of pstats.Stats(...).print_stats()")
    h = _PHEAD.search(text)
    return dict(rows=rows, total=float(h.group(3)) if h else sum(r["tot"] for r in rows), calls=int(h.group(1)) if h else None)


def profile_summary(text: str) -> list:
    p = parse_pstats(text)
    tot = p["total"] or 1.0
    by_tot = sorted(p["rows"], key=lambda r: -r["tot"])[:12]
    by_cum = sorted(p["rows"], key=lambda r: -r["cum"])[:6]
    out = [f"{len(p['rows'])} functions, total {p['total']:.3f}s" + (f", {p['calls']} calls" if p["calls"] else ""), "", "HOT SPOTS by own time (tottime)"]
    out += table([[r["calls"], f"{r['tot']:.3f}", f"{100 * r['tot'] / tot:.1f}%", f"{r['cum']:.3f}", r["fn"]] for r in by_tot],
                 ["calls", "own s", "own %", "cum s", "function"])
    out += ["", "TOP by cumulative time (includes callees)"]
    out += table([[r["calls"], f"{r['cum']:.3f}", f"{100 * r['cum'] / tot:.1f}%", r["fn"]] for r in by_cum], ["calls", "cum s", "cum %", "function"])
    return out


DEBUG_TOOLS = [
    ("Explain an error (Python traceback / JavaScript stack)", explain_error,
     'Traceback (most recent call last):\n  File "app.py", line 9, in <module>\n    run()\n  File "app.py", line 5, in run\n    return d["x"]\nKeyError: \'x\'',
     "paste the traceback"),
    ("Profile summary (cProfile / pstats text)", profile_summary,
     "         1200 function calls in 2.500 seconds\n\n   ncalls  tottime  percall  cumtime  percall filename:lineno(function)\n"
     "        1    0.010    0.010    2.500    2.500 main.py:1(<module>)\n      100    1.500    0.015    2.000    0.020 work.py:10(crunch)",
     "paste print_stats() output"),
]


# --------------------------------------------------------- cron / planner ----
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_DOWS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
_MACROS = {"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
           "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}
_SPEC = [("minute", 0, 59, 59, None), ("hour", 0, 23, 23, None), ("day-of-month", 1, 31, 31, None),
         ("month", 1, 12, 12, {m.lower(): i + 1 for i, m in enumerate(_MONTHS)}), ("day-of-week", 0, 7, 6, {d.lower(): i for i, d in enumerate(_DOWS)})]


def _field(txt: str, name: str, lo: int, hi: int, star_hi: int, names) -> list:
    if not txt or len(txt) > 80:
        raise ValueError(f"empty or too long {name} field")

    def val(x: str) -> int:
        v = names[x.lower()] if names and x.lower() in names else int(x) if x.isdigit() else None
        if v is None or not lo <= v <= hi:
            raise ValueError(f"{name}: {x!r} is not {lo}-{hi}" + (" or a name" if names else ""))
        return v
    out = set()
    for part in txt.split(","):
        rng, slash, step = part.partition("/")
        if slash and not (step.isdigit() and int(step) > 0):
            raise ValueError(f"{name}: bad step in {part!r}")
        st = int(step) if slash else 1
        if rng == "*":
            a, b = lo, star_hi
        elif "-" in rng:
            x, y = rng.split("-", 1)
            a, b = val(x), val(y)
            if a > b:
                raise ValueError(f"{name}: range {rng!r} runs backwards")
        else:
            a = val(rng)
            b = star_hi if slash else a
        out.update(range(a, b + 1, st))
    return sorted({v % 7 if name == "day-of-week" else v for v in out})


def parse_cron(expr: str) -> dict:
    """5 fields (lists, ranges, steps, names) or @daily-style -> dict with the allowed values and the original text."""
    e = " ".join(expr.split())
    e = _MACROS.get(e.lower(), e)
    if e.startswith("@"):
        raise ValueError(f"{e.split()[0]} is not supported (use @yearly @monthly @weekly @daily @hourly or 5 fields)")
    f = e.split(" ")
    if len(f) != 5:
        raise ValueError("a cron schedule has 5 fields: minute hour day-of-month month day-of-week")
    v = [_field(t, *s) for t, s in zip(f, _SPEC)]
    return dict(f=f, minute=v[0], hour=v[1], dom=v[2], month=v[3], dow=v[4], dom_star=f[2].startswith("*"), dow_star=f[4].startswith("*"))


def _day_ok(j: dict, day) -> bool:
    d_ok, w_ok = day.day in j["dom"], (day.weekday() + 1) % 7 in j["dow"]
    # Vixie cron: if either day field starts with '*', both must match; if both are restricted, EITHER may match.
    return (d_ok and w_ok) if (j["dom_star"] or j["dow_star"]) else (d_ok or w_ok)


def next_runs(j: dict, after: datetime, n: int, until: datetime | None = None) -> list:
    """The next `n` run times strictly after `after` (naive UTC). Looks at most ~9 years ahead (enough for 29 Feb)."""
    out, d0 = [], after.date()
    for i in range(3300):
        try:
            day = d0 + timedelta(days=i)
        except OverflowError:
            break
        if until and day > until.date():
            break
        if day.month in j["month"] and _day_ok(j, day):
            for h in j["hour"]:
                for m in j["minute"]:
                    t = datetime(day.year, day.month, day.day, h, m)
                    if t > after and (not until or t < until):
                        out.append(t)
                        if len(out) >= n:
                            return out
    return out


def explain_cron(j: dict) -> str:
    f, mins, hrs = j["f"], j["minute"], j["hour"]
    if f[0] == "*" and f[1] == "*": t = "every minute"
    elif f[0].startswith("*/") and f[1] == "*": t = f"every {f[0][2:]} minutes"
    elif f[1] == "*": t = f"at minute {', '.join(map(str, mins))} of every hour"
    elif len(mins) * len(hrs) <= 8: t = "at " + ", ".join(f"{h:02d}:{m:02d}" for h in hrs for m in mins)
    elif f[0] == "*": t = f"every minute during hour(s) {', '.join(map(str, hrs))}"
    else: t = f"at minute {', '.join(map(str, mins))} past hour(s) {', '.join(map(str, hrs))}"
    dom = "on day " + ", ".join(map(str, j["dom"])) + " of the month"
    dow = "on " + ", ".join(_DOWS[d] for d in j["dow"])
    if f[2] == "*" and f[4] == "*": day = "every day"
    elif f[4] == "*": day = dom
    elif f[2] == "*": day = dow
    elif j["dom_star"] or j["dow_star"]: day = dom + " and " + dow
    else: day = dom + " or " + dow
    mo = "" if f[3] == "*" else " in " + ", ".join(_MONTHS[m - 1] for m in j["month"])
    return f"{t} {day}{mo}"


_DUR = re.compile(r"~\s*(\d+)\s*([smh])\b")


def parse_jobs(text: str) -> tuple:
    """-> (options, jobs). Optional lines `start: 2026-01-05` and `count: 5`; job lines: `<schedule> <name> [~10m]`."""
    opts, jobs = {}, []
    for n, l in enumerate(lines_of(text, 400), 1):
        s = l.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(start|count):\s*(.+)$", s, re.I)
        if m:
            opts[m.group(1).lower()] = m.group(2).strip(); continue
        parts = s.split()
        k = 1 if parts[0].startswith("@") else 5
        d = _DUR.search(s)
        dur = int(d.group(1)) * {"s": 1, "m": 60, "h": 3600}[d.group(2)] if d else 60
        name = _DUR.sub("", " ".join(parts[k:])).strip() or f"job{len(jobs) + 1}"
        if len(jobs) >= 30:
            raise ValueError("at most 30 jobs")
        try:
            j = parse_cron(" ".join(parts[:k]))
        except ValueError as e:
            raise ValueError(f"line {n}: {e}")
        j.update(name=name[:60], dur=min(max(dur, 1), 7200), line=n)
        jobs.append(j)
    return opts, jobs


def _start(opts) -> datetime:
    if "start" in opts:
        t = _iso(opts["start"])
        if t is None:
            raise ValueError("start: must look like 2026-01-05 or 2026-01-05T08:30")
        return t
    g = time.gmtime()
    return datetime(g.tm_year, g.tm_mon, g.tm_mday)


def _f(t): return f"{t.strftime('%Y-%m-%d %H:%M')} {_DOWS[(t.weekday() + 1) % 7]}"


def t_cron_explain(text):
    opts, jobs = parse_jobs(text)
    if not jobs:
        raise ValueError("one job per line: minute hour day month weekday name   (or @daily name)")
    n, start, out = max(1, min(int(opts.get("count", "5")) if opts.get("count", "5").isdigit() else 5, 20)), _start(opts), []
    out.append("This PLANS schedules only: KOS has no background services, so nothing here ever runs.")
    for j in jobs:
        runs = next_runs(j, start - timedelta(minutes=1), n)
        out += ["", f"{j['name']}:  {' '.join(j['f'])}", f"  {explain_cron(j)}", f"  next {len(runs)} from {_f(start)}:"]
        out += [f"    {_f(t)}" for t in runs] or ["    never within 9 years"]
    return out


def _day_runs(jobs, start):
    end = start + timedelta(days=1)
    return {id(j): next_runs(j, start - timedelta(minutes=1), 1500, end) for j in jobs}, end


def find_overlaps(jobs, start) -> list:
    """(job a, job b, count, first time) for every pair whose runs [t, t+duration) overlap during the 24 hours from `start`;
    a == b means a job still running when its next run begins."""
    runs, _ = _day_runs(jobs, start)
    out = []
    for i, a in enumerate(jobs):
        A = runs[id(a)]
        if any(A[k + 1] < A[k] + timedelta(seconds=a["dur"]) for k in range(len(A) - 1)):
            cnt = sum(A[k + 1] < A[k] + timedelta(seconds=a["dur"]) for k in range(len(A) - 1))
            first = next(A[k + 1] for k in range(len(A) - 1) if A[k + 1] < A[k] + timedelta(seconds=a["dur"]))
            out.append((a["name"], a["name"], cnt, first))
        for b in jobs[i + 1:]:
            B, cnt, first = runs[id(b)], 0, None
            for t in A:
                lo = bisect_right(B, t - timedelta(seconds=b["dur"]))
                hi = bisect_left(B, t + timedelta(seconds=a["dur"]))
                if hi > lo:
                    cnt += hi - lo
                    first = first or max(t, B[lo])
            if cnt:
                out.append((a["name"], b["name"], cnt, first))
    return out


def t_cron_conflicts(text):
    opts, jobs = parse_jobs(text)
    if len(jobs) < 1:
        raise ValueError("no jobs; add ~10m after a name to give its duration (default 1m)")
    start = _start(opts)
    ov = find_overlaps(jobs, start)
    out = [f"Checked the 24 hours from {_f(start)} (runs counted up to 1500 per job).", ""]
    for a, b, n, t in ov[:60]:
        out.append(f"{a} still running at its own next start: {n} time(s), first {_f(t)}" if a == b else f"{a} overlaps {b}: {n} time(s), first {_f(t)}")
    return out + ([] if ov else ["no overlaps"])


def t_cron_day(text):
    opts, jobs = parse_jobs(text)
    if not jobs:
        raise ValueError("no jobs")
    start = _start(opts)
    runs, _ = _day_runs(jobs, start)
    per = [Counter() for _ in range(24)]
    for j in jobs:
        for t in runs[id(j)]:
            per[t.hour][j["name"]] += 1
    mx = max([sum(c.values()) for c in per] + [1])
    out = [f"Runs per hour, {start.strftime('%Y-%m-%d')} {_DOWS[(start.weekday() + 1) % 7]} (UTC)", ""]
    for h, c in enumerate(per):
        names = ", ".join(sorted(c)[:3]) + ("..." if len(c) > 3 else "")
        out.append(f"{h:02d} {sum(c.values()):>5} {bar(sum(c.values()), mx, 24):<24} {names}")
    return out


def t_cron_export(text):
    opts, jobs = parse_jobs(text)
    return ["# Planned with KOS Scheduled Task Planner. KOS does not run these: install them yourself with your own cron."] + \
        [f"{' '.join(j['f'])} {j['name']}" for j in jobs]


CRON_SAMPLE = "start: 2026-11-09\ncount: 5\n30 9 * * 1-5 report ~20m\n*/15 9-10 * * * sync ~10m\n@daily backup ~2h\n0 12 13 * 5 monthly-check"
CRON_TOOLS = [("Explain and next run times", t_cron_explain, CRON_SAMPLE, "one job per line"),
              ("Overlaps and conflicts (24 hours)", t_cron_conflicts, CRON_SAMPLE, "~10m = duration"),
              ("Day timeline", t_cron_day, CRON_SAMPLE, ""), ("Export crontab text", t_cron_export, CRON_SAMPLE, "")]


# -------------------------------------------------------- website analytics ----
_BOT = re.compile(r"bot|crawl|spider|slurp|bing|google|yandex|baidu|duckduck|curl|wget|python-requests|httpclient|monitor|headless|scrapy|facebookexternalhit", re.I)
_ASSET = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp[34]|webm)$", re.I)


def web_stats(text: str) -> dict:
    recs = [r for r in parse_log(text)[0] if r["fmt"] == "access"]
    if not recs:
        raise ValueError("no access-log lines found (common or combined log format)")
    s = dict(hits=len(recs), visitors=len({(r["ip"], r["ua"]) for r in recs}),
             human_visitors=len({(r["ip"], r["ua"]) for r in recs if not _BOT.search(r["ua"])}),
             bots=sum(1 for r in recs if _BOT.search(r["ua"])), bytes=sum(r["bytes"] for r in recs))
    page = lambda r: r["path"].split("?")[0].split("#")[0]
    s["pages"] = Counter(page(r) for r in recs if r["status"] < 400 and r["method"] == "GET" and not _ASSET.search(page(r)))
    s["assets"] = sum(1 for r in recs if _ASSET.search(page(r)))
    refs = Counter()
    for r in recs:
        m = re.match(r"^[a-z]+://([^/:?#]+)", r["ref"], re.I)
        refs[m.group(1).lower() if m else "(direct / none)"] += 1
    s["refs"] = refs
    s["status"] = Counter(r["status"] for r in recs)
    s["classes"] = Counter(f"{r['status'] // 100}xx" for r in recs)
    s["notfound"] = Counter(page(r) for r in recs if r["status"] == 404)
    s["agents"] = Counter(r["ua"][:60] or "(none: common log format)" for r in recs)
    s["days"], s["day_bytes"], s["path_bytes"] = Counter(), Counter(), Counter()
    for r in recs:
        if r["ts"]:
            s["days"][r["ts"].strftime("%Y-%m-%d")] += 1
            s["day_bytes"][r["ts"].strftime("%Y-%m-%d")] += r["bytes"]
        s["path_bytes"][page(r)] += r["bytes"]
    return s


def _pct(a, b): return f"{100 * a / b:.1f}%" if b else "0%"
def _mb(n): return f"{n / 1048576:.2f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB"


def t_web_summary(text):
    s = web_stats(text)
    return ["From the pasted log only: no tracking script, no live data.", "",
            f"hits {s['hits']}   unique visitors (IP+user-agent) {s['visitors']}   of which not-bot {s['human_visitors']}",
            f"bot hits {s['bots']} ({_pct(s['bots'], s['hits'])})   static asset hits {s['assets']}   bandwidth {_mb(s['bytes'])}", "",
            "TOP PAGES (GET, status < 400, assets excluded)"] + [f"  {n:>6}  {p}" for p, n in s["pages"].most_common(10)]


def t_web_refs(text):
    s = web_stats(text)
    return [f"{n:>6}  {h}" for h, n in s["refs"].most_common(20)]


def t_web_status(text):
    s = web_stats(text)
    out = ["STATUS CLASSES"] + [f"  {k}  {n:>6}  {_pct(n, s['hits'])}" for k, n in sorted(s["classes"].items())]
    out += ["", "STATUS CODES"] + [f"  {k}  {n:>6}" for k, n in sorted(s["status"].items())] + ["", "404 NOT FOUND (path, hits)"]
    return out + [f"  {n:>6}  {p}" for p, n in s["notfound"].most_common(25)] + ([] if s["notfound"] else ["  none"])


def t_web_bots(text):
    s = web_stats(text)
    out = [f"bot hits {s['bots']} of {s['hits']} ({_pct(s['bots'], s['hits'])}); visitors {s['visitors']}, not-bot {s['human_visitors']}",
           "Bots are guessed from words in the user-agent (bot, crawler, curl, ...); a faked user-agent is not detected.", "", "TOP USER-AGENTS"]
    return out + [f"  {n:>6}  {'BOT ' if _BOT.search(a) else '    '}{a}" for a, n in s["agents"].most_common(15)]


def t_web_time(text):
    s = web_stats(text)
    mx = max(s["days"].values(), default=1)
    out = [f"{'day':<11}{'hits':>6} {'bandwidth':>10}", ""] + [f"{d:<11}{n:>6} {_mb(s['day_bytes'][d]):>10} {bar(n, mx, 30)}" for d, n in sorted(s["days"].items())[:120]]
    return out + ["", f"total bandwidth {_mb(s['bytes'])}", "TOP PATHS BY BYTES"] + [f"  {_mb(b):>10}  {p}" for p, b in s["path_bytes"].most_common(8)]


WEB_SAMPLE = ('203.0.113.9 - - [05/Mar/2024:10:03:00 +0000] "GET /index.html HTTP/1.1" 200 1500 "https://example.org/x" "Mozilla/5.0"\n'
              '198.51.100.2 - - [05/Mar/2024:11:00:00 +0000] "GET /missing HTTP/1.1" 404 153 "-" "Googlebot/2.1"\n'
              '203.0.113.9 - - [06/Mar/2024:09:00:00 +0000] "GET /about?x=1 HTTP/1.1" 200 800 "-" "Mozilla/5.0"')
WEB_TOOLS = [("Summary (hits, visitors, top pages)", t_web_summary, WEB_SAMPLE, "paste access-log lines"),
             ("Referrers", t_web_refs, WEB_SAMPLE, ""), ("Status mix and 404 list", t_web_status, WEB_SAMPLE, ""),
             ("Bot share and user-agents", t_web_bots, WEB_SAMPLE, ""), ("Per-day timeline and bandwidth", t_web_time, WEB_SAMPLE, "")]


# ----------------------------------------------------------------- entries ----
ENTRIES: list = [
    app("Developer Utilities", _suite("Developer Utilities", "devutil", DEV_TOOLS,
        ["Type or paste text, press Ctrl-R to run, Ctrl-S to keep it in the vault."]), "full",
        "Regex (conservative guard: nested repeats refused), base64/hex/URL, hashes, UUID4, timestamps, JSON, diff, bases, JWT decode (never verifies), line tools. Text only."),
    app("Log Viewer", _suite("Log Viewer", "logview", LOG_TOOLS, [NOTE_LOG]), "partial",
        "Parses syslog, ISO-timestamp, JSON-lines and access-log text you paste; it cannot read /var/log, the console or crash reports by itself."),
    app("Debug Helper", _suite("Debug Helper", "debughelp", DEBUG_TOOLS, ["Reads pasted text. It does not run or profile your code."]), "partial",
        "Explains pasted Python tracebacks and JavaScript stacks and summarises pasted pstats text; it does not run code, attach a debugger or profile anything."),
    app("Scheduled Task Planner", _suite("Scheduled Task Planner", "cronplan", CRON_TOOLS,
        ["Plans cron schedules. KOS has no background services: nothing here runs."]), "partial",
        "Parses and explains cron, lists next runs, finds overlaps and exports crontab text; KOS has no scheduler, so nothing is ever run for you."),
    app("Website Analytics", _suite("Website Analytics", "webstats", WEB_TOOLS, ["Reports from access-log lines you paste. No tracking, no live data."]), "partial",
        "Statistics from pasted access-log lines only; there is no tracking script, live feed or log collection."),
]
