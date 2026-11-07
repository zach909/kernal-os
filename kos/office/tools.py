"""Text and data tools. Pure functions (text in, lines out) so they are easy
to test and to compose into the 'workbench' apps. Nothing here needs a model:
these are deterministic algorithms, and they say what they are."""

from __future__ import annotations

import csv
import io
import json
import math
import re
import statistics
from collections import Counter, defaultdict

from .search import STOP, tokens
from .sheet import Sheet, SheetError, col_name, to_str
from .ui import bar, table


# -------------------------------------------------------------- tables ----
def parse_table(text: str) -> tuple[list, list]:
    """CSV / TSV / semicolon / JSON array / JSON lines -> (columns, rows of dict)."""
    t = text.strip()
    if not t:
        return [], []
    if t[0] in "[{":
        try:
            data = json.loads(t)
            data = data if isinstance(data, list) else [data]
        except ValueError:
            data = [json.loads(l) for l in t.split("\n") if l.strip()]
        cols: list = []
        for d in data:
            for k in d:
                if k not in cols: cols.append(k)
        return cols, [{k: ("" if d.get(k) is None else d.get(k)) for k in cols} for d in data]
    first = t.split("\n", 1)[0]
    delim = max(",\t;|", key=first.count)
    rows = list(csv.reader(io.StringIO(t), delimiter=delim))
    cols = [c.strip() or f"col{i + 1}" for i, c in enumerate(rows[0])]
    return cols, [dict(zip(cols, r + [""] * (len(cols) - len(r)))) for r in rows[1:]]


def to_csv(cols: list, rows: list) -> str:
    out = io.StringIO(); w = csv.writer(out, lineterminator="\n"); w.writerow(cols)
    for r in rows: w.writerow([r.get(c, "") for c in cols])
    return out.getvalue()


def num(v):
    try: return float(str(v).replace(",", "").strip())
    except ValueError: return None


def infer_types(cols, rows) -> dict:
    out = {}
    for c in cols:
        vals = [r.get(c, "") for r in rows if str(r.get(c, "")).strip() != ""]
        if not vals: out[c] = "empty"
        elif all(num(v) is not None for v in vals): out[c] = "integer" if all(float(num(v)).is_integer() for v in vals) else "number"
        elif all(re.match(r"^\d{4}-\d{2}-\d{2}", str(v)) for v in vals): out[c] = "date"
        elif all(str(v).lower() in ("true", "false", "yes", "no") for v in vals): out[c] = "boolean"
        else: out[c] = "text"
    return out


def _row_eval(expr: str, row: dict):
    s = Sheet(); s.names = {k: (num(v) if num(v) is not None else v) for k, v in row.items()}
    s.cells["A1"] = "=" + expr
    v = s.value("A1")
    if isinstance(v, SheetError): raise v
    return v


def transform(cols: list, rows: list, script: str) -> tuple[list, list, list]:
    """Pipeline DSL, one step per line or separated by '|':
    filter EXPR | select a,b | sort col [desc] | limit N | dedupe [col] | rename a=b
    addcol name = EXPR | group col [sum:other|avg:other|count] | template "text {col}"
    Expressions use the spreadsheet formula language with column names as variables.
    -> (cols, rows, log)"""
    log = []
    rows = [dict(r) for r in rows]
    steps = [s.strip() for line in script.split("\n") for s in re.split(r"\s\|\s", line) if s.strip() and not s.strip().startswith("#")]
    for st in steps:
        op, _, arg = st.partition(" ")
        op, arg = op.lower(), arg.strip()
        try:
            if op == "filter":
                before = len(rows); rows = [r for r in rows if _truthy(_row_eval(arg, r))]; log.append(f"filter: {before} -> {len(rows)}")
            elif op == "select":
                keep = [c.strip() for c in arg.split(",")]
                missing = [c for c in keep if c not in cols]
                if missing: raise ValueError("no column " + ", ".join(missing))
                cols = keep; log.append("select " + ",".join(keep))
            elif op == "sort":
                p = arg.split(); c = p[0]
                if c not in cols: raise ValueError("no column " + c)
                rows.sort(key=lambda r: (0, num(r[c])) if num(r[c]) is not None else (1, str(r[c]).lower()), reverse=len(p) > 1 and p[1].lower().startswith("d"))
                log.append(f"sort {arg}")
            elif op == "limit": rows = rows[:int(arg)]; log.append(f"limit {arg}")
            elif op == "dedupe":
                seen, out = set(), []
                for r in rows:
                    k = tuple(r.get(c) for c in ([arg] if arg else cols))
                    if k not in seen: seen.add(k); out.append(r)
                log.append(f"dedupe: {len(rows)} -> {len(out)}"); rows = out
            elif op == "rename":
                a, b = [x.strip() for x in arg.split("=", 1)]
                cols = [b if c == a else c for c in cols]
                for r in rows: r[b] = r.pop(a, "")
                log.append(f"rename {a}->{b}")
            elif op == "addcol":
                name, expr = [x.strip() for x in arg.split("=", 1)]
                for r in rows:
                    try: r[name] = to_str(_row_eval(expr, r))
                    except SheetError as e: r[name] = e.code
                if name not in cols: cols = cols + [name]
                log.append(f"addcol {name}")
            elif op == "group":
                p = arg.split(); key = p[0]; agg = p[1] if len(p) > 1 else "count"
                g: dict = defaultdict(list)
                for r in rows: g[r.get(key, "")].append(r)
                kind, _, tgt = agg.partition(":")
                out = []
                for k, rs in g.items():
                    row = {key: k, "count": len(rs)}
                    if tgt:
                        vals = [num(r.get(tgt)) for r in rs if num(r.get(tgt)) is not None]
                        row[f"{kind}_{tgt}"] = to_str({"sum": sum(vals), "avg": (sum(vals) / len(vals)) if vals else 0,
                                                       "min": min(vals, default=0), "max": max(vals, default=0)}[kind])
                    out.append(row)
                cols = [key, "count"] + ([f"{kind}_{tgt}"] if tgt else []); rows = out; log.append(f"group by {key}")
            elif op == "template":
                tpl = arg.strip('"')
                rows = [{"text": re.sub(r"\{(\w+)\}", lambda m: str(r.get(m.group(1), m.group(0))), tpl)} for r in rows]
                cols = ["text"]; log.append("template")
            else:
                log.append(f"? unknown step '{op}'")
        except (ValueError, KeyError, IndexError, SheetError) as e:
            log.append(f"! {op}: {e}"); break
    return cols, rows, log


def _truthy(v) -> bool:
    return bool(v) if not isinstance(v, str) else v.upper() == "TRUE"


def analyze(cols: list, rows: list) -> list:
    types = infer_types(cols, rows)
    out = [f"{len(rows)} rows x {len(cols)} columns", ""]
    numeric = []
    for c in cols:
        vals = [r.get(c, "") for r in rows]
        filled = [v for v in vals if str(v).strip() != ""]
        line = f"{c} [{types[c]}]  filled {len(filled)}/{len(vals)}  unique {len(set(map(str, filled)))}"
        if types[c] in ("integer", "number") and filled:
            ns = sorted(num(v) for v in filled); numeric.append((c, [num(v) for v in vals]))
            q1, q3 = _q(ns, .25), _q(ns, .75); iqr = q3 - q1
            outl = [x for x in ns if x < q1 - 1.5 * iqr or x > q3 + 1.5 * iqr]
            line += (f"\n    min {ns[0]:g}  q1 {q1:g}  median {statistics.median(ns):g}  q3 {q3:g}  max {ns[-1]:g}"
                     f"\n    mean {statistics.fmean(ns):.4g}  stdev {(statistics.stdev(ns) if len(ns) > 1 else 0):.4g}  outliers {len(outl)}")
        elif filled:
            top = Counter(map(str, filled)).most_common(3)
            line += "\n    top: " + ", ".join(f"{k} ({n})" for k, n in top)
        out.append(line)
    if len(numeric) > 1:
        out += ["", "Correlations (|r| >= 0.5):"]
        found = False
        for i in range(len(numeric)):
            for j in range(i + 1, len(numeric)):
                pairs = [(a, b) for a, b in zip(numeric[i][1], numeric[j][1]) if a is not None and b is not None]
                r = pearson(pairs)
                if r is not None and abs(r) >= 0.5:
                    out.append(f"  {numeric[i][0]} ~ {numeric[j][0]}: {r:+.2f}"); found = True
        if not found: out.append("  none")
    return out


def _q(sorted_vals, p):
    k = (len(sorted_vals) - 1) * p; f = math.floor(k); c = math.ceil(k)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def pearson(pairs):
    if len(pairs) < 3: return None
    xs, ys = zip(*pairs); mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs)); sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return None if sx == 0 or sy == 0 else sum((x - mx) * (y - my) for x, y in pairs) / (sx * sy)


def chart(cols: list, rows: list, spec: str) -> list:
    """spec: 'COL' (histogram/frequency) or 'LABELCOL VALUECOL' (bars) or 'line VALUECOL'."""
    p = spec.split()
    if not p: return ["usage: COL | LABELCOL VALUECOL | line VALUECOL"]
    if p[0] == "line" and len(p) > 1 and p[1] in cols:
        vs = [num(r[p[1]]) for r in rows if num(r[p[1]]) is not None]
        if not vs: return ["no numbers"]
        lo, hi = min(vs), max(vs); ticks = "▁▂▃▄▅▆▇█"
        spark = "".join(ticks[0 if hi == lo else int((v - lo) / (hi - lo) * 7)] for v in vs[:78])
        return [p[1], spark, f"min {lo:g}  max {hi:g}  n {len(vs)}"]
    if len(p) == 2 and p[0] in cols and p[1] in cols:
        agg: dict = defaultdict(float)
        for r in rows:
            v = num(r[p[1]])
            if v is not None: agg[str(r[p[0]])] += v
        mx = max(agg.values(), default=0)
        return [f"{k[:18]:<18} {bar(v, mx, 36)} {v:g}" for k, v in sorted(agg.items(), key=lambda kv: -kv[1])[:30]] or ["no data"]
    if p[0] in cols:
        vals = [num(r[p[0]]) for r in rows]
        if rows and all(v is not None for v in vals if v is not None) and any(v is not None for v in vals):
            ns = [v for v in vals if v is not None]; lo, hi = min(ns), max(ns); k = 10; w = (hi - lo) / k or 1
            bins = Counter(min(k - 1, int((v - lo) / w)) for v in ns); mx = max(bins.values())
            return [f"{lo + i * w:>10.4g} {bar(bins.get(i, 0), mx, 36)} {bins.get(i, 0)}" for i in range(k)]
        c = Counter(str(r[p[0]]) for r in rows); mx = max(c.values(), default=1)
        return [f"{k[:18]:<18} {bar(v, mx, 36)} {v}" for k, v in c.most_common(30)]
    return ["unknown column; columns: " + ", ".join(cols)]


# ----------------------------------------------------------- text tools ----
def sentences(text: str) -> list: return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n{2,}", text) if s.strip()]


def summarize(text: str, n: int = 3) -> list:
    """Extractive: score sentences by the frequency of their content words."""
    ss = sentences(text)
    if len(ss) <= n: return ss
    freq = Counter(tokens(text)); top = max(freq.values(), default=1)
    scored = []
    for i, s in enumerate(ss):
        ts = tokens(s)
        if not ts: continue
        sc = sum(freq[t] / top for t in ts) / (len(ts) ** 0.6) + (0.3 if i == 0 else 0)
        scored.append((sc, i))
    keep = sorted(i for _s, i in sorted(scored, reverse=True)[:n])
    return [ss[i] for i in keep]


def keywords(text: str, n: int = 10) -> list:
    ts = tokens(text); c = Counter(ts); bi = Counter(f"{a} {b}" for a, b in zip(ts, ts[1:]))
    out = [(k, v * 1.5) for k, v in bi.items() if v > 1] + list(c.items())
    return [k for k, _v in sorted(out, key=lambda kv: -kv[1])[:n]]


_PATTERNS = [
    ("email", r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), ("url", r"https?://[^\s<>\"')]+"),
    ("phone", r"(?<!\d)(?:\+?\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"),
    ("date", r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b"),
    ("money", r"[$€£]\s?\d[\d,]*(?:\.\d{1,2})?"), ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("hashtag", r"(?<!\w)#[A-Za-z]\w+"), ("mention", r"(?<!\w)@[A-Za-z]\w+")]


def extract(text: str) -> list:
    out = []
    for name, rx in _PATTERNS:
        found = sorted(set(m.group(0).strip() for m in re.finditer(rx, text)))
        if found: out.append(f"{name} ({len(found)}): " + "; ".join(found[:15]))
    return out or ["nothing recognised"]


def luhn(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return len(d) >= 13 and (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", s): return False
    n = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(n) % 97 == 1


def dlp(text: str) -> tuple[list, str]:
    """-> (findings, redacted text). Validates (Luhn, IBAN) to cut false positives."""
    finds, red = [], text
    def sub(kind, rx, check=None, mask="█"):
        nonlocal red
        def f(m):
            raw = m.group(0)
            if check and not check(re.sub(r"[ -]", "", raw)): return raw
            finds.append((kind, raw[:4] + "…")); return f"[{kind.upper()} REDACTED]"
        red = re.sub(rx, f, red)
    sub("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
    sub("aws-key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"); sub("github-token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
    sub("api-key", r"\bsk-[A-Za-z0-9_-]{20,}\b"); sub("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")
    sub("card", r"\b\d(?:[ -]?\d){12,18}\b", check=luhn)
    sub("iban", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", check=iban_ok)
    sub("ssn", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    sub("password", r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*\S+")
    return [f"{k}: {v}" for k, v in finds], red


def threats(log: str) -> list:
    lines = log.split("\n"); out = []
    fails = Counter(m.group(1) for l in lines if (m := re.search(r"(?i)failed (?:password|login|auth)\w*.*?(\d+\.\d+\.\d+\.\d+)", l)))
    for ip, n in fails.items():
        if n >= 5: out.append(("HIGH", f"brute force: {n} failed logins from {ip}"))
    ports: dict = defaultdict(set)
    for l in lines:
        m = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+).*?DPT=(\d+)", l) or re.search(r"(\d+\.\d+\.\d+\.\d+).*?(?:port|dpt)[= ](\d+)", l, re.I)
        if m: ports[m.group(1)].add(m.group(2))
    for ip, ps in ports.items():
        if len(ps) >= 10: out.append(("HIGH", f"port scan: {ip} touched {len(ps)} ports"))
    web = [(r"(?i)(union\s+select|or\s+1=1|'--|sleep\(\d+\))", "SQL injection attempt"), (r"(?i)<script|javascript:|onerror=", "XSS attempt"),
           (r"\.\./\.\./|%2e%2e%2f", "path traversal"), (r"(?i)(;|\|)\s*(cat|wget|curl|nc|bash)\s", "command injection"),
           (r"(?i)sqlmap|nikto|nmap|masscan", "scanner user-agent")]
    for rx, label in web:
        hits = [i + 1 for i, l in enumerate(lines) if re.search(rx, l)]
        if hits: out.append(("MEDIUM" if label == "scanner user-agent" else "HIGH", f"{label}: {len(hits)} line(s), first at line {hits[0]}"))
    su = [i + 1 for i, l in enumerate(lines) if re.search(r"(?i)sudo:.*COMMAND=|session opened for user root", l)]
    if su: out.append(("LOW", f"privileged commands: {len(su)} line(s), first at line {su[0]}"))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return [f"[{s}] {m}" for s, m in sorted(out, key=lambda x: order[x[0]])] or ["no rule matched"]


def meeting(text: str) -> list:
    acts, decs, qs = [], [], []
    for raw in text.split("\n"):
        l = raw.strip(" -*\t")
        if not l: continue
        if re.search(r"(?i)\b(action|todo|to-do|follow[- ]up)\b\s*[:\-]?", l) or re.search(r"(?i)\b\w+ (?:will|to|needs to|should)\b.{4,}", l) and re.match(r"^[@A-Z]", l):
            acts.append(l)
        elif re.search(r"(?i)\b(decided|decision|agreed|approved|we will)\b", l): decs.append(l)
        elif l.endswith("?"): qs.append(l)
    return (["ACTION ITEMS"] + [f"  [ ] {a}" for a in acts or ["(none found)"]] + ["", "DECISIONS"] + [f"  - {d}" for d in decs or ["(none found)"]]
            + ["", "OPEN QUESTIONS"] + [f"  ? {q}" for q in qs or ["(none found)"]])


_WEASEL = "very really quite basically actually just maybe perhaps somewhat fairly literally simply".split()


def writing_check(text: str) -> list:
    out = []
    for i, s in enumerate(sentences(text), 1):
        n = len(s.split())
        if n > 30: out.append(f"sentence {i}: long ({n} words) - consider splitting")
        if re.search(r"(?i)\b(?:is|are|was|were|been|being|be)\s+\w+ed\b(?:\s+by\b)?", s): out.append(f"sentence {i}: possible passive voice")
    ws = re.findall(r"[A-Za-z']+", text.lower())
    for a, b in zip(ws, ws[1:]):
        if a == b and a not in ("that", "had"): out.append(f"repeated word: '{a} {b}'")
    weasel = Counter(w for w in ws if w in _WEASEL)
    if weasel: out.append("filler words: " + ", ".join(f"{k}×{v}" for k, v in weasel.most_common()))
    adv = [w for w in ws if w.endswith("ly") and len(w) > 5 and w not in _WEASEL]
    if len(adv) > max(3, len(ws) // 40): out.append(f"many adverbs ({len(adv)}): " + ", ".join(sorted(set(adv))[:6]))
    return out or ["no issues found by these (simple) checks"]


def recommend(text: str, user: str = "", k: int = 5) -> list:
    """Item-based collaborative filtering over lines 'user,item,rating'."""
    R: dict = defaultdict(dict)
    for row in csv.reader(io.StringIO(text.strip())):
        if len(row) >= 3 and num(row[2]) is not None: R[row[0].strip()][row[1].strip()] = num(row[2])
    if not R: return ["enter ratings as lines: user,item,rating"]
    users = sorted(R); user = user or users[0]
    if user not in R: return [f"unknown user; users: {', '.join(users)}"]
    items = sorted({i for r in R.values() for i in r})
    def sim(a, b):
        both = [(R[u][a], R[u][b]) for u in R if a in R[u] and b in R[u]]
        if not both: return 0.0
        na = math.sqrt(sum(x * x for x, _ in both)); nb = math.sqrt(sum(y * y for _, y in both))
        return sum(x * y for x, y in both) / (na * nb) if na and nb else 0.0
    scores = {}
    for it in items:
        if it in R[user]: continue
        num_, den = 0.0, 0.0
        for seen, r in R[user].items():
            s = sim(it, seen); num_ += s * r; den += abs(s)
        if den: scores[it] = num_ / den
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])[:k]
    return [f"recommendations for {user}:"] + [f"  {i}  (predicted {s:.2f})" for i, s in ranked] if ranked else [f"nothing to recommend for {user} yet"]


SEED_GLOSSARY = {
    "es": {"hello": "hola", "goodbye": "adiós", "thank you": "gracias", "please": "por favor", "yes": "sí", "no": "no", "good morning": "buenos días",
           "good night": "buenas noches", "water": "agua", "food": "comida", "house": "casa", "friend": "amigo", "where is": "dónde está", "how much": "cuánto cuesta"},
    "fr": {"hello": "bonjour", "goodbye": "au revoir", "thank you": "merci", "please": "s'il vous plaît", "yes": "oui", "no": "non", "good morning": "bonjour",
           "good night": "bonne nuit", "water": "eau", "food": "nourriture", "house": "maison", "friend": "ami", "where is": "où est", "how much": "combien"},
    "de": {"hello": "hallo", "goodbye": "auf wiedersehen", "thank you": "danke", "please": "bitte", "yes": "ja", "no": "nein", "good morning": "guten morgen",
           "good night": "gute nacht", "water": "wasser", "food": "essen", "house": "haus", "friend": "freund", "where is": "wo ist", "how much": "wie viel kostet"}}


def glossary_translate(text: str, glossary: dict) -> tuple[str, list]:
    """Longest-match phrase substitution, case-preserving. This is a glossary
    lookup, not machine translation; unknown words are listed, not guessed."""
    keys = sorted(glossary, key=len, reverse=True)
    if not keys: return text, []
    rx = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b", re.I)
    def sub(m):
        t = glossary[m.group(0).lower()]
        return t.capitalize() if m.group(0)[:1].isupper() else t
    out = rx.sub(sub, text)
    unknown = sorted({w for w in re.findall(r"[A-Za-z']+", rx.sub(" ", text).lower()) if w not in STOP})
    return out, unknown
