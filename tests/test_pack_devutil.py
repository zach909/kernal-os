"""Tests for kos/office/pack_devutil.py: exact values, hostile input, and one FakeHost run per app."""

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_devutil as P  # noqa: E402
from kos.office.packkit import shared_add, shared_items  # noqa: E402
from kos.office.ui import FakeHost, SpaceHost, run  # noqa: E402

D = datetime


def runs(expr, after, n):
    return P.next_runs(P.parse_cron(expr), after, n)


class TestEntries(unittest.TestCase):
    def test_titles_scopes_and_permissions(self):
        by = {e.title: e for e in P.ENTRIES}
        self.assertEqual(sorted(by), sorted(["Developer Utilities", "Log Viewer", "Debug Helper", "Scheduled Task Planner", "Website Analytics"]))
        self.assertEqual(by["Log Viewer"].owns, ["logs"])
        self.assertEqual(by["Website Analytics"].uses, ["logs"])
        self.assertEqual(by["Debug Helper"].uses, ["logs"])
        for t in ("Developer Utilities", "Scheduled Task Planner"):
            self.assertEqual((by[t].owns, by[t].uses), ([], []))
        for e in P.ENTRIES:
            if e.scope != "full": self.assertGreater(len(e.note), 20)


class TestDevTools(unittest.TestCase):
    def test_regex_bombs_refused(self):
        for p in ["(a+)+$", "(a*)*", "(a|aa)+$", r"(\w+\s?)*$", "(.*a){20}", "(a+){2,}", r"(a)\1", "x" * 201, ".*.*.*x"]:
            self.assertTrue(P.regex_risk(p), p)
            with self.assertRaises(ValueError): P.t_regex(p + "\naaaaaaaaaaaaaaaaaaaaaaaa!")
        for p in [r"\w+@\w+\.com", r"(\d{3})-(\d{4})", r"^\d+$", "(?:foo|bar)", "(?i)abc", "[a+]+x", r"(\d+)\.(\d+)"]:
            self.assertEqual(P.regex_risk(p), "", p)

    def test_regex_matches(self):
        out = P.t_regex(r"(\w+)@(\w+)\.com" + "\nmail ann@example.com now")
        self.assertIn("line 1 at 5-20: 'ann@example.com'  groups=['ann', 'example']", out)
        self.assertEqual(out[-1], "1 match(es)")
        with self.assertRaises(ValueError): P.t_regex("(unclosed\nx")

    def test_encodings(self):
        self.assertEqual(P.t_b64e("hello"), ["aGVsbG8="])
        self.assertEqual(P.t_b64d("aGVsbG8="), ["hello"])
        self.assertEqual(P.t_hexe("hello"), ["68656c6c6f"])
        self.assertEqual(P.t_hexd("68 65 6c 6c 6f"), ["hello"])
        self.assertEqual(P.t_urle("a b&c=d/é"), ["a%20b%26c%3Dd%2F%C3%A9"])
        self.assertEqual(P.t_urld("a%20b%26c%C3%A9+x")[0], "a b&cé+x")
        for bad in (P.t_b64d, P.t_hexd):
            with self.assertRaises(ValueError): bad("not valid!!")
        self.assertIn("binary", P.t_b64d("/w==")[0])

    def test_hashes_known_digests(self):
        out = "\n".join(P.t_hash("abc"))
        self.assertIn("900150983cd24fb0d6963f7d28e17f72   NOT for security", out)
        self.assertIn("a9993e364706816aba3e25717850c26c9cd0d89d   NOT for security", out)
        self.assertIn("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out)
        self.assertIn("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a", out)
        self.assertNotIn("ad\x20  NOT", out)

    def test_uuid4(self):
        import uuid
        ids = P.t_uuid("")[:5]
        self.assertEqual(len(set(ids)), 5)
        for i in ids: self.assertEqual(uuid.UUID(i).version, 4)

    def test_timestamps(self):
        out = P.t_time("1700000000\n946684800000\n2000-01-01\n2024-03-05T10:20:00+01:00\nbogus")
        self.assertEqual(out[0], "1700000000 -> 2023-11-14T22:13:20Z (Tuesday)")
        self.assertIn("2000-01-01T00:00:00Z", out[1]); self.assertIn("milliseconds", out[1])
        self.assertEqual(out[2], "2000-01-01 -> 946684800  (UTC, Saturday)")
        self.assertIn("1709630400", out[3])           # 09:20 UTC
        self.assertIn("not a number", out[4])
        self.assertIn("out of range", P.t_time("99999999999999999999")[0])

    def test_json(self):
        self.assertEqual(P.t_jmin('{ "a": [1, 2],\n "b": true }'), ['{"a":[1,2],"b":true}'])
        self.assertEqual(P.t_jpretty('{"a":[1]}'), ["{", '  "a": [', "    1", "  ]", "}"])
        self.assertEqual(P.t_jpath('$.users[*].name\n{"users":[{"name":"ann"},{"name":"bob"}]}'), ['"ann"', '"bob"', "2 match(es)"])
        self.assertEqual(P.t_jpath('$.a[1]\n{"a":[5,6]}')[0], "6")
        self.assertEqual(P.t_jpath('$.zz\n{"a":1}'), ["0 match(es)"])
        for bad in ("$.a\n{bad", "$..a\n{}", "$.a\n" + "[" * 100000):
            with self.assertRaises(ValueError): P.t_jpath(bad)

    def test_diff_and_bases_and_lines(self):
        d = P.t_diff("one\ntwo\nthree\n---\none\n2\nthree")
        self.assertIn("-two", d); self.assertIn("+2", d)
        self.assertEqual(P.t_diff("a\n---\na")[-1], "identical")
        with self.assertRaises(ValueError): P.t_diff("no separator")
        b = P.t_base("255\n0xff\n0b1010\nzz 36\nnope")
        self.assertEqual(b[0], "255 = dec 255 | hex 0xff | oct 0o377 | bin 0b11111111 | base36 73")
        self.assertIn("dec 255", b[1]); self.assertIn("dec 10 ", b[2]); self.assertIn("dec 1295", b[3]); self.assertIn("not a number", b[4])
        self.assertEqual(P.t_sort("pear\nApple\nfig"), ["Apple", "fig", "pear"])
        self.assertEqual(P.t_dedupe("a\nb\na")[:2], ["a", "b"])
        self.assertTrue(P.t_count("a\nb\na")[0].startswith("lines 3   non-empty 3   unique 2"))
        self.assertIn("     2  a", P.t_count("a\nb\na"))

    def test_jwt_decode_only(self):
        tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.sig"
        out = "\n".join(P.t_jwt(tok))
        self.assertIn("SIGNATURE NOT VERIFIED", out); self.assertIn('"name": "John Doe"', out); self.assertIn("iat: 2018-01-18T01:30:22Z", out)
        with self.assertRaises(ValueError): P.t_jwt("a.b.c")
        with self.assertRaises(ValueError): P.t_jwt("nodots")
        none_tok = "eyJhbGciOiJub25lIn0.e30."
        self.assertIn("unsigned", "\n".join(P.t_jwt(none_tok)))


class TestLogs(unittest.TestCase):
    TEXT = ("2024-03-05T10:00:01Z INFO server started\n2024-03-05T10:00:09Z ERROR db timeout after 30s for user 1042\n"
            "Mar  5 10:01:00 host sshd[811]: Failed password for root from 10.0.0.9\n"
            '{"time":"2024-03-05T10:02:00Z","level":"error","msg":"db timeout after 45s for user 77"}\n'
            '203.0.113.9 - - [05/Mar/2024:10:03:00 +0000] "GET /missing HTTP/1.1" 404 153 "-" "curl/8.0"\n'
            "    continuation line")

    def test_parse_formats(self):
        recs, bad = P.parse_log(self.TEXT, 2024)
        self.assertEqual([r["fmt"] for r in recs], ["iso", "iso", "syslog", "json", "access", "text"])
        self.assertEqual(bad, 1)
        self.assertEqual(recs[0]["ts"], D(2024, 3, 5, 10, 0, 1)); self.assertEqual(recs[0]["level"], 2)
        self.assertEqual(recs[2]["ts"], D(2024, 3, 5, 10, 1, 0)); self.assertEqual(recs[2]["level"], 4)
        self.assertEqual(recs[3]["level"], 4)
        a = recs[4]
        self.assertEqual((a["ip"], a["status"], a["bytes"], a["path"], a["level"], a["ts"]), ("203.0.113.9", 404, 153, "/missing", 3, D(2024, 3, 5, 10, 3, 0)))

    def test_timezone_to_utc(self):
        self.assertEqual(P.parse_line("2024-03-05 10:00:00+02:00 hi")["ts"], D(2024, 3, 5, 8, 0, 0))

    def test_signature_and_groups(self):
        self.assertEqual(P.signature("db timeout after 30s for user 1042"), "db timeout after <n>s for user <n>")
        self.assertEqual(P.signature("conn from 10.1.2.3 id 3f2a9c1de0 uuid 123e4567-e89b-12d3-a456-426614174000 0xdeadbeef"),
                         "conn from <ip> id <hex> uuid <uuid> <hex>")
        g = P.error_groups(P.parse_log(self.TEXT, 2024)[0])
        self.assertEqual(g[0][0], "db timeout after <n>s for user <n>")
        self.assertEqual((g[0][1]["count"], g[0][1]["first"], g[0][1]["last"], g[0][1]["line"]), (2, D(2024, 3, 5, 10, 0, 9), D(2024, 3, 5, 10, 2, 0), 2))
        self.assertEqual(g[1][0], "sshd: Failed password for root from <ip>")
        self.assertEqual(len(g), 2)

    def test_filter(self):
        out = P.t_log_filter("level>=ERROR from=2024-03-05T10:01\n" + self.TEXT)
        self.assertTrue(out[0].startswith("2 of 6"))
        self.assertEqual(P.t_log_filter("text=TIMEOUT\n" + self.TEXT)[0][:6], "2 of 6")
        self.assertTrue(P.t_log_filter("level=INFO\n" + self.TEXT)[0].startswith("2 of 6"))
        with self.assertRaises(ValueError): P.t_log_filter("bogus=1\n" + self.TEXT)
        with self.assertRaises(ValueError): P.t_log_filter("level>=LOUD\n" + self.TEXT)

    def test_top_and_timeline_and_summary(self):
        self.assertEqual(P.top_messages(P.parse_log("x ERROR a\nx ERROR a\ny INFO b")[0])[0], ("x ERROR a", 2))
        tl = P.timeline(P.parse_log("2024-03-05T10:00:00Z a\n2024-03-05T10:00:30Z ERROR b\n2024-03-05T10:02:10Z c")[0])
        self.assertTrue(tl[2].startswith("2024-03-05 10:00     2    1!"))
        self.assertTrue(tl[3].startswith("2024-03-05 10:01     0"))
        self.assertTrue(tl[4].startswith("2024-03-05 10:02     1"))
        with self.assertRaises(ValueError): P.timeline(P.parse_log("no time here")[0])
        s = "\n".join(P.t_log_summary(self.TEXT))
        self.assertIn("cannot read /var/log", s); self.assertIn("6 line(s)", s)


class TestDebug(unittest.TestCase):
    PY = ('Traceback (most recent call last):\n  File "/app/db.py", line 10, in get\n    return rows[0]\nIndexError: list index out of range\n\n'
          "During handling of the above exception, another exception occurred:\n\n"
          'Traceback (most recent call last):\n  File "/app/main.py", line 3, in <module>\n    get()\n'
          '  File "/usr/lib/python3.11/json/__init__.py", line 346, in loads\n    return _default_decoder.decode(s)\n'
          "json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)")

    def test_python_chain(self):
        exs = P.parse_py(self.PY)
        self.assertEqual([e["type"] for e in exs], ["IndexError", "json.decoder.JSONDecodeError"])
        self.assertEqual(exs[1]["link"], "raised while handling the one above")
        self.assertEqual(exs[0]["frames"][0], dict(file="/app/db.py", line=10, func="get", code="return rows[0]"))
        out = "\n".join(P.explain_error(self.PY))
        self.assertIn("Last of YOUR code: /app/main.py:3 in <module>", out)
        self.assertIn("Raised at:   /usr/lib/python3.11/json/__init__.py:346 in loads", out)
        self.assertIn("Root cause: IndexError", out); self.assertIn("not valid JSON", out)

    def test_python_simple_and_hints(self):
        t = 'Traceback (most recent call last):\n  File "a.py", line 5, in run\n    return d["x"]\nKeyError: \'x\''
        out = P.explain_error(t)
        self.assertIn("Failed with: KeyError: 'x'", out); self.assertIn("Failing line: return d[\"x\"]", out)
        self.assertIn("is None", P.hint("AttributeError", "'NoneType' object has no attribute 'a'"))
        self.assertIn("divisor", P.hint("ZeroDivisionError", "division by zero"))
        self.assertIn("No stock hint", P.hint("WeirdError", ""))
        syn = P.parse_py('  File "x.py", line 3\n    if x\n        ^\nSyntaxError: expected \':\'')
        self.assertEqual((syn[0]["type"], syn[0]["frames"][0]["line"]), ("SyntaxError", 3))

    def test_javascript(self):
        js = ("TypeError: Cannot read properties of undefined (reading 'x')\n    at foo (/app/a.js:10:5)\n    at Object.<anonymous> (/app/b.js:3:1)\n"
              "    at Module._compile (node:internal/modules/cjs/loader:1:1)")
        ex = P.parse_js(js)
        self.assertEqual((ex["type"], len(ex["frames"])), ("TypeError", 3))
        self.assertEqual(ex["frames"][0], dict(file="/app/a.js", line=10, col=5, func="foo"))
        out = "\n".join(P.explain_error(js))
        self.assertIn("Thrown at:   /app/a.js:10:5 in foo", out); self.assertIn("optional chaining", out)
        with self.assertRaises(ValueError): P.explain_error("nothing useful")

    PROF = ("         1200 function calls (1100 primitive calls) in 2.500 seconds\n\n   Ordered by: cumulative time\n\n"
            "   ncalls  tottime  percall  cumtime  percall filename:lineno(function)\n"
            "        1    0.010    0.010    2.500    2.500 main.py:1(<module>)\n      100    1.500    0.015    2.000    0.020 work.py:10(crunch)\n"
            "     1000    0.500    0.001    0.500    0.001 {built-in method builtins.len}")

    def test_pstats(self):
        p = P.parse_pstats(self.PROF)
        self.assertEqual((len(p["rows"]), p["total"], p["calls"]), (3, 2.5, 1200))
        out = P.profile_summary(self.PROF)
        hot = next(l for l in out if "work.py:10(crunch)" in l)
        self.assertIn("1.500", hot); self.assertIn("60.0%", hot)
        self.assertLess(out.index(hot), next(i for i, l in enumerate(out) if "len" in l))
        with self.assertRaises(ValueError): P.profile_summary("nothing")


class TestCron(unittest.TestCase):
    def test_parse(self):
        j = P.parse_cron("*/15 9-10 1,15 jan-mar mon,fri")
        self.assertEqual((j["minute"], j["hour"], j["dom"], j["month"], j["dow"]), ([0, 15, 30, 45], [9, 10], [1, 15], [1, 2, 3], [1, 5]))
        self.assertEqual(P.parse_cron("0 0 * * 7")["dow"], [0])
        self.assertEqual(P.parse_cron("@daily")["f"], ["0", "0", "*", "*", "*"])
        self.assertEqual(P.parse_cron("10/20 * * * *")["minute"], [10, 30, 50])
        for bad in ("* * * *", "60 * * * *", "* 24 * * *", "5-1 * * * *", "*/0 * * * *", "@reboot", "x * * * *", "* * 0 * *", "* * * 13 *", ""):
            with self.assertRaises(ValueError, msg=bad): P.parse_cron(bad)

    def test_next_runs_weekdays(self):
        self.assertEqual(runs("30 9 * * 1-5", D(2026, 11, 7), 6),
                         [D(2026, 11, 9, 9, 30), D(2026, 11, 10, 9, 30), D(2026, 11, 11, 9, 30), D(2026, 11, 12, 9, 30), D(2026, 11, 13, 9, 30), D(2026, 11, 16, 9, 30)])

    def test_dom_or_dow_when_both_restricted(self):
        # 2026-11-07 is a Saturday. "13th OR Friday": Fridays Nov 13 20 27, Dec 4 11, and the 13th (a Sunday) Dec 13.
        self.assertEqual(runs("0 12 13 * 5", D(2026, 11, 7), 6),
                         [D(2026, 11, 13, 12), D(2026, 11, 20, 12), D(2026, 11, 27, 12), D(2026, 12, 4, 12), D(2026, 12, 11, 12), D(2026, 12, 13, 12)])
        # a '*' step in day-of-month means both must match: odd days that are also Mondays
        self.assertEqual(runs("0 0 */2 * 1", D(2026, 11, 7), 3), [D(2026, 11, 9), D(2026, 11, 23), D(2026, 12, 7)])

    def test_months_leap_and_never(self):
        self.assertEqual(runs("0 0 29 2 *", D(2026, 1, 1), 2), [D(2028, 2, 29), D(2032, 2, 29)])
        self.assertEqual(runs("0 0 31 * *", D(2026, 11, 7), 3), [D(2026, 12, 31), D(2027, 1, 31), D(2027, 3, 31)])
        self.assertEqual(runs("0 0 30 2 *", D(2026, 1, 1), 3), [])
        self.assertEqual(runs("0 0 * * 7", D(2026, 11, 7), 1), [D(2026, 11, 8)])

    def test_steps_and_macros_and_strictly_after(self):
        self.assertEqual(runs("*/15 9-10 * * *", D(2026, 11, 7, 9, 50), 3), [D(2026, 11, 7, 10, 0), D(2026, 11, 7, 10, 15), D(2026, 11, 7, 10, 30)])
        self.assertEqual(runs("@weekly", D(2026, 11, 7, 10), 1), [D(2026, 11, 8)])
        self.assertEqual(runs("0 12 * * *", D(2026, 11, 7, 12, 0), 1), [D(2026, 11, 8, 12)])
        self.assertEqual(runs("@yearly", D(2026, 11, 7), 1), [D(2027, 1, 1)])

    def test_explain(self):
        e = lambda x: P.explain_cron(P.parse_cron(x))
        self.assertEqual(e("30 9 * * 1-5"), "at 09:30 on Mon, Tue, Wed, Thu, Fri")
        self.assertEqual(e("*/5 * * * *"), "every 5 minutes every day")
        self.assertEqual(e("@daily"), "at 00:00 every day")
        self.assertEqual(e("0 12 13 * 5"), "at 12:00 on day 13 of the month or on Fri")
        self.assertEqual(e("0 0 1 jan,jul *"), "at 00:00 on day 1 of the month in Jan, Jul")

    def test_overlaps(self):
        s = D(2026, 11, 9)
        _, jobs = P.parse_jobs("0 9 * * * a ~30m\n15 9 * * * b ~5m\n45 9 * * * c\n0 9 * * * x\n0 * * * * h ~90m")
        ov = {(a, b): (n, t) for a, b, n, t in P.find_overlaps(jobs, s)}
        self.assertEqual(ov[("a", "b")], (1, D(2026, 11, 9, 9, 15)))
        self.assertNotIn(("a", "c"), ov); self.assertNotIn(("b", "c"), ov)
        self.assertEqual(ov[("a", "x")], (1, D(2026, 11, 9, 9, 0)))       # same start minute
        self.assertEqual(ov[("h", "h")][0], 23)                            # 90-minute job every 60 minutes
        self.assertEqual(ov[("a", "h")][0], 2)                            # a (9:00-9:30) meets h's 8:00 (to 9:30) and 9:00 runs
        out = P.t_cron_conflicts("start: 2026-11-09\n0 9 * * * a\n0 9 * * * b")
        self.assertIn("a overlaps b: 1 time(s), first 2026-11-09 09:00 Mon", out)

    def test_day_timeline_and_export_and_explain_tool(self):
        out = P.t_cron_day("start: 2026-11-09\n0 9 * * * a\n30 9 * * * b\n0 * * * * h")
        self.assertTrue(out[2 + 9].startswith("09     3"))
        self.assertTrue(out[2 + 8].startswith("08     1"))
        ex = P.t_cron_export("0 9 * * * a ~30m\n# c\n@daily b")
        self.assertEqual(ex[1:], ["0 9 * * * a", "0 0 * * * b"]); self.assertIn("does not run", ex[0])
        e = P.t_cron_explain("start: 2026-11-07\ncount: 2\n0 0 1 * * m")
        self.assertIn("    2026-12-01 00:00 Tue", e); self.assertIn("nothing here ever runs", e[0])
        with self.assertRaises(ValueError): P.t_cron_explain("1 2 3")
        with self.assertRaises(ValueError): P.parse_jobs("\n".join(["* * * * * j"] * 31))


class TestWeb(unittest.TestCase):
    LOG = ('1.1.1.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1000 "https://google.com/q" "Mozilla/5.0"\n'
           '1.1.1.1 - - [05/Mar/2024:10:00:01 +0000] "GET /a.css HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n'
           '2.2.2.2 - - [05/Mar/2024:11:00:00 +0000] "GET /nope HTTP/1.1" 404 100 "-" "Googlebot/2.1"\n'
           '1.1.1.1 - - [06/Mar/2024:09:00:00 +0000] "GET /?x=1 HTTP/1.1" 200 1000 "https://google.com/x" "Mozilla/5.0"')

    def test_stats(self):
        s = P.web_stats(self.LOG)
        self.assertEqual((s["hits"], s["visitors"], s["human_visitors"], s["bots"], s["bytes"], s["assets"]), (4, 2, 1, 1, 2600, 1))
        self.assertEqual(dict(s["pages"]), {"/": 2})
        self.assertEqual(dict(s["refs"]), {"google.com": 2, "(direct / none)": 2})
        self.assertEqual(dict(s["status"]), {200: 3, 404: 1}); self.assertEqual(dict(s["classes"]), {"2xx": 3, "4xx": 1})
        self.assertEqual(dict(s["notfound"]), {"/nope": 1})
        self.assertEqual(dict(s["days"]), {"2024-03-05": 3, "2024-03-06": 1}); self.assertEqual(s["day_bytes"]["2024-03-05"], 1600)

    def test_views(self):
        self.assertIn("hits 4   unique visitors (IP+user-agent) 2", "\n".join(P.t_web_summary(self.LOG)))
        self.assertIn("bot hits 1 of 4 (25.0%)", P.t_web_bots(self.LOG)[0])
        self.assertIn("  4xx       1  25.0%", P.t_web_status(self.LOG))
        self.assertTrue(any("2024-03-05" in l and "1.6 KB" in l for l in P.t_web_time(self.LOG)))
        with self.assertRaises(ValueError): P.web_stats("not a log\n")


class TestHostile(unittest.TestCase):
    ALL = [t for ts in (P.DEV_TOOLS, P.LOG_TOOLS, P.DEBUG_TOOLS, P.CRON_TOOLS, P.WEB_TOOLS) for t in ts]

    def test_samples_run_clean(self):
        for t in self.ALL:
            out = P._render(t[1], t[2])
            self.assertFalse(out[0].startswith("error:"), (t[0], out[:2]))

    def test_hostile_inputs_never_crash_or_leak_controls(self):
        for t in self.ALL:
            for bad in ["", "\n\n", "\x00\x1b[31mred\x07" * 50, "A" * 300000, "{" * 5000, "((((", "\n".join(["* * * * * j"] * 500), "9" * 5000, "%" * 999, "\ufffe\u202e" * 100]:
                out = P._render(t[1], bad)
                self.assertIsInstance(out, list)
                self.assertTrue(all(c.isprintable() for l in out for c in l), t[0])
                self.assertLessEqual(len(out), 2000)

    def test_bounds(self):
        self.assertEqual(len(P.lines_of("x\n" * 20000)), P.MAXLINES)
        self.assertEqual(len(P.lines_of("y" * 10000)[0]), 2000)
        self.assertEqual(len(P.parse_log("x ERROR y\n" * 20000)[0]), P.MAXLINES)


class TestScreens(unittest.TestCase):
    def test_every_app_draws_runs_and_saves(self):
        for e in P.ENTRIES:
            h = FakeHost(["enter", "ctrl-r", "escape", "ctrl-s", "escape", "ctrl-q"])
            run(h, e.args["make"](h, e))
            self.assertTrue(h.frames, e.title)
            self.assertTrue(any(k.startswith(("devutil.", "logview.", "debughelp.", "cronplan.", "webstats.")) for k in h.data), e.title)
            self.assertEqual(h.exited, 0)

    def test_every_app_survives_a_key_battery(self):
        keys = ["up", "down", "enter", "a", "backspace", "ctrl-r", "ctrl-g", "escape", "end", "home", "pagedown", "tab", "x", "1", "9", "delete", "left", "right"] * 4
        for e in P.ENTRIES:
            h = FakeHost(keys); run(h, e.args["make"](h, e)); self.assertTrue(h.frames)

    def test_shared_logs_between_two_hosts(self):
        by = {e.title: e for e in P.ENTRIES}
        owner = FakeHost(["enter", "ctrl-g", "escape"])
        run(owner, by["Log Viewer"].args["make"](owner, by["Log Viewer"]))
        saved = shared_items(owner, "logs")
        self.assertEqual(len(saved), 1); self.assertIn("server started", saved[0]["text"])
        user = FakeHost(["end", "enter", "enter", "enter"])
        user.spaces = owner.spaces                                  # the same shared folder, a different app
        run(user, by["Website Analytics"].args["make"](user, by["Website Analytics"]))
        self.assertIn("hits 1", user.text)
        dbg = FakeHost(["end", "enter", "enter", "enter"]); dbg.spaces = owner.spaces
        run(dbg, by["Debug Helper"].args["make"](dbg, by["Debug Helper"]))
        self.assertIn("error:", dbg.text)                            # a log is not a traceback: refused politely, not a crash

    def test_missing_grant_says_so(self):
        e = {e.title: e for e in P.ENTRIES}["Website Analytics"]
        h = FakeHost(["end", "enter"]); run(h, e.args["make"](h, e))
        self.assertIn("granted read access", h.text)

    def test_user_apps_cannot_write_the_shared_folder(self):
        e = {e.title: e for e in P.ENTRIES}["Website Analytics"]
        h = FakeHost(["enter", "ctrl-g"]); run(h, e.args["make"](h, e))
        self.assertEqual(shared_items(h, "logs"), [])


if __name__ == "__main__":
    unittest.main()
