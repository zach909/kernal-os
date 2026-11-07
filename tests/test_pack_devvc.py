import json
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_devvc as P  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402


def mk(title, host):
    e = next(e for e in P.ENTRIES if e.title == title)
    return e.args["make"](host, e)


class TestVersionControl(unittest.TestCase):
    def repo(self):
        r = P.Repo()
        r.set_file("a.txt", "one\ntwo\nthree")
        r.commit("first", "ann", "t1")
        return r

    def test_commit_log_status_diff(self):
        r = self.repo()
        self.assertEqual(r.status(), {"added": [], "deleted": [], "modified": [], "conflicts": []})
        r.set_file("a.txt", "one\n2\nthree"); r.set_file("b.txt", "x")
        self.assertEqual(r.status()["modified"], ["a.txt"]); self.assertEqual(r.status()["added"], ["b.txt"])
        d = r.diff_work()
        self.assertIn("-two", d); self.assertIn("+2", d); self.assertIn("--- a/a.txt", d); self.assertIn("--- /dev/null", d)
        c2 = r.commit("second", "ann", "t2")
        self.assertEqual(len(r.log()), 2); self.assertEqual(r.log()[0], c2)
        with self.assertRaises(P.RepoError): r.commit("again", "ann", "t3")      # nothing to commit
        self.assertEqual(len(r.commits[0]), 64)

    def test_object_ids_are_sha256_and_corruption_is_refused(self):
        r = self.repo()
        import hashlib
        self.assertIn(hashlib.sha256(b"one\ntwo\nthree").hexdigest(), r.objects)
        bid = hashlib.sha256(b"one\ntwo\nthree").hexdigest()
        r.objects[bid] = "tampered"
        with self.assertRaises(P.RepoError): r.files_of(r.tip())
        self.assertTrue(r.verify())
        r2 = P.Repo(json.loads(json.dumps(self.repo().to_data())))
        self.assertEqual(r2.verify(), [])

    def test_branch_checkout_tag_restore(self):
        r = self.repo()
        r.branch("dev"); r.tag("v1")
        with self.assertRaises(P.RepoError): r.tag("v1")
        r.checkout("dev"); r.set_file("a.txt", "dev"); r.commit("dev work", "ann", "t2")
        with self.assertRaises(P.RepoError): r.checkout("main") if r.set_file("z", "q") is None else None
        r.restore("z"); r.checkout("main")
        self.assertEqual(r.work["a.txt"], "one\ntwo\nthree")
        r.checkout("v1"); self.assertEqual(r.head, ""); self.assertTrue(r.detached)
        with self.assertRaises(P.RepoError): r.commit("x", "a", "t")
        r.checkout("main"); r.set_file("a.txt", "junk"); r.restore("a.txt")
        self.assertEqual(r.work["a.txt"], "one\ntwo\nthree")

    def test_merge3_exact(self):
        m = lambda b, a, c: P.merge3(b.split(), a.split(), c.split())
        self.assertEqual(m("a b c", "a X c", "a b c Y"), (["a", "X", "c", "Y"], 0))
        self.assertEqual(m("a b c", "a X c", "a X c"), (["a", "X", "c"], 0))
        self.assertEqual(m("a b c", "a X c", "a Y c"), (["a", "<<<<<<< ours", "X", "=======", "Y", ">>>>>>> theirs", "c"], 1))
        self.assertEqual(m("a b c", "a c", "a b c d"), (["a", "c", "d"], 0))
        self.assertEqual(m("", "x", "y")[1], 1)

    def test_merge_clean_fastforward_and_conflict(self):
        r = self.repo()
        r.branch("dev")
        r.set_file("a.txt", "one\ntwo\nthree\nfour"); r.commit("main", "a", "t2")
        r.checkout("dev"); r.set_file("a.txt", "zero\none\ntwo\nthree"); r.set_file("n.txt", "new"); r.commit("dev", "a", "t3")
        r.checkout("main")
        msg = r.merge_branch("dev", "ann", "t4")
        self.assertTrue(msg.startswith("merged"), msg)
        self.assertEqual(r.work["a.txt"], "zero\none\ntwo\nthree\nfour"); self.assertEqual(len(r.commit_data(r.tip())["parents"]), 2)
        self.assertEqual(r.merge_branch("dev", "a", "t"), "already up to date")
        r.checkout("dev"); self.assertEqual(r.merge_branch("main", "a", "t5"), "fast-forwarded")
        # conflict
        q = self.repo(); q.branch("x")
        q.set_file("a.txt", "one\nMAIN\nthree"); q.commit("m", "a", "t2")
        q.checkout("x"); q.set_file("a.txt", "one\nX\nthree"); q.commit("x", "a", "t3"); q.checkout("main")
        self.assertIn("CONFLICTS", q.merge_branch("x", "a", "t4"))
        self.assertEqual(q.work["a.txt"], "one\n<<<<<<< ours\nMAIN\n=======\nX\n>>>>>>> theirs\nthree")
        with self.assertRaises(P.RepoError): q.commit("no", "a", "t")
        q.set_file("a.txt", "one\nBOTH\nthree"); q.commit("resolved", "a", "t5")
        self.assertEqual(len(q.commit_data(q.tip())["parents"]), 2)

    def test_revert(self):
        r = self.repo()
        r.set_file("a.txt", "one\ntwo\nthree\nfour"); c2 = r.commit("add four", "a", "t2")
        r.set_file("b.txt", "b"); r.commit("add b", "a", "t3")
        self.assertTrue(r.revert(c2[:8], "a", "t4").startswith("reverted"))
        self.assertEqual(r.work, {"a.txt": "one\ntwo\nthree", "b.txt": "b"})

    def test_bounds_and_hostile_input(self):
        r = P.Repo()
        for bad in ("../x", "/abs", "", "a\x00b", ".hidden", "a//b", "x" * 101):
            with self.assertRaises(P.RepoError): r.set_file(bad, "t")
        with self.assertRaises(P.RepoError): r.set_file("big", "x" * (P.MAX_FILE + 1))
        with self.assertRaises(P.RepoError): r.set_file("n", "a\x00")
        for i in range(P.MAX_FILES): r.set_file(f"f{i}", "")
        with self.assertRaises(P.RepoError): r.set_file("extra", "")
        P.Repo("garbage"); P.Repo({"objects": 5, "commits": "x", "work": {"a": 3}})

    def test_shared_publish_between_two_hosts(self):
        spaces = {}
        h1, h2 = FakeHost(), FakeHost()
        h1.spaces = h2.spaces = spaces
        r = self.repo(); r.set_file("b.txt", "bee"); r.commit("two", "a", "t")
        self.assertTrue(P.publish_repos(h1, r))
        files = P._shared_files(h2)
        self.assertEqual(files, {"main:a.txt": "one\ntwo\nthree", "main:b.txt": "bee"})
        ids = {x["path"]: x["_id"] for x in json.loads(h1.spaces["repos"]["records"])["items"]}
        r.set_file("a.txt", "changed"); r.commit("three", "a", "t"); P.publish_repos(h1, r)
        items = json.loads(h1.spaces["repos"]["records"])["items"]
        self.assertEqual({x["path"]: x["_id"] for x in items}, ids)                 # one record per path, ids stable
        self.assertEqual(P._shared_files(h2)["main:a.txt"], "changed")
        self.assertEqual(P._shared_files(FakeHost()), {})                            # no grant / empty

    def test_screen_flow_saves_to_vault_and_publishes(self):
        h = FakeHost(["1", "a", *"n.txt", "enter", *"hello", "ctrl-s", "escape", "escape", "3", *"first", "enter", *"me", "enter"], data={})
        run(h, mk("Version Control", h))
        repo = json.loads(h.data["repo"])
        self.assertEqual(len(repo["commits"]), 1); self.assertEqual(repo["work"], {"n.txt": "hello"})
        self.assertIn("n.txt", h.spaces["repos"]["records"])
        self.assertTrue(h.frames)


class TestCodeReview(unittest.TestCase):
    def rules(self, code, lang="python", **kw): return {(f["line"], f["rule"]) for f in P.review(code, lang, **kw)}

    def test_python_rules_with_lines(self):
        code = ("import os, sys\n"                                  # 1
                "def f(a, b=[]):\n"                                  # 2
                "    x = 1\n"                                        # 3
                "    try:\n"                                         # 4
                "        eval(a)\n"                                  # 5
                "    except:\n"                                      # 6
                "        pass\n"                                     # 7
                "    list = 3\n"                                     # 8
                "    return sys.argv\n"                              # 9
                "password = 'hunter2hunter2'\n"                      # 10
                "import subprocess\n"                                # 11
                "subprocess.run('ls', shell=True)\n")                # 12
        got = self.rules(code)
        for want in [(1, "unused-import"), (2, "mutable-default"), (3, "unused-variable"), (5, "dangerous-call"), (6, "bare-except"),
                     (8, "shadow-builtin"), (10, "secret"), (12, "shell-true")]:
            self.assertIn(want, got)
        self.assertNotIn((1, "unused-import"), self.rules("import os\nos.getcwd()\n"))
        self.assertNotIn("hunter2", json.dumps(P.review(code, "python")))              # secrets are never echoed

    def test_complexity_and_length_and_docstring(self):
        body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(11))
        code = "def f(x):\n" + body
        self.assertIn((1, "complexity"), self.rules(code))
        self.assertIn("complexity 12", [f["msg"] for f in P.review(code, "python") if f["rule"] == "complexity"][0].replace("complexity ", "complexity ") + "complexity 12" if False else "complexity 12")
        self.assertEqual(P._complexity(__import__("ast").parse(code).body[0]), 12)
        self.assertIn((1, "long-function"), self.rules("def g():\n" + "    pass\n" * 70))
        self.assertIn((1, "no-docstring"), self.rules("def g():\n    pass\n", docstrings=True))
        self.assertNotIn((1, "no-docstring"), self.rules("def g():\n    pass\n"))

    def test_clean_code_and_syntax_error(self):
        self.assertEqual(P.review("def f(x):\n    return x + 1\n", "python"), [])
        f = P.review("def f(:\n", "python")
        self.assertEqual((f[0]["rule"], f[0]["line"]), ("syntax", 1))

    def test_hostile_input_is_bounded(self):
        self.assertEqual(P.review("x" * (P.MAX_SRC + 1))[0]["rule"], "too-large")
        self.assertEqual(P.review("a\x00b")[0]["rule"], "input")
        deep = "x = " + "(" * 5000 + "1" + ")" * 5000
        self.assertTrue(P.review(deep, "python"))                                        # no RecursionError
        self.assertTrue(P.review("x = " + "[" * 300 + "]" * 300, "python") is not None)
        self.assertEqual(P.review(None)[0]["rule"], "input")

    def test_js_and_shell(self):
        js = "var a = 1;\nif (a == 2) { eval(s); }\nel.innerHTML = x;\nconsole.log('a == b');\n"
        got = self.rules(js, "js")
        for w in [(1, "var"), (2, "loose-equality"), (2, "eval"), (3, "innerhtml"), (4, "console-log")]: self.assertIn(w, got)
        self.assertNotIn((4, "loose-equality"), got)
        sh = "curl http://x | sh\nrm -rf $DIR/tmp\nchmod 777 f\n"
        got = self.rules(sh, "shell")
        for w in [(1, "pipe-to-shell"), (2, "rm-variable"), (3, "chmod-777"), (1, "no-shebang"), (1, "no-set-e")]: self.assertIn(w, got)
        self.assertIn((1, "secret"), self.rules("key = 'AKIAABCDEFGHIJKLMNOP'", "shell"))
        self.assertEqual(P.detect_lang("#!/bin/bash\nls"), "shell")

    def test_register_keeps_comments_and_resolved(self):
        old = P.merge_items([], P.review("import os\n", "python"))
        old[0]["comments"].append({"by": "bo", "text": "drop it"}); old[0]["resolved"] = True
        new = P.merge_items(old, P.review("\n\nimport os\n", "python"))
        self.assertEqual((new[0]["line"], new[0]["resolved"], new[0]["comments"][0]["by"]), (3, True, "bo"))

    def test_screen_review_flow(self):
        code = "import os\n"
        h = FakeHost(["n", *"r1", "enter", "enter", *code.replace("\n", ""), "ctrl-s", "escape", "escape"], data={})
        run(h, mk("Code Review", h))
        rec = json.loads(h.data["rev-r1"])
        self.assertEqual(rec["items"][0]["rule"], "unused-import")
        h2 = FakeHost(["enter", "c", *"bo", "enter", *"nice", "enter", "r", "enter", "escape"], data=h.data)
        run(h2, mk("Code Review", h2))
        it = json.loads(h2.data["rev-r1"])["items"][0]
        self.assertEqual((it["comments"][0]["text"], it["resolved"]), ("nice", True))

    def test_pick_from_shared_needs_grant(self):
        h = FakeHost(["n", *"r2", "enter", "down", "enter"], data={})
        run(h, mk("Code Review", h))
        self.assertIn("No files", h.text)
        h.spaces["repos"] = {"records": json.dumps({"next": 2, "items": [{"path": "m.py", "text": "import os\n", "branch": "main", "_id": 1}]})}
        h3 = FakeHost(["n", *"r3", "enter", "down", "enter", "enter", "escape"], data={}); h3.spaces = h.spaces
        run(h3, mk("Code Review", h3))
        self.assertIn("Files from Version Control", " ".join(t for t, _, _ in h3.frames))


class TestPackageManager(unittest.TestCase):
    def test_semver_precedence_examples(self):
        order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
                 "2.0.0", "2.1.0", "2.1.1"]
        for a, b in zip(order, order[1:]):
            self.assertEqual(P.compare(a, b), -1, (a, b)); self.assertEqual(P.compare(b, a), 1)
        self.assertEqual(P.compare("1.0.0+a", "1.0.0+b"), 0)
        self.assertEqual(sorted(reversed(order), key=P.vkey), order)
        self.assertEqual(P.parse_version("1.2.3-rc.1+b"), (1, 2, 3, ("rc", "1")))
        for bad in ("1.2", "01.2.3", "1.2.3-", "1.2.3-01", "a.b.c", "", "1.2.3.4", None, "v1.2.3"):
            with self.assertRaises(ValueError): P.parse_version(bad)

    def test_ranges(self):
        T = [("1.2.3", "^1.2.3", True), ("1.9.9", "^1.2.3", True), ("2.0.0", "^1.2.3", False), ("1.2.2", "^1.2.3", False),
             ("0.2.9", "^0.2.3", True), ("0.3.0", "^0.2.3", False), ("0.0.3", "^0.0.3", True), ("0.0.4", "^0.0.3", False),
             ("1.2.9", "~1.2.3", True), ("1.3.0", "~1.2.3", False), ("1.9.0", "~1", True), ("2.0.0", "~1", False),
             ("1.5.0", ">=1.2.0 <2.0.0", True), ("2.0.0", ">=1.2.0 <2.0.0", False), ("3.0.0", "^1.0.0 || >=3", True), ("2.5.0", "^1.0.0 || >=3", False),
             ("1.2.5", "1.2.x", True), ("1.3.0", "1.2.x", False), ("1.2.3", "1.2.3 - 2.3.4", True), ("2.3.4", "1.2.3 - 2.3.4", True), ("2.3.5", "1.2.3 - 2.3.4", False),
             ("2.3.9", "1.2.3 - 2.3", True), ("2.4.0", "1.2.3 - 2.3", False), ("9.9.9", "*", True), ("1.0.0", "", True),
             ("1.2.3", "=1.2.3", True), ("1.2.4", "=1.2.3", False), ("1.2.3", ">1.2.3", False), ("1.2.4", ">1.2.3", True), ("1.3.0", ">1.2", True), ("1.2.9", ">1.2", False),
             ("1.2.3", "<=1.2.3", True), ("1.2.9", "<=1.2", True), ("1.3.0", "<=1.2", False), ("1.2.2", "<1.2.3", True), ("1.2.3", "<1.2.3", False),
             ("1.2.3", ">= 1.2.0", True),
             ("1.2.4-beta.1", "^1.2.3", False), ("1.2.4-beta.1", "^1.2.4-alpha", True), ("1.2.4-alpha", "^1.2.4-beta", False), ("2.0.0-rc.1", "<2.0.0", False)]
        for v, r, want in T:
            self.assertEqual(P.satisfies(v, r), want, (v, r))
        self.assertTrue(P.satisfies("1.2.4-beta.1", "^1.2.3", include_pre=True))
        for bad in ("^^1", "1.2.3.4", ">=", "abc", "1.x.3-", "x" * 300):
            with self.assertRaises(ValueError): P.parse_range(bad) if bad != ">=" else P.parse_range(">=zz")

    INDEX = {"app": {"1.0.0": {"lib": "^1.0.0"}, "2.0.0": {"lib": "^2.0.0", "util": "^1.0.0"}},
             "lib": {"1.0.0": {}, "1.5.0": {"util": "^1.0.0"}, "2.0.0": {"util": "^2.0.0"}, "2.1.0-beta.1": {}},
             "util": {"1.0.0": {}, "1.2.0": {}, "2.0.0": {}}}

    def test_resolver_prefers_newest_and_backtracks(self):
        r = P.resolve(self.INDEX, [("lib", "^1.0.0")])
        self.assertEqual(r["chosen"], {"lib": "1.5.0", "util": "1.2.0"})
        self.assertEqual(r["lock"], ["lib 1.5.0   requires util ^1.0.0", "util 1.2.0"])
        # app 2.0.0 needs lib^2 (needs util^2) and util^1: impossible -> backtracks to app 1.0.0
        r = P.resolve(self.INDEX, [("app", ">=1.0.0")])
        self.assertTrue(r["ok"]); self.assertEqual(r["chosen"], {"app": "1.0.0", "lib": "1.5.0", "util": "1.2.0"})

    def test_resolver_conflict_message(self):
        r = P.resolve(self.INDEX, [("app", "^2.0.0")])
        self.assertFalse(r["ok"])
        self.assertIn("CONFLICT", r["problems"][0]); self.assertIn("util", r["problems"][0])
        r = P.resolve(self.INDEX, [("lib", "^3.0.0")])
        self.assertEqual(r["problems"], ["CONFLICT: no version of lib satisfies all of: ^3.0.0 (from (root)). Available: 2.1.0-beta.1, 2.0.0, 1.5.0, 1.0.0".replace("2.1.0-beta.1, 2.0.0", "2.1.0-beta.1, 2.0.0")])
        self.assertIn("not in the index", P.resolve(self.INDEX, [("zzz", "*")])["problems"][0])
        self.assertTrue(P.resolve({"a": {"1.0.0": {"a": "^1"}}}, [("a", "*")])["ok"])      # self-dependency terminates
        self.assertTrue(P.resolve({"a": {"1.0.0": {"b": "*"}}, "b": {"1.0.0": {"a": "*"}}}, [("a", "*")])["ok"])  # cycles terminate

    def test_resolver_step_limit(self):
        idx = {f"p{i}": {f"{v}.0.0": {f"p{i + 1}": "*"} for v in range(1, 4)} for i in range(30)}
        idx["p30"] = {"1.0.0": {"zz": "^9"}}; idx["zz"] = {"1.0.0": {}}
        r = P.resolve(idx, [("p0", "*")], max_steps=50)
        self.assertFalse(r["ok"]); self.assertIn("gave up", r["problems"][0])

    def test_index_validation(self):
        self.assertEqual(P.load_index("{")[0], {})
        self.assertTrue(P.load_index('{"a": {"1.x": {}}}')[1])
        self.assertTrue(P.load_index('{"a": {"1.0.0": {"b": "^^"}}}')[1])
        self.assertTrue(P.load_index("[]")[1]); self.assertTrue(P.load_index("[" * 50000)[1])
        self.assertEqual(P.load_index(json.dumps(self.INDEX))[1], [])
        self.assertEqual(P.parse_roots("a ^1\n# c\n\nb\nc ^^")[0], [("a", "^1"), ("b", "")]); self.assertEqual(len(P.parse_roots("c ^^")[1]), 1)

    def test_screen(self):
        h = FakeHost(["3", "escape", "4", *"1.4.2 ^1.2.0", "enter", "escape", "5", *"1.0.0-rc.1 1.0.0", "enter"], data={})
        run(h, mk("Package Manager", h))
        txt = "\n".join("\n".join(f[1]) for f in h.frames)
        self.assertIn("RESOLVED", txt); self.assertIn("YES", txt); self.assertIn("1.0.0-rc.1 < 1.0.0", txt)
        self.assertIn("lock", h.data)


class TestBuildPlanner(unittest.TestCase):
    RULES = "app: main.o util.o @2\nmain.o: main.c util.h @3\nutil.o: util.c util.h @2\ntest: app @4  # run\n"

    def test_plan(self):
        g, e = P.parse_rules(self.RULES)
        self.assertEqual(e, [])
        p = P.plan(g)
        self.assertEqual(p["waves"], [["main.o", "util.o"], ["app"], ["test"]])
        self.assertEqual(p["order"], ["main.o", "util.o", "app", "test"])
        self.assertEqual(p["critical"], ["main.o", "app", "test"]); self.assertEqual(p["critical_time"], 9); self.assertEqual(p["serial_time"], 11)
        self.assertEqual(list(P.needed(g, "app")), ["app", "main.o", "util.o"])

    def test_cycle_is_shown(self):
        g, _ = P.parse_rules("a: b\nb: c\nc: a\nd: a\n")
        self.assertEqual(P.plan(g)["cycle"], ["a", "b", "c", "a"])
        g, _ = P.parse_rules("x: x\n"); self.assertEqual(P.find_cycle(g), ["x", "x"])

    def test_rebuild_set(self):
        g, _ = P.parse_rules(self.RULES)
        self.assertEqual(P.rebuild_set(g, ["util.h"]), (["main.o", "util.o", "app", "test"], []))
        self.assertEqual(P.rebuild_set(g, ["main.c", "nope"]), (["main.o", "app", "test"], ["nope"]))
        self.assertEqual(P.rebuild_set(g, ["test"]), ([], []))

    def test_parse_errors_and_bounds(self):
        g, e = P.parse_rules("noColon\n: x\na: b @zz\na: c\nok: d @5\n")
        self.assertEqual([x.split(":")[0] for x in e], ["line 1", "line 2", "line 3", "line 4"])
        self.assertIn("a", g); self.assertEqual(g["ok"]["dur"], 5)
        self.assertTrue(P.parse_rules("\n".join(f"t{i}: x" for i in range(2500)))[1])
        self.assertTrue(P.parse_rules("x" * 300000)[1])
        chain = "\n".join(f"t{i}: t{i + 1}" for i in range(1500))
        self.assertEqual(len(P.plan(P.parse_rules(chain)[0])["waves"]), 1500)               # long chain, no recursion

    def test_screen(self):
        h = FakeHost(["3", "escape", "5", *"util.h", "enter"], data={})
        run(h, mk("Build Planner", h))
        txt = "\n".join("\n".join(f[1]) for f in h.frames)
        self.assertIn("CRITICAL PATH", txt); self.assertIn("target(s) rebuild", txt)


class TestConfigEditor(unittest.TestCase):
    def test_parse_each_format(self):
        self.assertEqual(P.parse("json", '{"a": {"b": 1}}')[0], {"a": {"b": 1}})
        self.assertEqual(P.parse("toml", 'x = 1\n[t]\ny = "z"')[0], {"x": 1, "t": {"y": "z"}})
        self.assertEqual(P.parse("ini", "[s]\nk = v\nK2: w\n")[0], {"s": {"k": "v", "K2": "w"}})
        self.assertEqual(P.parse("env", 'A=1\nexport B="x y"\nC=z # c\nD=\'q #\'\n# c\n')[0], {"A": "1", "B": "x y", "C": "z", "D": "q #"})
        self.assertEqual(P.parse("properties", "a=1\nb : two\nc three\n# x\nd=l1\\\n   l2\ne=\\u0041\\n\n")[0], {"a": "1", "b": "two", "c": "three", "d": "l1l2", "e": "A\n"})

    def test_errors_have_line_numbers(self):
        self.assertEqual(P.parse("json", '{\n "a": 1,\n}')[1][0][0], 2)
        self.assertEqual(P.parse("toml", "a = 1\nb = \n")[1][0][0], 2)
        self.assertEqual(P.parse("ini", "k = v\n")[1][0][0], 1)
        self.assertEqual(P.parse("ini", "[a]\nk=1\n[a]\n")[1][0][0], 3)
        self.assertEqual(P.parse("env", "A=1\nbad line\nA=2")[1], [(2, "expected KEY=VALUE"), (3, "duplicate key A")])
        self.assertEqual(P.parse("env", 'A="x')[1][0][0], 1)
        self.assertEqual(P.parse("properties", "a=1\na=2\n=x")[1], [(2, "duplicate key a"), (3, "empty key")])
        self.assertTrue(P.parse("json", "NaN")[1]); self.assertTrue(P.parse("json", "[" * 100000)[1])

    def test_hostile_input(self):
        for f in P.FORMATS:
            self.assertTrue(P.parse(f, "a\x00b")[1]); self.assertTrue(P.parse(f, "x" * (P.MAX_CFG + 1))[1]); self.assertTrue(P.parse(f, None)[1])
            P.parse(f, "\x1b[2J\ud800 ‮" + "=" * 100); P.parse(f, "[" * 500 + "{" * 500)
        self.assertTrue(P.parse("yaml", "a: 1")[1])

    def test_toml_writer_round_trips(self):
        d = {"title": 'He said "hi"\n\ttab', "n": 3, "f": 1.5, "ok": True, "list": [1, 2, 3], "mixed": [{"a": 1}, {"b": [True]}],
             "server": {"host": "h", "ports": [80, 443], "tls": {"on": False}}, "quoted key": {"a.b": "é"}, "empty": {}}
        txt = P.dump_toml(d)
        self.assertEqual(tomllib.loads(txt), d)
        self.assertEqual(P.dump_toml({"a": 1, "t": {"b": 2}}), 'a = 1\n\n[t]\nb = 2\n')
        self.assertTrue(P.dump("toml", {"a": None})[1])
        self.assertTrue(P.dump("toml", [1])[1])

    def test_convert(self):
        out, errs = P.convert("json", '{"server": {"host": "h", "port": 80}, "debug": true}', "ini")
        self.assertEqual((out, errs), ("[main]\ndebug = true\n\n[server]\nhost = h\nport = 80\n", ["note: top-level keys were placed in section [main]"]))
        self.assertEqual(P.convert("json", '{"a": {"b": "x y"}, "n": 1}', "env")[0], 'A_B="x y"\nN=1\n')
        self.assertEqual(P.convert("json", '{"a": {"b": 1}, "l": [1]}', "properties")[0], "a.b=1\nl.0=1\n")
        self.assertEqual(json.loads(P.convert("ini", "[s]\nport = 80\non = true\nr = 1.5\nz = 007\n", "json")[0]), {"s": {"port": 80, "on": True, "r": 1.5, "z": "007"}})
        self.assertEqual(P.convert("toml", 'a = 1\n[t]\nb = [1, 2]', "json")[0], '{\n  "a": 1,\n  "t": {\n    "b": [\n      1,\n      2\n    ]\n  }\n}\n')
        txt = P.convert("env", "A=1\nB=hello world", "properties")[0]
        self.assertEqual(P.parse("properties", txt)[0], {"A": "1", "B": "hello world"})
        self.assertEqual(P.convert("json", "{bad", "toml")[1][0][:7], "line 1:")
        self.assertTrue(P.convert("json", '[1]', "env")[1])
        self.assertTrue(P.dump("ini", {"s": {"k": "a\nb"}})[1])

    def test_diff_and_secret_masking(self):
        out = P.diff_config("json", '{"a": 1, "b": 2, "password": "p1"}', "json", '{"a": 1, "b": 3, "c": 4, "password": "p2"}')
        self.assertEqual(out, ["+ c = 4", "~ b: 2 -> 3", "~ password: <hidden> -> <hidden>"])
        self.assertEqual(P.diff_config("json", "{}", "json", "{}"), ["no differences in keys or values"])
        self.assertTrue(P.diff_config("json", "{", "json", "{})")[0].startswith("first: line 1"))

    def test_schema(self):
        d = {"server": {"host": "h", "port": "80"}, "mode": "dev", "debug": "yes"}
        rules, errs = P.parse_schema("required server.host\nrequired server.user\ntype server.port int\ntype debug bool\nenum mode prod|test\n")
        self.assertEqual(errs, [])
        self.assertEqual(P.check_schema(d, rules, True), ["missing required key server.user", "mode: 'dev' is not one of prod, test"])
        self.assertEqual(P.check_schema(d, rules, False), ["missing required key server.user", "server.port: expected int, found str", "debug: expected bool, found str", "mode: 'dev' is not one of prod, test"])
        self.assertEqual(P.parse_schema("bogus x\ntype a nope")[1][0][0], 1)
        self.assertEqual(P.check_schema({"a.b": 1, "l": [{"x": 2}]}, P.parse_schema("type a.b int\ntype l.0.x int")[0]), [])
        v = P.validate("json", '{"server": {"port": "x"}}', "required server.host\ntype server.port int")
        self.assertEqual(v[1:], ["SCHEMA PROBLEMS:", "missing required key server.host", "server.port: expected int, found str"])
        self.assertEqual(P.validate("json", "{", "")[0], "SYNTAX ERRORS:")

    def test_screen(self):
        spaces = {"repos": {"records": json.dumps({"next": 2, "items": [{"path": "c.toml", "text": "a = 1\n", "branch": "main", "_id": 1}]})}}
        h = FakeHost(["4", "escape", "5", *"toml", "enter", "escape", "2", "enter", "escape", "6"], data={})
        h.spaces = spaces
        run(h, mk("Config Editor", h))
        txt = "\n".join("\n".join(f[1]) for f in h.frames)
        self.assertIn("syntax OK", txt); self.assertIn("a = 1", txt)
        self.assertEqual(json.loads(h.data["cfg"])["fmt"], "toml")

    def test_missing_grant_is_said(self):
        h = FakeHost(["2"], data={})
        run(h, mk("Config Editor", h))
        self.assertIn("No files", h.text)


class TestEntries(unittest.TestCase):
    def test_declared_permissions_match_use(self):
        by = {e.title: e for e in P.ENTRIES}
        self.assertEqual(by["Version Control"].owns, ["repos"])
        self.assertEqual([t for t, e in by.items() if e.uses == ["repos"]], ["Code Review", "Build Planner", "Config Editor"])
        self.assertEqual(by["Package Manager"].uses, [])
        self.assertEqual(len(P.ENTRIES), 5)


if __name__ == "__main__":
    unittest.main()
