"""pack_org: Semantic Graph and Rule Router. Exact results from known cases, refusals, hostile data, FakeHost runs."""
import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from kos.cli import COMMANDS  # noqa: E402
from kos.office import pack_org as O  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

T0 = "2026-11-07 09:00"
D0 = "2026-11-07"
TITLES = [l.split("\t")[1] for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines()
          if l.strip() and l.split("\t")[0] == "pack_org"]


def graph():
    box = {}
    g = O.Graph(None, lambda s: box.update(saved=json.loads(json.dumps(s))) or True)
    return g, box


def reload(box):
    return O.Graph(json.loads(json.dumps(box["saved"])))


class Catalogue(unittest.TestCase):
    def test_titles_match_the_group_exactly(self):
        self.assertEqual([e.title for e in O.ENTRIES], TITLES)
        self.assertEqual(len(TITLES), 13)

    def test_scopes_and_notes(self):
        for e in O.ENTRIES:
            self.assertIn(e.scope, ("partial", "none"), e.title)      # nothing here claims to be complete
            self.assertTrue(60 <= len(e.note) <= 300, (e.title, len(e.note)))
        self.assertEqual([e.title for e in O.ENTRIES if e.scope == "partial"], ["Semantic Graph", "Rule Router"])

    def test_every_named_command_exists(self):
        for e in O.ENTRIES:
            for cmd in re.findall(r"`kos (\w+)", e.note):
                self.assertIn(cmd, COMMANDS, (e.title, cmd))

    def test_apps_ask_for_storage_only(self):
        for e in O.ENTRIES:
            if e.scope != "none":
                self.assertFalse(e.network or e.owns or e.uses, e.title)


class Content(unittest.TestCase):
    def test_same_content_is_stored_once(self):
        g, _ = graph()
        a, b, c = (g.add(t, T0, body="the same text") for t in ("A", "B", "C"))
        d = g.add("D", T0, body="other")
        self.assertEqual(len(g.s["blobs"]), 2)
        self.assertEqual(g.nodes[a]["sha"], O.sha("the same text"))
        self.assertEqual(g.shared_with(g.nodes[a]), [b, c])
        st = g.stats()
        self.assertEqual((st["nodes"], st["distinct"], st["saved"]), (4, 2, 2 * len("the same text")))
        self.assertEqual(g.query("sha:" + O.sha("other")[:8], D0), [d])

    def test_old_content_is_kept_for_history_and_new_content_is_hashed(self):
        g, _ = graph()
        i = g.add("N", T0, body="v1")
        g.set_body(i, "v2", "2026-11-08 10:00")
        self.assertEqual(g.body(g.nodes[i]), "v2")
        self.assertEqual([h["kept"] for h in g.history(i)], [True, True])      # v1 is still in the history
        self.assertEqual(len({h["sha"] for h in g.history(i)}), 2)

    def test_a_body_that_does_not_hash_to_its_key_is_dropped_on_load(self):
        g, box = graph()
        i = g.add("N", T0, body="real")
        raw = json.loads(json.dumps(box["saved"]))
        raw["blobs"][O.sha("real")] = "forged"
        g2 = O.Graph(raw)
        self.assertFalse(g2.body_ok(g2.nodes[i]))
        self.assertEqual(g2.body(g2.nodes[i]), "")

    def test_content_limits_and_control_characters(self):
        g, _ = graph()
        with self.assertRaises(O.GraphError):
            g.add("N", T0, body="x" * (O.MAX_BODY + 1))
        with self.assertRaises(O.GraphError):
            g.add("   ", T0)
        with self.assertRaises(O.GraphError):
            g.add("N", T0, body=b"bytes")
        i = g.add("a\x1b[2Jb\x00", T0, body="x\x1b[31my\x07")
        self.assertEqual(g.nodes[i]["title"], "a[2Jb")
        self.assertEqual(g.body(g.nodes[i]), "x[31my")

    def test_blob_store_is_bounded_and_a_refusal_changes_nothing(self):
        g, box = graph()
        with self.assertRaises(O.GraphError):
            for n in range(100):
                g.add(f"n{n}", T0, body=f"{n:03d}" + "x" * 3890)       # about 100,000 characters in all
        self.assertLess(len(g.nodes), 100)
        before = json.dumps(g.s, sort_keys=True)
        with self.assertRaises(O.GraphError):
            g.add("one more", T0, body="z" * 3900)
        self.assertEqual(json.dumps(g.s, sort_keys=True), before)
        self.assertEqual(json.dumps(box["saved"], sort_keys=True), before)


class Dependencies(unittest.TestCase):
    def make(self):
        g, _ = graph()
        ids = [g.add(t, T0, "task") for t in "ABCD"]            # n1..n4
        return g, ids

    def test_cycles_are_refused_directly_and_through_a_chain(self):
        g, (a, b, c, d) = self.make()
        g.add_dep(b, a, T0)
        g.add_dep(c, b, T0)
        for x, y in ((a, a), (a, b), (a, c)):
            with self.assertRaises(O.GraphError, msg=(x, y)):
                g.add_dep(x, y, T0)
        with self.assertRaises(O.GraphError):
            g.add_dep(c, b, T0)                                  # duplicate
        self.assertEqual(g.nodes[a]["deps"], [])
        g.add_dep(d, a, T0)
        g.add_dep(d, c, T0)                                      # a diamond is fine

    def test_unknown_ids_and_limits(self):
        g, (a, b, c, d) = self.make()
        with self.assertRaises(O.GraphError):
            g.add_dep(a, "n99", T0)
        with self.assertRaises(O.GraphError):
            g.add_dep("../x", a, T0)

    def test_toposort_is_deterministic_and_puts_dependencies_first(self):
        g, (a, b, c, d) = self.make()
        g.add_dep(a, d, T0)
        g.add_dep(b, d, T0)
        g.add_dep(c, a, T0)
        self.assertEqual(g.toposort(), ["n4", "n1", "n2", "n3"])

    def test_remove_refuses_while_depended_on_and_cleans_relations(self):
        g, (a, b, c, d) = self.make()
        g.add_dep(b, a, T0)
        g.add_rel(c, "see-also", a, T0)
        with self.assertRaises(O.GraphError):
            g.remove(a, T0)
        g.drop_dep(b, a, T0)
        g.remove(a, T0)
        self.assertNotIn(a, g.nodes)
        self.assertEqual(g.nodes[c]["rels"], [])
        self.assertTrue(g.verify()[0])
        self.assertEqual(g.history(a)[-1]["op"], "del")

    def test_relations_are_validated(self):
        g, (a, b, c, d) = self.make()
        for label in ("", "Has Space", "x" * 40, "9x"):
            with self.assertRaises(O.GraphError, msg=label):
                g.add_rel(a, label, b, T0)
        g.add_rel(a, "see-also", b, T0)
        with self.assertRaises(O.GraphError):
            g.add_rel(a, "see-also", b, T0)
        self.assertEqual(g.query(f"rel:{b}", D0), [a])
        self.assertEqual(g.query(f"rel:{a}", D0), [b])


class Planning(unittest.TestCase):
    def build(self):
        # A(3) -> B(2) -> D(1);  A -> C(4) -> D ;  E(2) alone.  Critical path A C D = 3+4+1 = 8 days.
        g, _ = graph()
        spec = [("A", 3), ("B", 2), ("C", 4), ("D", 1), ("E", 2)]
        ids = {}
        for t, days in spec:
            ids[t] = g.add(t, T0, "task")
            g.set_field(ids[t], "days", str(days), T0)
        g.add_dep(ids["B"], ids["A"], T0)
        g.add_dep(ids["C"], ids["A"], T0)
        g.add_dep(ids["D"], ids["B"], T0)
        g.add_dep(ids["D"], ids["C"], T0)
        return g, ids

    def test_critical_path_slack_and_dates(self):
        g, ids = self.build()
        p = g.plan("2026-11-07")
        r = p["rows"]
        self.assertEqual(p["end"], 8)
        self.assertEqual(p["finish"], "2026-11-14")
        self.assertEqual(p["critical"], [ids["A"], ids["C"], ids["D"]])
        self.assertEqual((r[ids["B"]]["es"], r[ids["B"]]["ef"], r[ids["B"]]["slack"]), (3, 5, 2))
        self.assertEqual((r[ids["D"]]["es"], r[ids["D"]]["ef"], r[ids["D"]]["slack"]), (7, 8, 0))
        self.assertEqual(r[ids["E"]]["slack"], 6)                          # E could slip until day 8
        self.assertEqual((r[ids["A"]]["start"], r[ids["A"]]["finish"]), ("2026-11-07", "2026-11-09"))

    def test_due_dates_and_finished_tasks(self):
        g, ids = self.build()
        g.set_field(ids["D"], "due", "2026-11-13", T0)
        self.assertEqual(g.plan("2026-11-07")["late"], [ids["D"]])
        g.set_field(ids["D"], "due", "2026-11-14", T0)
        self.assertEqual(g.plan("2026-11-07")["late"], [])
        g.set_field(ids["A"], "status", "done", T0)                        # a finished task no longer holds anything up
        p = g.plan("2026-11-07")
        self.assertEqual(p["end"], 5)
        self.assertNotIn(ids["A"], p["rows"])

    def test_no_tasks_and_bad_start(self):
        g, _ = graph()
        self.assertEqual(g.plan(D0)["order"], [])
        with self.assertRaises(O.GraphError):
            g.plan("tomorrow")

    def test_a_task_with_no_days_counts_as_one(self):
        g, _ = graph()
        i = g.add("T", T0, "task")
        self.assertEqual(g.plan(D0)["end"], 1)
        self.assertEqual(g.plan(D0)["rows"][i]["finish"], D0)


class Queries(unittest.TestCase):
    def build(self):
        g, _ = graph()
        a = g.add("Write report", "2026-11-06 08:00", "task", body="quarterly numbers")
        b = g.add("Call Ann", "2026-11-07 08:00", "person")
        c = g.add("Budget", "2026-11-07 09:30", "note", body="report draft")
        g.set_field(a, "project", "Alpha", "2026-11-06 08:05")
        g.set_field(c, "project", "alpha", "2026-11-07 09:31")
        g.set_field(c, "tags", "finance, urgent", "2026-11-07 09:32")
        g.set_field(a, "status", "doing", "2026-11-06 08:06")
        g.set_field(c, "valid_from", "2026-01-01", "2026-11-07 09:33")
        g.set_field(c, "valid_to", "2026-06-30", "2026-11-07 09:34")
        g.add_dep(a, c, "2026-11-06 08:07")
        return g, a, b, c

    def test_filters(self):
        g, a, b, c = self.build()
        q = lambda s: g.query(s, D0)
        self.assertEqual(q(""), [a, b, c])
        self.assertEqual(q("project:alpha"), [a, c])
        self.assertEqual(q("project:alpha edited:today"), [c])         # the example from the blueprint
        self.assertEqual(q("edited:2026-11-06"), [a])
        self.assertEqual(q("created:2026-11"), [a, b, c])
        self.assertEqual(q("kind:task status:doing"), [a])
        self.assertEqual(q("-project:alpha"), [b])
        self.assertEqual(q("tag:urgent"), [c])
        self.assertEqual(q("report"), [a, c])                          # title or content
        self.assertEqual(q("report -status:doing"), [c])
        self.assertEqual(q("depends:" + c), [a])
        self.assertEqual(q("needs:" + a), [c])
        self.assertEqual(q("REPORT"), [a, c])

    def test_temporal_validity(self):
        g, a, b, c = self.build()
        self.assertEqual(g.query("valid:2026-03-01", D0), [a, b, c])
        self.assertEqual(g.query("valid:2026-07-01", D0), [a, b])
        self.assertEqual(g.query("valid:today", D0), [a, b])
        with self.assertRaises(O.GraphError):
            g.set_field(c, "valid_from", "2026-12-01", T0)                # after valid_to

    def test_the_index_is_never_stale(self):
        g, a, b, c = self.build()
        self.assertEqual(g.query("project:beta", D0), [])
        g.set_field(b, "project", "beta", T0)
        self.assertEqual(g.query("project:beta", D0), [b])
        g.set_field(b, "project", "alpha", T0)
        self.assertEqual(g.query("project:beta", D0), [])
        g.remove(b, T0)
        self.assertEqual(g.query("kind:person", D0), [])

    def test_bad_queries_are_refused_not_ignored(self):
        g, *_ = self.build()
        for q in ("nope:x", "project:", "edited:yesterday", "valid:2026-13-45", "depends:../x", "sha:ab",
                  "a b c d e f g h i j k l m", "x" * 5):
            if q == "x" * 5:
                self.assertEqual(g.query(q, D0), [])
                continue
            with self.assertRaises(O.GraphError, msg=q):
                g.query(q, D0)

    def test_hostile_query_text(self):
        g, *_ = self.build()
        self.assertEqual(g.query("\x1b[2J\x00 " + "q" * 10000, D0), [])


class Fields(unittest.TestCase):
    def test_field_parsing(self):
        P = O.parse_field
        self.assertEqual(P("tags", "B, a  c,a"), ["b", "a", "c"])
        self.assertEqual(P("days", "12"), 12)
        self.assertEqual(P("due", "+3", D0), "2026-11-10")
        self.assertEqual(P("due", "today", D0), D0)
        self.assertEqual(P("due", "", D0), "")
        self.assertEqual(P("from", "2026-02-03"), "2026-02-03")
        for name, bad in (("days", "-1"), ("days", "366"), ("days", "1e3"), ("days", "x"), ("kind", "folder"),
                          ("status", "dead"), ("project", "A B"), ("project", "x" * 30), ("due", "2026-02-30"),
                          ("tags", ",".join(f"t{i}" for i in range(11))), ("tags", "bad!"), ("color", "red"),
                          ("title", " ")):
            with self.assertRaises(O.GraphError, msg=(name, bad)):
                P(name, bad, D0)


class History(unittest.TestCase):
    def test_chain_verifies_survives_a_reload_and_detects_edits(self):
        g, box = graph()
        i = g.add("N", "2026-11-01 08:00", body="one")
        g.set_body(i, "two", "2026-11-02 08:00")
        g.set_field(i, "title", "Renamed", "2026-11-03 08:00")
        self.assertEqual(g.verify(), (True, -1))
        g2 = reload(box)
        self.assertEqual(g2.verify(), (True, -1))
        raw = json.loads(json.dumps(box["saved"]))
        raw["log"][1]["node"]["title"] = "forged"
        self.assertEqual(O.Graph(raw).verify(), (False, 1))
        raw = json.loads(json.dumps(box["saved"]))
        del raw["log"][1]
        self.assertFalse(O.Graph(raw).verify()[0])

    def test_as_of_a_date(self):
        g, _ = graph()
        i = g.add("Old", "2026-11-01 08:00")
        g.set_field(i, "title", "New", "2026-11-03 08:00")
        j = g.add("Other", "2026-11-04 08:00")
        g.remove(j, "2026-11-05 08:00")
        self.assertEqual(g.asof("2026-10-31"), {})
        self.assertEqual(g.asof("2026-11-02")[i]["title"], "Old")
        self.assertEqual(g.asof("2026-11-03")[i]["title"], "New")
        self.assertEqual(sorted(g.asof("2026-11-04")), [i, j])
        self.assertEqual(sorted(g.asof("2026-11-05")), [i])
        with self.assertRaises(O.GraphError):
            g.asof("last week")

    def test_old_history_is_folded_and_the_chain_still_verifies(self):
        g, box = graph()
        i = g.add("N", "2026-01-01 08:00")
        for k in range(O.MAX_LOG + 10):
            g.set_field(i, "days", str(k % 300), f"2026-02-{1 + k // 20:02d} 08:{k % 60:02d}")
        self.assertLessEqual(len(g.s["log"]), O.MAX_LOG)
        self.assertTrue(g.s["base"]["at"])
        self.assertEqual(g.verify(), (True, -1))
        self.assertEqual(reload(box).verify(), (True, -1))
        self.assertEqual(g.asof("2026-02-28")[i]["title"], "N")
        with self.assertRaises(O.GraphError):
            g.asof("2026-01-01")                                           # folded away: refused, not guessed
        self.assertLess(g.stats()["bytes"], O.MAX_STORE)


class Hostile(unittest.TestCase):
    def test_garbage_state_gives_an_empty_valid_graph(self):
        for raw in (None, 5, "x", [], {"nodes": 5}, {"nodes": {"n1": 5}}, {"nodes": {"n1": {"id": "n1"}}},
                    {"nodes": [], "blobs": 1, "log": "x", "base": []}):
            g = O.Graph(raw)
            self.assertEqual(g.nodes, {})
            self.assertEqual(g.query("", D0), [])

    def test_a_hostile_graph_is_cleaned_cycles_dropped(self):
        sh = O.sha("")
        mk = lambda i, **kw: {"id": i, "title": "t\x1b" + i, "sha": sh, **kw}
        raw = {"nodes": {"n1": mk("n1", deps=["n2", "n1", "../etc", 5], kind="weird", days=10 ** 9),
                         "n2": mk("n2", deps=["n3"], tags=["A"] * 50, project="Bad Name!"),
                         "n3": mk("n3", deps=["n1", "n9"], rels=[["x", "n1"], ["BAD", "n1"], ["y", "n77"]]),
                         "n4": {"id": "n3", "title": "id mismatch", "sha": sh}},
               "next": -5}
        g = O.Graph(raw)
        self.assertEqual(sorted(g.nodes), ["n1", "n2", "n3"])
        g.toposort()                                                       # raises if any cycle survived
        self.assertTrue(all(n["kind"] == "note" and n["days"] == 0 for n in g.nodes.values()))
        self.assertEqual(g.nodes["n1"]["title"], "tn1")
        self.assertEqual(g.nodes["n2"]["tags"], ["a"])
        self.assertEqual(g.nodes["n2"]["project"], "badname")
        self.assertEqual(g.nodes["n3"]["rels"], [["x", "n1"]])
        self.assertGreaterEqual(g.s["next"], 4)
        g.add("fine", T0)

    def test_unreadable_saved_data_is_never_overwritten(self):
        host = FakeHost(["enter", "n", "x", "enter"], data={"graph": "{not json"})
        run(host, O.ENTRIES[0].args["make"](host, O.ENTRIES[0]))
        self.assertEqual(host.data["graph"], "{not json")
        self.assertIn("could not be read", "\n".join("\n".join(f[1]) for f in host.frames))

    def test_a_failed_save_changes_nothing(self):
        g = O.Graph(None, lambda s: False)
        with self.assertRaises(O.GraphError):
            g.add("N", T0)
        self.assertEqual(g.nodes, {})


class Rules(unittest.TestCase):
    CFG = ("# comment\n"
           "rule deep: on enter:deep-work then set alerts=muted ; set view=pivot ; log entered\n"
           "rule late: on enter:review if alerts=muted and hour>=18 then log too late\n"
           "rule early: on enter:review if alerts=muted and hour<18 then set pinged=yes\n"
           "rule out: on leave:deep-work then set alerts=on ; unset view\n")

    def test_parse_and_fire_with_exact_results(self):
        rules = O.parse_rules(self.CFG)
        self.assertEqual([r["name"] for r in rules], ["deep", "late", "early", "out"])
        st, tr = O.fire(rules, {}, "enter:deep-work")
        self.assertEqual(st, {"alerts": "muted", "view": "pivot"})
        self.assertEqual([k for k, _ in tr], ["match", "set", "set", "log"])
        st, tr = O.fire(rules, {**st, "hour": "19"}, "enter:review")
        self.assertEqual(st["alerts"], "muted")
        self.assertNotIn("pinged", st)
        self.assertIn(("log", "too late"), tr)
        st2, tr = O.fire(rules, {**st, "hour": "9"}, "enter:review")
        self.assertEqual(st2["pinged"], "yes")
        st3, _ = O.fire(rules, st, "leave:deep-work")
        self.assertEqual(st3["alerts"], "on")
        self.assertNotIn("view", st3)
        _, tr = O.fire(rules, {}, "nothing:here")
        self.assertEqual(tr, [("skip", "no rule listens for nothing:here")])

    def test_conditions(self):
        H = O.holds
        self.assertTrue(H((False, "a", "=", "5"), {"a": "5.0"}))
        self.assertTrue(H((False, "a", "!=", "x"), {"a": "y"}))
        self.assertTrue(H((False, "a", ">", "2"), {"a": "10"}))
        self.assertFalse(H((False, "a", ">", "2"), {"a": "abc"}))
        self.assertFalse(H((False, "a", ">", "2"), {}))
        self.assertTrue(H((True, "a", None, None), {}))
        self.assertTrue(H((False, "a", None, None), {"a": "x"}))
        self.assertFalse(H((False, "a", None, None), {"a": ""}))
        self.assertFalse(H((False, "a", "<", "nan"), {"a": "1"}))

    def test_a_rule_loop_is_cut_short(self):
        rules = O.parse_rules("rule a: on x then fire y\nrule b: on y then fire x\n")
        st, tr = O.fire(rules, {}, "x")
        self.assertEqual(tr[-1][0], "stop")
        self.assertLessEqual(len(tr), 3 * O.MAX_DEPTH + 2)
        big = "\n".join(f"rule r{i}: on go then " + " ; ".join(f"set k{i}{j}=1" for j in range(5)) for i in range(40))
        st, tr = O.fire(O.parse_rules(big), {}, "go")
        self.assertLessEqual(len(st), O.MAX_STATE)
        self.assertTrue(any(k == "stop" for k, _ in tr))

    def test_bad_configs_are_refused_with_the_line_number(self):
        for text, line in (("rule a: on x then explode now", 1), ("\n\nrule a on x then log hi", 3),
                           ("rule a: on x then log hi\nrule a: on y then log hi", 2),
                           ("rule a: on X! then log hi", 1), ("rule a: on x if then log hi", 1),
                           ("rule a: on x if not a=b then log hi", 1), ("rule a: on x then set k", 1),
                           ("rule a: on x then set K=1", 1), ("rule a: on x then log \x1b[2J", 1),
                           ("rule a: on x then " + "; ".join(["log a"] * 9), 1), ("rule a: on x then ;", 1)):
            with self.assertRaises(O.ConfigError, msg=text) as cm:
                O.parse_rules(text)
            self.assertIn(f"line {line}:", str(cm.exception), text)
        with self.assertRaises(O.ConfigError):
            O.parse_rules("x" * (O.MAX_CONFIG + 1))
        with self.assertRaises(O.ConfigError):
            O.parse_rules("\n" * O.MAX_LINES)
        with self.assertRaises(O.ConfigError):
            O.parse_rules("\n".join(f"rule r{i}: on x then log a" for i in range(O.MAX_RULES + 1)))

    def test_nothing_in_a_config_can_run_code(self):
        # Every verb is on a fixed list; text that looks like code is just text in a log line.
        rules = O.parse_rules("rule a: on x then log __import__('os').system('id') ; set k=$(id)")
        st, tr = O.fire(rules, {}, "x")
        self.assertEqual(st, {"k": "$(id)"})
        with self.assertRaises(O.ConfigError):
            O.parse_rules("rule a: on x then exec ls")

    def test_the_example_config_is_valid(self):
        self.assertEqual(len(O.parse_rules(O.EXAMPLE_RULES)), 3)


class ConfigVersions(unittest.TestCase):
    def test_versions_are_append_only_hashed_and_rollback_adds_a_version(self):
        v = O.Versions()
        self.assertEqual(v.save("rule a: on x then log one", T0), 1)
        self.assertEqual(v.save("rule a: on x then log one\n", T0), 0)       # unchanged: no new version
        self.assertEqual(v.save("rule a: on x then log two", T0), 2)
        self.assertEqual(v.rollback(1, T0), 3)
        self.assertEqual(v.latest(), "rule a: on x then log one")
        self.assertEqual([x["n"] for x in v.items], [1, 2, 3])
        self.assertEqual(v.items[1]["text"], "rule a: on x then log two")    # version 2 is still there
        self.assertTrue(v.verify())
        self.assertEqual(v.items[1]["h"], O.version_hash(v.items[0]["h"], v.items[1]["text"]))
        self.assertTrue(O.Versions(json.loads(json.dumps(v.dump()))).verify())
        raw = json.loads(json.dumps(v.dump()))
        raw["items"][0]["text"] = "rule a: on x then log forged"
        self.assertFalse(O.Versions(raw).verify())
        with self.assertRaises(O.ConfigError):
            v.rollback(99, T0)

    def test_an_invalid_config_is_not_saved(self):
        v = O.Versions()
        v.save("rule a: on x then log one", T0)
        with self.assertRaises(O.ConfigError):
            v.save("rule a: on x then nonsense", T0)
        self.assertEqual(len(v.items), 1)

    def test_old_versions_fall_off_and_the_chain_still_checks(self):
        v = O.Versions()
        for k in range(O.MAX_VERSIONS + 5):
            v.save(f"rule a: on x then log v{k}", T0)
        self.assertEqual(len(v.items), O.MAX_VERSIONS)
        self.assertEqual(v.items[-1]["n"], O.MAX_VERSIONS + 5)
        self.assertTrue(v.verify())
        self.assertTrue(O.Versions(json.loads(json.dumps(v.dump()))).verify())

    def test_garbage_version_data(self):
        for raw in (None, 5, {"items": 5}, {"items": [5, {"n": "x"}]}, {"base": 5}):
            self.assertEqual(O.Versions(raw).items, [])


# ---------------------------------------------------------------- the screens ----
def drive(entry_title, keys, data=None, **kw):
    e = next(e for e in O.ENTRIES if e.title == entry_title)
    host = FakeHost(keys, data=data, width=100, height=30, **kw)
    run(host, e.args["make"](host, e))
    return host


def saved_graph(host):
    return O.Graph(json.loads(host.data["graph"]))


class GraphScreens(unittest.TestCase):
    def test_opening_and_looking_writes_nothing(self):
        h = drive("Semantic Graph", ["enter", "enter", "escape", "escape", "down", "enter", "escape", "escape"])
        self.assertEqual(h.data, {})
        self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t])

    def test_new_node_edit_fields_link_and_query_through_the_screens(self):
        keys = ["down", "enter", *"task: Write plan", "enter",                 # New node
                "f", *"project=alpha", "enter", "f", *"days=3", "enter", "f", *"tags=a,b", "enter",
                "e", *"hello body", "ctrl-s", "escape",
                "escape", "up",
                "enter", *"project:alpha", "enter"]                           # Browse
        h = drive("Semantic Graph", keys)
        g = saved_graph(h)
        n = g.nodes["n1"]
        self.assertEqual((n["kind"], n["title"], n["project"], n["days"], n["tags"]), ("task", "Write plan", "alpha", 3, ["a", "b"]))
        self.assertEqual(g.body(n), "hello body")
        self.assertIn("1 found", h.text)
        self.assertIn("Write plan", h.text)
        self.assertEqual(g.verify(), (True, -1))

    def test_a_cycle_through_the_screen_is_refused_and_says_so(self):
        g, box = graph()
        a, b = g.add("A", T0), g.add("B", T0)
        g.add_dep(b, a, T0)
        data = {"graph": json.dumps(box["saved"])}
        h = drive("Semantic Graph", ["enter", "enter", "enter", "d", *"n2", "enter"], data=data)     # open n1, make it need n2
        self.assertIn("cycle", h.text)
        self.assertEqual(saved_graph(h).nodes["n1"]["deps"], [])

    def test_plan_matrix_storage_asof_and_help_screens_draw(self):
        g, box = graph()
        a, b = g.add("A", "2026-11-01 08:00", "task"), g.add("B", "2026-11-01 08:00", "task")
        g.set_field(a, "days", "2", T0)
        g.add_dep(b, a, T0)
        g.set_field(a, "project", "alpha", T0)
        data = {"graph": json.dumps(box["saved"])}
        h = drive("Semantic Graph", ["down", "down", "enter", *"2026-11-07", "enter"], data=data)
        self.assertIn("CRITICAL", h.text)
        self.assertIn("Finishes 2026-11-09", h.text)
        h = drive("Semantic Graph", ["down", "down", "down", "enter"], data=data)
        self.assertIn("alpha", h.text)
        h = drive("Semantic Graph", ["down", "down", "down", "down", "down", "enter"], data=data)
        self.assertIn("chain: ok", h.text)
        h = drive("Semantic Graph", ["down", "down", "down", "down", "enter", *"2026-11-02", "enter"], data=data)
        self.assertIn("2 nodes at the end of 2026-11-02", h.text)
        h = drive("Semantic Graph", ["down", "down", "down", "down", "down", "down", "enter"], data=data)
        self.assertIn("edited:today", h.text)

    def test_hostile_keys_and_a_damaged_vault_do_not_crash(self):
        evil = "\x1b[2J" + "A" * 5000
        for data in ({}, {"graph": "[1,2]"}, {"graph": json.dumps({"nodes": {"n1": {"id": "n1", "title": evil, "sha": "0" * 64}}})}):
            keys = ["enter", *evil[:60], "enter", "escape", "n", *evil[:30], "enter", "f", "x", "enter", "e", "z", "escape", "escape", "x", "y"]
            h = drive("Semantic Graph", keys, data=dict(data))
            self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], data)


class RouterScreens(unittest.TestCase):
    def test_edit_save_fire_and_read_back_the_state(self):
        e = next(e for e in O.ENTRIES if e.title == "Rule Router")
        host = FakeHost(["enter", "ctrl-s", "escape", "down", "enter", *"enter:deep-work", "enter", "escape", "down", "enter"], width=100, height=30)
        run(host, e.args["make"](host, e))
        saved = json.loads(host.data["rules"])
        self.assertEqual(len(saved["versions"]["items"]), 1)                 # the example config was saved as version 1
        self.assertEqual(saved["state"], {"alerts": "muted", "view": "pivot"})
        self.assertIn("alerts = muted", host.text)
        self.assertTrue(O.Versions(saved["versions"]).verify())

    def test_a_bad_config_shows_the_line_and_saves_nothing(self):
        host = drive("Rule Router", ["enter", "x", "ctrl-s"])
        self.assertNotIn("rules", host.data)
        self.assertIn("line 1", host.text)

    def test_hostile_state_in_the_vault_is_cleaned(self):
        data = {"rules": json.dumps({"versions": 5, "state": {"ok": "1", "BAD KEY": "x", "n": 5, "long": "x" * 100},
                                     "runlog": [1, "fine", {"a": 1}]})}
        host = drive("Rule Router", ["down", "down", "enter", "escape", "down", "enter"], data=data)
        self.assertIn("ok = 1", "\n".join("\n".join(f[1]) for f in host.frames))
        self.assertNotIn("BAD KEY", "\n".join("\n".join(f[1]) for f in host.frames))
        self.assertFalse([t for t, _l, _s in host.frames if "Internal error" in t])


if __name__ == "__main__":
    unittest.main()
