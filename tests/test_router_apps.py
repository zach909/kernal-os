"""The router group (``apps/router``): router.islands finds the islands in a 0/1 network, router.plan chooses
local or cloud, the effort and how many islands run. Two separate apps sharing the ``router`` folder.

Imports only what stands on its own, so it runs even where the OS package does not import (see the note on the
proof-gate test). The apps are driven through their real ``main()`` with a fake SDK. Nothing here proves a
model gets faster or better: it proves the island finder finds the islands a brute-force search finds, that
the gating never runs fewer than one or more than all, and that hostile input is refused."""

import ast
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
GROUP = ROOT / "apps" / "router"
SPACE_PERM_RE = re.compile(r"^(owns|uses):[a-z][a-z0-9-]{0,31}$")   # the same pattern kos/kapp.py uses


def load(prog):
    spec = importlib.util.spec_from_file_location(f"router_{prog}", GROUP / prog / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ISL, PLAN = load("islands"), load("plan")


class FakeApp:
    """Stands in for kos.sdk.App. It has no ask/service/request: a program that tried to send the prompt out
    would fail with AttributeError, so every run below also shows nothing is sent."""

    def __init__(self, store=None, events=(), refuse=False):
        self.store, self._events, self.refuse = dict(store or {}), list(events), refuse
        self.width, self.height, self.screens, self.exited = 80, 24, [], False

    def events(self):
        yield from self._events

    def vault_get(self, key, space=None):
        assert space == "router"
        return self.store.get(key)

    def vault_put(self, key, value, space=None):
        assert space == "router"
        if self.refuse:
            return False
        self.store[key] = value
        return True

    def screen(self, title, lines, status=""):
        self.screens.append("\n".join(lines))

    def exit(self, code=0):
        self.exited = True


def drive(mod, **kw):
    app = FakeApp(**kw)
    mod.App = lambda: app
    mod.main()
    return app


def keys(*ks):
    return [{"cmd": "hello"}] + [{"cmd": "key", "key": k} for k in ks]


def typed(text):
    return [("space" if c == " " else "enter" if c == "\n" else c) for c in text]


def reference_islands(layers, t):
    """Brute force: breadth-first search over units, written separately from the app's union-find."""
    sizes = [len(layers[0])] + [len(m[0]) for m in layers]
    adj = {}
    for li, m in enumerate(layers):
        for r, row in enumerate(m):
            for c, w in enumerate(row):
                if abs(w) > t:
                    a, b = (li, r), (li + 1, c)
                    adj.setdefault(a, []).append(b)
                    adj.setdefault(b, []).append(a)
    seen, found = set(), []
    for start in sorted(adj):
        if start in seen:
            continue
        seen.add(start)
        todo, comp = [start], []
        while todo:
            n = todo.pop()
            comp.append(n)
            for o in adj[n]:
                if o not in seen:
                    seen.add(o)
                    todo.append(o)
        edges = sum(1 for li, m in enumerate(layers) for r, row in enumerate(m) for c, w in enumerate(row)
                    if abs(w) > t and (li, r) in set(comp))
        found.append((edges, len(comp)))
    return sorted(found, reverse=True), sum(sizes) - len(adj)


class Lcg:
    """A small deterministic random source (a test must not depend on luck)."""
    def __init__(self, seed):
        self.s = seed

    def next(self, n):
        self.s = (self.s * 1103515245 + 12345) % (1 << 31)
        return (self.s >> 8) % n


class TestIslandFinder(unittest.TestCase):
    def test_matches_a_brute_force_search_on_many_networks(self):
        rng = Lcg(7)
        for _ in range(300):
            depth = 1 + rng.next(4)
            sizes = [1 + rng.next(7) for _ in range(depth + 1)]
            density = 1 + rng.next(6)           # out of 12: sparse networks have many islands
            layers = [[[(1 + rng.next(9)) * (1 if rng.next(2) else -1) if rng.next(12) < density else 0
                        for _ in range(sizes[i + 1])] for _ in range(sizes[i])] for i in range(depth)]
            got, dead = ISL.find_islands(ISL.binarize(layers, 0))
            want, want_dead = reference_islands(layers, 0)
            self.assertEqual(sorted(((i["edges"], i["units"]) for i in got), reverse=True), want)
            self.assertEqual(dead, want_dead)

    def test_a_dense_network_is_one_island_and_says_nothing_can_be_turned_off(self):
        layers = [[[5] * 6 for _ in range(6)] for _ in range(3)]
        isl, dead = ISL.find_islands(ISL.binarize(layers, 0))
        self.assertEqual((len(isl), dead), (1, 0))
        net = json.dumps({"threshold": 0, "layers": layers})
        app = drive(ISL, store={"net": net}, events=keys("l"))
        self.assertIn("ONE island", app.screens[-1])

    def test_the_threshold_decides_what_a_connection_is(self):
        layers = [[[1, 0], [0, 9]]]
        self.assertEqual(len(ISL.find_islands(ISL.binarize(layers, 0))[0]), 2)
        self.assertEqual(len(ISL.find_islands(ISL.binarize(layers, 1))[0]), 1)
        self.assertEqual(ISL.find_islands(ISL.binarize(layers, 9))[0], [])

    def test_islands_are_ordered_biggest_first_and_the_order_never_changes(self):
        t, layers = ISL.parse_net(ISL.demo_net())
        a = ISL.find_islands(ISL.binarize(layers, t))
        self.assertEqual(a, ISL.find_islands(ISL.binarize(layers, t)))
        edges = [i["edges"] for i in a[0]]
        self.assertEqual(edges, sorted(edges, reverse=True))
        self.assertEqual((len(a[0]), a[1]), (2, 3))

    def test_keeping_islands_costs_a_growing_share_that_ends_at_100(self):
        isl = [{"edges": e} for e in (50, 30, 10, 6, 4)]
        costs = [ISL.keep_cost(isl, k) for k in range(0, 6)]
        self.assertEqual(costs, sorted(costs))
        self.assertEqual((costs[0], costs[-1]), (0, 100))
        self.assertEqual(ISL.keep_cost([], 3), 0)


class TestIslandsRefuseHostileNetworks(unittest.TestCase):
    def refused(self, text):
        with self.assertRaises(ISL.NetError, msg=str(text)[:60]):
            ISL.parse_net(text)

    def test_every_malformed_network_is_refused_before_use(self):
        good = [[1, 0], [0, 1]]
        for bad in (None, 5, "", "not json", "[]", "{}", "NaN",
                    json.dumps({"threshold": 0}), json.dumps({"threshold": 0, "layers": [good], "x": 1}),
                    json.dumps({"threshold": -1, "layers": [good]}),
                    json.dumps({"threshold": 1.5, "layers": [good]}),
                    json.dumps({"threshold": True, "layers": [good]}),
                    json.dumps({"threshold": 0, "layers": []}),
                    json.dumps({"threshold": 0, "layers": "x"}),
                    json.dumps({"threshold": 0, "layers": [[]]}),
                    json.dumps({"threshold": 0, "layers": [[[]]]}),
                    json.dumps({"threshold": 0, "layers": [[[1, 2], [3]]]}),                  # ragged
                    json.dumps({"threshold": 0, "layers": [[[1.5, 0], [0, 1]]]}),              # a decimal weight
                    json.dumps({"threshold": 0, "layers": [[[True, 0], [0, 1]]]}),             # a bool is not a number here
                    json.dumps({"threshold": 0, "layers": [[["1", 0], [0, 1]]]}),
                    json.dumps({"threshold": 0, "layers": [[[10 ** 12, 0], [0, 1]]]}),
                    json.dumps({"threshold": 0, "layers": [good, [[1, 0]] * 3]}),             # does not chain
                    '{"threshold": 0, "layers": [[[NaN, 0], [0, 1]]]}',
                    '{"threshold": 0, "layers": [[[Infinity, 0], [0, 1]]]}'):
            self.refused(bad)

    def test_size_limits_hold(self):
        self.refused(json.dumps({"threshold": 0, "layers": [[[1]]] * (ISL.MAX_LAYERS + 1)}))
        self.refused(json.dumps({"threshold": 0, "layers": [[[1] * (ISL.MAX_UNITS + 1)]]}))
        self.refused("x" * (ISL.MAX_NET_CHARS + 1))

    def test_too_many_connections_is_refused_not_slow(self):
        bits = [[[1] * 255 for _ in range(255)]] * 2          # 130050 kept connections
        with self.assertRaises(ISL.NetError):
            ISL.find_islands(bits)

    def test_the_screen_shows_a_refusal_and_never_draws_the_bad_data(self):
        app = drive(ISL, store={"net": '{"threshold": 0, "layers": [[[1.5]]]}'}, events=keys("l"))
        self.assertIn("refused", app.screens[-1])
        app = drive(ISL, events=keys("l"))                      # nothing in the folder
        self.assertIn("refused", app.screens[-1])


class TestPublishAndGate(unittest.TestCase):
    def test_islands_publish_and_plan_reads_them_back(self):
        app = drive(ISL, events=keys("d", "p"))
        self.assertIn("router.plan", app.screens[-1])
        got = PLAN.load_islands(app.store["islands"])
        self.assertEqual([i["edges"] for i in got], [50, 8])

    def test_a_refused_publish_is_said_not_hidden(self):
        app = drive(ISL, events=keys("d", "p"), refuse=True)
        self.assertIn("could not publish", app.screens[-1])

    def test_plan_rejects_islands_data_that_is_not_exactly_what_islands_writes(self):
        ok = {"id": 1, "units": 2, "edges": 3, "inputs": 1, "outputs": 1}
        self.assertEqual(len(PLAN.load_islands(json.dumps([ok]))), 1)
        for bad in (None, "", "x", "{}", "[]", json.dumps([ok] * 65), json.dumps([{**ok, "edges": -1}]),
                    json.dumps([{**ok, "edges": 1.5}]), json.dumps([{**ok, "edges": True}]),
                    json.dumps([{**ok, "extra": 1}]), json.dumps([{"id": 1}]), json.dumps(["x"]),
                    json.dumps([{**ok, "edges": 10 ** 10}])):
            self.assertEqual(PLAN.load_islands(bad), [], str(bad)[:60])

    def test_the_number_of_islands_is_at_least_one_at_most_all_and_never_falls_as_effort_rises(self):
        for n in range(1, PLAN.MAX_ISLANDS + 1):
            ks = [PLAN.island_count(n, t) for t in PLAN.TIERS]
            self.assertEqual(ks, sorted(ks))
            self.assertTrue(all(1 <= k <= n for k in ks), (n, ks))
            self.assertEqual(ks[-1], n)         # max effort runs everything
            self.assertEqual(ks[0], 1)          # instant runs one
        self.assertEqual(PLAN.island_count(0, "max"), 0)


class TestRouting(unittest.TestCase):
    ISLANDS = [{"id": n, "units": 9, "edges": e, "inputs": 3, "outputs": 3} for n, e in enumerate((50, 30, 10, 6, 4), 1)]

    def test_effort_follows_the_score_and_the_score_is_bounded(self):
        tiers = [PLAN.tier_of(s) for s in range(0, 101)]
        self.assertEqual([PLAN.TIERS.index(t) for t in tiers], sorted(PLAN.TIERS.index(t) for t in tiers))
        self.assertEqual((tiers[0], tiers[100]), ("instant", "max"))
        for text in ("", " ", "hi", "x" * 50000, "prove " * 500, "?" * 900, "```" * 400, "\x00\x1b[31m"):
            self.assertTrue(0 <= PLAN.score(text) <= 100, text[:10])

    def test_easy_prompts_are_instant_and_local_hard_ones_are_high_and_cloud(self):
        easy = PLAN.decide("hi there", self.ISLANDS)
        self.assertEqual((easy["tier"], easy["where"], easy["islands_run"]), ("instant", "local", 1))
        hard = PLAN.decide("Explain why quicksort is O(n log n), prove it step by step, compare it with mergesort,\n"
                           "1. derive the recurrence\n2. implement it ```def f(): pass```\n3. analyze the security of the design?", self.ISLANDS)
        self.assertIn(hard["tier"], ("high", "max"))
        self.assertEqual(hard["where"], "cloud")
        self.assertGreater(hard["islands_run"], easy["islands_run"])
        self.assertGreater(hard["compute_percent"], easy["compute_percent"])

    def test_a_secret_stays_local_at_every_effort_unless_you_force_cloud_and_then_you_are_warned(self):
        p = "my password is hunter2, now prove step by step and analyze and design and debug and optimize"
        for tier in PLAN.TIERS:
            self.assertEqual(PLAN.decide(p, self.ISLANDS, tier_override=tier)["where"], "local", tier)
        forced = PLAN.decide(p, self.ISLANDS, where_override="cloud")
        self.assertEqual(forced["where"], "cloud")
        self.assertTrue(any("WARNING" in n for n in forced["notes"]))
        key = PLAN.decide("-----BEGIN OPENSSH PRIVATE KEY----- explain", self.ISLANDS)
        self.assertEqual(key["where"], "local")

    def test_a_short_prompt_is_not_forced_to_instant_just_for_being_short(self):
        d = PLAN.decide("prove, derive, analyze, design, debug", self.ISLANDS)
        self.assertNotEqual(d["tier"], "instant")
        self.assertEqual(PLAN.decide("thanks", self.ISLANDS)["tier"], "instant")

    def test_a_prompt_too_long_for_a_local_model_goes_to_cloud(self):
        d = PLAN.decide("word " * 3000, self.ISLANDS)
        self.assertEqual(d["where"], "cloud")

    def test_overrides_win_over_the_automatic_choice(self):
        d = PLAN.decide("hi there", self.ISLANDS, tier_override="max", where_override="cloud")
        self.assertEqual((d["tier"], d["where"], d["islands_run"], d["compute_percent"]), ("max", "cloud", 5, 100))
        self.assertEqual(d["auto_tier"], "instant")

    def test_without_island_data_it_says_all_and_does_not_invent_a_number(self):
        d = PLAN.decide("hello", [])
        self.assertEqual((d["islands_total"], d["islands_run"], d["compute_percent"]), (0, 0, 100))
        app = drive(PLAN, events=keys(*typed("hello"), "enter"))
        self.assertIn("no island data", app.screens[-1])


class TestTidy(unittest.TestCase):
    def test_tidy_removes_filler_spaces_and_repeats_and_nothing_else(self):
        out = PLAN.tidy("Please   explain   X\nplease explain x\n\n\n\num, then do Y  ")
        self.assertEqual(out, "explain X\n\nthen do Y")

    def test_tidy_is_idempotent_never_longer_and_never_empty(self):
        for text in ("Please", "  ", "um um", "a\n\n\n\nb", "x" * 100, "kindly, please, um", "line\nline\nLINE"):
            once = PLAN.tidy(text)
            self.assertEqual(PLAN.tidy(once), once, repr(text))
            self.assertTrue(once or not text.strip(), repr(text))
            self.assertLessEqual(len(once), len(text.strip()) or 1)

    def test_tidy_leaves_meaning_words_alone(self):
        for text in ("just do it", "it is actually 5", "literally copy this"):
            self.assertEqual(PLAN.tidy(text), text)

    def test_the_tidied_prompt_is_used_only_when_it_is_on(self):
        raw = "Please   explain   X"
        self.assertEqual(PLAN.decide(raw, [], optimize=False)["prompt"], raw)
        on = PLAN.decide(raw, [], optimize=True)
        self.assertEqual((on["prompt"], on["tidied"]), ("explain X", True))


class TestScreens(unittest.TestCase):
    def test_typing_deciding_toggling_and_starting_over(self):
        app = drive(PLAN, events=keys(*typed("Please   say hi"), "enter", "o", "e", "e", "w", "w", "n"))
        self.assertIn("ON", app.screens[-4])
        self.assertIn("say hi", app.screens[-4])
        self.assertIn("low  (forced)", app.screens[-3] + app.screens[-4])
        self.assertIn("Type your prompt", app.screens[-1])

    def test_control_characters_never_reach_the_screen(self):
        app = drive(PLAN, events=keys(*typed("a\x1b[31mb"), "enter"))
        self.assertNotIn("\x1b", app.screens[-1])

    def test_a_very_long_prompt_is_capped(self):
        app = drive(PLAN, events=keys(*(["x"] * (PLAN.MAX_PROMPT + 500)), "enter"))
        self.assertTrue(app.screens)

    def test_escape_clears_then_leaves_and_empty_enter_decides_nothing(self):
        app = drive(PLAN, events=keys("a", "escape", "escape"))
        self.assertTrue(app.exited)
        app = drive(PLAN, events=keys("enter"))
        self.assertIn("Type your prompt", app.screens[-1])

    def test_it_only_advises(self):
        app = drive(PLAN, events=keys(*typed("hello"), "enter"))
        self.assertIn("Nothing was sent", app.screens[-1])


class TestRulesForTheGroup(unittest.TestCase):
    def manifests(self):
        return {p: json.loads((GROUP / p / "manifest.json").read_text()) for p in ("islands", "plan")}

    def test_each_program_is_its_own_app_and_asks_only_for_its_own_folder_permission(self):
        m = self.manifests()
        self.assertEqual(m["islands"]["name"], "router.islands")
        self.assertEqual(m["plan"]["name"], "router.plan")
        self.assertEqual(m["islands"]["permissions"], ["owns:router"])
        self.assertEqual(m["plan"]["permissions"], ["uses:router"])
        for d in m.values():
            self.assertTrue(all(SPACE_PERM_RE.match(p) for p in d["permissions"]))
            self.assertLessEqual(len(d["description"]), 200)
            self.assertEqual(d["modes"], ["tui"])

    def sources(self):
        return {p: (GROUP / p / "app.py").read_text() for p in ("islands", "plan")}

    def test_no_decimals_in_either_app(self):
        """An independent check of the proof gate's main rule, so it runs even where the gate cannot import."""
        for name, src in self.sources().items():
            for node in ast.walk(ast.parse(src)):
                if isinstance(node, ast.Constant):
                    self.assertNotIsInstance(node.value, (float, complex), f"{name}:{node.lineno}")
                if isinstance(node, (ast.Div,)):
                    self.fail(f"{name}:{node.lineno}: '/' between numbers (use //)")
                if isinstance(node, ast.Name):
                    self.assertNotIn(node.id, {"float", "complex", "Decimal", "Fraction", "eval", "exec", "compile"})

    def test_each_app_imports_only_kos_sdk_from_the_os_and_nothing_that_reaches_out(self):
        for name, src in self.sources().items():
            for node in ast.walk(ast.parse(src)):
                mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                        else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                for mod in mods:
                    if mod.split(".")[0] == "kos":
                        self.assertEqual(mod, "kos.sdk", name)
                    self.assertNotIn(mod.split(".")[0], {"socket", "urllib", "http", "subprocess", "os", "ssl", "requests"}, name)

    def test_the_apps_do_not_import_each_other(self):
        for name, src in self.sources().items():
            self.assertNotRegex(src, r"(?m)^\s*(?:from|import)\s+(?:islands|plan)\b")

    def test_the_os_proof_gate_passes_both_apps_when_the_os_imports(self):
        try:
            from kos import proof
        except Exception as e:  # the base branch's kos/kapp.py does not compile (see the pull request note)
            self.skipTest(f"kos.proof cannot be imported on this branch: {type(e).__name__}")
        for name, src in self.sources().items():
            self.assertEqual(proof.violations(src.encode(), "app.py"), [], name)


if __name__ == "__main__":
    unittest.main()
