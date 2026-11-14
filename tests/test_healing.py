"""The healing app: a counter kept in three checksummed copies that repairs itself.

Nothing here is a Z3 proof (rule 7): the claims are about SHA-256 and files, not maths. They are checked by
trying to break them: every combination of damage to the three copies, hostile stored text, a refused write,
and a crash in the middle of the real event loop. What is NOT covered is said in the README gaps table:
a checksum is not a signature, and the OS does not restart an app that dies.
"""

import importlib.util
import itertools
import json
import os
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "apps" / "healing"


def load(name):
    spec = importlib.util.spec_from_file_location(name, APP / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeApp:
    """The part of kos.sdk.App the healing logic uses: a private vault, which can be made to refuse writes."""

    def __init__(self):
        self.vault, self.refuse = {}, False

    def vault_get(self, key, space=None):
        return self.vault.get(key)

    def vault_put(self, key, value, space=None):
        if self.refuse:
            return False
        self.vault[key] = value
        return True


def fresh(h, val=0, gen=1):
    app = FakeApp()
    for c in h.COPIES:
        app.vault[c] = h.encode(gen, val)
    return app, h.Store(app)


# What can be wrong with one copy: fine and current, fine but one write behind, junk, or gone.
CONDITIONS = ("current", "stale", "junk", "missing")


class TestDecode(unittest.TestCase):
    def setUp(self):
        self.h = load("healing_decode")

    def test_a_copy_round_trips(self):
        self.assertEqual(self.h.decode(self.h.encode(7, -3)), (7, -3))

    def test_hostile_stored_text_is_never_trusted_and_never_raises(self):
        h = self.h
        good = json.loads(h.encode(1, 1))
        bad = ["", None, 7, [], "[]", "{}", "null", "{", "NaN", "\x00", "[" * 100000, "{" * 100000,
               json.dumps({**good, "sum": "0" * 64}),                       # checksum does not match
               json.dumps({**good, "val": 2}),                              # value changed, checksum kept
               json.dumps({**good, "gen": 2}),                              # generation changed
               json.dumps({**good, "sum": 5}),                              # checksum is not text
               json.dumps({**good, "extra": 1}),                            # a field that does not belong
               json.dumps({"gen": 1, "val": 1}),                            # no checksum
               json.dumps({**good, "val": 1.5}), json.dumps({**good, "val": True}),
               json.dumps({**good, "gen": -1, "sum": h.checksum(-1, 1)}),   # valid checksum, impossible gen
               json.dumps({**good, "val": 10 ** 9 + 1, "sum": h.checksum(1, 10 ** 9 + 1)}),
               json.dumps({**good, "val": 10 ** 40, "sum": h.checksum(1, 10 ** 40)})]
        for text in bad:
            self.assertIsNone(h.decode(text), repr(text)[:60])

    def test_pick_takes_the_newest_valid_copy_then_the_most_common(self):
        h = self.h
        self.assertEqual(h.pick([(2, 5), (3, 6), None]), (3, 6))
        self.assertEqual(h.pick([(3, 1), (3, 2), (3, 2)]), (3, 2))
        self.assertIsNone(h.pick([None, None, None]))


class TestHeal(unittest.TestCase):
    def setUp(self):
        self.h = load("healing_heal")

    def build(self, conditions):
        """Three copies in the given conditions around the truth: value 5 at generation 4 (stale: 4 at 3)."""
        h = self.h
        app = FakeApp()
        for c, cond in zip(h.COPIES, conditions):
            if cond == "current":
                app.vault[c] = h.encode(4, 5)
            elif cond == "stale":
                app.vault[c] = h.encode(3, 4)
            elif cond == "junk":
                app.vault[c] = "garbage"
        return app

    def test_every_combination_of_damage_ends_in_three_identical_good_copies(self):
        h = self.h
        for conds in itertools.product(CONDITIONS, repeat=3):
            app = self.build(conds)
            val, gen, status, lines = h.heal(h.Store(app))
            decoded = [h.decode(app.vault[c]) for c in h.COPIES]
            self.assertEqual(len(set(decoded)), 1, conds)           # all three agree ...
            self.assertIsNotNone(decoded[0], conds)                  # ... and are valid
            self.assertEqual(decoded[0], (gen, val), conds)
            if "current" in conds:                                   # the newest copy always wins
                self.assertEqual((gen, val), (4, 5), conds)
            elif "stale" in conds:                                   # only old data survived: say so, keep it
                self.assertEqual((gen, val), (3, 4), conds)
            else:                                                    # nothing survived: restart, and say it
                self.assertEqual((gen, val), (1, 0), conds)
                self.assertTrue(any("lost" in ln for ln in lines), conds)
            # healing again changes nothing and says nothing
            again = h.heal(h.Store(app))
            self.assertEqual(again[:2], (val, gen), conds)
            self.assertEqual(again[3], [], conds)

    def test_a_healthy_set_is_left_alone(self):
        h = self.h
        app, store = fresh(h, 9, 3)
        before = dict(app.vault)
        val, gen, status, lines = h.heal(store)
        self.assertEqual((val, gen, lines), (9, 3, []))
        self.assertEqual(app.vault, before)
        self.assertEqual(set(status.values()), {"ok"})

    def test_it_reports_what_it_repaired(self):
        h = self.h
        app, store = fresh(h, 9, 3)
        app.vault["b"] = "garbage"
        val, gen, status, lines = h.heal(store)
        self.assertEqual(status, {"a": "ok", "b": "repaired", "c": "ok"})
        self.assertEqual(len(lines), 1)
        self.assertIn("copy b", lines[0])

    def test_when_the_storage_refuses_the_repair_it_says_so_and_does_not_crash(self):
        h = self.h
        app, store = fresh(h, 9, 3)
        app.vault["b"] = "garbage"
        app.refuse = True
        val, gen, status, lines = h.heal(store)
        self.assertEqual((val, status["b"]), (9, "unwritten"))
        self.assertIn("could not be rewritten", lines[0])

    def test_when_everything_is_lost_and_nothing_can_be_written_it_gives_up_honestly(self):
        h = self.h
        app = FakeApp()
        app.refuse = True
        val, gen, status, lines = h.heal(h.Store(app))
        self.assertIsNone(val)
        self.assertEqual(set(status.values()), {"lost"})

    def test_an_interrupted_write_is_finished_not_undone(self):
        h = self.h
        app, store = fresh(h, 1, 1)
        app.vault["a"] = h.encode(2, 2)                              # the write reached copy a, then died
        self.assertEqual(h.heal(store)[:2], (2, 2))
        self.assertEqual({h.decode(app.vault[c]) for c in h.COPIES}, {(2, 2)})


class TestChange(unittest.TestCase):
    def setUp(self):
        self.h = load("healing_change")

    def test_it_counts_and_stays_inside_the_limit(self):
        h = self.h
        app, store = fresh(h, 0, 1)
        state = {"val": 0, "gen": 1}
        h.change(store, state, 1)
        self.assertEqual(h.heal(store)[:2], (1, 2))
        top = {"val": h.LIMIT, "gen": 2}
        h.change(store, top, 1)
        self.assertEqual(h.heal(store)[0], h.LIMIT)
        low = {"val": -h.LIMIT, "gen": 3}
        h.change(store, low, -1)
        self.assertEqual(h.heal(store)[0], -h.LIMIT)

    def test_the_log_is_bounded_and_a_damaged_log_is_reset_not_trusted(self):
        h = self.h
        app, store = fresh(h)
        for n in range(40):
            store.add_log([f"line {n} " + "x" * 500])
        log = store.log()
        self.assertEqual(len(log), h.LOG_MAX)
        self.assertTrue(all(len(s) <= h.LOG_LINE for s in log))
        for junk in ("garbage", "{}", '"text"', "[1, 2, null]", "[" * 100000):
            app.vault[h.LOG_KEY] = junk
            self.assertIsInstance(store.log(), list, junk[:20])
        app.vault[h.LOG_KEY] = "garbage"
        self.assertEqual(store.log(), ["log was damaged and was reset"])


class TestEvents(unittest.TestCase):
    def setUp(self):
        self.h = load("healing_events")

    def state(self):
        return {"val": 0, "gen": 0, "status": {}, "log": [], "note": "", "ok": True, "hits": 0}

    def test_keys_change_the_value_and_damage_is_healed_on_the_spot(self):
        h = self.h
        app, store = fresh(h, 0, 1)
        st = self.state()
        for key in ("up", "up", "+", "down"):
            self.assertTrue(h.handle(store, st, {"cmd": "key", "key": key}))
        self.assertEqual(st["val"], 2)
        self.assertTrue(h.handle(store, st, {"cmd": "key", "key": "d"}))
        self.assertIn("damaged copy a", st["note"])
        self.assertEqual(st["status"]["a"], "repaired")              # damaged and repaired in the same event
        self.assertEqual(st["val"], 2)
        self.assertTrue(any("copy a" in ln for ln in st["log"]))

    def test_damage_to_every_copy_in_turn_never_loses_the_value(self):
        h = self.h
        app, store = fresh(h, 41, 1)
        st = self.state()
        for _ in range(9):
            h.handle(store, st, {"cmd": "key", "key": "d"})
        self.assertEqual(st["val"], 41)
        self.assertTrue(st["ok"])

    def test_events_the_app_does_not_use_are_ignored(self):
        h = self.h
        app, store = fresh(h)
        st = self.state()
        for ev in ({"cmd": "pointer", "x": 1, "y": 2}, {"cmd": "key", "key": "q"},
                   {"cmd": "button", "pressed": False, "button": "left", "x": 0, "y": 0}, {"cmd": "device"}):
            self.assertFalse(h.handle(store, st, ev), ev)

    def test_a_change_after_outside_damage_is_built_on_the_healed_value(self):
        h = self.h
        app, store = fresh(h, 10, 5)
        st = self.state()
        h.handle(store, st, {"cmd": "hello"})
        app.vault["a"] = app.vault["b"] = "garbage"                  # damaged between two keys
        h.handle(store, st, {"cmd": "key", "key": "up"})
        self.assertEqual(st["val"], 11)


class TestRealEventLoop(unittest.TestCase):
    """Runs the app's real main() over the real SDK on a socket, with a fake OS on the other end."""

    def run_app(self, break_on=None):
        h = load("healing_loop")
        mine, theirs = socket.socketpair()
        os.environ["KOS_CHANNEL_FD"] = str(theirs.detach())    # the SDK owns this fd now
        os.environ["KOS_MODE"] = "tui"
        vault = {}
        calls = {"n": 0}
        if break_on is not None:
            real = h.handle

            def handle(store, state, ev):
                calls["n"] += 1
                if calls["n"] == break_on:
                    raise RuntimeError("boom")
                return real(store, state, ev)
            h.handle = handle
        t = threading.Thread(target=h.main, daemon=True)
        t.start()
        rfile = mine.makefile("rb")
        screens = []

        def send(obj):
            mine.sendall(json.dumps(obj).encode() + b"\n")

        def serve_until_screen():
            while True:
                msg = json.loads(rfile.readline())
                if msg["cmd"] == "vault":
                    if msg["op"] == "put":
                        vault[msg["key"]] = msg["value"]
                        send({"cmd": "vault", "id": msg["id"], "ok": True})
                    else:
                        ok = msg["key"] in vault
                        send({"cmd": "vault", "id": msg["id"], "ok": ok, "value": vault.get(msg["key"]),
                              **({} if ok else {"detail": "no such key"})})
                elif msg["cmd"] == "screen":
                    screens.append(msg)
                    return

        send({"cmd": "hello", "mode": "tui", "width": 80, "height": 24})
        serve_until_screen()
        for key in ("up", "up", "d"):
            send({"cmd": "key", "key": key})
            serve_until_screen()
        send({"cmd": "quit"})
        t.join(5)
        mine.close()
        return h, vault, screens, t

    def test_it_starts_counts_and_heals_over_the_real_protocol(self):
        h, vault, screens, t = self.run_app()
        self.assertFalse(t.is_alive())
        text = "\n".join(screens[-1]["lines"])
        self.assertIn("value 2", text)
        self.assertIn("copy a: repaired", text)
        self.assertEqual({h.decode(vault[c]) for c in h.COPIES}, {(3, 2)})

    def test_an_error_in_the_middle_of_the_loop_is_survived_and_logged(self):
        h, vault, screens, t = self.run_app(break_on=3)              # the second 'up' raises
        self.assertFalse(t.is_alive())
        text = "\n".join(screens[-1]["lines"])
        self.assertIn("recovered from RuntimeError", text)
        self.assertIn("value 1", text)                               # the failed key was lost, nothing else was


class TestRules(unittest.TestCase):
    def test_the_app_asks_only_for_storage_and_its_files_are_all_there(self):
        m = json.loads((APP / "manifest.json").read_text())
        self.assertEqual(m["name"], "healing")
        self.assertEqual(m["permissions"], ["storage"])
        self.assertTrue((APP / "app.py").is_file())

    def test_it_passes_the_proof_gate_whole_numbers_and_all(self):
        from kos.proof import violations
        self.assertEqual(violations((APP / "app.py").read_bytes(), "app.py"), [])

    def test_it_packs_and_installs_as_an_app(self):
        import tempfile
        from kos.kapp import KApp, pack
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "healing.kapp"
            self.assertEqual(pack(APP, out).name, "healing")
            self.assertEqual(KApp.from_file(out).manifest.permissions, ("storage",))


if __name__ == "__main__":
    unittest.main()
