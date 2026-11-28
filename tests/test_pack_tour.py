import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.auth import ACTIONS  # noqa: E402
from kos.cli import COMMANDS  # noqa: E402
from kos.office import pack_tour as T  # noqa: E402
from kos.office.catalog import BY_NAME  # noqa: E402
from kos.office.ui import FakeHost  # noqa: E402

TITLES = [l.split("\t")[1] for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines()
          if l.strip() and l.split("\t")[0] == "pack_tour"]
APPS = {e.title for e in BY_NAME.values()} | {l.split("\t")[1] for l in (ROOT / "docs" / "REQUESTED2.txt").read_text().splitlines() if "\t" in l}
QS = [(p[0], q) for p in T.PARTS for q in p[3]]


def texts(q):
    return [q[0], q[1], *q[2], q[3]]


class TestTourFacts(unittest.TestCase):
    def test_entry(self):
        self.assertEqual([e.title for e in T.ENTRIES], TITLES)
        self.assertEqual(T.ENTRIES[0].scope, "full")

    def test_ten_parts_and_enough_questions(self):
        self.assertEqual(len(T.PARTS), 10)
        for p in T.PARTS: self.assertGreaterEqual(len(p[3]), 6, p[0])

    def test_shape(self):
        for key, q in QS:
            self.assertEqual(len(q), 4, q)
            choices = [q[1], *q[2]]
            self.assertIn(len(choices), (3, 4), q[0])
            self.assertEqual(len(set(choices)), len(choices), q[0])   # exactly one right, no duplicates
            self.assertTrue(q[3].strip() and q[0].strip(), q[0])
            self.assertLess(len(q[3]), 200, q[0])

    def test_unique_questions(self):
        qs = [q[0] for _, q in QS]
        self.assertEqual(len(qs), len(set(qs)))

    def test_kos_commands_exist(self):
        n = 0
        for _, q in QS:
            for t in texts(q):
                for m in re.findall(r"\bkos ([a-z]+)", t):
                    n += 1; self.assertIn(m, COMMANDS, t)
        self.assertGreater(n, 15)
        for q in T.PARTS[8][3]:
            self.assertIn(q[1].split()[1], COMMANDS)

    def test_actions_exist(self):
        n = 0
        for _, q in QS:
            for t in texts(q):
                for m in re.findall(r"\b((?:session|auth|app|file|device|space|scan|disk|cell|code|admin|backup|skill|audit)\.[a-z]+(?:\.[a-z]+)*)", t):
                    n += 1; self.assertIn(m, ACTIONS, t)
        self.assertGreater(n, 8)

    def test_apps_exist(self):
        for job, app_title, why in T.SAFARI: self.assertIn(app_title, APPS, app_title)
        for key in ("shared",):
            for _, q in QS:
                if _ == key:
                    for t in [q[1], *q[2]]:
                        if t in ("Contact Manager", "Email Client", "CRM", "Task Manager", "Calendar Manager", "Places"):
                            self.assertIn(t, APPS)

    def test_commands_game_commands_have_no_wrong_command_ambiguity(self):
        for q in T.PARTS[8][3]:
            self.assertNotIn(q[1], q[2])

    def test_no_claim_of_unbuilt_things(self):
        # README gaps table: no firewall, nothing encrypted. Any mention must be negated or be a "not yet".
        neg = re.compile(r"\bno\b|\bnot\b|\bnever\b|\byet\b|nothing|\bnone\b|\bshould\b|\bgoal\b|\brule\b|n't|refus", re.I)
        for _, q in QS:
            right_and_why = f"{q[0]} {q[1]} {q[3]}"
            for w in ("firewall", "encrypt", "hardware", "camera", "microphone"):
                if w in right_and_why.lower():
                    self.assertRegex(right_and_why, neg, right_and_why)
        for _, q in QS:   # the right answer never says yes to "is it encrypted"
            if re.search(r"encrypted", q[0], re.I) and q[0].lower().startswith(("does", "is ")):
                self.assertTrue(q[1].startswith("No"), q[0])
        # The firewall exists, with limits. The tour may say so, but any firewall claim must carry its limit:
        # nothing is said to cover the OS's own connections, host names or encryption.
        limit = re.compile(r"only|cannot|not|nothing|until|blocked|stock|default|edits|each|no ", re.I)
        for _, q in QS:
            about = f"{q[0]} {q[1]} {q[3]}"
            if "firewall" in about.lower():
                self.assertRegex(about, limit, about)
                self.assertNotRegex(q[1], r"(?i)\b(all|every) (connection|traffic)s? (is|are) (encrypted|covered)", q[0])


class TestTourPlay(unittest.TestCase):
    def play(self, keys, data=None):
        host = FakeHost(keys, data=data)
        hub = T.Hub(host)
        stack = [hub]
        for k in host.script:
            r = stack[-1].key(k if isinstance(k, str) else "")
            if r and r[0] == "push": stack.append(r[1])
            elif r and r[0] == "pop" and len(stack) > 1: stack.pop()
        return host, hub, stack

    def test_deterministic_and_shuffled_by_seed(self):
        a, b = T.Game(T.Hub(FakeHost()), T.PARTS[0], 1), T.Game(T.Hub(FakeHost()), T.PARTS[0], 1)
        self.assertEqual(a.qs, b.qs)
        c = T.Game(T.Hub(FakeHost()), T.PARTS[0], 2)
        self.assertNotEqual(a.qs, c.qs)
        for text, ch, ok, why in a.qs: self.assertEqual(len(set(ch)), len(ch))

    def test_play_every_part_perfectly_and_save(self):
        host = FakeHost()
        hub = T.Hub(host)
        for i, p in enumerate(T.PARTS):
            r = hub.key(str(i + 1) if i < 9 else "0")
            if i == 9: hub.nav.sel = 9; r = hub.key("enter")
            g = r[1]
            for q in g.qs:
                g.key(str(q[2] + 1)); g.key("enter")
                self.assertIn(q[3][:20], "\n".join(g.render(80, 22)))
                g.key("enter")
            self.assertEqual((g.score, g.best), (len(g.qs), len(g.qs)))
            self.assertIn("Finished", "\n".join(g.render(80, 22)))
        self.assertEqual(len(hub.done), 10)
        self.assertIn("explored 10/10", "\n".join(hub.render(80, 22)))
        again = T.Hub(host)          # reload from the vault
        self.assertEqual(len(again.done), 10)

    def test_wrong_answers_reset_streak(self):
        g = T.Game(T.Hub(FakeHost()), T.PARTS[1], 1)
        g.key(str(g.qs[0][2] + 1)); g.key("enter"); g.key("enter")
        wrong = (g.qs[1][2] + 1) % len(g.qs[1][1])
        g.sel = wrong; g.key("enter")
        self.assertEqual((g.score, g.streak), (1, 0))

    def test_hostile_keys(self):
        host = FakeHost()
        hub = T.Hub(host, seed=7)
        stack = [hub]
        for k in ["", "x", "0", "9", "enter", "up", "down", "pagedown", "\x00", "ctrl-z", "enter", "enter", "5", "escape", "end", "home", "enter"] * 30:
            r = stack[-1].key(k)
            stack[-1].render(40, 8)
            if r and r[0] == "push": stack.append(r[1])
            elif r and r[0] == "pop" and len(stack) > 1: stack.pop()

    def test_corrupt_vault_is_tolerated(self):
        for bad in ('"x"', '{"done": 5}', '{"done": {"pipeline": "x", "nope": [1,2,3]}, "plays": "a"}', "not json"):
            h = T.Hub(FakeHost(data={"tour": bad}))
            h.render(80, 22)
            self.assertEqual(h.done, {})


if __name__ == "__main__":
    unittest.main()
