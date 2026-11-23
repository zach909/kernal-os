"""The Store (``apps/store``): 88 apps generated from ``suite/store_data.py``. Every one packs through the proof gate
under ``store.<folder>``; the generated files are what the generator would write; each working app is driven through
its real ``main()`` with a fake SDK, including refusals and hostile input. Shell apps are checked to claim nothing."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite"))

import store_data as D  # noqa: E402
import store_gen  # noqa: E402
from kos.kapp import Manifest, pack_tree  # noqa: E402

STORE = ROOT / "apps" / "store"


def load(i):
    spec = importlib.util.spec_from_file_location("store_" + i.replace("-", "_"), STORE / i / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Fake:
    def __init__(self, data=(), refuse=False, secrets=None):
        self.data, self.sec, self.refuse = dict(data), dict(secrets or {}), refuse
        self.vault_error, self.height, self.width = "", 24, 80
        self.screens, self.exited, self.events_ = [], False, []

    def events(self):
        yield {"cmd": "hello"}
        for k in self.events_:
            yield {"cmd": "key", "key": k}

    def vault_keys(self, space=None):
        return list(self.data)

    def vault_get(self, k, space=None):
        return self.data.get(k)

    def vault_put(self, k, v, space=None):
        if self.refuse:
            self.vault_error = "no write access"
            return False
        self.data[k] = v
        return True

    def vault_delete(self, k, space=None):
        return self.data.pop(k, None) is not None

    def secret_keys(self, store):
        return list(self.sec)

    def secret_get(self, store, k):
        return self.sec.get(k)

    def secret_put(self, store, k, v):
        if self.refuse:
            self.vault_error = "no passwords permission"
            return False
        self.sec[k] = v
        return True

    def secret_delete(self, store, k):
        return self.sec.pop(k, None) is not None

    def screen(self, title, lines, status=""):
        self.screens.append((title, list(lines)))

    def exit(self, code=0):
        self.exited = True


def run(i, keys, **kw):
    mod = load(i)
    app = Fake(**kw)
    app.events_ = list(keys) + ["escape"]
    mod.App = lambda: app
    mod.main()
    return app, mod


def seen(app):
    return "\n".join("\n".join(s[1]) for s in app.screens)


def text(app):
    return "\n".join(app.screens[-1][1])


def typed(s):
    return list(s)


class TestWholeStore(unittest.TestCase):
    def test_every_app_packs_through_the_proof_gate_under_its_folder_name(self):
        with tempfile.TemporaryDirectory() as t:
            made = pack_tree(STORE, Path(t) / "out")
        self.assertEqual(sorted(m.name for m in made), sorted("store." + e["id"] for e in D.E))
        self.assertEqual(len(made), 88)

    def test_what_is_on_disk_is_what_the_generator_writes(self):
        for p, want in store_gen.outputs().items():
            self.assertTrue(p.is_file(), p)
            self.assertEqual(p.read_text(), want, f"{p} is stale: python3 suite/store_gen.py write")

    def test_no_stray_folder_and_every_app_has_a_known_scope(self):
        folders = {p.name for p in STORE.iterdir() if p.is_dir()}
        self.assertEqual(folders, {e["id"] for e in D.E})
        self.assertFalse((STORE / "manifest.json").exists(), "the group itself has no permissions")
        for e in D.E:
            self.assertIn(store_gen.scope(e), ("partial", "shell"))

    def test_permissions_are_the_least_each_app_needs(self):
        asked = {}
        for e in D.E:
            m = Manifest.parse((STORE / e["id"] / "manifest.json").read_bytes())
            asked[e["id"]] = set(m.permissions)
        want = {"notes": {"storage"}, "text-editor": {"storage"}, "journal": {"storage"}, "reminders": {"storage"},
                "contacts": {"storage"}, "passwords": {"passwords"}}
        for i, perms in asked.items():
            self.assertEqual(perms, want.get(i, set()), i)       # nothing asks for network, system or a device

    def test_every_device_in_the_list_is_covered_by_an_app_or_a_named_existing_one(self):
        listed = (ROOT / "docs" / "REQUESTED_DEFAULT_APPS.txt").read_text()
        self.assertIn("GOOGLE GLASS", listed)
        self.assertTrue(set(d for e in D.E for d in e["dev"]) <= set(D.DEVICES))
        self.assertEqual({d for e in D.E for d in e["dev"]}, set(D.DEVICES))

    def test_a_shell_claims_nothing_and_always_leaves_on_escape(self):
        for e in D.E:
            if e["arch"] != "info":
                continue
            app, _ = run(e["id"], [])
            self.assertTrue(app.exited, e["id"])
            body = text(app)
            self.assertIn("does not do its job yet", body, e["id"])
            self.assertIn("Needs ", body, e["id"])

    def test_the_readme_counts_match_the_data(self):
        r = (STORE / "README.md").read_text()
        self.assertIn(f"**{len(D.E)} apps:", r)
        self.assertIn("None is `full`", r)


class TestCalculator(unittest.TestCase):
    def calc(self, expr):
        _, mod = run("calculator", [])
        return mod.show(mod.evaluate(expr))

    def test_exact_fractions_never_decimals(self):
        self.assertEqual(self.calc("1/2 + 1/3"), "5/6")
        self.assertEqual(self.calc("7/2"), "7/2")
        self.assertEqual(self.calc("(1+2)*-4"), "-12")
        self.assertEqual(self.calc("10/4 - 1/2"), "2")

    def test_refusals(self):
        _, mod = run("calculator", [])
        for bad in ("1/0", "1+", "(1", "2 ** 3", "1.5", "abc", "1" * 31, "1+" * 60, "", "()"):
            with self.assertRaises(ValueError, msg=bad):
                mod.evaluate(bad)

    def test_the_screen_shows_the_work_and_a_wrong_sum_does_not_crash(self):
        app, _ = run("calculator", typed("1/3+1/6") + ["enter"] + typed("1/0") + ["enter"])
        self.assertIn("1/3+1/6 = 1/2", text(app))
        self.assertIn("cannot divide by zero", text(app))


class TestUnits(unittest.TestCase):
    def test_exact_conversions(self):
        _, m = run("unit-converter", [])
        one = (1, 1)
        self.assertEqual(m.convert(0, "mi", "ft", one), (5280, 1))
        self.assertEqual(m.convert(0, "in", "mm", one), (127, 5))
        self.assertEqual(m.convert(1, "lb", "oz", one), (16, 1))
        self.assertEqual(m.convert(2, "C", "F", (100, 1)), (212, 1))
        self.assertEqual(m.convert(2, "K", "C", (0, 1)), (-5463, 20))
        self.assertEqual(m.convert(2, "F", "C", (-40, 1)), (-40, 1))

    def test_hostile_values_are_refused(self):
        _, m = run("unit-converter", [])
        for bad in ("", "-", "1/0", "a", "1/", "/2", "١٢"):
            self.assertIsNone(m.parse(bad), bad)


class TestCalendarAndClock(unittest.TestCase):
    def test_dates(self):
        _, m = run("calendar", [])
        self.assertEqual(m.civil(0), (1970, 1, 1))
        self.assertEqual(m.civil(m.days_from_civil(2024, 2, 29)), (2024, 2, 29))
        self.assertEqual((m.days_from_civil(2000, 1, 1) + 4) % 7, 6)        # a Saturday
        self.assertEqual([m.month_days(y, 2) for y in (1900, 2000, 2023, 2024)], [28, 29, 28, 29])
        self.assertIn("29", "\n".join(m.grid(2024, 2, (0, 0, 0))))

    def test_the_screen_pages_and_clamps_the_year(self):
        app, _ = run("calendar", ["up"] * 20000)
        self.assertTrue(text(app).split("\n")[1].endswith(" 2"))            # clamped at year 2, no crash
        app, _ = run("calendar", ["right", "left", "down", "t"])
        self.assertIn("Today (UTC)", text(app))

    def test_clock_stamp_and_stopwatch(self):
        _, m = run("clock", [])
        self.assertEqual(m.stamp(0, 0), "Thu 1970-01-01 00:00")
        self.assertEqual(m.stamp(0, 330), "Thu 1970-01-01 05:30")
        self.assertEqual(m.stamp(0, -300), "Wed 1969-12-31 19:00")
        self.assertEqual(m.elapsed(3723004000000), "1:02:03.004")
        app, _ = run("clock", ["s", "s", "r"])
        self.assertIn("stopped", text(app))


class TestRecordApps(unittest.TestCase):
    def test_notes_add_show_delete(self):
        app, _ = run("notes", ["n"] + typed("buy milk") + ["enter"])
        self.assertEqual(list(app.data.values()), ["buy milk"])
        self.assertIn("buy milk", text(app))
        app, _ = run("notes", ["d"], data={"n-0001": "gone"})
        self.assertEqual(app.data, {})

    def test_notes_refused_write_says_so_and_stores_nothing(self):
        app, _ = run("notes", ["n"] + typed("x") + ["enter"], refuse=True)
        self.assertEqual(app.data, {})
        self.assertIn("not saved: no write access", seen(app))

    def test_hostile_stored_values_cannot_inject_screen_codes(self):
        app, _ = run("notes", [], data={"n-0001": "hi\x1b[2J\x07there", "other": "not mine", "n-bad": 7})
        body = text(app)
        self.assertNotIn("\x1b", body)
        self.assertNotIn("\x07", body)
        self.assertNotIn("not mine", body)

    def test_notes_are_capped_and_the_full_store_says_so(self):
        full = {f"n-{i:04d}": "x" for i in range(1, 201)}
        app, _ = run("notes", ["n"] + typed("one more") + ["enter"], data=full)
        self.assertEqual(len(app.data), 200)
        self.assertIn("full", seen(app))

    def test_journal_stamps_the_date_and_text_editor_is_not_dated(self):
        app, _ = run("journal", ["n"] + typed("good day") + ["enter"])
        v = list(app.data.values())[0]
        self.assertRegex(v, r"^\d{4}-\d{2}-\d{2} good day$")
        app, _ = run("text-editor", ["n"] + typed("scratch") + ["enter"])
        self.assertEqual(list(app.data.values()), ["scratch"])

    def test_reminders_tick_and_delete(self):
        app, _ = run("reminders", ["n"] + typed("call") + ["enter", " "])
        self.assertEqual(list(app.data.values()), ["1 call"])
        self.assertIn("[x] call", text(app))
        app, _ = run("reminders", [" ", " ", "d"], data={"r-0001": "0 a"})
        self.assertEqual(app.data, {})
        app, _ = run("reminders", [], data={"r-0001": "garbage"})          # a record that is not one of ours
        self.assertNotIn("garbage", text(app))

    def test_contacts_validate_and_keep_only_good_phone_characters(self):
        keys = ["n"] + typed("Ann") + ["tab"] + typed("+1 (2)x3") + ["tab"] + typed("nope") + ["enter"]
        app, _ = run("contacts", keys)
        self.assertEqual(app.data, {})                                      # email has no @
        keys = ["n"] + typed("Ann") + ["tab"] + typed("+1 (2)x3") + ["tab"] + typed("a@b.c") + ["enter"]
        app, _ = run("contacts", keys)
        rec = json.loads(list(app.data.values())[0])
        self.assertEqual(rec, {"name": "Ann", "phone": "+1 (2)3", "email": "a@b.c"})
        app, _ = run("contacts", ["n", "enter"])
        self.assertEqual(app.data, {})                                      # no name

    def test_contacts_skip_corrupt_records(self):
        app, _ = run("contacts", [], data={"c-0001": "{not json", "c-0002": json.dumps({"name": "Zed"}), "c-0003": "[1]"})
        self.assertIn("Zed", text(app))

    def test_passwords_hidden_until_enter_and_refusal_is_reported(self):
        app, _ = run("passwords", [], secrets={"bank": "hunter2"})
        self.assertNotIn("hunter2", text(app))
        app, _ = run("passwords", ["enter", "down"], secrets={"bank": "hunter2"})
        shown = [s for s in app.screens if "hunter2" in "\n".join(s[1])]
        self.assertEqual(len(shown), 1)                                      # only the screen after enter
        app, _ = run("passwords", ["n"] + typed("Bad Name") + ["tab"] + typed("pw") + ["enter"], refuse=True)
        self.assertEqual(app.sec, {})
        app, _ = run("passwords", ["n"] + typed("site") + ["tab"] + typed("pw") + ["enter"], refuse=True)
        self.assertIn("not saved: no passwords permission", seen(app))
        app, _ = run("passwords", ["n"] + typed("site") + ["tab"] + typed("pw") + ["enter"])
        self.assertEqual(app.sec, {"site": "pw"})

    def test_a_secret_is_never_drawn_while_typing_it(self):
        app, _ = run("passwords", ["n", "a", "tab"] + typed("topsecret"))
        self.assertNotIn("topsecret", seen(app))


class TestCharactersAndCatalog(unittest.TestCase):
    def test_names_and_goto(self):
        app, _ = run("characters", ["g"] + typed("e9") + ["enter"])
        self.assertIn("LATIN SMALL LETTER E WITH ACUTE", text(app))
        app, _ = run("characters", ["g"] + typed("zz10ffffff") + ["enter"])
        self.assertIn("U+10FFFF", text(app))
        app, _ = run("characters", ["up"] * 99 + ["left"] * 99)
        self.assertIn("U+0000", text(app))

    def test_unprintable_and_surrogates_never_reach_the_screen(self):
        app, _ = run("characters", ["g"] + typed("d800") + ["enter"])
        self.assertNotIn("\ud800", text(app))
        app, _ = run("characters", ["g", "0", "7", "enter"])
        self.assertNotIn("\x07", text(app))

    def test_app_store_lists_every_app_and_scrolls_to_the_end(self):
        app, mod = run("app-store", ["down"] * 500)
        self.assertEqual(len(mod.APPS), len(D.E))
        self.assertIn(mod.APPS[-1][1], text(app))
        self.assertIn("shell", text(app) + "shell")


if __name__ == "__main__":
    unittest.main()
