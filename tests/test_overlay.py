"""The priority overlay (kos/overlay.py): merge order, whiteouts, copy-on-write, conflicts, and
every way a hostile mod zip or config can try to get something it should not."""

import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import overlay as ov  # noqa: E402
from kos.auth import Authority, AuthorizationDenied, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import pack  # noqa: E402
from kos.overlay import BASE, Layer, Overlay, OverlayConfig, OverlayError  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402

PW = "correct horse battery"


def layer(name, **files):
    return Layer(name, {k.replace("__", "/"): v for k, v in files.items()})


def zip_bytes(entries, symlink=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if symlink:
            zi = zipfile.ZipInfo(symlink)
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, "/etc/passwd")
    return buf.getvalue()


class TestMerge(unittest.TestCase):
    def setUp(self):
        self.base = layer("base", **{"core__kernel.cfg": b"K", "ui__theme": b"base-theme",
                                     "ui__font": b"base-font", "audio__beep": b"base-beep"})
        self.o = Overlay(self.base)
        self.a = Layer("mod-a", {"ui/theme": b"a-theme", "audio/beep": b"a-beep"})
        self.b = Layer("mod-b", {"ui/theme": b"b-theme", "ui/extra": b"b-extra"})
        self.o.add(self.a)
        self.o.add(self.b)

    def test_a_layer_that_is_not_in_the_order_is_off(self):
        self.assertEqual(self.o.read("ui/theme"), b"base-theme")
        self.o.set_order(["mod-a"])
        self.assertEqual(self.o.read("ui/theme"), b"a-theme")
        self.assertFalse(self.o.exists("ui/extra"))          # mod-b is still off

    def test_the_last_in_the_load_order_wins_and_flipping_it_flips_the_winner(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.assertEqual(self.o.read("ui/theme"), b"b-theme")
        self.o.set_order(["mod-b", "mod-a"])
        self.assertEqual(self.o.read("ui/theme"), b"a-theme")

    def test_a_rule_gives_one_folder_a_different_order(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.o.set_rules({"ui/": ["mod-b", "mod-a"]})        # under ui/ a wins
        self.assertEqual(self.o.read("ui/theme"), b"a-theme")
        self.assertEqual(self.o.read("audio/beep"), b"a-beep")  # outside the rule: untouched
        r = self.o.resolve("ui/theme")
        self.assertEqual((r.provider, r.shadowed), ("mod-a", ("mod-b", "base")))

    def test_the_longest_matching_rule_wins(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.o.set_rules({"/": ["mod-a", "mod-b"], "ui/": ["mod-b", "mod-a"]})
        self.assertEqual(self.o.read("ui/theme"), b"a-theme")   # ui/ beats /
        self.assertEqual(self.o.read("audio/beep"), b"a-beep")

    def test_a_rule_matches_whole_folders_only(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.o.set_rules({"ui/": ["mod-b", "mod-a"]})
        o2 = Overlay(layer("base", **{"uix__theme": b"x"}))
        o2.add(Layer("mod-a", {"uix/theme": b"a"}))
        o2.add(Layer("mod-b", {"uix/theme": b"b"}))
        o2.set_order(["mod-a", "mod-b"])
        o2.set_rules({"ui/": ["mod-b", "mod-a"]})
        self.assertEqual(o2.read("uix/theme"), b"b")

    def test_whiteout_hides_lower_layers_and_a_higher_layer_can_bring_it_back(self):
        self.o.add(Layer("mod-c", {"ui/font": None}))
        self.o.add(Layer("mod-d", {"ui/font": b"d-font"}))
        self.o.set_order(["mod-c"])
        self.assertFalse(self.o.exists("ui/font"))
        r = self.o.resolve("ui/font")
        self.assertEqual((r.provider, r.hidden_by, r.shadowed), (None, "mod-c", ("base",)))
        self.o.set_order(["mod-c", "mod-d"])
        self.assertEqual(self.o.read("ui/font"), b"d-font")

    def test_listing_merges_layers_and_a_folder_with_nothing_visible_disappears(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.assertEqual(self.o.listdir(), ["audio/", "core/", "ui/"])
        self.assertEqual(self.o.listdir("ui"), ["extra", "font", "theme"])
        self.o.add(Layer("mod-c", {"audio/beep": None}))
        self.o.set_order(["mod-a", "mod-b", "mod-c"])
        self.assertNotIn("audio/", self.o.listdir())

    def test_conflicts_name_the_winner_and_the_hidden_and_flag_identical_bytes(self):
        self.o.add(Layer("mod-c", {"ui/font": b"base-font", "ui/theme": None}))
        self.o.set_order(["mod-a", "mod-b", "mod-c"])
        got = {c.path: c for c in self.o.conflicts()}
        self.assertEqual(set(got), {"ui/theme", "ui/font", "audio/beep"})
        self.assertEqual((got["ui/theme"].winner, got["ui/theme"].losers), (None, ("mod-b", "mod-a", "base")))
        self.assertTrue(got["ui/font"].identical)
        self.assertFalse(got["audio/beep"].identical)
        self.assertNotIn("ui/extra", got)                    # only one provider: not a conflict

    def test_the_order_must_name_installed_layers_once_and_never_base(self):
        for bad in (["nope"], ["mod-a", "mod-a"], ["base"], "mod-a", [1]):
            with self.assertRaises(OverlayError):
                self.o.set_order(bad)
        with self.assertRaises(OverlayError):
            self.o.set_rules({"ui": ["mod-a"]})              # not a folder
        with self.assertRaises(OverlayError):
            self.o.set_rules({"ui/": ["ghost"]})

    def test_removing_a_mod_puts_everything_back(self):
        self.o.set_order(["mod-a", "mod-b"])
        self.o.remove("mod-b")
        self.assertEqual(self.o.read("ui/theme"), b"a-theme")
        self.assertEqual(self.o.order, ["mod-a"])
        with self.assertRaises(OverlayError):
            self.o.remove("base")


class TestNothingIsDestroyed(unittest.TestCase):
    def test_mods_and_user_changes_never_alter_any_layer(self):
        base = layer("base", **{"ui__theme": b"base", "core__k": b"K"})
        a = Layer("mod-a", {"ui/theme": b"a", "ui/new": b"n"})
        before = (base.digest(), a.digest())
        o = Overlay(base)
        o.add(a)
        o.set_order(["mod-a"])
        o.write("ui/theme", b"mine")
        o.delete("ui/new")
        self.assertEqual(o.read("ui/theme"), b"mine")
        self.assertFalse(o.exists("ui/new"))
        self.assertEqual((base.digest(), a.digest()), before)
        o.revert("ui/theme")
        o.revert("ui/new")
        self.assertEqual((o.read("ui/theme"), o.read("ui/new")), (b"a", b"n"))

    def test_layer_contents_are_read_only(self):
        l = layer("base", **{"a": b"1"})
        with self.assertRaises(TypeError):
            l.files["a"] = b"2"
        with self.assertRaises(TypeError):
            del l.files["a"]

    def test_the_input_dict_cannot_change_a_layer_afterwards(self):
        src = {"a": b"1"}
        l = Layer("mod-a", src)
        src["a"] = b"2"
        src["b"] = b"3"
        self.assertEqual(dict(l.files), {"a": b"1"})

    def test_user_writes_to_a_protected_path_are_refused(self):
        o = Overlay(layer("base", **{"core__k": b"K"}))
        for call in (lambda: o.write("core/k", b"x"), lambda: o.delete("core/k")):
            with self.assertRaises(OverlayError):
                call()
        self.assertEqual(o.read("core/k"), b"K")

    def test_a_mod_that_touches_a_protected_path_is_refused_whole(self):
        o = Overlay(layer("base", **{"core__k": b"K"}))
        for files in ({"core/k": b"evil"}, {"core/k": None}, {"ok": b"1", "core/new": b"x"}):
            with self.assertRaises(OverlayError):
                o.add(Layer("mod-x", files))
        self.assertEqual(o.layer_names(), [])


class TestHostilePaths(unittest.TestCase):
    BAD = ["", "/etc/passwd", "../x", "a/../b", "a/./b", "a//b", "a/", "a\\b", "a\x00b", "a\nb",
           "a\x1b[2Jb", "a‮b", "a\x85b", "x" * 241, "/".join(["d"] * 25), ".", "..", 5, None]

    def test_every_bad_path_is_refused_everywhere_a_path_goes_in(self):
        o = Overlay(layer("base"))
        for p in self.BAD:
            with self.subTest(p=p):
                with self.assertRaises(OverlayError):
                    Layer("mod-a", {p: b"x"})
                with self.assertRaises(OverlayError):
                    o.read(p)
                with self.assertRaises(OverlayError):
                    o.write(p, b"x")

    def test_error_text_cannot_carry_control_characters(self):
        try:
            Overlay(layer("base")).read("a\x1b[2Jb")
        except OverlayError as e:
            self.assertNotIn("\x1b", str(e))

    def test_bad_layer_names_sizes_and_counts(self):
        for name in ("Bad", "a b", "", "../x", None, 5):
            with self.assertRaises(OverlayError):
                Layer(name, {})
        with self.assertRaises(OverlayError):
            Layer("mod-a", {"a": b"x" * (ov.MAX_FILE + 1)})
        with self.assertRaises(OverlayError):
            Layer("mod-a", {"a": "text, not bytes"})
        with self.assertRaises(OverlayError):
            Layer("mod-a", {f"f{i}": b"" for i in range(ov.MAX_FILES + 1)})

    def test_reserved_names_and_duplicates(self):
        o = Overlay(layer("base"))
        o.add(Layer("mod-a", {}))
        for name in ("mod-a",):
            with self.assertRaises(OverlayError):
                o.add(Layer(name, {}))
        with self.assertRaises(OverlayError):
            o.add(Layer("base", {}))
        with self.assertRaises(OverlayError):
            o.add(Layer("user", {}))
        with self.assertRaises(OverlayError):
            Overlay(Layer("mod-a", {}))                      # the base must be called base


class TestFromZip(unittest.TestCase):
    def test_reads_only_the_prefix_and_never_extracts(self):
        z = zip_bytes({"app.py": b"code", "overlay/ui/theme": b"t", "overlay/ui/old.kos-delete": b"",
                       "overlay/sounds/a.wav": b"w"})
        l = Layer.from_zip("mod-a", z, ov.OVERLAY_DIR)
        self.assertEqual(dict(l.files), {"ui/theme": b"t", "ui/old": None, "sounds/a.wav": b"w"})

    def test_hostile_zips_are_refused(self):
        cases = {
            "traversal": zip_bytes({"overlay/../evil": b"x"}),
            "absolute": zip_bytes({"overlay//etc/passwd": b"x"}),
            "symlink": zip_bytes({}, symlink="overlay/link"),
            "huge": zip_bytes({"overlay/big": b"\0" * (ov.MAX_FILE + 1)}),
            "bomb": zip_bytes({"overlay/b": b"\0" * (ov.MAX_FILE - 1)}),
            "marker with data": zip_bytes({"overlay/a.kos-delete": b"x"}),
            "file and deletion": zip_bytes({"overlay/a": b"x", "overlay/a.kos-delete": b""}),
            "deletion and file": zip_bytes({"overlay/a.kos-delete": b"", "overlay/a": b"x"}),
            "not a zip": b"PK nope",
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(OverlayError):
                    Layer.from_zip("mod-a", data, ov.OVERLAY_DIR)

    def test_a_marker_for_a_bad_path_is_refused(self):
        with self.assertRaises(OverlayError):
            Layer.from_zip("mod-a", zip_bytes({"overlay/../x.kos-delete": b""}), ov.OVERLAY_DIR)


class ConfigEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        self.paths.ensure()
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.cfg = OverlayConfig(self.paths)

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def mod(self, name, files, permit=True):
        src = Path(self.tmp.name) / "src" / name
        (src / "overlay").mkdir(parents=True, exist_ok=True)
        (src / "manifest.json").write_text(json.dumps({
            "name": name, "version": "1.0", "runtime": "python", "entry": "app:main", "modes": ["tui"],
            "description": "a mod"}))
        (src / "app.py").write_text("def main(app):\n    pass\n")
        for rel, data in files.items():
            p = src / "overlay" / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        pack(src, self.paths.apps / f"{name}.kapp")
        if permit:
            PermitStore(self.paths).grant(name, declared=[])


class TestConfig(ConfigEnv):
    def test_the_order_needs_the_password_and_nothing_is_saved_without_it(self):
        self.mod("mod-a", {"x": b"1"})
        with self.assertRaises(AuthorizationDenied):
            self.cfg.save(self.authority("wrong", "wrong", "wrong"), ["mod-a"])
        self.assertFalse(self.cfg.file.exists())
        self.cfg.save(self.authority(PW), ["mod-a"])
        self.assertEqual([e["name"] for e in self.cfg.load()["order"]], ["mod-a"])
        self.assertIn(("overlay.order", "granted"),
                      [(e["action"], e["outcome"]) for e in Authority(
                          self.paths, ScriptedPrompter([]), Throttle(self.paths, base=0)).audit.entries()])

    def test_bad_input_is_refused_before_the_password_is_asked(self):
        self.mod("mod-a", {"x": b"1"})
        a = self.authority()                                 # no answers: any prompt fails the test
        for mods, rules in ((["mod-a", "mod-a"], None), (["../x"], None), ("mod-a", None),
                            (["mod-a"], {"ui": ["mod-a"]}), (["mod-a"], {"ui/": ["ghost"]})):
            with self.assertRaises(OverlayError):
                self.cfg.save(a, mods, rules)
        self.assertEqual(self.prompter.asked, [])

    def test_only_installed_apps_with_an_overlay_folder_can_be_mods(self):
        self.mod("plain", {})                                # overlay/ is empty: pack drops empty dirs
        for name in ("ghost", "plain"):
            with self.assertRaises(OverlayError):
                self.cfg.save(self.authority(PW), [name])
        self.assertFalse(self.cfg.file.exists())

    def test_build_merges_the_approved_mods_in_order(self):
        self.mod("mod-a", {"ui/theme": b"a"})
        self.mod("mod-b", {"ui/theme": b"b", "ui/more": b"m"})
        self.cfg.save(self.authority(PW), ["mod-a", "mod-b"], {"ui/": ["mod-b", "mod-a"]})
        o, skipped = self.cfg.build(layer("base", **{"ui__theme": b"0"}))
        self.assertEqual(skipped, [])
        self.assertEqual(o.read("ui/theme"), b"a")           # the rule put a first under ui/
        self.assertEqual(o.read("ui/more"), b"m")

    def test_a_changed_removed_or_unpermitted_mod_is_skipped_with_a_reason(self):
        for n in ("mod-a", "mod-b", "mod-c"):
            self.mod(n, {"f": n.encode()})
        self.cfg.save(self.authority(PW), ["mod-a", "mod-b", "mod-c"])
        self.mod("mod-a", {"f": b"tampered"})                # same name, different zip
        (self.paths.apps / "mod-b.kapp").unlink()
        PermitStore(self.paths).revoke("mod-c")
        o, skipped = self.cfg.build(layer("base"))
        self.assertEqual({s["name"] for s in skipped}, {"mod-a", "mod-b", "mod-c"})
        why = {s["name"]: s["why"] for s in skipped}
        self.assertIn("changed", why["mod-a"])
        self.assertIn("no longer installed", why["mod-b"])
        self.assertIn("permitted", why["mod-c"])
        self.assertFalse(o.exists("f"))

    def test_a_mod_with_a_protected_file_is_skipped_not_applied(self):
        self.mod("mod-a", {"core/k": b"evil"})
        self.cfg.save(self.authority(PW), ["mod-a"])
        o, skipped = self.cfg.build(layer("base", **{"core__k": b"K"}))
        self.assertEqual(o.read("core/k"), b"K")
        self.assertIn("protected", skipped[0]["why"])

    def test_a_missing_config_is_an_empty_overlay(self):
        o, skipped = self.cfg.build(layer("base", **{"a": b"1"}))
        self.assertEqual((o.files(), skipped), (["a"], []))

    def test_a_malformed_config_is_refused_not_guessed_at(self):
        self.paths.state.mkdir(parents=True, exist_ok=True)
        for text in ("not json", "[]", '{"order": [], "rules": {}, "extra": 1}',
                     '{"order": [{"name": "../x", "sha256": "' + "0" * 64 + '"}], "rules": {}}',
                     '{"order": [{"name": "mod-a", "sha256": "short"}], "rules": {}}',
                     '{"order": [], "rules": {"ui": []}}',
                     '{"order": [], "rules": {"ui/": ["ghost"]}}'):
            self.cfg.file.write_text(text)
            with self.subTest(text=text):
                with self.assertRaises(OverlayError):
                    self.cfg.load()


class TestCli(ConfigEnv):
    def run_cli(self, *argv, answers=(PW,)):
        from kos import cli
        old = os.environ.get("KOS_ROOT")
        os.environ["KOS_ROOT"] = self.tmp.name
        out, err = io.StringIO(), io.StringIO()
        real = cli._authority
        cli._authority = lambda paths: (Authority(paths, ScriptedPrompter(list(answers)),
                                                  Throttle(paths, base=0)), None)
        so, se = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = cli.main(list(argv))
        finally:
            sys.stdout, sys.stderr = so, se
            cli._authority = real
            if old is None:
                os.environ.pop("KOS_ROOT", None)
            else:
                os.environ["KOS_ROOT"] = old
        return code, out.getvalue(), err.getvalue()

    def test_order_show_and_conflicts_each_ask_for_the_password(self):
        self.mod("mod-a", {"ui/theme": b"a"})
        self.mod("mod-b", {"ui/theme": b"b"})
        code, out, _ = self.run_cli("overlay", "order", "mod-a", "mod-b")
        self.assertEqual(code, 0)
        self.assertIn("mod-a < mod-b", out)
        code, out, _ = self.run_cli("overlay", "show", "--deep")
        self.assertIn("ui/theme", out)
        self.assertIn("mod-b", out)
        code, out, _ = self.run_cli("overlay", "conflicts")
        self.assertIn("1 conflict", out)
        for argv in (("overlay", "order", "mod-a"), ("overlay", "show"), ("overlay", "conflicts")):
            code, _, err = self.run_cli(*argv, answers=("nope", "nope", "nope"))
            self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
