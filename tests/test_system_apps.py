"""The OS's own commands as apps (kos/office/pack_system.py, and five titles in pack_os.py).

Each app is driven by scripted keys against a real ServiceHost with a real authority, so what is tested is the
whole path: a key press, the service call, the password asked in the OS's prompt, the OS's answer on the screen.
Where a screen can be refused (wrong password, missing permission) that is tested next to the success."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import cli  # noqa: E402
from kos.auth import AuditLog, Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KApp, pack  # noqa: E402
from kos.launchmap import APP_FOR_COMMAND, BOOTSTRAP, STILL_THE_OS  # noqa: E402
from kos.office import pack_os, pack_system  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import validate_app_message  # noqa: E402
from kos.scan import EICAR  # noqa: E402
from kos.services import ServiceHost  # noqa: E402
from kos.store import AppStore  # noqa: E402

PW = "correct horse battery"
HELLO = ROOT / "examples" / "hello"
ENTRIES = list(pack_system.ENTRIES) + [e for e in pack_os.ENTRIES if e.scope != "none"]
BY_NAME = {e.name: e for e in ENTRIES}


def typed(s):
    return list(s)


class Os(unittest.TestCase):
    """A real OS state in a temp dir, and an adapter that gives an app host the same view a session would."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.root = Path(self.tmp.name)
        self.paths = Paths(self.root)
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.addCleanup(self.tmp.cleanup)

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def drive(self, name, keys, answers=None, groups=None, width=100, height=30):
        e = BY_NAME[name]
        groups = e.services if groups is None else groups
        self.prompter = ScriptedPrompter(list(answers) if answers is not None else [PW] * 60)
        authority = Authority(self.paths, self.prompter, Throttle(self.paths, base=0))
        host_os = ServiceHost(self.paths, name, frozenset(groups))

        def services(svc, args):
            msg = validate_app_message({"cmd": "service", "id": 1, "name": svc, "args": args}, "tui")
            return host_os.call(msg, authority)
        h = FakeHost(keys, services=services, width=width, height=height)
        run(h, e.args["make"](h, e))
        return h

    def tree(self):
        d = self.root / "tree"
        d.mkdir(exist_ok=True)
        (d / "note.txt").write_text("hello from a note\nsecond line\n")
        (d / "bin.dat").write_bytes(b"\x00\x01\x02")
        (d / "eicar.txt").write_bytes(EICAR)
        (d / "evil\x1b[31mname.txt").write_text("x")
        pack(HELLO, d / "hello.kapp")
        return d


class TestTheCatalogue(unittest.TestCase):
    def test_every_command_is_an_app_or_says_why_it_is_still_the_os(self):
        cmds = set(cli.COMMANDS)
        self.assertEqual(cmds, set(APP_FOR_COMMAND) | set(BOOTSTRAP) | set(STILL_THE_OS))
        groups = [set(APP_FOR_COMMAND), set(BOOTSTRAP), set(STILL_THE_OS)]
        for i, a in enumerate(groups):
            for b in groups[i + 1:]:
                self.assertFalse(a & b, "a command is in exactly one group")
        for n, why in STILL_THE_OS.items():
            self.assertGreater(len(why), 10, n)
        for n in BOOTSTRAP:
            self.assertIn(n, cli.COMMANDS)

    def test_every_command_that_moved_points_at_a_real_app(self):
        from kos.office.packs import entries as all_packs
        names = {e.name for e in ENTRIES} | {e.name for e in all_packs()}      # kos-help is an older pack app
        for cmd, appname in {**APP_FOR_COMMAND, **BOOTSTRAP}.items():
            self.assertIn(appname, names, cmd)

    def test_a_converted_command_is_only_a_launcher_in_the_command_line(self):
        for cmd in APP_FOR_COMMAND:
            if cmd in ("scan", "skills"):
                continue            # `scan watch` is a watcher, `skills --out` a guarded write: both stay the OS's
            self.assertEqual(cli.COMMANDS[cmd].__qualname__, "_launcher.<locals>.go", cmd)
        self.assertEqual(cli.COMMANDS["scan"].__name__, "cmd_scan")
        self.assertEqual(cli.COMMANDS["skills"].__name__, "cmd_skills")

    def test_a_launcher_for_an_app_that_is_not_installed_says_so_and_does_nothing(self):
        import contextlib
        import io
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as td:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = cli.COMMANDS["audit"](SimpleNamespace(cmd="audit", n=5, verify=False), Paths(Path(td)))
            self.assertEqual(code, 66)
            self.assertIn("audit-log", err.getvalue())
            self.assertIn("kos desktop install", err.getvalue())

    def test_the_apps_ask_for_exactly_the_groups_they_use_and_only_the_terminal_may_open_apps(self):
        from suite import gen
        from kos.servicespec import GROUPS
        with tempfile.TemporaryDirectory() as td:
            made = gen.build(Path(td))
            for e in ENTRIES:
                self.assertIn(e.name, made)
                perms = KApp.from_file(Path(td) / f"{e.name}.kapp").manifest.permissions
                self.assertEqual(sorted(p[8:] for p in perms if p.startswith("service:")), sorted(e.services), e.name)
                self.assertTrue(set(e.services) <= set(GROUPS), e.name)
                self.assertNotIn("network", perms, e.name)
                self.assertEqual("system" in perms, e.name == "terminal", e.name)

    def test_the_apps_hold_no_os_logic_the_same_syntax_guard_as_every_pack(self):
        from tests.test_packs import TestPacksAreLight as G
        self.assertEqual(G.violations((ROOT / "kos" / "office" / "pack_system.py").read_text()), [])

    def test_notes_say_what_is_missing(self):
        for e in ENTRIES:
            if e.scope == "partial":
                self.assertGreater(len(e.note), 60, e.name)


class TestKeyBattery(Os):
    OPENS = ["r", "enter", "a", "d", "g", "x", "v", "f", "p", "s", "o", "c", "n", "i", "u", "l", "1", "up", "down"]
    BODY = ["T", "e", "1", "enter", "down", "enter", "y", "escape", "enter", "ctrl-u", "escape", "y", "escape"]

    def battery(self, answers, groups=None):
        for e in ENTRIES:
            for o in self.OPENS:
                h = self.drive(e.name, [o] + self.BODY, answers=answers, groups=groups)
                for t, lines, st in h.frames:
                    validate_app_message({"cmd": "screen", "title": t, "lines": lines, "status": st}, "tui")
                    self.assertNotIn("Internal error", t + " ".join(lines), (e.name, o))

    def test_no_key_sequence_crashes_an_app_when_the_password_is_right(self):
        self.battery(None)

    def test_nor_when_the_password_is_wrong(self):
        self.battery(["no"] * 4000)

    def test_nor_when_the_manifest_has_no_permission(self):
        self.battery(None, groups=[])


class TestRefusals(Os):
    def test_with_no_permission_an_app_shows_the_reason_and_no_data(self):
        h = self.drive("audit-log", ["r"], groups=[])
        self.assertIn("refused", h.frames[-1][2])
        self.assertIn("service:audit", h.frames[-1][2])
        self.assertNotIn("granted", h.text)

    def test_a_wrong_password_shows_refused_and_never_the_data(self):
        h = self.drive("audit-log", ["r"], answers=["no"] * 10)
        self.assertIn("refused", h.frames[-1][2])
        self.assertNotIn("audit.read", "\n".join(h.frames[-1][1]))

    def test_each_read_asks_for_the_password_again(self):
        self.drive("audit-log", ["r", "r", "r"])
        self.assertEqual(sum(1 for p in self.prompter.asked if "view the authorization log" in p), 3)


class TestReadingApps(Os):
    def test_audit_log_reads_the_log_and_verifies_it(self):
        h = self.drive("audit-log", ["r"])
        self.assertIn("audit.read", h.text)
        self.assertIn("granted", h.text)
        h = self.drive("audit-log", ["v"])
        self.assertIn("intact", h.text)

    def test_audit_log_says_tampered_when_the_chain_is_broken(self):
        for i in range(4):
            AuditLog(self.paths).record("file.view", f"/x/{i}", "granted")
        f = AuditLog(self.paths).file
        lines = f.read_text().splitlines()
        f.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        h = self.drive("audit-log", ["v"])
        self.assertIn("TAMPERED", h.text)
        self.assertNotIn("intact", h.text)

    def test_a_hostile_target_in_the_log_cannot_reach_the_terminal(self):
        AuditLog(self.paths).record("file.view", "x\x1b[2Jy‮exe", "granted")
        h = self.drive("audit-log", ["r"])
        self.assertNotIn("\x1b", h.text)
        self.assertNotIn("‮", h.text)

    def test_security_check_shows_pass_warn_fail_and_a_result(self):
        h = self.drive("security-check", ["r"])
        self.assertRegex(h.text, r"(PASS|WARN|FAIL)")
        self.assertIn("Result:", h.text)

    def test_system_info_says_whether_this_is_the_kos_kernel(self):
        h = self.drive("system-info", ["r"])
        self.assertIn("Landlock ABI", h.text)
        self.assertRegex(h.text, r"KOS kernel +: (present|NOT PRESENT)")
        h = self.drive("system-info", ["f"])
        self.assertIn("policy: kos.firmware=", h.text)
        h = self.drive("system-info", ["p"])
        self.assertIn("read-only", h.text)

    def test_activity_lists_the_decisions_so_far(self):
        AuditLog(self.paths).record("app.run", "hello", "granted")
        h = self.drive("activity", ["r"])
        self.assertIn("granted: app.run hello", h.text)

    def test_disk_care_says_nothing_is_owed_and_optimizes_after_a_yes(self):
        h = self.drive("disk-care", ["r"])
        self.assertIn("nothing is owed", h.text)
        h = self.drive("disk-care", ["o", "y"])
        self.assertIn("reclaimed", h.text)
        n = self.drive("disk-care", ["o", "n"])
        self.assertNotIn("reclaimed", n.text)
        self.assertFalse(any("optimize disk space" in p for p in self.prompter.asked), "answering no asks for nothing")


class TestFilesAndScanner(Os):
    def test_browse_a_folder_and_a_zip_and_read_a_file(self):
        d = self.tree()
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter"])
        self.assertIn("note.txt", h.text)
        self.assertIn("hello.kapp (zip)", h.text)
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d / "hello.kapp")), "enter"])
        self.assertIn("manifest.json", h.text)
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter", "down", "down", "down", "down"] )
        self.assertIn("files", h.text.lower())

    def test_opening_a_text_file_shows_it_and_a_binary_one_is_not_dumped(self):
        d = self.tree()
        # list the folder, move to note.txt (entries are sorted by the VFS; find its row by reading the screen)
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter"])
        rows = [l.strip().lstrip("> ").strip() for l in h.frames[-1][1]]
        i = next(n for n, r in enumerate(rows) if r.startswith("note.txt")) - next(n for n, r in enumerate(rows) if r.startswith(".."))
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter", *(["down"] * i), "enter"])
        self.assertIn("hello from a note", h.text)
        j = next(n for n, r in enumerate(rows) if r.startswith("bin.dat")) - next(n for n, r in enumerate(rows) if r.startswith(".."))
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter", *(["down"] * j), "enter"])
        self.assertIn("binary data: not shown", h.text)

    def test_a_hostile_file_name_is_shown_escaped(self):
        d = self.tree()
        h = self.drive("files", ["g", "ctrl-u", *typed(str(d)), "enter"])
        self.assertNotIn("\x1b", h.text)
        self.assertIn("\\x1b", h.text)

    def test_a_path_that_is_not_there_is_a_reason_not_a_crash(self):
        h = self.drive("files", ["g", "ctrl-u", *typed("/no/such/place"), "enter"])
        self.assertIn("refused", h.frames[-1][2])

    def test_without_the_files_permission_nothing_is_listed(self):
        h = self.drive("files", ["r"], groups=["scan"])
        self.assertIn("refused", h.frames[-1][2])

    def test_scanner_flags_the_test_virus_and_passes_a_clean_file(self):
        d = self.tree()
        h = self.drive("scanner", ["p", *typed(str(d / "eicar.txt")), "enter"])
        self.assertIn("FLAGGED", h.text)
        h = self.drive("scanner", ["p", *typed(str(d / "note.txt")), "enter"])
        self.assertIn("clean", h.text)
        h = self.drive("scanner", ["p", "enter"])                       # an empty path scans nothing, asks nothing
        self.assertFalse(any("view file" in p for p in self.prompter.asked))


class TestFirewallApp(Os):
    def test_add_list_and_remove_a_rule_with_the_password_each_time(self):
        add = ["a", *typed("web"), "enter", "enter", "enter", *typed("93.184.216.34"), "enter", *typed("443"), "enter"]
        h = self.drive("firewall", add)
        self.assertIn("Rule added.", h.text)
        h = self.drive("firewall", ["r"])
        self.assertIn("web", h.text)
        self.assertIn("93.184.216.34:443", h.text)
        self.assertIn("blocked unless a rule", h.text)
        h = self.drive("firewall", ["r", "d", "y"])
        self.assertIn("Rule removed.", h.text)
        h = self.drive("firewall", ["r"])
        self.assertNotIn("93.184.216.34", h.text)

    def test_a_rule_that_is_a_name_or_a_range_is_refused_and_nothing_is_asked(self):
        for bad in ("example.com", "10.0.0.0/8", "*", "0.0.0.0"):
            h = self.drive("firewall", ["a", *typed("web"), "enter", "enter", "enter", *typed(bad), "enter", *typed("80"), "enter"])
            self.assertIn("Refused", h.text, bad)
            self.assertFalse(any("firewall" in p for p in self.prompter.asked), bad)
        h = self.drive("firewall", ["r"])
        self.assertNotIn("web", h.text)

    def test_a_port_that_is_not_a_number_is_refused_in_the_app(self):
        h = self.drive("firewall", ["a", *typed("web"), "enter", "enter", "enter", *typed("1.2.3.4"), "enter", *typed("http"), "enter"])
        self.assertIn("number from 1 to 65535", h.text)
        self.assertEqual(h.service_calls, [])

    def test_it_says_when_the_kernel_cannot_enforce(self):
        h = self.drive("firewall", ["r"])
        self.assertRegex(h.text, r"KOS kernel: (enforcing|NOT PRESENT)")

    def test_a_tampered_rule_file_is_shown_as_failing_its_seal(self):
        self.drive("firewall", ["a", *typed("web"), "enter", "enter", "enter", *typed("1.2.3.4"), "enter", *typed("80"), "enter"])
        from kos.firewall import FirewallStore
        f = FirewallStore(self.paths).file
        raw = json.loads(f.read_text())
        raw["rules"].append({"app": "evil", "proto": "tcp", "direction": "connect", "host": "6.6.6.6", "port": 80})
        f.write_text(json.dumps(raw))
        h = self.drive("firewall", ["r"])
        self.assertIn("FAILED ITS SEAL", h.text)
        self.assertNotIn("6.6.6.6", h.text)

    def test_the_connection_log_view(self):
        h = self.drive("firewall", ["r", "l"])
        self.assertIn("Connection log", h.text)


class TestPackageAndPermissionApps(Os):
    def setUp(self):
        super().setUp()
        self.kapp = self.root / "hello.kapp"
        pack(HELLO, self.kapp)

    def test_install_permit_list_revoke_remove_through_the_app(self):
        h = self.drive("software-updates", ["i", *typed(str(self.kapp)), "enter"])
        self.assertIn("hello", h.text)
        self.assertEqual([a.name for a in AppStore(self.paths).installed()], ["hello"])
        h = self.drive("software-updates", ["r", "p"])
        self.assertIn("may now run", h.text)
        self.assertTrue(PermitStore(self.paths).is_permitted("hello"))
        h = self.drive("software-updates", ["r"])
        self.assertIn("hello", h.text)
        self.assertIn("permitted", h.text)
        h = self.drive("software-updates", ["r", "p"])
        self.assertIn("no longer", h.text)
        h = self.drive("software-updates", ["r", "d", "y"])
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_declining_to_remove_removes_nothing(self):
        AppStore(self.paths).install(self.kapp, Authority(self.paths, ScriptedPrompter([PW]), Throttle(self.paths, base=0)))
        self.drive("software-updates", ["r", "d", "n"])
        self.assertEqual([a.name for a in AppStore(self.paths).installed()], ["hello"])

    def test_a_flagged_package_is_refused_before_a_password(self):
        d = self.root / "bad"
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({"name": "bad", "version": "1", "runtime": "python", "entry": "app:main"}))
        (d / "app.py").write_text("def main(): pass\n")
        (d / "eicar.txt").write_bytes(EICAR)
        pack(d, self.root / "bad.kapp")
        h = self.drive("software-updates", ["i", *typed(str(self.root / "bad.kapp")), "enter"])
        self.assertIn("Refused", h.text)
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_grant_and_revoke_a_shared_folder(self):
        h = self.drive("permissions", ["g", *typed("reader"), "enter", *typed("contacts"), "enter", "enter"])
        self.assertIn("may now read contacts", h.text)
        h = self.drive("permissions", ["r"])
        self.assertIn("contacts", h.text)
        h = self.drive("permissions", ["r", "x", "y"])
        self.assertIn("revoked", h.text)

    def test_converter_refuses_a_missing_package_with_a_reason(self):
        h = self.drive("deb-converter", ["c", *typed("/no/such.deb"), "enter", *typed(str(self.root / "out.kapp")), "enter", "enter"])
        self.assertIn("Refused", h.text)
        self.assertFalse((self.root / "out.kapp").exists())


class TestHelpAndTerminal(Os):
    def test_every_command_in_the_help_table_is_classified(self):
        from kos.office.cmdindex import COMMANDS
        for n, _h, _u in COMMANDS:
            self.assertTrue(n in APP_FOR_COMMAND or n in BOOTSTRAP or n in STILL_THE_OS, n)

    def test_a_command_in_the_terminal_opens_the_app_that_holds_it(self):
        h = self.drive("terminal", [*typed("audit"), "enter"], groups=[])
        self.assertEqual(h.opened, [("app", "audit-log", "tui")])
        self.assertIn("audit-log", h.text)

    def test_a_command_that_is_still_the_os_says_so_and_opens_nothing(self):
        h = self.drive("terminal", [*typed("write notes.txt hello"), "enter"], groups=[])
        self.assertEqual(h.opened, [])
        self.assertIn("OS's own command", h.text)

    def test_unknown_input_is_refused_and_opens_nothing(self):
        h = self.drive("terminal", [*typed("frobnicate the widgets"), "enter"], groups=[])
        self.assertEqual(h.opened, [])
        self.assertIn("don't know", h.text)

    def test_a_line_of_code_is_a_service_call_that_needs_the_password(self):
        h = self.drive("terminal", [*typed("print(6*7)"), "enter"])
        self.assertEqual([c[0] for c in h.service_calls], ["code.run"])
        self.assertIn("42", h.text)

    def test_the_terminal_cannot_run_code_without_the_group(self):
        h = self.drive("terminal", [*typed("print(6*7)"), "enter"], groups=[])
        self.assertNotIn("42", h.text)
        self.assertIn("refused", h.text)


class TestSkillMaker(Os):
    def test_it_shows_skills_for_the_installed_apps(self):
        kapp = self.root / "hello.kapp"
        pack(HELLO, kapp)
        AppStore(self.paths).install(kapp, Authority(self.paths, ScriptedPrompter([PW]), Throttle(self.paths, base=0)))
        h = self.drive("skill-maker", ["r"])
        self.assertIn("SKILL.md", h.text)


class TestInstallingTheOsApps(Os):
    def test_the_bundle_installs_every_app_under_one_password(self):
        from kos import sysapps
        files = sysapps.build(self.root / "built")
        self.assertEqual(len(files), len(ENTRIES))
        a = self.authority(PW)
        ms = AppStore(self.paths).install_bundle(files, a, f"{len(files)} apps")
        self.assertEqual(sorted(m.name for m in ms), sorted(e.name for e in ENTRIES))
        self.assertEqual(sum("install the OS's own apps" in p for p in self.prompter.asked), 1)
        self.assertEqual(len(self.prompter.asked), 1, "one password for the whole bundle")
        self.assertEqual({x.name for x in AppStore(self.paths).installed()}, {e.name for e in ENTRIES})

    def test_one_flagged_file_stops_the_whole_bundle_before_any_password(self):
        from kos import sysapps
        from kos.store import VirusFoundError
        files = sysapps.build(self.root / "built")
        bad = self.root / "bad"
        bad.mkdir()
        (bad / "manifest.json").write_text(json.dumps({"name": "bad", "version": "1", "runtime": "python", "entry": "app:main"}))
        (bad / "app.py").write_text("def main(): pass\n")
        (bad / "eicar.txt").write_bytes(EICAR)
        pack(bad, self.root / "bad.kapp")
        a = self.authority()                                         # no answers: a prompt would raise
        with self.assertRaises(VirusFoundError):
            AppStore(self.paths).install_bundle([*files, self.root / "bad.kapp"], a, "x")
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(AppStore(self.paths).installed(), [], "not even the clean ones were installed")
        self.assertTrue(list((self.paths.state / "quarantine").glob("bad-*.kapp")))

    def test_a_wrong_password_installs_nothing(self):
        from kos import sysapps
        from kos.auth import AuthorizationDenied
        files = sysapps.build(self.root / "built", only={"audit-log", "firewall"})
        with self.assertRaises(AuthorizationDenied):
            AppStore(self.paths).install_bundle(files, self.authority("no", "no", "no"), "2 apps")
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_the_same_app_twice_in_one_bundle_is_refused(self):
        from kos import sysapps
        from kos.kapp import KAppError
        f = sysapps.build(self.root / "built", only={"audit-log"})[0]
        with self.assertRaises(KAppError):
            AppStore(self.paths).install_bundle([f, f], self.authority(), "dup")

    def test_desktop_install_puts_the_os_apps_in_and_permits_them(self):
        from types import SimpleNamespace
        from unittest import mock
        import contextlib
        import io
        prompter = ScriptedPrompter([PW] * 6)
        authority = Authority(self.paths, prompter, Throttle(self.paths, base=0))
        with mock.patch.object(cli, "_authority", lambda paths: (authority, prompter)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.cmd_desktop(SimpleNamespace(src=None), self.paths)
        self.assertEqual(code, 0)
        names = {a.name for a in AppStore(self.paths).installed()}
        self.assertTrue({"taskbar", "app-library"} | {e.name for e in ENTRIES} <= names)
        permits = PermitStore(self.paths)
        for e in ENTRIES:
            self.assertTrue(permits.is_permitted(e.name), e.name)
        self.assertEqual(sum("install the OS's own apps" in p for p in prompter.asked), 1)
        # running it again changes nothing and asks for nothing
        prompter2 = ScriptedPrompter([])
        authority2 = Authority(self.paths, prompter2, Throttle(self.paths, base=0))
        with mock.patch.object(cli, "_authority", lambda paths: (authority2, prompter2)), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_desktop(SimpleNamespace(src=None), self.paths)
        self.assertEqual(prompter2.asked, [])


class TestARealInstalledOsApp(Os):
    """The whole stack: the real .kapp, the real manifest permission, the real sandbox, the real channel."""

    def run_installed(self, name, press, watch_for):
        import socket
        import threading
        import time
        from kos import loader
        from kos.devices import ScriptedDevices
        from kos.protocol import Channel
        from kos.sandbox import SandboxPolicy
        from kos.session import Session
        from kos.tui import TUISurface
        from kos import sysapps
        files = sysapps.build(self.root / "built", only={name})
        store = AppStore(self.paths)
        store.install_bundle(files, self.authority(PW), "1 app")
        PermitStore(self.paths).grant(name, KApp.from_file(files[0]).manifest.permissions)
        with self.authority(PW).authorize("app.run", name) as g:
            app = store.load_verified(name, g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui", None, ""), SandboxPolicy(), None)
        b.close()
        devices, out = ScriptedDevices(), tempfile.TemporaryFile()
        self.addCleanup(out.close)
        session = Session(name=name, mode="tui", channel=Channel(a), proc=proc,
                          surface=TUISurface(out.fileno(), 100, 30, name), devices=devices,
                          authority=Authority(self.paths, None, Throttle(self.paths, base=0)),
                          services=cli._services_for(self.paths, name, app.manifest.permissions),
                          preboot=("mouse", "keyboard"))
        devices.push(*[{"type": "key", "key": c} for c in press])
        seen = {"modal": False, "text": ""}

        def watch():
            typed, end = False, time.monotonic() + 25
            while time.monotonic() < end:
                m = session.surface.modal
                if m is not None and not typed:
                    seen["modal"], typed = m.title, True
                    devices.push(*[{"type": "key", "key": c} for c in PW], {"type": "key", "key": "enter"})
                seen["text"] = os.pread(out.fileno(), 1 << 22, 0).decode(errors="replace")
                if watch_for in seen["text"]:
                    devices.push({"type": "interrupt"})
                    return
                time.sleep(0.03)
            devices.push({"type": "interrupt"})
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        session.run()
        t.join(2)
        return seen

    def test_audit_log_runs_in_the_sandbox_and_the_password_is_typed_in_the_os_prompt(self):
        seen = self.run_installed("audit-log", "r", "audit.read")
        self.assertTrue(seen["modal"], "the OS raised its own password prompt")
        self.assertIn("authorization log", seen["modal"])
        self.assertIn("audit.read", seen["text"])

    def test_the_firewall_app_shows_the_default_deny(self):
        seen = self.run_installed("firewall", "r", "blocked unless a rule")
        self.assertTrue(seen["modal"])
        self.assertIn("blocked unless a rule", seen["text"])


if __name__ == "__main__":
    unittest.main()
