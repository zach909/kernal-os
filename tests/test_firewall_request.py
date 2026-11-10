"""An app's request to see or change the firewall rules, through the OS (narrow 'firewall' permission).

Refusals first: every odd request is refused with nothing written (firewall.json is compared byte for byte)."""

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import firewall as F  # noqa: E402
from kos.auth import ACTIONS, Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KAppError, Manifest  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.system import SystemBridge  # noqa: E402
from test_sysinfo import install_fake  # noqa: E402

PW = "correct horse battery"


def req(op, **kw):
    return {"cmd": "request", "action": "firewall", "op": op, **kw}


def allow(**kw):
    return req("allow", **{"who": "app:web", "host": "example.org", "port": 443, "proto": "https", **kw})


def remove(**kw):
    return req("remove", **{"who": "app:web", "host": "example.org", "port": 443, **kw})


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        install_fake(self.paths, "web")
        self.out = []

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def audit_text(self):
        f = self.paths.logs / "audit.log"
        return f.read_text() if f.exists() else ""

    def rules_bytes(self):
        f = F.rules_path(self.paths)
        return f.read_bytes() if f.exists() else None

    def bridge(self, **kw):
        return SystemBridge(self.paths, **{"app": "panel", "system": False, "firewall": True, **kw})

    def ask(self, b, msg, *answers):
        """Through the protocol validator exactly as a real app's message goes."""
        b.handle(validate_app_message(msg, "tui"), self.out.append, self.authority(*answers))
        return self.out[-1]

    def raw(self, b, msg, *answers):
        """Past the protocol (what a buggy validator would let through): the bridge must still refuse."""
        b.handle(msg, self.out.append, self.authority(*answers))
        return self.out[-1]


ODD = [req("flush"), req("LIST"), req("list "), req(5), req(None), req(["list"]), req(""), req("x" * 100000),
       req("list", extra=1), req("log", who="app:web"), req("list", host="x.example"),
       {"cmd": "request", "action": "firewall"}, {"cmd": "request", "action": "firewall", "op": b"list"},
       allow(extra=1), allow(remove=True), remove(proto="https"),
       {k: v for k, v in allow().items() if k != "who"}, {k: v for k, v in allow().items() if k != "proto"},
       {k: v for k, v in remove().items() if k != "port"},
       allow(host="*"), remove(host="*"), allow(who="app:web", host="*", proto="loopback"),
       allow(who="user:root"), allow(who="app:"), allow(who="APP:web"), allow(who="app:web "), allow(who="os:other"),
       allow(who=5), allow(who=None), allow(who="app:../x"), allow(who="app:" + "a" * 40),
       allow(host="https://example.org"), allow(host="example.org:443"), allow(host="EXAMPLE.org/"), allow(host="exa mple.org"),
       allow(host="127.1"), allow(host="0.0.0.0"), allow(host="ex\x1b[31m.org"), allow(host="é.org"), allow(host=5), allow(host=None),
       allow(port=0), allow(port=65536), allow(port=-1), allow(port="443"), allow(port=True), allow(port=443.0), allow(port=None),
       allow(proto="http"), allow(proto="HTTPS"), allow(proto=None), allow(proto="loopback"), allow(proto="*"),
       remove(port=0), remove(port="443"), remove(who="nobody"), remove(host=None)]


class TestRefusals(Env):
    def test_odd_requests_never_pass_the_protocol(self):
        for msg in ODD:
            with self.assertRaises(ProtocolError, msg=str(msg)[:80]):
                validate_app_message(msg, "tui")

    def test_odd_requests_past_the_protocol_are_refused_by_the_bridge_with_nothing_written(self):
        F.add_rule(self.paths, "app:web", "keep.example", 443, "https")
        before = self.rules_bytes()
        b = self.bridge()
        for msg in ODD:
            r = self.raw(b, dict(msg))                # no password answers: a prompt would fail anyway
            self.assertEqual(r, {"cmd": "firewall", "ok": False, "error": "refused"}, str(msg)[:80])
        self.assertEqual(self.rules_bytes(), before)
        self.assertEqual(self.prompter.asked, [])      # refused BEFORE any password question
        self.assertNotIn("x" * 50, self.audit_text())  # nothing an app typed is audited

    def test_wildcard_is_refused_from_an_app(self):
        before = self.rules_bytes()
        for m in (allow(host="*"), allow(host="*", who="os:assistant"), remove(host="*")):
            with self.assertRaises(ProtocolError):
                validate_app_message(m, "tui")
            self.assertEqual(self.raw(self.bridge(), m)["error"], "refused")
        self.assertEqual(self.rules_bytes(), before)

    def test_unknown_who_is_refused_for_allow(self):
        self.assertEqual(self.ask(self.bridge(), allow(who="app:ghost"), PW)["error"], "refused")
        self.assertFalse(F.load(self.paths))
        self.assertEqual(self.prompter.asked, [])

    def test_without_the_permission_nothing_happens(self):
        for kw in ({"firewall": False, "system": True}, {"firewall": False, "sysinfo": True}, {"firewall": False, "assistant": True}):
            for m in (req("list"), req("log"), allow(), remove()):
                self.assertEqual(self.ask(self.bridge(**kw), m), {"cmd": "firewall", "ok": False, "error": "refused"})
        self.assertIsNone(self.rules_bytes())

    def test_a_session_without_a_bridge_refuses(self):
        sent = []
        Session._on_request(types.SimpleNamespace(bridge=None, _send=sent.append), validate_app_message(req("list"), "tui"))
        self.assertEqual(sent, [{"cmd": "firewall", "ok": False, "error": "refused"}])

    def test_no_password_means_no_list_log_allow_or_remove(self):
        F.add_rule(self.paths, "app:web", "keep.example", 443, "https")
        before = self.rules_bytes()
        for answers in ([None], ["no", "no", "no"], [b""] * 3):
            for m in (req("list"), req("log"), allow(), remove(host="keep.example")):
                r = self.ask(self.bridge(), m, *answers)
                self.assertEqual(r, {"cmd": "firewall", "ok": False, "error": "refused"}, m)
        self.assertEqual(self.rules_bytes(), before)

    def test_a_refusal_for_list_is_cached_but_changes_ask_again(self):
        b = self.bridge()
        self.assertEqual(self.ask(b, req("list"), None)["error"], "refused")
        self.assertEqual(self.ask(b, req("log"))["error"], "refused")          # no answers: a prompt would fail
        self.assertEqual(self.ask(b, allow(), None)["error"], "refused")
        self.assertTrue(self.prompter.asked)                                    # allow DID ask
        self.assertFalse(F.load(self.paths))

    def test_an_app_cannot_nag_for_the_password_after_two_denials(self):
        b = self.bridge()
        self.assertEqual(self.ask(b, allow(), None)["error"], "refused")       # 1st prompt, owner cancels
        self.assertEqual(self.ask(b, allow(host="a.example.org"), None)["error"], "refused")   # 2nd prompt, owner cancels
        before = len(self.prompter.asked)
        for _ in range(5):                                                      # no answers at all: a prompt would be visible
            self.assertEqual(self.ask(b, allow(host="b.example.org"))["error"], "refused")
            self.assertEqual(self.ask(b, remove())["error"], "refused")
        self.assertEqual(len(self.prompter.asked), 0)                           # latched: not one more prompt
        self.assertFalse(F.load(self.paths))
        b2 = self.bridge()                                                      # a new app instance starts fresh
        self.assertEqual(self.ask(b2, allow(), PW)["ok"], True)

    def test_audit_failure_means_nothing_is_read(self):
        a = self.authority(PW)
        with mock.patch.object(type(a.audit), "record", side_effect=OSError):
            self.bridge().handle(validate_app_message(req("list"), "tui"), self.out.append, a)
        self.assertEqual(self.out[-1]["ok"], False)

    def test_a_firewall_only_app_cannot_do_anything_else(self):
        b = self.bridge()
        for r in ({"cmd": "request", "action": "apps"}, {"cmd": "request", "action": "open", "app": "hello", "mode": "tui"},
                  {"cmd": "request", "action": "close", "id": "hello-abcdef"}, {"cmd": "request", "action": "backup"},
                  {"cmd": "request", "action": "backup_add", "path": "/etc"}):
            b.handle(r, self.out.append, self.authority())
            self.assertFalse(self.out[-1]["ok"], r)
            self.assertIn("'system' permission", self.out[-1]["detail"])
        b.handle({"cmd": "request", "action": "sysinfo", "topic": "os"}, self.out.append, self.authority())
        self.assertEqual(self.out[-1], {"cmd": "sysinfo", "ok": False, "error": "refused"})
        b.handle({"cmd": "request", "action": "assistant", "system": "", "messages": [{"role": "user", "content": "x"}]},
                 self.out.append, self.authority())
        self.assertEqual(self.out[-1], {"cmd": "assistant", "ok": False, "error": "refused"})
        b.handle({"cmd": "request", "action": "fetch", "url": "https://example.org/", "method": "GET", "headers": {}, "body": ""},
                 self.out.append, self.authority())
        self.assertEqual(self.out[-1], {"cmd": "fetch", "ok": False, "error": "refused"})
        self.assertEqual(self.prompter.asked, [])

    def test_other_narrow_permissions_cannot_use_the_firewall(self):
        for kw in ({"sysinfo": True}, {"assistant": True}, {"network": True}, {"system": True}):
            self.assertEqual(self.ask(self.bridge(firewall=False, **kw), req("list"))["error"], "refused")

    def test_permission_is_known_exactly(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "a:main"}
        self.assertEqual(Manifest.parse(json.dumps({**base, "permissions": ["firewall"]}).encode()).permissions, ("firewall",))
        for p in ("firewall ", "Firewall", "firewalls"):
            with self.assertRaises(KAppError):
                Manifest.parse(json.dumps({**base, "permissions": [p]}).encode())
        self.assertIn("firewall.read", ACTIONS)
        self.assertIn("firewall.change", ACTIONS)


class TestAllowed(Env):
    def test_list_and_log_ask_once_per_instance(self):
        F.add_rule(self.paths, "app:web", "keep.example", 443, "https")
        F.decide(self.paths, "app:web", "keep.example", 443, "https")
        F.decide(self.paths, "app:web", "no.example", 443, "https")
        b = self.bridge()
        r = self.ask(b, req("list"), PW)
        self.assertEqual(r, {"cmd": "firewall", "ok": True,
                             "rules": [{"who": "app:web", "host": "keep.example", "port": 443, "proto": "https"}]})
        self.assertEqual(self.prompter.asked, ["Password to let an app read the firewall rules and log 'panel (rules and log)': "])
        r = self.ask(b, req("log"))                                              # no prompt, no answers
        self.assertTrue(r["ok"])
        self.assertEqual([(x["host"], x["outcome"]) for x in r["log"]], [("keep.example", "allowed"), ("no.example", "blocked")])
        self.assertEqual(set(r["log"][0]), {"who", "host", "port", "proto", "outcome", "time"})
        self.assertEqual(self.ask(self.bridge(), req("list"), None)["error"], "refused")   # a new instance asks again

    def test_log_is_the_last_100_and_escaped(self):
        for i in range(130):
            F.decide(self.paths, "app:web", f"h{i}.example", 443, "https")
        self.paths.logs.mkdir(parents=True, exist_ok=True)
        a = self.authority(PW)
        a.audit.record("firewall.connect", "app:web ev\x1b[31mil:1 https", "blocked")
        a.audit.record("firewall.connect", "garbage", "blocked")
        r = self.ask(self.bridge(), req("log"), PW)
        self.assertEqual(len(r["log"]), 100)
        self.assertNotIn("\x1b", json.dumps(r))
        self.assertIn("\\x1b", json.dumps(r["log"][-1]) + json.dumps(r["log"][-2]))

    def test_allow_asks_every_time_and_the_prompt_carries_the_exact_rule(self):
        b = self.bridge()
        r = self.ask(b, allow(), PW)
        self.assertEqual(r, {"cmd": "firewall", "ok": True, "detail": "rule added"})
        self.assertEqual(self.prompter.asked,
                         ["Password to change the firewall rules 'allow app:web  example.org:443  https': "])
        self.assertEqual(F.load(self.paths), [{"who": "app:web", "host": "example.org", "port": 443, "proto": "https"}])
        before = self.rules_bytes()
        self.assertEqual(self.ask(b, allow(host="other.example"), None)["error"], "refused")   # asked AGAIN; declined
        self.assertEqual(len(self.prompter.asked), 1)
        self.assertEqual(self.rules_bytes(), before)
        self.assertTrue(self.ask(b, allow(host="other.example"), PW)["ok"])
        self.assertEqual(len(F.load(self.paths)), 2)

    def test_remove_asks_every_time_with_the_rule_and_only_then_removes(self):
        F.add_rule(self.paths, "app:web", "example.org", 443, "https")
        F.add_rule(self.paths, "app:web", "two.example", 443, "https")
        b = self.bridge()
        before = self.rules_bytes()
        self.assertEqual(self.ask(b, remove(), None)["error"], "refused")
        self.assertEqual(self.rules_bytes(), before)
        r = self.ask(b, remove(), PW)
        self.assertEqual(r, {"cmd": "firewall", "ok": True, "detail": "rule removed"})
        self.assertEqual(self.prompter.asked, ["Password to change the firewall rules 'remove app:web example.org:443': "])
        self.assertEqual([x["host"] for x in F.load(self.paths)], ["two.example"])
        self.assertEqual(self.ask(b, remove(), PW)["detail"], "no such rule")

    def test_an_os_party_can_be_allowed(self):
        self.assertTrue(self.ask(self.bridge(), allow(who="os:assistant", host="127.0.0.1", port=8080, proto="loopback"), PW)["ok"])
        self.assertEqual(F.load(self.paths)[0]["who"], "os:assistant")

    def test_audit_has_the_rule_and_never_data(self):
        F.add_rule(self.paths, "app:web", "secret-listed.example", 443, "https")
        self.ask(self.bridge(), allow(), PW)
        self.ask(self.bridge(), req("list"), PW)
        log = self.audit_text()
        self.assertIn('"action":"firewall.change"', log)
        self.assertIn("allow app:web  example.org:443  https", log)
        self.assertIn('"action":"firewall.request"', log)
        self.assertIn('"target":"panel allow"', log)
        self.assertIn('"action":"firewall.read"', log)
        self.assertNotIn("secret-listed.example", log)            # list output is never written to the log

    def test_a_crash_is_a_fixed_phrase(self):
        with mock.patch.object(F, "load", side_effect=RuntimeError("boom PLANTED")):
            r = self.ask(self.bridge(), req("list"), PW)
        self.assertEqual(r, {"cmd": "firewall", "ok": False, "error": "unavailable"})
        self.assertNotIn("PLANTED", json.dumps(self.out) + self.audit_text())

    def test_rule_limit_is_a_fixed_refusal(self):
        with mock.patch.object(F, "MAX_RULES", 1):
            self.assertTrue(self.ask(self.bridge(), allow(), PW)["ok"])
            self.assertEqual(self.ask(self.bridge(), allow(host="b.example"), PW)["error"], "refused")


class TestSdkAndApp(unittest.TestCase):
    def test_sdk_round_trip(self):
        from collections import deque
        from kos.sdk import App
        a = App.__new__(App)
        sent, events = [], [{"cmd": "key", "key": "a"}, {"cmd": "firewall", "ok": True, "rules": [], "junk": 1}]
        a._queue = deque()
        a.send = sent.append
        a._read_event = lambda: events.pop(0) if events else None
        self.assertEqual(a.firewall("list"), (True, {"rules": []}))
        self.assertEqual(sent, [req("list")])
        self.assertEqual(a._queue[0], {"cmd": "key", "key": "a"})
        sent.clear()
        events[:] = [{"cmd": "firewall", "ok": True, "detail": "rule added"}]
        self.assertEqual(a.firewall("allow", "app:web", "example.org", 443, "https"), (True, {"detail": "rule added"}))
        self.assertEqual(sent, [allow()])
        sent.clear()
        events[:] = [{"cmd": "firewall", "ok": False, "error": "refused"}]
        self.assertEqual(a.firewall("remove", "app:web", "example.org", 443), (False, "refused"))
        self.assertEqual(sent, [remove()])
        events[:] = []
        self.assertEqual(a.firewall("list"), (False, "unreachable"))

    def test_the_app_survives_a_key_battery_and_changes_only_through_the_host(self):
        from kos.office.pack_os import ENTRIES
        from kos.office.ui import FakeHost, run
        e = next(e for e in ENTRIES if e.title == "Firewall Management")
        rules = [{"who": "app:web", "host": "example.org", "port": 443, "proto": "https"},
                 {"who": "os:assistant", "host": "*", "port": 443, "proto": "https"}]
        log = [{"who": "app:web", "host": "example.org", "port": 443, "proto": "https", "outcome": "allowed", "time": "2026-01-01 10:00:00"}]

        def fn(op, who="", host="", port=0, proto=""):
            if op == "list": return (True, {"rules": rules})
            if op == "log": return (True, {"log": log})
            return (True, {"detail": "rule added" if op == "allow" else "rule removed"})
        keys = ["r", "down", "up", "pagedown", "home", "end", "x", "enter", "ctrl-n", "d", "escape", "a", "escape", "escape", "q"]
        for f in (fn, None, lambda *a: (False, "unavailable"), lambda *a: 1 / 0, lambda *a: (True, {"rules": "zz", "log": 5})):
            h = FakeHost(keys); h.firewall_fn = f
            run(h, e.args["make"](h, e))
            self.assertTrue(h.frames)
        # add flow: who, host, port, proto
        h = FakeHost(["a", *"app:web", "enter", *"new.example", "enter", *"443", "enter", *"https", "enter"]); h.firewall_fn = fn
        run(h, e.args["make"](h, e))
        self.assertIn(("allow", "app:web", "new.example", 443, "https"), h.firewall_calls)
        # a wildcard or bad rule is never sent
        h = FakeHost(["a", *"app:web", "enter", "*", "enter", *"443", "enter", *"https", "enter"]); h.firewall_fn = fn
        run(h, e.args["make"](h, e))
        self.assertFalse([c for c in h.firewall_calls if c[0] == "allow"])
        # remove flow: rule 1 is removable, the wildcard rule 2 is not sent
        h = FakeHost(["d", "1", "enter"]); h.firewall_fn = fn
        run(h, e.args["make"](h, e))
        self.assertIn(("remove", "app:web", "example.org", 443, ""), h.firewall_calls)
        h = FakeHost(["d", "2", "enter"]); h.firewall_fn = fn
        run(h, e.args["make"](h, e))
        self.assertFalse([c for c in h.firewall_calls if c[0] == "remove"])
        self.assertEqual(e.perms, ("firewall",))


if __name__ == "__main__":
    unittest.main()
