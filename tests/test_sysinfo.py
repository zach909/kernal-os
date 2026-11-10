"""Read-only facts about this computer, read by the OS on an app's behalf.

Refusals first. Nothing here reads the real /proc: `read()` is pointed at fixture roots."""

import builtins
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import sysinfo as S  # noqa: E402
from kos.auth import ACTIONS, Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KAppError, Manifest  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.system import SystemBridge  # noqa: E402

PW = "correct horse battery"
HOST = "secret-hostname-77"
PLANT = "PLANTED-VALUE-4242"


def req(topic="os", **kw):
    return {"cmd": "request", "action": "sysinfo", "topic": topic, **kw}


def fixture(td, *, meminfo=None, battery=True):
    r = Path(td)
    (r / "proc/sys/kernel").mkdir(parents=True)
    (r / "proc/sys/kernel/osrelease").write_text("6.1.0-test\n")
    (r / "proc/sys/kernel/hostname").write_text(HOST + "\n")
    (r / "proc/meminfo").write_text(meminfo or "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
                                    f"Hugepagesize: 1 kB\n{PLANT}: 5 kB\n")
    (r / "proc/uptime").write_text("7200.55 100.0\n")
    (r / "proc/loadavg").write_text("0.50 1.25 2.00 1/200 999\n")
    if battery:
        b = r / "sys/class/power_supply/BAT0"
        b.mkdir(parents=True)
        (b / "type").write_text("Battery\n"); (b / "capacity").write_text("80\n"); (b / "status").write_text("Charging\n")
        (b / "serial_number").write_text(PLANT + "\n"); (b / "model_name").write_text(PLANT + "\n")
    return str(r)


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.out = []

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def audit_text(self):
        f = self.paths.logs / "audit.log"
        return f.read_text() if f.exists() else ""

    def bridge(self, **kw):
        return SystemBridge(self.paths, **{"app": "monitor", "system": False, "sysinfo": True, **kw})

    def ask(self, b, topic, *answers):
        b.handle(validate_app_message(req(topic), "tui"), self.out.append, self.authority(*answers))
        return self.out[-1]


class TestProtocol(unittest.TestCase):
    def test_exact_shape_only(self):
        for t in S.TOPICS:
            self.assertEqual(validate_app_message(req(t), "tui"), req(t))

    def test_odd_topics_and_keys_are_refused(self):
        for msg in (req("../etc/passwd"), req("os; rm -rf /"), req("a" * 100000), req(5), req(None), req(["os"]),
                    req(""), req("OS"), req("os "), req("/proc/meminfo"), req("os", extra=1), req("os", path="/etc"),
                    {"cmd": "request", "action": "sysinfo"}, {"cmd": "request", "action": "sysinfo", "topic": b"os"}):
            with self.assertRaises(ProtocolError, msg=str(msg)[:60]):
                validate_app_message(msg, "tui")

    def test_topics_agree(self):
        from kos.protocol import SYSINFO_TOPICS
        self.assertEqual(set(SYSINFO_TOPICS), set(S.TOPICS))

    def test_permission_and_action(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "a:main"}
        self.assertEqual(Manifest.parse(json.dumps({**base, "permissions": ["sysinfo"]}).encode()).permissions, ("sysinfo",))
        with self.assertRaises(KAppError):
            Manifest.parse(json.dumps({**base, "permissions": ["sysinfo "]}).encode())
        self.assertIn("sysinfo.read", ACTIONS)


class TestBridgeRefusals(Env):
    def test_without_the_permission_nothing_is_read(self):
        with mock.patch.object(S, "read") as rd:
            r = self.ask(self.bridge(sysinfo=False, system=True), "os")
        self.assertEqual(r, {"cmd": "sysinfo", "ok": False, "error": "refused"})
        rd.assert_not_called()
        self.assertIn("monitor os", self.audit_text())

    def test_a_session_without_a_bridge_refuses(self):
        import types
        sent = []
        Session._on_request(types.SimpleNamespace(bridge=None, _send=sent.append), validate_app_message(req(), "tui"))
        self.assertEqual(sent, [{"cmd": "sysinfo", "ok": False, "error": "refused"}])

    def test_a_sysinfo_only_app_cannot_use_other_requests(self):
        b = self.bridge()
        for r in ({"cmd": "request", "action": "apps"}, {"cmd": "request", "action": "open", "app": "hello", "mode": "tui"},
                  {"cmd": "request", "action": "close", "id": "hello-abcdef"}, {"cmd": "request", "action": "focus", "id": "hello-abcdef"},
                  {"cmd": "request", "action": "backup"}, {"cmd": "request", "action": "backup_add", "path": "/etc"},
                  {"cmd": "request", "action": "backup_remove", "id": "0" * 12},
                  {"cmd": "request", "action": "assistant", "system": "", "messages": [{"role": "user", "content": "x"}]}):
            self.assertIsNone(b.handle(r, self.out.append, self.authority()))   # any prompt would fail: no answers
            last = self.out[-1]
            if r["action"] == "assistant":
                self.assertEqual(last, {"cmd": "assistant", "ok": False, "error": "refused"})
            else:
                self.assertFalse(last["ok"], r)
                self.assertIn("'system' permission", last["detail"])

    def test_an_assistant_only_app_cannot_use_sysinfo(self):
        with mock.patch.object(S, "read") as rd:
            self.assertEqual(self.ask(self.bridge(sysinfo=False, system=False, assistant=True), "os")["error"], "refused")
        rd.assert_not_called()

    def test_a_system_app_without_sysinfo_cannot_read(self):
        with mock.patch.object(S, "read") as rd:
            self.assertEqual(self.ask(self.bridge(sysinfo=False, system=True), "os")["error"], "refused")
        rd.assert_not_called()

    def test_a_topic_that_got_past_the_protocol_still_opens_nothing(self):
        opened = []
        real = builtins.open
        def spy(f, *a, **k):
            opened.append(str(f)); return real(f, *a, **k)
        for topic in ("../etc/passwd", "os; rm", "x" * 5000, 5, None):
            with mock.patch.object(builtins, "open", spy):
                self.bridge().handle({"cmd": "request", "action": "sysinfo", "topic": topic}, self.out.append, self.authority(PW))
            self.assertEqual(self.out[-1], {"cmd": "sysinfo", "ok": False, "error": "refused"})
        self.assertFalse([o for o in opened if "/proc" in o or "/sys" in o or "passwd" in o], opened)
        self.assertNotIn("x" * 50, self.audit_text())          # the app's text is never audited

    def test_no_password_means_nothing_is_read(self):
        for answers in ([None], ["no", "no", "no"], [b""] * 3):
            with mock.patch.object(S, "read") as rd:
                self.assertEqual(self.ask(self.bridge(), "os", *answers)["error"], "refused")
            rd.assert_not_called()

    def test_a_refusal_is_cached_for_the_session(self):
        b = self.bridge()
        with mock.patch.object(S, "read") as rd:
            self.assertEqual(self.ask(b, "os", None)["error"], "refused")
            self.assertEqual(self.ask(b, "memory")["error"], "refused")     # no answers: a prompt would fail
            self.assertEqual(self.ask(b, "load")["error"], "refused")
        rd.assert_not_called()

    def test_audit_failure_means_no_read(self):
        b = self.bridge()
        a = self.authority(PW)
        a.audit.record("sysinfo.read", "x", "warm")
        with mock.patch.object(S, "read") as rd, mock.patch.object(type(a.audit), "record", side_effect=OSError):
            b.handle(validate_app_message(req("os"), "tui"), self.out.append, a)
        rd.assert_not_called()
        self.assertEqual(self.out[-1]["ok"], False)


class TestBridgeAllowed(Env):
    def test_the_grant_lasts_one_instance(self):
        b = self.bridge()
        r = self.ask(b, "memory", PW)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["data"], dict)
        self.assertEqual(self.prompter.asked, ["Password to let an app read facts about this computer 'monitor (any topic)': "])
        self.assertTrue(self.ask(b, "load")["ok"])               # no prompt, no answers
        self.assertEqual(self.ask(self.bridge(), "os", None)["error"], "refused")   # a new instance asks again

    def test_audit_has_app_and_topic_never_the_data(self):
        with mock.patch.dict(S.TOPICS, {"os": lambda root, paths: {"kernel": PLANT}}):
            r = self.ask(self.bridge(), "os", PW)
        self.assertEqual(r["data"], {"kernel": PLANT})            # the app got it ...
        log = self.audit_text()
        self.assertIn('"action":"sysinfo.read"', log)
        self.assertIn('"target":"monitor os"', log)
        self.assertIn("allowed", log)
        self.assertNotIn(PLANT, log)                              # ... the log did not

    def test_a_crash_is_a_fixed_phrase_and_audited(self):
        with mock.patch.object(S, "read", side_effect=RuntimeError("boom " + PLANT)):
            r = self.ask(self.bridge(), "os", PW)
        self.assertEqual(r, {"cmd": "sysinfo", "ok": False, "error": "unavailable"})
        self.assertIn("failed:unavailable", self.audit_text())
        self.assertNotIn(PLANT, self.audit_text())


class TestRead(Env):
    def scan(self, v, bad=(HOST, "/home", PLANT, "/proc", "/sys", "BAT0")):
        text = json.dumps(v)
        for b in bad:
            self.assertNotIn(b, text)

    def test_fixture_values(self):
        with tempfile.TemporaryDirectory() as td:
            r = fixture(td)
            self.assertEqual(S.read("memory", r), {"total_mib": 2048, "available_mib": 1024, "swap_total_mib": 0, "swap_free_mib": 0})
            self.assertEqual(S.read("load", r), {"uptime_s": 7200, "load1": 0.5, "load5": 1.25, "load15": 2.0})
            self.assertEqual(S.read("battery", r), {"batteries": [{"type": "Battery", "percent": 80, "status": "Charging"}]})
            self.assertEqual(S.read("os", r)["kernel"], "6.1.0-test")
            for t in ("memory", "load", "battery", "os"):
                self.scan(S.read(t, r))

    def test_no_battery(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(S.read("battery", fixture(td, battery=False)), {"batteries": []})
        self.assertEqual(S.read("battery", "/nonexistent-root"), {"batteries": []})

    def test_garbage_huge_missing_and_symlinked_files_never_raise(self):
        with tempfile.TemporaryDirectory() as td:
            r = fixture(td, meminfo="MemTotal: abc kB\nMemAvailable: -5 kB\nSwapTotal: 1e400 kB\n" + "x" * 10_000_000)
            (Path(r) / "proc/uptime").write_bytes(b"\xff\xfe nan inf\x00")
            (Path(r) / "proc/loadavg").unlink()
            (Path(r) / "proc/sys/kernel/osrelease").unlink()
            os.symlink(Path(r) / "proc/sys/kernel/hostname", Path(r) / "proc/sys/kernel/osrelease")
            b = Path(r) / "sys/class/power_supply/BAT0"
            (b / "type").write_text("Battery\n"); (b / "capacity").write_text("9999\n"); (b / "status").write_text("\x1b[2J" + PLANT)
            for t in S.TOPICS:
                v = S.read(t, r, paths=self.paths)
                self.assertIsInstance(v, dict)
                self.assertLess(len(json.dumps(v)), 100_000)
                self.scan(v)
            self.assertEqual(S.read("memory", r), {})
            self.assertEqual(S.read("battery", r), {"batteries": [{"type": "Battery"}]})
            self.assertNotIn("kernel", S.read("os", r))      # a symlink to the host name file gives no host name

    def test_unknown_topic_raises_only_the_fixed_error(self):
        for t in ("../x", "", None, 5, "os;ls"):
            with self.assertRaises(S.SysinfoError):
                S.read(t)

    def test_lists_are_capped_and_strings_clean(self):
        v = S._bound({"a": ["x\x1b[31m" * 100] * 500})
        self.assertEqual(len(v["a"]), 200)
        self.assertLessEqual(len(v["a"][0]), 64)
        self.assertNotIn("\x1b", v["a"][0])

    def test_storage_and_apps_on_a_real_state_dir(self):
        d = self.paths.state / "appdata" / "notes" / "data"
        d.mkdir(parents=True)
        (d / "f").write_bytes(b"x" * 1000)
        os.symlink("/etc", d / "link")                           # must not be followed
        (self.paths.apps).mkdir(parents=True, exist_ok=True)
        (self.paths.apps / "notes.seal").write_text(json.dumps({"name": "notes", "version": "1", "sha256": "0" * 64}))
        s = S.read("storage", paths=self.paths)
        self.assertGreater(s["total_bytes"], 0)
        row = next(a for a in s["apps"] if a["name"] == "notes")
        self.assertTrue(1000 <= row["bytes"] < 5000, row)
        a = S.read("apps", paths=self.paths)
        self.assertEqual(a["installed"][0]["name"], "notes")
        self.assertIn("permitted", a["installed"][0])
        self.scan(s, (HOST, "/home", str(self.paths.state)))
        self.scan(a, (HOST, "/home", str(self.paths.state)))
        self.assertEqual(S.read("storage"), {})                  # no state dir given: nothing

    def test_walk_is_capped(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(30):
                Path(td, f"f{i}").write_text("x")
            with mock.patch.object(S, "WALK_ENTRIES", 10):
                b, ok = S._tree_bytes(td)
            self.assertFalse(ok)
            self.assertLessEqual(b, 10)

    def test_sandbox_reuses_the_kernel_report(self):
        fake = {"landlock_abi": 4, "seccomp_filter": True, "user_namespaces": True, "kvm": False, "vhost_vsock": False,
                "framebuffer": True, "evdev": True}
        with mock.patch("kos.sandbox.report", return_value=fake):
            self.assertEqual(S.read("sandbox"), {"landlock_abi": 4, "seccomp_filter": True, "user_namespaces": True,
                                                 "kvm": False, "vhost_vsock": False})


FOUR = ("Battery and Power", "Storage and Disk Management", "Process and Resource Monitor",
        "System Information and Diagnostics")
KEYS = ["r", "down", "up", "pagedown", "pageup", "home", "end", "x", "enter", "ctrl-n", "escape", "r", "q"]


class TestApps(unittest.TestCase):
    def entries(self):
        from kos.office.pack_os import ENTRIES
        return [e for e in ENTRIES if e.title in FOUR]

    def fake_data(self, topic):
        return (True, {
            "os": {"kernel": "6.1", "machine": "x86_64", "python": "3.12.0", "kos": "0.1.0"},
            "sandbox": {"landlock_abi": 4, "seccomp_filter": True, "user_namespaces": True, "kvm": False, "vhost_vsock": False},
            "memory": {"total_mib": 2048, "available_mib": 1024, "swap_total_mib": 512, "swap_free_mib": 256},
            "load": {"uptime_s": 9000, "load1": 0.1, "load5": 0.2, "load15": 0.3},
            "storage": {"total_bytes": 10**11, "free_bytes": 4 * 10**10,
                        "apps": [{"name": "notes", "bytes": 5000, "complete": True}, {"name": "x", "bytes": 0, "complete": False}]},
            "battery": {"batteries": [{"type": "Battery", "percent": 50, "status": "Charging"}]},
            "apps": {"installed": [], "open": [{"name": "notes", "mode": "tui", "status": "running"}]},
        }[topic])

    def run_app(self, e, fn):
        from kos.office.ui import FakeHost, run
        h = FakeHost(KEYS)
        h.sysinfo_fn = fn
        run(h, e.args["make"](h, e))
        return h

    def test_each_app_shows_data_and_survives_a_key_battery(self):
        for e in self.entries():
            h = self.run_app(e, self.fake_data)
            self.assertTrue(h.sysinfo_calls, e.title)
            self.assertTrue(set(h.sysinfo_calls) <= set(S.TOPICS))
            self.assertTrue(h.frames, e.title)

    def test_refused_and_failing_hosts_show_a_plain_message(self):
        for e in self.entries():
            for fn in (None, lambda t: (False, "unavailable"), lambda t: 1 / 0):
                h = self.run_app(e, fn)
                self.assertIn("did not give this", "\n".join(sum((list(f[1]) for f in h.frames), [])), e.title)

    def test_content(self):
        from kos.office.ui import FakeHost
        txt = {}
        for e in self.entries():
            h = FakeHost([]); h.sysinfo_fn = self.fake_data
            s = e.args["make"](h, e); s.on_enter()
            txt[e.title] = "\n".join(s.render(100, 100))
        self.assertIn("OK", txt[FOUR[3]]); self.assertIn("NOT OK", txt[FOUR[3]])
        self.assertIn("cannot delete", txt[FOUR[1]]); self.assertIn("notes", txt[FOUR[1]])
        self.assertIn("can NOT see or manage other", txt[FOUR[2]])
        self.assertIn("cannot change power", txt[FOUR[0]])
        h = FakeHost([]); h.sysinfo_fn = lambda t: (True, {"batteries": []})
        e = self.entries()[0]; s = e.args["make"](h, e); s.on_enter()
        self.assertIn("No battery found", "\n".join(s.render(100, 100)))

    def test_manifests_carry_sysinfo_and_nothing_else_of_note(self):
        from suite.gen import every, manifest
        for e in every():
            if e.scope == "none": continue
            p = manifest(e)["permissions"]
            if e.title in FOUR or e.title in ("Device Settings", "Network and Wireless", "Software Updates"):
                self.assertEqual(p, ["storage", "assistant", "sysinfo"], e.title)
            elif e.title == "Firewall Management":
                self.assertEqual(p, ["storage", "assistant", "firewall"])
            else:
                self.assertNotIn("sysinfo", p, e.title)
            self.assertNotIn("system", p, e.title)
            if e.title in FOUR: self.assertNotIn("network", p)
        Manifest.parse(json.dumps(manifest(next(e for e in every() if e.title == FOUR[0]))).encode())


def install_fake(paths, name, version="1.0", permissions=()):
    """A .kapp + .seal on disk (the seal is not verified by the read-only topics; they only describe)."""
    from kos.kapp import pack
    src = Path(paths.root if hasattr(paths, "root") else paths.state) / ("src-" + name)
    src.mkdir(parents=True, exist_ok=True)
    (src / "main.py").write_text("def main():\n    pass\n")
    (src / "manifest.json").write_text(json.dumps({"name": name, "version": version, "runtime": "python",
                                                   "entry": "main:main", "permissions": list(permissions)}))
    paths.apps.mkdir(parents=True, exist_ok=True)
    pack(src, paths.apps / f"{name}.kapp")
    (paths.apps / f"{name}.seal").write_text(json.dumps({"name": name, "version": version, "sha256": "0" * 64}))


class TestNetworkAndSettings(Env):
    SECRET_KEY = "sk-ant-PLANTED-SECRET-KEY-9999"

    def plant(self):
        from kos import assistant as A, firewall as F
        from kos.permissions import Permissions
        from kos.permit import PermitStore
        install_fake(self.paths, "web", permissions=["network"])
        install_fake(self.paths, "quiet")
        (self.paths.state).mkdir(parents=True, exist_ok=True)
        A.set_api(self.paths, "anthropic", "", "claude-x", self.SECRET_KEY)
        A.use(self.paths, "api")
        F.add_rule(self.paths, "app:web", "example.org", 443, "https")
        F.add_rule(self.paths, "os:assistant", "api.anthropic.com", 443, "https")
        PermitStore(self.paths).grant("web")
        Permissions(self.paths).grant("web", "space:contacts", "read")
        for i in range(3):
            F.decide(self.paths, "app:web", "example.org", 443, "https")
        F.decide(self.paths, "app:web", "evil.example", 443, "https")

    def test_network_topic(self):
        self.plant()
        n = S.read("network", paths=self.paths)
        self.assertEqual(n["declared_network_apps"], ["web"])
        self.assertIn({"who": "app:web", "host": "example.org", "port": 443, "proto": "https"}, n["rules"])
        self.assertEqual(n["assistant"], {"active": True, "endpoint_host_port": "api.anthropic.com", "firewall_allows": True})
        self.assertEqual(n["recent"], {"allowed": 3, "blocked": 1})

    def test_settings_topic(self):
        self.plant()
        s = S.read("settings", paths=self.paths)
        self.assertEqual(s["assistant_active"], True)
        self.assertEqual(s["permitted_apps"], 1)
        self.assertEqual(s["shared_folder_grants"], [{"app": "web", "space": "contacts", "level": "read"}])
        self.assertEqual(s["extensions_on"], [])
        self.assertEqual(s["firewall_rules"], 2)

    def test_no_secret_path_or_host_name_in_either_topic(self):
        self.plant()
        root = fixture(self.tmp.name + "/fx")
        for t in ("network", "settings"):
            text = json.dumps(S.read(t, root, paths=self.paths))
            for bad in (self.SECRET_KEY, "PLANTED", HOST, str(self.paths.state), "/home", "assistant.json", "\\x1b"):
                self.assertNotIn(bad, text, (t, bad))

    def test_without_state_nothing(self):
        self.assertEqual(S.read("network"), {})
        self.assertEqual(S.read("settings"), {})

    def test_damaged_sources_give_empty_not_errors(self):
        self.paths.state.mkdir(parents=True, exist_ok=True)
        (self.paths.state / "firewall.json").write_text("{not json")
        (self.paths.state / "assistant.json").write_text("\x00\x01")
        (self.paths.apps).mkdir(parents=True, exist_ok=True)
        (self.paths.apps / "bad.kapp").write_bytes(b"junk")
        (self.paths.apps / "bad.seal").write_text(json.dumps({"name": "bad", "version": "1", "sha256": "0"}))
        n = S.read("network", paths=self.paths)
        self.assertEqual((n["rules"], n["declared_network_apps"]), ([], []))
        self.assertEqual(S.read("settings", paths=self.paths)["firewall_rules"], 0)

    def test_recent_counts_only_the_last_200(self):
        from kos import firewall as F
        for i in range(210):
            F.decide(self.paths, "app:web", "x.example", 443, "https")      # blocked
        F.decide(self.paths, "app:web", "x.example", 443, "https")
        r = S.read("network", paths=self.paths)["recent"]
        self.assertEqual(r["allowed"] + r["blocked"], 200)

    def test_bridge_gating_is_the_same(self):
        self.plant()
        with mock.patch.object(S, "read") as rd:
            self.assertEqual(self.ask(self.bridge(sysinfo=False, system=True), "network")["error"], "refused")
            self.assertEqual(self.ask(self.bridge(), "settings", None)["error"], "refused")
        rd.assert_not_called()
        b = self.bridge()
        r = self.ask(b, "network", PW)
        self.assertTrue(r["ok"])
        self.assertTrue(self.ask(b, "settings")["ok"])           # one password per instance
        self.assertNotIn(self.SECRET_KEY, self.audit_text())
        self.assertIn('"target":"monitor network"', self.audit_text())


class TestNewApps(unittest.TestCase):
    TITLES = ("Network and Wireless", "Device Settings", "Software Updates")

    def entry(self, t):
        from kos.office.pack_os import ENTRIES
        return next(e for e in ENTRIES if e.title == t)

    def data(self, topic):
        return (True, {
            "network": {"declared_network_apps": ["web"], "rules": [{"who": "app:web", "host": "example.org", "port": 443, "proto": "https"},
                                                                      {"who": "os:assistant", "host": "*", "port": 443, "proto": "https"}],
                        "assistant": {"active": True, "endpoint_host_port": "api.example.com:443", "firewall_allows": False},
                        "recent": {"allowed": 3, "blocked": 4}},
            "settings": {"assistant_active": True, "permitted_apps": 2,
                         "shared_folder_grants": [{"app": "web", "space": "c", "level": "read"}],
                         "extensions_on": [{"name": "ext", "host_app": "web", "kind": "extension"}], "firewall_rules": 2},
            "apps": {"installed": [{"name": "web", "version": "1.9", "permitted": True}, {"name": "notes", "version": "2.0-rc1", "permitted": True}],
                     "open": []},
        }[topic])

    def run_app(self, t, fn, keys=KEYS):
        from kos.office.ui import FakeHost, run
        h = FakeHost(keys); h.sysinfo_fn = fn
        e = self.entry(t)
        run(h, e.args["make"](h, e))
        return h

    def test_survive_key_battery_with_data_refusal_and_crash(self):
        for t in self.TITLES:
            for fn in (self.data, None, lambda x: (False, "unavailable"), lambda x: 1 / 0, lambda x: (True, {"x": {"y": 1}}),
                       lambda x: (True, {"network": 5, "settings": [], "apps": {"installed": "zz"}})):
                h = self.run_app(t, fn, KEYS + ["ctrl-d", "e", "a", "enter", "ctrl-d"])
                self.assertTrue(h.frames, t)

    def test_network_content(self):
        from kos.office.ui import FakeHost
        h = FakeHost([]); h.sysinfo_fn = self.data
        e = self.entry("Network and Wireless"); s = e.args["make"](h, e); s.on_enter()
        txt = "\n".join(s.render(100, 100))
        for want in ("web", "example.org", "WILDCARD", "api.example.com:443", "BLOCKS it", "3 allowed, 4 blocked",
                     "no network of their own", "no Wi-Fi or Bluetooth"):
            self.assertIn(want, txt)
        self.assertEqual(h.sysinfo_calls, ["network"])

    def test_settings_content_and_every_named_command_exists(self):
        import re
        from kos.cli import COMMANDS
        from kos.office.ui import FakeHost
        h = FakeHost([]); h.sysinfo_fn = self.data
        e = self.entry("Device Settings"); s = e.args["make"](h, e); s.on_enter()
        txt = "\n".join(s.render(100, 100))
        self.assertIn("space:c", txt)
        self.assertIn("ext", txt)
        cmds = re.findall(r"`kos (\w+)", txt)
        self.assertGreaterEqual(len(set(cmds)), 5)
        for c in cmds:
            self.assertIn(c, COMMANDS, c)
        self.assertEqual(h.sysinfo_calls, ["settings"])
        # sub-commands named exist too (parse them with the real parser)
        for c in ("assistant status", "assistant use off", "permit web", "permit web --revoke", "grant web space:c --level read",
                  "grant web space:c --revoke", "extend ext", "extend ext --revoke", "passwd", "firewall allow app:web example.org 443 --proto https",
                  "firewall remove app:web example.org 443"):
            self.assertTrue(any(c.split()[0] + " " in l or c in l for l in txt.splitlines()) or c.split()[0] in cmds, c)
            from kos import cli
            parser = cli.build_parser() if hasattr(cli, "build_parser") else None
            if parser is not None:
                parser.parse_args(c.split())

    def test_software_updates_via_the_screen(self):
        from kos.office.ui import FakeHost
        h = FakeHost([]); h.sysinfo_fn = self.data
        e = self.entry("Software Updates"); s = e.args["make"](h, e); s.on_enter()
        for ch in "web 1.10":
            s.key(ch)
        s.key("enter")
        for ch in "notes 2.0":
            s.key(ch)
        s.key("ctrl-d")
        txt = "\n".join(s.render(100, 100))
        self.assertIn("update available", txt)
        self.assertIn("kos update web-1.10.kapp", txt)
        self.assertIn("kos update notes-2.0.kapp", txt)
        self.assertIn("cannot download or install", txt)
        self.assertEqual(h.sysinfo_calls, ["apps"])


class TestVersionCompare(unittest.TestCase):
    CASES = [("1.9", "1.10", -1), ("1.10", "1.9", 1), ("1.0", "1.0.0", 0), ("1.0.0.0", "1", 0), ("2", "10", -1),
             ("1.0-rc1", "1.0", -1), ("1.0", "1.0-rc1", 1), ("1.0-rc1", "1.0-rc2", -1), ("1.0-rc2", "1.0-rc10", -1),
             ("1.0-alpha", "1.0-beta", -1), ("1.0-beta", "1.0-rc1", -1), ("1.0rc1", "1.0-rc1", 0), ("1.0+build5", "1.0", 0),
             ("1.0.1-rc1", "1.0", 1), ("1.0-rc1", "1.0.1", -1), ("0.9.9", "1.0", -1), ("3.2.1", "3.2.1", 0),
             ("1.0a", "1.0", -1), ("001.2", "1.2", 0),
             ("latest", "1.0", None), ("", "1.0", None), ("1.", "1.0", None), (".1", "1.0", None), ("v1.0", "1.0", None),
             ("1..0", "1.0", None), ("1.0", "x" * 40, None), ("1.0 ; rm", "1.0", None), (5, "1.0", None), (None, None, None),
             ("1.0\n2.0", "1.0", None)]

    def test_table(self):
        from kos.office.pack_os import compare_versions
        for a, b, want in self.CASES:
            self.assertEqual(compare_versions(a, b), want, (a, b))
            if want is not None:
                self.assertEqual(compare_versions(b, a), -want, (b, a))

    def test_garbage_lines_ignored_and_bounded(self):
        from kos.office.pack_os import parse_available, update_rows, MAX_UPDATE_LINES
        text = "web 1.2\nnotes\n\n  x  \nBad Name 1.0\nweb2 latest\nweb3 1.0 extra\n../etc 1\n\x1b[31m 1.0\nnotes 2.0\nweb 1.3\n"
        self.assertEqual(parse_available(text), {"web": "1.3", "notes": "2.0"})
        self.assertEqual(parse_available(None), {})
        huge = "a 1.0\n" * 10 ** 6
        self.assertEqual(parse_available(huge), {"a": "1.0"})
        many = "".join(f"app{chr(97 + i % 26)}{i} 1.0\n" for i in range(5000))
        self.assertLessEqual(len(parse_available(many)), MAX_UPDATE_LINES)
        rows = update_rows([{"name": "a", "version": "1.0"}, {"name": "b", "version": "2.0"}, {"name": "c", "version": "1.0"},
                            {"name": "d", "version": "1.0"}, {"name": "e", "version": "weird"}, "junk", {"name": 5}],
                           {"a": "1.1", "b": "2.0", "c": "0.9", "e": "1.0"})
        self.assertEqual([(r[0], r[3]) for r in rows],
                         [("a", "update available"), ("b", "up to date"), ("c", "would be a downgrade (KOS refuses)"),
                          ("d", "unknown"), ("e", "unknown")])
        self.assertEqual(rows[0][4], "kos update a-1.1.kapp")
        self.assertEqual([r[4] for r in rows[1:]], [""] * 4)


class TestSdk(unittest.TestCase):
    def test_sdk_round_trip(self):
        from kos.sdk import App
        a = App.__new__(App)
        sent, events = [], [{"cmd": "key", "key": "a"}, {"cmd": "sysinfo", "ok": True, "data": {"a": 1}}]
        from collections import deque
        a._queue = deque()
        a.send = sent.append
        a._read_event = lambda: events.pop(0) if events else None
        self.assertEqual(a.sysinfo("os"), (True, {"a": 1}))
        self.assertEqual(sent, [req("os")])
        self.assertEqual(a._queue[0], {"cmd": "key", "key": "a"})
        events[:] = [{"cmd": "sysinfo", "ok": False, "error": "refused"}]
        self.assertEqual(a.sysinfo("os"), (False, "refused"))
        events[:] = []
        self.assertEqual(a.sysinfo("os"), (False, "unreachable"))


if __name__ == "__main__":
    unittest.main()
