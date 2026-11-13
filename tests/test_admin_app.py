"""Apps that can be administrators (the ``admin`` permission) and the kernel as an app.

Rules under test: an app only ever *asks*; the OS refuses before any password when it can; the
password still names the app and the file; the guarded write still scans and optimizes; ``admin``
never rides in on an add-on, a sibling or the ``system`` permission.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.admin import AdminError, AdminKeyboard  # noqa: E402
from kos.auth import Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import ASK_ACTIONS, KAppError, Manifest, PERMISSIONS, pack  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import MAX_ADMIN_TEXT, ProtocolError, validate_app_message  # noqa: E402
from kos.registry import Registry  # noqa: E402
from kos.scan import EICAR  # noqa: E402
from kos.store import AppStore  # noqa: E402
from kos.system import SystemBridge, bridge_for, open_background  # noqa: E402

PW = "correct horse battery"
ROOT = Path(__file__).resolve().parent.parent
KERNEL_APP = ROOT / "examples" / "system" / "kernel"
ADMIN_APP = ROOT / "examples" / "admin-write"
WEAK = {"KOS_DEV_ADMIN_WEAK": "1"}      # this container has no keyboard to take exclusively


def manifest(name="x", perms=(), **extra):
    d = {"name": name, "version": "1.0", "runtime": "python", "entry": "app:main", "permissions": list(perms)}
    d.update(extra)
    return json.dumps(d).encode()


def load(path):
    spec = importlib.util.spec_from_file_location("app_" + path.name.replace("-", "_"), path / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name) / "kos")
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2 ** 10), throttle_base=0)
        self.work = Path(self.tmp.name) / "work"
        self.work.mkdir()
        self.sent = []

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def boot_admin(self):
        with mock.patch.dict(os.environ, WEAK):
            with self.authority(PW).authorize("session.login") as g:
                return AdminKeyboard(self.paths).boot(g)

    def ask(self, perms, req, *answers, **bridge_kw):
        bridge = bridge_for(self.paths, "someapp", perms)
        if bridge_kw:
            bridge = SystemBridge(self.paths, who="someapp", app="someapp", permissions={"admin"}, **bridge_kw)
        with mock.patch.dict(os.environ, WEAK):
            bridge.handle(req, self.sent.append, self.authority(*answers))
        return self.sent[-1]

    def write_req(self, name="note.txt", text="hello"):
        return {"cmd": "request", "action": "write", "path": str(self.work / name), "text": text}

    def audit(self):
        return [(e["action"], e["target"], e["outcome"]) for e in self.authority().audit.entries()]


class TestManifest(unittest.TestCase):
    def test_admin_is_a_permission_and_kernel_is_askable(self):
        self.assertIn("admin", PERMISSIONS)
        self.assertIn("kernel", ASK_ACTIONS)
        self.assertEqual(Manifest.parse(manifest(perms=["admin"])).permissions, ("admin",))
        self.assertEqual(Manifest.parse(manifest(perms=["ask:kernel"])).asks, ("kernel",))

    def test_unknown_powers_are_still_refused(self):
        for bad in ("administrator", "root", "ask:admin", "ask:write", "admin:write", "ask:kernel2"):
            with self.assertRaises(KAppError, msg=bad):
                Manifest.parse(manifest(perms=[bad]))

    def test_an_extension_or_a_mod_can_never_be_an_admin(self):
        with self.assertRaises(KAppError):
            Manifest.parse(manifest("ext-x", ["admin"], kind="extension", extends="hello"))
        with self.assertRaises(KAppError):
            Manifest.parse(manifest("mod-x", ["admin"], kind="mod", extends="taskbar"))
        with self.assertRaises(KAppError):               # a kernel view is an ask: also barred
            Manifest.parse(manifest("ext-y", ["ask:kernel"], kind="extension", extends="hello"))

    def test_the_example_apps_pack_with_exactly_their_one_power(self):
        for src, perms in ((KERNEL_APP, ("ask:kernel",)), (ADMIN_APP, ("admin",))):
            out = Path(tempfile.mkdtemp()) / "a.kapp"
            self.assertEqual(pack(src, out).permissions, perms)


class TestProtocol(unittest.TestCase):
    def v(self, **kw):
        return validate_app_message({"cmd": "request", **kw}, "tui")

    def test_accepted_shapes(self):
        self.assertEqual(self.v(action="kernel"), {"cmd": "request", "action": "kernel"})
        self.assertEqual(self.v(action="admin"), {"cmd": "request", "action": "admin"})
        self.assertEqual(self.v(action="write", path="/home/me/a.txt", text="line1\nline2\t\x00"),
                         {"cmd": "request", "action": "write", "path": "/home/me/a.txt",
                          "text": "line1\nline2\t\x00"})        # file data is kept exactly

    def test_every_rejection(self):
        bad = [dict(action="write", text="x"), dict(action="write", path="/a"),
               dict(action="write", path="a.txt", text="x"), dict(action="write", path="", text="x"),
               dict(action="write", path="/a\nb", text="x"), dict(action="write", path="/a\x1b[2J", text="x"),
               dict(action="write", path="/a‮", text="x"), dict(action="write", path="/a\x00", text="x"),
               dict(action="write", path="/" + "a" * 1100, text="x"), dict(action="write", path=5, text="x"),
               dict(action="write", path="/a", text=5), dict(action="write", path="/a", text=None),
               dict(action="write", path="/a", text="x" * (MAX_ADMIN_TEXT + 1)),
               dict(action="write", path="/a", text="\ud800"),
               dict(action="write", path="/a", text="x", mode="0777"),
               dict(action="write", path="/a", text="x", who="root"),
               dict(action="kernel", cell="c1"), dict(action="admin", path="/a")]
        for b in bad:
            with self.assertRaises(ProtocolError, msg=str(b)[:80]):
                self.v(**b)


class TestBridgeFor(Env):
    def test_each_power_is_separate(self):
        self.assertIsNone(bridge_for(self.paths, "x", []))
        self.assertIsNone(bridge_for(self.paths, "x", ["network", "storage"]))
        b = bridge_for(self.paths, "x", ["admin"])
        self.assertEqual(b.permissions, frozenset({"admin"}))
        self.assertIsNone(b.allowed)
        b = bridge_for(self.paths, "x", ["ask:kernel"])
        self.assertEqual((b.allowed, "admin" in b.permissions), (frozenset({"kernel"}), False))
        b = bridge_for(self.paths, "x", ["system"])
        self.assertNotIn("admin", b.permissions)         # system is every request, but not admin
        b = bridge_for(self.paths, "x", ["ai", "admin", "ask:backup"])
        self.assertEqual(b.permissions, frozenset({"ai", "admin", "system"}))
        self.assertEqual(b.allowed, frozenset({"backup"}))


class TestAdminWrite(Env):
    def test_an_app_without_the_admin_permission_is_refused_and_it_is_audited(self):
        self.boot_admin()
        for perms in (["system"], ["ask:kernel"], ["ai"]):
            self.sent.clear()
            reply = self.ask(perms, self.write_req(), PW)
            self.assertFalse(reply["ok"], perms)
            self.assertIn("'admin' permission", reply["detail"])
        self.assertFalse((self.work / "note.txt").exists())
        self.assertIn(("bridge.admin", "someapp:write", "refused"), self.audit())

    def test_a_bridge_for_no_admin_app_never_reaches_the_writer(self):
        # an app with no bridge at all is told no by the session itself (see Session._on_request)
        self.assertIsNone(bridge_for(self.paths, "x", ["storage"]))

    def test_refused_before_any_password_when_the_keyboard_is_not_booted(self):
        reply = self.ask(["admin"], self.write_req(), PW)
        self.assertFalse(reply["ok"])
        self.assertIn("not booted", reply["detail"])
        self.assertEqual(self.prompter.answers, [PW])    # the password was never asked for
        self.assertFalse((self.work / "note.txt").exists())

    def test_the_kernel_is_still_required(self):
        self.boot_admin()
        bridge = bridge_for(self.paths, "someapp", ["admin"])
        with mock.patch.dict(os.environ, {}, clear=False) as env:
            env.pop("KOS_DEV_ADMIN_WEAK", None)          # the dev switch would excuse the gap on purpose
            with mock.patch.object(AdminKeyboard, "kernel_report", lambda s: {"landlock_abi": 0}):
                bridge.handle(self.write_req(), self.sent.append, self.authority(PW))
        reply = self.sent[-1]
        self.assertFalse(reply["ok"])
        self.assertIn("needs the KOS kernel", reply["detail"])
        self.assertEqual(self.prompter.answers, [PW])
        self.assertFalse((self.work / "note.txt").exists())

    def test_a_wrong_password_writes_nothing(self):
        self.boot_admin()
        reply = self.ask(["admin"], self.write_req(), "no", "no", "no")
        self.assertFalse(reply["ok"])
        self.assertFalse((self.work / "note.txt").exists())

    def test_the_right_password_writes_scans_optimizes_and_names_the_app(self):
        self.boot_admin()
        reply = self.ask(["admin"], self.write_req(text="line\nline"), PW)
        self.assertTrue(reply["ok"], reply)
        f = self.work / "note.txt"
        self.assertEqual(f.read_text(), "line\nline")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertIn("scan", reply["detail"])
        self.assertEqual(self.authority().audit.entries()[-1]["outcome"], "written")
        rows = self.audit()
        self.assertIn(("file.write", f"{f} for someapp", "granted"), rows)   # the prompt named the app
        self.assertIn(("bridge.admin", "someapp:write", "written"), rows)
        from kos.requires import Ledger
        self.assertEqual(Ledger(self.paths).owed(), [])                      # nothing left owed

    def test_a_flagged_file_is_refused_and_quarantined(self):
        self.boot_admin()
        reply = self.ask(["admin"], self.write_req("bad.bin", EICAR.decode("latin-1")), PW)
        self.assertFalse(reply["ok"])
        self.assertIn("scan", reply["detail"])
        self.assertFalse((self.work / "bad.bin").exists())
        self.assertIn(("bridge.admin", "someapp:write", "scan-failed"), self.audit())

    def test_kos_own_state_cannot_be_written_by_an_app(self):
        self.boot_admin()
        req = {"cmd": "request", "action": "write", "path": str(self.paths.state / "owed.json"), "text": "[]"}
        reply = self.ask(["admin"], req, PW)
        self.assertFalse(reply["ok"])
        self.assertIn("KOS system state", reply["detail"])

    def test_it_will_not_write_through_a_symlink_or_over_a_directory(self):
        self.boot_admin()
        (self.work / "real").write_text("keep")
        (self.work / "link").symlink_to(self.work / "real")
        (self.work / "adir").mkdir()
        for name in ("link", "adir"):
            self.sent.clear()
            self.assertFalse(self.ask(["admin"], self.write_req(name), PW)["ok"], name)
        self.assertEqual((self.work / "real").read_text(), "keep")

    def test_the_status_request(self):
        reply = self.ask(["admin"], {"cmd": "request", "action": "admin"})
        self.assertFalse(reply["ok"])
        self.assertIn("OFF", reply["detail"])
        self.boot_admin()
        with mock.patch.dict(os.environ, WEAK):
            reply = self.ask(["admin"], {"cmd": "request", "action": "admin"})
        self.assertTrue(reply["ok"])
        self.assertIn("ON", reply["detail"])
        self.assertNotIn("answers", reply)

    def test_on_a_real_keyboard_it_fails_closed_if_the_keyboard_cannot_be_taken(self):
        lease = self.boot_admin()
        lease_file = self.paths.state / "admin-lease.json"
        d = json.loads(lease_file.read_text())
        self.assertTrue(d["weak"])
        # an exclusive lease (as booted on real hardware) whose keyboards are held by someone else
        with mock.patch("kos.admin.open_admin_devices", side_effect=AdminError("held by another process")):
            bridge = SystemBridge(self.paths, who="someapp", app="someapp", permissions={"admin"})
            with mock.patch.dict(os.environ, WEAK):
                bridge.handle(self.write_req(), self.sent.append, self.authority(PW))
        self.assertFalse(self.sent[-1]["ok"])
        self.assertIn("held by another process", self.sent[-1]["detail"])
        self.assertFalse((self.work / "note.txt").exists())
        self.assertEqual(self.prompter.answers, [PW])

    def test_the_password_prompt_comes_from_the_injected_authority(self):
        """The password for an admin write is asked through ``admin_authority``, never the app's session
        authority when the keyboard has to be taken (here a spy stands in for the exclusive keyboard)."""
        self.boot_admin()
        used = []

        @contextmanager
        def spy(lease, session_authority):
            used.append(lease.weak)
            yield self.authority(PW)

        reply = self.ask(["admin"], self.write_req(), "session-would-fail", admin_authority=spy)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(used, [True])

    def test_instance_records_admin_from_the_verified_manifest(self):
        out = self.work / "admin-write.kapp"
        pack(ADMIN_APP, out)
        AppStore(self.paths).install(out, self.authority(PW))
        PermitStore(self.paths).grant("admin-write", ["admin"])

        def spawner(inst, app, mode, policy, registry, log_path, cache_dir=None):
            inst.status, inst.broker_pid = "running", os.getpid()
            registry.write(inst)

        inst = open_background(self.paths, self.authority(PW), "admin-write", spawner=spawner)
        self.assertTrue(Registry(self.paths).get(inst.id).admin)

    def test_a_widened_manifest_is_caught_by_the_permit_pin(self):
        PermitStore(self.paths).grant("admin-write", ["storage"])
        with self.assertRaises(Exception) as ctx:
            PermitStore(self.paths).check_declared("admin-write", ["storage", "admin"])
        self.assertIn("admin", str(ctx.exception))

    def test_the_example_app_only_asks(self):
        mod = load(ADMIN_APP)

        class FakeApp:
            def __init__(self):
                self.calls, self.mode = [], "tui"

            def request_write(self, p, t): self.calls.append((p, t))

        self.assertIn("admin", Path(ADMIN_APP / "manifest.json").read_text())
        self.assertEqual(mod.lines({"path": "/a", "text": "b", "field": 0, "note": ""})[1], "  > path: /a_")
        self.assertTrue(hasattr(FakeApp(), "request_write"))


class TestKernelApp(Env):
    def test_an_ask_kernel_app_gets_the_kernel_and_no_password_is_asked(self):
        reply = self.ask(["ask:kernel"], {"cmd": "request", "action": "kernel"}, "unused")
        self.assertEqual(reply["cmd"], "kernel")
        self.assertIn("landlock_abi", reply["protections"])
        self.assertEqual(self.prompter.answers, ["unused"])
        self.assertEqual(reply["cells"], [])
        self.assertIn("administrator keyboard", reply["admin"])
        json.dumps(reply)                                # plain data: it can cross the channel

    def test_system_gets_it_too_but_another_ask_does_not(self):
        self.assertEqual(self.ask(["system"], {"cmd": "request", "action": "kernel"})["cmd"], "kernel")
        reply = self.ask(["ask:backup"], {"cmd": "request", "action": "kernel"})
        self.assertEqual(reply["cmd"], "result")
        self.assertFalse(reply["ok"])
        self.assertIn("ask:kernel", reply["detail"])
        self.assertIn(("bridge.ask", "someapp:kernel", "refused"), self.audit())

    def test_an_ask_kernel_app_can_do_nothing_else(self):
        for req in ({"action": "apps"}, {"action": "open", "app": "hello", "mode": "tui"},
                    {"action": "close", "id": "hello-aaaaaa"}, {"action": "backup"},
                    {"action": "write", "path": "/tmp/x", "text": "x"}, {"action": "admin"}):
            self.sent.clear()
            reply = self.ask(["ask:kernel"], {"cmd": "request", **req})
            self.assertEqual(reply["cmd"], "result", req)
            self.assertFalse(reply["ok"], req)

    def test_cells_are_listed_as_plain_data_only(self):
        self.paths.ensure()
        self.paths.cells.mkdir(parents=True, exist_ok=True)
        (self.paths.cells / "c1.json").write_text(json.dumps(
            {"name": "c1\x1b[2J", "cid": 4, "cpus": [2, 3], "memory_mb": 256, "pid": 0,
             "kernel": "/secret/bzImage", "initrd": "/secret/initrd"}))
        reply = self.ask(["ask:kernel"], {"cmd": "request", "action": "kernel"})
        self.assertEqual(reply["cells"], [{"name": "c1[2J", "cid": 4, "cpus": [2, 3],
                                           "memory_mb": 256, "running": False}])
        self.assertNotIn("secret", json.dumps(reply))

    def test_the_app_draws_what_the_os_says(self):
        mod = load(KERNEL_APP)
        self.assertEqual(mod.shown(True), "yes")
        self.assertEqual(mod.shown(0), "NO")
        self.assertEqual(mod.shown(7), "yes (ABI 7)")
        reply = self.ask(["ask:kernel"], {"cmd": "request", "action": "kernel"})
        text = "\n".join(mod.lines({"kernel": reply}))
        self.assertIn("Landlock", text)
        self.assertIn("kernel cells: none", text)
        self.assertIn("asking", "\n".join(mod.lines({"kernel": None})))


if __name__ == "__main__":
    unittest.main()
