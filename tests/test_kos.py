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


if __name__ == "__main__":
    unittest.main()
