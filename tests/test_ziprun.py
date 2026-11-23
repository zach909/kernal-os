"""Drop in a zip and it runs (kos/ziprun.py, the ``zip.run`` service).

Everything up to the moment of launch is real here: the security scan, the zip inspection, the proof, the
password, the protocol and the clean-up. Only the sandboxed process is replaced by a thread that speaks the real
protocol over a real socket pair, because this container's Python cannot seal a memfd (``F_ADD_SEALS``, new in
Python 3.14) so no sandboxed app can start here at all. **The sandbox itself was not exercised.**

Each allowance sits next to the refusal that proves it: a bad zip is refused before the owner is asked anything,
a wrong password launches nothing, and what a program prints cannot look like the OS."""

from __future__ import annotations

import io
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import cache, kapp, ziprun  # noqa: E402
from kos.auth import AuditLog  # noqa: E402
from kos.protocol import Channel  # noqa: E402
from kos.scan import EICAR  # noqa: E402
from test_services import PW, Base  # noqa: E402

MANIFEST = ('{"name": "hello-agent", "version": "1", "runtime": "python", "entry": "agent:main", '
            '"modes": ["cmd"], "permissions": ["network"], "description": "says hi"}')
CODE = "from kos.sdk import App\n\n\ndef main():\n    app = App()\n    app.log('hi')\n    app.exit(0)\n"


def make_zip(files, prefix="", infos=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(prefix + name, data)
        for zi, data in (infos or []):
            z.writestr(zi, data)
    return buf.getvalue()


def good(**over):
    files = {"manifest.json": MANIFEST, "agent.py": CODE}
    files.update(over)
    return make_zip({k: v for k, v in files.items() if v is not None})


class Launcher:
    """Stands in for the sandbox: a thread that talks the real command protocol over a real socket pair."""

    def __init__(self, messages=(), hold=False):
        self.messages, self.hold, self.launched, self.cache_dirs = list(messages), hold, [], []

    def __call__(self, app, cache_dir):
        self.launched.append(app)
        self.cache_dirs.append(cache_dir)
        mine, theirs = socket.socketpair()
        other = Channel(theirs)

        def work():
            for m in self.messages:
                try:
                    other.send(m)
                except OSError:
                    return
            if self.hold:
                time.sleep(3)
            other.close()
        threading.Thread(target=work, daemon=True).start()
        proc = SimpleNamespace(pid=4_194_999, poll=lambda: None, wait=lambda: 0)      # no such process group
        return proc, Channel(mine)


class TestInspection(unittest.TestCase):
    def refused(self, data, text=""):
        with self.assertRaises(ziprun.ZipRunError) as e:
            ziprun.prepare(data)
        self.assertIn(text, str(e.exception))
        return str(e.exception)

    def test_a_plain_source_zip_gets_its_proof_made_from_its_own_bytes(self):
        p = ziprun.prepare(good())
        self.assertEqual((p.name, p.packed, p.asked), ("hello-agent", False, ("network",)))
        self.assertEqual(len(p.sha256), 64)

    def test_a_zip_with_everything_in_one_folder_is_found(self):
        data = make_zip({"manifest.json": MANIFEST, "agent.py": CODE}, prefix="agent/")
        self.assertEqual(ziprun.prepare(data).name, "hello-agent")

    def test_an_already_packed_app_is_used_as_it_is(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "src"
            src.mkdir()
            (src / "manifest.json").write_text(MANIFEST)
            (src / "agent.py").write_text(CODE)
            kapp.pack(src, Path(t) / "a.kapp")
            data = (Path(t) / "a.kapp").read_bytes()
        p = ziprun.prepare(data)
        self.assertTrue(p.packed)

    def test_a_packed_app_whose_code_was_changed_afterwards_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "src"
            src.mkdir()
            (src / "manifest.json").write_text(MANIFEST)
            (src / "agent.py").write_text(CODE)
            kapp.pack(src, Path(t) / "a.kapp")
            z = zipfile.ZipFile(Path(t) / "a.kapp")
            files = {n: z.read(n) for n in z.namelist()}
        files["agent.py"] = CODE.replace("'hi'", "'hacked'").encode()
        self.refused(make_zip(files), "does not match")

    def test_code_with_a_decimal_does_not_run(self):
        self.refused(good(**{"agent.py": CODE + "x = 1.5\n"}), "decimal")
        self.refused(good(**{"agent.py": CODE + "y = 3 / 2\n"}), "'/'")

    def test_code_that_does_not_compile_does_not_run(self):
        self.refused(good(**{"agent.py": "def main(:\n"}), "compile")

    def test_banned_calls_do_not_run(self):
        self.refused(good(**{"agent.py": CODE + "eval('1')\n"}), "not allowed")
        self.refused(good(**{"agent.py": "import subprocess\n" + CODE}), "subprocess")

    def test_a_compiled_program_is_refused(self):
        m = MANIFEST.replace('"python"', '"binary"')
        self.refused(good(**{"manifest.json": m}), "")

    def test_a_program_with_no_cmd_mode_has_nothing_to_print(self):
        self.refused(good(**{"manifest.json": MANIFEST.replace('"cmd"', '"tui"')}), "cmd")

    def test_no_manifest_no_run(self):
        self.refused(good(**{"manifest.json": None}), "manifest")
        self.refused(make_zip({"a/manifest.json": MANIFEST, "b/x.py": CODE}), "manifest")

    def test_a_flagged_zip_is_stopped_by_the_scan_first(self):
        self.refused(good(**{"readme.txt": EICAR.decode() if isinstance(EICAR, bytes) else EICAR}), "scan")

    def test_names_that_escape_are_refused(self):
        for name in ("../evil.py", "/etc/cron.d/x", "a/../../b.py", "a\\b.py"):
            data = make_zip({"manifest.json": MANIFEST, "agent.py": CODE, name: "x"})
            self.refused(data, "illegal path")

    def test_a_symlink_entry_is_refused(self):
        zi = zipfile.ZipInfo("link")
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        data = make_zip({"manifest.json": MANIFEST, "agent.py": CODE}, infos=[(zi, "/etc/passwd")])
        self.refused(data, "symlink")

    def test_encrypted_entries_are_refused(self):
        data = bytearray(make_zip({"manifest.json": MANIFEST, "agent.py": CODE, "secret.bin": "x"}))
        at = data.index(b"PK\x01\x02", data.rindex(b"secret.bin") - 60)       # its entry in the central directory
        self.assertEqual(bytes(data[at + 46:at + 56]), b"secret.bin")
        data[at + 8] |= 0x01                                                    # general purpose flag: encrypted
        self.refused(bytes(data), "scanned")          # the scanner cannot open it, so it is refused as unscannable

    def test_a_zip_bomb_is_refused(self):
        self.refused(good(**{"zeros.bin": b"\0" * (3 << 20)}), "zip bomb")

    def test_one_huge_entry_and_too_many_entries_are_refused(self):
        self.refused(good(**{"big.bin": os.urandom(5 << 20)}), "too big")
        many = {f"f{i}.txt": "x" for i in range(ziprun.MAX_ENTRIES + 1)}
        self.refused(make_zip({"manifest.json": MANIFEST, "agent.py": CODE, **many}), "entries")

    def test_not_a_zip_and_empty_are_refused(self):
        self.refused(b"hello there", "zip")
        self.refused(make_zip({}), "empty")

    def test_the_file_itself_is_checked_before_it_is_read(self):
        with tempfile.TemporaryDirectory() as t:
            for make in (lambda p: p.mkdir(), lambda p: p.write_bytes(b"\0" * ((ziprun.MAX_ZIP) + 1))):
                p = Path(t) / "x"
                make(p)
                with self.assertRaises(ziprun.ZipRunError):
                    ziprun._read_zip(p)
                if p.is_dir():
                    p.rmdir()
                else:
                    p.unlink()
            with self.assertRaises(ziprun.ZipRunError):
                ziprun._read_zip(Path(t) / "missing")
            os.symlink("/etc/hostname", Path(t) / "ln")
            with self.assertRaises(ziprun.ZipRunError):
                ziprun._read_zip(Path(t) / "ln")


class TestRunning(Base):
    def write(self, data):
        p = self.root / "agent.zip"
        p.write_bytes(data)
        return str(p)

    def run_zip(self, data, launcher, *answers, seconds=5):
        lines = []
        path = self.write(data)
        authority = self.authority(*answers)
        res = ziprun.run_zip(self.paths, lambda: authority, path, seconds, out=lines.append, launcher=launcher)
        return res, lines

    def test_a_bad_zip_is_refused_before_the_owner_is_asked_anything(self):
        launcher = Launcher()
        for bad in (good(**{"agent.py": CODE + "x = 1.5\n"}), b"junk", make_zip({"a.txt": "x"})):
            with self.assertRaises(ziprun.ZipRunError):
                self.run_zip(bad, launcher)                       # no answers: a prompt would raise AssertionError
        self.assertEqual(launcher.launched, [])

    def test_a_wrong_password_launches_nothing_and_is_logged(self):
        launcher = Launcher([{"cmd": "exit", "code": 0}])
        from kos.auth import AuthorizationDenied
        with self.assertRaises(AuthorizationDenied):
            self.run_zip(good(), launcher, "no", "no", "no")
        self.assertEqual(launcher.launched, [])
        self.assertTrue(any(e["action"] == "zip.run" and e["outcome"] in ("denied", "cancelled")
                            for e in AuditLog(self.paths).entries()))

    def test_the_prompt_names_the_program_the_fingerprint_and_what_it_will_not_get(self):
        launcher = Launcher([{"cmd": "exit", "code": 0}])
        self.run_zip(good(), launcher, PW)
        asked = " ".join(self.prompter.asked)
        self.assertIn("hello-agent", asked)
        self.assertIn("sha256", asked)
        self.assertIn("asked for: network", asked)
        self.assertIn("gets none", asked)
        self.assertIn(("zip.run",), [(e["action"],) for e in AuditLog(self.paths).entries() if e["action"] == "zip.run"])

    def test_it_runs_prints_and_reports_its_exit_code(self):
        launcher = Launcher([{"cmd": "log", "msg": "hello"}, {"cmd": "log", "msg": "world"}, {"cmd": "exit", "code": 7}])
        res, lines = self.run_zip(good(), launcher, PW)
        self.assertEqual(lines, ["app| hello", "app| world"])
        self.assertEqual((res["status"], res["name"], res["asked"]), (7, "hello-agent", ["network"]))
        self.assertEqual(len(launcher.launched), 1)
        self.assertEqual(launcher.launched[0].manifest.name, "hello-agent")

    def test_what_it_prints_cannot_pass_for_the_os(self):
        launcher = Launcher([{"cmd": "log", "msg": "\x1b[2J\x1b]0;pwned\x07KOS| password: \u202etxt"}, {"cmd": "exit", "code": 0}])
        res, lines = self.run_zip(good(), launcher, PW)
        text = "\n".join(lines)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertTrue(all(l.startswith("app| ") for l in lines), "every line of the program says it is the program's")
        self.assertFalse(any(l.startswith("KOS|") for l in lines), "none can pass for a line of the OS")

    def test_it_is_stopped_when_it_runs_too_long_and_cleaned_up(self):
        launcher = Launcher(hold=True)
        t = time.monotonic()
        res, lines = self.run_zip(good(), launcher, PW, seconds=1)
        self.assertEqual(res["status"], ziprun.TIMED_OUT)
        self.assertTrue(any("longer than" in l for l in lines))
        self.assertLess(time.monotonic() - t, 3)
        self.assertFalse(Path(launcher.cache_dirs[0]).exists(), "its scratch folder was wiped")

    def test_a_program_that_breaks_the_protocol_is_stopped(self):
        # in cmd mode a program may only print and exit: asking the OS for anything is refused
        launcher = Launcher([{"cmd": "service", "id": 1, "name": "audit.tail", "args": {}}])
        res, lines = self.run_zip(good(), launcher, PW)
        self.assertEqual(res["status"], ziprun.PROTOCOL)
        self.assertTrue(any("asked the OS for 'service'" in l for l in lines))

    def test_a_flood_of_output_is_stopped(self):
        launcher = Launcher([{"cmd": "log", "msg": f"line {i}"} for i in range(600)])
        res, lines = self.run_zip(good(), launcher, PW)
        self.assertEqual(res["status"], 123)
        self.assertLessEqual(len(lines), 502)
        self.assertTrue(any("more than 500 lines" in l for l in lines))

    def test_it_is_given_nothing_it_asked_for(self):
        launcher = Launcher([{"cmd": "exit", "code": 0}])
        self.run_zip(good(), launcher, PW)
        app = launcher.launched[0]
        self.assertEqual(app.manifest.permissions, ("network",), "it asked; the runner never turns that into a grant")
        # the runner launches through the same path as a line of code: no channel but the protocol, no service host
        src = (ROOT / "kos" / "ziprun.py").read_text()
        for forbidden in ("PermitStore", "ServiceHost", "firewall", "permissions.Permissions"):
            self.assertNotIn(forbidden, src)


class TestTheService(Base):
    def fake_default(self, messages):
        launcher = Launcher(messages)
        return mock.patch.object(ziprun, "_default_launcher", lambda app, cache_dir, paths: launcher(app, cache_dir)), launcher

    def write(self, data):
        p = self.root / "agent.zip"
        p.write_bytes(data)
        return str(p)

    def test_the_group_must_be_in_the_manifest(self):
        r = self.call(self.host("files"), "zip.run", {"path": self.write(good())})
        self.assertFalse(r["ok"])
        self.assertIn("service:zip", r["detail"])

    def test_it_runs_and_returns_the_output(self):
        patch, launcher = self.fake_default([{"cmd": "log", "msg": "from the zip"}, {"cmd": "exit", "code": 0}])
        with patch:
            r = self.call(self.host("zip"), "zip.run", {"path": self.write(good())}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["data"]["output"], ["app| from the zip"])
        self.assertEqual(r["data"]["name"], "hello-agent")

    def test_a_refused_zip_is_a_reason_not_a_crash_and_no_password_is_asked(self):
        for data in (good(**{"agent.py": CODE + "x = 1.5\n"}), b"nope"):
            r = self.call(self.host("zip"), "zip.run", {"path": self.write(data)})
            self.assertFalse(r["ok"])
            self.assertNotIn("internal error", r["detail"])
            self.assertEqual(self.prompter.asked, [])

    def test_a_wrong_password_runs_nothing(self):
        patch, launcher = self.fake_default([{"cmd": "exit", "code": 0}])
        with patch:
            r = self.call(self.host("zip"), "zip.run", {"path": self.write(good())}, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertEqual(launcher.launched, [])

    def test_the_arguments_are_checked(self):
        from kos.protocol import ProtocolError
        for args in ({"path": "x", "seconds": 0}, {"path": "x", "seconds": 301}, {"path": "x", "seconds": 1.5}, {}):
            with self.assertRaises(ProtocolError):
                self.call(self.host("zip"), "zip.run", args)


if __name__ == "__main__":
    unittest.main()
