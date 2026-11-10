"""Encryption at rest (kos/crypto.py), the Credential Manager and the encrypted assistant key.

Refusals first. The crypto itself is the `cryptography` library's AES-GCM; KOS has none of its own, and
test_known_answer proves the library call is what we think. Nothing is ever allowed to fall back to
plaintext: every secret, label and key planted below is searched for in every byte under the state dir
after each operation."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import assistant as A  # noqa: E402
from kos import cli as kcli  # noqa: E402
from kos import credentials as C  # noqa: E402
from kos import crypto  # noqa: E402
from kos import firewall as F  # noqa: E402
from kos import system as S  # noqa: E402
from kos.auth import Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KAppError, Manifest  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.system import SystemBridge  # noqa: E402

PW, NEW = "correct horse battery", "another staple correct"
SECRET, LABEL, USER = "PLANTED-secret-Zq81-æø", "PLANTED-label-Mx42", "PLANTED-user-Kd07"
KEY = "sk-PLANTED-APIKEY-9f3a1c"
PLANTS = (SECRET, LABEL, USER, KEY)
BAD = "cannot decrypt"


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def grant(self, pw=PW):
        return self.authority(pw).authorize("assistant.config", "set api")

    def master(self, pw=PW):
        return PasswordStore(self.paths).verify(pw.encode())

    def scan(self, *extra):
        """No planted plaintext in any byte of any file under the whole root (state, logs, temp files)."""
        for dp, _, fs in os.walk(self.tmp.name):
            for f in fs:
                data = (Path(dp) / f).read_bytes()
                for p in PLANTS + extra:
                    self.assertNotIn(p.encode(), data, (f, "plaintext on disk"))
                    self.assertNotIn(p.encode("utf-16-le"), data, f)
        leftovers = [f for dp, _, fs in os.walk(self.tmp.name) for f in fs if ".tmp." in f]
        self.assertEqual(leftovers, [])

    def bridge(self, **kw):
        kw.setdefault("credentials", True)
        return SystemBridge(self.paths, app="vaultapp", system=False, **kw)

    def call(self, b, auth, **req):
        out = []
        msg = validate_app_message({"cmd": "request", "action": "credential", **req}, "tui")
        b.handle(msg, out.append, auth)
        self.assertEqual(len(out), 1)
        return out[0]

    def add(self, b, auth, label=LABEL, secret=SECRET):
        return self.call(b, auth, op="add", label=label, username=USER, secret=secret, url="https://e.example", notes="n")


# ================================================================ the blob ====
class TestBlob(Env):
    def dek(self):
        return os.urandom(32)

    def test_refusals_are_all_the_same_error(self):
        dek = self.dek()
        blob = crypto.seal(dek, "p", b"hello world")
        cases = {
            "magic": bytes([blob[0] ^ 1]) + blob[1:],
            "version": blob[:3] + b"\x02" + blob[4:],
            "nonce": blob[:6] + bytes([blob[6] ^ 1]) + blob[7:],
            "ciphertext": blob[:20] + bytes([blob[20] ^ 1]) + blob[21:],
            "tag": blob[:-1] + bytes([blob[-1] ^ 1]),
            "truncated by one": blob[:-1], "truncated to header": blob[:16], "truncated to magic": blob[:4],
            "empty": b"", "extended": blob + b"\0",
        }
        for name, bad in cases.items():
            with self.assertRaises(crypto.CryptoError, msg=name) as cm:
                crypto.open_(dek, "p", bad)
            self.assertEqual(str(cm.exception), BAD, name)
            self.assertIsNone(cm.exception.__cause__, name)
        with self.assertRaises(crypto.CryptoError) as wrong_key:
            crypto.open_(self.dek(), "p", blob)
        with self.assertRaises(crypto.CryptoError) as wrong_purpose:
            crypto.open_(dek, "q", blob)
        self.assertEqual(str(wrong_key.exception), str(wrong_purpose.exception))
        self.assertEqual(crypto.open_(dek, "p", blob), b"hello world")       # and the good case does work
        for junk in (None, 5, "str", object()):
            with self.assertRaises(crypto.CryptoError):
                crypto.open_(dek, "p", junk)
        for bad_purpose in ("", None, "x" * 65, "café", "a\nb"):
            with self.assertRaises(crypto.CryptoError):
                crypto.seal(dek, bad_purpose, b"x")

    def test_an_assistant_blob_cannot_be_opened_as_credentials(self):
        dek = self.dek()
        blob = crypto.seal(dek, A.KEY_PURPOSE, b"k")
        with self.assertRaises(crypto.CryptoError):
            crypto.open_(dek, C.PURPOSE, blob)

    def test_known_answer_of_the_aead_wiring(self):
        """NIST/McGrew-Viega AES-GCM test cases 2 and 4: proves crypto._aead is real AES-GCM."""
        ct = crypto._aead(bytes(16)).encrypt(bytes(12), bytes(16), None)
        self.assertEqual(ct.hex(), "0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf")
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                           "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        want = ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" "5bc94fbc3221a5db94fae95ae7121a47")
        self.assertEqual(crypto._aead(key).encrypt(iv, pt, aad).hex(), want)
        # and the blob layout round-trips through exactly that primitive
        blob = crypto._seal(key, aad, pt)
        self.assertEqual(blob[:4], crypto.MAGIC)
        self.assertEqual(crypto._aead(key).decrypt(blob[4:16], blob[16:], aad), pt)

    def test_ten_thousand_seals_never_repeat_a_nonce(self):
        dek = self.dek()
        nonces = {crypto.seal(dek, "p", b"x")[4:16] for _ in range(10_000)}
        self.assertEqual(len(nonces), 10_000)

    def test_nonce_comes_from_urandom(self):
        dek = self.dek()
        with mock.patch("kos.crypto.os.urandom", return_value=b"\x07" * 12) as u:
            blob = crypto.seal(dek, "p", b"x")
        u.assert_called_with(12)
        self.assertEqual(blob[4:16], b"\x07" * 12)


# ============================================================== the keyring ====
class TestKeyring(Env):
    def test_wrong_password_cannot_open_the_keyring(self):
        dek = crypto.create_keyring(self.paths, self.master())
        self.assertEqual(len(dek), 32)
        other = PasswordStore(self.paths)
        other.create(NEW.encode(), KdfParams.fresh(n=2**10), throttle_base=0, overwrite=True)
        with self.assertRaises(crypto.CryptoError) as cm:
            crypto.unlock(self.paths, self.master(NEW))
        self.assertEqual(str(cm.exception), BAD)

    def test_tampered_or_missing_keyring_is_refused(self):
        m = self.master()
        crypto.create_keyring(self.paths, m)
        good = self.paths.keyring_file.read_bytes()
        for i in (0, 5, 20, len(good) - 1):
            self.paths.keyring_file.write_bytes(good[:i] + bytes([good[i] ^ 1]) + good[i + 1:])
            with self.assertRaises(crypto.CryptoError):
                crypto.unlock(self.paths, m)
        for bad in (b"", good[:-1], good[:10]):
            self.paths.keyring_file.write_bytes(bad)
            with self.assertRaises(crypto.CryptoError):
                crypto.unlock(self.paths, m)
        self.paths.keyring_file.unlink()
        with self.assertRaises(crypto.CryptoError):
            crypto.unlock(self.paths, m)

    def test_a_second_keyring_is_never_made_over_the_first(self):
        crypto.create_keyring(self.paths, self.master())
        before = self.paths.keyring_file.read_bytes()
        with self.assertRaises(crypto.CryptoError):
            crypto.create_keyring(self.paths, self.master())
        self.assertEqual(self.paths.keyring_file.read_bytes(), before)

    def test_a_deleted_keyring_is_not_silently_replaced_when_data_exists(self):
        b, auth = self.bridge(), self.authority(PW)
        self.assertTrue(self.add(b, auth)["ok"])
        self.paths.keyring_file.unlink()
        auth = self.authority(PW)
        r = self.call(self.bridge(), auth, op="add", label="other", username="", secret="s", url="", notes="")
        self.assertEqual(r, {"cmd": "credential", "ok": False, "error": "unavailable"})
        self.assertFalse(self.paths.keyring_file.exists())

    def test_modes_are_0600_and_there_are_no_temp_files(self):
        b, auth = self.bridge(), self.authority(PW)
        self.add(b, auth)
        A.set_api(self.paths, "anthropic", "", "m", KEY, self.grant())
        for f in (self.paths.keyring_file, self.paths.credentials_file, A.config_path(self.paths)):
            self.assertEqual(f.stat().st_mode & 0o777, 0o600, f.name)
        self.scan()

    def test_rewrap_keeps_the_dek_and_moves_it_to_the_new_password(self):
        old = self.master()
        dek = crypto.create_keyring(self.paths, old)
        blob = crypto.seal(dek, "p", b"data")
        new = KdfParams.fresh(n=2**10)
        from kos.auth import derive_master
        nm = derive_master(NEW.encode(), new)
        crypto.rewrap(self.paths, old, nm)
        self.assertEqual(bytes(crypto.unlock(self.paths, nm)), bytes(dek))
        self.assertEqual(crypto.open_(crypto.unlock(self.paths, nm), "p", blob), b"data")
        with self.assertRaises(crypto.CryptoError):
            crypto.unlock(self.paths, old)

    def test_doctor_reports_library_and_keyring_without_secrets(self):
        for state in ("absent", "present"):
            if state == "present":
                crypto.create_keyring(self.paths, self.master())
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), contextlib.redirect_stdout(out):
                kcli.main(["doctor"])
            self.assertIn("encryption library    : yes", out.getvalue())
            self.assertIn(f"keyring               : {state}", out.getvalue())
        with mock.patch.dict(sys.modules, {"cryptography.hazmat.primitives.ciphers.aead": None}):
            self.assertFalse(crypto.available())


# ===================================================== library missing: closed ====
class TestLibraryMissing(Env):
    def setUp(self):
        super().setUp()
        p = mock.patch.dict(sys.modules, {"cryptography.hazmat.primitives.ciphers.aead": None})
        p.start()
        self.addCleanup(p.stop)

    def files(self):
        return sorted(str(p.relative_to(self.tmp.name)) for p in Path(self.tmp.name).rglob("*") if p.is_file())

    def test_seal_and_open_fail_with_a_clear_error_not_plaintext(self):
        self.assertFalse(crypto.available())
        for fn in (lambda: crypto.seal(os.urandom(32), "p", b"x"), lambda: crypto.open_(os.urandom(32), "p", crypto.MAGIC + bytes(40)),
                   lambda: crypto.create_keyring(self.paths, self.master())):
            with self.assertRaises(crypto.CryptoError) as cm:
                fn()
            self.assertIn("unavailable", str(cm.exception))
        self.assertFalse(self.paths.keyring_file.exists())

    def test_assistant_key_and_credentials_write_nothing(self):
        before = self.files()
        with self.assertRaises(A.ConfigError):
            A.set_api(self.paths, "anthropic", "", "m", KEY, self.grant())
        r = self.call(self.bridge(), self.authority(PW), op="add", label=LABEL, username=USER, secret=SECRET, url="", notes="")
        self.assertEqual(r["error"], "unavailable")
        self.assertEqual([f for f in self.files() if "audit" not in f and "throttle" not in f], [f for f in before if "audit" not in f and "throttle" not in f])
        self.scan()

    def test_legacy_plaintext_key_is_left_alone_not_silently_kept_or_lost(self):
        cfg = A.config_path(self.paths)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"active": "off", "api": {"provider": "anthropic", "model": "m", "key": KEY}}))
        before = cfg.read_bytes()
        with self.assertRaises(A.ConfigError):
            A.migrate(self.paths, self.grant())
        self.assertEqual(cfg.read_bytes(), before)
        with self.assertRaises(A.ConfigError):               # and save() refuses to write a plaintext key at all
            A.save(self.paths, {"active": "off", "local": {}, "api": {"key": KEY}})


# =========================================================== password change ====
class TestPasswordChange(Env):
    def run_passwd(self, *answers):
        out, err = io.StringIO(), io.StringIO()
        auth = self.authority(*answers)
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", return_value=(auth, self.prompter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kcli.main(["passwd", "--fast-kdf"])
        return code, out.getvalue() + err.getvalue()

    def fill(self):
        b = self.bridge()
        self.add(b, self.authority(PW))
        A.set_api(self.paths, "anthropic", "", "m", KEY, self.grant())

    def test_encrypt_change_password_still_decrypts_under_new_and_not_old(self):
        self.fill()
        old_master = self.master()
        code, out = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 0, out)
        self.assertIsNone(PasswordStore(self.paths).verify(PW.encode()))
        nm = self.master(NEW)
        dek = crypto.unlock(self.paths, nm)
        self.assertEqual(C.get(self.paths, dek, LABEL)["secret"], SECRET)
        cfg = A.with_key(self.paths, self.grant(NEW), {**A.load(self.paths), "active": "api"})
        self.assertEqual(cfg["api"]["key"], KEY)
        with self.assertRaises(crypto.CryptoError):
            crypto.unlock(self.paths, old_master)
        r = self.call(self.bridge(), self.authority(NEW), op="get", label=LABEL)      # through the bridge too
        self.assertEqual(r["entry"]["secret"], SECRET)
        self.scan(NEW)

    def test_a_failure_writing_the_new_password_leaves_the_old_one_working(self):
        self.fill()
        ring, creds = self.paths.keyring_file.read_bytes(), self.paths.credentials_file.read_bytes()
        auth_before = self.paths.auth_file.read_bytes()
        with mock.patch("kos.auth.PasswordStore.write", side_effect=OSError("disk full")):
            code, out = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 1)
        self.assertEqual(self.paths.keyring_file.read_bytes(), ring)         # the OLD keyring is back
        self.assertEqual(self.paths.credentials_file.read_bytes(), creds)
        self.assertEqual(self.paths.auth_file.read_bytes(), auth_before)
        self.assertIsNotNone(PasswordStore(self.paths).verify(PW.encode()))
        self.assertEqual(C.get(self.paths, crypto.unlock(self.paths, self.master()), LABEL)["secret"], SECRET)
        self.assertNotIn(SECRET, out)

    def test_a_hard_crash_before_the_new_password_file_loses_nothing(self):
        """The process dies after staging the new keyring and before writing the password file: no cleanup runs."""
        self.fill()
        ring = self.paths.keyring_file.read_bytes()
        with mock.patch("kos.auth.PasswordStore.write", side_effect=KeyboardInterrupt), \
                mock.patch("kos.crypto.abandon_keyring"):                  # a killed process runs no except-block
            code, _ = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 130)
        staged = self.paths.keyring_file.with_name("keyring.bin.new")
        self.assertTrue(staged.exists())                                    # the stale staged file is left behind...
        self.assertEqual(self.paths.keyring_file.read_bytes(), ring)        # ...but the real keyring was never touched
        self.assertIsNotNone(PasswordStore(self.paths).verify(PW.encode())) # the old password still works
        self.assertEqual(C.get(self.paths, crypto.unlock(self.paths, self.master()), LABEL)["secret"], SECRET)
        self.assertFalse(staged.exists() and PasswordStore(self.paths).verify(NEW.encode()))    # and the new one does not exist yet
        code, out = self.run_passwd(PW, NEW, NEW)                           # a later change simply succeeds
        self.assertEqual(code, 0, out)
        self.assertEqual(C.get(self.paths, crypto.unlock(self.paths, self.master(NEW)), LABEL)["secret"], SECRET)
        self.assertFalse(staged.exists())

    def test_a_hard_crash_after_the_new_password_file_is_healed_by_the_next_unlock(self):
        """THE window: the new password is written but the keyring swap never happened. Nothing may be lost."""
        self.fill()
        ring = self.paths.keyring_file.read_bytes()
        old_master = self.master()
        with mock.patch("kos.crypto.finish_keyring", side_effect=KeyboardInterrupt):
            code, _ = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 130)
        staged = self.paths.keyring_file.with_name("keyring.bin.new")
        self.assertIsNotNone(PasswordStore(self.paths).verify(NEW.encode()))   # the new password is the real one now
        self.assertEqual(self.paths.keyring_file.read_bytes(), ring)           # the keyring is still the OLD one
        self.assertTrue(staged.exists())
        nm = self.master(NEW)
        dek = crypto.unlock(self.paths, nm)                                    # opens through the staged keyring...
        self.assertEqual(C.get(self.paths, dek, LABEL)["secret"], SECRET)      # ...and the data is all there
        self.assertFalse(staged.exists())                                      # ...and the swap was finished
        self.assertNotEqual(self.paths.keyring_file.read_bytes(), ring)
        cfg = A.with_key(self.paths, self.grant(NEW), {**A.load(self.paths), "active": "api"})
        self.assertEqual(cfg["api"]["key"], KEY)
        with self.assertRaises(crypto.CryptoError):                            # the old password opens nothing any more
            crypto.unlock(self.paths, old_master)
        self.assertEqual(oct(self.paths.keyring_file.stat().st_mode & 0o777), "0o600")
        self.scan(NEW)

    def test_the_staged_keyring_opens_only_with_the_new_password(self):
        self.fill()
        old_master = self.master()                                             # taken BEFORE the password file changes
        with mock.patch("kos.crypto.finish_keyring", side_effect=KeyboardInterrupt):
            self.run_passwd(PW, NEW, NEW)
        staged = self.paths.keyring_file.with_name("keyring.bin.new")
        # In this window the OLD keyring file is still in place (sealed under the old password) until the next unlock
        # swaps the staged one in - the same as any old backup of the file. What must hold is that the STAGED file
        # is no way in for the old password: take the old file away and only the new password may open what is left.
        self.paths.keyring_file.unlink()
        with self.assertRaises(crypto.CryptoError):
            crypto.unlock(self.paths, old_master)
        self.assertTrue(staged.exists())                                       # a failed unlock changes nothing
        self.assertEqual(C.get(self.paths, crypto.unlock(self.paths, self.master(NEW)), LABEL)["secret"], SECRET)

    def test_a_failure_writing_the_new_keyring_changes_nothing(self):
        self.fill()
        ring, auth_before = self.paths.keyring_file.read_bytes(), self.paths.auth_file.read_bytes()
        with mock.patch("kos.crypto._write_keyring", side_effect=OSError("io error")):
            code, _ = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 1)
        self.assertEqual(self.paths.keyring_file.read_bytes(), ring)
        self.assertEqual(self.paths.auth_file.read_bytes(), auth_before)
        self.assertIsNotNone(PasswordStore(self.paths).verify(PW.encode()))

    def test_a_broken_keyring_stops_the_change_before_anything_is_touched(self):
        self.fill()
        self.paths.keyring_file.write_bytes(b"garbage")
        auth_before = self.paths.auth_file.read_bytes()
        code, out = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 1)
        self.assertIn(BAD, out)
        self.assertEqual(self.paths.auth_file.read_bytes(), auth_before)
        self.assertEqual(self.paths.keyring_file.read_bytes(), b"garbage")

    def test_without_a_keyring_the_change_works_as_before(self):
        code, _ = self.run_passwd(PW, NEW, NEW)
        self.assertEqual(code, 0)
        self.assertFalse(self.paths.keyring_file.exists())


# ================================================================ assistant ====
class TestAssistantKey(Env):
    def run_cli(self, argv, *answers):
        out, err = io.StringIO(), io.StringIO()
        auth = self.authority(*answers)
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", return_value=(auth, self.prompter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kcli.main(argv)
        return code, out.getvalue() + err.getvalue()

    def legacy(self):
        cfg = A.config_path(self.paths)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"active": "off", "local": {}, "api": {
            "provider": "anthropic", "endpoint": "", "model": "claude-x", "key": KEY}}))

    def test_set_stores_only_a_sealed_key(self):
        code, out = self.run_cli(["assistant", "set", "api", "--provider", "anthropic", "--model", "claude-x"], PW, KEY)
        self.assertEqual(code, 0, out)
        raw = A.config_path(self.paths).read_text()
        self.assertIn("key_enc", raw)
        self.assertNotIn(KEY, raw)
        self.assertNotIn('"key"', raw)
        self.scan()
        self.assertEqual(A.with_key(self.paths, self.grant(), {**A.load(self.paths), "active": "api"})["api"]["key"], KEY)

    def test_status_says_not_yet_encrypted_and_never_prints_the_key(self):
        self.legacy()
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), contextlib.redirect_stdout(out):
            self.assertEqual(kcli.main(["assistant", "status"]), 0)
        self.assertIn("key not yet encrypted", out.getvalue())
        self.assertNotIn(KEY, out.getvalue())

    def test_legacy_plaintext_key_is_encrypted_by_use_and_the_plaintext_removed(self):
        self.legacy()
        code, out = self.run_cli(["assistant", "use", "api"], PW)
        self.assertEqual(code, 0, out)
        self.assertNotIn(KEY.encode(), A.config_path(self.paths).read_bytes())
        self.assertTrue(self.paths.keyring_file.exists())
        self.scan()
        self.assertEqual(A.with_key(self.paths, self.grant(), A.load(self.paths))["api"]["key"], KEY)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), contextlib.redirect_stdout(out):
            kcli.main(["assistant", "status"])
        self.assertIn("set (encrypted)", out.getvalue())

    def test_legacy_key_is_also_migrated_by_set_local_and_by_the_bridge(self):
        self.legacy()
        code, out = self.run_cli(["assistant", "set", "local", "--endpoint", "http://127.0.0.1:11434/v1/chat/completions",
                                  "--model", "m"], PW)
        self.assertEqual(code, 0, out)
        self.assertNotIn(KEY.encode(), A.config_path(self.paths).read_bytes())
        self.assertIn("key_enc", A.config_path(self.paths).read_text())

    def test_the_bridge_opens_the_key_once_per_instance_and_only_in_memory(self):
        self.legacy()
        F.add_rule(self.paths, "os:assistant", "api.anthropic.com", 443, "https")
        A.migrate(self.paths, self.grant())
        cfg = A.load(self.paths); cfg["active"] = "api"; A.save(self.paths, cfg)
        seen = []
        b = SystemBridge(self.paths, app="chat", system=False, assistant=True)
        auth = self.authority(PW)
        msg = validate_app_message({"cmd": "request", "action": "assistant", "system": "",
                                    "messages": [{"role": "user", "content": "hi"}]}, "tui")
        with mock.patch("kos.assistant.ask", side_effect=lambda cfg, *a, **k: seen.append(cfg["api"].get("key")) or "yes"):
            out = []
            b.handle(msg, out.append, auth)
            b.handle(msg, out.append, auth)
        self.assertEqual(seen, [KEY, KEY])
        self.assertEqual(len(self.prompter.asked), 1)                  # one password for the instance
        self.assertTrue(all(o["ok"] for o in out))
        self.assertNotIn(KEY, json.dumps(out))
        self.assertNotIn("key", json.dumps(A.load(self.paths)["api"]).replace("key_enc", ""))
        self.scan()

    def test_the_bridge_refuses_when_the_key_cannot_be_decrypted(self):
        A.set_api(self.paths, "anthropic", "", "m", KEY, self.grant())
        cfg = A.load(self.paths); cfg["active"] = "api"; A.save(self.paths, cfg)
        F.add_rule(self.paths, "os:assistant", "api.anthropic.com", 443, "https")
        self.paths.keyring_file.write_bytes(b"x" * 80)
        b = SystemBridge(self.paths, app="chat", system=False, assistant=True)
        msg = validate_app_message({"cmd": "request", "action": "assistant", "system": "",
                                    "messages": [{"role": "user", "content": "hi"}]}, "tui")
        out = []
        with mock.patch("kos.assistant.ask", side_effect=AssertionError("must not connect")):
            b.handle(msg, out.append, self.authority(PW))
        self.assertEqual(out, [{"cmd": "assistant", "ok": False, "error": "refused"}])


# ====================================================== credential protocol ====
class TestCredentialValidation(Env):
    def msg(self, **kw):
        return {"cmd": "request", "action": "credential", **kw}

    def test_table_of_bad_requests_is_refused_and_nothing_is_written(self):
        full = dict(op="add", label="l", username="u", secret="s", url="", notes="")
        bad = [msg for msg in (
            {}, dict(op=None), dict(op=5), dict(op=["list"]), dict(op="LIST"), dict(op="x"), dict(op="list ", ),
            dict(op="list", label="x"), dict(op="list", extra=1),
            dict(op="get"), dict(op="get", label=5), dict(op="get", label=None), dict(op="get", label=""),
            dict(op="get", label="x" * 81), dict(op="get", label="a", id=1), dict(op="delete"),
            dict(op="delete", label=["a"]), dict(op="delete", label="a\x1b[2J"),
            *[dict(op="get", label="a" + c + "b") for c in ("\x00", "\n", "\r", "\t", "\x7f", "\x85", " ", "‮", "⁦")],
            {k: v for k, v in full.items() if k != "notes"}, {**full, "extra": "x"}, {**full, "secret": ""}, {**full, "label": ""},
            {**full, "secret": "s" * 1025}, {**full, "username": "u" * 161}, {**full, "url": "u" * 513},
            {**full, "notes": "n" * 1001}, {**full, "username": 5}, {**full, "secret": b"bytes"}, {**full, "url": None},
            {**full, "notes": ["n"]}, {**full, "secret": "a\x00b"}, {**full, "notes": "line\nbreak"}, {**full, "url": "x\x9by"},
        )]
        for kw in bad:
            with self.assertRaises(ProtocolError, msg=str(kw)[:80]):
                validate_app_message(self.msg(**kw), "tui")
        for kw in (dict(op="list"), dict(op="get", label="a b"), dict(op="delete", label="a" * 80), full,
                   {**full, "secret": "s" * 1024, "notes": "n" * 1000, "username": "", "url": ""}):
            self.assertEqual(validate_app_message(self.msg(**kw), "tui")["action"], "credential")
        self.assertEqual([p for p in Path(self.tmp.name).rglob("*") if p.name in ("keyring.bin", "credentials.bin")], [])

    def test_the_bridge_itself_refuses_unvalidated_junk_before_writing(self):
        b = self.bridge()
        for req in ({"cmd": "request", "action": "credential", "op": "add", "label": "a", "username": "", "secret": "s" * 5000,
                     "url": "", "notes": ""},
                    {"cmd": "request", "action": "credential", "op": "weird"}):
            out = []
            b.handle(req, out.append, self.authority(PW))
            self.assertFalse(out[0]["ok"])
        self.assertFalse(self.paths.credentials_file.exists())

    def test_duplicate_label_and_entry_limit(self):
        b, auth = self.bridge(), self.authority(*[PW] * 600)
        self.assertTrue(self.add(b, auth)["ok"])
        self.assertEqual(self.add(b, auth)["error"], "exists")
        dek = crypto.unlock(self.paths, self.master())
        for i in range(1, C.MAX_ENTRIES):
            C.add(self.paths, dek, {"label": f"l{i}", "username": "", "secret": "s", "url": "", "notes": ""})
        self.assertEqual(self.add(b, auth, label="one-more")["error"], "full")

    def test_manifest_accepts_only_the_exact_permission_name(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "app.py", "modes": ["tui"], "description": "d"}
        Manifest.parse(json.dumps({**base, "permissions": ["credentials"]}).encode())
        with self.assertRaises(KAppError):
            Manifest.parse(json.dumps({**base, "permissions": ["credential"]}).encode())


# ================================================================ the bridge ====
class TestCredentialBridge(Env):
    def seed(self):
        self.add(self.bridge(), self.authority(PW))

    def test_no_password_means_nothing_is_decrypted_and_a_fixed_refusal(self):
        self.seed()
        for op, kw in (("list", {}), ("get", {"label": LABEL}), ("delete", {"label": LABEL}),
                       ("add", dict(label="z", username="", secret=SECRET + "2", url="", notes=""))):
            auth = self.authority(None)                      # the owner cancels the prompt
            r = self.call(self.bridge(), auth, op=op, **kw)
            self.assertEqual(r, {"cmd": "credential", "ok": False, "error": "refused"}, op)
            self.assertEqual(len(self.prompter.asked), 1)
            text = self.prompter.asked[0]
            self.assertNotIn(SECRET, text)
        before = self.paths.credentials_file.read_bytes()
        self.assertEqual(C.list_rows(self.paths, crypto.unlock(self.paths, self.master()))[0]["label"], LABEL)
        self.assertEqual(self.paths.credentials_file.read_bytes(), before)      # nothing deleted or added

    def test_wrong_password_three_times_is_refused(self):
        self.seed()
        r = self.call(self.bridge(), self.authority("nope-nope-1", "nope-nope-2", "nope-nope-3"), op="get", label=LABEL)
        self.assertEqual(r["error"], "refused")
        self.assertNotIn("entry", r)

    def test_per_operation_password_rule(self):
        b = self.bridge()
        auth = self.authority(*[PW] * 20)
        self.add(b, auth)                                              # add: password
        self.assertEqual(len(self.prompter.asked), 1)
        r = self.call(b, auth, op="list")                              # list: once per instance
        self.assertEqual(len(self.prompter.asked), 2)
        self.assertEqual(r["entries"], [{"id": 1, "label": LABEL, "username": USER, "url": "https://e.example"}])
        self.assertNotIn(SECRET, json.dumps(r))
        self.call(b, auth, op="list"); self.call(b, auth, op="list")
        self.assertEqual(len(self.prompter.asked), 2)
        for n in (3, 4):                                               # get: every time
            r = self.call(b, auth, op="get", label=LABEL)
            self.assertEqual(r["entry"]["secret"], SECRET)
            self.assertEqual(len(self.prompter.asked), n)
        self.assertIn("get", self.prompter.asked[-1])
        self.assertIn(LABEL, self.prompter.asked[-1])                  # the prompt shows the label ...
        self.assertNotIn(SECRET, "".join(self.prompter.asked))         # ... never the secret
        self.assertTrue(self.call(b, auth, op="delete", label=LABEL)["ok"])    # delete: password
        self.assertEqual(len(self.prompter.asked), 5)
        self.assertIn("delete", self.prompter.asked[-1])
        self.assertEqual(self.call(b, auth, op="list")["entries"], [])          # list reflects the change, no new prompt
        self.assertEqual(len(self.prompter.asked), 5)
        self.assertEqual(self.call(b, auth, op="get", label=LABEL)["error"], "not-found")

    def test_audit_has_app_op_outcome_but_never_label_secret_or_value(self):
        b = self.bridge()
        auth = self.authority(*[PW] * 5)
        self.add(b, auth); self.call(b, auth, op="list"); self.call(b, auth, op="get", label=LABEL)
        self.call(b, auth, op="get", label="missing-" + LABEL)
        self.call(b, auth, op="delete", label=LABEL)
        log = (self.paths.logs / "audit.log").read_text()
        self.assertIn("credential.request", log)
        self.assertIn("vaultapp add", log)
        self.assertIn("vaultapp get", log)
        self.assertIn("failed:not-found", log)
        for p in PLANTS + ("missing-", "e.example"):
            self.assertNotIn(p, log)
        self.scan()

    def latch_holds(self):
        """True if an app that was denied twice is not asked a third time (the 2-denial latch)."""
        self.add(self.bridge(), self.authority(PW))
        b = self.bridge()
        auth = self.authority(None, None, PW, PW)
        r1 = self.call(b, auth, op="get", label=LABEL)
        r2 = self.call(b, auth, op="delete", label=LABEL)
        self.assertEqual((r1["error"], r2["error"]), ("refused", "refused"))
        asked = len(self.prompter.asked)
        r3 = self.call(b, auth, op="get", label=LABEL)
        r4 = self.call(b, auth, op="list")
        return asked == 2 and len(self.prompter.asked) == 2 and r3["error"] == r4["error"] == "refused" and "entry" not in r3

    def test_two_denials_latch_the_app_off(self):
        self.assertTrue(self.latch_holds())

    def test_latch_mutation_is_detected(self):
        with mock.patch("kos.system.MAX_CRED_DENIALS", 10 ** 6):          # the latch disabled
            self.assertFalse(self.latch_holds())

    def test_a_new_app_instance_starts_with_a_clean_count(self):
        self.seed()
        auth = self.authority(None, None, PW)
        b = self.bridge()
        self.call(b, auth, op="get", label=LABEL); self.call(b, auth, op="get", label=LABEL)
        self.assertEqual(self.call(self.bridge(), auth, op="get", label=LABEL)["entry"]["secret"], SECRET)

    def test_narrow_permission_isolation(self):
        self.seed()
        cred_only = self.bridge()
        others = [{"cmd": "request", "action": "assistant", "system": "", "messages": [{"role": "user", "content": "x"}]},
                  {"cmd": "request", "action": "sysinfo", "topic": "os"},
                  {"cmd": "request", "action": "firewall", "op": "list"},
                  {"cmd": "request", "action": "fetch", "url": "https://example.org/", "method": "GET", "headers": {}, "body": ""},
                  {"cmd": "request", "action": "apps"}]
        auth = self.authority()                  # any prompt raises: these must be refused without asking
        for req in others:
            out = []
            cred_only.handle(req, out.append, auth)
            self.assertFalse(out[0].get("ok"), req["action"])
        self.assertEqual(self.prompter.asked, [])
        for kw in (dict(assistant=True), dict(sysinfo=True), dict(firewall=True), dict(network=True)):
            b = SystemBridge(self.paths, app="other", system=True, **kw)
            out = []
            b.handle({"cmd": "request", "action": "credential", "op": "get", "label": LABEL}, out.append, auth)
            self.assertEqual(out, [{"cmd": "credential", "ok": False, "error": "refused"}], kw)
        self.assertEqual(self.prompter.asked, [])

    def test_every_operation_leaves_no_plaintext_and_no_secret_in_exceptions(self):
        b = self.bridge()
        auth = self.authority(*[PW] * 10)
        for step in (lambda: self.add(b, auth), lambda: self.call(b, auth, op="list"),
                     lambda: self.call(b, auth, op="get", label=LABEL), lambda: self.call(b, auth, op="delete", label=LABEL)):
            step()
            self.scan()
        msgs = []
        for fn in (lambda: crypto.open_(os.urandom(32), "credentials", self.paths.credentials_file.read_bytes() if self.paths.credentials_file.exists() else b""),
                   lambda: C.check_field("secret", SECRET + "\x00"), lambda: C.get(self.paths, os.urandom(32), LABEL)):
            try:
                fn()
            except Exception as e:                              # noqa: BLE001
                msgs.append(repr(e) + str(e) + repr(e.__cause__) + repr(e.__context__))
        self.assertTrue(msgs)
        for m in msgs:
            for p in PLANTS:
                self.assertNotIn(p, m)

    def test_a_blob_swapped_between_files_is_refused(self):
        A.set_api(self.paths, "anthropic", "", "m", KEY, self.grant())
        self.seed()
        import base64
        key_blob = base64.b64decode(A.load(self.paths)["api"]["key_enc"])
        good = self.paths.credentials_file.read_bytes()
        self.paths.credentials_file.write_bytes(key_blob)               # assistant blob as the credentials file
        r = self.call(self.bridge(), self.authority(PW), op="list")
        self.assertEqual(r, {"cmd": "credential", "ok": False, "error": "unavailable"})
        self.paths.credentials_file.write_bytes(good)                   # and the other way round
        cfg = A.load(self.paths)
        cfg["api"]["key_enc"] = base64.b64encode(good).decode()
        A.save(self.paths, cfg)
        with self.assertRaises(A.AssistantError):
            A.with_key(self.paths, self.grant(), {**A.load(self.paths), "active": "api"})
        self.paths.credentials_file.write_bytes(good[:-1])             # truncated store
        self.assertEqual(self.call(self.bridge(), self.authority(PW), op="list")["error"], "unavailable")
        self.paths.credentials_file.write_bytes(b"")
        self.assertEqual(self.call(self.bridge(), self.authority(PW), op="list")["error"], "unavailable")

    def test_empty_store_lists_nothing_without_making_a_keyring(self):
        r = self.call(self.bridge(), self.authority(PW), op="list")
        self.assertEqual(r, {"cmd": "credential", "ok": True, "entries": []})
        self.assertFalse(self.paths.keyring_file.exists())


class TestSdk(unittest.TestCase):
    def test_sdk_round_trip_sends_a_valid_request_and_keeps_other_events(self):
        import socket
        from kos.sdk import App
        a, b = socket.socketpair()
        self.addCleanup(a.close); self.addCleanup(b.close)
        app = App(a)
        b.sendall(b'{"cmd":"key","key":"x"}\n{"cmd":"credential","ok":true,"entry":{"secret":"s"},"junk":1}\n')
        self.assertEqual(app.credential("get", "lbl"), (True, {"entry": {"secret": "s"}}))
        sent = json.loads(b.recv(65536).split(b"\n")[0])
        self.assertEqual(validate_app_message(sent, "tui")["op"], "get")
        self.assertEqual(next(app.events())["key"], "x")
        b.sendall(b'{"cmd":"credential","ok":false,"error":"refused"}\n')
        self.assertEqual(app.credential("list"), (False, "refused"))
        b.close()
        self.assertEqual(app.credential("list"), (False, "unreachable"))


# ================================================================== the app ====
class TestCredentialManagerApp(unittest.TestCase):
    KEYS = ["r", "down", "up", "enter", "escape", "d", "n", "a", "x", "escape", "ctrl-n", "escape", "pagedown", "end", "home",
            "a", "L", "enter", "enter", "enter", "enter", "S", "enter", "y", "d", "y", "q"]

    def entry(self):
        from kos.office.pack_os import ENTRIES
        return next(e for e in ENTRIES if e.title == "Credential Manager")

    def fake(self, store, calls=None):
        def fn(op, label="", username="", secret="", url="", notes=""):
            if op == "list":
                return True, {"entries": [{"id": i, "label": k, "username": v["username"], "url": v["url"]}
                                          for i, (k, v) in enumerate(store.items(), 1)]}
            if op == "get":
                return (True, {"entry": {"label": label, **store[label]}}) if label in store else (False, "not-found")
            if op == "add":
                if label in store:
                    return False, "exists"
                store[label] = {"username": username, "secret": secret, "url": url, "notes": notes}
                return True, {"detail": "stored"}
            if label in store:
                del store[label]
                return True, {"detail": "deleted"}
            return False, "not-found"
        return fn

    def run_app(self, keys, fn):
        from kos.office.ui import FakeHost, run
        h = FakeHost(keys)
        h.credential_fn = fn
        e = self.entry()
        run(h, e.args["make"](h, e))
        return h

    def test_entry_is_a_real_narrow_partial_app(self):
        e = self.entry()
        self.assertEqual((e.scope, e.perms, e.network, e.name), ("partial", ("credentials",), False, "credential-manager"))
        self.assertTrue(60 <= len(e.note) <= 320 and len(e.name) <= 32)
        low = e.note.lower()
        for phrase in ("encrypted at rest", "your password", "no autofill", "no sync", "no browser integration", "no sharing",
                       "not a compromised running system"):
            self.assertIn(phrase, low, phrase)

    def test_add_reveal_delete_and_planted_secrets_never_reach_the_vault(self):
        store = {}
        typed = ["a", *LABEL_KEYS("lbl"), "enter", *LABEL_KEYS("usr"), "enter", "enter", "enter", *LABEL_KEYS("SECRETPLANT"), "enter"]
        h = self.run_app(typed + ["enter", "x", "d", "y", "q"], self.fake(store))
        ops = [c[0] for c in h.credential_calls]
        self.assertIn("add", ops)
        self.assertIn("get", ops)
        self.assertIn("delete", ops)
        self.assertEqual(store, {})                                   # deleted again
        self.assertEqual(h.data, {})                                  # the app's own vault was never written
        self.assertEqual(h.spaces, {})
        self.assertTrue(h.frames)

    def test_secret_is_shown_only_on_the_reveal_screen_and_masked_while_typing(self):
        store = {"site": {"username": "me", "secret": "SECRETPLANT", "url": "", "notes": ""}}
        h = self.run_app(["enter"], self.fake(store))
        self.assertIn("SECRETPLANT", "\n".join(h.frames[-1][1]))
        h = self.run_app(["enter", "x"], self.fake(store))            # any key closes it
        for f in h.frames[-1:]:
            self.assertNotIn("SECRETPLANT", "\n".join(f[1]))
        h = self.run_app(["r", "down"], self.fake(store))             # the list never shows it
        self.assertTrue(all("SECRETPLANT" not in "\n".join(f[1]) for f in h.frames))
        h = self.run_app(["a", *LABEL_KEYS("l"), "enter", "enter", "enter", "enter", *LABEL_KEYS("HIDDENPLANT")], self.fake({}))
        self.assertNotIn("HIDDENPLANT", "\n".join(h.frames[-1][1]))

    def test_survives_a_key_battery_and_hostile_hosts(self):
        planted = {"site": {"username": "me", "secret": SECRET, "url": "u", "notes": "n"}}
        for fn in (self.fake(dict(planted)), None, lambda *a: (False, "unavailable"), lambda *a: 1 / 0,
                   lambda *a: (True, {"entries": "zz"}), lambda *a: (True, {"entries": [1, None, {"label": 5}]}),
                   lambda *a: (True, {"entry": "nope"}), lambda *a: (False, "x" * 500), lambda *a: (True, 5)):
            h = self.run_app(self.KEYS, fn)
            self.assertTrue(h.frames)
            self.assertEqual(h.data, {})
            self.assertEqual(h.spaces, {})

    def test_the_agent_context_never_holds_a_secret(self):
        """The Ctrl-N agent reads only the app's vault (empty) and its own chat; the app never put a secret in either."""
        from kos.office.agent import Agent
        store = {"site": {"username": "me", "secret": SECRET, "url": "", "notes": ""}}
        h = self.run_app(["enter", "x", "ctrl-n"], self.fake(store))
        self.assertEqual(h.data, {})
        self.assertFalse(any(SECRET in json.dumps(c) for c in h.assistant_calls))
        self.assertTrue(callable(Agent))


def LABEL_KEYS(text):
    return list(text)


if __name__ == "__main__":
    unittest.main()
