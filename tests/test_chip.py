"""Run with: python3 -m unittest discover -s tests -v

The security chip (kos/chip.py, kos/chipcmd.py) is tested against a FAKE TPM: this container has no
TPM, no swtpm and no tpm2-tools. So what is tested is KOS's own logic - key mixing, the recovery key,
re-keying, refusal when the chip says no, hostile auth.json. What is NOT tested is the real chip: the
exact tpm2_* command lines are only checked for shape (argument list, secret never on a command line).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import chip, chipcmd  # noqa: E402
from kos.auth import ACTIONS, AuthError, AuthorizationDenied, KdfParams, PasswordStore  # noqa: E402
from kos.chip import ChipError  # noqa: E402
from kos.store import AppStore, TamperedError  # noqa: E402
from test_kos import PW, Env  # noqa: E402


class FakeTpm:
    """A TPM that only opens what it sealed itself. `online=False` is a dead or cleared chip."""

    def __init__(self):
        self.key = os.urandom(8).hex()
        self.online = True
        self.seals = []

    def seal(self, secret, pcr):
        if not self.online:
            raise ChipError("the chip did not answer")
        self.seals.append(pcr)
        return {"pub": f"{self.key}".encode().hex(), "priv": secret[::-1].hex()}   # opaque, chip-bound

    def unseal(self, blob, pcr):
        if not self.online:
            raise ChipError("the chip did not answer")
        if bytes.fromhex(blob["pub"]).decode() != self.key:
            raise ChipError("the chip refused")
        return bytes.fromhex(blob["priv"])[::-1]


USABLE = {"present": True, "version": "2", "device": True, "tools": True, "usable": True}
NONE = {"present": False, "version": "", "device": False, "tools": False, "usable": False}


class ChipEnv(Env):
    def setUp(self):
        super().setUp()
        self.tpm = FakeTpm()
        for p in (mock.patch.object(chip, "_backend", self.tpm),
                  mock.patch.object(chip, "status", lambda *a, **k: dict(USABLE))):
            p.start()
            self.addCleanup(p.stop)

    def authority(self, *answers):
        from kos.auth import Throttle
        from kos.prompt import ScriptedPrompter
        self.prompter = ScriptedPrompter(answers)
        from kos.auth import Authority
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def enroll(self, pcr="sha256:7"):
        """Enroll and return the recovery key the owner was shown (read back from what was displayed)."""
        a = self.authority(PW)
        prompter = a.prompter
        plain = prompter.password

        def password(prompt):
            if prompt.startswith("Type the recovery key"):
                prompter.asked.append(prompt)
                return self.shown(prompter).encode()
            return plain(prompt)
        prompter.password = password
        chipcmd.enroll(self.paths, a, prompter, pcr)
        return self.shown(prompter)

    @staticmethod
    def shown(prompter):
        msg = [m for m in prompter.messages if "RECOVERY KEY" in m][-1]
        return [ln.strip() for ln in msg.splitlines() if ln.startswith("    ")][0]


class TestMixing(unittest.TestCase):
    def test_chip_secret_changes_the_master_and_is_not_the_password_alone(self):
        k = os.urandom(32)
        self.assertEqual(chip.mix(b"a" * 32, k), chip.mix(b"a" * 32, k))
        self.assertNotEqual(chip.mix(b"a" * 32, k), k)
        self.assertNotEqual(chip.mix(b"a" * 32, k), chip.mix(b"b" * 32, k))
        self.assertNotEqual(chip.mix(b"a" * 32, k), chip.mix(b"a" * 32, os.urandom(32)))

    def test_wrong_length_secret_refused(self):
        with self.assertRaises(ChipError):
            chip.mix(b"short", os.urandom(32))

    def test_recovery_wrap_round_trip_and_wrong_key(self):
        rk, secret = chip.new_recovery_key(), os.urandom(32)
        wrapped = chip.wrap_secret(rk, secret)
        self.assertEqual(chip.unwrap_secret(rk, wrapped), secret)
        with self.assertRaises(ChipError):
            chip.unwrap_secret(chip.new_recovery_key(), wrapped)
        with self.assertRaises(ChipError):
            chip.unwrap_secret(rk, "not base64 !!")
        tampered = bytearray(__import__("base64").b64decode(wrapped))
        tampered[-1] ^= 1
        with self.assertRaises(ChipError):
            chip.unwrap_secret(rk, __import__("base64").b64encode(bytes(tampered)).decode())

    def test_recovery_text_format(self):
        rk = chip.new_recovery_key()
        text = chip.format_recovery(rk)
        self.assertEqual(len(text.replace("-", "")), 52)
        self.assertEqual(chip.parse_recovery(text), rk)
        self.assertEqual(chip.parse_recovery(text.lower().replace("-", " ")), rk)
        for bad in ("", "short", text + "AA", "1" * 52, None):
            with self.assertRaises(ChipError):
                chip.parse_recovery(bad)

    def test_pcr_selection_is_validated(self):
        self.assertEqual(chip.check_pcr("sha256:0,2,7"), "sha256:0,2,7")
        self.assertEqual(chip.check_pcr("none"), "")
        for bad in ("sha1:7", "sha256:7; rm -rf /", "sha256:", "sha256:700", "-c x", "sha256:1,2,3,4,5,6,7,8,9"):
            with self.assertRaises(ChipError):
                chip.check_pcr(bad)

    def test_actions_exist(self):
        for a in ("chip.enroll", "chip.remove", "chip.recover"):
            self.assertIn(a, ACTIONS)


class TestDetection(unittest.TestCase):
    def test_status_reads_sysfs_and_opens_no_device(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs = Path(d, "tpm0")
            sysfs.mkdir()
            sysfs.joinpath("tpm_version_major").write_text("2\n")
            node = Path(d, "tpmrm0")
            node.write_text("")
            with mock.patch("builtins.open", side_effect=AssertionError("opened a file with open()")) as o, \
                    mock.patch.object(chip, "_tool", return_value="/bin/tpm2_unseal"):
                with mock.patch("pathlib.Path.read_text", lambda self, **k: "2\n"):
                    st = chip.status(sysfs, str(node))
            self.assertEqual((st["present"], st["version"], st["device"], st["usable"]), (True, "2", True, True))
            self.assertFalse(o.called)

    def test_no_chip_and_old_chip_are_not_usable(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(chip.status(Path(d, "none"), str(Path(d, "none")))["usable"])
            sysfs = Path(d, "tpm0")
            sysfs.mkdir()
            sysfs.joinpath("tpm_version_major").write_text("1\n")
            Path(d, "n").write_text("")
            with mock.patch.object(chip, "_tool", return_value="/x"):
                self.assertFalse(chip.status(sysfs, str(Path(d, "n")))["usable"])


class TestEnrollment(ChipEnv):
    def test_enroll_then_password_needs_the_chip(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        rk = self.enroll()
        store = PasswordStore(self.paths)
        self.assertIsNotNone(store.chip_block())
        # the password still works, with the chip
        self.authority(PW).authorize("app.run", "hello").close()
        # apps were re-sealed under the new master, so they still load
        with self.authority(PW).authorize("app.run", "hello") as g:
            AppStore(self.paths).load_verified("hello", g)
        # the chip gone (copied disk / dead board): refused as a chip problem, NOT a wrong password
        self.tpm.online = False
        a = self.authority(PW)
        with self.assertRaises(ChipError):
            a.authorize("app.run", "hello")
        self.assertEqual(len(a.prompter.asked), 1)          # no retry loop, no throttle strike
        self.assertTrue(chip.parse_recovery(rk))

    def test_another_computers_chip_cannot_open_it(self):
        self.enroll()
        self.tpm.key = "someone-elses-board"
        with self.assertRaises(ChipError):
            self.authority(PW).authorize("app.run", "hello")

    def test_password_alone_is_not_enough_even_with_the_block_deleted(self):
        self.enroll()
        doc = json.loads(self.paths.auth_file.read_text())
        del doc["chip"]
        self.paths.auth_file.write_text(json.dumps(doc))
        with self.assertRaises(AuthorizationDenied):
            self.authority(PW, PW, PW).authorize("app.run", "hello")

    def test_wrong_password_with_working_chip_is_still_refused(self):
        self.enroll()
        with self.assertRaises(AuthorizationDenied):
            self.authority("nope nope nope", "nope nope nope", "nope nope nope").authorize("app.run", "x")

    def test_enroll_needs_the_password_and_changes_nothing_without_it(self):
        before = self.paths.auth_file.read_text()
        with self.assertRaises(AuthorizationDenied):
            chipcmd.enroll(self.paths, self.authority("bad pass", "bad pass", "bad pass"), self.prompter)
        self.assertEqual(self.paths.auth_file.read_text(), before)

    def test_wrong_recovery_confirmation_changes_nothing(self):
        before = self.paths.auth_file.read_text()
        a = self.authority(PW, "AAAA-AAAA")
        with self.assertRaises(ChipError):
            chipcmd.enroll(self.paths, a, a.prompter)
        self.assertEqual(self.paths.auth_file.read_text(), before)

    def test_no_usable_chip_refuses_before_any_password(self):
        with mock.patch.object(chip, "status", lambda *a, **k: dict(NONE)):
            a = self.authority()
            with self.assertRaises(ChipError):
                chipcmd.enroll(self.paths, a, a.prompter)
            self.assertEqual(a.prompter.asked, [])

    def test_chip_that_will_not_read_back_changes_nothing(self):
        before = self.paths.auth_file.read_text()
        with mock.patch.object(self.tpm, "unseal", return_value=b"x" * 32):
            a = self.authority(PW)
            with self.assertRaises(ChipError):
                chipcmd.enroll(self.paths, a, a.prompter)
        self.assertEqual(self.paths.auth_file.read_text(), before)

    def test_second_enroll_refused(self):
        self.enroll()
        a = self.authority()
        with self.assertRaises(ChipError):
            chipcmd.enroll(self.paths, a, a.prompter)

    def test_passwd_keeps_the_chip(self):
        from kos import cli
        self.enroll()
        a = self.authority(PW, "brand new password", "brand new password")
        with mock.patch.object(cli, "_authority", return_value=(a, a.prompter)):
            cli.cmd_passwd(type("A", (), {"fast_kdf": True})(), self.paths)
        self.assertIsNotNone(PasswordStore(self.paths).chip_block())
        self.authority("brand new password").authorize("app.run", "x").close()
        self.tpm.online = False
        with self.assertRaises(ChipError):
            self.authority("brand new password").authorize("app.run", "x")


class TestRemoveAndRecover(ChipEnv):
    def test_remove_goes_back_to_password_alone(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.enroll()
        a = self.authority(PW, "plain password 1", "plain password 1")
        chipcmd.remove(self.paths, a, a.prompter)
        self.assertIsNone(PasswordStore(self.paths).chip_block())
        self.tpm.online = False                      # the chip is irrelevant now
        with self.authority("plain password 1").authorize("app.run", "hello") as g:
            AppStore(self.paths).load_verified("hello", g)

    def test_recover_onto_a_replacement_chip_keeps_the_master(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        rk = self.enroll()
        seals_before = (self.paths.apps / "hello.seal").read_text()
        self.tpm = FakeTpm()                         # the board was replaced
        for p in (mock.patch.object(chip, "_backend", self.tpm),):
            p.start()
            self.addCleanup(p.stop)
        with self.assertRaises(ChipError):
            self.authority(PW).authorize("app.run", "hello")
        a = self.authority(PW, rk)
        chipcmd.recover(self.paths, a, a.prompter)
        self.assertEqual((self.paths.apps / "hello.seal").read_text(), seals_before)   # nothing re-sealed
        with self.authority(PW).authorize("app.run", "hello") as g:
            AppStore(self.paths).load_verified("hello", g)

    def test_recover_refuses_wrong_pair_and_audits_it(self):
        rk = self.enroll()
        before = self.paths.auth_file.read_text()
        for pw, key in (("wrong password!", rk), (PW, chip.format_recovery(chip.new_recovery_key()))):
            a = self.authority(pw, key)
            with self.assertRaises(ChipError):
                chipcmd.recover(self.paths, a, a.prompter)
        self.assertEqual(self.paths.auth_file.read_text(), before)
        log = (self.paths.logs / "audit.log").read_text()
        self.assertIn("chip.recover", log)
        self.assertIn("bad-credentials", log)

    def test_recovery_key_alone_is_not_the_password(self):
        rk = self.enroll()
        a = self.authority("", rk)                   # empty password + the right recovery key
        with self.assertRaises(ChipError):
            chipcmd.recover(self.paths, a, a.prompter)

    def test_recover_drop_chip_with_a_dead_chip(self):
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        rk = self.enroll()
        self.tpm.online = False
        a = self.authority(PW, rk, "after the chip 1", "after the chip 1")
        chipcmd.recover(self.paths, a, a.prompter, drop_chip=True)
        self.assertIsNone(PasswordStore(self.paths).chip_block())
        with self.authority("after the chip 1").authorize("app.run", "hello") as g:
            AppStore(self.paths).load_verified("hello", g)

    def test_recover_with_nothing_enrolled(self):
        a = self.authority()
        with self.assertRaises(ChipError):
            chipcmd.recover(self.paths, a, a.prompter)


class TestHostileAuthJson(ChipEnv):
    def test_damaged_chip_blocks_stop_a_login_with_a_message(self):
        self.enroll()
        for bad in ({}, {"kind": "tpm2"}, {"kind": "tpm2", "blob": "x", "pcr": "sha256:7"},
                    {"kind": "tpm2", "blob": {"pub": 1, "priv": 2}, "pcr": "sha256:7;boom"}):
            doc = json.loads(self.paths.auth_file.read_text())
            doc["chip"] = bad
            self.paths.auth_file.write_text(json.dumps(doc))
            with self.assertRaises((AuthError, AuthorizationDenied, TypeError, ValueError, AttributeError)) as cm:
                self.authority(PW).authorize("app.run", "x")
            self.assertNotIsInstance(cm.exception, KeyError)

    def test_non_dict_chip_block_is_treated_as_not_enrolled_and_cannot_open_it(self):
        self.enroll()
        doc = json.loads(self.paths.auth_file.read_text())
        doc["chip"] = "none"
        self.paths.auth_file.write_text(json.dumps(doc))
        with self.assertRaises(AuthorizationDenied):
            self.authority(PW, PW, PW).authorize("app.run", "x")


class TestTpm2ToolsShape(unittest.TestCase):
    """Only the shape of the calls: the real tools were never run here."""

    def run_seal(self, pcr):
        calls = []

        def fake_run(argv, input=b"", cwd=None, env=None, **kw):
            calls.append((argv, input, env))
            for flag in ("seal.pub", "seal.priv"):
                if "-u" in argv or "-r" in argv:
                    Path(cwd, flag).write_bytes(b"blob")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        with mock.patch.object(chip, "_tool", side_effect=lambda n: "/usr/bin/" + n), \
                mock.patch("subprocess.run", fake_run):
            chip.Tpm2Tools().seal(b"S" * 32, pcr)
        return calls

    def test_secret_goes_on_stdin_only_and_no_shell(self):
        calls = self.run_seal("sha256:7")
        for argv, stdin, env in calls:
            self.assertIsInstance(argv, list)
            self.assertNotIn(b"S" * 32, b" ".join(a.encode() for a in argv))
            self.assertEqual(env["TPM2TOOLS_TCTI"], "device:/dev/tpmrm0")
        create = [c for c in calls if c[0][0].endswith("tpm2_create")][0]
        self.assertEqual(create[1], b"S" * 32)

    def test_pcr_policy_does_not_allow_a_password_bypass(self):
        create = [c for c in self.run_seal("sha256:7") if c[0][0].endswith("tpm2_create")][0][0]
        attrs = create[create.index("-a") + 1]
        self.assertNotIn("userwithauth", attrs)
        self.assertIn("adminwithpolicy", attrs)

    def test_no_pcr_means_no_policy(self):
        names = [c[0][0] for c in self.run_seal("none")]
        self.assertFalse(any(n.endswith("tpm2_createpolicy") for n in names))

    def test_missing_tools_and_failure_are_chip_errors(self):
        with mock.patch.object(chip, "_tool", return_value=None):
            with self.assertRaises(ChipError):
                chip.Tpm2Tools().seal(b"S" * 32, "none")
        with mock.patch.object(chip, "_tool", return_value="/bin/false"):
            with self.assertRaises(ChipError):
                chip.Tpm2Tools().seal(b"S" * 32, "none")

    def test_hostile_pcr_never_reaches_a_command_line(self):
        with mock.patch("subprocess.run") as run, mock.patch.object(chip, "_tool", return_value="/x"):
            with self.assertRaises(ChipError):
                chip.Tpm2Tools().seal(b"S" * 32, "sha256:7 --evil")
            self.assertFalse(run.called)


class TestSecurityCheck(ChipEnv):
    def levels(self):
        from kos.secure import run_checks
        return [(c.level, c.detail) for c in run_checks(self.paths) if c.name == "chip"]

    def test_usable_chip_not_enrolled_warns(self):
        (lvl, text), = self.levels()
        self.assertEqual(lvl, "warn")
        self.assertIn("kos chip enroll", text)

    def test_enrolled_passes_and_opens_no_device(self):
        self.enroll()
        with mock.patch.object(self.tpm, "unseal", side_effect=AssertionError("security check touched the chip")):
            (lvl, _), = self.levels()
        self.assertEqual(lvl, "pass")

    def test_enrolled_but_chip_missing_fails_and_names_recovery(self):
        self.enroll()
        with mock.patch.object(chip, "status", lambda *a, **k: dict(NONE)):
            (lvl, text), = self.levels()
        self.assertEqual(lvl, "fail")
        self.assertIn("kos chip recover", text)


if __name__ == "__main__":
    unittest.main()
