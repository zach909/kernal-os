"""Run with: python3 -m unittest tests.test_fwflash -v   (or discover -s tests)

The firmware flasher (kos/fwflash.py) is tested against a fake machine (a sysfs tree under a temp
directory) and a fake chip (a file). Nothing here touches a real flash chip and ``flashrom`` is never
run. Each refusal has its own test: a write that must not happen is checked by looking at the chip.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import fwflash  # noqa: E402
from kos.auth import ACTIONS, Authority, AuthorizationDenied, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402

PW = "correct horse battery"
OLD = b"OLD-FIRMWARE-" * 8            # what the fake chip holds
NEW = b"KOS-FIRMWARE-" * 8            # same size: a whole-chip image
BOARD = {"board_vendor": "Framework", "board_name": "Laptop13"}


class FakeChip(fwflash.Writer):
    """A flash chip that is a file. Faults are switched on per test."""

    def __init__(self, kind, path, data=OLD):
        self.kind, self.path = kind, Path(path)
        self.path.write_bytes(data)
        self.writes = []
        self.flip_after_write = False      # the chip stores something other than what was written
        self.fail_write_n = ()             # 1-based write numbers that raise
        self.unstable = False              # reads differ from one call to the next
        self.reads = 0

    def read(self, chip, dest):
        self.reads += 1
        data = self.path.read_bytes()
        if self.unstable and self.reads % 2:
            data = data[:-1] + b"?"
        Path(dest).write_bytes(data)

    def write(self, chip, image):
        n = len(self.writes) + 1
        self.writes.append(Path(image).read_bytes())
        if n in self.fail_write_n:
            raise fwflash.FlashError("flashrom failed (1): simulated")
        data = Path(image).read_bytes()
        if self.flip_after_write and n == 1:
            data = data[:-1] + b"X"
        self.path.write_bytes(data)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.paths = Paths(self.root)
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        for k, v in BOARD.items():
            self.write(f"sys/class/dmi/id/{k}", v + "\n")
        self.write("proc/cpuinfo", "flags : fpu vme\n")                  # not a VM
        self.keys = self.root / "keys"
        _, pub = fwflash.keygen(self.keys)
        (self.root / "etc/kos").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/kos/firmware.pub").write_bytes(pub.read_bytes())
        self.pub = self.root / "etc/kos/firmware.pub"
        self.chipfile = self.root / "chip.bin"

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def bundle_dir(self, images=None, name="b"):
        d = self.root / name
        d.mkdir(exist_ok=True)
        (d / "bios.rom").write_bytes(NEW)
        images = images if images is not None else [
            {"id": "bios", "kind": "spi-flash", "file": "bios.rom", "match": dict(BOARD)}]
        (d / "manifest.json").write_text(json.dumps({"format": 1, "name": "kos-fw", "images": images}))
        return d

    def signed(self, images=None, name="b"):
        d = self.bundle_dir(images, name)
        fwflash.sign_bundle(d, self.keys / "firmware-sign.key")
        return d

    def load(self, d):
        return fwflash.load_bundle(d, self.pub)

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def spi(self, **kw):
        self.chip = fwflash.Chip("spi-flash", "System flash (BIOS/UEFI)", "sys/class/dmi/id")
        self.fake = FakeChip("spi-flash", self.chipfile)
        return [self.chip], {"spi-flash": self.fake}

    def run_flash(self, bundle, authority, chips, writers, **kw):
        kw.setdefault("typed", lambda prompt: "FLASH bios")
        return fwflash.flash(self.paths, bundle, authority, chip_list=chips, writers=writers, **kw)

    def audit_outcomes(self):
        p = self.paths.logs / "audit.log"
        lines = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
        return [(e["action"], e["outcome"]) for e in lines if e["action"] == "firmware.flash"]


class TestBundle(Base):
    def test_a_signed_bundle_loads_and_its_hash_is_filled_in(self):
        b = self.load(self.signed())
        self.assertEqual(b.images[0].sha256, hashlib.sha256(NEW).hexdigest())
        self.assertEqual(b.images[0].size, len(NEW))

    def test_the_action_is_one_the_password_gate_knows(self):
        self.assertIn("firmware.flash", ACTIONS)

    def test_no_owner_key_installed_means_nothing_loads(self):
        d = self.signed()
        self.pub.unlink()
        with self.assertRaises(fwflash.BundleError):
            self.load(d)

    def test_a_manifest_signed_by_another_key_is_refused(self):
        d = self.bundle_dir()
        _, other_pub = fwflash.keygen(self.root / "other")
        fwflash.sign_bundle(d, self.root / "other" / "firmware-sign.key")
        with self.assertRaisesRegex(fwflash.BundleError, "not signed"):
            self.load(d)

    def test_an_edited_manifest_is_refused(self):
        d = self.signed()
        m = json.loads((d / "manifest.json").read_text())
        m["images"][0]["match"]["board_name"] = "SomethingElse"
        (d / "manifest.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(fwflash.BundleError, "not signed"):
            self.load(d)

    def test_an_edited_image_is_refused(self):
        d = self.signed()
        (d / "bios.rom").write_bytes(NEW[:-1] + b"!")
        with self.assertRaisesRegex(fwflash.BundleError, "signed hash"):
            self.load(d)

    def test_a_truncated_or_missing_signature_is_refused(self):
        d = self.signed()
        (d / "manifest.sig").write_bytes(b"x" * 10)
        with self.assertRaises(fwflash.BundleError):
            self.load(d)
        (d / "manifest.sig").unlink()
        with self.assertRaises(fwflash.BundleError):
            self.load(d)

    def test_an_image_that_is_a_symlink_is_refused(self):
        d = self.signed()
        (d / "real.rom").write_bytes(NEW)
        (d / "bios.rom").unlink()
        os.symlink(d / "real.rom", d / "bios.rom")
        with self.assertRaisesRegex(fwflash.BundleError, "plain file"):
            self.load(d)

    def _hostile(self, **over):
        img = {"id": "bios", "kind": "spi-flash", "file": "bios.rom", "match": dict(BOARD)}
        img.update(over)
        d = self.bundle_dir([img])
        # sign the raw manifest as written: signing must not paper over a bad field
        data = (d / "manifest.json").read_bytes()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes((self.keys / "firmware-sign.key").read_bytes())
        (d / "manifest.sig").write_bytes(key.sign(data))
        return d

    def test_hostile_fields_are_refused(self):
        sha = hashlib.sha256(NEW).hexdigest()
        ok = {"sha256": sha, "size": len(NEW)}
        cases = {
            "path traversal": dict(ok, file="../bios.rom"),
            "absolute path": dict(ok, file="/etc/passwd"),
            "no match": dict(ok, match={}),
            "wildcard": dict(ok, match={"board_vendor": "Frame*", "board_name": "Laptop13"}),
            "unknown match key": dict(ok, match={"board_vendor": "x", "board_name": "y", "serial": "z"}),
            "spi image with no board": dict(ok, match={"pci": "8086:1234"}),
            "bad kind": dict(ok, kind="bootrom"),
            "float size": dict(ok, size=len(NEW) + 0.5),
            "wrong size": dict(ok, size=len(NEW) + 1),
            "bad id": dict(ok, id="../x"),
            "extra field": dict(ok, run="rm -rf /"),
            "control char": dict(ok, match={"board_vendor": "Frame\x1b[31m", "board_name": "Laptop13"}),
        }
        for label, fields in cases.items():
            with self.subTest(label):
                d = self._hostile(**fields)
                with self.assertRaises(fwflash.BundleError):
                    self.load(d)

    def test_nan_and_infinity_in_the_manifest_are_refused(self):
        d = self.bundle_dir()
        data = b'{"format":1,"name":"x","images":[{"size":NaN}]}'
        (d / "manifest.json").write_bytes(data)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes((self.keys / "firmware-sign.key").read_bytes())
        (d / "manifest.sig").write_bytes(key.sign(data))
        with self.assertRaises(fwflash.BundleError):
            self.load(d)

    def test_duplicate_ids_are_refused(self):
        sha = hashlib.sha256(NEW).hexdigest()
        img = {"id": "bios", "kind": "spi-flash", "file": "bios.rom", "match": dict(BOARD), "sha256": sha, "size": len(NEW)}
        d = self.bundle_dir([img, dict(img)])
        data = (d / "manifest.json").read_bytes()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes((self.keys / "firmware-sign.key").read_bytes())
        (d / "manifest.sig").write_bytes(key.sign(data))
        with self.assertRaises(fwflash.BundleError):
            self.load(d)


class TestPlan(Base):
    def test_an_image_for_this_board_is_ready(self):
        chips, writers = self.spi()
        plan = fwflash.make_plan(self.root, self.load(self.signed()), writers, all_chips=chips)
        self.assertEqual([i.refusal for i in plan.items], [""])

    def test_an_image_for_another_board_is_refused(self):
        d = self.signed([{"id": "bios", "kind": "spi-flash", "file": "bios.rom",
                          "match": {"board_vendor": "Framework", "board_name": "Laptop16"}}])
        chips, writers = self.spi()
        plan = fwflash.make_plan(self.root, self.load(d), writers, all_chips=chips)
        self.assertIn("board_name", plan.items[0].refusal)

    def test_an_image_for_hardware_that_is_not_here_is_reported_not_written(self):
        d = self.signed([{"id": "nic", "kind": "network", "file": "bios.rom", "match": {"pci": "8086:15f3"}}])
        chips, writers = self.spi()
        plan = fwflash.make_plan(self.root, self.load(d), writers, all_chips=chips)
        self.assertEqual([i.id for i in plan.absent], ["nic"])
        self.assertEqual([c.kind for c in plan.uncovered], ["spi-flash"])

    def test_every_chip_class_without_a_real_writer_refuses_and_says_why(self):
        for kind in fwflash.KINDS:
            if kind == "spi-flash":
                continue
            with self.subTest(kind):
                d = self.signed([{"id": "x", "kind": kind, "file": "bios.rom", "match": {"pci": "8086:1234"}}], name=f"b-{kind}")
                chip = fwflash.Chip(kind, kind, "sys/bus/pci/devices/0000:00:00.0", "8086:1234")
                plan = fwflash.make_plan(self.root, self.load(d), all_chips=[chip])
                self.assertTrue(plan.items[0].refusal, kind)

    def test_the_me_and_psp_point_at_the_system_flash(self):
        self.assertIn("system flash", fwflash.REFUSALS["intel-me"])
        self.assertIn("system flash", fwflash.REFUSALS["amd-psp"])

    def test_on_battery_nothing_is_ready(self):
        self.write("sys/class/power_supply/BAT0/type", "Battery\n")
        self.write("sys/class/power_supply/AC/type", "Mains\n")
        self.write("sys/class/power_supply/AC/online", "0\n")
        chips, writers = self.spi()
        plan = fwflash.make_plan(self.root, self.load(self.signed()), writers, all_chips=chips)
        self.assertIn("charger", plan.items[0].refusal)
        self.write("sys/class/power_supply/AC/online", "1\n")
        plan = fwflash.make_plan(self.root, self.load(self.signed()), writers, all_chips=chips)
        self.assertEqual(plan.items[0].refusal, "")

    def test_a_virtual_machine_has_no_system_flash(self):
        self.write("proc/cpuinfo", "flags : fpu hypervisor\n")
        self.assertNotIn("spi-flash", [c.kind for c in fwflash.chips(self.root)])

    def test_a_real_machine_has_one(self):
        self.assertIn("spi-flash", [c.kind for c in fwflash.chips(self.root)])


class TestFlash(Base):
    def go(self, *answers, typed=None, **kw):
        chips, writers = self.spi()
        auth = self.authority(*answers)
        kw = dict(kw)
        if typed is not None:
            kw["typed"] = typed
        return self.run_flash(self.load(self.signed()), auth, chips, writers, **kw), auth

    def test_a_dry_run_reads_nothing_writes_nothing_and_asks_for_no_password(self):
        res, auth = self.go()
        self.assertEqual([r.status for r in res], [fwflash.WOULD])
        self.assertEqual(self.chipfile.read_bytes(), OLD)
        self.assertEqual(self.fake.reads, 0)
        self.assertEqual(self.prompter.asked, [])
        self.assertFalse((self.paths.state / "firmware-backup").exists())

    def test_apply_backs_up_writes_and_verifies(self):
        res, _ = self.go(PW, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.DONE], res)
        self.assertEqual(self.chipfile.read_bytes(), NEW)
        self.assertEqual(Path(res[0].backup).read_bytes(), OLD)
        self.assertEqual(oct(os.stat(res[0].backup).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(self.paths.state / "firmware-backup").st_mode & 0o777), "0o700")

    def test_only_a_verified_write_says_a_reboot_is_needed(self):
        from kos import norestart
        self.go()                                                    # a dry run writes nothing
        self.assertEqual(norestart.reboot_reasons(self.paths, running="", root=self.root), [])
        res, _ = self.go(PW, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.DONE])
        (why,) = norestart.reboot_reasons(self.paths, running="", root=self.root)
        self.assertIn("firmware", why)
        self.assertEqual(self.audit_outcomes(),
                         [("firmware.flash", "granted"), ("firmware.flash", "flash-started"),
                          ("firmware.flash", "flashed")])

    def test_the_password_prompt_names_the_chip(self):
        self.go(PW, apply=True)
        self.assertIn("spi-flash:bios", self.prompter.asked[0])

    def test_a_wrong_typed_phrase_declines_before_any_password(self):
        res, _ = self.go(apply=True, typed=lambda p: "yes")
        self.assertEqual([r.status for r in res], [fwflash.DECLINED])
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(self.chipfile.read_bytes(), OLD)
        self.assertEqual(self.fake.reads, 0)

    def test_no_typed_function_means_declined(self):
        chips, writers = self.spi()
        res = fwflash.flash(self.paths, self.load(self.signed()), self.authority(), apply=True,
                            chip_list=chips, writers=writers)
        self.assertEqual([r.status for r in res], [fwflash.DECLINED])
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_a_wrong_password_writes_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            self.go("wrong one 1", "wrong one 2", "wrong one 3", apply=True)
        self.assertEqual(self.chipfile.read_bytes(), OLD)
        self.assertEqual(self.fake.reads, 0)
        self.assertEqual(self.fake.writes, [])

    def test_a_cancelled_password_writes_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            self.go(None, apply=True)
        self.assertEqual(self.fake.writes, [])

    def test_a_password_is_asked_for_each_chip(self):
        d = self.signed([
            {"id": "bios", "kind": "spi-flash", "file": "bios.rom", "match": dict(BOARD)},
            {"id": "nic", "kind": "network", "file": "bios.rom", "match": {"pci": "8086:15f3"}}])
        spi = fwflash.Chip("spi-flash", "System flash", "sys/class/dmi/id")
        nic = fwflash.Chip("network", "network controller", "sys/bus/pci/devices/0000:00:1f.6", "8086:15f3")
        fake = FakeChip("spi-flash", self.chipfile)
        auth = self.authority(PW)                      # one password only
        res = fwflash.flash(self.paths, self.load(d), auth, apply=True, typed=lambda p: "FLASH bios",
                            chip_list=[spi, nic], writers={**fwflash.default_writers(), "spi-flash": fake})
        by = {r.target.split("@")[0]: r.status for r in res}
        self.assertEqual(by["spi-flash:bios"], fwflash.DONE)
        self.assertEqual(by["network:nic"], fwflash.REFUSED)      # no writer: refused, no password asked for it
        self.assertEqual(len(self.prompter.asked), 1)

    def test_an_image_the_wrong_size_for_the_chip_is_refused_before_a_write(self):
        self.chipfile.write_bytes(OLD)
        chips, writers = self.spi()
        self.fake.path.write_bytes(OLD + b"more")
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.REFUSED])
        self.assertEqual(self.fake.writes, [])

    def test_an_unstable_read_refuses_the_write(self):
        chips, writers = self.spi()
        self.fake.unstable = True
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.REFUSED])
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_an_image_changed_after_it_was_verified_is_never_written(self):
        d = self.signed()
        b = self.load(d)
        (d / "bios.rom").write_bytes(b"E" * len(NEW))             # swapped after the signature was checked
        chips, writers = self.spi()
        res = self.run_flash(b, self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.REFUSED])
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_a_write_that_does_not_verify_is_rolled_back(self):
        chips, writers = self.spi()
        self.fake.flip_after_write = True
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.RESTORED], res)
        self.assertEqual(self.chipfile.read_bytes(), OLD)
        self.assertEqual(self.fake.writes[-1], OLD)

    def test_a_failed_write_is_rolled_back(self):
        chips, writers = self.spi()
        self.fake.fail_write_n = (1,)
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.RESTORED])
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_when_the_rollback_fails_too_the_result_says_so_loudly(self):
        chips, writers = self.spi()
        self.fake.flip_after_write = True
        self.fake.fail_write_n = (2,)
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.LOST])
        self.assertIn("do not reboot", res[0].detail.lower())
        self.assertTrue(Path(res[0].backup).is_file())
        self.assertIn(("firmware.flash", "flash-failed-NOT-RESTORED"), self.audit_outcomes())

    def test_a_name_collision_in_the_backup_folder_refuses_before_any_write(self):
        chips, writers = self.spi()
        b = self.load(self.signed())
        first = self.run_flash(b, self.authority(PW), chips, writers, apply=True, now=lambda: 1)
        self.assertEqual([r.status for r in first], [fwflash.DONE])
        self.chipfile.write_bytes(OLD)
        writes = len(self.fake.writes)
        second = self.run_flash(b, self.authority(PW), chips, writers, apply=True, now=lambda: 1)
        self.assertEqual([r.status for r in second], [fwflash.REFUSED])
        self.assertEqual(len(self.fake.writes), writes)
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_a_disk_error_after_the_write_still_rolls_back(self):
        chips, writers = self.spi()
        orig = self.fake.read
        calls = {"n": 0}

        def read(chip, dest):
            calls["n"] += 1
            if calls["n"] == 3:                 # the read-back after the write: the disk is full
                raise OSError(28, "No space left on device")
            return orig(chip, dest)
        self.fake.read = read
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips, writers, apply=True)
        self.assertEqual([r.status for r in res], [fwflash.RESTORED], res)
        self.assertEqual(self.chipfile.read_bytes(), OLD)

    def test_a_refusal_in_apply_mode_is_audited(self):
        self.write("sys/class/power_supply/BAT0/type", "Battery\n")
        res, _ = self.go(apply=True)
        self.assertEqual([r.status for r in res], [fwflash.REFUSED])
        self.assertTrue(any(o.startswith("refused:") for _, o in self.audit_outcomes()))
        self.assertEqual(self.prompter.asked, [])

    def test_only_limits_the_images(self):
        res, _ = self.go(only={"nothing"})
        self.assertEqual(res, [])

    def test_hostile_tool_output_is_scrubbed(self):
        class Noisy(FakeChip):
            def read(self, chip, dest):
                raise fwflash.FlashError("boom \x1b[31m" + "A" * 1000)
        chips, _ = self.spi()
        res = self.run_flash(self.load(self.signed()), self.authority(PW), chips,
                             {"spi-flash": Noisy("spi-flash", self.chipfile)}, apply=True)
        self.assertNotIn("\x1b", res[0].detail)
        self.assertLessEqual(len(res[0].detail), 300)


class TestFlashrom(Base):
    def test_the_command_lines_are_exactly_these(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if "-r" in cmd:
                Path(cmd[cmd.index("-r") + 1]).write_bytes(OLD)
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        w = fwflash.FlashromWriter(run, program="flashrom")
        w.read(fwflash.Chip("spi-flash", "x"), self.root / "o")
        w.write(fwflash.Chip("spi-flash", "x"), self.root / "i")
        self.assertEqual(calls, [["flashrom", "-p", "internal", "-r", str(self.root / "o")],
                                 ["flashrom", "-p", "internal", "-w", str(self.root / "i")]])

    def test_a_failing_flashrom_is_an_error_with_clean_text(self):
        def run(cmd, **kw):
            return type("R", (), {"returncode": 3, "stdout": "", "stderr": "bad \x07 thing"})()
        with self.assertRaisesRegex(fwflash.FlashError, "failed"):
            fwflash.FlashromWriter(run).read(fwflash.Chip("spi-flash", "x"), self.root / "o")

    def test_a_missing_flashrom_is_a_refusal_not_a_crash(self):
        self.assertTrue(fwflash.FlashromWriter(program="no-such-flashrom-binary").refusal())


class TestCommandLine(Base):
    def test_there_is_no_unattended_mode(self):
        d = self.signed()
        err = self.root / "err"
        old = sys.stderr
        sys.stderr = open(err, "w")
        try:
            code = fwflash.main(["flash", str(d), "--apply"], paths=self.paths)
        finally:
            sys.stderr.close()
            sys.stderr = old
        self.assertEqual(code, 1)
        self.assertIn("terminal", err.read_text())

    def test_keygen_never_overwrites_a_key(self):
        with self.assertRaises(fwflash.FlashError):
            fwflash.keygen(self.keys)

    def test_the_private_key_is_private(self):
        self.assertEqual(oct(os.stat(self.keys / "firmware-sign.key").st_mode & 0o777), "0o600")

    def test_plan_on_a_bundle_signed_by_nobody_we_trust_is_refused(self):
        d = self.bundle_dir()
        fwflash.sign_bundle(d, self.keys / "firmware-sign.key")
        self.pub.write_bytes(b"\0" * 32)
        self.assertEqual(fwflash.main(["plan", str(d)], paths=self.paths), 1)


if __name__ == "__main__":
    unittest.main()
