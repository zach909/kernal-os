"""Run with: python3 -m unittest discover -s tests -v

The firmware gate is tested against a fake sysfs tree. Both implementations -
kos/firmware.py and the pre-boot shell script - must give the same verdict on
the same tree, because the second one is what actually runs first.
"""

import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import firmware  # noqa: E402
from kos.admin import AdminKeyboard, requirements  # noqa: E402
from kos.init import firmware_gate  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.requires import Unsatisfied  # noqa: E402

SH = Path(__file__).resolve().parent.parent / "boot" / "initramfs" / "firmware.sh"


class Tree:
    """A fake machine: sysfs/devfs/procfs under a temp directory."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def close(self):
        self._tmp.cleanup()

    def write(self, rel, text=""):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def pci(self, bdf, vendor, klass, hfsts1=None, driver=None):
        d = f"sys/bus/pci/devices/{bdf}"
        self.write(f"{d}/vendor", vendor + "\n")
        self.write(f"{d}/class", klass + "\n")
        self.write(f"{d}/driver_override", "(null)\n")
        cfg = bytearray(256)
        if hfsts1 is not None:
            cfg[0x40:0x44] = struct.pack("<I", hfsts1)
        (self.root / d / "config").write_bytes(bytes(cfg))
        if driver:
            self.write(f"sys/bus/pci/drivers/{driver}/unbind", "")
            (self.root / d / "driver").symlink_to(self.root / f"sys/bus/pci/drivers/{driver}")
        return bdf

    def intel_me(self, mode=0, bdf="0000:00:16.0", driver="mei_me"):
        return self.pci(bdf, "0x8086", "0x078000", hfsts1=mode << 16, driver=driver)

    def cmdline(self, text):
        self.write("proc/cmdline", text + "\n")

    def sh_findings(self):
        """(kind, state) pairs and the gate's exit status from the shell script."""
        script = (f'FW_ROOT="{self.root}"; . "{SH}"; kos_firmware_scan; '
                  f'echo "ACTIVE=$fw_active"; kos_firmware_gate >/dev/null; echo "GATE=$?"')
        out = subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True).stdout
        found = {tuple(l.split()[1:3]) for l in out.splitlines() if l.startswith("FINDING ")}
        gate = int([l for l in out.splitlines() if l.startswith("GATE=")][0][5:])
        return found, gate

    def py_findings(self):
        v = firmware.probe(self.root)
        return {(f.kind, f.state) for f in v.findings}, v


class FirmwareCase(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.addCleanup(self.t.close)


class TestDetection(FirmwareCase):
    def test_an_empty_machine_has_nothing_to_report(self):
        found, v = self.t.py_findings()
        self.assertEqual(found, set())
        self.assertTrue(v.ok)

    def test_running_intel_me_is_found_and_blocks_boot(self):
        self.t.intel_me(mode=0)
        found, v = self.t.py_findings()
        self.assertEqual(found, {("intel-me", "active")})
        self.assertFalse(v.ok)
        self.assertIn("Intel Management Engine", v.reason())

    def test_every_other_operation_mode_counts_as_running(self):
        for mode in (1, 2, 4, 5, 15):
            t = Tree()
            self.addCleanup(t.close)
            t.intel_me(mode=mode)
            self.assertEqual(t.py_findings()[0], {("intel-me", "active")}, mode)

    def test_disabled_me_is_the_only_one_believed_off(self):
        self.t.intel_me(mode=firmware.ME_MODE_DISABLED)
        found, v = self.t.py_findings()
        self.assertEqual(found, {("intel-me", "neutralized")})
        self.assertTrue(v.ok)

    def test_unreadable_status_register_is_running_not_off(self):
        d = self.t.intel_me(mode=3)
        (self.t.root / "sys/bus/pci/devices" / d / "config").write_bytes(b"\x00" * 8)  # too short
        self.assertEqual(self.t.py_findings()[0], {("intel-me", "active")})
        (self.t.root / "sys/bus/pci/devices" / d / "config").unlink()
        self.assertEqual(self.t.py_findings()[0], {("intel-me", "active")})

    def test_amd_psp_is_always_running(self):
        self.t.pci("0000:05:00.2", "0x1022", "0x108000")
        self.assertEqual(self.t.py_findings()[0], {("amd-psp", "active")})

    def test_bmc_found_by_dmi_record_or_device_node(self):
        self.t.write("sys/firmware/dmi/entries/38-0/raw", "x")
        self.assertEqual(self.t.py_findings()[0], {("bmc-ipmi", "active")})
        t = Tree()
        self.addCleanup(t.close)
        t.write("dev/ipmi0")
        self.assertEqual(t.py_findings()[0], {("bmc-ipmi", "active")})

    def test_other_pci_devices_are_not_flagged(self):
        self.t.pci("0000:00:02.0", "0x8086", "0x030000")     # an Intel GPU
        self.t.pci("0000:06:00.0", "0x1022", "0x020000")     # an AMD NIC
        self.assertEqual(self.t.py_findings()[0], set())

    def test_bare_metal_with_nothing_visible_gets_a_caveat_but_boots(self):
        self.t.write("proc/cpuinfo", "vendor_id\t: GenuineIntel\nflags\t: fpu vme\n")
        _, v = self.t.py_findings()
        self.assertTrue(v.ok)
        self.assertIn("cannot prove", v.caveat)
        t = Tree()
        self.addCleanup(t.close)
        t.write("proc/cpuinfo", "vendor_id\t: GenuineIntel\nflags\t: fpu hypervisor\n")
        self.assertEqual(t.py_findings()[1].caveat, "")      # a VM has no ME of its own


class TestPolicy(FirmwareCase):
    def test_enforce_is_the_default_and_unknown_values_fail_closed(self):
        self.t.intel_me()
        for cmdline in ("quiet", "kos.firmware=enforce", "kos.firmware=off", "kos.firmware="):
            self.t.cmdline(cmdline)
            self.assertFalse(firmware.probe(self.t.root).ok, cmdline)

    def test_warn_boots_anyway_but_still_reports(self):
        self.t.intel_me()
        self.t.cmdline("quiet kos.firmware=warn")
        v = firmware.probe(self.t.root)
        self.assertTrue(v.ok)
        self.assertEqual(len(v.blocking), 1)

    def test_pid1_ignores_the_environment_but_a_dev_run_honours_it(self):
        self.t.cmdline("quiet")
        os.environ["KOS_DEV_FIRMWARE"] = "warn"
        try:
            self.assertEqual(firmware.current_policy(self.t.root), "warn")   # we are not PID 1
            from unittest import mock
            with mock.patch("os.getpid", return_value=1):
                self.assertEqual(firmware.current_policy(self.t.root), "enforce")
        finally:
            del os.environ["KOS_DEV_FIRMWARE"]


class TestMitigation(FirmwareCase):
    def test_it_cuts_the_os_side_and_says_the_thing_is_still_running(self):
        bdf = self.t.intel_me()
        v = firmware.enforce(self.t.root, "enforce")
        self.assertEqual((self.t.root / "sys/bus/pci/drivers/mei_me/unbind").read_text().strip(), bdf)
        self.assertEqual((self.t.root / f"sys/bus/pci/devices/{bdf}/driver_override").read_text().strip(),
                         firmware.OVERRIDE)
        self.assertTrue(v.findings[0].detached)
        self.assertTrue(any("still running" in a for a in v.actions))

    def test_mitigation_never_turns_running_into_off(self):
        self.t.intel_me()
        v = firmware.enforce(self.t.root, "enforce")
        self.assertEqual({(f.kind, f.state) for f in v.findings}, {("intel-me", "active")})
        self.assertFalse(v.ok)

    def test_the_device_stays_visible_so_the_next_scan_cannot_say_absent(self):
        self.t.intel_me()
        firmware.enforce(self.t.root, "enforce")
        self.assertEqual(self.t.py_findings()[0], {("intel-me", "active")})

    def test_a_disabled_me_is_left_alone(self):
        self.t.intel_me(mode=3)
        v = firmware.enforce(self.t.root, "enforce")
        self.assertEqual(v.actions, [])
        self.assertEqual((self.t.root / "sys/bus/pci/drivers/mei_me/unbind").read_text(), "")

    def test_bmc_driver_behind_a_class_device_is_unbound(self):
        self.t.write("sys/bus/platform/drivers/ipmi_si/unbind", "")
        dev = self.t.root / "sys/devices/platform/ipmi_si.0"
        dev.mkdir(parents=True)
        (dev / "driver").symlink_to(self.t.root / "sys/bus/platform/drivers/ipmi_si")
        cls = self.t.root / "sys/class/ipmi/ipmi0"
        cls.mkdir(parents=True)
        (cls / "device").symlink_to(dev)
        v = firmware.enforce(self.t.root, "enforce")
        self.assertEqual((self.t.root / "sys/bus/platform/drivers/ipmi_si/unbind").read_text().strip(),
                         "ipmi_si.0")
        self.assertTrue(v.findings[0].detached)
        self.assertFalse(v.ok)


class TestShellAgreesWithPython(FirmwareCase):
    def agree(self, expect_gate):
        sh_found, sh_gate = self.t.sh_findings()
        py_found, v = self.t.py_findings()
        self.assertEqual(sh_found, py_found)
        self.assertEqual(sh_gate, expect_gate)
        self.assertEqual(sh_gate == 0, v.ok)

    def test_empty(self):
        self.agree(0)

    def test_running_me(self):
        self.t.intel_me(mode=0)
        self.agree(1)

    def test_disabled_me(self):
        self.t.intel_me(mode=3)
        self.agree(0)

    def test_unreadable_me(self):
        d = self.t.intel_me(mode=3)
        (self.t.root / "sys/bus/pci/devices" / d / "config").write_bytes(b"")
        self.agree(1)

    def test_psp_and_bmc(self):
        self.t.pci("0000:05:00.2", "0x1022", "0x108000")
        self.t.write("dev/ipmi0")
        self.agree(1)

    def test_unrelated_devices(self):
        self.t.pci("0000:00:02.0", "0x8086", "0x030000")
        self.agree(0)

    def test_warn_policy(self):
        self.t.intel_me()
        self.t.cmdline("quiet kos.firmware=warn")
        self.agree(0)

    def test_unknown_policy_fails_closed(self):
        self.t.intel_me()
        self.t.cmdline("kos.firmware=off")
        self.agree(1)

    def test_shell_detaches_the_driver_before_refusing(self):
        bdf = self.t.intel_me()
        self.t.sh_findings()
        self.assertEqual((self.t.root / "sys/bus/pci/drivers/mei_me/unbind").read_text().strip(), bdf)

    def test_preboot_init_runs_the_gate_before_touching_the_disk(self):
        init = (SH.parent / "init").read_text()
        self.assertLess(init.index("kos_firmware_gate"), init.index("cryptsetup open"))
        self.assertLess(init.index("kos_firmware_gate"), init.index("kos.root"))
        self.assertIn('firmware.sh || halt_forever', init)       # missing script = fail closed
        mk = (SH.parent.parent / "mkinitramfs.sh").read_text()
        self.assertIn("firmware.sh", mk)
        self.assertRegex(mk, r"applet in [^;]*\bod\b")


class _Say:
    def __init__(self):
        self.lines = []

    def info(self, m):
        self.lines.append(m)


class TestInitGate(FirmwareCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(Path(self.tmp.name))

    def test_machine_with_a_running_me_does_not_boot(self):
        self.t.intel_me()
        say = _Say()
        with self.assertRaises(SystemExit) as ctx:
            firmware_gate(self.paths, say, self.t.root)
        self.assertEqual(ctx.exception.code, 70)
        text = "\n".join(say.lines)
        self.assertIn("Intel Management Engine", text)
        self.assertIn("will not boot", text)
        log = (self.paths.logs / "audit.log").read_text()
        self.assertIn("refused-to-boot", log)
        self.assertIn("intel-me:active", log)

    def test_clean_machine_boots_silently(self):
        say = _Say()
        self.assertTrue(firmware_gate(self.paths, say, self.t.root).ok)
        self.assertEqual(say.lines, [])

    def test_warn_boots_after_alerting_and_detaching(self):
        self.t.intel_me()
        self.t.cmdline("kos.firmware=warn")
        say = _Say()
        v = firmware_gate(self.paths, say, self.t.root)
        self.assertTrue(v.ok)
        self.assertIn("Intel Management Engine", "\n".join(say.lines))
        self.assertTrue(v.findings[0].detached)

    def test_unlock_requires_firmware_control(self):
        kb = AdminKeyboard(self.paths, kernel_report=lambda: {"landlock_abi": 3, "user_namespaces": True},
                           probe=lambda: ["/dev/input/event0"])
        self.t.intel_me()
        bad = requirements(kb, None, firmware=lambda: firmware.probe(self.t.root).reason())
        with self.assertRaises(Unsatisfied) as ctx:
            bad.ensure("session.unlock")
        self.assertEqual(ctx.exception.chain, ["session.unlock", "firmware"])
        self.assertIn("complete control", str(ctx.exception))
        good = requirements(kb, None, firmware=lambda: None)
        with self.assertRaises(Unsatisfied) as ctx:
            good.ensure("session.unlock")
        self.assertEqual(ctx.exception.chain[-1], "admin.keyboard")   # got past firmware, stopped at the next link


class TestCli(unittest.TestCase):
    def test_firmware_command_is_read_only_and_reports(self):
        from contextlib import redirect_stdout
        from kos import cli
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as d, redirect_stdout(buf):
            os.environ["KOS_ROOT"] = d
            try:
                code = cli.main(["firmware"])
            finally:
                del os.environ["KOS_ROOT"]
        self.assertIn("boot:", buf.getvalue())
        self.assertIn(code, (0, 1))


if __name__ == "__main__":
    unittest.main()
