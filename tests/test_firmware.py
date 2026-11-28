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
        (self.root / "sys/kernel/iommu_groups/0").mkdir(parents=True)   # a healthy machine has an IOMMU

    def close(self):
        self._tmp.cleanup()

    def write(self, rel, text=""):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def allow(self, *lines):
        self.write("etc/kos/firmware.allow", "\n".join(lines) + "\n")
        return self.root / "etc/kos/firmware.allow"

    def pci(self, bdf, vendor, klass, hfsts1=None, driver=None, device="0x1234"):
        d = f"sys/bus/pci/devices/{bdf}"
        self.write(f"{d}/vendor", vendor + "\n")
        self.write(f"{d}/device", device + "\n")
        self.write(f"{d}/class", klass + "\n")
        self.write(f"{d}/driver_override", "(null)\n")
        self.write(f"{d}/d3cold_allowed", "0\n")
        self.write(f"{d}/power/control", "on\n")
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
        script = (f'FW_ROOT="{self.root}"; FW_ALLOW="{self.root}/etc/kos/firmware.allow"; . "{SH}"; kos_firmware_scan; '
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
        self.t.pci("0000:00:00.0", "0x8086", "0x060000")     # a host bridge
        self.t.pci("0000:00:14.0", "0x8086", "0x0c0330")     # a USB xHCI controller
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


class TestOtherFirmwareChips(FirmwareCase):
    CASES = [
        ("thunderbolt", lambda t: t.pci("0000:00:0d.2", "0x8086", "0x0c0340")),
        ("network", lambda t: t.pci("0000:02:00.0", "0x8086", "0x020000")),
        ("display", lambda t: t.pci("0000:00:02.0", "0x8086", "0x030000")),
        ("nvme", lambda t: t.pci("0000:01:00.0", "0x144d", "0x010802")),
        ("wireless", lambda t: t.pci("0000:03:00.0", "0x8086", "0x0d1100")),
        ("typec-port", lambda t: (t.root / "sys/class/typec/port0").mkdir(parents=True)),
        ("embedded-controller", lambda t: (t.root / "sys/bus/acpi/devices/PNP0C09:00").mkdir(parents=True)),
        ("thunderbolt", lambda t: (t.root / "sys/bus/thunderbolt/devices/domain0").mkdir(parents=True)),
    ]

    def test_each_is_found_and_blocks_boot_in_python_and_shell(self):
        for kind, make in self.CASES:
            t = Tree()
            self.addCleanup(t.close)
            make(t)
            py, v = t.py_findings()
            sh, gate = t.sh_findings()
            self.assertEqual(py, {(kind, "active")}, kind)
            self.assertEqual(sh, py, kind)
            self.assertFalse(v.ok, kind)
            self.assertEqual(gate, 1, kind)

    def test_optional_peripherals_off_only_if_the_kernel_says_d3cold(self):
        for kind, klass in (("thunderbolt", "0x0c0340"), ("wireless", "0x0d1100")):
            for state, want in (("D3cold", "neutralized"), ("D0", "active"), ("D3hot", "active")):
                t = Tree()
                self.addCleanup(t.close)
                bdf = t.pci("0000:03:00.0", "0x8086", klass)
                t.write(f"sys/bus/pci/devices/{bdf}/power_state", state + "\n")
                py, v = t.py_findings()
                self.assertEqual(py, {(kind, want)}, (kind, state))
                self.assertEqual(t.sh_findings(), (py, 0 if want == "neutralized" else 1), (kind, state))
                self.assertEqual(v.ok, want == "neutralized")

    def test_things_that_must_stay_powered_are_never_counted_off(self):
        for klass in ("0x020000", "0x030000", "0x010802"):       # NIC, GPU, NVMe
            t = Tree()
            self.addCleanup(t.close)
            bdf = t.pci("0000:03:00.0", "0x8086", klass)
            t.write(f"sys/bus/pci/devices/{bdf}/power_state", "D3cold\n")
            self.assertEqual({s for _, s in t.py_findings()[0]}, {"active"}, klass)
            self.assertEqual(t.sh_findings()[1], 1, klass)

    def test_mitigation_unbinds_and_requests_power_down_but_does_not_decide(self):
        bdf = self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", driver="iwlwifi")
        v = firmware.enforce(self.t.root, "enforce")
        d = self.t.root / "sys/bus/pci/devices" / bdf
        self.assertEqual((self.t.root / "sys/bus/pci/drivers/iwlwifi/unbind").read_text().strip(), bdf)
        self.assertEqual((d / "d3cold_allowed").read_text().strip(), "1")
        self.assertEqual((d / "power/control").read_text().strip(), "auto")
        self.assertEqual({(f.kind, f.state) for f in v.findings}, {("wireless", "active")})   # not off: no D3cold
        self.assertFalse(v.ok)

    def test_shell_requests_power_down_then_rescans(self):
        bdf = self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", driver="iwlwifi")
        self.t.sh_findings()
        d = self.t.root / "sys/bus/pci/devices" / bdf
        self.assertEqual((d / "power/control").read_text().strip(), "auto")

    def test_none_of_them_are_unbound_or_touched(self):
        self.t.pci("0000:01:00.0", "0x144d", "0x010802", driver="nvme")
        v = firmware.enforce(self.t.root, "enforce")
        self.assertEqual(v.actions, [])
        self.assertEqual((self.t.root / "sys/bus/pci/drivers/nvme/unbind").read_text(), "")

    def test_inside_a_vm_emulated_chips_are_ignored_but_the_ME_is_not(self):
        self.t.write("proc/cpuinfo", "flags\t: fpu hypervisor\n")
        self.t.pci("0000:02:00.0", "0x8086", "0x020000")
        self.assertEqual(self.t.py_findings()[0], set())
        self.assertEqual(self.t.sh_findings(), (set(), 0))
        self.t.intel_me()
        self.assertEqual(self.t.py_findings()[0], {("intel-me", "active")})

    def test_dma_chips_without_an_iommu_are_a_finding_of_their_own(self):
        import shutil
        shutil.rmtree(self.t.root / "sys/kernel/iommu_groups")
        self.t.pci("0000:02:00.0", "0x8086", "0x020000")
        want = {("network", "active"), ("no-iommu", "active")}
        self.assertEqual(self.t.py_findings()[0], want)
        self.assertEqual(self.t.sh_findings()[0], want)

    def test_no_dma_chips_means_no_iommu_finding(self):
        import shutil
        shutil.rmtree(self.t.root / "sys/kernel/iommu_groups")
        self.assertEqual(self.t.py_findings()[0], set())

    def test_there_is_no_resident_checker(self):
        import ast
        tree = ast.parse(Path(firmware.__file__).read_text())
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertFalse(imported & {"threading", "subprocess", "multiprocessing", "sched", "asyncio", "signal"})
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.While)])    # no loop that waits and watches
        sh = SH.read_text()
        self.assertNotRegex(sh, r"(?m)^\s*(while\s+(true|:)|sleep\b)|&\s*$")        # no sleep loop, no background job

    def test_cmdline_turns_the_iommu_on_strictly(self):
        cmd = (SH.parent.parent.parent / "kernel" / "cmdline.txt").read_text()
        for arg in ("intel_iommu=on", "amd_iommu=force_isolation", "iommu.strict=1", "iommu.passthrough=0"):
            self.assertIn(arg, cmd)


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
        self.t.pci("0000:00:00.0", "0x8086", "0x060000")
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


class TestAllowList(FirmwareCase):
    def both(self):
        return self.t.py_findings(), self.t.sh_findings()

    def test_an_allowed_device_stops_blocking_but_is_still_reported(self):
        self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", device="0x2725")
        self.t.allow("# my reflashed card", "pci 8086:2725")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("wireless", "allowed")})
        self.assertEqual(sh, py)
        self.assertTrue(v.ok)
        self.assertEqual(gate, 0)
        self.assertIn("ALLOWED", v.findings[0].line())

    def test_it_matches_the_exact_device_only(self):
        self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", device="0x2725")
        self.t.allow("pci 8086:9999", "pci 1022:2725")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("wireless", "active")})
        self.assertEqual((sh, gate), (py, 1))

    def test_a_kind_entry_covers_non_pci_chips_too(self):
        (self.t.root / "sys/bus/acpi/devices/PNP0C09:00").mkdir(parents=True)
        self.t.allow("kind embedded-controller")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("embedded-controller", "allowed")})
        self.assertEqual((sh, gate), (py, 0))

    def test_allowing_the_me_still_shows_it_and_a_typo_allows_nothing(self):
        self.t.intel_me()
        self.t.allow("pci 8086:1234x", "kinds intel-me", "pci", "kind")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("intel-me", "active")})
        self.assertEqual((sh, gate), (py, 1))
        self.t.allow("pci 0x8086:0x1234")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("intel-me", "allowed")})
        self.assertEqual((sh, gate), (py, 0))

    def test_matching_is_case_sensitive_in_both_scanners(self):
        self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", device="0x2a2b")
        self.t.allow("pci 8086:2A2B")                    # uppercase: not the id sysfs reports
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("wireless", "active")})
        self.assertEqual((sh, gate), (py, 1))

    def test_the_missing_iommu_cannot_be_allowed_away(self):
        import shutil
        shutil.rmtree(self.t.root / "sys/kernel/iommu_groups")
        self.t.pci("0000:02:00.0", "0x8086", "0x020000", device="0x15f3")
        self.t.allow("kind no-iommu", "pci 8086:15f3")
        (py, v), (sh, gate) = self.both()
        self.assertFalse(v.ok)       # the NIC is allowed, but with no IOMMU the finding stands
        self.assertEqual(gate, 1)

    def test_the_image_ships_the_list_in_both_places(self):
        mk = (SH.parent.parent / "mkinitramfs.sh").read_text()
        img = (SH.parent.parent.parent / "image" / "mkimage.sh").read_text()
        self.assertIn("firmware.allow", mk)
        self.assertIn("etc/kos/firmware.allow", img)
        self.assertEqual(firmware.load_allow(SH.parent.parent / "firmware.allow"), (set(), set()))   # ships empty


class TestMachineRule(FirmwareCase):
    def both(self):
        return self.t.py_findings(), self.t.sh_findings()

    def test_off_by_default_so_other_machines_and_vms_boot(self):
        self.t.write("sys/class/dmi/id/sys_vendor", "Dell Inc.\n")
        (py, v), (sh, gate) = self.both()
        self.assertEqual((py, sh, gate), (set(), set(), 0))

    def test_framework_only_refuses_everything_else_in_both_scanners(self):
        self.t.cmdline("quiet kos.machine=framework")
        self.t.write("sys/class/dmi/id/sys_vendor", "Dell Inc.\n")
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("wrong-machine", "active")})
        self.assertEqual((sh, gate), (py, 1))
        self.assertFalse(v.ok)

    def test_a_framework_passes_and_nothing_reported_is_refused_too(self):
        self.t.cmdline("kos.machine=framework")
        self.t.write("sys/class/dmi/id/sys_vendor", "Framework\n")
        (py, v), (sh, gate) = self.both()
        self.assertEqual((py, sh, gate), (set(), set(), 0))
        (self.t.root / "sys/class/dmi/id/sys_vendor").unlink()
        (py, v), (sh, gate) = self.both()
        self.assertEqual(py, {("wrong-machine", "active")})
        self.assertEqual((sh, gate), (py, 1))

    def test_the_allow_list_cannot_waive_it(self):
        self.t.cmdline("kos.machine=framework")
        self.t.allow("kind wrong-machine")
        self.assertFalse(self.t.py_findings()[1].ok)

    def test_it_is_shipped_off(self):
        cmd = (SH.parent.parent.parent / "kernel" / "cmdline.txt").read_text()
        self.assertNotIn("kos.machine=framework", cmd)


class TestPlan(FirmwareCase):
    def test_every_blocking_kind_has_advice_and_nothing_is_written(self):
        self.t.intel_me()
        self.t.pci("0000:02:00.0", "0x8086", "0x020000")
        (self.t.root / "sys/bus/acpi/devices/PNP0C09:00").mkdir(parents=True)
        before = sorted(str(p) for p in self.t.root.rglob("*"))
        before_text = {p: p.read_bytes() for p in self.t.root.rglob("*") if p.is_file()}
        items = firmware.plan(self.t.root)
        self.assertEqual({i.kind for i in items}, {"intel-me", "network", "embedded-controller"})
        self.assertTrue(all(i.advice and i.open_replacement for i in items))
        self.assertEqual(sorted(str(p) for p in self.t.root.rglob("*")), before)
        self.assertEqual({p: p.read_bytes() for p in self.t.root.rglob("*") if p.is_file()}, before_text)
        self.assertEqual({i.kind: i.open_replacement for i in items}["network"], "no")

    def test_every_kind_the_scanner_can_emit_is_in_the_plan_table(self):
        emitted = {"intel-me", "amd-psp", "bmc-ipmi", "thunderbolt", "network", "display", "nvme",
                   "wireless", "typec-port", "embedded-controller", "no-iommu", "wrong-machine"}
        self.assertEqual(emitted - set(firmware.PLAN), set())

    def test_accepted_and_off_chips_are_not_advised_to_do_anything(self):
        self.t.intel_me(mode=3)
        self.t.pci("0000:03:00.0", "0x8086", "0x0d1100", device="0x2725")
        self.t.allow("pci 8086:2725")
        items = {i.kind: i for i in firmware.plan(self.t.root)}
        self.assertIn("Already believed off", items["intel-me"].advice)
        self.assertIn("allow list", items["wireless"].advice)
        self.assertEqual(firmware.plan_summary(list(items.values())), "Nothing blocks the boot.")

    def test_summary_says_when_no_open_replacement_exists(self):
        self.t.pci("0000:02:00.0", "0x8086", "0x020000")
        text = firmware.plan_summary(firmware.plan(self.t.root))
        self.assertIn("no open replacement", text)
        self.assertIn("kos.firmware=warn", text)

    def test_platform_firmware_names_coreboot_only_when_it_says_so(self):
        self.t.write("sys/class/dmi/id/bios_vendor", "coreboot\n")
        self.t.write("sys/class/dmi/id/bios_version", "4.19\n")
        self.assertIn("open (coreboot)", firmware.platform_firmware(self.t.root))
        self.t.write("sys/class/dmi/id/bios_vendor", "American Megatrends\n")
        self.assertIn("vendor firmware", firmware.platform_firmware(self.t.root))

class TestProtections(FirmwareCase):
    def by_name(self):
        return {n: (st, note) for n, st, note in firmware.protections(self.t.root)}

    def test_reports_what_is_on_and_is_honest_about_the_rest(self):
        self.t.write("proc/cpuinfo", "flags\t: fpu tme\n")
        self.t.write("sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-kosroot\n")
        self.t.write("sys/bus/thunderbolt/devices/domain0/security", "user\n")
        p = self.by_name()
        self.assertEqual(p["IOMMU"][0], "on")
        self.assertIn("tme", p["memory encryption"][0])
        self.assertIn("cannot confirm", p["memory encryption"][1])
        self.assertEqual(p["disk encryption (LUKS2)"][0], "on")
        self.assertEqual(p["Thunderbolt security"][0], "user")
        self.assertIn("never who you talk to", p["network"][1])

    def test_missing_protections_are_called_out_not_hidden(self):
        import shutil
        shutil.rmtree(self.t.root / "sys/kernel/iommu_groups")
        self.t.write("sys/bus/thunderbolt/devices/domain0/security", "none\n")
        p = self.by_name()
        self.assertEqual(p["IOMMU"][0], "OFF")
        self.assertEqual(p["memory encryption"][0], "not offered by this CPU")
        self.assertEqual(p["disk encryption (LUKS2)"][0], "not seen")
        self.assertEqual(p["Thunderbolt security"][0], "OFF (none)")

    def test_protections_never_change_the_boot_verdict(self):
        self.t.intel_me()
        before = firmware.probe(self.t.root).ok
        firmware.protections(self.t.root)
        self.assertEqual(firmware.probe(self.t.root).ok, before)


class TestFirmwareService(unittest.TestCase):
    """`kos firmware` and `kos doctor` are the System Information app now; it asks the OS through the
    system.firmware and system.report services (kos/services.py), and the password is the permission."""

    def setUp(self):
        from kos.auth import Authority, KdfParams, PasswordStore, Throttle
        from kos.paths import Paths
        from kos.prompt import ScriptedPrompter
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(b"correct horse battery", KdfParams.fresh(n=2**10), throttle_base=0)
        self._mk = lambda *a: Authority(self.paths, ScriptedPrompter(a), Throttle(self.paths, base=0))

    def _service(self, name, args, *answers):
        from kos.protocol import validate_app_message
        from kos.services import ServiceHost
        msg = validate_app_message({"cmd": "service", "id": 1, "name": name, "args": args}, "tui")
        return ServiceHost(self.paths, "test", frozenset({"system"})).call(msg, self._mk(*answers))

    def test_firmware_reports_the_gate_and_what_narrows_the_remaining_chips(self):
        r = self._service("system.firmware", {"plan": False}, "correct horse battery")
        self.assertTrue(r["ok"], r)
        d = r["data"]
        self.assertIn(d["policy"], ("enforce", "warn"))
        self.assertIsInstance(d["ok"], bool)
        self.assertEqual(d["ok"], not d["reason"], "a refusal always says why")
        self.assertTrue(d["protections"])
        self.assertNotIn("plan", d)

    def test_the_plan_is_advice_only(self):
        r = self._service("system.firmware", {"plan": True}, "correct horse battery")
        self.assertTrue(r["ok"], r)
        self.assertIn("plan", r["data"])
        self.assertTrue(r["data"]["summary"])
        self.assertTrue(r["data"]["platform"])

    def test_it_needs_the_password_and_gives_nothing_without_it(self):
        r = self._service("system.firmware", {"plan": False}, "no", "no", "no")
        self.assertFalse(r["ok"])
        self.assertEqual(r["data"], {})

    def test_the_system_report_says_whether_this_is_the_kos_kernel(self):
        r = self._service("system.report", {}, "correct horse battery")
        self.assertTrue(r["ok"], r)
        k = r["data"]["kos_kernel"]
        self.assertEqual(set(k) >= {"present", "role", "required"}, True)
        self.assertIsInstance(k["present"], bool)


if __name__ == "__main__":
    unittest.main()
