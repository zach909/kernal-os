"""Run with: python3 -m unittest discover -s tests -v

The hardware map (kos/hardware.py) is tested against a fake sysfs tree, the same way the firmware
gate is. Nothing here touches a real device. One smoke test scans the real /sys of whatever
machine runs the tests, only to check that a real tree does not crash the walker.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import cli as kcli  # noqa: E402
from kos import hardware  # noqa: E402
from kos.auth import ACTIONS, AuthorizationDenied  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from test_kos import PW, Env  # noqa: E402

SECRET_SERIAL = "SN-SECRET-12345"
SECRET_MAC = "aa:bb:cc:dd:ee:ff"


class Machine:
    """A fake machine: a sysfs tree under a temp directory."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def close(self):
        self._tmp.cleanup()

    @property
    def devices(self):
        return self.root.joinpath("sys", "devices")

    def write(self, rel, text=""):
        p = self.root.joinpath(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def device(self, rel, attrs=None, subsystem=None, driver=None):
        d = self.devices.joinpath(rel)
        d.mkdir(parents=True, exist_ok=True)
        d.joinpath("uevent").write_text("")
        for k, v in (attrs or {}).items():
            d.joinpath(k).write_text(str(v) + "\n")
        if subsystem:
            os.symlink(f"../../../bus/{subsystem}", d.joinpath("subsystem"))
        if driver:
            os.symlink(f"../../../bus/x/drivers/{driver}", d.joinpath("driver"))
        return d

    def populate(self):
        """A small PC: PCIe root -> NIC (with a net interface) and a USB controller -> hub -> stick."""
        self.device("pci0000:00", subsystem="pci")
        self.device("pci0000:00/0000:00:1c.0", {"vendor": "0x8086", "device": "0x1c10", "class": "0x060400",
                                                "current_link_speed": "8.0 GT/s PCIe", "current_link_width": "4",
                                                "max_link_speed": "8.0 GT/s PCIe", "max_link_width": "4"},
                    subsystem="pci", driver="pcieport")
        self.device("pci0000:00/0000:00:1c.0/0000:01:00.0",
                    {"vendor": "0x8086", "device": "0x15b8", "class": "0x020000", "serial": SECRET_SERIAL},
                    subsystem="pci", driver="e1000e")
        # 'net' is a plain directory (no uevent): eth0 hangs off the NIC, not off 'net'
        self.device("pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0",
                    {"carrier": "1", "operstate": "up", "address": SECRET_MAC, "speed": "1000"}, subsystem="net")
        # real class devices carry a 'device' symlink to their parent; it shares its name with the PCI id attribute
        os.symlink("../../../0000:01:00.0", self.devices.joinpath("pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0/device"))
        self.device("pci0000:00/0000:00:14.0", {"vendor": "0x8086", "device": "0x9d2f"}, subsystem="pci", driver="xhci_hcd")
        self.device("pci0000:00/0000:00:14.0/usb1", {"speed": "480", "busnum": "1", "devnum": "1"}, subsystem="usb")
        self.device("pci0000:00/0000:00:14.0/usb1/1-1", {"speed": "480", "devpath": "1", "busnum": "1", "devnum": "2",
                                                         "idVendor": "0781", "idProduct": "5567",
                                                         "product": "Cruzer", "serial": SECRET_SERIAL}, subsystem="usb")
        self.device("pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0", {"bDeviceClass": "08"}, subsystem="usb")
        # virtual devices are not hardware
        self.device("virtual/tty/tty0", subsystem="tty")
        self.device("virtual/mem/null")
        return self


class MapTest(unittest.TestCase):
    def setUp(self):
        self.m = Machine().populate()
        self.addCleanup(self.m.close)

    def scan(self, **kw):
        return hardware.scan(self.m.root, **kw)

    def dev(self, found, id_):
        return next(d for d in found.devices if d["id"] == id_)

    def link(self, found, kind, a, b):
        return next((l for l in found.links if (l["kind"], l["from"], l["to"]) == (kind, a, b)), None)


class TestDevicesAndConnections(MapTest):
    def test_every_device_is_found_with_its_subsystem_driver_and_parent(self):
        f = self.scan()
        nic = self.dev(f, "pci0000:00/0000:00:1c.0/0000:01:00.0")
        self.assertEqual((nic["subsystem"], nic["driver"], nic["parent"]), ("pci", "e1000e", "pci0000:00/0000:00:1c.0"))
        self.assertEqual(nic["attrs"]["vendor"], "0x8086")
        self.assertEqual(len(f.devices), 8)              # ten dirs with a uevent, minus the two virtual ones

    def test_a_plain_directory_between_two_devices_is_not_a_device(self):
        f = self.scan()
        eth = self.dev(f, "pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0")
        self.assertEqual(eth["parent"], "pci0000:00/0000:00:1c.0/0000:01:00.0")
        self.assertNotIn("pci0000:00/0000:00:1c.0/0000:01:00.0/net", [d["id"] for d in f.devices])

    def test_each_device_is_connected_to_what_it_hangs_off(self):
        f = self.scan()
        root_port = "pci0000:00/0000:00:1c.0"
        link = self.link(f, "bus", root_port + "/0000:01:00.0", root_port)
        self.assertIsNotNone(link)
        self.assertIsNone(self.link(f, "bus", "pci0000:00", root_port))     # direction: child -> parent
        self.assertIsNotNone(self.link(f, "bus", root_port, "pci0000:00"))
        self.assertEqual(len(f.links), len(f.devices) - 1)                  # only the top-level root has no parent

    def test_a_pcie_link_carries_its_speed_and_width_and_a_usb_port_its_path(self):
        f = self.scan()
        pcie = self.link(f, "bus", "pci0000:00/0000:00:1c.0", "pci0000:00")
        self.assertEqual(pcie["attrs"]["current_link_speed"], "8.0 GT/s PCIe")
        self.assertEqual(pcie["attrs"]["max_link_width"], "4")
        usb = self.link(f, "bus", "pci0000:00/0000:00:14.0/usb1/1-1", "pci0000:00/0000:00:14.0/usb1")
        self.assertEqual((usb["attrs"]["devpath"], usb["attrs"]["busnum"]), ("1", "1"))

    def test_a_class_devices_device_symlink_is_skipped_quietly_not_reported_unreadable(self):
        f = self.scan()
        self.assertEqual(f.notes["unreadable"], 0)
        self.assertNotIn("device", self.dev(f, "pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0")["attrs"])

    def test_a_live_network_carrier_is_recorded_but_not_the_mac(self):
        eth = self.dev(self.scan(), "pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0")
        self.assertEqual((eth["attrs"]["carrier"], eth["attrs"]["operstate"]), ("1", "up"))

    def test_virtual_devices_are_left_out_and_it_says_so(self):
        f = self.scan()
        self.assertFalse([d for d in f.devices if d["id"].startswith("virtual")])
        self.assertTrue(f.notes["virtual_skipped"])

    def test_the_output_is_the_same_every_time(self):
        a, b = self.scan(), self.scan()
        self.assertEqual((a.devices, a.links), (b.devices, b.links))

    def test_a_machine_with_no_sysfs_gives_an_empty_map_not_a_crash(self):
        with tempfile.TemporaryDirectory() as t:
            f = hardware.scan(Path(t))
        self.assertEqual((f.devices, f.links, f.notes["sources"]["devices"]), ([], [], False))


class TestWhatIsNeverRead(MapTest):
    def test_serial_numbers_and_mac_addresses_are_never_stored(self):
        f = self.scan()
        blob = json.dumps([f.devices, f.links, f.notes])
        self.assertNotIn(SECRET_SERIAL, blob)
        self.assertNotIn(SECRET_MAC, blob)

    def test_the_map_says_what_software_cannot_see(self):
        text = " ".join(self.scan().notes["not_visible"])
        for word in ("solder", "far end", "GPIO", "hides"):
            self.assertIn(word, text)

    def test_a_device_cannot_put_control_characters_in_the_map(self):
        usb = self.m.devices.joinpath("pci0000:00/0000:00:14.0/usb1/1-1")
        usb.joinpath("product").write_bytes(b"\x1b[2J\x1b]0;pwned\x07Cruzer\xe2\x80\xaeevil\n" + b"A" * 500)
        value = self.dev(self.scan(), "pci0000:00/0000:00:14.0/usb1/1-1")["attrs"]["product"]
        self.assertEqual(value, hardware.clean(value))
        self.assertTrue(all(c.isprintable() for c in value))
        self.assertNotIn("\x1b", value)
        self.assertLessEqual(len(value), hardware.MAX_VALUE)

    def test_an_attribute_is_never_read_through_a_symlink(self):
        secret = self.m.write("outside/secret", "do-not-read\n")
        nic = self.m.devices.joinpath("pci0000:00/0000:00:1c.0/0000:01:00.0")
        nic.joinpath("vendor").unlink()
        os.symlink(secret, nic.joinpath("vendor"))
        f = self.scan()
        self.assertNotIn("vendor", self.dev(f, "pci0000:00/0000:00:1c.0/0000:01:00.0")["attrs"])
        self.assertNotIn("do-not-read", json.dumps(f.devices))

    def test_a_directory_in_place_of_an_attribute_is_counted_not_fatal(self):
        nic = self.m.devices.joinpath("pci0000:00/0000:00:1c.0/0000:01:00.0")
        nic.joinpath("vendor").unlink()
        nic.joinpath("vendor").mkdir()
        f = self.scan()
        self.assertGreaterEqual(f.notes["unreadable"], 1)
        self.assertIn("device", self.dev(f, "pci0000:00/0000:00:1c.0/0000:01:00.0")["attrs"])

    def test_a_symlinked_directory_is_not_followed_out_of_the_device_tree(self):
        outside = self.m.root.joinpath("outside_dev")
        outside.mkdir()
        outside.joinpath("uevent").write_text("")
        os.symlink(outside, self.m.devices.joinpath("pci0000:00", "escape"))
        self.assertNotIn("outside_dev", json.dumps(self.scan().devices))
        self.assertFalse([d for d in self.scan().devices if d["name"] == "escape"])


class TestDependenciesAndDeviceTree(MapTest):
    def devlink(self, name, consumer, supplier, status="active"):
        d = self.m.devices.joinpath("virtual", "devlink", name)
        d.mkdir(parents=True)
        d.joinpath("uevent").write_text("")
        d.joinpath("status").write_text(status + "\n")
        os.symlink("../../../" + consumer, d.joinpath("consumer"))
        os.symlink("../../../" + supplier, d.joinpath("supplier"))

    def test_a_supplier_consumer_pair_becomes_a_dependency_from_consumer_to_supplier(self):
        self.devlink("a--b", "pci0000:00/0000:00:1c.0/0000:01:00.0", "pci0000:00/0000:00:14.0")
        f = self.scan()
        link = self.link(f, "dependency", "pci0000:00/0000:00:1c.0/0000:01:00.0", "pci0000:00/0000:00:14.0")
        self.assertEqual(link["attrs"], {"status": "active"})
        self.assertFalse([d for d in f.devices if "devlink" in d["id"]])

    def test_a_dependency_on_something_not_in_the_map_is_dropped_and_counted(self):
        self.devlink("a--ghost", "pci0000:00/0000:00:1c.0", "platform/ghost")
        f = self.scan()
        self.assertEqual([l for l in f.links if l["kind"] == "dependency"], [])
        self.assertEqual(f.notes["dangling"], 1)

    def endpoint(self, rel, phandle=None, remote=None):
        d = self.m.root.joinpath("sys", "firmware", "devicetree", "base", rel)
        d.mkdir(parents=True, exist_ok=True)
        if phandle is not None:
            d.joinpath("phandle").write_bytes(phandle.to_bytes(4, "big"))
        if remote is not None:
            d.joinpath("remote-endpoint").write_bytes(remote.to_bytes(4, "big"))

    def test_two_ends_of_a_declared_port_connection_are_linked_once_and_both_exist(self):
        self.endpoint("soc/camera/port/endpoint", phandle=5, remote=9)
        self.endpoint("soc/receiver/ports/port@0/endpoint", phandle=9, remote=5)
        f = self.scan()
        ends = [l for l in f.links if l["kind"] == "devicetree-endpoint"]
        self.assertEqual(len(ends), 1)
        ids = {d["id"] for d in f.devices}
        for l in f.links:
            self.assertIn(l["from"], ids)
            self.assertIn(l["to"], ids)
        self.assertTrue(f.notes["sources"]["devicetree"])

    def test_one_sided_declaration_still_links_and_a_missing_target_is_counted(self):
        self.endpoint("a/endpoint", phandle=1, remote=2)
        self.endpoint("b/endpoint", phandle=2)
        self.endpoint("c/endpoint", phandle=3, remote=77)
        f = self.scan()
        self.assertEqual(len([l for l in f.links if l["kind"] == "devicetree-endpoint"]), 1)
        self.assertEqual(f.notes["dangling"], 1)

    def test_a_malformed_phandle_is_ignored(self):
        d = self.m.root.joinpath("sys", "firmware", "devicetree", "base", "x")
        d.mkdir(parents=True)
        d.joinpath("remote-endpoint").write_bytes(b"\x00\x01")
        self.assertEqual([l for l in self.scan().links if l["kind"] == "devicetree-endpoint"], [])


class TestLimits(MapTest):
    def test_too_many_devices_stops_early_and_says_the_map_is_partial(self):
        f = self.scan(max_devices=3)
        self.assertEqual(len(f.devices), 3)
        self.assertIn("devices", f.notes["truncated"])

    def test_too_many_directories_stops_early_and_says_so(self):
        f = self.scan(max_dirs=4)
        self.assertIn("directories", f.notes["truncated"])

    def test_every_link_points_at_a_device_that_is_in_the_map_even_when_cut_short(self):
        for kw in ({}, {"max_devices": 3}, {"max_dirs": 5}):
            f = self.scan(**kw)
            ids = {d["id"] for d in f.devices}
            for l in f.links:
                self.assertIn(l["from"], ids, kw)
                self.assertIn(l["to"], ids, kw)

    def test_a_very_deep_tree_stops_at_the_depth_limit(self):
        rel = "/".join(f"d{i}" for i in range(hardware.MAX_DEPTH + 5))
        self.m.device("deep/" + rel)
        self.assertIn("depth", self.scan().notes["truncated"])


class TestTheFolderInPermissions(Env):
    def setUp(self):
        super().setUp()
        self.m = Machine().populate()
        self.addCleanup(self.m.close)
        self.found = hardware.scan(self.m.root)

    def test_three_files_are_written_inside_the_permissions_folder_owner_only(self):
        where = hardware.save(self.paths, self.found)
        self.assertEqual(where, self.paths.state.joinpath("permissions", "hardware"))
        self.assertEqual(sorted(p.name for p in where.iterdir()), ["devices.json", "links.json", "scan.json"])
        self.assertEqual(os.stat(where).st_mode & 0o777, 0o700)
        for p in where.iterdir():
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600, p.name)

    def test_it_loads_back_the_same(self):
        hardware.save(self.paths, self.found)
        back = hardware.load(self.paths)
        self.assertEqual((back.devices, back.links), (self.found.devices, self.found.links))
        self.assertEqual(back.notes["devices"], len(self.found.devices))
        self.assertIsInstance(back.notes["scanned_at"], int)

    def test_no_map_yet_is_none_not_an_error(self):
        self.assertIsNone(hardware.load(self.paths))

    def test_an_edited_or_half_written_map_is_refused(self):
        where = hardware.save(self.paths, self.found)
        where.joinpath("links.json").write_text("[]\n")
        with self.assertRaises(hardware.HardwareError):
            hardware.load(self.paths)

    def test_garbage_files_are_refused_not_crashed_on(self):
        where = hardware.save(self.paths, self.found)
        where.joinpath("scan.json").write_text("not json")
        with self.assertRaises(hardware.HardwareError):
            hardware.load(self.paths)

    def test_a_saved_device_is_closed_to_every_app_until_someone_grants_it(self):
        hardware.save(self.paths, self.found)
        nic = next(d for d in hardware.load(self.paths).devices if d["driver"] == "e1000e")
        self.assertEqual(nic["resource"], "hw:" + nic["id"])
        self.assertFalse(Permissions(self.paths).has("any-app", nic["resource"], "use"))

    def test_what_appeared_and_what_went_away_is_reported(self):
        before = self.found
        self.m.device("pci0000:00/0000:00:14.0/usb1/1-2", {"idVendor": "dead"}, subsystem="usb")
        import shutil
        shutil.rmtree(self.m.devices.joinpath("pci0000:00/0000:00:14.0/usb1/1-1"))
        d = hardware.diff(before, hardware.scan(self.m.root))
        self.assertEqual(d["devices_added"], ["pci0000:00/0000:00:14.0/usb1/1-2"])
        self.assertIn("pci0000:00/0000:00:14.0/usb1/1-1", d["devices_removed"])
        self.assertEqual(len(d["links_added"]), 1)
        self.assertEqual(len(hardware.diff(before, before)["devices_added"]), 0)
        self.assertEqual(len(hardware.diff(None, before)["devices_added"]), len(before.devices))


class TestTheCommand(Env):
    def setUp(self):
        super().setUp()
        self.m = Machine().populate()
        self.addCleanup(self.m.close)
        self.real_scan = hardware.scan
        self.looked = []                      # every time the hardware was actually looked at

    def run_cmd(self, hw_cmd, *answers, match=None):
        out = io.StringIO()
        args = types.SimpleNamespace(hw_cmd=hw_cmd, match=match)
        with mock.patch.object(kcli, "_authority", lambda paths: (self.authority(*answers), None)), \
                mock.patch.object(hardware, "scan", lambda: self.looked.append(1) or self.real_scan(self.m.root)), \
                contextlib.redirect_stdout(out):
            code = kcli.cmd_hardware(args, self.paths)
        return code, out.getvalue()

    def audit(self):
        return [(e["action"], e["outcome"]) for e in self.authority().audit.entries()]

    def test_the_action_is_a_real_password_action(self):
        self.assertIn("hardware.scan", ACTIONS)

    def test_scan_needs_the_password_and_writes_nothing_without_it(self):
        with self.assertRaises(AuthorizationDenied):
            self.run_cmd("scan", "no", "no", "no")
        self.assertEqual(self.looked, [])                 # the hardware was not even looked at
        self.assertFalse(hardware.folder(self.paths).exists())
        self.assertIn(("hardware.scan", "denied"), self.audit())

    def test_scan_with_the_password_saves_the_map_and_audits_it(self):
        code, out = self.run_cmd("scan", PW)
        self.assertEqual(code, 0)
        self.assertIn("8 devices", out)
        self.assertIn("7 connections", out)
        self.assertIsNotNone(hardware.load(self.paths))
        self.assertIn(("hardware.scan", "granted"), self.audit())

    def test_a_second_scan_reports_what_changed(self):
        self.run_cmd("scan", PW)
        self.assertIn("unchanged", self.run_cmd("scan", PW)[1])
        self.m.device("pci0000:00/0000:00:14.0/usb1/1-3", {"idVendor": "dead"}, subsystem="usb")
        out = self.run_cmd("scan", PW)[1]
        self.assertIn("NEW device: pci0000:00/0000:00:14.0/usb1/1-3", out)
        self.assertIn("NEW connection", out)

    def test_a_scan_that_hit_a_limit_says_the_map_is_partial(self):
        orig = self.real_scan
        self.real_scan = lambda root: orig(root, max_devices=2)
        self.assertIn("INCOMPLETE", self.run_cmd("scan", PW)[1])

    def test_showing_needs_the_password_and_prints_nothing_without_it(self):
        self.run_cmd("scan", PW)
        for what in ("show", "links"):
            with self.assertRaises(AuthorizationDenied):
                self.run_cmd(what, "no", "no", "no")

    def test_show_lists_devices_and_links_lists_connections(self):
        self.run_cmd("scan", PW)
        out = self.run_cmd("show", PW)[1]
        self.assertIn("pci0000:00/0000:00:1c.0/0000:01:00.0  pci  e1000e", out)
        self.assertIn("Not visible to software", out)
        out = self.run_cmd("links", PW)[1]
        self.assertIn("bus", out)
        self.assertIn("current_link_speed=8.0 GT/s PCIe", out)

    def test_the_filter_narrows_the_list(self):
        self.run_cmd("scan", PW)
        out = self.run_cmd("show", PW, match="e1000e")[1]
        self.assertIn("e1000e", out)
        self.assertNotIn("xhci_hcd", out)

    def test_showing_before_any_scan_says_so(self):
        self.assertIn("no hardware map yet", self.run_cmd("show", PW)[1])

    def test_a_corrupt_old_map_does_not_stop_a_fresh_scan(self):
        self.run_cmd("scan", PW)
        hardware.folder(self.paths).joinpath("scan.json").write_text("garbage")
        self.assertEqual(self.run_cmd("scan", PW)[0], 0)
        self.assertIsNotNone(hardware.load(self.paths))

    def test_it_is_a_real_command_with_help_and_in_the_index(self):
        self.assertIn("hardware", kcli.COMMANDS)
        from kos.office import cmdindex
        self.assertIn("hardware", [c[0] for c in cmdindex.COMMANDS])


class TestARealTree(unittest.TestCase):
    @unittest.skipUnless(Path("/sys/devices").is_dir(), "no /sys/devices on this machine")
    def test_the_walker_survives_this_machines_real_sysfs(self):
        f = hardware.scan(Path("/"))
        self.assertGreater(len(f.devices), 0)
        ids = {d["id"] for d in f.devices}
        for l in f.links:
            self.assertIn(l["from"], ids)
            self.assertIn(l["to"], ids)
        for d in f.devices:
            for v in d["attrs"].values():
                self.assertTrue(v.isprintable())


if __name__ == "__main__":
    unittest.main()
