"""Run with: python3 -m unittest discover -s tests -v"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import usb  # noqa: E402
from kos.cli import build_parser  # noqa: E402

LSBLK = """{"blockdevices": [
 {"name":"sda","path":"/dev/sda","size":"500107862016","tran":"sata","rm":false,"ro":false,
  "model":"Samsung SSD","vendor":"ATA     ","type":"disk","mountpoints":[null],
  "children":[{"name":"sda2","path":"/dev/sda2","type":"part","mountpoints":["/"]}]},
 {"name":"sdb","path":"/dev/sdb","size":"16008609792","tran":"usb","rm":true,"ro":false,
  "model":"Cruzer Blade","vendor":"SanDisk ","type":"disk","mountpoints":[null]},
 {"name":"sdc","path":"/dev/sdc","size":"16008609792","tran":"usb","rm":true,"ro":false,
  "model":"Mounted Stick","vendor":"","type":"disk","mountpoints":[null],
  "children":[{"name":"sdc1","path":"/dev/sdc1","type":"part","mountpoints":["/media/x"]}]},
 {"name":"sdd","path":"/dev/sdd","size":"1000000","tran":"usb","rm":true,"ro":false,
  "model":"Tiny","vendor":"","type":"disk","mountpoints":[null]},
 {"name":"loop0","path":"/dev/loop0","size":"100","type":"loop","mountpoints":[null]}
]}"""


def make_image(path: Path, with_loader=True, esp=True, pad_mib=4):
    """A minimal GPT disk image: protective MBR, header, one partition entry,
    and an 'ESP' that does (or does not) contain a BOOTX64.EFI directory entry."""
    img = bytearray(pad_mib * 1024 * 1024)
    img[510:512] = b"\x55\xaa"
    hdr = bytearray(92)
    hdr[:8] = b"EFI PART"
    hdr[72:80] = (2).to_bytes(8, "little")
    hdr[80:84] = (128).to_bytes(4, "little")
    hdr[84:88] = (128).to_bytes(4, "little")
    img[512:512 + 92] = hdr
    guid = usb.ESP_GUID if esp else uuid.uuid4()
    entry = bytearray(128)
    entry[:16] = guid.bytes_le
    entry[16:32] = uuid.uuid4().bytes_le
    entry[32:40] = (2048).to_bytes(8, "little")
    entry[40:48] = (4095).to_bytes(8, "little")
    img[1024:1024 + 128] = entry
    if with_loader:
        img[2048 * 512 + 1000:2048 * 512 + 1011] = b"BOOTX64 EFI"
    path.write_bytes(bytes(img))
    return path


class TestUsb(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.disks = usb.parse_lsblk(LSBLK)

    def test_parse_and_refusals(self):
        by = {d.path: d for d in self.disks}
        self.assertEqual(set(by), {"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/loop0"})
        self.assertIsNone(usb.refusal(by["/dev/sdb"], need=4 * 1024 * 1024))
        self.assertIn("mounted: /", usb.refusal(by["/dev/sda"]))          # child mount counts
        self.assertIn("/media/x", usb.refusal(by["/dev/sdc"]))
        self.assertIn("too small", usb.refusal(by["/dev/sdd"], need=10 ** 9))
        self.assertIn("not a USB disk", usb.refusal(usb.Disk("/dev/sde", 10 ** 12, tran="sata")))
        self.assertIsNone(usb.refusal(usb.Disk("/dev/sde", 10 ** 12, tran="sata"), allow_non_usb=True))
        self.assertIn("mounted", usb.refusal(by["/dev/sda"], allow_non_usb=True))   # never a mounted disk

    def test_check_image(self):
        ok = make_image(self.tmp / "ok.img")
        self.assertEqual(len(usb.check_image(ok)), 2)
        with self.assertRaisesRegex(usb.UsbError, "BOOTX64.EFI"):
            usb.check_image(make_image(self.tmp / "noloader.img", with_loader=False))
        with self.assertRaisesRegex(usb.UsbError, "EFI system partition"):
            usb.check_image(make_image(self.tmp / "noesp.img", esp=False))
        junk = self.tmp / "junk.img"
        junk.write_bytes(b"\0" * 4096)
        with self.assertRaisesRegex(usb.UsbError, "not a disk image"):
            usb.check_image(junk)
        with self.assertRaises(usb.UsbError):
            usb.check_image(self.tmp / "missing.img")

    def test_loader_name_across_chunk_boundary(self):
        img = make_image(self.tmp / "b.img", with_loader=False, pad_mib=8)
        data = bytearray(img.read_bytes())
        edge = 2048 * 512 + usb.CHUNK            # the name straddles the 4 MiB read boundary
        data[edge - 5:edge + 6] = b"BOOTX64 EFI"
        data[4095 * 512:4096 * 512] = b"\0" * 512
        img.write_bytes(bytes(data))
        # the ESP ends at LBA 4095 (~1 MiB) in this synthetic layout, so widen it
        d = bytearray(img.read_bytes())
        d[1024 + 40:1024 + 48] = (2048 + usb.CHUNK // 512 + 100).to_bytes(8, "little")
        img.write_bytes(bytes(d))
        self.assertTrue(usb.check_image(img))

    def test_write_to_file_and_verify(self):
        img = make_image(self.tmp / "ok.img")
        out = self.tmp / "stick.bin"
        notes = usb.write_image(img, str(out))
        self.assertEqual(out.read_bytes(), img.read_bytes())
        self.assertTrue(any("matches" in n for n in notes))

    def test_write_refuses_bad_image_before_touching_target(self):
        out = self.tmp / "stick.bin"
        with self.assertRaises(usb.UsbError):
            usb.write_image(make_image(self.tmp / "x.img", with_loader=False), str(out))
        self.assertFalse(out.exists())

    def test_verify_detects_a_lying_drive(self):
        img = make_image(self.tmp / "ok.img")
        out = self.tmp / "stick.bin"
        real = usb._copy

        def corrupt(src, dst, total, progress):
            real(src, dst, total, progress)
            dst.seek(123456)
            dst.write(b"\xff")
            dst.flush()
        usb._copy = corrupt
        try:
            with self.assertRaisesRegex(usb.UsbError, "verification FAILED at byte 123456"):
                usb.write_image(img, str(out))
        finally:
            usb._copy = real

    def test_device_targets_are_guarded(self):
        img = make_image(self.tmp / "ok.img")
        with self.assertRaises(usb.UsbError):                       # missing /dev node
            usb.write_image(img, "/dev/definitely-not-a-disk", disks=self.disks)
        if os.geteuid() == 0:
            # /dev/null is not a block device: never opened for writing
            with self.assertRaisesRegex(usb.UsbError, "not a block device"):
                usb.write_image(img, "/dev/null", disks=self.disks)

    def test_cli_parser_and_list(self):
        p = build_parser()
        a = p.parse_args(["usb", "write", "k.img", "/dev/sdb", "--yes", "--no-verify"])
        self.assertEqual((a.usb_cmd, a.image, a.device, a.yes, a.no_verify),
                         ("write", "k.img", "/dev/sdb", True, True))
        lines = []
        rc = usb.cmd_usb(p.parse_args(["usb", "list"]), disks=self.disks, out=lines.append)
        text = "\n".join(lines)
        self.assertEqual(rc, 0)
        self.assertIn("/dev/sdb", text)
        self.assertIn("ok to write", text)
        self.assertIn("REFUSED: in use", text)          # the mounted stick
        self.assertNotIn("/dev/sda ", text)             # internal disk hidden unless --all
        lines.clear()
        usb.cmd_usb(p.parse_args(["usb", "list", "--all"]), disks=self.disks, out=lines.append)
        self.assertIn("/dev/sda", "\n".join(lines))

    def test_cli_write_file_target(self):
        img = make_image(self.tmp / "ok.img")
        out = self.tmp / "stick.bin"
        a = build_parser().parse_args(["usb", "write", str(img), str(out), "--yes"])
        lines = []
        self.assertEqual(usb.cmd_usb(a, disks=self.disks, out=lines.append), 0)
        self.assertEqual(out.read_bytes(), img.read_bytes())
        self.assertTrue(any("boot menu" in l for l in lines))

    def test_qemu_script_attaches_image_as_usb_storage(self):
        fake = self.tmp / "bin"
        fake.mkdir()
        q = fake / "qemu-system-x86_64"
        q.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$QEMU_ARGS"\n')
        q.chmod(q.stat().st_mode | stat.S_IEXEC)
        ovmf = self.tmp / "OVMF_CODE.fd"
        ovmf.write_bytes(b"x")
        img = make_image(self.tmp / "ok.img")
        args_file = self.tmp / "args"
        env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", OVMF=str(ovmf), QEMU_ARGS=str(args_file))
        subprocess.run([str(usb.qemu_script()), "--usb", str(img)], env=env, check=True)
        args = args_file.read_text().split("\n")
        self.assertIn("usb-storage,bus=xhci.0,drive=stick,bootindex=0,removable=on", args)
        self.assertIn(f"if=none,id=stick,file={img},format=raw", args)
        self.assertFalse(any("virtio" in a and "drive" in a for a in args))   # no non-USB disk
        subprocess.run([str(usb.qemu_script()), str(img)], env=env, check=True)
        self.assertTrue(any(a.startswith("file=") and "if=virtio" in a for a in args_file.read_text().split("\n")))


if __name__ == "__main__":
    unittest.main()
