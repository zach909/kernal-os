"""Boot KOS from a USB stick.

``kos usb`` is a host-side tool (run it as root on the machine that built the
image, or any Linux box). It never touches a disk you did not name, and it
refuses every disk that is not a plain, unmounted, USB-attached whole disk
unless you say otherwise:

  kos usb list                       USB sticks it would be willing to write
  kos usb check kos.img              is this image bootable from removable media?
  kos usb write kos.img /dev/sdX     check, write, read back and compare
  kos usb test  kos.img              boot the image in QEMU *as a USB stick*

Why the image boots from a stick without any extra work: UEFI firmware looks
for ``\\EFI\\BOOT\\BOOTX64.EFI`` on the EFI system partition of removable media,
and ``image/mkimage.sh`` puts the signed Unified Kernel Image exactly there.
The kernel has the xHCI/EHCI/usb-storage drivers built in (kernel/kos.config)
and the pre-boot environment waits for the stick to enumerate, finding the
encrypted root by LUKS UUID, not by a /dev name, so it does not matter whether
the stick shows up as sda or sdb.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

SECTOR = 512
CHUNK = 4 * 1024 * 1024
ESP_GUID = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
BOOT_FILE_ENTRY = b"BOOTX64 EFI"       # FAT 8.3 directory entry for BOOTX64.EFI
REPO = Path(__file__).resolve().parent.parent


class UsbError(Exception):
    pass


@dataclass
class Disk:
    path: str
    size: int
    tran: str = ""
    removable: bool = False
    readonly: bool = False
    model: str = ""
    kind: str = "disk"
    mounts: list[str] = field(default_factory=list)

    @property
    def is_usb(self) -> bool:
        return self.tran == "usb"

    @property
    def label(self) -> str:
        return f"{self.model.strip() or 'unknown model'}, {human(self.size)}"


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


# ---------------------------------------------------------------- discovery

def _mounts(node: dict) -> list[str]:
    found = [m for m in (node.get("mountpoints") or [node.get("mountpoint")]) if m]
    for child in node.get("children") or []:
        found += _mounts(child)
    return found


def parse_lsblk(text: str) -> list[Disk]:
    disks = []
    for node in json.loads(text).get("blockdevices", []):
        path = node.get("path") or "/dev/" + node["name"]
        disks.append(Disk(
            path=path,
            size=int(node.get("size") or 0),
            tran=(node.get("tran") or "").lower(),
            removable=str(node.get("rm")).lower() in ("1", "true"),
            readonly=str(node.get("ro")).lower() in ("1", "true"),
            model=" ".join(filter(None, [(node.get("vendor") or "").strip(),
                                         (node.get("model") or "").strip()])),
            kind=node.get("type") or "disk",
            mounts=_mounts(node)))
    return disks


def list_disks(run: Callable = subprocess.run) -> list[Disk]:
    """Every whole disk the kernel knows about, with what is mounted from it."""
    if shutil.which("lsblk") is None:
        raise UsbError("lsblk not found (install util-linux)")
    last = ""
    for mount_col in ("MOUNTPOINTS", "MOUNTPOINT"):          # older util-linux has no plural
        r = run(["lsblk", "-J", "-b", "-o",
                 f"NAME,PATH,SIZE,TRAN,RM,RO,MODEL,VENDOR,TYPE,{mount_col}"],
                capture_output=True, text=True)
        if r.returncode == 0:
            return [d for d in parse_lsblk(r.stdout) if d.kind == "disk"]
        last = r.stderr.strip()
    raise UsbError(f"lsblk failed: {last}")


def refusal(disk: Disk, need: int = 0, allow_non_usb: bool = False) -> Optional[str]:
    """Why this disk must not be written, or None if it is fine."""
    if disk.readonly:
        return "read-only"
    if disk.mounts:
        return "in use (mounted: " + ", ".join(sorted(set(disk.mounts))) + ")"
    if not disk.is_usb and not allow_non_usb:
        return f"not a USB disk (transport: {disk.tran or 'unknown'}); " \
               "use --allow-non-usb only if you are sure"
    if need and disk.size < need:
        return f"too small ({human(disk.size)}, image needs {human(need)})"
    return None


# ------------------------------------------------------------ image checks

def _read_gpt(f) -> list[tuple[int, int]]:
    """(first_lba, last_lba) of every EFI system partition in a GPT image."""
    f.seek(0)
    mbr = f.read(SECTOR)
    if len(mbr) < SECTOR or mbr[510:512] != b"\x55\xaa":
        raise UsbError("no protective MBR signature: not a disk image")
    f.seek(SECTOR)
    hdr = f.read(92)
    if hdr[:8] != b"EFI PART":
        raise UsbError("no GPT: UEFI cannot boot this (was it built by image/mkimage.sh?)")
    entries_lba = int.from_bytes(hdr[72:80], "little")
    count = int.from_bytes(hdr[80:84], "little")
    size = int.from_bytes(hdr[84:88], "little")
    if not (0 < count <= 4096 and size >= 128):
        raise UsbError("corrupt GPT header")
    f.seek(entries_lba * SECTOR)
    table = f.read(count * size)
    found = []
    for i in range(count):
        e = table[i * size:(i + 1) * size]
        if len(e) >= 48 and any(e[:16]) and uuid.UUID(bytes_le=e[:16]) == ESP_GUID:
            found.append((int.from_bytes(e[32:40], "little"), int.from_bytes(e[40:48], "little")))
    return found


def check_image(path: Path) -> list[str]:
    """Verify an image is laid out to boot from removable media. Returns the
    list of facts it confirmed; raises UsbError describing the first problem."""
    try:
        f = open(path, "rb")
    except OSError as e:
        raise UsbError(f"cannot open image: {e}")
    with f:
        esps = _read_gpt(f)
        if not esps:
            raise UsbError("no EFI system partition (type EF00) in the image")
        first, last = esps[0]
        f.seek(first * SECTOR)
        remaining = (last - first + 1) * SECTOR
        tail = b""
        has_boot = False
        while remaining > 0 and not has_boot:
            block = f.read(min(CHUNK, remaining))
            if not block:
                break
            remaining -= len(block)
            has_boot = BOOT_FILE_ENTRY in tail + block
            tail = block[-len(BOOT_FILE_ENTRY):]
        if not has_boot:
            raise UsbError("the EFI partition has no EFI/BOOT/BOOTX64.EFI: "
                           "firmware will not boot this from removable media")
    return ["GPT with an EFI system partition",
            "fallback loader EFI/BOOT/BOOTX64.EFI present on it (what UEFI boots from a USB stick)"]


# ------------------------------------------------------------------ writing

def _copy(src_path: Path, dst, total: int, progress: Optional[Callable[[str, int, int], None]]) -> None:
    done = 0
    with open(src_path, "rb") as src:
        while True:
            block = src.read(CHUNK)
            if not block:
                break
            dst.write(block)
            done += len(block)
            if progress:
                progress("writing", done, total)
    dst.flush()
    os.fsync(dst.fileno())


def _verify(src_path: Path, dst_path: Path, total: int,
            progress: Optional[Callable[[str, int, int], None]]) -> None:
    fd = os.open(dst_path, os.O_RDONLY)
    try:
        if hasattr(os, "posix_fadvise"):      # read from the device, not from the page cache
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        done = 0
        with open(src_path, "rb") as src, os.fdopen(fd, "rb", closefd=False) as dst:
            while True:
                want = src.read(CHUNK)
                if not want:
                    break
                got = dst.read(len(want))
                if got != want:
                    first = next((i for i in range(min(len(got), len(want))) if got[i] != want[i]),
                                 min(len(got), len(want)))
                    raise UsbError(f"verification FAILED at byte {done + first}: the stick did not "
                                   "store what was written (bad or counterfeit drive?)")
                done += len(want)
                if progress:
                    progress("verifying", done, total)
    finally:
        os.close(fd)


def write_image(image: Path, target: str, *, confirm: Optional[Callable[[Disk], bool]] = None,
                allow_non_usb: bool = False, verify: bool = True,
                disks: Optional[list[Disk]] = None, run: Callable = subprocess.run,
                progress: Optional[Callable[[str, int, int], None]] = None) -> list[str]:
    """Write ``image`` to a USB disk (or to a plain file) and prove it landed."""
    image = Path(image)
    if not image.is_file():
        raise UsbError(f"{image}: no such image (build one with image/mkimage.sh)")
    total = image.stat().st_size
    notes = check_image(image)

    is_device = target.startswith("/dev/")
    if is_device:
        if os.geteuid() != 0:
            raise UsbError("writing a disk needs root: sudo kos usb write ...")
        if not (os.path.exists(target) and stat.S_ISBLK(os.stat(target).st_mode)):
            raise UsbError(f"{target} is not a block device")
        real = os.path.realpath(target)
        disks = list_disks(run) if disks is None else disks
        disk = next((d for d in disks if os.path.realpath(d.path) == real), None)
        if disk is None:
            raise UsbError(f"{target} is not a whole disk (give /dev/sdX, not a partition like /dev/sdX1)")
        why = refusal(disk, total, allow_non_usb)
        if why:
            raise UsbError(f"refusing {target} ({disk.label}): {why}")
        if confirm is not None and not confirm(disk):
            raise UsbError("cancelled; nothing was written")
    else:
        if os.path.isdir(target):
            raise UsbError(f"{target} is a directory")
        disk = None

    mode = "r+b" if os.path.exists(target) else "wb"
    with open(target, mode) as dst:
        _copy(image, dst, total, progress)
    notes.append(f"wrote {human(total)} to {target}")
    if verify:
        _verify(image, Path(target), total, progress)
        notes.append("read it back from the device and it matches the image byte for byte")

    if disk is not None:
        # The image carries its backup GPT at the image's end; on a bigger stick
        # that is mid-disk and UEFI/tools complain. Move it to the real end.
        if shutil.which("sgdisk"):
            r = run(["sgdisk", "--move-second-header", target], capture_output=True, text=True)
            notes.append("moved the backup GPT to the end of the stick" if r.returncode == 0
                         else f"WARNING: could not move the backup GPT ({r.stderr.strip()})")
        else:
            notes.append("note: sgdisk not found; the backup GPT was left where the image put it")
        run(["sync"])
        if shutil.which("blockdev"):
            run(["blockdev", "--rereadpt", target], capture_output=True)
    return notes


# ------------------------------------------------------------------ testing

def qemu_script() -> Path:
    return REPO / "image" / "run-qemu.sh"


def test_boot(image: Path, run: Callable = subprocess.call) -> int:
    """Boot the image in QEMU with the disk attached as a USB mass-storage stick."""
    check_image(Path(image))
    return run([str(qemu_script()), "--usb", str(image)])


# --------------------------------------------------------------------- CLI

def _bar(stage: str, done: int, total: int) -> None:
    if sys.stderr.isatty():
        pct = 100 * done // max(total, 1)
        end = "\n" if done >= total else ""
        sys.stderr.write(f"\r  {stage:<9} {pct:3d}%  {human(done)} / {human(total)}{end}")
        sys.stderr.flush()


def cmd_usb(args, paths=None, *, disks=None, run=subprocess.run, read_line=input,
            out=print) -> int:
    action = args.usb_cmd
    try:
        if action == "list":
            found = list_disks(run) if disks is None else disks
            shown = [d for d in found if args.all or d.is_usb]
            if not shown:
                out("no USB disks found (plug the stick in; use --all to see every disk)")
                return 1
            for d in shown:
                why = refusal(d, allow_non_usb=args.allow_non_usb)
                out(f"{d.path:<14} {d.label:<40} {'USB' if d.is_usb else d.tran or '?':<6} "
                    + ("ok to write" if not why else "REFUSED: " + why))
            return 0
        if action == "check":
            for fact in check_image(Path(args.image)):
                out("ok: " + fact)
            return 0
        if action == "write":
            def confirm(d: Disk) -> bool:
                if args.yes:
                    return True
                out(f"\nThis ERASES everything on {d.path} ({d.label}).")
                return read_line(f"Type the device name to continue ({d.path}): ").strip() == d.path
            for note in write_image(Path(args.image), args.device, confirm=confirm,
                                    allow_non_usb=args.allow_non_usb, verify=not args.no_verify,
                                    disks=disks, run=run, progress=_bar):
                out("ok: " + note)
            out(f"\nDone. Plug {args.device} into the target machine, open its boot menu "
                "(often F12/F10/Esc) and pick the USB device.\n"
                "If the firmware has Secure Boot on, enroll the key the image was signed with first.")
            return 0
        if action == "test":
            return test_boot(Path(args.image))
    except UsbError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 2
