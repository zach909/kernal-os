"""Is everything encrypted? An honest answer, layer by layer - and the hardening KOS can do for itself.

KOS does not write ciphers. It uses what the kernel and the hardware provide, checks that they are switched on, and says so
plainly when they are not:

* **Disk (at rest)**: the root filesystem should sit on dm-crypt/LUKS (the pre-boot environment unlocks it). Checked through
  ``/sys/class/block``: a device-mapper device whose uuid starts with ``CRYPT-`` (directly or beneath LVM).
* **Swap**: anything the kernel pages out lands on disk. Swap must be on an encrypted device, or absent. A swap *file* or
  plain partition is reported as not encrypted. (``zram`` is compressed RAM, never disk.)
* **RAM**: software cannot encrypt main memory. The CPU's memory controller can (AMD SME/SEV, Intel TME/TDX). KOS reports
  whether this CPU can and whether the kernel was asked to; whether the BIOS actually switched it on can only be confirmed
  from the boot log (``dmesg``), which needs root - it says "unknown" rather than guess.
* **Scratch and /tmp**: app scratch lives in RAM-backed tmpfs, so it is exactly as protected as RAM.
* **Leaks**: core dumps off, no hibernation image of RAM written to disk, and KOS's own processes are not dumpable
  (:func:`harden`) with secrets in ``mlock``-ed memory (``kos/secret.py``).
* **Off-site**: backups are sealed with AES-256-GCM before they leave (``kos/vault.py``).

Every function takes the /proc and /sys roots, so tests can feed it a pretend machine.
"""

from __future__ import annotations

import ctypes
import os
import resource
from dataclasses import dataclass
from pathlib import Path

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3


@dataclass
class Item:
    layer: str
    status: str          # ok | no | unknown | partial
    detail: str
    fix: str = ""

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def harden() -> dict:
    """Make this process hard to read from outside: no core dump, not attachable by a debugger of the same user, never
    dumpable. Returns what was achieved. Safe to call more than once."""
    out = {"core_limit": False, "dumpable_off": False}
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        out["core_limit"] = True
    except (ValueError, OSError):
        pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        out["dumpable_off"] = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 and libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        pass
    return out


def _read(path: Path) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def _crypt_below(sysroot: Path, dev: str, depth: int = 0) -> bool:
    """Is block device ``dev`` (e.g. ``dm-0``, ``sda2``) encrypted, itself or through what it sits on?"""
    base = sysroot / "class" / "block" / dev
    if _read(base / "dm" / "uuid").startswith("CRYPT-"):
        return True
    if depth > 6:
        return False
    try:
        below = [p.name for p in (base / "slaves").iterdir()]
    except OSError:
        below = []
    return any(_crypt_below(sysroot, b, depth + 1) for b in below)


def _dev_name(path: str, sysroot: Path) -> str:
    """``/dev/mapper/root`` or ``/dev/dm-0`` or ``/dev/sda2`` -> the kernel name (dm-0, sda2)."""
    name = os.path.basename(path)
    if (sysroot / "class" / "block" / name).exists():
        return name
    try:
        return os.path.basename(os.path.realpath(path))
    except OSError:
        return name


def disk(proc: Path, sysroot: Path) -> Item:
    root_dev = ""
    for line in _read(proc / "mounts").splitlines():
        f = line.split()
        if len(f) > 2 and f[1] == "/" and f[2] not in ("rootfs",):
            root_dev = f[0]
    if not root_dev.startswith("/dev/"):
        return Item("disk (at rest)", "unknown", f"the root filesystem is {root_dev or 'not identifiable'}, not a block device",
                    "a KOS install keeps / on LUKS2: see boot/")
    if _crypt_below(sysroot, _dev_name(root_dev, sysroot)):
        return Item("disk (at rest)", "ok", f"{root_dev} is on dm-crypt (LUKS)")
    return Item("disk (at rest)", "no", f"{root_dev} is not on an encrypted device",
                "reinstall with LUKS2 on the root (cryptsetup luksFormat), or encrypt it before use")


def swap(proc: Path, sysroot: Path) -> Item:
    rows = [l.split() for l in _read(proc / "swaps").splitlines()[1:] if l.strip()]
    if not rows:
        return Item("swap", "ok", "no swap: nothing is paged out to disk")
    bad, soft = [], []
    for r in rows:
        name, kind = r[0], r[1] if len(r) > 1 else ""
        dev = _dev_name(name, sysroot)
        if "zram" in name:
            soft.append(name)
        elif kind == "partition" and _crypt_below(sysroot, dev):
            continue
        else:
            bad.append(f"{name} ({kind})")
    if bad:
        return Item("swap", "no", "swap that is not on an encrypted device: " + ", ".join(bad),
                    "swapoff it, or put it on dm-crypt with a random key (crypttab: swap,cipher=aes-xts-plain64,size=512)")
    if soft:
        return Item("swap", "partial", "zram only (compressed RAM, never written to disk): as protected as RAM")
    return Item("swap", "ok", "every swap area is on an encrypted device")


def ram(proc: Path) -> Item:
    flags = set()
    for line in _read(proc / "cpuinfo").splitlines():
        if line.startswith("flags"):
            flags = set(line.split(":", 1)[1].split())
            break
    cmd = _read(proc / "cmdline")
    feats = sorted(f for f in ("sme", "sev", "sev_es", "sev_snp", "tme", "tdx_guest", "tme_ext") if f in flags)
    asked = "mem_encrypt=on" in cmd.split()
    if not feats:
        return Item("RAM", "no", "this CPU shows no memory-encryption feature (AMD SME/SEV, Intel TME/TDX): main memory is "
                    "stored in the clear", "software cannot encrypt RAM; use a CPU with SME/TME, or keep secrets short-lived "
                    "(KOS wipes them and locks them out of swap)")
    detail = f"the CPU reports {', '.join(feats)}"
    if "tdx_guest" in feats or "sev" in feats and "sev_es" in feats and _read(proc / "cpuinfo").find("hypervisor") >= 0:
        return Item("RAM", "ok", detail + " (this machine is an encrypted guest)")
    if asked:
        return Item("RAM", "unknown", detail + "; the kernel was asked (mem_encrypt=on). Whether the BIOS turned it on shows "
                    "in the boot log: dmesg | grep -i 'memory encryption'", "check as root")
    return Item("RAM", "unknown", detail + "; not asked for on the kernel command line",
                "AMD: enable SME in the BIOS and boot with mem_encrypt=on; Intel: enable TME in the BIOS")


def scratch(proc: Path) -> Item:
    tmpfs = sorted({f[1] for f in (l.split() for l in _read(proc / "mounts").splitlines()) if len(f) > 2 and f[2] == "tmpfs"
                    and f[1] in ("/tmp", "/dev/shm")})
    if tmpfs:
        return Item("scratch and /tmp", "partial", f"{', '.join(tmpfs)} live in RAM only, so they are exactly as protected as RAM")
    return Item("scratch and /tmp", "no", "/tmp is on disk", "mount /tmp as tmpfs (and rely on RAM encryption), or on dm-crypt")


def leaks(proc: Path, sysroot: Path) -> list[Item]:
    out = []
    core = _read(proc / "sys" / "kernel" / "core_pattern").strip()
    dumpable = _read(proc / "sys" / "fs" / "suid_dumpable").strip()
    piped = core.startswith("|")
    out.append(Item("core dumps", "ok" if dumpable == "0" else "no",
                    f"core_pattern={core or '?'}, suid_dumpable={dumpable or '?'}; apps and KOS processes run with a core limit of 0"
                    + (" (a handler is piped in: it only ever sees processes that dump)" if piped else ""),
                    "sysctl fs.suid_dumpable=0 and kernel.core_pattern=|/bin/false"))
    cmd = _read(proc / "cmdline").split()
    resume = any(c.startswith("resume=") for c in cmd)
    can_hibernate = "disk" in _read(sysroot / "power" / "state").split()
    if resume and can_hibernate:
        out.append(Item("hibernation", "no", "hibernation can write all of RAM to swap", "remove resume= from the kernel line"))
    else:
        out.append(Item("hibernation", "ok", "no hibernation image of RAM is written to disk"))
    return out


def check(proc: str = "/proc", sysroot: str = "/sys") -> list[Item]:
    p, s = Path(proc), Path(sysroot)
    return [disk(p, s), swap(p, s), ram(p), scratch(p), *leaks(p, s),
            _secrets(), _offsite()]


def _secrets() -> Item:
    try:
        libc = ctypes.CDLL(None)
        off = libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        off = False
    if off:
        return Item("secrets in memory", "ok", "keys live in mlock-ed buffers, are wiped after use, and this process is not "
                    "dumpable or attachable")
    return Item("secrets in memory", "partial", "keys live in mlock-ed buffers and are wiped after use, but this process is "
                "still dumpable", "run it through the kos command (it hardens itself at start)")


def _offsite() -> Item:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return Item("off-site backups", "no", "the 'cryptography' package is missing, so KOS will refuse to push (nothing leaves "
                    "unencrypted)", "install python3-cryptography")
    return Item("off-site backups", "ok", "sealed with AES-256-GCM (key from your password) before they leave this machine")
