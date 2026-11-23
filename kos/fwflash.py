"""Firmware flasher: replace a chip's firmware with a KOS firmware image the owner signed.

``kos/firmware.py`` finds the chips that run their own firmware and refuses to boot
under them. This module is the other half: it can write firmware the owner supplies.

What it is, and what it is not
------------------------------
* **It does not contain firmware.** There is no "KOS firmware" in this repository. The
  owner builds the images (coreboot, LinuxBoot, me_cleaner'd SPI images, ...) and signs a
  *bundle* of them with their own key. This module only checks the bundle and writes it.
* **A bundle** is a folder: ``manifest.json``, ``manifest.sig`` (Ed25519, 64 bytes, over
  the exact bytes of the manifest) and the image files. The public key is the owner's
  trust anchor, ``etc/kos/firmware.pub`` (32 raw bytes). No key, no flashing. The key
  that signs never needs to be on this machine.
* **Each image names the hardware it is for** (``match``): a PCI id, or the board's DMI
  vendor and name. No wildcards, nothing implied. An image that does not say is refused,
  and an image for a board this is not is never written.
* **Every write is its own action**: ``firmware.flash`` with the chip as target, so the
  password is typed per chip, in the OS's own prompt, after a typed ``FLASH <id>``.
  Nothing is flashed silently, in the background, or without a terminal.
* **Dry run by default.** Without ``apply`` nothing is read from or written to any chip.
* **Before a write**: the machine is on mains power; the old firmware is read twice and
  must come back identical (an unstable read means the wiring or the tool is wrong), and
  is kept in ``<state>/firmware-backup/``; the image is staged in that folder and hashed
  again, so what is written is what was signed.
* **After a write**: the chip is read back and compared with the signed hash. On a
  mismatch the backup is written back and checked the same way. If that fails too the
  result says so, in capitals, and the backup file path is what you need.

What is real: only the system flash (``spi-flash``, the BIOS/UEFI chip) has a writer, and
it is ``flashrom`` run as a subprocess. An Intel ME or AMD PSP lives *inside* that chip, so
it is changed by flashing a whole-chip image that already carries the changed region.
Every other chip class the firmware scan lists (BMC, embedded controller, Thunderbolt,
USB-C, NIC, GPU, NVMe, wireless) has a writer slot that **refuses and says why**: there is
no standard, safe way to rewrite those from a running OS, and guessing would brick them.
Add a real writer by registering one for that kind; the rest of the checks apply to it.

**Not tested on real hardware.** The tests use a fake sysfs, a fake ``flashrom`` and a
fake chip. A real write can brick a machine; keep a hardware programmer and the backup.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from . import firmware
from .auth import AUDIT_KEY_LABEL
from .paths import Paths

ACTION = "firmware.flash"
KINDS = ("spi-flash", "intel-me", "amd-psp", "bmc-ipmi", "embedded-controller", "thunderbolt",
         "typec-port", "network", "display", "nvme", "wireless")
MATCH_KEYS = ("pci", "board_vendor", "board_name", "sys_vendor", "product_name")
DMI_KEYS = ("board_vendor", "board_name", "sys_vendor", "product_name")
MAX_MANIFEST = 1024 * 1024
MAX_IMAGES = 64
MAX_IMAGE = 256 * 1024 * 1024
CHUNK = 1024 * 1024
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PCI_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{4}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MANIFEST, SIGNATURE, PUBKEY = "manifest.json", "manifest.sig", "firmware.pub"


class FlashError(Exception):
    pass


class BundleError(FlashError):
    pass


def _clean(s: object, cap: int = 200) -> str:
    """Anything a tool or a file says is data: printable ASCII only, capped."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in str(s))[:cap]


def sha256_file(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def _regular(path: Path, what: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError:
        raise BundleError(f"{what} is missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise BundleError(f"{what} is not a plain file (links and devices are refused)")
    return st


# --- the bundle ----------------------------------------------------------------------

@dataclass(frozen=True)
class Image:
    id: str
    kind: str
    file: str
    sha256: str
    size: int
    match: tuple[tuple[str, str], ...]
    path: Path

    def match_dict(self) -> dict:
        return dict(self.match)


@dataclass(frozen=True)
class Bundle:
    name: str
    directory: Path
    images: tuple[Image, ...]


def _no_float(token: str):
    raise BundleError("the manifest may only contain whole numbers")


def _parse_image(raw: object, directory: Path, seen: set) -> Image:
    if not isinstance(raw, dict):
        raise BundleError("every image must be an object")
    extra = set(raw) - {"id", "kind", "file", "sha256", "size", "match"}
    if extra:
        raise BundleError(f"unknown image field {_clean(sorted(extra)[0], 40)!r}")
    iid, kind, fname = raw.get("id"), raw.get("kind"), raw.get("file")
    if not isinstance(iid, str) or not ID_RE.match(iid) or iid in seen:
        raise BundleError("image id must be unique lowercase letters, digits and '-'")
    seen.add(iid)
    if kind not in KINDS:
        raise BundleError(f"image {iid}: kind must be one of {', '.join(KINDS)}")
    if not isinstance(fname, str) or not FILE_RE.match(fname) or fname in (MANIFEST, SIGNATURE):
        raise BundleError(f"image {iid}: bad file name")
    sha, size = raw.get("sha256"), raw.get("size")
    if not isinstance(sha, str) or not SHA_RE.match(sha):
        raise BundleError(f"image {iid}: sha256 must be 64 lowercase hex characters")
    if type(size) is not int or not 0 < size <= MAX_IMAGE:
        raise BundleError(f"image {iid}: size must be a whole number of bytes, at most {MAX_IMAGE}")
    m = raw.get("match")
    if not isinstance(m, dict) or not m or set(m) - set(MATCH_KEYS):
        raise BundleError(f"image {iid}: 'match' must name the hardware using only {', '.join(MATCH_KEYS)}")
    for k, v in m.items():
        if not isinstance(v, str) or not v or len(v) > 64 or v != _clean(v, 64) or "*" in v:
            raise BundleError(f"image {iid}: match {k} must be plain text with no wildcard")
    if "pci" in m and not PCI_RE.match(m["pci"]):
        raise BundleError(f"image {iid}: pci must look like 8086:1234 (lowercase hex)")
    if "pci" not in m and not ("board_vendor" in m and "board_name" in m):
        raise BundleError(f"image {iid}: with no pci id, match must give board_vendor and board_name")
    if kind == "spi-flash" and not ("board_vendor" in m and "board_name" in m):
        raise BundleError(f"image {iid}: a system-flash image must give board_vendor and board_name")
    path = directory / fname
    st = _regular(path, f"image file {fname}")
    if st.st_size != size:
        raise BundleError(f"image {iid}: file is {st.st_size} bytes, the manifest says {size}")
    if sha256_file(path)[0] != sha:
        raise BundleError(f"image {iid}: file does not match the signed hash")
    return Image(iid, kind, fname, sha, size, tuple(sorted(m.items())), path)


def load_pubkey(path: Path) -> Ed25519PublicKey:
    try:
        _regular(path, "the owner's firmware key")
        raw = path.read_bytes()
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw)
    except BundleError:
        raise
    except (OSError, ValueError):
        raise BundleError(f"{path} is not a 32-byte Ed25519 public key") from None


def load_bundle(directory: Path, pubkey_path: Path) -> Bundle:
    """Verify the signature first, then trust nothing else in the manifest until it is checked."""
    directory = Path(directory)
    pub = load_pubkey(pubkey_path)          # no key installed -> nothing can ever be flashed
    st = _regular(directory / MANIFEST, "manifest.json")
    if st.st_size > MAX_MANIFEST:
        raise BundleError("manifest is too large")
    _regular(directory / SIGNATURE, "manifest.sig")
    data, sig = (directory / MANIFEST).read_bytes(), (directory / SIGNATURE).read_bytes()
    try:
        if len(sig) != 64:
            raise InvalidSignature
        pub.verify(sig, data)
    except InvalidSignature:
        raise BundleError("the manifest is not signed by your firmware key") from None
    try:
        doc = json.loads(data.decode("utf-8"), parse_float=_no_float, parse_constant=_no_float)
    except (ValueError, UnicodeDecodeError):
        raise BundleError("manifest.json is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("format") != 1 or set(doc) - {"format", "name", "images"}:
        raise BundleError("manifest must be {format: 1, name, images}")
    name, imgs = doc.get("name"), doc.get("images")
    if not isinstance(name, str) or not name or name != _clean(name, 64):
        raise BundleError("manifest needs a plain-text name")
    if not isinstance(imgs, list) or not 0 < len(imgs) <= MAX_IMAGES:
        raise BundleError(f"manifest needs 1 to {MAX_IMAGES} images")
    seen: set = set()
    return Bundle(name, directory, tuple(_parse_image(i, directory, seen) for i in imgs))


# --- the owner's side: make a key, sign a bundle (run offline, not on the machine) ------

def keygen(out: Path) -> tuple[Path, Path]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    priv, pub = out / "firmware-sign.key", out / PUBKEY
    for p in (priv, pub):
        if p.exists():
            raise FlashError(f"{p} exists; refusing to overwrite a key")
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return priv, pub


def sign_bundle(directory: Path, private_key: Path) -> Bundle:
    """Fill in each image's sha256 and size from its file, write manifest.json and sign it."""
    directory = Path(directory)
    raw = json.loads((directory / MANIFEST).read_text(), parse_float=_no_float, parse_constant=_no_float)
    for img in raw.get("images", []):
        p = directory / str(img.get("file", ""))
        if FILE_RE.match(str(img.get("file", ""))):
            _regular(p, f"image file {img['file']}")
            img["sha256"], img["size"] = sha256_file(p)
    data = json.dumps(raw, indent=2, sort_keys=True).encode() + b"\n"
    (directory / MANIFEST).write_bytes(data)
    key = Ed25519PrivateKey.from_private_bytes(Path(private_key).read_bytes())
    (directory / SIGNATURE).write_bytes(key.sign(data))
    pub = directory / ".verify.pub"
    pub.write_bytes(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    try:
        return load_bundle(directory, pub)
    finally:
        pub.unlink()


# --- the machine ----------------------------------------------------------------------

@dataclass
class Chip:
    kind: str
    name: str
    where: str = ""
    pci_id: str = ""


def read_dmi(root: Path) -> dict:
    out = {}
    for k in DMI_KEYS:
        try:
            out[k] = _clean((Path(root) / "sys/class/dmi/id" / k).read_text().strip(), 64)
        except OSError:
            out[k] = ""
    return out


def chips(root: Path) -> list[Chip]:
    """Every chip the firmware scan sees, plus the system flash on a physical machine."""
    root = Path(root)
    out = []
    if not firmware._in_vm(root):
        dmi = read_dmi(root)
        if dmi["board_vendor"] and dmi["board_name"]:
            out.append(Chip("spi-flash", "System flash (BIOS/UEFI)", "sys/class/dmi/id"))
    for f in firmware.probe(root, policy="warn").findings:
        if f.kind in KINDS and f.kind != "spi-flash":
            out.append(Chip(f.kind, f.name, f.where, f.pci_id))
    return out


def image_refusal(img: Image, chip: Chip, dmi: dict) -> Optional[str]:
    """Why this image may not be written to this chip, or None. Every key must match exactly."""
    if img.kind != chip.kind:
        return "wrong kind of chip"
    for k, v in img.match:
        have = chip.pci_id if k == "pci" else dmi.get(k, "")
        if have != v:
            return f"{k} is {have or 'unknown'}, the image is for {v}"
    return None


def on_mains(root: Path) -> Optional[str]:
    """A refusal if the machine runs from its battery. A write cut short by a flat battery bricks it."""
    base = Path(root) / "sys/class/power_supply"
    try:
        supplies = sorted(base.iterdir())
    except OSError:
        return None                                   # no power information: a desktop or a VM
    mains = battery = False
    for s in supplies:
        try:
            kind = (s / "type").read_text().strip().lower()
            if kind == "mains" and (s / "online").read_text().strip() == "1":
                mains = True
            if kind == "battery":
                battery = True
        except OSError:
            continue
    return "plug in the charger: a write cut short by a flat battery bricks the machine" \
        if battery and not mains else None


# --- writers --------------------------------------------------------------------------

class Writer:
    """One per chip kind. ``refusal`` says why this machine cannot write; read/write do it."""
    kind = ""

    def refusal(self) -> Optional[str]:
        return None

    def read(self, chip: Chip, dest: Path) -> None:
        raise FlashError("not implemented")

    def write(self, chip: Chip, image: Path) -> None:
        raise FlashError("not implemented")


class FlashromWriter(Writer):
    """The system flash, whole chip, through flashrom's internal programmer."""
    kind = "spi-flash"

    def __init__(self, run: Callable = subprocess.run, program: str = "flashrom"):
        self.run, self.program = run, program

    def refusal(self) -> Optional[str]:
        return None if shutil.which(self.program) else "flashrom is not installed"

    def _go(self, *args: str) -> None:
        try:
            r = self.run([self.program, "-p", "internal", *args], capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise FlashError(f"flashrom did not run: {_clean(e)}") from None
        if r.returncode != 0:
            raise FlashError(f"flashrom failed ({r.returncode}): {_clean(r.stderr or r.stdout, 300)}")

    def read(self, chip: Chip, dest: Path) -> None:
        self._go("-r", str(dest))

    def write(self, chip: Chip, image: Path) -> None:
        self._go("-w", str(image))


class RefusingWriter(Writer):
    def __init__(self, kind: str, why: str):
        self.kind, self.why = kind, why

    def refusal(self) -> Optional[str]:
        return self.why


_INSIDE_SPI = "lives inside the system flash: change it by flashing a whole-chip spi-flash image that carries it"
_NO_WRITER = "has no standard way to be rewritten from a running OS; no writer is registered for it"
REFUSALS = {
    "intel-me": f"the Intel ME {_INSIDE_SPI}",
    "amd-psp": f"the AMD PSP {_INSIDE_SPI}",
    "bmc-ipmi": "a BMC has its own flash and update path (OpenBMC / vendor tool); " + _NO_WRITER,
    "embedded-controller": "an embedded controller " + _NO_WRITER,
    "thunderbolt": "a Thunderbolt/USB4 controller " + _NO_WRITER,
    "typec-port": "a USB-C port controller " + _NO_WRITER,
    "network": "a network controller " + _NO_WRITER,
    "display": "a GPU " + _NO_WRITER,
    "nvme": "an NVMe controller " + _NO_WRITER,
    "wireless": "a wireless controller " + _NO_WRITER,
}


def default_writers(run: Callable = subprocess.run) -> dict[str, Writer]:
    w: dict[str, Writer] = {k: RefusingWriter(k, v) for k, v in REFUSALS.items()}
    w["spi-flash"] = FlashromWriter(run)
    return w


# --- plan and flash -------------------------------------------------------------------

@dataclass
class PlanItem:
    image: Image
    chip: Chip
    refusal: str = ""          # empty = ready

    @property
    def target(self) -> str:
        return f"{self.chip.kind}:{self.image.id}" + (f"@{self.chip.where}" if self.chip.where else "")


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)
    absent: list[Image] = field(default_factory=list)       # an image for hardware this machine lacks
    uncovered: list[Chip] = field(default_factory=list)     # a chip no image is for


def make_plan(root: Path, bundle: Bundle, writers: Optional[dict] = None, *,
              all_chips: Optional[list] = None) -> Plan:
    root = Path(root)
    writers = writers if writers is not None else default_writers()
    dmi = read_dmi(root)
    cs = all_chips if all_chips is not None else chips(root)
    plan, covered = Plan(), set()
    power = on_mains(root)
    for img in bundle.images:
        hits = [c for c in cs if c.kind == img.kind]
        if not hits:
            plan.absent.append(img)
            continue
        for c in hits:
            why = image_refusal(img, c, dmi)
            if why is None:
                covered.add(id(c))
                w = writers.get(c.kind)
                why = (w.refusal() if w else "no writer for this kind of chip") or power or ""
            plan.items.append(PlanItem(img, c, why or ""))
    plan.uncovered = [c for c in cs if id(c) not in covered]
    return plan


@dataclass
class Result:
    target: str
    status: str
    detail: str = ""
    backup: str = ""


WOULD, DONE, DECLINED = "would-flash", "flashed", "declined"
REFUSED, RESTORED, LOST = "refused", "failed-restored", "FAILED-NOT-RESTORED"


def _stage(src: Path, dst: Path, sha: str) -> None:
    """Copy the image somewhere only we can write and hash it as it goes: what is written is what was signed."""
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    h = hashlib.sha256()
    with os.fdopen(fd, "wb") as out, open(src, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            out.write(b)
    if h.hexdigest() != sha:
        dst.unlink()
        raise FlashError("the image changed after it was verified; nothing was written")


def _private(path: Path) -> Path:
    """Create an empty file only we can read before a tool writes into it: a flash dump can hold
    vendor keys and NVRAM variables, so it is never world-readable, not even for a moment."""
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    return path


def _read_into(w: Writer, chip: Chip, dest: Path) -> None:
    w.read(chip, _private(dest))


def _read_twice(w: Writer, chip: Chip, dest: Path) -> str:
    second = dest.with_suffix(".check")
    try:
        _read_into(w, chip, dest)
        _read_into(w, chip, second)
        a, b = sha256_file(dest), sha256_file(second)
    finally:
        if second.exists():
            second.unlink()
    if a != b:
        raise FlashError("the chip read back differently twice; the backup cannot be trusted, nothing was written")
    return a[0]


def flash(paths: Paths, bundle: Bundle, authority, *, apply: bool = False,
          typed: Optional[Callable[[str], str]] = None, writers: Optional[dict] = None,
          only: Optional[set] = None, root: Optional[Path] = None,
          chip_list: Optional[list] = None, now: Callable[[], float] = time.time) -> list[Result]:
    """Walk the plan. Without ``apply`` nothing is read from or written to a chip."""
    root = Path(root) if root is not None else paths.root
    writers = writers if writers is not None else default_writers()
    plan = make_plan(root, bundle, writers, all_chips=chip_list)
    results = []
    for it in plan.items:
        if only is not None and it.image.id not in only:
            continue
        if it.refusal:
            if apply:
                authority.audit.record(ACTION, it.target, "refused:" + _clean(it.refusal, 80))
            results.append(Result(it.target, REFUSED, it.refusal))
            continue
        if not apply:
            results.append(Result(it.target, WOULD, f"would write {it.image.size} bytes ({it.image.file})"))
            continue
        results.append(_flash_one(paths, authority, it, writers[it.chip.kind], typed, now))
    return results


def _flash_one(paths: Paths, authority, it: PlanItem, w: Writer, typed, now) -> Result:
    phrase = f"FLASH {it.image.id}"
    if typed is None or typed(f"This rewrites the firmware of {it.chip.name}. Type {phrase} to go on: ").strip() != phrase:
        authority.audit.record(ACTION, it.target, "declined")
        return Result(it.target, DECLINED, "the confirmation was not typed")
    grant = authority.authorize(ACTION, it.target)          # raises if the password is wrong or cancelled
    try:
        grant.check(ACTION, it.target)
        key = grant.key(AUDIT_KEY_LABEL)
        keep = paths.state / "firmware-backup"
        keep.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(keep, 0o700)
        stamp = f"{int(now())}-{it.image.id}"
        backup, staged = keep / f"{stamp}.backup", keep / f"{stamp}.image"
        try:
            _stage(it.image.path, staged, it.image.sha256)
            old = _read_twice(w, it.chip, backup)
            if sha256_file(backup)[1] != it.image.size:
                raise FlashError(f"the chip holds {sha256_file(backup)[1]} bytes, the image is {it.image.size}: "
                                 "it is not for this chip; nothing was written")
        except (FlashError, OSError) as e:        # nothing has been written yet
            authority.audit.record(ACTION, it.target, "refused:" + _clean(e, 80), key=key)
            return Result(it.target, REFUSED, _clean(e, 300), str(backup) if backup.exists() else "")
        authority.audit.record(ACTION, it.target, "flash-started", key=key)
        try:
            w.write(it.chip, staged)
            after = keep / f"{stamp}.after"
            _read_into(w, it.chip, after)
            ok = sha256_file(after)[0] == it.image.sha256
            after.unlink()
            if ok:
                authority.audit.record(ACTION, it.target, "flashed", key=key)
                try:
                    from .norestart import note_reboot_needed        # a new firmware image loads only at boot
                    note_reboot_needed(paths, f"the firmware of {it.target} was rewritten")
                except OSError:
                    pass                                             # a missing note must not hide a finished write
                return Result(it.target, DONE, "written and read back identical; reboot to use it", str(backup))
            problem = "the chip does not hold the signed image after the write"
        except (FlashError, OSError) as e:        # from here the chip may be half-written: always roll back
            problem = _clean(e, 200)
        # the write failed or did not verify: put the old firmware back and check that too
        try:
            w.write(it.chip, backup)
            back = keep / f"{stamp}.restored"
            _read_into(w, it.chip, back)
            restored = sha256_file(back)[0] == old
            back.unlink()
        except (FlashError, OSError):
            restored = False
        out = RESTORED if restored else LOST
        authority.audit.record(ACTION, it.target, "flash-failed-restored" if restored else "flash-failed-NOT-RESTORED", key=key)
        return Result(it.target, out, problem + ("; the old firmware is back" if restored else
                      "; THE OLD FIRMWARE COULD NOT BE WRITTEN BACK - do not reboot; use the backup with a programmer"),
                      str(backup))
    finally:
        grant.close()


# --- command line: python3 -m kos.fwflash ----------------------------------------------

def _print_plan(plan: Plan) -> None:
    for it in plan.items:
        print(f"  {it.target}: " + (f"REFUSED - {it.refusal}" if it.refusal else "ready"))
    for img in plan.absent:
        print(f"  {img.kind}:{img.id}: no such chip on this machine (not written)")
    for c in plan.uncovered:
        print(f"  {c.kind} ({c.name}): no image in this bundle; its firmware stays as it is")


def main(argv: Optional[list] = None, paths: Optional[Paths] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="kos.fwflash", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen", help="make the signing key pair (run offline; keep the .key off this machine)")
    s.add_argument("out")
    s = sub.add_parser("sign", help="fill in hashes and sign a bundle folder")
    s.add_argument("bundle"), s.add_argument("--key", required=True)
    for name, h in (("plan", "check a bundle and say what would be written (no password, writes nothing)"),
                    ("flash", "write the bundle: dry run unless --apply")):
        s = sub.add_parser(name, help=h)
        s.add_argument("bundle")
        s.add_argument("--only", action="append", help="flash only this image id (repeatable)")
        if name == "flash":
            s.add_argument("--apply", action="store_true", help="really write (password and a typed phrase per chip)")
    a = ap.parse_args(argv)
    paths = paths or Paths.from_env()
    try:
        if a.cmd == "keygen":
            priv, pub = keygen(Path(a.out))
            print(f"private key {priv} (keep it off this machine)\npublic key  {pub} -> install as {paths.etc / PUBKEY}")
            return 0
        if a.cmd == "sign":
            b = sign_bundle(Path(a.bundle), Path(a.key))
            print(f"signed {b.name}: {len(b.images)} image(s)")
            return 0
        bundle = load_bundle(Path(a.bundle), paths.etc / PUBKEY)
        print(f"bundle {bundle.name!r}: signature and hashes verified, {len(bundle.images)} image(s)")
        apply = a.cmd == "flash" and a.apply
        if a.cmd == "plan" or not apply:
            _print_plan(make_plan(paths.root, bundle))
            print("dry run: nothing was written." if a.cmd == "flash" else "")
            return 0
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise FlashError("flashing needs a terminal: there is no unattended mode")
        from .auth import Authority
        from .prompt import TTYPrompter
        prompter = TTYPrompter()
        try:
            results = flash(paths, bundle, Authority(paths, prompter), apply=True, typed=input,
                            only=set(a.only) if a.only else None)
        finally:
            prompter.close()
        for r in results:
            print(f"  {r.target}: {r.status.upper()} - {r.detail}" + (f"\n    backup: {r.backup}" if r.backup else ""))
        return 0 if results and all(r.status == DONE for r in results) else 1
    except FlashError as e:
        print(f"refused: {_clean(e, 300)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
