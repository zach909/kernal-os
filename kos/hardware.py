"""The hardware map: every device the kernel can see, and every connection between them.

``kos hardware scan`` walks the kernel's device tree (read-only sysfs) and writes what it finds
to a folder inside the permission store:

    <state>/permissions/hardware/devices.json   one record per device
    <state>/permissions/hardware/links.json     one record per connection between two devices
    <state>/permissions/hardware/scan.json      when, what could be read, what could not, checksums

Each record has a ``resource`` name (``hw:<device>``, ``hwlink:<kind>:<from>><to>``) in the same
naming style the permission store already uses (``space:NAME``). Nobody holds a grant to any of
them, so by the "blocked by default" rule every device and connection starts closed to every app.
Nothing enforces those names yet: no app-facing command reads the map and no grant is checked
against it. That is a gap, listed in the README.

What a "connection" is here, and what it is not
-----------------------------------------------
No operating system can see solder joints, PCB traces or individual pins. The kernel only knows
what a driver or the firmware tells it. So the map holds the *logical* wiring:

* ``bus``: a device and the bus, hub, controller or port it hangs off (a PCIe device on its root
  port, a USB stick on its hub, a Type-C partner on its port). PCIe links also carry their
  negotiated speed and width, and USB devices their port path.
* ``dependency``: device A needs device B to work (the kernel's own supplier/consumer links:
  a clock, a regulator, a power domain, an interrupt controller).
* ``devicetree-endpoint``: on boards that describe their wiring in a device tree (most ARM
  boards), the two ends of a declared port-to-port connection (a camera sensor to its receiver,
  a display controller to its HDMI port).

Not in the map, and not knowable from software:

* Solder joints, PCB traces, pin-level wiring, and anything the firmware does not describe.
* What is plugged into the far end of a port. A network interface's ``carrier`` says a cable is
  live, not what is at the other end.
* GPIO *lines*: the kernel exposes the number of lines on a chip (``ngpio``), but naming each
  line needs a device-file ioctl, and the OS opens no device without the password. Only the
  count is recorded.
* Hidden or absent devices. A BIOS can hide a device from the OS; the map cannot say so.

Privacy: serial numbers, MAC addresses and unique ids are never read. Only a fixed list of
attributes is, each cut short and stripped of control characters, because a USB device chooses
its own product string and the map is shown in a terminal.

Only the OS reads this. The scan reads sysfs files; it opens nothing under ``/dev``.

The folder is not tamper-proof: ``scan.json`` holds a checksum of the other two files, which
catches a half-written or hand-edited map, not an attacker who can write the whole folder.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .paths import Paths, atomic_write

DEVICE_ATTRS = ("vendor", "device", "class", "subsystem_vendor", "subsystem_device", "revision",
                "modalias", "name", "label", "manufacturer", "product", "idVendor", "idProduct",
                "bDeviceClass", "removable", "ngpio", "base", "power_state", "carrier",
                "operstate", "speed", "duplex", "type")
LINK_ATTRS = ("current_link_speed", "current_link_width", "max_link_speed", "max_link_width",
              "devpath", "busnum", "devnum")
SKIP_DIRS = frozenset({"power", "msi_irqs", "iommu", "firmware_node", "subsystem", "driver"})

MAX_DEVICES = 20000
MAX_DIRS = 200000
MAX_DEPTH = 40
MAX_VALUE = 96
READ_BYTES = 256

NOT_VISIBLE = (
    "solder joints, PCB traces and pin-level wiring (no kernel interface exposes them)",
    "what is plugged into the far end of a port (a live carrier is not an identity)",
    "individual GPIO lines (only the count per chip; naming a line needs a device-file ioctl)",
    "devices the firmware hides from the OS",
    "serial numbers, MAC addresses and unique ids (never read)",
)


class HardwareError(Exception):
    pass


@dataclass
class Map:
    devices: list = field(default_factory=list)
    links: list = field(default_factory=list)
    notes: dict = field(default_factory=dict)


def clean(raw, limit: int = MAX_VALUE) -> str:
    """Hostile-input rule for sysfs strings: a device picks its own name. Control characters,
    bidi/format characters and anything non-printable become '?'; the length is capped."""
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    s = s.strip()
    return "".join(c if c.isprintable() else "?" for c in s)[:limit]


def _attr(p: Path, notes: Optional[dict] = None) -> Optional[str]:
    """Read one small sysfs attribute. Never follows a symlink, never blocks, never reads more
    than READ_BYTES. None means missing; something that exists but cannot be read is counted."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        # A symlink where an attribute is expected is not an attribute and is never followed.
        # Class devices (net, block, tty) have a 'device' symlink to their parent, so it is normal.
        if notes is not None and e.errno != errno.ELOOP:
            notes["unreadable"] += 1
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a plain file")
        return clean(os.read(fd, READ_BYTES))
    except OSError:
        if notes is not None:
            notes["unreadable"] += 1
        return None
    finally:
        os.close(fd)


def _link_name(p: Path) -> Optional[str]:
    try:
        return clean(os.path.basename(os.readlink(p))) or None
    except OSError:
        return None


def _is_device(p: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(p.joinpath("uevent")).st_mode)
    except OSError:
        return False


def _resolve(link: Path, devroot: Path) -> Optional[str]:
    """Which device a symlink inside the device tree points at, as an id, or None if it points
    anywhere else. The link is read, never followed."""
    try:
        target = os.readlink(link)
    except OSError:
        return None
    full = os.path.normpath(os.path.join(os.path.dirname(link), target))
    prefix = str(devroot) + os.sep
    if not full.startswith(prefix):
        return None
    return full[len(prefix):]


def _device(rel: str, path: Path, parent: Optional[str], notes: dict) -> tuple[dict, dict]:
    attrs = {n: v for n in DEVICE_ATTRS if (v := _attr(path.joinpath(n), notes)) is not None}
    link_attrs = {n: v for n in LINK_ATTRS if (v := _attr(path.joinpath(n), notes)) is not None}
    dev = {"id": rel, "resource": "hw:" + rel, "name": clean(os.path.basename(rel)),
           "subsystem": _link_name(path.joinpath("subsystem")), "driver": _link_name(path.joinpath("driver")),
           "parent": parent, "attrs": attrs}
    return dev, link_attrs


def _walk(devroot: Path, notes: dict, max_devices: int, max_dirs: int) -> tuple[dict, list]:
    devices: dict = {}
    links: list = []
    dirs = 0
    stack = [(devroot, None, 0)]
    while stack:
        path, owner, depth = stack.pop()
        dirs += 1
        if dirs > max_dirs:
            notes["truncated"].append("directories")
            break
        here = owner
        if path != devroot and _is_device(path):
            if len(devices) >= max_devices:
                notes["truncated"].append("devices")
                break
            rel = os.path.relpath(path, devroot)
            dev, link_attrs = _device(rel, path, owner, notes)
            devices[rel] = dev
            here = rel
            if owner is not None:
                links.append({"kind": "bus", "from": rel, "to": owner, "attrs": link_attrs})
        if depth >= MAX_DEPTH:
            notes["truncated"].append("depth")
            continue
        try:
            with os.scandir(path) as it:
                kids = sorted(e.name for e in it if e.is_dir(follow_symlinks=False))
        except OSError:
            notes["unreadable"] += 1
            continue
        for name in reversed(kids):
            if name in SKIP_DIRS:
                continue
            if depth == 0 and name == "virtual":
                notes["virtual_skipped"] = True
                continue
            stack.append((path.joinpath(name), here, depth + 1))
    return devices, links


def _dependencies(devroot: Path, devices: dict, notes: dict) -> list:
    """The kernel's supplier/consumer links: the consumer needs the supplier to work."""
    out = []
    base = devroot.joinpath("virtual", "devlink")
    try:
        with os.scandir(base) as it:
            names = sorted(e.name for e in it if e.is_dir(follow_symlinks=False))
    except OSError:
        return out
    notes["sources"]["devlink"] = True
    for name in names:
        a = _resolve(base.joinpath(name, "consumer"), devroot)
        b = _resolve(base.joinpath(name, "supplier"), devroot)
        if a in devices and b in devices and a != b:
            out.append({"kind": "dependency", "from": a, "to": b,
                        "attrs": {k: v for k, v in (("status", _attr(base.joinpath(name, "status"), notes)),) if v}})
        else:
            notes["dangling"] += 1
    return out


def _phandle(p: Path) -> Optional[int]:
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        data = os.read(fd, 8)
    except OSError:
        return None
    finally:
        os.close(fd)
    return int.from_bytes(data, "big") if len(data) == 4 else None


def _devicetree(root: Path, notes: dict, max_dirs: int) -> tuple[dict, list]:
    """Declared port-to-port wiring: an ``endpoint`` node with a ``remote-endpoint`` phandle
    names the node on the other end. Each end becomes a device so no link points at nothing."""
    base = root.joinpath("sys", "firmware", "devicetree", "base")
    if not base.is_dir():
        return {}, []
    notes["sources"]["devicetree"] = True
    by_phandle: dict = {}
    remote: dict = {}
    stack, dirs = [base], 0
    while stack:
        path = stack.pop()
        dirs += 1
        if dirs > max_dirs:
            notes["truncated"].append("devicetree")
            break
        rel = os.path.relpath(path, base)
        for prop in ("phandle", "linux,phandle"):
            h = _phandle(path.joinpath(prop))
            if h is not None:
                by_phandle[h] = rel
                break
        r = _phandle(path.joinpath("remote-endpoint"))
        if r is not None:
            remote[rel] = r
        try:
            with os.scandir(path) as it:
                stack.extend(path.joinpath(e.name) for e in sorted(it, key=lambda e: e.name)
                             if e.is_dir(follow_symlinks=False))
        except OSError:
            notes["unreadable"] += 1
    devices: dict = {}
    pairs: set = set()
    for a, h in remote.items():
        b = by_phandle.get(h)
        if b is None or b == a:
            notes["dangling"] += 1
            continue
        pairs.add(tuple(sorted((a, b))))
    for a, b in pairs:
        for n in (a, b):
            devices.setdefault("dt:" + n, {"id": "dt:" + n, "resource": "hw:dt:" + n,
                                           "name": clean(os.path.basename(n)),
                                           "subsystem": "devicetree", "driver": None,
                                           "parent": None, "attrs": {}})
    links = [{"kind": "devicetree-endpoint", "from": "dt:" + a, "to": "dt:" + b, "attrs": {}}
             for a, b in sorted(pairs)]
    return devices, links


def scan(root: Path = Path("/"), max_devices: int = MAX_DEVICES, max_dirs: int = MAX_DIRS) -> Map:
    """Look at the machine. ``root`` is a fake tree in tests, ``/`` for real. Reads only."""
    notes = {"sources": {"devices": False, "devlink": False, "devicetree": False},
             "unreadable": 0, "dangling": 0, "truncated": [], "virtual_skipped": False,
             "not_visible": list(NOT_VISIBLE)}
    devroot = root.joinpath("sys", "devices")
    devices: dict = {}
    links: list = []
    if devroot.is_dir():
        notes["sources"]["devices"] = True
        devices, links = _walk(devroot, notes, max_devices, max_dirs)
        links += _dependencies(devroot, devices, notes)
    dt_devices, dt_links = _devicetree(root, notes, max_dirs)
    devices.update(dt_devices)
    links += dt_links
    for link in links:
        link["resource"] = f"hwlink:{link['kind']}:{link['from']}>{link['to']}"
    notes["truncated"] = sorted(set(notes["truncated"]))
    return Map(devices=sorted(devices.values(), key=lambda d: d["id"]),
               links=sorted(links, key=lambda l: (l["kind"], l["from"], l["to"])), notes=notes)


# ---------------------------------------------------------------- the folder in permissions

def folder(paths: Paths) -> Path:
    return paths.state.joinpath("permissions", "hardware")


def _dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode()


def save(paths: Paths, m: Map) -> Path:
    """Write the three files. ``scan.json`` goes last and carries the checksums of the other
    two, so a reader can tell a half-written map from a whole one."""
    d = folder(paths)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    devices, links = _dump(m.devices), _dump(m.links)
    atomic_write(d.joinpath("devices.json"), devices)
    atomic_write(d.joinpath("links.json"), links)
    meta = dict(m.notes)
    meta.update({"scanned_at": time.time_ns() // 1_000_000_000, "devices": len(m.devices),
                 "links": len(m.links),
                 "sha256": {"devices.json": hashlib.sha256(devices).hexdigest(),
                            "links.json": hashlib.sha256(links).hexdigest()}})
    atomic_write(d.joinpath("scan.json"), _dump(meta))
    return d


def load(paths: Paths) -> Optional[Map]:
    """The saved map, or None if there is none. A map that does not match its checksums raises."""
    d = folder(paths)
    try:
        meta = json.loads(d.joinpath("scan.json").read_text())
        raw = {n: d.joinpath(n).read_bytes() for n in ("devices.json", "links.json")}
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise HardwareError(f"hardware map unreadable ({e}); scan again") from e
    for n, data in raw.items():
        if meta.get("sha256", {}).get(n) != hashlib.sha256(data).hexdigest():
            raise HardwareError(f"{n} does not match its checksum (half-written or edited); scan again")
    try:
        devices, links = json.loads(raw["devices.json"]), json.loads(raw["links.json"])
    except ValueError as e:
        raise HardwareError(f"hardware map unreadable ({e}); scan again") from e
    if not isinstance(devices, list) or not isinstance(links, list):
        raise HardwareError("hardware map has the wrong shape; scan again")
    return Map(devices=devices, links=links, notes=meta)


def diff(old: Optional[Map], new: Map) -> dict:
    """What appeared and what went away since the last scan: a new device or connection you did
    not plug in is the thing worth noticing."""
    od = {d["id"] for d in (old.devices if old else [])}
    nd = {d["id"] for d in new.devices}
    ol = {l["resource"] for l in (old.links if old else [])}
    nl = {l["resource"] for l in new.links}
    return {"devices_added": sorted(nd - od), "devices_removed": sorted(od - nd),
            "links_added": sorted(nl - ol), "links_removed": sorted(ol - nl)}
