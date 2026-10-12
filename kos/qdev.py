"""Quantum and photonic hardware: finding it, and running jobs on it through a driver.

The honest picture, so nobody is misled: Linux has **no standard device class** for quantum computers. A photonic or
superconducting processor, a "quantum RAM", a Majorana-based device - each comes with its maker's own driver and protocol,
and most are reached over the network rather than plugged in. KOS cannot make a driver appear. What it can do - and what is
built and tested here - is the part that is KOS's to do:

* **Find** what the machine shows: device nodes with quantum-ish names (``/dev/qpu*``, ``/dev/quantum*``, ``/dev/qrng*``,
  ``/dev/photonic*``), sysfs entries, hardware random-number sources that identify as quantum (the one kind of quantum
  hardware with wide Linux support), and PCI IDs you list yourself in ``/etc/kos/quantum-devices.json``.
* **Give a driver the device, and nothing else.** A driver is an ordinary KOS app whose manifest says ``"driver": "quantum"`` and
  ``"devices": ["/dev/qpu*"]``. At launch KOS names the nodes, asks, and (after your password, every time) opens exactly those
  nodes to that app inside the usual sandbox - no network, no files, nothing else in ``/dev``.
* **One protocol** for jobs, so an app does not care which device it is: a program (OpenQASM text), a shot count, and
  counts back. The driver translates to whatever the hardware speaks.
* **An emulator driver** (``examples/drivers/qsim``) that follows the same protocol with a state-vector simulator, so the whole
  path can be tested without hardware. It is labelled an emulator everywhere and is never presented as a device.

What is NOT here: any vendor's driver, and any claim that a real quantum device has been driven. None was available to test.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

NODE_GLOBS = {"qpu": "qpu*", "quantum": "quantum*", "qrng": "qrng*", "photonic": "photonic*", "qram": "qram*"}
SYS_NAME = re.compile(r"(qpu|quantum|qrng|photonic|majorana|qram)", re.I)
QRNG_NAME = re.compile(r"(quantis|qrng|quantum|photon)", re.I)


@dataclass
class Device:
    id: str
    kind: str                  # qpu | quantum | qrng | photonic | qram | pci | emulator
    name: str
    node: str = ""             # the /dev path a driver would open ("" for an emulator)
    source: str = ""           # how it was found
    driver: str = ""           # the app name its registry entry names, if any
    drivers: list[str] = field(default_factory=list)    # installed driver apps that could serve it
    real: bool = True

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def detect(root: str = "/", registry_file: Optional[str] = None) -> list[Device]:
    """What the machine shows. Reads only; opens no device. ``root`` exists so tests can point at a fake tree."""
    base = Path(root)
    out: dict[str, Device] = {}

    def add(d: Device) -> None:
        out.setdefault(d.id, d)

    for kind, pat in NODE_GLOBS.items():
        for p in sorted(glob.glob(str(base / "dev" / pat))):
            node = "/" + str(Path(p).relative_to(base))
            add(Device(f"{kind}:{Path(p).name}", kind, f"{kind} device {Path(p).name}", node, "device node"))
    sysfs = base / "sys" / "class"
    if sysfs.is_dir():
        for cls in sorted(sysfs.iterdir()):
            try:
                names = sorted(os.listdir(cls))
            except OSError:
                continue
            for n in names:
                if SYS_NAME.search(n) and cls.name not in ("hw_random",):
                    node = f"/dev/{n}" if (base / "dev" / n).exists() else ""
                    add(Device(f"sysfs:{cls.name}/{n}", "quantum", f"{n} (class {cls.name})", node, "sysfs class"))
    rng = base / "sys" / "class" / "misc" / "hw_random" / "rng_available"
    try:
        for n in rng.read_text().split():
            if QRNG_NAME.search(n):                       # an ordinary RNG is not quantum hardware: only name-matches
                add(Device(f"qrng:{n}", "qrng", f"hardware random source {n} (identifies as quantum)",
                           "/dev/hwrng" if (base / "dev" / "hwrng").exists() else "", "hw_random"))
    except OSError:
        pass
    reg = Path(registry_file) if registry_file else base / "etc" / "kos" / "quantum-devices.json"
    try:
        entries = json.loads(reg.read_text())
    except (OSError, ValueError):
        entries = []
    pci = base / "sys" / "bus" / "pci" / "devices"
    for e in entries if isinstance(entries, list) else []:
        try:
            vid, did = e["id"].lower().split(":")
            for dev in sorted(pci.glob("*")):
                v = (dev / "vendor").read_text().strip().lower().removeprefix("0x")
                d = (dev / "device").read_text().strip().lower().removeprefix("0x")
                if (v, d) == (vid, did):
                    add(Device(f"pci:{dev.name}", e.get("kind", "pci"), e.get("name", f"PCI {e['id']}"),
                               e.get("node", ""), f"PCI id {e['id']} (from {reg.name})", e.get("driver", "")))
        except (KeyError, ValueError, OSError, TypeError, AttributeError):
            continue
    return sorted(out.values(), key=lambda d: d.id)


def with_drivers(devices: list[Device], paths) -> list[Device]:
    """Fill in which installed driver apps could serve each device, and add the emulator when its driver is installed."""
    from .kapp import KApp
    from .store import AppStore
    drivers = []
    for a in AppStore(paths).installed():
        try:
            m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
        except Exception:
            continue
        if m.driver == "quantum":
            drivers.append(m)
    out = list(devices)
    for d in out:
        for m in drivers:
            if m.devices and d.node and any(fnmatch.fnmatch(d.node, pat) for pat in m.devices):
                d.drivers.append(m.name)
            elif d.driver and d.driver == m.name:
                d.drivers.append(m.name)
    for m in drivers:
        if not m.devices:                                  # a driver that needs no device is an emulator
            out.append(Device(f"emulator:{m.name}", "emulator", f"{m.name} - an EMULATOR, not hardware", "",
                              "installed driver app", m.name, [m.name], real=False))
    return out
