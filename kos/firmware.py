"""Firmware control: the OS must be in charge of the machine, or it does not boot.

Some machines carry a second computer next to the CPU that runs before the OS,
keeps running under it, and can reach memory and the network without the OS
knowing: Intel's Management Engine (and AMT on top of it), AMD's Platform
Security Processor, and server BMCs (IPMI). KOS promises that nothing happens
without your password; code that KOS cannot see or stop breaks that promise.
So the rule is: **find them, say so, try to switch them off, and if they are
not provably off, refuse to boot.**

What is real here, and what is not
----------------------------------
* **Finding them** is real: PCI ids/classes, the MEI character device, the IPMI
  DMI record and device nodes, all read from sysfs. The same scan runs in the
  pre-boot shell (``boot/initramfs/firmware.sh``, before the disk is even
  unlocked) and again here; ``tests`` runs both against one fake sysfs and
  insists they agree.
* **Proving an Intel ME is off** is the one thing software can check: the ME
  reports its operation mode in PCI config space (HFSTS1, bits 19:16). Mode 3
  is "disabled" (the HAP / soft-disable state that ``me_cleaner`` or the
  vendor sets). Anything else, or a register we cannot read, counts as running.
  The layout follows coreboot/intelmetool's description; it has not been
  checked against hardware in this repository (the tests use synthetic config
  space).
* **Switching them off from the OS is not possible.** The ME, PSP and BMC run
  on their own processor with their own flash, and the OS cannot stop them.
  All KOS can do - and does, as "mitigation" - is to cut *its own side*: unbind
  the driver and forbid rebinding, so nothing on this machine talks to them.
  That is not "off". The device is left visible on purpose (removing it would
  make the next scan wrongly say "absent"). Really disabling needs the flash:
  ``me_cleaner``/HAP, coreboot, or a vendor BIOS switch - an offline job we do
  not attempt, because a bad write bricks the machine.
* **Absence cannot be proved.** A BIOS can hide the ME's PCI function. On bare
  metal x86 with nothing visible, :func:`probe` reports a *caveat* (printed,
  boot allowed): the OS cannot see what is deliberately hidden from it.

There is no resident checker: the gate is a one-shot look at boot (and at each
unlock). No daemon, no watchdog, no "check manager" process or chip - a thing
that watches the OS would be one more thing the OS does not control.

Beyond the ME/PSP/BMC, every other chip that runs its own firmware is reported
and, under ``enforce``, blocks the boot too (Thunderbolt/USB4, USB-C port
controller, embedded controller, network, GPU, NVMe, wireless/Bluetooth), as does
a machine with such chips and no IOMMU. Those are not mitigated: unbinding a
NIC, GPU or the root disk's controller would break the machine, and the IOMMU
(``kernel/cmdline.txt``) is what confines them. Inside a VM they are emulated
and ignored. On real hardware this means almost nothing boots under ``enforce``.

Policy comes from the signed kernel command line (``kos.firmware=``):
``enforce`` (default, also for any unknown value) halts; ``warn`` mitigates,
alerts and boots anyway. PID 1 ignores the environment; only a development run
honours ``KOS_DEV_FIRMWARE=warn``.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

INTEL, AMD = "0x8086", "0x1022"
CLASS_MEI = "0x0780"      # PCI "communication controller, other" = Intel MEI/HECI
CLASS_CRYPTO = "0x1080"   # PCI "encryption controller" = AMD PSP (ccp)
HFSTS1 = 0x40             # ME host firmware status 1, in the MEI function's config space
ME_MODE_DISABLED = 3
OVERRIDE = "kos-none"     # a driver name that does not exist: nothing can bind

POLICIES = ("enforce", "warn")

# Other chips that run their own firmware and can act below or beside the OS.
# Every one is "running": the OS cannot see inside them or prove them benign.
# (class prefix, kind, name). Skipped inside a VM, where they are emulated.
FIRMWARE_CLASSES = (
    ("0x0c0340", "thunderbolt", "Thunderbolt/USB4 controller"),
    ("0x02", "network", "network controller"),
    ("0x03", "display", "display/GPU controller"),
    ("0x0108", "nvme", "NVMe storage controller"),
    ("0x0d", "wireless", "wireless/Bluetooth controller"),
)


@dataclass
class Finding:
    kind: str            # intel-me | amd-psp | bmc-ipmi
    name: str            # human name
    where: str           # sysfs path or device node
    state: str           # "active" or "neutralized"
    detail: str = ""
    device: str = ""     # sysfs device directory, relative to the root, for mitigation
    detached: bool = False   # the OS side was cut by neutralize()

    def line(self) -> str:
        tail = f" - {self.detail}" if self.detail else ""
        cut = " [OS side detached]" if self.detached else ""
        return f"{self.name} at {self.where}: {self.state.upper()}{cut}{tail}"


@dataclass
class Verdict:
    policy: str
    findings: list[Finding] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    caveat: str = ""

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.state == "active"]

    @property
    def ok(self) -> bool:
        """May the machine boot?"""
        return not self.blocking or self.policy == "warn"

    def reason(self) -> Optional[str]:
        if self.ok:
            return None
        return ("the OS does not have complete control of this machine: "
                + "; ".join(f.name for f in self.blocking) + " still running")

    def lines(self) -> list[str]:
        out = [f.line() for f in self.findings]
        out += [f"  did: {a}" for a in self.actions]
        if self.caveat:
            out.append(f"  note: {self.caveat}")
        if not self.findings:
            out.append("no management processor visible to the OS")
        return out


def _read(p: Path) -> str:
    try:
        return p.read_text().strip().lower()
    except OSError:
        return ""


def policy_from_cmdline(cmdline: str) -> str:
    for word in cmdline.split():
        if word.startswith("kos.firmware="):
            value = word.split("=", 1)[1]
            return value if value in POLICIES else "enforce"
    return "enforce"


def current_policy(root: Path = Path("/")) -> str:
    if os.getpid() != 1 and os.environ.get("KOS_DEV_FIRMWARE") in POLICIES:
        return os.environ["KOS_DEV_FIRMWARE"]
    return policy_from_cmdline(_read(root / "proc/cmdline"))


def me_operation_mode(config: Path) -> Optional[int]:
    """HFSTS1 bits 19:16 from a PCI config-space file; None if unreadable."""
    try:
        with open(config, "rb") as f:
            f.seek(HFSTS1)
            raw = f.read(4)
    except OSError:
        return None
    if len(raw) != 4:
        return None
    return (struct.unpack("<I", raw)[0] >> 16) & 0xF


def _in_vm(root: Path) -> bool:
    return " hypervisor" in _read(root / "proc/cpuinfo")


def _pci_findings(root: Path) -> list[Finding]:
    out = []
    vm = _in_vm(root)
    base = root / "sys/bus/pci/devices"
    try:
        devices = sorted(base.iterdir())
    except OSError:
        return out
    for dev in devices:
        vendor, klass = _read(dev / "vendor"), _read(dev / "class")
        rel = str(dev.relative_to(root))
        if vendor == INTEL and klass.startswith(CLASS_MEI):
            mode = me_operation_mode(dev / "config")
            if mode == ME_MODE_DISABLED:
                out.append(Finding("intel-me", "Intel Management Engine", rel, "neutralized",
                                   "firmware reports operation mode 'disabled'", rel))
            else:
                seen = "unreadable" if mode is None else f"operation mode {mode}"
                out.append(Finding("intel-me", "Intel Management Engine", rel, "active",
                                   f"{seen}; it can reach memory and the network (AMT) "
                                   "below the OS", rel))
        elif vendor == AMD and klass.startswith(CLASS_CRYPTO):
            out.append(Finding("amd-psp", "AMD Platform Security Processor", rel, "active",
                               "cannot be queried or stopped from the OS", rel))
        elif not vm:
            for prefix, kind, name in FIRMWARE_CLASSES:
                if klass.startswith(prefix):
                    out.append(Finding(kind, name, rel, "active",
                                       "runs its own firmware and can reach memory by DMA"))
                    break
    return out


def _other_findings(root: Path) -> list[Finding]:
    """Firmware-bearing chips that are not PCI functions, plus the check that
    the IOMMU is on whenever DMA-capable chips exist."""
    out = []
    if not _in_vm(root):
        for pattern, kind, name in (
                ("sys/class/typec/port*", "typec-port", "USB-C port controller"),
                ("sys/bus/acpi/devices/PNP0C09*", "embedded-controller", "embedded controller"),
                ("sys/bus/thunderbolt/devices/domain*", "thunderbolt", "Thunderbolt/USB4 controller")):
            hit = sorted(root.glob(pattern))
            if hit:
                out.append(Finding(kind, name, hit[0].relative_to(root).as_posix(), "active",
                                   "runs its own firmware; the OS cannot see inside it"))
    return out


def _iommu_finding(root: Path, findings: list[Finding]) -> list[Finding]:
    dma = {"thunderbolt", "network", "display", "nvme", "wireless", "intel-me", "amd-psp"}
    if not any(f.kind in dma and f.state == "active" for f in findings):
        return []
    try:
        if any((root / "sys/kernel/iommu_groups").iterdir()):
            return []
    except OSError:
        pass
    return [Finding("no-iommu", "no IOMMU", "sys/kernel/iommu_groups", "active",
                    "chips that do DMA are not confined to memory the OS gave them")]


def _bmc_findings(root: Path) -> list[Finding]:
    out = []
    dmi = root / "sys/firmware/dmi/entries"
    try:
        has_dmi = any(p.name.startswith("38-") for p in dmi.iterdir())
    except OSError:
        has_dmi = False
    nodes = sorted(p for pat in ("dev/ipmi*", "dev/ipmi/*") for p in root.glob(pat))
    nodes += sorted((root / "sys/class/ipmi").glob("ipmi*"))
    if has_dmi or nodes:
        where = (nodes[0].relative_to(root).as_posix() if nodes
                 else "sys/firmware/dmi/entries/38-*")
        device = ""
        if nodes and nodes[0].parts[-3:-1] == ("class", "ipmi"):
            device = f"{nodes[0].relative_to(root).as_posix()}/device"
        out.append(Finding("bmc-ipmi", "Baseboard management controller (IPMI)", where, "active",
                           "a separate computer with its own network access", device))
    return out


def _caveat(root: Path) -> str:
    cpu = _read(root / "proc/cpuinfo")
    if not cpu or " hypervisor" in cpu:
        return ""
    if "genuineintel" in cpu or "authenticamd" in cpu:
        return ("this is bare-metal Intel/AMD, which normally contains a management "
                "processor, but none is visible - it may be hidden by the firmware, and "
                "the OS cannot prove it is absent")
    return ""


def probe(root: Path = Path("/"), policy: Optional[str] = None) -> Verdict:
    root = Path(root)
    v = Verdict(policy or current_policy(root))
    v.findings = _pci_findings(root) + _bmc_findings(root) + _other_findings(root)
    v.findings += _iommu_finding(root, v.findings)
    if not v.findings:
        v.caveat = _caveat(root)
    return v


# --- mitigation: cut the OS's side. This is NOT switching the thing off. -------------

def _unbind(root: Path, device: str) -> Optional[str]:
    dev = root / device
    drv = dev / "driver"
    if drv.exists():
        try:
            # the kernel's unbind file takes the device's name (its bus address)
            (drv / "unbind").write_text(os.path.basename(os.path.realpath(dev)) + "\n")
        except OSError as e:
            return f"could not unbind {device}: {e.strerror}"
    try:
        (dev / "driver_override").write_text(OVERRIDE + "\n")
    except OSError:
        pass   # platform/ipmi devices may not offer it; the unbind above is what counts
    return None


def neutralize(root: Path, verdict: Verdict) -> Verdict:
    """Detach every active finding from the OS. The ME/PSP/BMC keep running."""
    root = Path(root)
    for f in verdict.blocking:
        if not f.device:
            continue
        err = _unbind(root, f.device)
        if err:
            verdict.actions.append(err)
        else:
            f.detached = True
            verdict.actions.append(f"detached the OS from {f.name} (driver unbound, rebinding "
                                   "forbidden) - it is still running")
    return verdict


def enforce(root: Path = Path("/"), policy: Optional[str] = None, *, mitigate: bool = True) -> Verdict:
    """Probe, mitigate what is active, and probe again. The second look is what
    counts: mitigation never turns 'active' into 'neutralized' by itself."""
    first = probe(root, policy)
    if mitigate and first.blocking:
        neutralize(root, first)
    second = probe(root, first.policy)
    second.actions = first.actions
    for f in second.findings:
        f.detached = any(g.detached and g.where == f.where for g in first.findings)
    return second
