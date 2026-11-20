"""The device chooser: which device a computational task should run on.

A task says what it is (``general``, ``parallel`` or ``inference``), how much memory it needs, whether
its data may leave this machine (``private``, true unless said otherwise) and whether it must run apart
from the main kernel (``isolate``). The chooser looks at every compute device the OS knows - the host
CPU, any GPU or NPU the kernel lists, the running kernel cells and the linked devices - and answers with
the best device that is *allowed*, or with no device and the reason each one was refused.

Three rules the code keeps, each with a test that tries to break it (``tests/test_compute.py``):

* **Fail closed.** A device is chosen only if it passes every hard check. There is no fallback to a
  weaker place: a task that must be isolated and has no isolated device gets *no device*, never the
  host. A device whose size is unknown cannot be shown to fit a task that states a size, so it is
  refused.
* **Nothing is chosen that cannot run.** A GPU or NPU is listed and ranked-out with the reason, because
  no KOS executor can put work on one: an app never opens a device (the hardware layer is the OS's
  alone) and there is no GPU executor in the OS. The table ``EXECUTORS`` is the one place that
  changes when one is added; a test fails if a kind is missing from it.
* **Whole numbers only.** Scores, cores and memory are integers (memory in MB, ``//`` for division).
  Nothing here is a decimal.

This module only *decides*. It reads sysfs and ``/proc`` (read-only, like ``kos/hardware.py``), opens
nothing under ``/dev`` and runs nothing. What is not wired yet (the launchers do not ask it) is in the
README gaps table.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .hardware import clean

KINDS = ("cpu", "gpu", "npu", "cell", "linked")
TASKS = ("general", "parallel", "inference")
MAX_MEMORY_MB = 1_048_576

# Which kinds KOS can actually put work on today. cpu: the sandbox on the host kernel. cell: a kernel
# cell over vsock. gpu, npu and linked: no executor exists, so they are shown and never chosen.
EXECUTORS: dict[str, str] = {
    "cpu": "",
    "cell": "",
    "gpu": "KOS has no GPU executor: an app cannot open a GPU and the OS does not run work on one yet",
    "npu": "KOS has no NPU executor: an app cannot open an accelerator and the OS does not run work on one yet",
    "linked": "a linked device can be asked for actions but there is no action that runs a task there yet",
}

# How well each kind suits each task, 0..100. Capacity (cores, memory) only breaks ties between kinds
# with the same fit: affinity * 1000 always outweighs the capacity part, which is under 1000.
AFFINITY: dict[str, dict[str, int]] = {
    "general":   {"cpu": 60, "cell": 50, "linked": 40, "gpu": 5, "npu": 5},
    "parallel":  {"gpu": 90, "linked": 60, "cpu": 50, "cell": 45, "npu": 40},
    "inference": {"npu": 95, "gpu": 85, "linked": 50, "cpu": 40, "cell": 35},
}

_VENDORS = {"0x10de": "NVIDIA", "0x1002": "AMD", "0x8086": "Intel", "0x1af4": "virtio", "0x15ad": "VMware"}
_CARD = re.compile(r"^(card|accel)[0-9]{1,3}$")


class ComputeError(ValueError):
    pass


@dataclass(frozen=True)
class Device:
    id: str                 # "cpu", "gpu:card0", "npu:accel0", "cell:NAME", "link:ID"
    kind: str               # one of KINDS
    name: str
    units: int = 0          # cores or compute units; 0 means not known
    memory_mb: int = 0      # memory a task may use; 0 means not known
    online: bool = True
    why_offline: str = ""
    remote: bool = False    # work on it leaves this machine
    isolated: bool = False  # runs apart from the main kernel

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ComputeError(f"unknown device kind {self.kind!r}")
        if type(self.units) is not int or type(self.memory_mb) is not int or self.units < 0 or self.memory_mb < 0:
            raise ComputeError("units and memory must be whole numbers, 0 or more")

    @property
    def runs(self) -> bool:
        return not EXECUTORS[self.kind]


@dataclass(frozen=True)
class Task:
    kind: str = "general"
    memory_mb: int = 0          # 0: the task states no size
    private: bool = True        # its data may not leave this machine
    isolate: bool = False       # it must run apart from the main kernel

    def __post_init__(self):
        if self.kind not in TASKS:
            raise ComputeError(f"unknown task kind {self.kind!r}: use one of {', '.join(TASKS)}")
        if type(self.memory_mb) is not int or not 0 <= self.memory_mb <= MAX_MEMORY_MB:
            raise ComputeError(f"memory must be a whole number of MB from 0 to {MAX_MEMORY_MB}")
        if type(self.private) is not bool or type(self.isolate) is not bool:
            raise ComputeError("private and isolate are true or false")


@dataclass(frozen=True)
class Decision:
    task: Task
    device: Optional[Device]
    ranked: tuple = field(default_factory=tuple)     # ((Device, score), ...) best first, allowed only
    refused: tuple = field(default_factory=tuple)    # ((Device, why), ...) in id order

    def as_dict(self) -> dict:
        t = self.task
        return {
            "task": {"kind": t.kind, "memory_mb": t.memory_mb, "private": t.private, "isolate": t.isolate},
            "device": self.device.id if self.device else None,
            "ranked": [{"id": d.id, "kind": d.kind, "name": d.name, "score": s} for d, s in self.ranked],
            "refused": [{"id": d.id, "kind": d.kind, "name": d.name, "why": why} for d, why in self.refused],
        }


def refusal(device: Device, task: Task) -> str:
    """Why this device may not take this task, or '' when it may. The first failing check wins."""
    if not device.runs:
        return EXECUTORS[device.kind]
    if not device.online:
        return device.why_offline or "not available"
    if device.remote and task.private:
        return "the task's data may not leave this machine"
    if task.isolate and not device.isolated:
        return "the task must run apart from the main kernel and this device is not apart from it"
    if task.memory_mb > 0 and device.memory_mb < task.memory_mb:
        return ("its memory is not known, so it cannot be shown to fit" if device.memory_mb == 0
                else f"it has {device.memory_mb} MB and the task needs {task.memory_mb} MB")
    return ""


def score(device: Device, task: Task) -> int:
    """Fit first (0..100 thousand), then size: cores and memory only ever break a tie in fit."""
    fit = AFFINITY[task.kind][device.kind]
    size = min(device.units, 64) * 5 + min(device.memory_mb // 1024, 64) * 5
    return fit * 1000 + size


def choose(task: Task, devices: Iterable[Device]) -> Decision:
    """The best allowed device, else none. Same input, same answer: ties go to the lower id."""
    seen: set[str] = set()
    allowed, refused = [], []
    for d in sorted(devices, key=lambda d: d.id):
        if d.id in seen:
            raise ComputeError(f"two devices share the id {d.id!r}")
        seen.add(d.id)
        why = refusal(d, task)
        (refused if why else allowed).append((d, why) if why else (d, score(d, task)))
    allowed.sort(key=lambda p: (-p[1], p[0].id))
    return Decision(task, allowed[0][0] if allowed else None, tuple(allowed), tuple(refused))


# ---- finding the devices (read-only; opens nothing under /dev) -----------------------------------------

def _int_from(path: Path, key: str) -> int:
    try:
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith(key + ":"):
                return int(line.split(":", 1)[1].split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def host_cpu(root: Path = Path("/")) -> Device:
    try:
        cores = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cores = os.cpu_count() or 0
    kb = _int_from(root.joinpath("proc", "meminfo"), "MemAvailable")
    return Device("cpu", "cpu", "host processor", units=cores, memory_mb=kb // 1024)


def _read(p: Path) -> str:
    try:
        return clean(p.read_text(errors="replace").strip(), 64)
    except OSError:
        return ""


def accelerators(root: Path = Path("/")) -> list[Device]:
    """GPUs (``/sys/class/drm/cardN``) and NPUs (``/sys/class/accel/accelN``) the kernel lists."""
    out = []
    for cls, kind in (("drm", "gpu"), ("accel", "npu")):
        base = root.joinpath("sys", "class", cls)
        try:
            entries = sorted(p for p in base.iterdir() if _CARD.match(p.name))
        except OSError:
            continue
        for p in entries:
            vendor = _VENDORS.get(_read(p.joinpath("device", "vendor")).lower(), "unknown vendor")
            out.append(Device(f"{kind}:{p.name}", kind, f"{vendor} {kind.upper()} {p.name}"))
    return out


def cell_devices(cells: Iterable[dict]) -> list[Device]:
    """Kernel cells (``CellManager.cells()``): each has its own kernel, memory and pinned cores."""
    out = []
    for c in cells:
        try:
            name = str(c["name"])
            cpus = c.get("cpus") or []
            mem = int(c.get("memory_mb", 0))
            up = bool(c.get("running"))
        except (KeyError, TypeError, ValueError):
            continue
        out.append(Device(f"cell:{clean(name, 32)}", "cell", f"kernel cell {clean(name, 32)}", units=len(cpus),
                          memory_mb=max(mem, 0), online=up, why_offline="the cell is not running",
                          isolated=True))
    return out


def linked_devices(peers: Iterable) -> list[Device]:
    """Linked devices (``LinkStore.peers()``). Work on one leaves this machine; a paused one is offline."""
    out = []
    for p in peers:
        try:
            ident, name, scope = str(p.device_id)[:16], str(p.name), str(p.scope)
        except AttributeError:
            continue
        out.append(Device(f"link:{ident}", "linked", f"linked device {clean(name, 40)}", online=scope != "paused",
                          why_offline="the link is paused", remote=True, isolated=True))
    return out


def probe(root: Path = Path("/"), cells: Iterable[dict] = (), peers: Iterable = ()) -> list[Device]:
    """Every compute device the OS knows about, in id order."""
    devices = [host_cpu(root), *accelerators(root), *cell_devices(cells), *linked_devices(peers)]
    return sorted(devices, key=lambda d: d.id)
