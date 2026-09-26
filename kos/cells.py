"""Multi-kernel: run several Linux kernels side by side, in parallel.

A *cell* is a complete, separate Linux kernel with its own memory, running on
its own dedicated CPU cores. Apps can be launched inside a cell instead of on
the main (host) kernel. If an app finds a kernel bug and takes over its
kernel, it has taken over *its cell's* kernel, not yours.

How it is built today (works on any Linux with KVM):
  * Each cell is a KVM micro-VM (QEMU ``-M microvm``): no emulated PCI, no
    BIOS, no disk; just a kernel, a tiny initramfs with the KOS cell agent and
    a vsock socket back to the host.
  * Each cell is pinned with ``taskset`` to its own host cores, so kernels
    truly execute in parallel rather than time-sharing one core. Add
    ``isolcpus=`` / ``nohz_full=`` for those cores on the host command line to
    keep the host kernel off them entirely.
  * The host talks to the cell over AF_VSOCK, which is the *same command
    protocol* a local app uses. The session code does not care where the app
    runs.

The future bare-metal backend is Linux's proposed "multikernel" support
(spawning additional kernel instances on partitioned CPUs/memory without a
hypervisor). That is an out-of-tree RFC, not mainline, so it is documented in
docs/ARCHITECTURE.md rather than implemented here.

Starting and stopping a cell each require the password.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .auth import Authority
from .kapp import NAME_RE, KApp
from .paths import Paths, atomic_write

AGENT_PORT = 7000
FIRST_CID = 3  # 0-2 are reserved by vsock


class CellError(RuntimeError):
    pass


@dataclass
class CellSpec:
    name: str
    kernel: str
    initrd: str
    memory_mb: int = 256
    cpus: list[int] = field(default_factory=lambda: [1])
    cid: int = 0

    def validate(self) -> None:
        if not NAME_RE.match(self.name):
            raise CellError(f"invalid cell name {self.name!r}")
        for p in (self.kernel, self.initrd):
            if not os.path.isfile(p):
                raise CellError(f"missing file: {p}")
        if not 64 <= self.memory_mb <= 65536:
            raise CellError("memory must be 64..65536 MiB")
        if not self.cpus or any(c < 0 for c in self.cpus):
            raise CellError("cpus must be a non-empty list of core numbers")


def qemu_argv(spec: CellSpec, console_log: str, qemu: str = "qemu-system-x86_64") -> list[str]:
    cpus = ",".join(str(c) for c in spec.cpus)
    append = ("console=ttyS0 quiet panic=-1 oops=panic lockdown=confidentiality "
              f"init_on_free=1 kos.cell={spec.name}")
    return [
        "taskset", "-c", cpus,
        qemu,
        "-M", "microvm,x-option-roms=off,rtc=off",
        "-enable-kvm", "-cpu", "host",
        "-smp", str(len(spec.cpus)),
        "-m", f"{spec.memory_mb}M",
        "-nodefaults", "-no-user-config", "-nographic", "-display", "none",
        "-serial", f"file:{console_log}",
        "-kernel", spec.kernel, "-initrd", spec.initrd,
        "-append", append,
        "-device", f"vhost-vsock-device,guest-cid={spec.cid}",
        # No network device, no disk: the cell only has its vsock to the host.
    ]


class CellManager:
    def __init__(self, paths: Paths):
        self.paths = paths

    def _file(self, name: str) -> Path:
        if not NAME_RE.match(name):
            raise CellError(f"invalid cell name {name!r}")
        return self.paths.cells / f"{name}.json"

    def cells(self) -> list[dict]:
        out = []
        for f in sorted(self.paths.cells.glob("*.json")):
            d = json.loads(f.read_text())
            d["running"] = _alive(d.get("pid", 0))
            out.append(d)
        return out

    def get(self, name: str) -> dict:
        try:
            d = json.loads(self._file(name).read_text())
        except FileNotFoundError:
            raise CellError(f"no such cell {name!r}") from None
        if not _alive(d.get("pid", 0)):
            raise CellError(f"cell {name!r} is not running")
        return d

    def _next_cid(self) -> int:
        used = {c["cid"] for c in self.cells() if c["running"]}
        cid = FIRST_CID
        while cid in used:
            cid += 1
        return cid

    def check_host(self) -> set[int]:
        """Raise if this machine can't run cells; return cores already in use."""
        missing = [p for p in ("/dev/kvm", "/dev/vhost-vsock") if not os.path.exists(p)]
        if missing:
            raise CellError(f"cells need KVM and vhost-vsock; missing {', '.join(missing)}")
        if not shutil.which("qemu-system-x86_64") or not shutil.which("taskset"):
            raise CellError("cells need qemu-system-x86_64 and taskset")
        busy = {c for cell in self.cells() if cell["running"] for c in cell["cpus"]}
        return busy

    def start(self, spec: CellSpec, grant_or_authority) -> dict:
        """`grant_or_authority` is either an `Authority` (live password) or
        an already-open grant/context (e.g. a redeemed autonomy token) -
        either way it's used as the context manager for the privileged
        window; only an `Authority` calls `.authorize()` itself."""
        spec.validate()
        busy = self.check_host()
        overlap = busy & set(spec.cpus)
        if overlap:
            raise CellError(f"cores {sorted(overlap)} already belong to another cell")
        if spec.cpus and max(spec.cpus) >= (os.cpu_count() or 1):
            raise CellError("requested core does not exist")
        cm = grant_or_authority.authorize("cell.start", spec.name) \
            if isinstance(grant_or_authority, Authority) else grant_or_authority
        with cm:
            self.paths.ensure()
            spec.cid = self._next_cid()
            log = str(self.paths.logs / f"cell-{spec.name}.console")
            proc = subprocess.Popen(qemu_argv(spec, log), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
        rec = {**asdict(spec), "pid": proc.pid, "started": time.time()}
        atomic_write(self._file(spec.name), json.dumps(rec, indent=2).encode())
        return rec

    def stop(self, name: str, grant_or_authority) -> None:
        rec = json.loads(self._file(name).read_text())
        cm = grant_or_authority.authorize("cell.stop", name) \
            if isinstance(grant_or_authority, Authority) else grant_or_authority
        with cm:
            if _alive(rec["pid"]):
                os.killpg(rec["pid"], signal.SIGTERM)
        self._file(name).unlink()


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def send_app(sock: socket.socket, app: KApp, mode: str) -> None:
    """Host side: ship an already-verified app into a cell over its vsock."""
    header = {"cmd": "load", "name": app.manifest.name, "mode": mode, "size": len(app.data)}
    sock.sendall(json.dumps(header).encode() + b"\n" + app.data)


def connect_cell(cid: int, port: int = AGENT_PORT, timeout: float = 30.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    last: Optional[Exception] = None
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        try:
            s.connect((cid, port))
            return s
        except OSError as e:
            last = e
            s.close()
            time.sleep(0.5)
    raise CellError(f"cell with cid {cid} did not answer: {last}")
