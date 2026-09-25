"""Run an app straight out of its zip, without unzipping anything to disk.

1. The verified zip bytes are copied into a ``memfd`` (an anonymous file that
   exists only in RAM) and the memfd is *sealed*: after sealing, the kernel
   refuses every write, shrink or grow, even from us. What runs is therefore
   byte-for-byte what the seal check approved - there is no window in which
   the file on disk could be swapped (no TOCTOU).
2. Python apps: the interpreter imports modules directly from the zip in the
   memfd (``zipimport`` on ``/proc/self/fd/N``).
   Native apps: the ELF entry is read from the zip into a second sealed memfd
   and executed with ``fexecve`` semantics (exec of ``/proc/self/fd/N``).
   Native apps must be statically linked.
3. The app gets one inherited socket (``KOS_CHANNEL_FD``). Its stdin/stdout
   are ``/dev/null``: it cannot write to your terminal. Everything it wants to
   show goes through the session as validated commands.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .kapp import KApp
from .sandbox import SandboxPolicy

SDK_DIR = str(Path(__file__).resolve().parent.parent)

_BOOTSTRAP = r"""
import sys, importlib
kapp, entry, sdk = sys.argv[1], sys.argv[2], sys.argv[3]
del sys.argv[1:4]
sys.path[:0] = [sdk, kapp]
mod, _, fn = entry.partition(":")
sys.exit(getattr(importlib.import_module(mod), fn or "main")())
"""


def sealed_memfd(label: str, data: bytes) -> int:
    fd = os.memfd_create(f"kos:{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


@dataclass
class LaunchPlan:
    argv: list[str]
    executable: str
    env: dict[str, str]
    pass_fds: list[int]
    owned_fds: list[int] = field(default_factory=list)

    def close(self) -> None:
        for fd in self.owned_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.owned_fds.clear()


def plan(app: KApp, channel_fd: int, mode: str) -> LaunchPlan:
    m = app.manifest
    kapp_fd = sealed_memfd(m.name, app.data)
    owned = [kapp_fd]
    env = {
        "KOS_CHANNEL_FD": str(channel_fd),
        "KOS_KAPP_FD": str(kapp_fd),
        "KOS_APP": m.name,
        "KOS_MODE": mode,
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    if m.runtime == "python":
        exe = os.path.realpath(sys.executable)
        argv = [exe, "-I", "-S", "-B", "-c", _BOOTSTRAP,
                f"/proc/self/fd/{kapp_fd}", m.entry, SDK_DIR]
    else:
        exe_fd = sealed_memfd(f"{m.name}-bin", app.read(m.entry))
        owned.append(exe_fd)
        exe = f"/proc/self/fd/{exe_fd}"
        argv = [m.name]
    return LaunchPlan(argv=argv, executable=exe, env=env,
                      pass_fds=[channel_fd, *owned], owned_fds=owned)


def launch(p: LaunchPlan, policy: SandboxPolicy, log_path: Optional[Path]) -> subprocess.Popen:
    log = open(log_path, "ab") if log_path else subprocess.DEVNULL
    try:
        return subprocess.Popen(
            p.argv, executable=p.executable, env=p.env, pass_fds=p.pass_fds,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
            cwd="/", start_new_session=True, preexec_fn=policy.preexec())
    finally:
        if log is not subprocess.DEVNULL:
            log.close()
        p.close()
