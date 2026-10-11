"""Process control: the only ways an app can ask the OS to act on a process.

Reading the process table needs no password (``osinfo.processes``). *Acting*
on one does: ``process.signal`` and ``process.renice`` are password actions,
and these guards hold no matter who asks:

* never PID 1, never KOS itself, never an ancestor of KOS (that would end the
  desktop out from under you);
* only processes owned by the same user - another user's process is not yours
  to stop, and KOS never runs as root for this;
* only the four signals a person means: TERM (ask it to exit), KILL (make it),
  STOP and CONT (pause / resume). Nothing else.
* nice can only be raised, 0..19 (lower priority). Lowering it needs root,
  which the kernel refuses and KOS does not try to work around.
"""

from __future__ import annotations

import os
import signal as sig

from .admin import AdminError
from .auth import Authority
from .osinfo import _kv, _read

SIGNALS = {"TERM": sig.SIGTERM, "KILL": sig.SIGKILL, "STOP": sig.SIGSTOP, "CONT": sig.SIGCONT}


class ProcessError(AdminError):
    pass


def _ancestors(proc: str = "/proc") -> set[int]:
    out, pid = set(), os.getpid()
    while pid > 1:
        out.add(pid)
        stat = _read(f"{proc}/{pid}/stat")
        try:
            pid = int(stat.rpartition(")")[2].split()[1])
        except (IndexError, ValueError):
            break
    return out


def _check(pid: int, proc: str = "/proc") -> None:
    if pid <= 1:
        raise ProcessError("PID 1 is the system itself")
    if pid in _ancestors(proc):
        raise ProcessError("that is KOS or the shell running it")
    status = _kv(_read(f"{proc}/{pid}/status"))
    if not status:
        raise ProcessError(f"no such process: {pid}")
    owner = int((status.get("Uid") or "0").split()[0])
    if owner != os.getuid():
        raise ProcessError("that process belongs to another user")


def signal_process(authority: Authority, pid: int, name: str, proc: str = "/proc") -> str:
    if name not in SIGNALS:
        raise ProcessError(f"signal must be one of {', '.join(SIGNALS)}")
    _check(pid, proc)
    with authority.authorize("process.signal", f"{pid} {name}"):
        _check(pid, proc)                       # still the same, after the prompt
        try:
            os.kill(pid, SIGNALS[name])
        except ProcessLookupError:
            raise ProcessError(f"{pid} already exited") from None
        except PermissionError as e:
            raise ProcessError(str(e)) from None
    return f"sent {name} to {pid}"


def renice(authority: Authority, pid: int, nice: int, proc: str = "/proc") -> str:
    if not 0 <= nice <= 19:
        raise ProcessError("nice must be between 0 and 19")
    _check(pid, proc)
    with authority.authorize("process.renice", f"{pid} {nice}"):
        _check(pid, proc)
        try:
            os.setpriority(os.PRIO_PROCESS, pid, nice)
        except ProcessLookupError:
            raise ProcessError(f"{pid} already exited") from None
        except PermissionError:
            raise ProcessError("the kernel only lets you lower a priority, not raise it") from None
    return f"priority of {pid} set to nice {nice}"
