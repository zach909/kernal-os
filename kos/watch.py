"""A file-write watcher that scans on write - started with your password,
like a kernel cell, and running only until you stop it. That's the resolve
to a real tension: KOS's one rule is nothing acts without your password, and
a scanner that silently watches every write forever would be exactly the kind
of autonomous background thing that rule forbids. So starting the watch is
the privileged action you authorize once; what it does with that
authorization (run the same static scanner on every file it sees written or
moved in) is bounded, visible in `kos activity`, and stopped the same way a
cell is stopped - `kos scan stop`, or it dies with your session.

Uses inotify directly (ctypes; Python's stdlib has no binding for it).
"""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import signal
import struct
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .paths import Paths, atomic_write
from .scan import ScanResult, scan_file

_libc = ctypes.CDLL(None, use_errno=True)

SYS_inotify_init1 = 294
SYS_inotify_add_watch = 254
SYS_inotify_rm_watch = 255

IN_CLOEXEC = 0o2000000
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_IGNORED = 0x00008000
WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE

_EVENT = struct.Struct("iIII")  # struct inotify_event header: wd, mask, cookie, len


class WatchError(RuntimeError):
    pass


def _syscall(nr: int, *args) -> int:
    r = _libc.syscall(ctypes.c_long(nr), *args)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


@dataclass
class ScanHit:
    path: str
    result: ScanResult


class Watcher:
    """Watches a set of directories (non-recursive per entry - pass each
    directory you want covered) and scans every file that's written,
    created, or moved into one of them."""

    def __init__(self, paths: list[str]):
        self.fd = _syscall(SYS_inotify_init1, ctypes.c_int(IN_CLOEXEC))
        self._wd_to_dir: dict[int, str] = {}
        for p in paths:
            wd = _syscall(SYS_inotify_add_watch, ctypes.c_int(self.fd),
                          str(p).encode() + b"\0", ctypes.c_uint32(WATCH_MASK))
            self._wd_to_dir[wd] = str(p)
        if not self._wd_to_dir:
            raise WatchError("no directories to watch")

    def fileno(self) -> int:
        return self.fd

    def read_events(self) -> list[str]:
        """Read whatever inotify has buffered; returns full paths of files
        that were written/created/moved-in."""
        try:
            raw = os.read(self.fd, 64 * (_EVENT.size + 256))
        except BlockingIOError:
            return []
        out = []
        off = 0
        while off + _EVENT.size <= len(raw):
            wd, mask, cookie, name_len = _EVENT.unpack_from(raw, off)
            off += _EVENT.size
            name = raw[off:off + name_len].split(b"\0", 1)[0].decode(errors="replace")
            off += name_len
            if mask & IN_IGNORED or wd not in self._wd_to_dir:
                continue
            if name:
                out.append(os.path.join(self._wd_to_dir[wd], name))
        return out

    def close(self) -> None:
        os.close(self.fd)


def run_watch(paths: list[str], on_hit: Callable[[ScanHit], None],
             should_stop: Callable[[], bool], on_scan: Optional[Callable[[str], None]] = None,
             poll_timeout: float = 1.0) -> None:
    """Blocking loop: scan every file the watcher reports until `should_stop`
    returns True. `on_hit` is called only for files the scanner flags;
    `on_scan` (optional) is called for every file scanned, clean or not."""
    import select

    w = Watcher(paths)
    try:
        while not should_stop():
            r, _, _ = select.select([w.fd], [], [], poll_timeout)
            if not r:
                continue
            for path in w.read_events():
                if not os.path.isfile(path):
                    continue
                try:
                    result = scan_file(Path(path))
                except OSError:
                    continue
                if on_scan:
                    on_scan(path)
                if not result.clean:
                    on_hit(ScanHit(path, result))
    finally:
        w.close()


def quarantine_hit(paths: Paths, hit: ScanHit) -> str:
    """Move a flagged file out of harm's way. Shared by the foreground and
    background forms of `kos scan watch` so both quarantine the same way."""
    qdir = paths.state / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    qpath = qdir / f"{Path(hit.path).name}-{int(time.time())}"
    os.replace(hit.path, qpath)
    return str(qpath)


# --- background watch jobs: same fork+daemonize+registry pattern as `kos open` ---

@dataclass
class WatchJob:
    id: str
    dirs: list[str]
    protected_dirs: list[str] = field(default_factory=list)
    pid: int = 0
    log_path: str = ""
    started: float = 0.0
    status: str = "starting"  # starting -> running -> exited


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


class WatchRegistry:
    def __init__(self, paths: Paths):
        self.dir = paths.state / "watchjobs"

    def new_id(self) -> str:
        return f"watch-{secrets.token_hex(3)}"

    def _file(self, job_id: str) -> Path:
        if "/" in job_id or job_id in ("", ".", ".."):
            raise WatchError(f"invalid watch job id {job_id!r}")
        return self.dir / f"{job_id}.json"

    def write(self, job: WatchJob) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        atomic_write(self._file(job.id), json.dumps(asdict(job), indent=2).encode())

    def get(self, job_id: str) -> WatchJob:
        try:
            return WatchJob(**json.loads(self._file(job_id).read_text()))
        except FileNotFoundError:
            raise WatchError(f"no such watch job {job_id!r}") from None

    def remove(self, job_id: str) -> None:
        try:
            self._file(job_id).unlink()
        except FileNotFoundError:
            pass

    def list(self) -> list[WatchJob]:
        if not self.dir.exists():
            return []
        out = []
        for f in sorted(self.dir.glob("*.json")):
            try:
                job = WatchJob(**json.loads(f.read_text()))
            except (ValueError, TypeError, KeyError):
                continue
            if job.status != "exited" and not _alive(job.pid):
                job.status = "exited"
            out.append(job)
        return out


def spawn_background(dirs: list[str], protected_dirs: list[str], paths: Paths,
                     log_path: Path) -> WatchJob:
    """Fork a background watch job. The parent returns immediately with the
    job record (your shell comes back); the child becomes the detached
    watcher, unlocking any protected directories for as long as it runs and
    relocking them - via the same `finally` a foreground watch uses - the
    instant it stops, by any path (`kos scan stop`, crash, anything)."""
    from .broker import daemonize
    from .protect import held_unlock

    registry = WatchRegistry(paths)
    job_id = registry.new_id()
    pid = os.fork()
    if pid:  # parent
        job = WatchJob(id=job_id, dirs=dirs, protected_dirs=protected_dirs, pid=pid,
                       log_path=str(log_path), started=time.time(), status="running")
        registry.write(job)
        return job
    # child: becomes the watcher
    try:
        daemonize(log_path)
        stop = {"flag": False}

        def handle_sigterm(signum, frame):
            stop["flag"] = True

        signal.signal(signal.SIGTERM, handle_sigterm)
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # only `kos scan stop` stops this

        def on_hit(hit: ScanHit) -> None:
            try:
                where = quarantine_hit(paths, hit)
                print(f"FLAGGED {hit.path}: {hit.result.summary()} - quarantined to {where}")
            except OSError as e:
                print(f"FLAGGED {hit.path}: {hit.result.summary()} - "
                     f"could NOT quarantine ({e})")

        contexts = [held_unlock(d, d in protected_dirs) for d in dirs]
        try:
            for ctx in contexts:
                ctx.__enter__()
            run_watch(dirs, on_hit, lambda: stop["flag"])
        finally:
            for ctx in reversed(contexts):
                ctx.__exit__(None, None, None)
            registry.remove(job_id)
    except BaseException as e:  # pragma: no cover - last-resort crash path
        print(f"kos-watch: {e!r}")
        registry.remove(job_id)
        os._exit(1)
    os._exit(0)
