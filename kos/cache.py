"""Each running app gets one private, writable scratch directory - and it is
wiped the instant that app's process ends, whether it exited on its own, you
closed it, or KOS shut it down. Nothing an app writes outlives the app.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .paths import Paths


def alloc(paths: Paths, name: str, ram: bool = False) -> Path:
    """A private scratch directory. ``ram=True`` puts it on tmpfs (/dev/shm) so
    an app that has to be unpacked (npm) never touches the disk."""
    if ram and os.access("/dev/shm", os.W_OK):
        base = Path("/dev/shm") / f"kos-{os.getuid()}"
    else:
        base = paths.state / "cache"
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o755 if (ram and os.geteuid() == 0) else 0o700)
    d = base / f"{name}-{secrets.token_hex(4)}"
    d.mkdir(mode=0o700)
    return d


def shm_executable() -> bool:
    """Can a program be run from /dev/shm? (Some systems mount it noexec.)"""
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            f = line.split()
            if len(f) > 3 and f[1] == "/dev/shm":
                return "noexec" not in f[3].split(",") and os.access("/dev/shm", os.W_OK)
    except OSError:
        pass
    return False


def alloc_exec(paths: Paths, name: str) -> Path:
    """A scratch directory a *compiled program* can be written to and run from, owned by whoever the sandbox runs as. It is in RAM
    (tmpfs) when programs may run from there, so what is built never touches the disk."""
    d = alloc(paths, name, ram=shm_executable())
    if os.geteuid() == 0:                                  # development as root: the app runs as 'nobody'
        os.chown(d, 65534, 65534)
        for parent in d.parents:
            if str(parent).startswith(str(paths.root)) or parent == d.parent:
                mode = parent.stat().st_mode
                if not mode & 0o001:
                    os.chmod(parent, mode | 0o001)         # search only: it can reach its own directory, not list the others
    return d


def wipe(cache_dir: Path) -> None:
    """Best-effort secure delete: overwrite every regular file's contents
    before unlinking, then remove the tree. Never raises - a wipe failure
    must not block the app from finishing shutting down."""
    if not cache_dir.exists():
        return
    try:
        for root, dirs, files in os.walk(cache_dir, topdown=False):
            for name in files:
                p = Path(root) / name
                try:
                    size = p.stat().st_size
                    if size:
                        with open(p, "r+b") as f:
                            f.write(os.urandom(min(size, 1 << 20)))
                            f.flush()
                            os.fsync(f.fileno())
                    p.unlink()
                except OSError:
                    pass
            for name in dirs:
                try:
                    (Path(root) / name).rmdir()
                except OSError:
                    pass
        cache_dir.rmdir()
    except OSError:
        pass
