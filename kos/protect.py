"""Protected directories: not just watched, *locked*.

``kos scan watch DIR`` (in ``watch.py``) only ever noticed a write after it
already happened - useful, but not a block. A protected directory is
different: it is kept with its write bit off (mode 0500 - read and list, no
write) so the kernel itself refuses to create, write, or move a file into it
for anyone, including the owner. `kos scan watch` is the only thing that
turns the write bit back on, and only for as long as it is actively running
and scanning every file that lands there; the moment it stops - Ctrl-C,
crash, anything - the directory is relocked in a ``finally``, no exceptions.

That is the literal answer to "it needs your password to start, but it will
block you from moving a file in if you don't let it start": before you ever
run the watcher, the directory is already locked (protecting it locks it
immediately); starting the watcher is what unlocks it, and only while the
watcher is the one standing there scanning everything that arrives.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .auth import Authority
from .paths import Paths, atomic_write

LOCKED_MODE = 0o500  # r-x for the owner, nothing for anyone else: no write, no create
UNLOCKED_MODE = 0o700


class ProtectError(Exception):
    pass


@dataclass(frozen=True)
class Protected:
    path: str


class ProtectStore:
    def __init__(self, paths: Paths):
        self.file = paths.state / "protected.json"

    def _read(self) -> list[str]:
        try:
            return json.loads(self.file.read_text())
        except FileNotFoundError:
            return []

    def _write(self, dirs: list[str]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(sorted(set(dirs)), indent=2).encode())

    def list(self) -> list[Protected]:
        return [Protected(p) for p in self._read()]

    def is_protected(self, directory: str) -> bool:
        return os.path.realpath(directory) in self._read()

    def protect(self, directory: str, authority: Authority) -> None:
        real = os.path.realpath(directory)
        if not os.path.isdir(real):
            raise ProtectError(f"not a directory: {directory}")
        with authority.authorize("scan.protect", real):
            dirs = self._read()
            if real not in dirs:
                dirs.append(real)
                self._write(dirs)
            lock(real)

    def unprotect(self, directory: str, authority: Authority, *, unlock_too: bool = True) -> None:
        real = os.path.realpath(directory)
        with authority.authorize("scan.unprotect", real):
            dirs = [d for d in self._read() if d != real]
            self._write(dirs)
            if unlock_too and os.path.isdir(real):
                unlock(real)


def lock(directory: str) -> None:
    """Turn off write access. Idempotent, and never breaks a directory that
    was already stricter than this for some other reason."""
    st = os.stat(directory)
    if stat.S_IMODE(st.st_mode) & 0o700 != 0o700:
        return  # already stricter than our own "unlocked" state; leave it alone
    os.chmod(directory, LOCKED_MODE)


def unlock(directory: str) -> None:
    os.chmod(directory, UNLOCKED_MODE)


class held_unlock:
    """Context manager: unlock a protected directory for exactly as long as
    something is actively watching it, then relock unconditionally."""

    def __init__(self, directory: str, protected: bool):
        self.directory = directory
        self.protected = protected

    def __enter__(self) -> "held_unlock":
        if self.protected:
            unlock(self.directory)
        return self

    def __exit__(self, *exc) -> None:
        if self.protected:
            lock(self.directory)
