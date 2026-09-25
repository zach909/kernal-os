"""Filesystem layout.

On a real KOS install everything lives under ``/`` (which is the LUKS2-encrypted
root unlocked by the pre-boot environment). For development on an ordinary
Linux host, set ``KOS_ROOT`` to a directory and the same layout is created
there.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    root: Path

    @classmethod
    def from_env(cls) -> "Paths":
        return cls(Path(os.environ.get("KOS_ROOT", "/")).resolve())

    @property
    def etc(self) -> Path:
        return self.root / "etc" / "kos"

    @property
    def state(self) -> Path:
        return self.root / "var" / "lib" / "kos"

    @property
    def apps(self) -> Path:
        return self.state / "apps"

    @property
    def logs(self) -> Path:
        return self.state / "log"

    @property
    def cells(self) -> Path:
        return self.state / "cells"

    @property
    def auth_file(self) -> Path:
        return self.etc / "auth.json"

    def ensure(self) -> None:
        for d in (self.etc, self.state, self.apps, self.logs, self.cells):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` so readers see either the old or new file."""
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
