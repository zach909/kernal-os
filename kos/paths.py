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
    def appdata(self) -> Path:
        """One private folder per app lives here: ``appdata/<name>/``. It survives restarts and updates."""
        return self.state / "appdata"

    def data_dir(self, name: str) -> Path:
        """This app's own folder, made on first use. Only that app (inside its sandbox) can write to it; nothing else is
        mounted into it. Removing the app keeps it (reinstalling gets your data back) until you ask to purge it."""
        d = self.appdata / name
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(self.appdata, 0o700)
        os.chmod(d, 0o700)
        if os.geteuid() == 0:                                   # dev/test as root: apps run as 'nobody'
            for parent in (self.appdata, *self.appdata.parents):   # nobody must be able to walk down to its folder
                mode = parent.stat().st_mode
                if not mode & 0o001:
                    os.chmod(parent, mode | 0o001)               # search only: it still cannot list or read them
            os.chown(d, 65534, 65534)
        return d

    def purge_data(self, name: str) -> bool:
        import shutil
        d = self.appdata / name
        if not d.is_dir() or d.is_symlink():
            return False
        shutil.rmtree(d)
        return True

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
