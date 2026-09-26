"""Each running app gets one private, writable scratch directory - and it is
wiped the instant that app's process ends, whether it exited on its own, you
closed it, or KOS shut it down. Nothing an app writes outlives the app.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .paths import Paths


def alloc(paths: Paths, name: str) -> Path:
    base = paths.state / "cache"
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    d = base / f"{name}-{secrets.token_hex(4)}"
    d.mkdir(mode=0o700)
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
