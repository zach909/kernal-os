"""File-system changes: make a folder, delete (to the trash), rename, chmod.

``file.change`` *requires* the administrator keyboard (``requires.RULES``) and
the password. Guards, whoever asks:

* KOS system state (``/etc/kos``, the state directory) is never touched;
* delete never destroys: it moves to ``<state>/trash`` (``kos optimize``
  empties old trash), so a wrong click is recoverable;
* a mount point, ``/``, or anything that contains KOS state cannot be moved;
* rename refuses to overwrite; chmod refuses setuid/setgid bits (a classic
  way to make a program run with someone else's power).
"""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Optional

from .admin import AdminError, AdminKeyboard, requirements
from .auth import Authority
from .paths import Paths
from .requires import Unsatisfied

OPS = ("mkdir", "trash", "rename", "chmod")
MODE_RE = re.compile(r"^[0-7]{3,4}$")
TRASH_KEEP_S = 30 * 24 * 3600


class FsChangeError(AdminError):
    pass


def trash_dir(paths: Paths) -> Path:
    return paths.state / "trash"


def _guard(paths: Paths, p: Path) -> None:
    for g in (Path(os.path.realpath(paths.etc)), Path(os.path.realpath(paths.state))):
        if p == g or g in p.parents or p in g.parents:
            raise FsChangeError("KOS system state (or a folder holding it) cannot be changed this way")
    if str(p) == "/" or os.path.ismount(p):
        raise FsChangeError("not a mount point or the root")


def change(paths: Paths, authority: Authority, keyboard: AdminKeyboard, op: str, path: str, *,
           to: Optional[str] = None, mode: Optional[str] = None) -> str:
    if op not in OPS:
        raise FsChangeError(f"operation must be one of {', '.join(OPS)}")
    try:
        requirements(keyboard).ensure("file.change")      # before any password
    except Unsatisfied as e:
        raise FsChangeError(str(e)) from None
    parent = Path(os.path.realpath(os.path.dirname(os.path.abspath(path)) or "/"))
    name = os.path.basename(os.path.abspath(path))
    if not name or name in (".", ".."):
        raise FsChangeError("not a file or folder name")
    target = parent / name
    _guard(paths, target) if op != "mkdir" else _guard(paths, target)
    if op != "mkdir" and not os.path.lexists(target):
        raise FsChangeError(f"no such file or folder: {path}")
    if op == "mkdir" and os.path.lexists(target):
        raise FsChangeError("that already exists")
    new = None
    if op == "rename":
        if not to or os.path.basename(to) in ("", ".", ".."):
            raise FsChangeError("rename needs a new name")
        new = Path(os.path.realpath(os.path.dirname(os.path.abspath(to)) or "/")) / os.path.basename(to)
        _guard(paths, new)
        if os.path.lexists(new):
            raise FsChangeError("something with that name already exists")
    bits = 0
    if op == "chmod":
        if not mode or not MODE_RE.match(mode):
            raise FsChangeError("mode must be octal like 644 or 0755")
        bits = int(mode, 8)
        if bits & 0o6000:
            raise FsChangeError("setuid/setgid bits are refused")
        if os.path.islink(target):
            raise FsChangeError("not changing the permissions of a symlink")
    with authority.authorize("file.change", f"{op} {target}"):
        if op == "mkdir":
            os.mkdir(target, 0o700)
            return f"made folder {target}"
        if op == "chmod":
            os.chmod(target, bits)
            return f"{target} is now {mode}"
        if op == "rename":
            os.rename(target, new)
            return f"renamed {target} to {new}"
        td = trash_dir(paths)
        td.mkdir(parents=True, exist_ok=True)
        os.chmod(td, 0o700)
        dest = td / f"{int(time.time())}-{name}"
        shutil.move(str(target), dest)
        return f"moved {target} to the trash ({dest.name})"


def empty_old_trash(paths: Paths, now: float = None) -> int:
    """Called by ``kos optimize``: forget trash older than the retention window."""
    now = now or time.time()
    removed = 0
    td = trash_dir(paths)
    for item in td.iterdir() if td.exists() else []:
        if now - item.stat().st_mtime > TRASH_KEEP_S:
            shutil.rmtree(item) if item.is_dir() and not item.is_symlink() else item.unlink()
            removed += 1
    return removed
