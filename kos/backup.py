"""Backups: a document, or a folder of them, copied into one zip kept under
KOS's own state directory.

* ``create`` needs the password (``backup.create``). The zip is written, and
  ``requires.RULES`` says a backup owes a **security scan** afterwards - done
  right away; a flagged backup is moved to quarantine and refused.
* Backups live where only KOS writes (``<state>/backups``), so a program
  running as you cannot quietly rewrite your safety copy through KOS.
* Nothing is extracted to look inside one: ``kos ls`` / the Files app walk into
  the zip like any other folder.
* ``restore_member`` hands one file back to the guarded write
  (``admin.write_file``): administrator keyboard, password, scan, optimize.
"""

from __future__ import annotations

import io
import os
import re
import time
import zipfile
from pathlib import Path
from typing import Optional

from .admin import AdminError, AuditLog, Ledger, WriteBlocked, _discharge, _quarantine
from .auth import Authority
from .paths import Paths, atomic_write
from .scan import scan_bytes

MAX_FILES = 2000
MAX_BYTES = 64 << 20
MAX_MEMBER = 16 << 20
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}\.zip$")


class BackupError(AdminError):
    pass


def backup_dir(paths: Paths) -> Path:
    return paths.state / "backups"


def _gather(src: Path) -> list[tuple[Path, str]]:
    base = src.parent
    files: list[tuple[Path, str]] = []
    if src.is_file():
        return [(src, src.name)]
    for root, dirs, names in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
        for n in sorted(names):
            p = Path(root) / n
            if p.is_symlink() or not p.is_file():
                continue
            files.append((p, p.relative_to(base).as_posix()))
            if len(files) > MAX_FILES:
                raise BackupError(f"more than {MAX_FILES} files; back up a smaller folder")
    return files


def create(paths: Paths, authority: Authority, source: str, *,
           ledger: Optional[Ledger] = None, now=time.time) -> dict:
    """Back ``source`` (a file or folder) up. Returns {name, path, files, size}."""
    ledger = ledger or Ledger(paths)
    src = Path(os.path.realpath(source))
    guarded = [Path(os.path.realpath(paths.etc)), Path(os.path.realpath(paths.state))]
    if any(src == g or g in src.parents for g in guarded):
        raise BackupError("KOS system state is not backed up this way")
    if not src.exists():
        raise BackupError(f"no such file or folder: {source}")
    files = _gather(src)
    if not files:
        raise BackupError("nothing to back up")
    total = sum(p.stat().st_size for p, _ in files)
    if total > MAX_BYTES:
        raise BackupError(f"{total >> 20} MiB is more than the {MAX_BYTES >> 20} MiB limit")
    with authority.authorize("backup.create", str(src)):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p, arc in files:
                z.write(p, arc)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now()))
        name = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)[:60] + f"-{stamp}.zip"
        dest = backup_dir(paths) / name
        paths.ensure()
        backup_dir(paths).mkdir(parents=True, exist_ok=True)
        os.chmod(backup_dir(paths), 0o700)
        atomic_write(dest, buf.getvalue())
        entry_id = ledger.owe("backup.create", str(dest))
        audit = AuditLog(paths)
        audit.record("backup.create", str(src), "written")
        entry = next(e for e in ledger.owed("backup.create") if e["id"] == entry_id)
        flagged = _discharge(paths, ledger, entry, scanner=scan_bytes,
                             optimize_once=lambda: None, audit=audit)
    if flagged is not None:
        raise WriteBlocked(flagged)
    return {"name": name, "path": str(dest), "files": len(files), "size": dest.stat().st_size}


def list_backups(paths: Paths) -> list[dict]:
    out = []
    d = backup_dir(paths)
    for f in sorted(d.glob("*.zip")) if d.exists() else []:
        try:
            with zipfile.ZipFile(f) as z:
                n = len(z.namelist())
        except zipfile.BadZipFile:
            n = -1
        out.append({"name": f.name, "path": str(f), "size": f.stat().st_size,
                    "t": f.stat().st_mtime, "files": n})
    return out


def read_member(paths: Paths, backup: str, member: str) -> bytes:
    if not NAME_RE.match(backup):
        raise BackupError("not a backup name")
    if (not member or member.startswith("/") or "\\" in member or "\x00" in member
            or any(p in ("..", ".") for p in member.split("/"))):
        raise BackupError("not a path inside the backup")
    f = backup_dir(paths) / backup
    if not f.is_file():
        raise BackupError(f"no such backup: {backup}")
    with zipfile.ZipFile(f) as z:
        try:
            info = z.getinfo(member)
        except KeyError:
            raise BackupError(f"{member} is not in {backup}") from None
        if info.file_size > MAX_MEMBER:
            raise BackupError("that file is too large to restore this way")
        return z.read(info)
