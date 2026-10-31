"""``kos backup``: content-addressed, deduplicated backups, behind the password.

This is the OS-side engine for the *backup* app. It lives in the OS rather than
inside the app on purpose: a KOS app is sandboxed - it cannot read your files,
cannot write anything that survives it, and cannot reach the network unless you
allow it - so an app cannot back anything up by itself. The engine reads and
stores; the ``backup`` app (``examples/backup``) is the window onto it and only
*asks* (see ``system.py``).

The model is the one from the Universal Backup System, kept honest:

* **Content-addressed.** A file body is stored once, under its SHA-256, in
  ``<state>/backup/blobs/ab/abcd...``. Adding the same bytes again - under any
  name, any number of times - writes nothing new.
* **Items are the logical files.** The index lists one item per (path, content)
  that was backed up. There is no stored reference count to drift: how many
  items point at a blob is simply counted, and a blob is deleted only when the
  last item pointing at it is removed.
* **Nothing enters unscanned.** Every file is scanned (``scan.py``) *before* it
  is stored. A flagged file is reported and never stored.
* **Password on everything.** ``backup.add``, ``backup.list``, ``backup.remove``
  and ``backup.restore`` each need the password typed for that action.
* **Tamper evident.** The index carries an HMAC under a password-derived key, so
  edited or swapped index entries are refused; every blob is re-hashed when it
  is read, so a modified blob is refused too.
* **Restore is a write.** It goes through the same guarded write as ``kos write``
  (administrator keyboard, scan, optimize) and never overwrites an existing file.

Honest limits: blobs are not encrypted by this module - on a real KOS install
the whole root is LUKS2 and KOS state is mode 0700 - and this vault is local; it
does not sync anywhere.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from .auth import Authority, Grant
from .paths import Paths, atomic_write
from .scan import MAX_SCAN, ScanResult, scan_bytes

INDEX_KEY_LABEL = "backup-index"
MAX_FILE = MAX_SCAN            # a file the scanner can't fully read is not stored
MAX_FILES_PER_ADD = 5000
_ID_LEN = 12


class BackupError(Exception):
    pass


class VaultTamperedError(BackupError):
    pass


@dataclass(frozen=True)
class Item:
    id: str
    path: str
    size: int
    sha256: str
    time: float

    def to_json(self) -> dict:
        return {"id": self.id, "path": self.path, "size": self.size,
                "sha256": self.sha256, "time": self.time}

    @classmethod
    def from_json(cls, d: dict) -> "Item":
        try:
            item = cls(str(d["id"]), str(d["path"]), int(d["size"]), str(d["sha256"]),
                       float(d["time"]))
        except (KeyError, TypeError, ValueError):
            raise VaultTamperedError("backup index has a malformed entry") from None
        if len(item.sha256) != 64 or any(c not in "0123456789abcdef" for c in item.sha256):
            raise VaultTamperedError("backup index has a malformed hash")
        return item


@dataclass
class Stats:
    items: int = 0
    unique_blobs: int = 0
    logical_bytes: int = 0       # what the items add up to
    stored_bytes: int = 0        # what is actually on disk (each body once)

    @property
    def saved_bytes(self) -> int:
        return self.logical_bytes - self.stored_bytes

    def summary(self) -> str:
        return (f"{self.items} item(s), {self.unique_blobs} unique body(ies); "
                f"{self.logical_bytes:,} bytes backed up, {self.stored_bytes:,} stored, "
                f"{self.saved_bytes:,} saved by deduplication")


@dataclass
class AddReport:
    stored: list[Item] = field(default_factory=list)      # new item recorded
    new_bodies: int = 0                                   # ... of which wrote a new blob
    deduplicated: int = 0                                 # ... of which reused a blob
    unchanged: int = 0                                    # same path+content already backed up
    saved_bytes: int = 0                                  # bytes not written thanks to dedup
    flagged: list[tuple[str, str]] = field(default_factory=list)   # (path, rules)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (path, why)

    def summary(self) -> str:
        parts = [f"{len(self.stored)} backed up ({self.new_bodies} new, "
                 f"{self.deduplicated} deduplicated, {self.saved_bytes:,} bytes saved)"]
        if self.unchanged:
            parts.append(f"{self.unchanged} unchanged")
        if self.flagged:
            parts.append(f"{len(self.flagged)} FLAGGED and not stored")
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        return ", ".join(parts)


# --------------------------------------------------------------------------
# The vault on disk
# --------------------------------------------------------------------------

def _blob_path(paths: Paths, digest: str) -> Path:
    return paths.backup / "blobs" / digest[:2] / digest


def _canonical(items: list[Item]) -> bytes:
    return json.dumps([i.to_json() for i in items], sort_keys=True,
                      separators=(",", ":")).encode()


def _mac(key: bytes, items: list[Item]) -> str:
    return hmac.new(key, _canonical(items), hashlib.sha256).hexdigest()


@contextmanager
def _locked(paths: Paths) -> Iterator[None]:
    """One writer at a time: two ``kos backup add`` runs must not lose items."""
    paths.backup.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.backup, 0o700)
    fd = os.open(paths.backup / ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def load_items(paths: Paths, grant: Grant) -> list[Item]:
    """Read the index and verify its seal. Needs a grant: the key comes from the password."""
    index = paths.backup / "index.json"
    if not index.exists():
        return []
    key = grant.key(INDEX_KEY_LABEL)
    try:
        doc = json.loads(index.read_text())
        items = [Item.from_json(d) for d in doc["items"]]
        mac = str(doc["mac"])
    except (OSError, ValueError, KeyError, TypeError):
        raise VaultTamperedError("backup index is unreadable or malformed") from None
    if not hmac.compare_digest(mac, _mac(key, items)):
        raise VaultTamperedError("backup index does not match its seal - refusing to use it")
    return items


def _save_items(paths: Paths, grant: Grant, items: list[Item]) -> None:
    key = grant.key(INDEX_KEY_LABEL)
    doc = {"items": [i.to_json() for i in items], "mac": _mac(key, items)}
    atomic_write(paths.backup / "index.json", json.dumps(doc, indent=1).encode())


def stats_of(paths: Paths, items: list[Item]) -> Stats:
    unique: dict[str, int] = {}
    for i in items:
        unique[i.sha256] = i.size
    return Stats(items=len(items), unique_blobs=len(unique),
                 logical_bytes=sum(i.size for i in items),
                 stored_bytes=sum(unique.values()))


def _read_blob(paths: Paths, item: Item) -> bytes:
    path = _blob_path(paths, item.sha256)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise VaultTamperedError(f"backup body for {item.id} is missing: {e.strerror}") from None
    if hashlib.sha256(data).hexdigest() != item.sha256:
        raise VaultTamperedError(f"backup body for {item.id} was modified - refusing to use it")
    return data


def _store_blob(paths: Paths, digest: str, data: bytes) -> bool:
    """Write the body unless it is already there. True when it was new."""
    path = _blob_path(paths, digest)
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    atomic_write(path, data, mode=0o600)
    return True


# --------------------------------------------------------------------------
# Reading the files to back up
# --------------------------------------------------------------------------

def _guarded(paths: Paths, p: str) -> bool:
    """KOS's own state (password verifier, seals, this vault) is never backed up."""
    real = os.path.realpath(p)
    for g in (paths.etc, paths.state):
        gr = str(Path(os.path.realpath(g)))
        if real == gr or real.startswith(gr + os.sep):
            return True
    return False


def _walk(paths: Paths, sources: list[str], report: AddReport) -> list[str]:
    """Regular files under ``sources``. Symlinks and special files are skipped, never followed."""
    out: list[str] = []

    def visit(p: str, top: bool) -> None:
        if len(out) >= MAX_FILES_PER_ADD:
            return
        try:
            st = os.lstat(p)
        except OSError as e:
            report.skipped.append((p, e.strerror or "unreadable"))
            return
        if _guarded(paths, p):
            report.skipped.append((p, "KOS system state is never backed up"))
        elif stat.S_ISLNK(st.st_mode):
            report.skipped.append((p, "symlink (not followed)"))
        elif stat.S_ISDIR(st.st_mode):
            try:
                names = sorted(os.listdir(p))
            except OSError as e:
                report.skipped.append((p, e.strerror or "unreadable"))
                return
            for n in names:
                visit(os.path.join(p, n), False)
        elif stat.S_ISREG(st.st_mode):
            out.append(p)
        else:
            report.skipped.append((p, "not a regular file"))

    for s in sources:
        visit(os.path.abspath(s), True)
    if len(out) >= MAX_FILES_PER_ADD:
        report.skipped.append(("<more>", f"stopped at {MAX_FILES_PER_ADD} files; add the rest separately"))
    return out


def _read_file(p: str) -> Optional[bytes]:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_FILE + 1)
    finally:
        os.close(fd)
    return data


# --------------------------------------------------------------------------
# The four actions
# --------------------------------------------------------------------------

def add(paths: Paths, authority: Authority, sources: list[str], *,
        scanner: Callable[[bytes, str], ScanResult] = scan_bytes) -> AddReport:
    """Back up files and directories: scan each, then store it once per body."""
    if not sources:
        raise BackupError("nothing to back up: backup add PATH...")
    report = AddReport()
    files = _walk(paths, sources, report)          # refuse before asking for a password
    if not files and not report.skipped:
        raise BackupError("nothing to back up")
    target = sources[0] if len(sources) == 1 else f"{len(sources)} paths"
    with authority.authorize("backup.add", target) as grant, _locked(paths):
        items = load_items(paths, grant)
        have = {(i.path, i.sha256) for i in items}
        for p in files:
            try:
                data = _read_file(p)
            except OSError as e:
                report.skipped.append((p, e.strerror or "unreadable"))
                continue
            if data is None:
                report.skipped.append((p, "not a regular file"))
                continue
            if len(data) > MAX_FILE:
                report.skipped.append((p, f"larger than {MAX_FILE >> 20} MiB"))
                continue
            result = scanner(data, p)
            if not result.clean:
                report.flagged.append((p, ", ".join(sorted({f.rule for f in result.findings}))))
                continue
            digest = hashlib.sha256(data).hexdigest()
            if (p, digest) in have:
                report.unchanged += 1
                continue
            if _store_blob(paths, digest, data):
                report.new_bodies += 1
            else:
                report.deduplicated += 1
                report.saved_bytes += len(data)
            item = Item(secrets.token_hex(_ID_LEN // 2), p, len(data), digest, time.time())
            items.append(item)
            have.add((p, digest))
            report.stored.append(item)
        _save_items(paths, grant, items)
    return report


def snapshot(paths: Paths, authority: Authority, action: str = "backup.list",
             target: str = "") -> tuple[list[Item], Stats]:
    """The index and its numbers (password first). The one read path for
    ``kos backup list`` and for the backup app's request."""
    with authority.authorize(action, target) as grant, _locked(paths):
        items = load_items(paths, grant)
    return items, stats_of(paths, items)


def _find(items: list[Item], ident: str) -> Item:
    hits = [i for i in items if i.id == ident]
    if not hits:
        raise BackupError(f"no backup item {ident!r} (see: backup list)")
    return hits[0]


def remove(paths: Paths, authority: Authority, ident: str) -> tuple[Item, bool]:
    """Forget one item. Its body is deleted only if no other item uses it.
    Returns (item, body_deleted)."""
    with authority.authorize("backup.remove", ident) as grant, _locked(paths):
        items = load_items(paths, grant)
        item = _find(items, ident)
        items = [i for i in items if i.id != ident]
        _save_items(paths, grant, items)               # index first: never point at a deleted body
        shared = any(i.sha256 == item.sha256 for i in items)
        if not shared:
            try:
                _blob_path(paths, item.sha256).unlink()
            except FileNotFoundError:
                pass
        return item, not shared


def fetch(paths: Paths, authority: Authority, ident: str) -> tuple[Item, bytes]:
    """The verified bytes of one item (password first)."""
    with authority.authorize("backup.restore", ident) as grant, _locked(paths):
        items = load_items(paths, grant)
        item = _find(items, ident)
        data = _read_blob(paths, item)
    return item, data


def restore(paths: Paths, authority: Authority, writer_authority: Authority, keyboard,
            ident: str, dest_dir: str, *,
            scanner: Callable[[bytes, str], ScanResult] = scan_bytes, write=None):
    """Put one item back as ``DEST_DIR/<its file name>``. It never overwrites.
    Reading the vault needs the password; writing the file is the guarded
    write (admin keyboard, scan, optimize) and asks for the password again."""
    from .admin import write_file
    write = write or write_file
    dest = Path(os.path.realpath(dest_dir))
    if not dest.is_dir():
        raise BackupError(f"no such directory: {dest_dir}")
    # cheap refusals first, before any password
    keyboard.require_booted()
    item, data = fetch(paths, authority, ident)
    name = os.path.basename(item.path)
    if name in ("", ".", ".."):
        raise BackupError("backup item has no usable file name")
    target = dest / name
    if os.path.lexists(target):
        raise BackupError(f"{target} already exists; restore never overwrites")
    result = scanner(data, str(target))
    if not result.clean:
        raise BackupError(f"backed-up data now scans as flagged ({result.summary()}); not restored")
    return item, write(paths, writer_authority, keyboard, str(target), data)
