"""Per-app durable storage, owned and written by the OS.

The sandbox gives an app one scratch directory that is wiped the moment the
app ends (``cache.py``), so a document editor, a contact manager or a task
list could never keep anything. The vault is the OS-mediated answer, in the
same spirit as every other capability here: the app only *asks* (a ``vault``
command), the OS decides, the OS touches the disk.

* needs the ``storage`` permission in the manifest, and the app must have
  been permitted to run (that is enforced before the session even starts);
* each app sees only its own vault - the name is the OS's, never the app's;
* keys are plain names (no paths, so no traversal), values are text;
* item size, item count and total size are capped.

Shared folders are the same store at a different path; who may open one is decided
by spaces.py and the universal permission store.

Gap, stated honestly: values are stored in clear on the (LUKS2-encrypted)
root volume. They are not sealed with the password-derived key, because the
session does not hold the master key while an app runs.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .paths import Paths, atomic_write
from .summary import summarize

KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_ITEM = 400_000          # characters; keeps one message under the 1 MiB wire limit
MAX_ITEMS = 500
MAX_TOTAL = 64 << 20


class VaultError(Exception):
    pass


class Vault:
    """A folder of named text items. By default an app's private data folder;
    pass ``directory`` for a shared space (see spaces.py)."""

    def __init__(self, paths: Paths, app: str = "", directory: Path | None = None):
        from .appdirs import AppDirs
        self.dir = directory if directory is not None else AppDirs(paths, app).data

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or not KEY_RE.match(key):
            raise VaultError("key must be lowercase letters, digits, '.', '_' or '-'")
        return self.dir / key

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)

    def keys(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.name for p in self.dir.iterdir()
                      if p.is_file() and not p.name.startswith("."))

    def get(self, key: str):
        p = self._path(key)
        try:
            return p.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    def put(self, key: str, value: str) -> None:
        p = self._path(key)
        if not isinstance(value, str) or len(value) > MAX_ITEM:
            raise VaultError(f"value must be text of at most {MAX_ITEM} characters")
        self._ensure()
        data = value.encode("utf-8")
        existing = p.stat().st_size if p.exists() else 0
        if not p.exists() and len(self.keys()) >= MAX_ITEMS:
            raise VaultError(f"vault is full ({MAX_ITEMS} items)")
        total = sum(q.stat().st_size for q in self.dir.iterdir() if q.is_file())
        if total - existing + len(data) > MAX_TOTAL:
            raise VaultError("vault is out of space")
        atomic_write(p, data)
        self._write_summary(key, value)

    def _summary_path(self, key: str) -> Path:
        self._path(key)                                   # same key check
        return self.dir / ".summaries" / f"{key}.txt"

    def _write_summary(self, key: str, value: str) -> None:
        """Every item has a text summary next to it (see summary.py). It is a
        dot-folder, so it is not an item: it is not listed and not counted."""
        sp = self._summary_path(key)
        sp.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(sp.parent, 0o700)
        atomic_write(sp, (summarize(key, value.encode("utf-8")) + "\n").encode("utf-8"))

    def summary(self, key: str):
        """The text summary of an item, or None if there is no such item. An item
        written before summaries existed gets one the first time it is asked for."""
        value = self.get(key)
        if value is None:
            return None
        try:
            return self._summary_path(key).read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            self._write_summary(key, value)
            return self._summary_path(key).read_text(encoding="utf-8").strip()

    def delete(self, key: str) -> bool:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            return False
        try:
            self._summary_path(key).unlink()
        except FileNotFoundError:
            pass
        return True
