"""A virtual filesystem that lets you ``cd`` straight into a zip file.

KOS never extracts zips (see ``kapp.py``): app archives are run straight from
a sealed memfd. The same rule applies to browsing them. ``VFS`` treats a real
directory tree and any zip files inside it as one continuous tree: crossing
from a real directory into ``something.zip`` is just another ``cd``, and the
zip's own entries become the listing. Nested zips (a zip inside a zip) work
the same way, one level at a time.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from typing import Union

MAX_READ = 4 << 20
ZIP_EXTS = (".zip", ".kapp")


class VFSError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    is_dir: bool
    is_archive: bool  # a file that can itself be `cd`-ed into
    size: int = 0


class _RealDir:
    kind = "real"

    def __init__(self, path):
        self.path = path


class _ZipDir:
    """A directory-like location inside an open (never-extracted) zip."""

    kind = "zip"

    def __init__(self, zf: zipfile.ZipFile, prefix: str, archive_label: str):
        self.zf = zf
        self.prefix = prefix  # "" for the zip root, else "sub/dir/"
        self.archive_label = archive_label  # for display: e.g. "hello.kapp"


Location = Union[_RealDir, _ZipDir]


def _is_archive_name(name: str) -> bool:
    return name.lower().endswith(ZIP_EXTS)


class VFS:
    """Tracks one current location and lets you move around it."""

    def __init__(self, start):
        from pathlib import Path
        self.root = Path(start).resolve()
        if not self.root.is_dir():
            raise VFSError(f"{self.root} is not a directory")
        self._stack: list[Location] = [_RealDir(self.root)]
        self._names: list[str] = [str(self.root)]

    def pwd(self) -> str:
        return "/".join(self._names)

    def in_archive(self) -> bool:
        return self._stack[-1].kind == "zip"

    def _here(self) -> Location:
        return self._stack[-1]

    def list(self) -> list[Entry]:
        here = self._here()
        if here.kind == "real":
            out = []
            for p in sorted(here.path.iterdir(), key=lambda p: p.name.lower()):
                if p.is_dir():
                    out.append(Entry(p.name, True, False))
                else:
                    out.append(Entry(p.name, False, _is_archive_name(p.name), p.stat().st_size))
            return out
        seen: dict[str, Entry] = {}
        plen = len(here.prefix)
        for info in here.zf.infolist():
            name = info.filename
            if not name.startswith(here.prefix) or name == here.prefix:
                continue
            rest = name[plen:]
            if not rest:
                continue
            child, _, more = rest.partition("/")
            if not child or child in seen:
                continue
            is_dir = bool(more) or name.endswith("/")
            seen[child] = Entry(child, is_dir, (not is_dir) and _is_archive_name(child),
                                info.file_size if not is_dir else 0)
        return sorted(seen.values(), key=lambda e: e.name.lower())

    def cd(self, name: str) -> None:
        if name in ("", "."):
            return
        if name == "..":
            self.up()
            return
        entries = {e.name: e for e in self.list()}
        e = entries.get(name)
        if e is None:
            raise VFSError(f"no such entry: {name!r}")
        if not e.is_dir and not e.is_archive:
            raise VFSError(f"{name!r} is not a directory or an archive")
        here = self._here()
        if e.is_archive:
            data = self.read_bytes(name)
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile as exc:
                raise VFSError(f"{name}: not a valid zip: {exc}") from None
            self._stack.append(_ZipDir(zf, "", name))
            self._names.append(name)
            return
        if here.kind == "real":
            self._stack.append(_RealDir(here.path / name))
        else:
            self._stack.append(_ZipDir(here.zf, here.prefix + name + "/", here.archive_label))
        self._names.append(name)

    def up(self) -> None:
        if len(self._stack) == 1:
            raise VFSError("already at the top")
        self._stack.pop()
        self._names.pop()

    def read_bytes(self, name: str) -> bytes:
        entries = {e.name: e for e in self.list()}
        e = entries.get(name)
        if e is None or e.is_dir:
            raise VFSError(f"no such file: {name!r}")
        if e.size > MAX_READ:
            raise VFSError(f"{name!r} is too large to view")
        here = self._here()
        if here.kind == "real":
            return (here.path / name).read_bytes()
        with here.zf.open(here.prefix + name) as f:
            data = f.read(MAX_READ + 1)
        if len(data) > MAX_READ:
            raise VFSError(f"{name!r} is too large to view")
        return data
