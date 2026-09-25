"""The ``.kapp`` app format: a plain zip file that is never unzipped.

An app is installed by copying the zip as-is into the store. At run time the
zip bytes are loaded into a sealed in-memory file and executed from there
(see ``loader.py``); no file inside the archive is ever written to disk.

Why this is a security feature and not just a quirk:

* One file = one hash. The whole app is covered by a single seal, so there is
  no directory of loose files that something could modify after install.
* Nothing to clean up, nothing left behind, no permissions on extracted files
  to get wrong, no path-traversal on extraction (because there is none).

Even though we never extract, the archive is still hostile input, so it is
validated strictly: bounded size, bounded entry count, no zip bombs, no
encrypted entries, no absolute or ``..`` paths, no duplicate names.

Layout::

    manifest.json        required, see Manifest
    <entry>              python module (e.g. app.py) or a static ELF binary
    ...                  any other resources the app reads via the SDK
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST = "manifest.json"
MAX_ARCHIVE = 512 << 20
MAX_ENTRIES = 4096
MAX_UNCOMPRESSED = 1 << 30
MAX_RATIO = 200
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
RESERVED_NAMES = {"graphical", "kos", "system", "all"}
RUNTIMES = {"python", "native"}
MODES = {"tui", "graphical"}
PERMISSIONS = {"network"}
_MANIFEST_KEYS = {"name", "version", "runtime", "entry", "modes", "permissions", "description"}


class KAppError(Exception):
    pass


@dataclass(frozen=True)
class Manifest:
    name: str
    version: str
    runtime: str
    entry: str
    modes: tuple[str, ...] = ("tui",)
    permissions: tuple[str, ...] = ()
    description: str = ""

    @classmethod
    def parse(cls, raw: bytes) -> "Manifest":
        try:
            d = json.loads(raw)
        except ValueError as e:
            raise KAppError(f"manifest.json is not valid JSON: {e}") from None
        if not isinstance(d, dict):
            raise KAppError("manifest.json must be an object")
        unknown = set(d) - _MANIFEST_KEYS
        if unknown:
            raise KAppError(f"unknown manifest keys: {sorted(unknown)}")
        for k in ("name", "version", "runtime", "entry"):
            if not isinstance(d.get(k), str) or not d[k]:
                raise KAppError(f"manifest.{k} must be a non-empty string")
        name = d["name"]
        if not NAME_RE.match(name) or name in RESERVED_NAMES:
            raise KAppError(f"invalid or reserved app name {name!r}")
        if not re.match(r"^[0-9A-Za-z.+-]{1,32}$", d["version"]):
            raise KAppError("invalid version string")
        if d["runtime"] not in RUNTIMES:
            raise KAppError(f"runtime must be one of {sorted(RUNTIMES)}")
        modes = tuple(d.get("modes", ["tui"]))
        if not modes or not set(modes) <= MODES or not all(isinstance(m, str) for m in modes):
            raise KAppError(f"modes must be a non-empty subset of {sorted(MODES)}")
        perms = tuple(d.get("permissions", []))
        if not set(perms) <= PERMISSIONS:
            raise KAppError(f"permissions must be a subset of {sorted(PERMISSIONS)}")
        desc = d.get("description", "")
        if not isinstance(desc, str) or len(desc) > 200:
            raise KAppError("description must be a string of at most 200 characters")
        if d["runtime"] == "python" and not re.match(
                r"^[A-Za-z_][\w.]*(:[A-Za-z_]\w*)?$", d["entry"]):
            raise KAppError("python entry must look like 'module' or 'module:function'")
        return cls(name=name, version=d["version"], runtime=d["runtime"], entry=d["entry"],
                   modes=modes, permissions=perms, description=desc)


def _check_member_name(n: str) -> None:
    if (not n or n.startswith("/") or "\\" in n or "\x00" in n
            or any(part in ("..", ".") for part in n.rstrip("/").split("/"))):
        raise KAppError(f"illegal path in archive: {n!r}")


class KApp:
    """A validated, in-memory view of a .kapp archive."""

    def __init__(self, data: bytes):
        if len(data) > MAX_ARCHIVE:
            raise KAppError("archive too large")
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        try:
            self._zip = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise KAppError(f"not a zip file: {e}") from None
        self._validate()
        self.manifest = Manifest.parse(self.read(MANIFEST, limit=64 << 10))
        self._check_entry()

    @classmethod
    def from_file(cls, path: Path) -> "KApp":
        with open(path, "rb") as f:
            data = f.read(MAX_ARCHIVE + 1)
        return cls(data)

    def _validate(self) -> None:
        infos = self._zip.infolist()
        if len(infos) > MAX_ENTRIES:
            raise KAppError("too many entries")
        seen: set[str] = set()
        total = 0
        for i in infos:
            _check_member_name(i.filename)
            if i.filename in seen:
                raise KAppError(f"duplicate entry {i.filename!r}")
            seen.add(i.filename)
            if i.flag_bits & 0x1:
                raise KAppError("encrypted entries are not allowed")
            if i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise KAppError("only stored/deflated entries are allowed")
            if stat.S_ISLNK(i.external_attr >> 16):
                raise KAppError("symlinks are not allowed")
            total += i.file_size
            if i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
                raise KAppError(f"suspicious compression ratio for {i.filename!r}")
        if total > MAX_UNCOMPRESSED:
            raise KAppError("archive expands to more than 1 GiB")
        if MANIFEST not in seen:
            raise KAppError("missing manifest.json")
        self._names = seen

    def _check_entry(self) -> None:
        m = self.manifest
        if m.runtime == "python":
            mod = m.entry.split(":")[0].replace(".", "/")
            if f"{mod}.py" not in self._names and f"{mod}/__init__.py" not in self._names:
                raise KAppError(f"entry module {m.entry!r} not found in archive")
        elif m.entry not in self._names:
            raise KAppError(f"entry binary {m.entry!r} not found in archive")

    def names(self) -> list[str]:
        return sorted(self._names)

    def read(self, name: str, limit: int = MAX_UNCOMPRESSED) -> bytes:
        _check_member_name(name)
        try:
            info = self._zip.getinfo(name)
        except KeyError:
            raise KAppError(f"no such entry {name!r}") from None
        if info.file_size > limit:
            raise KAppError(f"{name!r} is too large")
        with self._zip.open(info) as f:
            out = f.read(limit + 1)
        if len(out) > limit:
            raise KAppError(f"{name!r} is too large")
        return out


def pack(src: Path, out: Path) -> Manifest:
    """Build a reproducible .kapp from a directory (same input → same bytes)."""
    src = Path(src)
    files = []
    for root, dirs, names in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not d.startswith("."))
        for n in sorted(names):
            p = Path(root) / n
            if n.startswith(".") or n.endswith(".pyc"):
                continue
            if p.is_symlink():
                raise KAppError(f"refusing to pack symlink {p}")
            files.append(p)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in files:
            rel = p.relative_to(src).as_posix()
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if os.access(p, os.X_OK) else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            z.writestr(zi, p.read_bytes())
    data = buf.getvalue()
    app = KApp(data)  # validate exactly what we are about to ship
    Path(out).write_bytes(data)
    return app.manifest


SEAL_CONTEXT = b"kos-kapp-seal-v1\x00"


def compute_seal(key: bytes, name: str, version: str, sha256_hex: str) -> str:
    msg = SEAL_CONTEXT + b"\x00".join([name.encode(), version.encode(), sha256_hex.encode()])
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
