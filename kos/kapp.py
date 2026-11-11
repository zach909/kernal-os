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
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}\Z")   # \Z, not $: "$" lets a trailing newline through
# A program's id is its folder path under the app, joined with dots: ``backup.add`` is the program
# in ``apps/backup/add/``. A plain app name can never contain a dot, so a program id can never
# collide with, or pass for, an ordinary app. The id is identity only: it confers no authority.
MAX_DEPTH = 4
ID_PATTERN = r"[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){0,%d}" % (MAX_DEPTH - 1)
ID_RE = re.compile(rf"^{ID_PATTERN}\Z")
RESERVED_NAMES = {"graphical", "kos", "system", "all"}
RUNTIMES = {"python", "native"}
MODES = {"tui", "graphical", "cmd"}
# ``cookies`` and ``passwords`` each unlock one separate, OS-owned store (see vault.py / spaces.py).
# They are not part of ``storage``: an app that keeps notes cannot read a cookie jar or saved logins.
PERMISSIONS = {"network", "system", "storage", "ai", "cookies", "passwords"}
# A program may ask the OS for exactly one thing at a time: ``ask:ACTION``. ``system`` is every
# action at once (including opening and closing other apps) and stays all-or-nothing; the actions
# that touch other apps (open, close, focus) are deliberately not available one by one.
ASK_ACTIONS = ("apps", "backup", "backup_add", "backup_remove")
ASK_PREFIX = "ask:"
SPACE_PERM_RE = re.compile(r"^(owns|uses):[a-z][a-z0-9-]{0,31}$")
_MANIFEST_KEYS = {"name", "version", "runtime", "entry", "modes", "permissions", "description",
                  "kind", "extends"}

# Everything is an app, and an app has exactly one kind:
#   app        an ordinary app
#   extension  an app that adds to another ordinary app, like a browser extension
#   mod        an app that modifies a system app (the taskbar, the App Library)
# An extension or a mod is still a .kapp: installed, scanned, sealed, permitted and opened like any other.
KINDS = ("app", "extension", "mod")
SYSTEM_APP_NAMES = ("taskbar", "app-library")
EXTENSION_FILE = "extension.json"


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
    kind: str = "app"
    extends: str = ""

    @property
    def parent(self) -> str:
        """The app this is a program of (``backup`` for ``backup.add``), or ``""``."""
        return self.name.rpartition(".")[0]

    @property
    def asks(self) -> tuple[str, ...]:
        """The single OS requests this program may make (``ask:`` permissions, prefix removed)."""
        return tuple(p[len(ASK_PREFIX):] for p in self.permissions if p.startswith(ASK_PREFIX))

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
        if not ID_RE.match(name) or name in RESERVED_NAMES:
            raise KAppError(f"invalid or reserved app name {name!r}")
        if not re.match(r"^[0-9A-Za-z.+-]{1,32}$", d["version"]):
            raise KAppError("invalid version string")
        if d["runtime"] not in RUNTIMES:
            raise KAppError(f"runtime must be one of {sorted(RUNTIMES)}")
        modes = tuple(d.get("modes", ["tui"]))
        if not modes or not set(modes) <= MODES or not all(isinstance(m, str) for m in modes):
            raise KAppError(f"modes must be a non-empty subset of {sorted(MODES)}")
        perms = tuple(d.get("permissions", []))
        for perm in perms:
            if perm in PERMISSIONS or SPACE_PERM_RE.match(str(perm)):
                continue
            if isinstance(perm, str) and perm.startswith(ASK_PREFIX) and perm[len(ASK_PREFIX):] in ASK_ACTIONS:
                continue
            raise KAppError(f"unknown permission {perm!r}: use {sorted(PERMISSIONS)}, "
                            f"'ask:ACTION' (one of {', '.join(ASK_ACTIONS)}), "
                            "'owns:NAME' (create a shared folder) or 'uses:NAME' (look for one)")
        desc = d.get("description", "")
        if not isinstance(desc, str) or len(desc) > 200:
            raise KAppError("description must be a string of at most 200 characters")
        if d["runtime"] == "python" and not re.match(
                r"^[A-Za-z_][\w.]*(:[A-Za-z_]\w*)?$", d["entry"]):
            raise KAppError("python entry must look like 'module' or 'module:function'")
        kind, extends = d.get("kind", "app"), d.get("extends", "")
        if kind not in KINDS:
            raise KAppError(f"kind must be one of {list(KINDS)}")
        if "." in name and kind != "app":
            raise KAppError(f"only an ordinary app can be a program inside another app; "
                            f"a {kind} is named with a plain name")
        if kind == "app":
            if "extends" in d:
                raise KAppError("only an extension or a mod says what it extends")
        else:
            if not isinstance(extends, str) or not NAME_RE.match(extends) or extends == name:
                raise KAppError(f"a {kind} must say which other app it extends: \"extends\": \"NAME\"")
            if kind == "extension" and extends in SYSTEM_APP_NAMES:
                raise KAppError(f"an extension adds to an ordinary app; {extends} is a system app "
                                f"- to change it write a mod")
            if kind == "mod" and extends not in SYSTEM_APP_NAMES:
                raise KAppError(f"a mod modifies a system app ({', '.join(SYSTEM_APP_NAMES)}); "
                                f"{extends} is an ordinary app - to add to it write an extension")
            for power in ("system", "ai"):
                # The power to open and close apps, or to send text to a model, must never ride in on an add-on.
                if power in perms:
                    raise KAppError(f"a {kind} cannot ask for the '{power}' permission")
            if "system" in perms or any(str(p).startswith(ASK_PREFIX) for p in perms):
                # The power to open and close apps, or to ask the OS for anything, must never
                # ride in on an add-on.
                raise KAppError(f"a {kind} cannot ask for the 'system' permission or any 'ask:' permission")
        return cls(name=name, version=d["version"], runtime=d["runtime"], entry=d["entry"],
                   modes=modes, permissions=perms, description=desc, kind=kind, extends=extends)


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
        self.contributions = self._check_kind()

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

    def _check_kind(self) -> dict:
        """An app is exactly what its manifest says. An extension or a mod must ship its
        contributions as *data* (``extension.json``, validated here, never run); an ordinary
        app must not carry one."""
        has = EXTENSION_FILE in self._names
        if self.manifest.kind == "app":
            if has:
                raise KAppError(f"{EXTENSION_FILE} belongs to an extension or a mod, not an ordinary app")
            return {}
        if not has:
            raise KAppError(f"a {self.manifest.kind} must contain {EXTENSION_FILE}")
        from .extensions import parse_contributions      # lazy: extensions builds on this module
        return parse_contributions(self.read(EXTENSION_FILE, limit=64 << 10), self.manifest.kind)

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


def pack(src: Path, out: Path, skip_dirs: frozenset = frozenset()) -> Manifest:
    """Build a reproducible .kapp from a directory (same input → same bytes).
    ``skip_dirs`` are sub-directories left out (the folders of a program's own sub-programs)."""
    src = Path(src)
    files = []
    for root, dirs, names in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not d.startswith(".")
                         and Path(root, d) not in skip_dirs)
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


# --- apps made of programs -------------------------------------------------------------------
#
#   apps/backup/               the app: a folder with NO manifest, so it has no permissions
#       list/manifest.json     a program: its own KOS requirements, its own permissions
#       add/manifest.json      another program: asks for different things
#       remove/
#           manifest.json
#           confirm/manifest.json   a program of a program: backup.remove.confirm
#
# Every folder with a manifest.json is packed into its own .kapp, without the folders of its
# own sub-programs. Nothing is inherited down the tree or up it: a program holds exactly the
# permissions its own manifest asks for, and each is approved (``kos permit``) on its own.

_GROUP_OK_FILES = ("README", "README.md", "README.txt")


def _walk_dirs(d: Path) -> list[Path]:
    return sorted(c for c in d.iterdir()
                  if c.is_dir() and not c.is_symlink() and c.name != "__pycache__" and not c.name.startswith("."))


def has_program_below(d: Path) -> bool:
    return any((c / MANIFEST).is_file() or has_program_below(c) for c in _walk_dirs(d))


def find_programs(root: Path) -> list[tuple[str, Path]]:
    """Every program under the app folder ``root`` as ``(id, folder)``, parents before children.
    An id is the folder path joined with dots. Refuses a tree that cannot be one app: a folder
    that has code but no manifest (an app has no permissions, so there is nowhere for its code
    to run), an invalid or too deep name, or a symlink."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise KAppError(f"{root} is not a directory")
    out: list[tuple[str, Path]] = []

    def visit(d: Path, ident: str) -> None:
        if not ID_RE.match(ident):
            raise KAppError(f"{ident!r} is not a valid program id (names are lowercase letters, digits and -, "
                            f"at most {MAX_DEPTH} levels deep)")
        has = (d / MANIFEST).is_file()
        if has:
            out.append((ident, d))
        else:
            stray = sorted(c.name for c in d.iterdir()
                           if not c.is_dir() and c.name not in _GROUP_OK_FILES and not c.name.startswith("."))
            if stray:
                raise KAppError(f"{d} has no {MANIFEST}, so it is an app, not a program, and has no permissions "
                                f"and cannot hold code: move {', '.join(stray)} into a program folder")
            if not has_program_below(d):
                return
        for c in _walk_dirs(d):
            if has and not (c / MANIFEST).is_file() and not has_program_below(c):
                continue                        # plain resources of this program (assets/, data/ ...)
            visit(c, f"{ident}.{c.name}")

    visit(root, root.name)
    return out


def pack_tree(root: Path, out_dir: Path) -> list[Manifest]:
    """Pack every program under ``root`` into ``out_dir/<id>.kapp``. Each manifest's ``name`` must
    be the id its folder gives it, so a program cannot take another program's (or app's) name."""
    root, out_dir = Path(root), Path(out_dir)
    programs = find_programs(root)
    if not programs:
        raise KAppError(f"{root} holds no program (a folder with a {MANIFEST})")
    folders = {d for _, d in programs}
    for ident, d in programs:
        try:
            m = Manifest.parse((d / MANIFEST).read_bytes()[:64 << 10])
        except OSError as e:
            raise KAppError(f"{d / MANIFEST}: {e}") from None
        if m.name != ident:
            raise KAppError(f"{d / MANIFEST} says name {m.name!r} but its folder makes it {ident!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    result = []
    for ident, d in programs:
        below = frozenset(c for c in folders if c != d and d in c.parents)
        result.append(pack(d, out_dir / f"{ident}.kapp", skip_dirs=below))
    return result
