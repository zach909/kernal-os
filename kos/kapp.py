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

from . import servicespec

MANIFEST = "manifest.json"
MAX_ARCHIVE = 512 << 20
MAX_ENTRIES = 4096
MAX_UNCOMPRESSED = 1 << 30
MAX_RATIO = 200
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}\Z")   # \Z, not $: "$" lets a trailing newline through
# An id is the path of groups down to the app, joined with dots: ``backup.add`` is the app
# ``add`` in the group ``backup``. Groups nest as deep as you like - there is no level limit. The
# only bound is the id's total length (it becomes a file name, ``<id>.kapp``, and an instance
# id adds 7 more characters). A plain app name can never contain a dot, so a grouped app can
# never collide with, or pass for, an ordinary app. The id is identity only: it confers no authority.
MAX_ID_LEN = 200
ID_PATTERN = r"[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31})*"
ID_RE = re.compile(rf"^(?=.{{1,{MAX_ID_LEN}}}\Z){ID_PATTERN}\Z")      # length first: no regex work on a huge string
INSTANCE_RE = re.compile(rf"^(?=.{{1,{MAX_ID_LEN + 7}}}\Z){ID_PATTERN}-[0-9a-f]{{6}}\Z")
RESERVED_NAMES = {"graphical", "kos", "system", "all"}
RUNTIMES = {"python", "native"}
MODES = {"tui", "graphical", "cmd"}
# ``admin`` lets a program ask the OS for the administrator keyboard's one job, the guarded file
# write (request ``admin`` / ``write``). It is not root: the OS still needs a live lease, the
# password typed for exactly that write, a clean security scan and a disk optimize.
# ``cookies`` and ``passwords`` each unlock one separate, OS-owned store (see vault.py / spaces.py).
# They are not part of ``storage``: an app that keeps notes cannot read a cookie jar or saved logins.
PERMISSIONS = {"network", "system", "storage", "ai", "admin", "cookies", "passwords"}
# A program may ask the OS for exactly one thing at a time: ``ask:ACTION``. ``system`` is every
# action at once (including opening and closing other apps) and stays all-or-nothing; the actions
# that touch other apps (open, close, focus) are deliberately not available one by one.
ASK_ACTIONS = ("apps", "backup", "backup_add", "backup_remove", "kernel", "status")
ASK_PREFIX = "ask:"
SPACE_PERM_RE = re.compile(r"^(owns|uses):[a-z][a-z0-9-]{0,31}$")
SERVICE_PERM_RE = re.compile(r"^service:([a-z]+)$")      # ask the OS for one group of functions (servicespec.py)
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

# Every app can explain itself: ``help.json`` is its own "help" command, as data. It is validated
# when the app is read, never run, and what it says is the author's free text (untrusted).
#   {"about": "one line", "commands": [{"name": "Esc", "help": "leave the app"}]}
HELP_FILE = "help.json"
MAX_HELP_COMMANDS = 40
MAX_HELP_NAME = 40
MAX_HELP_TEXT = 200


def parse_help(raw: bytes) -> dict:
    """Validate ``help.json``. Returns ``{"about": str, "commands": [(name, help), ...]}``."""
    try:
        d = json.loads(raw)
    except ValueError as e:
        raise KAppError(f"help.json is not valid JSON: {e}") from None
    if not isinstance(d, dict) or set(d) - {"about", "commands"}:
        raise KAppError("help.json must be an object with only 'about' and 'commands'")
    about = d.get("about", "")
    if not isinstance(about, str) or len(about) > MAX_HELP_TEXT:
        raise KAppError(f"help.about must be a string of at most {MAX_HELP_TEXT} characters")
    cmds = d.get("commands", [])
    if not isinstance(cmds, list) or len(cmds) > MAX_HELP_COMMANDS:
        raise KAppError(f"help.commands must be a list of at most {MAX_HELP_COMMANDS} entries")
    out = []
    for c in cmds:
        if (not isinstance(c, dict) or set(c) != {"name", "help"}
                or not isinstance(c["name"], str) or not isinstance(c["help"], str)
                or not 0 < len(c["name"]) <= MAX_HELP_NAME or len(c["help"]) > MAX_HELP_TEXT):
            raise KAppError("each help command is {\"name\": text, \"help\": text} within the length limits")
        out.append((c["name"], c["help"]))
    return {"about": about, "commands": out}


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
            m = SERVICE_PERM_RE.match(str(perm))
            if m and m.group(1) not in servicespec.GROUPS:
                raise KAppError(f"unknown service group {m.group(1)!r}: use one of {', '.join(servicespec.GROUPS)}")
            if perm in PERMISSIONS or SPACE_PERM_RE.match(str(perm)) or m:
                continue
            if isinstance(perm, str) and perm.startswith(ASK_PREFIX) and perm[len(ASK_PREFIX):] in ASK_ACTIONS:
                continue
            raise KAppError(f"unknown permission {perm!r}: use {sorted(PERMISSIONS)}, "
                            f"'ask:ACTION' (one of {', '.join(ASK_ACTIONS)}), "
                            "'owns:NAME' (create a shared folder), 'uses:NAME' (look for one) "
                            "or 'service:GROUP' (ask the OS for a group of functions)")
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
            if "system" in perms or any(SERVICE_PERM_RE.match(str(p)) or str(p).startswith(ASK_PREFIX) for p in perms):
                # The power to open and close apps, or to ask the OS for anything (its own state, one
                # action, a service), must never ride in on an add-on.
                raise KAppError(f"a {kind} cannot ask for the 'system' permission, a 'service:' permission "
                                f"or any 'ask:' permission")
            for power in ("ai", "admin"):
                # The power to send text to a model, or to write files as the administrator, must
                # never ride in on an add-on.
                if power in perms:
                    raise KAppError(f"a {kind} cannot ask for the '{power}' permission")
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
        self.help = (parse_help(self.read(HELP_FILE, limit=64 << 10))
                     if HELP_FILE in self._names else None)

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


def pack(src: Path, out: Path, skip_dirs: frozenset = frozenset(), prove: bool = True) -> Manifest:
    """Build a reproducible .kapp from a directory (same input → same bytes).
    ``skip_dirs`` are sub-directories left out (the folders of a program's own sub-programs).
    Packing adds ``proof.json`` (see proof.py) and refuses code that cannot be proven; ``prove=False``
    is only for building an app that the OS must then refuse (tests)."""
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
    contents = {p.relative_to(src).as_posix(): p.read_bytes() for p in files}
    if prove:
        from . import proof      # lazy: proof builds on this module
        if proof.PROOF_FILE in contents:
            raise KAppError(f"{proof.PROOF_FILE} is written by pack, not by hand")
        m = Manifest.parse(contents.get(MANIFEST, b"")[:64 << 10])
        contents[proof.PROOF_FILE] = proof.make_proof(contents, m.runtime, m.name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for rel in sorted(contents):
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if os.access(src / rel, os.X_OK) else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            z.writestr(zi, contents[rel])
    data = buf.getvalue()
    app = KApp(data)  # validate exactly what we are about to ship
    Path(out).write_bytes(data)
    return app.manifest


SEAL_CONTEXT = b"kos-kapp-seal-v1\x00"


def compute_seal(key: bytes, name: str, version: str, sha256_hex: str) -> str:
    msg = SEAL_CONTEXT + b"\x00".join([name.encode(), version.encode(), sha256_hex.encode()])
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# --- groups of apps -------------------------------------------------------------------------
#
#   apps/docs/                    a GROUP: a folder with no manifest. No code, no permissions.
#       spell.py                  an APP: one file ...
#       spell.json                ... and its manifest, which is where that file's permissions are asked for
#       editor/                   a group inside the group - groups nest with no level limit
#           format.py
#           format.json           the app ``docs.editor.format``
#       old-style/manifest.json   a folder app (several files) is still an app; it is a leaf, not a group
#
# Every page is an app. A group only holds apps and other groups, so it has nothing to grant a
# permission to; an app's permissions are asked for in its own manifest, approved on that one file
# (``kos permit``, pinned to the file's hash) and never inherited, up or down the tree.
#
# A single-file app ships as its own ``.kapp``: ``NAME.py`` becomes ``app.py`` and ``NAME.json``
# becomes ``manifest.json``, so the manifest's entry must be ``app`` or ``app:FUNCTION``.

_GROUP_OK_FILES = ("README", "README.md", "README.txt")
FILE_ENTRY = "app"


def _walk_dirs(d: Path) -> list[Path]:
    return sorted(c for c in d.iterdir()
                  if c.is_dir() and not c.is_symlink() and c.name != "__pycache__" and not c.name.startswith("."))


def has_program_below(d: Path, pairs: bool = True) -> bool:
    """Is there any app (a folder with a manifest, or a ``NAME.py``/``NAME.json`` pair) below ``d``?
    With ``pairs=False`` only folders with a manifest count (inside a folder app a .py/.json pair is
    just one of its own resource files). Walks with a stack, not recursion, so a hostile tree cannot overflow the interpreter."""
    stack = [d]
    while stack:
        cur = stack.pop()
        for c in cur.iterdir():
            if c.is_symlink() or c.name.startswith("."):
                continue
            if c.is_dir():
                if c.name == "__pycache__":
                    continue
                if (c / MANIFEST).is_file():
                    return True
                stack.append(c)
            elif pairs and c.suffix == ".json" and c.name != MANIFEST and (cur / (c.stem + ".py")).is_file():
                return True                       # a NAME.py / NAME.json pair
    return False


def find_programs(root: Path) -> list[tuple[str, Path]]:
    """Every app under the group folder ``root`` as ``(id, path)``: ``path`` is the ``.py`` file of a
    single-file app or the folder of a folder app. Parents before children, names in order.
    Refuses a tree that cannot be a group: a group that holds code with no manifest (a group has no
    permissions, so nowhere for code to run), a ``.py`` without its ``.json`` or the reverse, an app
    and a group with the same name, an invalid or too long id, or a symlink."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise KAppError(f"{root} is not a directory")
    out: list[tuple[str, Path]] = []

    def visit(d: Path, ident: str) -> None:
        if not ID_RE.match(ident):
            raise KAppError(f"{ident!r} is not a valid id (names are lowercase letters, digits and -, "
                            f"at most {MAX_ID_LEN} characters in all)")
        if (d / MANIFEST).is_file():
            if has_program_below(d, pairs=False):
                raise KAppError(f"{d} is an app, and an app has no apps inside it: make {d.name}/ a group "
                                f"(no {MANIFEST}) and put the apps in it")
            out.append((ident, d))               # a folder app: a leaf, its own folder is all it owns
            return
        files = {c.name for c in d.iterdir() if not c.is_dir() and not c.name.startswith(".")}
        pairs = sorted(n[:-3] for n in files if n.endswith(".py") and n[:-3] + ".json" in files)
        paired = {f"{n}.py" for n in pairs} | {f"{n}.json" for n in pairs}
        stray = sorted(files - paired - set(_GROUP_OK_FILES))
        if stray:
            raise KAppError(f"{d} is a group, not an app, so it has no permissions and cannot hold code: "
                            f"{', '.join(stray)} must be an app (NAME.py with its NAME.json) or move out")
        dirs = {c.name: c for c in _walk_dirs(d)}
        for n in pairs:
            if n in dirs:
                raise KAppError(f"{d}: {n!r} is both an app ({n}.py) and a group ({n}/); an app has no apps inside it")
            if not ID_RE.match(f"{ident}.{n}"):
                raise KAppError(f"{ident}.{n!r} is not a valid id")
            out.append((f"{ident}.{n}", d / f"{n}.py"))
        for n, c in dirs.items():
            if (c / MANIFEST).is_file() or has_program_below(c):
                visit(c, f"{ident}.{n}")

    visit(root, root.name)
    return out


def _pack_file_app(py: Path, out: Path) -> Manifest:
    """One ``NAME.py`` and its ``NAME.json`` become one reproducible ``.kapp``."""
    side = py.with_suffix(".json")
    if py.is_symlink() or side.is_symlink():
        raise KAppError(f"refusing to pack symlink {py}")
    try:
        raw, code = side.read_bytes()[:64 << 10], py.read_bytes()
    except OSError as e:
        raise KAppError(f"{py}: {e}") from None
    m = Manifest.parse(raw)
    if m.runtime != "python" or m.entry.split(":")[0] != FILE_ENTRY:
        raise KAppError(f"{side}: a single-file app is python and its entry must be "
                        f"'{FILE_ENTRY}' or '{FILE_ENTRY}:FUNCTION' (the file is packed as {FILE_ENTRY}.py)")
    if m.kind != "app":
        raise KAppError(f"{side}: only an ordinary app can be a single file inside a group")
    from . import proof      # lazy: proof builds on this module
    contents = {MANIFEST: raw, f"{FILE_ENTRY}.py": code}
    contents[proof.PROOF_FILE] = proof.make_proof(contents, m.runtime, m.name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in sorted(contents.items()):
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(zi, body)
    data = buf.getvalue()
    KApp(data)                                   # validate exactly what we are about to ship
    Path(out).write_bytes(data)
    return m


def pack_tree(root: Path, out_dir: Path) -> list[Manifest]:
    """Pack every app under the group ``root`` into ``out_dir/<id>.kapp``. Each manifest's ``name``
    must be the id its place in the tree gives it, so an app cannot take another app's name."""
    root, out_dir = Path(root), Path(out_dir)
    programs = find_programs(root)
    if not programs:
        raise KAppError(f"{root} holds no app (a NAME.py with its NAME.json, or a folder with a {MANIFEST})")
    for ident, p in programs:
        mf = p / MANIFEST if p.is_dir() else p.with_suffix(".json")
        try:
            m = Manifest.parse(mf.read_bytes()[:64 << 10])
        except OSError as e:
            raise KAppError(f"{mf}: {e}") from None
        if m.name != ident:
            raise KAppError(f"{mf} says name {m.name!r} but its place in the tree makes it {ident!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    result = []
    for ident, p in programs:
        dest = out_dir / f"{ident}.kapp"
        result.append(pack(p, dest) if p.is_dir() else _pack_file_app(p, dest))
    return result
