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

from . import capabilities
from pathlib import Path

MANIFEST = "manifest.json"
MAX_ARCHIVE = 512 << 20
MAX_ENTRIES = 4096
MAX_UNCOMPRESSED = 1 << 30
MAX_RATIO = 200
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
NPM_ENTRY_RE = re.compile(r"^(?:npx:[A-Za-z0-9._-]{1,60}|[A-Za-z0-9:_-]{1,40})$")
RESERVED_NAMES = {"graphical", "kos", "system", "all"}
RUNTIMES = {"python", "native", "npm", "bundle"}
MODES = {"tui", "graphical", "cmd"}
PERMISSIONS = {"network", "system", "ticks", "shell", "pointer", "animate", "neural"}
# Interface slots a "mod" can fill (kos/mods.py decides what each may ask for).
SLOTS = {"wallpaper", "menubar", "dock", "pins", "search", "widgets", "cursor", "effects", "sidebar", "launcher",
         "pins", "widget"}
BUNDLE_ENTRY_RE = re.compile(r"^[A-Za-z0-9._+-][A-Za-z0-9._+/-]{0,199}$")
_MANIFEST_KEYS = {"name", "version", "runtime", "entry", "modes", "permissions", "description", "commands",
                  "args", "slot", "exec_scratch", "devices", "driver"}
DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9_.*?/-]{1,60}$")
DRIVER_KINDS = {"quantum", "xr", "camera", "neural"}
COMMAND_ID_RE = re.compile(r"^[A-Za-z0-9:_.-]{1,60}$")
MAX_COMMANDS = 24


class KAppError(Exception):
    pass


@dataclass(frozen=True)
class Command:
    """Something an app can do, which desktop search can find and start."""
    id: str
    title: str
    keywords: tuple[str, ...] = ()
    line: str = ""        # a line of the line shell to run in the app when it opens (optional)


@dataclass(frozen=True)
class Manifest:
    name: str
    version: str
    runtime: str
    entry: str
    modes: tuple[str, ...] = ("tui",)
    permissions: tuple[str, ...] = ()
    description: str = ""
    commands: tuple[Command, ...] = ()
    args: tuple[str, ...] = ()          # bundle: arguments the program is started with
    slot: str = ""                      # mod: the interface slot this app fills
    exec_scratch: bool = False          # bundle: the program unpacks code into its scratch dir and runs it (AppImage)
    devices: tuple[str, ...] = ()       # device nodes (globs under /dev) it asks to open - asked again at every launch
    driver: str = ""                    # the kind of hardware it is a driver for (see DRIVER_KINDS)

    @property
    def scopes(self) -> frozenset:
        """What it may ask the OS to do: ``{"*"}`` for the bare ``system`` permission, else its ``system:<scope>`` ones."""
        return capabilities.scopes_of(self.permissions)

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
        if not all(isinstance(p, str) for p in perms) or not set(perms) <= PERMISSIONS | {p for p in perms if p.startswith(capabilities.PREFIX) and capabilities.valid(p)}:
            raise KAppError(f"permissions must be a subset of {sorted(PERMISSIONS)} or system:<scope> with a scope from {sorted(capabilities.SCOPES)}")
        desc = d.get("description", "")
        if not isinstance(desc, str) or len(desc) > 200:
            raise KAppError("description must be a string of at most 200 characters")
        if d["runtime"] == "npm" and not NPM_ENTRY_RE.match(d["entry"]):
            raise KAppError("npm entry must be an npm script name (e.g. 'start') or 'npx:TOOL'")
        if d["runtime"] == "python" and not re.match(
                r"^[A-Za-z_][\w.]*(:[A-Za-z_]\w*)?$", d["entry"]):
            raise KAppError("python entry must look like 'module' or 'module:function'")
        args = d.get("args", [])
        if (not isinstance(args, list) or len(args) > 8
                or not all(isinstance(a, str) and len(a) <= 128 and a.isprintable() for a in args)):
            raise KAppError("args must be up to 8 short printable strings")
        slot = d.get("slot", "")
        if slot and slot not in SLOTS:
            raise KAppError(f"slot must be one of {sorted(SLOTS)}")
        xs = d.get("exec_scratch", False)
        if not isinstance(xs, bool) or (xs and d["runtime"] != "bundle"):
            raise KAppError("exec_scratch is only for bundle apps")
        if d["runtime"] == "bundle" and (not BUNDLE_ENTRY_RE.match(d["entry"]) or ".." in d["entry"].split("/")):
            raise KAppError("a bundle entry is a path inside the archive")
        devices = d.get("devices", [])
        if (not isinstance(devices, list) or len(devices) > 4
                or not all(isinstance(x, str) and DEVICE_RE.match(x) and ".." not in x.split("/") for x in devices)):
            raise KAppError("devices must be up to 4 patterns like /dev/qpu* (under /dev, no ..)")
        driver = d.get("driver", "")
        if driver and driver not in DRIVER_KINDS:
            raise KAppError(f"driver must be one of {sorted(DRIVER_KINDS)}")
        if "neural" in perms and driver != "neural":
            raise KAppError("the 'neural' permission (sending intents to the interface) is only for a driver: \"driver\": \"neural\"")
        return cls(name=name, version=d["version"], runtime=d["runtime"], entry=d["entry"],
                   modes=modes, permissions=perms, description=desc, commands=_commands(d.get("commands", [])),
                   args=tuple(args), slot=slot, exec_scratch=xs, devices=tuple(devices), driver=driver)


def _commands(raw) -> tuple[Command, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_COMMANDS:
        raise KAppError(f"commands must be a list of at most {MAX_COMMANDS}")
    out = []
    for c in raw:
        if not isinstance(c, dict) or not set(c) <= {"id", "title", "keywords", "line"}:
            raise KAppError("each command is {id, title, keywords?, line?}")
        cid, title, kw, line = c.get("id"), c.get("title"), c.get("keywords", []), c.get("line", "")
        if not isinstance(cid, str) or not COMMAND_ID_RE.match(cid):
            raise KAppError(f"bad command id {cid!r}")
        if not isinstance(title, str) or not 1 <= len(title) <= 70:
            raise KAppError("a command title is 1 to 70 characters")
        if (not isinstance(kw, list) or len(kw) > 8
                or not all(isinstance(k, str) and 1 <= len(k) <= 24 for k in kw)):
            raise KAppError("command keywords: up to 8 short words")
        if not isinstance(line, str) or len(line) > 200:
            raise KAppError("a command line is at most 200 characters")
        out.append(Command(cid, title, tuple(k.lower() for k in kw), line))
    return tuple(out)


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
        elif m.runtime == "npm":
            if "package.json" not in self._names:
                raise KAppError("an npm app needs a package.json")
            try:
                pkg = json.loads(self.read("package.json", limit=1 << 20))
            except ValueError:
                raise KAppError("package.json is not valid JSON") from None
            scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
            if not m.entry.startswith("npx:") and (not isinstance(scripts, dict) or m.entry not in scripts):
                raise KAppError(f"package.json has no script {m.entry!r}")
        elif m.entry not in self._names:
            raise KAppError(f"entry binary {m.entry!r} not found in archive")

    def names(self) -> list[str]:
        return sorted(self._names)

    def mode_of(self, name: str) -> int:
        """The permission bits the archive recorded for a file (executable or not)."""
        return (self._zip.getinfo(name).external_attr >> 16) & 0o777

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
