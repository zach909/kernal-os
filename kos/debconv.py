"""Convert a Debian package (.deb) into a KOS app (.kapp).

What carries over, and what deliberately does not:

* The program's files are kept, in memory only, inside the .kapp zip under
  ``payload/``. Nothing is ever unpacked to disk, here or at run time.
* **Maintainer scripts (preinst, postinst, prerm, postrm, config) are never
  run and never stored.** They run as root on Debian; KOS has no such thing.
  They are listed in the report so you can see what was dropped.
* Only **statically linked** programs convert. KOS native apps run from one
  sealed file with no shared libraries, so a dynamically linked program would
  fail at start; it is refused with the package's ``Depends`` shown, rather
  than produce an app that cannot run.
* Symlinks, hard links, devices and FIFOs are dropped (a .kapp may hold none).
  setuid/setgid/sticky bits are stripped.
* The converted app gets **no permissions**: no network, no ``system``. It runs
  inside the usual sandbox through a small shim (``debshim.py``) that shows its
  output as a text page.

The .deb is untrusted input. Sizes, counts and paths are bounded and checked
before anything is read, and the finished .kapp is scanned; a flagged one is
refused. The conversion itself never installs anything - ``kos install`` still
scans again, asks for the password and seals.
"""

from __future__ import annotations

import io
import re
import stat
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .kapp import MAX_ENTRIES, MAX_UNCOMPRESSED, RESERVED_NAMES, KApp, KAppError
from .protocol import clean_text
from .scan import scan_bytes

MAX_DEB = 256 << 20
MAX_MEMBER = 256 << 20
MAX_CONTROL = 1 << 20
BIN_DIRS = ("usr/bin/", "bin/", "usr/sbin/", "sbin/", "usr/games/", "usr/local/bin/")
SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config")


class DebError(Exception):
    pass


@dataclass
class Deb:
    control: dict
    files: dict            # path (no leading ./) -> (bytes, mode)
    dropped: list = field(default_factory=list)
    scripts: list = field(default_factory=list)


@dataclass
class Report:
    package: str
    version: str
    kapp_name: str
    kapp_version: str
    entry: str
    machine: str
    depends: str
    dropped: list
    scripts: list
    files: int

    def summary(self) -> str:
        lines = [f"converted {self.package} {self.version} -> app {self.kapp_name} {self.kapp_version}",
                 f"  program: {self.entry} ({self.machine}, statically linked), {self.files} files kept",
                 "  permissions: none (no network, no system)"]
        if self.scripts:
            lines.append(f"  maintainer scripts NOT run and NOT kept: {', '.join(self.scripts)}")
        if self.dropped:
            lines.append(f"  dropped {len(self.dropped)} unsupported entries (symlinks, devices, ...)")
        if self.depends:
            lines.append(f"  Debian Depends (not installed, informational): {self.depends}")
        return "\n".join(lines)


# --- reading the .deb ---------------------------------------------------

def _ar_members(data: bytes) -> dict:
    if not data.startswith(b"!<arch>\n"):
        raise DebError("not a Debian package (no ar header)")
    pos, out = 8, {}
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            raise DebError("corrupt ar header")
        name = hdr[0:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(hdr[48:58].decode().strip())
        except ValueError:
            raise DebError("corrupt ar member size") from None
        pos += 60
        if size < 0 or pos + size > len(data):
            raise DebError("ar member runs past the end of the file")
        if name in out:
            raise DebError(f"duplicate ar member {name!r}")
        out[name] = data[pos:pos + size]
        pos += size + (size & 1)
    return out


def _tar(blob: bytes, what: str) -> tarfile.TarFile:
    try:
        return tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise DebError(f"cannot read {what}: {e}") from None


def _member(members: dict, stem: str) -> tuple:
    for name, blob in members.items():
        if name == stem or name.startswith(stem + "."):
            if name.endswith(".zst"):
                raise DebError(f"{name} is zstd-compressed; this Python cannot read zstd "
                               "(needs Python 3.14). Re-pack the .deb with xz or gzip")
            return name, blob
    raise DebError(f"not a Debian package: no {stem} member")


def _safe_path(raw: str) -> str:
    n = raw[2:] if raw.startswith("./") else raw
    if (not n or n.startswith("/") or "\\" in n or "\x00" in n
            or any(part in ("..", ".", "") for part in n.rstrip("/").split("/"))):
        raise DebError(f"illegal path in package: {raw!r}")
    return n


def parse_control(text: str) -> dict:
    fields, key = {}, None
    for line in text.splitlines():
        if line[:1] in (" ", "\t"):
            if key:
                fields[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            fields[key] = val.strip()
    return fields


def parse_deb(data: bytes) -> Deb:
    if len(data) > MAX_DEB:
        raise DebError("package too large")
    members = _ar_members(data)
    _, ctl_blob = _member(members, "control.tar")
    control, scripts = {}, []
    with _tar(ctl_blob, "control archive") as t:
        for m in t:
            name = m.name[2:] if m.name.startswith("./") else m.name
            if name == "control" and m.isreg() and m.size <= MAX_CONTROL:
                control = parse_control(t.extractfile(m).read().decode("utf-8", "replace"))
            elif name in SCRIPTS:
                scripts.append(name)
    for k in ("Package", "Version"):
        if not control.get(k):
            raise DebError(f"control file has no {k}")

    _, data_blob = _member(members, "data.tar")
    files, dropped, total, count = {}, [], 0, 0
    with _tar(data_blob, "data archive") as t:
        for m in t:
            count += 1
            if count > MAX_ENTRIES * 4:
                raise DebError("too many entries in the package")
            path = _safe_path(m.name)
            if m.isdir():
                continue
            if not m.isreg():
                kind = "symlink" if m.issym() else "hard link" if m.islnk() else "special file"
                dropped.append(f"{kind}: {path}")
                continue
            if m.size > MAX_MEMBER:
                raise DebError(f"{path} is too large")
            total += m.size
            if total > MAX_UNCOMPRESSED:
                raise DebError("package expands to more than 1 GiB")
            if len(files) >= MAX_ENTRIES - 8:
                raise DebError("too many files to fit in an app")
            if path in files:
                raise DebError(f"duplicate file {path!r}")
            files[path] = (t.extractfile(m).read(), m.mode)
    if not files:
        raise DebError("the package contains no files")
    return Deb(control, files, dropped, scripts)


# --- ELF ----------------------------------------------------------------

_MACHINES = {62: "x86-64", 183: "aarch64", 3: "x86", 40: "arm", 243: "riscv"}


def elf_info(blob: bytes):
    """(kind, machine) where kind is 'static', 'dynamic' or 'not-elf'."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF" or blob[4] not in (1, 2) or blob[5] != 1:
        return "not-elf", ""
    is64 = blob[4] == 2
    try:
        if is64:
            machine = struct.unpack_from("<H", blob, 18)[0]
            phoff, = struct.unpack_from("<Q", blob, 32)
            phentsize, phnum = struct.unpack_from("<HH", blob, 54)
        else:
            machine = struct.unpack_from("<H", blob, 18)[0]
            phoff, = struct.unpack_from("<I", blob, 28)
            phentsize, phnum = struct.unpack_from("<HH", blob, 42)
        for i in range(min(phnum, 256)):
            off = phoff + i * phentsize
            ptype, = struct.unpack_from("<I", blob, off)
            if ptype == 3:                      # PT_INTERP: needs a dynamic loader
                return "dynamic", _MACHINES.get(machine, f"machine {machine}")
    except struct.error:
        return "not-elf", ""
    return "static", _MACHINES.get(machine, f"machine {machine}")


# --- naming -------------------------------------------------------------

def kos_name(package: str) -> str:
    n = re.sub(r"[^a-z0-9-]", "-", package.lower()).lstrip("-0123456789")[:32].rstrip("-")
    if not n:
        raise DebError(f"cannot make an app name from {package!r}")
    if n in RESERVED_NAMES:
        n = ("deb-" + n)[:32]
    return n


def kos_version(version: str) -> str:
    v = re.sub(r"^\d+:", "", version)             # drop the epoch
    v = re.sub(r"[^0-9A-Za-z.+-]", "-", v)[:32]
    if not v:
        raise DebError(f"cannot make an app version from {version!r}")
    return v


# --- building the .kapp -------------------------------------------------

def _pick_entry(deb: Deb, exe: str | None) -> tuple:
    if exe is not None:
        path = exe[2:] if exe.startswith("./") else exe.lstrip("/")
        if path not in deb.files:
            raise DebError(f"{exe!r} is not in the package")
        kind, machine = elf_info(deb.files[path][0])
        if kind == "not-elf":
            raise DebError(f"{exe} is not an ELF program (scripts are not converted)")
        if kind == "dynamic":
            raise DebError(f"{exe} is dynamically linked; only static programs run in KOS")
        return path, machine
    static, dynamic = [], []
    for path, (blob, mode) in sorted(deb.files.items()):
        if path.startswith(BIN_DIRS) and mode & 0o111:
            kind, machine = elf_info(blob)
            (static if kind == "static" else dynamic if kind == "dynamic" else []).append((path, machine))
    if len(static) == 1:
        return static[0]
    if len(static) > 1:
        raise DebError("several static programs found; choose one with --exe: "
                       + ", ".join(p for p, _ in static))
    if dynamic:
        raise DebError("only dynamically linked programs found (" + ", ".join(p for p, _ in dynamic[:5])
                       + "). KOS runs one sealed static file with no shared libraries, so these "
                       "cannot run. Debian Depends: " + (deb.control.get("Depends") or "(none)"))
    raise DebError("no executable program found in bin/ directories (use --exe to name one)")


def convert(data: bytes, exe: str | None = None) -> tuple:
    """(kapp bytes, Report). Raises DebError; never writes anything."""
    deb = parse_deb(data)
    pkg, ver = deb.control["Package"], deb.control["Version"]
    entry, machine = _pick_entry(deb, exe)
    name, kver = kos_name(pkg), kos_version(ver)
    desc_src = clean_text(deb.control.get("Description", "").split("\n")[0], 400)
    description = f"Debian {pkg} {ver}: {desc_src}"[:200]

    shim = (Path(__file__).resolve().parent / "debshim.py").read_bytes()
    import json
    meta = {"package": clean_text(pkg, 100), "version": clean_text(ver, 100), "exe": f"payload/{entry}",
            "argv": [], "depends": clean_text(deb.control.get("Depends", ""), 1000),
            "dropped_scripts": deb.scripts}
    manifest = {"name": name, "version": kver, "runtime": "python", "entry": "debshim:main",
                "modes": ["tui"], "permissions": [], "description": description}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        def add(rel: str, blob: bytes, mode: int) -> None:
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (stat.S_IFREG | mode) << 16
            z.writestr(zi, blob)
        add("manifest.json", json.dumps(manifest, indent=2).encode(), 0o644)
        add("debshim.py", shim, 0o644)
        add("deb.json", json.dumps(meta, indent=2).encode(), 0o644)
        for path, (blob, mode) in sorted(deb.files.items()):
            add(f"payload/{path}", blob, 0o755 if mode & 0o111 else 0o644)   # setuid/setgid/sticky stripped
    out = buf.getvalue()
    try:
        KApp(out)                                   # validate exactly what we would ship
    except KAppError as e:
        raise DebError(f"the converted app is not valid: {e}") from None
    result = scan_bytes(out, label=f"{name}.kapp")
    if not result.clean:
        raise DebError(f"the converted app was flagged by the scanner ({result.summary()}); nothing written")
    return out, Report(pkg, ver, name, kver, entry, machine, deb.control.get("Depends", ""),
                       deb.dropped, deb.scripts, len(deb.files))
