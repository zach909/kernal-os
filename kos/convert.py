"""Convert a Debian package or an AppImage into a KOS app (.kapp).

Nothing here executes the package. A ``.deb`` is an ``ar`` archive holding tarballs; an
AppImage is an ELF file with a filesystem appended. Both are *read as data*, checked,
and rewritten as a sealed-able ``.kapp`` of runtime ``bundle`` - a program tree that KOS
unpacks read-only into RAM and runs inside the usual sandbox (``kos/hostrun.py``).

What conversion refuses or drops, on purpose:
* absolute paths, ``..``, device nodes, FIFOs - the package is rejected or the member skipped;
* setuid/setgid bits (they would do nothing under no_new_privs anyway) are cleared;
* symlinks are replaced by a copy of what they point at *inside the package* (a ``.kapp`` has no
  symlinks); links that leave the package or are broken are dropped and listed;
* maintainer scripts (preinst/postinst/...) are NEVER run - they run as root on a real install;
  they are reported so you can see what the package would have done;
* docs, man pages, locales and info files are left out to stay under the entry limit.

Honest limits: dependencies are listed, not installed - a program needing a library that is not
in the package or in the system's /usr and /lib will fail to start inside the sandbox. A program
that wants a graphical display has none (KOS is not an X server). zstd-compressed ``.deb`` files
need Python 3.14+ (``compression.zstd``); xz, gzip and bzip2 work everywhere.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .kapp import (BUNDLE_ENTRY_RE, MANIFEST, MAX_ENTRIES, MAX_RATIO, MAX_UNCOMPRESSED, KApp, KAppError)
from .scan import scan_bytes

MAX_DEB = 400 << 20
MAX_MEMBER = 300 << 20
DROP_PREFIXES = ("usr/share/doc/", "usr/share/man/", "usr/share/info/", "usr/share/lintian/", "usr/share/locale/",
                 "usr/share/bug/", "usr/share/doc-base/", "var/lib/dpkg/", "var/cache/", "etc/cron", "etc/init.d/",
                 "lib/systemd/", "usr/lib/systemd/")
MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config")
CONVERTED = "kos-converted.json"


class ConvertError(KAppError):
    pass


@dataclass
class Report:
    kind: str                       # deb | appimage
    source: str
    sha256: str
    name: str
    version: str
    entry: str
    description: str = ""
    depends: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    maintainer_scripts: list[str] = field(default_factory=list)
    files: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return dict(self.__dict__)


# --------------------------------------------------------------------------- names
def app_name(raw: str, prefix: str = "deb") -> str:
    n = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-")
    n = re.sub(r"-{2,}", "-", n)
    if not n or not n[0].isalpha():
        n = f"{prefix}-{n}".strip("-")
    n = n[:32].rstrip("-")
    from .kapp import NAME_RE, RESERVED_NAMES
    if not NAME_RE.match(n) or n in RESERVED_NAMES:
        raise ConvertError(f"cannot make an app name from {raw!r}; pass --name")
    return n


def app_version(raw: str) -> str:
    v = re.sub(r"[^0-9A-Za-z.+-]+", ".", raw).strip(".")[:32]
    return v or "0"


# --------------------------------------------------------------------------- ar / tar
def _ar_members(data: bytes) -> dict[str, bytes]:
    if data[:8] != b"!<arch>\n":
        raise ConvertError("not a Debian package (missing ar header)")
    out: dict[str, bytes] = {}
    pos = 8
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        pos += 60
        if hdr[58:60] != b"`\n":
            raise ConvertError("corrupt ar archive")
        name = hdr[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(hdr[48:58].decode().strip())
        except ValueError:
            raise ConvertError("corrupt ar member size") from None
        if size < 0 or pos + size > len(data):
            raise ConvertError("truncated ar archive")
        out[name] = data[pos:pos + size]
        pos += size + (size & 1)
    return out


def _decompress(name: str, raw: bytes) -> bytes:
    limit = MAX_MEMBER * 2
    if name.endswith(".gz"):
        d = gzip.GzipFile(fileobj=io.BytesIO(raw))
    elif name.endswith(".xz"):
        d = lzma.LZMAFile(io.BytesIO(raw))
    elif name.endswith(".bz2"):
        d = bz2.BZ2File(io.BytesIO(raw))
    elif name.endswith(".zst"):
        try:
            from compression import zstd              # Python 3.14+
        except ImportError:
            raise ConvertError("this package is zstd-compressed; that needs Python 3.14+ "
                               "(or recompress it: dpkg-deb --root-owner-group -Zxz -R ...)") from None
        d = zstd.ZstdFile(io.BytesIO(raw))
    elif name.endswith(".tar"):
        return raw
    else:
        raise ConvertError(f"unknown compression for {name}")
    out = d.read(limit + 1)
    if len(out) > limit:
        raise ConvertError("package expands to more than the limit")
    return out


def _control(fields_raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    key = None
    for line in fields_raw.splitlines():
        if line[:1] in (" ", "\t") and key:
            out[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, v = line.partition(":")
            out[key.strip()] = v.strip()
    return out


def _clean_path(n: str) -> Optional[str]:
    n = n.lstrip("./")
    while n.startswith("/"):
        n = n[1:]
    if not n:
        return None
    parts = n.split("/")
    if any(p == ".." for p in parts) or "\x00" in n or "\\" in n:
        raise ConvertError(f"unsafe path in package: {n!r}")
    return "/".join(p for p in parts if p not in ("", "."))


def _resolve_link(base: str, target: str) -> Optional[str]:
    if target.startswith("/"):
        path = target.lstrip("/")
    else:
        path = "/".join(base.split("/")[:-1] + [target])
    out: list[str] = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not out:
                return None
            out.pop()
        else:
            out.append(p)
    return "/".join(out)


# --------------------------------------------------------------------------- zip
def _write_kapp(files: dict[str, tuple[bytes, int]], manifest: dict, out: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        def add(name: str, data: bytes, mode: int) -> None:
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            deflated = zlib_len(data)
            ratio_ok = not data or not deflated or len(data) / max(1, deflated) <= MAX_RATIO * 0.8
            zi.compress_type = zipfile.ZIP_DEFLATED if (ratio_ok and len(data) < (8 << 20) and data) else zipfile.ZIP_STORED
            zi.external_attr = (stat.S_IFREG | mode) << 16
            z.writestr(zi, data)
        add(MANIFEST, json.dumps(manifest, indent=1).encode(), 0o644)
        for name in sorted(files):
            add(name, *files[name])
    data = buf.getvalue()
    KApp(data)                                        # validate exactly what we are about to ship
    out.write_bytes(data)
    return data


def zlib_len(data: bytes) -> int:
    import zlib
    return len(zlib.compress(data[:1 << 20], 1)) * max(1, len(data) // max(1, min(len(data), 1 << 20)))


# --------------------------------------------------------------------------- .deb
def convert_deb(src: Path, out: Path, *, name: Optional[str] = None, entry: Optional[str] = None) -> Report:
    src, out = Path(src), Path(out)
    raw = src.read_bytes() if src.stat().st_size <= MAX_DEB else None
    if raw is None:
        raise ConvertError("that .deb is larger than the 400 MiB limit")
    digest = hashlib.sha256(raw).hexdigest()
    members = _ar_members(raw)
    ctl_name = next((n for n in members if n.startswith("control.tar")), None)
    data_name = next((n for n in members if n.startswith("data.tar")), None)
    if not ctl_name or not data_name:
        raise ConvertError("not a Debian package: control.tar or data.tar is missing")
    control: dict[str, str] = {}
    scripts: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(_decompress(ctl_name, members[ctl_name]))) as t:
        for m in t.getmembers():
            base = m.name.lstrip("./")
            if base == "control" and m.isfile():
                control = _control(t.extractfile(m).read(1 << 20).decode("utf-8", "replace"))
            elif base in MAINTAINER_SCRIPTS:
                scripts.append(base)
    pkg = control.get("Package", src.stem)
    files: dict[str, tuple[bytes, int]] = {}
    links: list[tuple[str, str]] = []
    dropped: list[str] = []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(_decompress(data_name, members[data_name]))) as t:
        for m in t.getmembers():
            path = _clean_path(m.name)
            if path is None or m.isdir():
                continue
            if any((path + "/").startswith(p) or path.startswith(p) for p in DROP_PREFIXES):
                dropped.append(path)
                continue
            if m.issym():
                links.append((path, m.linkname))
                continue
            if m.islnk():
                links.append((path, "/" + (m.linkname or "")))
                continue
            if not m.isfile():
                dropped.append(path)                      # device nodes, FIFOs, ...
                continue
            if m.size > MAX_MEMBER:
                raise ConvertError(f"{path} is larger than the per-file limit")
            total += m.size
            if total > MAX_UNCOMPRESSED:
                raise ConvertError("the package expands to more than 1 GiB")
            mode = 0o755 if m.mode & 0o111 else 0o644      # setuid/setgid/sticky are dropped here
            files[path] = (t.extractfile(m).read(), mode)
    for path, target in links:                             # replace links by copies of in-package files
        for _ in range(8):
            dest = _resolve_link(path, target)
            if dest in files:
                files[path] = files[dest]
                break
            hop = next((l for l in links if l[0] == dest), None)
            if hop is None:
                dropped.append(path + " (link leaves the package or is broken)")
                break
            path_for = hop
            target = path_for[1]
            dest_base = path_for[0]
            dest = _resolve_link(dest_base, target)
            if dest in files:
                files[path] = files[dest]
                break
        else:
            dropped.append(path + " (link chain too long)")
    if len(files) + 2 > MAX_ENTRIES:
        keep = sorted(files, key=lambda p: (not p.startswith(("usr/bin/", "bin/", "usr/lib/", "lib/")), p))[:MAX_ENTRIES - 4]
        for p in set(files) - set(keep):
            dropped.append(p + " (over the entry limit)")
            del files[p]
    if not files:
        raise ConvertError("the package contains no files this converter can use")
    execs = sorted(p for p, (_, mode) in files.items()
                   if mode & 0o111 and p.startswith(("usr/bin/", "bin/", "usr/games/", "opt/")) and "/lib" not in p)
    chosen = _choose_entry(entry, pkg, execs, files)
    nm = app_name(name or pkg)
    desc = (control.get("Description", "") or "").splitlines()[0][:200] if control.get("Description") else ""
    depends = [d.strip() for d in control.get("Depends", "").split(",") if d.strip()]
    report = Report("deb", src.name, digest, nm, app_version(control.get("Version", "0")), chosen, desc, depends,
                    execs[:20], sorted(dropped)[:200], scripts, len(files))
    report.notes = [
        "maintainer scripts were NOT run" if scripts else "no maintainer scripts",
        f"{len(depends)} dependencies are listed, not installed" if depends else "no declared dependencies",
    ]
    manifest = {"name": nm, "version": report.version, "runtime": "bundle", "entry": chosen,
                "modes": ["tui", "cmd"], "permissions": [], "description": desc or f"{pkg} (converted from a .deb)",
                "commands": [{"id": "run", "title": f"Run {nm}", "keywords": [pkg.lower()[:24]]}]}
    files[CONVERTED] = (json.dumps(report.as_dict(), indent=1).encode(), 0o644)
    data = _write_kapp(files, manifest, out)
    if not scan_bytes(data, nm).clean:
        out.unlink(missing_ok=True)
        raise ConvertError("the converted app was flagged by the security scan; nothing was written")
    return report


def _choose_entry(entry: Optional[str], pkg: str, execs: list[str], files: dict) -> str:
    if entry:
        e = _clean_path(entry)
        if not e or e not in files or not BUNDLE_ENTRY_RE.match(e):
            raise ConvertError(f"--entry {entry!r} is not a file in the package")
        return e
    stem = pkg.lower()
    for want in (stem, stem.removeprefix("lib"), stem.split("-")[0]):
        hits = [p for p in execs if Path(p).name.lower() == want]
        if hits:
            return hits[0]
    if len(execs) == 1:
        return execs[0]
    desktop = [p for p in files if p.startswith("usr/share/applications/") and p.endswith(".desktop")]
    for d in desktop:
        m = re.search(rb"(?m)^Exec=(\S+)", files[d][0])
        if m:
            base = Path(m.group(1).decode("utf-8", "replace")).name
            hits = [p for p in execs if Path(p).name == base]
            if hits:
                return hits[0]
    raise ConvertError("cannot tell which program to run; pass --entry. Candidates: "
                       + (", ".join(execs[:12]) or "none (no executables under usr/bin, bin, usr/games, opt)"))


# --------------------------------------------------------------------------- AppImage
def is_appimage(head: bytes) -> int:
    """0 = not an AppImage, else its type (1 or 2)."""
    if head[:4] == b"\x7fELF" and head[8:10] == b"AI" and head[10] in (1, 2):
        return head[10]
    return 0


def convert_appimage(src: Path, out: Path, *, name: Optional[str] = None) -> Report:
    src, out = Path(src), Path(out)
    size = src.stat().st_size
    if size > 480 << 20:
        raise ConvertError("that AppImage is larger than the 480 MiB limit")
    raw = src.read_bytes()
    kind = is_appimage(raw[:16])
    if not kind:
        raise ConvertError("not an AppImage (no AppImage marker after the ELF header)")
    if kind == 1:
        raise ConvertError("this is a type 1 AppImage (ISO filesystem); only type 2 can be run without FUSE")
    digest = hashlib.sha256(raw).hexdigest()
    stem = re.sub(r"(?i)\.appimage$", "", src.name)
    ver = re.search(r"[-_ ]v?(\d+(?:\.\d+)+)", stem)
    base = re.split(r"[-_ ]v?\d", stem, maxsplit=1)[0] or stem
    nm = app_name(name or base, "app")
    report = Report("appimage", src.name, digest, nm, app_version(ver.group(1) if ver else "0"), "AppImage",
                    f"{base} (AppImage)", files=1)
    report.notes = ["runs with --appimage-extract-and-run (no FUSE): its filesystem is unpacked into a private "
                    "RAM scratch directory and executed from there, inside the sandbox",
                    "no network unless you grant it; a program that needs a graphical display has none in KOS"]
    manifest = {"name": nm, "version": report.version, "runtime": "bundle", "entry": "AppImage",
                "args": ["--appimage-extract-and-run"], "exec_scratch": True, "modes": ["tui", "cmd"],
                "permissions": [], "description": report.description[:200]}
    data = _write_kapp({"AppImage": (raw, 0o755), CONVERTED: (json.dumps(report.as_dict(), indent=1).encode(), 0o644)},
                       manifest, out)
    if not scan_bytes(data, nm).clean:
        out.unlink(missing_ok=True)
        raise ConvertError("the converted app was flagged by the security scan; nothing was written")
    return report


# --------------------------------------------------------------------------- entry point
def convert(src: Path, out: Optional[Path] = None, *, name: Optional[str] = None,
            entry: Optional[str] = None) -> tuple[Path, Report]:
    src = Path(src)
    if not src.is_file():
        raise ConvertError(f"{src}: no such file")
    with open(src, "rb") as f:
        head = f.read(16)
    if head[:8] == b"!<arch>\n" or src.suffix.lower() == ".deb":
        kind = "deb"
    elif is_appimage(head) or src.suffix.lower() == ".appimage":
        kind = "appimage"
    else:
        raise ConvertError("I can convert a .deb or an AppImage; this is neither")
    out = Path(out) if out else src.with_suffix(".kapp") if kind == "deb" else src.parent / (re.sub(r"(?i)\.appimage$", "", src.name) + ".kapp")
    report = convert_deb(src, out, name=name, entry=entry) if kind == "deb" else convert_appimage(src, out, name=name)
    return out, report
