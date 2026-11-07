#!/usr/bin/env python3
"""Build the whole repository into ONE Debian package.

    python3 packaging/build_deb.py [OUTPUT_DIR]        (default: dist/)

Standard library only. It does not need dpkg-deb; the package is assembled
directly (ar + tar) so the build is the same on any machine, and reproducible:
the same commit gives the same bytes (file times come from the commit time, and
owners are root).

What goes in: every file in the last commit, exactly as committed, under
``/usr/lib/kernal-os/``. Two symlinks make it usable: ``/usr/bin/kos`` and
``/usr/bin/kos-run`` (the repo's ``bin/run`` shortcut; it is not installed as
``/usr/bin/run`` because that name is too generic to take from other packages).

What does NOT go in, on purpose - these are KOS's own rules applied to its
package:

* no maintainer scripts (no preinst/postinst/prerm/postrm): installing or
  removing the package runs nothing, as root or otherwise;
* no services, no autostart, nothing under /etc or /lib/systemd;
* no setuid or setgid files;
* no state: ``/etc/kos`` and ``/var/lib/kos`` are created by ``kos setup`` when
  the owner chooses a password, never by the package.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "kernal-os"
PREFIX = "usr/lib/kernal-os"
LINKS = {"usr/bin/kos": "../lib/kernal-os/bin/kos",
         "usr/bin/kos-run": "../lib/kernal-os/bin/run"}
FORBIDDEN_CONTROL = ("preinst", "postinst", "prerm", "postrm", "config", "triggers")


class BuildError(Exception):
    pass


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          capture_output=True, text=True).stdout


def version_and_time() -> tuple[str, int]:
    base = None
    for line in (ROOT / "kos" / "__init__.py").read_text().splitlines():
        if line.startswith("__version__"):
            base = line.split("=", 1)[1].strip().strip("\"'")
    if not base:
        raise BuildError("no __version__ in kos/__init__.py")
    ctime = int(_git("log", "-1", "--format=%ct").strip())
    sha = _git("rev-parse", "--short", "HEAD").strip()
    day = __import__("time").strftime("%Y%m%d", __import__("time").gmtime(ctime))
    # '~' sorts before the plain release, so 0.1.0~git... is older than 0.1.0
    return f"{base}~git{day}.{sha}", ctime


def tracked_files() -> list[tuple[str, int, str]]:
    """(path, mode, blob id) for every file in the last commit. The package is
    built from the commit, not the working tree, so a version always means the
    same bytes and uncommitted edits can never leak in."""
    out = []
    for line in _git("ls-tree", "-r", "-z", "HEAD").split("\0"):
        if not line:
            continue
        meta, path = line.split("\t", 1)
        mode, kind, blob = meta.split()
        if kind != "blob" or mode == "120000":
            raise BuildError(f"{path} is a symlink or submodule in the repository; not packaged")
        out.append((path, 0o755 if mode == "100755" else 0o644, blob))
    out.sort()
    if not out:
        raise BuildError("the commit has no files")
    return out


def _blob(blob_id: str) -> bytes:
    return subprocess.run(["git", "-C", str(ROOT), "cat-file", "blob", blob_id],
                          check=True, capture_output=True).stdout


def _tarinfo(name: str, mtime: int, mode: int, size: int = 0, kind=tarfile.REGTYPE, link: str = ""):
    ti = tarfile.TarInfo(name)
    ti.mtime, ti.mode, ti.size, ti.type, ti.linkname = mtime, mode, size, kind, link
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti


def _tar_gz(entries, mtime: int) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        for ti, data in entries:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=mtime, compresslevel=9) as g:
        g.write(raw.getvalue())
    return out.getvalue()


def _ar(members: list[tuple[str, bytes]], mtime: int) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, blob in members:
        out += f"{name + '/':<16}{mtime:<12}{0:<6}{0:<6}{'100644':<8}{len(blob):<10}".encode() + b"`\n"
        out += blob
        if len(blob) % 2:
            out += b"\n"
    return bytes(out)


def build(out_dir: Path) -> Path:
    if _git("status", "--porcelain", "--untracked-files=no").strip():
        print("note: uncommitted changes are NOT in this package (it is built from HEAD)", file=sys.stderr)
    version, mtime = version_and_time()
    files = tracked_files()

    # --- data.tar: directories first, then files, then the two symlinks ---
    dirs: set[str] = set()
    def add_dirs(path: str) -> None:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    entries, md5s, size = [], [], 0
    all_paths = [f"{PREFIX}/{p}" for p, _, _ in files] + list(LINKS)
    for p in all_paths:
        add_dirs(p)
    for d in sorted(dirs):
        entries.append((_tarinfo(f"./{d}/", mtime, 0o755, kind=tarfile.DIRTYPE), None))
    for path, mode, blob in files:
        data = _blob(blob)
        size += len(data)
        rel = f"{PREFIX}/{path}"
        entries.append((_tarinfo(f"./{rel}", mtime, mode, len(data)), data))
        md5s.append(f"{hashlib.md5(data).hexdigest()}  {rel}\n")      # dpkg's md5sums format
    for link, target in sorted(LINKS.items()):
        entries.append((_tarinfo(f"./{link}", mtime, 0o777, kind=tarfile.SYMTYPE, link=target), None))
    data_tar = _tar_gz(entries, mtime)

    # --- control.tar ---
    description = (" A security-first operating system layer on the Linux kernel: nothing happens\n"
                   " without your password. Apps are zip files that are never unzipped, run in a\n"
                   " sandbox, and talk to the OS only through a command protocol.\n"
                   " .\n"
                   " This package installs files only. It has no maintainer scripts, starts no\n"
                   " service, and creates no state: run 'kos setup' to choose your password.")
    control = (f"Package: {NAME}\nVersion: {version}\nSection: admin\nPriority: optional\n"
               f"Architecture: all\nMaintainer: zach909 <zach909@users.noreply.github.com>\n"
               f"Installed-Size: {(size + 1023) // 1024}\nDepends: python3 (>= 3.11)\n"
               f"Suggests: qemu-system-x86, cryptsetup-bin, busybox-static, cpio\n"
               f"Homepage: https://github.com/zach909/kernal-os\n"
               f"Description: KOS, a security-first OS layer (every action needs your password)\n"
               f"{description}\n").encode()
    ctl_entries = [(_tarinfo("./", mtime, 0o755, kind=tarfile.DIRTYPE), None),
                   (_tarinfo("./control", mtime, 0o644, len(control)), control)]
    md5_blob = "".join(md5s).encode()
    ctl_entries.append((_tarinfo("./md5sums", mtime, 0o644, len(md5_blob)), md5_blob))
    for e, _ in ctl_entries:
        if e.name.lstrip("./") in FORBIDDEN_CONTROL:
            raise BuildError("maintainer scripts are not allowed in this package")
    control_tar = _tar_gz(ctl_entries, mtime)

    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control_tar),
               ("data.tar.gz", data_tar)], mtime)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{NAME}_{version}_all.deb"
    out.write_bytes(deb)
    return out


def main(argv: list[str]) -> int:
    out_dir = Path(argv[1]) if len(argv) > 1 else ROOT / "dist"
    try:
        deb = build(out_dir)
    except (BuildError, subprocess.CalledProcessError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{deb}  ({deb.stat().st_size} bytes)")
    print(f"sha256 {hashlib.sha256(deb.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
