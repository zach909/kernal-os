"""Migration: export everything to one encrypted bundle, import it on any OS.

Bundle (see PROTOCOL.md): a small plain header (key settings, authenticated), then one encrypted stream holding
a manifest and the file bodies. The manifest lists every file with its size and SHA-256; an import checks each
body against it and checks the whole stream's authentication before a single file is put in place.

Rules this module keeps:
* nothing in the source is changed;
* symlinks and special files are not followed or exported - they are listed as skipped;
* an import never writes outside its destination folders and never through a symlink;
* an import never overwrites: a different file already there makes the incoming one
  ``name (imported N).ext`` unless ``overwrite`` is asked for; an identical one is left alone;
* file names illegal on the target OS are fixed and every change is in the report.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import apps as apps_mod
from . import paths as P
from .crypto import (CryptoError, DEFAULT_KDF, decrypt_stream, encrypt_stream, master_key, new_password_ok,
                     subkey, SALT_LEN, check_kdf)

MAGIC = b"KOSMIG1\n"
FORMAT = 1
MAX_MANIFEST = 64 << 20
MAX_HEADER = 4096
MAX_ENTRIES = 2_000_000
ROLES = ("documents", "pictures", "music", "videos", "downloads", "desktop", "config", "other")


class MigrateError(Exception):
    pass


@dataclass
class ExportReport:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    skipped: list = field(default_factory=list)
    apps: int = 0


@dataclass
class ImportReport:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    already_there: int = 0
    kept_both: list = field(default_factory=list)       # [(wanted path, path used)]
    renamed: list = field(default_factory=list)          # [(original, path used on this OS)]
    install_commands: list = field(default_factory=list)
    no_equivalent: list = field(default_factory=list)
    source_os: str = ""
    dry_run: bool = False


def default_dir(role: str, osname: str, home: Path | None = None, env=None) -> Path | None:
    """Where a role lives by default on ``osname``; ``None`` where the person must say (phones, KOS)."""
    env = os.environ if env is None else env
    home = Path(home) if home else Path.home()
    if osname not in ("linux", "macos", "windows") or role == "other":
        return None
    names = {"documents": "Documents", "pictures": "Pictures", "music": "Music", "downloads": "Downloads",
             "desktop": "Desktop", "videos": "Movies" if osname == "macos" else "Videos"}
    if role in names:
        return home / names[role]
    if role == "config":
        if osname == "windows":
            return Path(env.get("APPDATA") or home / "AppData" / "Roaming")
        if osname == "macos":
            return home / "Library" / "Application Support"
        return Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    return None


# ---- export ---------------------------------------------------------------------------------------------

def _scan(role: str, root: Path, report: ExportReport) -> list[dict]:
    entries: list[dict] = []
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise MigrateError(f"{root} is not a plain folder")

    def walk(rel: str):
        here = root / rel if rel else root
        try:
            names = sorted(os.listdir(here))
        except OSError as e:
            report.skipped.append((f"{role}/{rel}", f"cannot list: {e.strerror}"))
            return
        for name in names:
            r = f"{rel}/{name}" if rel else name
            full = here / name
            try:
                st = os.lstat(full)
                P.validate(r)
            except (OSError, P.PathError) as e:
                report.skipped.append((f"{role}/{r}", f"unusable name or unreadable: {e}"))
                continue
            if stat.S_ISLNK(st.st_mode):
                report.skipped.append((f"{role}/{r}", "symbolic link (not followed)"))
            elif stat.S_ISDIR(st.st_mode):
                entries.append({"role": role, "path": r, "kind": "dir", "mode": stat.S_IMODE(st.st_mode),
                                "mtime": int(st.st_mtime_ns // 10**9)})
                walk(r)
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                try:
                    with open(full, "rb") as fh:
                        for blk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(blk)
                except OSError as e:
                    report.skipped.append((f"{role}/{r}", f"cannot read: {e.strerror}"))
                    continue
                entries.append({"role": role, "path": r, "kind": "file", "size": st.st_size, "sha256": h.hexdigest(),
                                "mode": stat.S_IMODE(st.st_mode), "mtime": int(st.st_mtime_ns // 10**9)})
            else:
                report.skipped.append((f"{role}/{r}", "not a regular file"))
    walk("")
    return entries


class _Source:
    """Plaintext of a bundle: length-prefixed manifest, then each file body, each re-checked as it is read."""

    def __init__(self, manifest: bytes, files: list[tuple[Path, dict]]):
        self.parts = [io.BytesIO(len(manifest).to_bytes(4, "big") + manifest)]
        self.files = files
        self.cur = self.parts[0]
        self.idx = 0
        self.fh = None
        self.hash = None
        self.read_n = 0

    def _next_file(self):
        if self.idx >= len(self.files):
            return False
        path, entry = self.files[self.idx]
        self.fh = open(path, "rb")
        self.hash = hashlib.sha256()
        self.read_n = 0
        self.entry = entry
        return True

    def _end_file(self):
        self.fh.close()
        self.fh = None
        if self.read_n != self.entry["size"] or self.hash.hexdigest() != self.entry["sha256"]:
            raise MigrateError(f"{self.entry['role']}/{self.entry['path']} changed while it was being exported; "
                               "close the programs using it and export again")
        self.idx += 1

    def read(self, n=-1):
        out = bytearray()
        while len(out) < n:
            if self.cur is not None:
                b = self.cur.read(n - len(out))
                if b:
                    out += b
                    continue
                self.cur = None
            if self.fh is None and not self._next_file():
                break
            b = self.fh.read(n - len(out))
            if b:
                self.hash.update(b)
                self.read_n += len(b)
                out += b
            else:
                self._end_file()
        return bytes(out)


def export_bundle(roots: dict, out, password: str, *, include_apps=False, source_os=None, kdf=None,
                  apps_runner=None) -> ExportReport:
    """Write ``out`` (a new file). ``roots`` maps a role (documents, pictures, ...) to a folder."""
    new_password_ok(password)
    out = Path(out)
    if out.exists():
        raise MigrateError(f"{out} already exists; it is never overwritten")
    for role in roots:
        if role not in ROLES:
            raise MigrateError(f"unknown role {role!r}; use one of {', '.join(ROLES)}")
    source_os = source_os or P.detect_os()
    kdf = check_kdf(kdf or DEFAULT_KDF)
    report = ExportReport()
    entries: list[dict] = []
    for role, root in sorted(roots.items()):
        entries += _scan(role, Path(root), report)
    if len(entries) > MAX_ENTRIES:
        raise MigrateError("too many files for one bundle; export fewer folders")
    app_list = (apps_mod.collect(source_os, **({"run": apps_runner} if apps_runner else {}))
                if include_apps else [])
    manifest = {"format": FORMAT, "created": int(time.time()), "source_os": source_os, "entries": entries,
                "apps": app_list, "skipped": [list(s) for s in report.skipped]}
    mbytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    salt = secrets.token_bytes(SALT_LEN)
    header = json.dumps({"v": FORMAT, "kdf": {"alg": "scrypt", **kdf}, "salt": salt.hex()},
                        sort_keys=True, separators=(",", ":")).encode()
    key = subkey(master_key(password, salt, kdf), "bundle")
    files = [(Path(roots[e["role"]]) / e["path"], e) for e in entries if e["kind"] == "file"]
    tmp = out.with_name(out.name + f".part-{secrets.token_hex(4)}")
    try:
        with open(tmp, "xb") as fh:
            fh.write(MAGIC + len(header).to_bytes(4, "big") + header)
            encrypt_stream(key, MAGIC + header, _Source(mbytes, files), fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    report.files = sum(e["kind"] == "file" for e in entries)
    report.dirs = sum(e["kind"] == "dir" for e in entries)
    report.bytes = sum(e.get("size", 0) for e in entries)
    report.apps = len(app_list)
    return report


# ---- import ---------------------------------------------------------------------------------------------

def _open_bundle(fh, password: str) -> tuple:
    if fh.read(len(MAGIC)) != MAGIC:
        raise MigrateError("this is not a kosync bundle")
    raw = fh.read(4)
    hl = int.from_bytes(raw, "big") if len(raw) == 4 else 0
    if not 2 <= hl <= MAX_HEADER:
        raise MigrateError("bundle header is damaged")
    header = fh.read(hl)
    try:
        meta = json.loads(header)
        if meta["v"] != FORMAT:
            raise MigrateError(f"bundle format {meta['v']!r} is not supported by this version")
        kdf = check_kdf(meta["kdf"])
        salt = bytes.fromhex(meta["salt"])
        return subkey(master_key(password, salt, kdf), "bundle"), MAGIC + header
    except (ValueError, KeyError, TypeError):
        raise MigrateError("bundle header is damaged") from None


class _Sink:
    """Receives the decrypted stream: manifest first, then each file body in manifest order."""

    def __init__(self, stage: dict | None):
        self.stage = stage                      # role -> staging folder; None means verify only
        self.buf = bytearray()
        self.state = "len"
        self.need = 0
        self.manifest = None
        self.files: list = []
        self.i = 0
        self.staged: dict = {}                  # (role, path) -> staged file
        self.fh = None
        self.hash = None
        self.remaining = 0

    @staticmethod
    def _entry_valid(e):
        if not isinstance(e, dict) or e.get("role") not in ROLES or e.get("kind") not in ("file", "dir"):
            raise MigrateError("manifest entry is damaged")
        try:
            P.validate(e["path"])
        except (KeyError, P.PathError):
            raise MigrateError("manifest entry has an unsafe path") from None
        if e["kind"] == "file" and (type(e.get("size")) is not int or e["size"] < 0
                                    or not isinstance(e.get("sha256"), str) or len(e["sha256"]) != 64):
            raise MigrateError("manifest entry is damaged")
        if type(e.get("mode")) is not int or type(e.get("mtime")) is not int:
            raise MigrateError("manifest entry is damaged")

    def write(self, data: bytes):
        self.buf += data
        while True:
            if self.state == "len":
                if len(self.buf) < 4:
                    return
                self.need = int.from_bytes(self.buf[:4], "big")
                del self.buf[:4]
                if not 0 < self.need <= MAX_MANIFEST:
                    raise MigrateError("manifest size is damaged")
                self.state = "manifest"
            elif self.state == "manifest":
                if len(self.buf) < self.need:
                    return
                raw = bytes(self.buf[:self.need])
                del self.buf[:self.need]
                try:
                    self.manifest = json.loads(raw)
                    entries = self.manifest["entries"]
                    if self.manifest.get("format") != FORMAT or not isinstance(entries, list):
                        raise ValueError
                except (ValueError, KeyError, TypeError, AttributeError):
                    raise MigrateError("manifest is damaged") from None
                for e in entries:
                    self._entry_valid(e)
                self.files = [e for e in entries if e["kind"] == "file"]
                self.state = "body"
                self._begin()
            else:
                if self.i >= len(self.files):
                    if self.buf:
                        raise MigrateError("extra data after the last file")
                    return
                take = bytes(self.buf[:self.remaining])
                if not take:
                    return
                del self.buf[:len(take)]
                self.hash.update(take)
                if self.fh:
                    self.fh.write(take)
                self.remaining -= len(take)
                if self.remaining:
                    return
                self._finish()
                self.i += 1
                self._begin()

    def _begin(self):
        """Open the next file with a body; empty files finish at once."""
        while self.i < len(self.files):
            e = self.files[self.i]
            self.hash = hashlib.sha256()
            self.remaining = e["size"]
            self.fh = None
            if self.stage is not None:
                p = self.stage[e["role"]] / f"{len(self.staged)}.part"
                self.staged[(e["role"], e["path"])] = p
                self.fh = open(p, "wb")
            if self.remaining:
                return
            self._finish()
            self.i += 1

    def _finish(self):
        e = self.files[self.i]
        if self.fh:
            self.fh.close()
            self.fh = None
        if self.hash.hexdigest() != e["sha256"]:
            raise MigrateError(f"{e['role']}/{e['path']} does not match its checksum")

    def done(self):
        if self.manifest is None or self.state != "body" or self.i < len(self.files) or self.buf:
            raise MigrateError("bundle ended before every file arrived")


def _safe_dirs(root: Path, rel: str) -> Path:
    """Create the parent folders of ``root/rel`` one at a time, refusing any symlink on the way."""
    cur = root
    for part in rel.split("/")[:-1]:
        cur = cur / part
        if cur.is_symlink():
            raise MigrateError(f"{cur} is a symbolic link; refusing to write through it")
        if not cur.exists():
            cur.mkdir()
        elif not cur.is_dir():
            raise MigrateError(f"{cur} exists and is not a folder")
    return cur


def _free_name(path: Path) -> Path:
    stem, ext = path.stem, path.suffix
    n = 1
    while True:
        cand = path.with_name(f"{stem} (imported {n}){ext}")
        if not os.path.lexists(cand):
            return cand
        n += 1


def import_bundle(bundle, dests: dict, password: str, *, target_os=None, overwrite=False, dry_run=False,
                  default_dest=None) -> ImportReport:
    """Put a bundle's files in place. ``dests`` maps each role in the bundle to a folder on this machine."""
    target_os = target_os or P.detect_os()
    report = ImportReport(dry_run=dry_run)
    with open(bundle, "rb") as fh:
        key, aad = _open_bundle(fh, password)
        # pass 1 (always): verify the whole stream and read the manifest. Bodies are staged only when we will use them.
        start = fh.tell()
        probe = _Sink(None)
        try:
            decrypt_stream(key, aad, fh, probe)
            probe.done()
        except CryptoError as e:
            raise MigrateError(str(e)) from None
        manifest = probe.manifest
        entries = manifest["entries"]
        report.source_os = str(manifest.get("source_os", ""))
        roles = sorted({e["role"] for e in entries})
        dests = dict(dests)
        for r in roles:
            if r not in dests and default_dest and default_dest(r) is not None:
                dests[r] = default_dest(r)
        missing = [r for r in roles if r not in dests]
        if missing and not dry_run:
            raise MigrateError("say where these go on this OS (--dest ROLE=FOLDER): " + ", ".join(missing))
        orig = [f"{e['role']}/{e['path']}" for e in entries]
        plan = P.plan(orig, target_os)
        report.renamed = [(o, n) for o, n in plan.items() if o != n]
        report.files = sum(e["kind"] == "file" for e in entries)
        report.dirs = sum(e["kind"] == "dir" for e in entries)
        report.bytes = sum(e.get("size", 0) for e in entries)
        report.install_commands, report.no_equivalent = apps_mod.install_hints(manifest.get("apps", []), target_os)
        if dry_run:
            return report
        # pass 2: stage the bodies next to their destinations (same file system, so the final move is a rename)
        stage_dirs: dict[str, Path] = {}
        try:
            for r in roles:
                root = Path(dests[r])
                root.mkdir(parents=True, exist_ok=True)
                if root.is_symlink():
                    raise MigrateError(f"{root} is a symbolic link")
                d = root / f".kosync-import-{secrets.token_hex(4)}"
                d.mkdir()
                stage_dirs[r] = d
            fh.seek(start)
            sink = _Sink(stage_dirs)
            try:
                decrypt_stream(key, aad, fh, sink)
                sink.done()
            except CryptoError as e:
                raise MigrateError(str(e)) from None
            for e in entries:
                new = plan[f"{e['role']}/{e['path']}"].split("/", 1)[1]
                root = Path(dests[e["role"]])
                parent = _safe_dirs(root, new)
                final = parent / new.rsplit("/", 1)[-1]
                if e["kind"] == "dir":
                    if final.is_symlink():
                        raise MigrateError(f"{final} is a symbolic link")
                    final.mkdir(exist_ok=True)
                    continue
                staged = sink.staged[(e["role"], e["path"])]
                if os.path.lexists(final):
                    if final.is_symlink() or final.is_dir():
                        final = _free_name(final)
                        report.kept_both.append((new, final.name))
                    elif not overwrite:
                        if _same_content(final, e["sha256"]):
                            report.already_there += 1
                            continue
                        final = _free_name(final)
                        report.kept_both.append((new, str(final.relative_to(root)).replace(os.sep, "/")))
                os.replace(staged, final)
                if os.name == "posix":
                    os.chmod(final, (e["mode"] & 0o777) | 0o600)
                os.utime(final, (e["mtime"], e["mtime"]))
        finally:
            for d in stage_dirs.values():
                shutil.rmtree(d, ignore_errors=True)
    return report


def _same_content(path: Path, sha: str) -> bool:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
    except OSError:
        return False
    return h.hexdigest() == sha
