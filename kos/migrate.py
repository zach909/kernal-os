"""Migration: pack everything you have into one encrypted file, and unpack it on another computer or
another operating system, losing nothing and changing nothing it does not have to.

What it does
------------
``export_bundle`` walks the folders you name (and, on KOS, your installed apps and permission list),
and writes one file: ``.kmig``. ``import_bundle`` reads it on the new machine, which can run KOS,
Linux, macOS or Windows (anything that can run this file; a phone gets the bundle as a folder after it is
unpacked on a computer, see docs/SYNC.md). Bytes are never converted: no line endings, no encodings,
no "optimisation". A file comes out with the same SHA-256 it went in with.

The guarantees, and how each is kept
------------------------------------
* **Confidential and tamper-evident.** ChaCha20-Poly1305 over 192 KiB chunks, key from scrypt over a
  passphrase you choose (not your KOS password: it has to work where KOS is not installed). Every chunk
  is bound to the header and to its position, so a flipped bit, a swapped chunk, a dropped chunk, or a
  bundle cut short all fail authentication. A bundle with no end record is refused.
* **Nothing is written until everything verifies.** ``import_bundle`` reads the whole bundle once to check
  every chunk and every file's SHA-256 against its record, and only then reads it again to write. A bad
  bundle changes nothing on disk.
* **Never overwrites.** A file that is already there with the same content is left alone; one that
  differs is kept and the migrated copy is written beside it with a ``(migrated xxxxxxxx)`` suffix.
* **Names survive the trip.** A name that cannot exist on the target (Windows: ``a:b``, ``con``, a trailing
  dot; macOS and Windows: two names that differ only by case or accents) is given a deterministic,
  unique replacement, and ``MIGRATION-REPORT.txt`` lists every one. Nothing is dropped silently.
* **Paths from the bundle are hostile input.** Same checks as sync (``portable.safe_relative``, no
  symlink on the way down, temp file then hash check then rename: ``syncer.Applier``).
* **KOS parts are staged, not applied.** Apps arrive in ``kos-staging/apps/`` and are installed with
  ``kos install`` (scan, password, seal, proof: README rule 1); the old permission list arrives as a
  file to *read*, because a grant needs its password.

What is deliberately NOT carried, and why
-----------------------------------------
The password and its throttle (a new machine sets its own), the audit log (it is anchored to the old
password), the firewall rules (sealed under the old password), the AI key (a secret), and this device's link
identity (a copy would let two devices pose as one: link them again). Extended attributes, ACLs,
macOS resource forks, hard-link structure, and symlinks are not preserved (symlinks are listed as
skipped). Timestamps are kept to the second; permission bits are kept on POSIX targets with setuid/setgid
and world-write removed.

It does not install an operating system. "Switching OS" means: install the new one the usual way, then
import. Whole numbers only. Primitives are the vetted ``cryptography`` ones.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import portable
from .auth import AuditLog, Authority
from .paths import Paths
from .syncer import CHUNK, Applier, SyncError, sha256_file

MAGIC = b"KOSMIG1\n"
VERSION = 1
SALT_LEN = 16
HEADER = struct.Struct(">8s16sIII")       # magic, salt, scrypt n, r, p
KDF_N, KDF_R, KDF_P = 2 ** 15, 8, 1
KDF_N_MIN, KDF_N_MAX = 2 ** 10, 2 ** 17    # what a bundle may ask for when it is *opened*
MIN_PASSPHRASE = 12
MAX_RECORD = 1 + (1 << 20)
MAX_FILES = 2_000_000
MAX_TOTAL = 1 << 40
MAX_SKIPPED = 1000
TARGETS = ("kos", "linux", "macos", "windows", "ios", "android")

T_META, T_BEGIN, T_DATA, T_END_FILE, T_END = 1, 2, 3, 4, 5

# What on a KOS machine goes into a bundle besides the folders you name, and where it lands on import.
STAGE_APPS, STAGE_GRANTS = "kos/apps/", "kos/permissions/grants.json"
STAGING = "kos-staging"
REPORT_NAME = "MIGRATION-REPORT.txt"


class MigrateError(Exception):
    """A refusal or a failure with a reason fit to show the owner. Nothing was left half done."""


@dataclass
class Source:
    arcname: str           # path inside the bundle: files/<root>/<rel>  or  kos/...
    path: Path


@dataclass
class Summary:
    files: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    digest: str = ""


@dataclass
class Report:
    written: list[str] = field(default_factory=list)
    identical: list[str] = field(default_factory=list)                 # already there, same bytes
    kept_both: list[tuple[str, str]] = field(default_factory=list)     # (existing path, where the migrated copy went)
    renamed: list[tuple[str, str, str]] = field(default_factory=list)  # (original, new, reason)
    staged: list[str] = field(default_factory=list)
    skipped_at_source: list[str] = field(default_factory=list)
    bytes: int = 0

    def text(self) -> str:
        lines = [f"KOS migration report: {len(self.written)} files written, {len(self.identical)} already there "
                 f"(same bytes), {len(self.kept_both)} kept beside different files, {len(self.renamed)} renamed for "
                 f"this system, {len(self.staged)} staged for you to review, {self.bytes} bytes."]
        for orig, new, why in self.renamed:
            lines.append(f"renamed: {orig} -> {new}  ({why})")
        for old, new in self.kept_both:
            lines.append(f"kept both: {old} was different; the migrated copy is {new}")
        for s in self.staged:
            lines.append(f"staged: {s}")
        for s in self.skipped_at_source:
            lines.append(f"left behind on the old computer: {s}")
        return "\n".join(lines) + "\n"


# ---- the container -------------------------------------------------------------------------------

def _key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise MigrateError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")


class _Writer:
    def __init__(self, f, passphrase: str, n: int = KDF_N):
        if not KDF_N_MIN <= n <= KDF_N_MAX:
            raise MigrateError("scrypt cost out of range")
        salt = secrets.token_bytes(SALT_LEN)
        self.header = HEADER.pack(MAGIC, salt, n, KDF_R, KDF_P)
        self.aead = ChaCha20Poly1305(_key(passphrase, salt, n, KDF_R, KDF_P))
        self.bind = hashlib.sha256(self.header).digest()
        self.f, self.counter = f, 0
        f.write(self.header)

    def put(self, kind: int, payload: bytes = b"") -> None:
        body = bytes([kind]) + payload
        if len(body) > MAX_RECORD:
            raise MigrateError("record too large")
        ct = self.aead.encrypt(_nonce(self.counter), body, self.bind + self.counter.to_bytes(8, "big"))
        self.f.write(struct.pack(">I", len(ct)) + ct)
        self.counter += 1

    def put_json(self, kind: int, obj: dict) -> None:
        self.put(kind, json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def _records(path: Path, passphrase: str) -> Iterator[tuple[int, bytes]]:
    """Every record of the bundle, in order, each one authenticated. A bundle that stops before its END
    record raises: truncation is an error, never a short bundle."""
    with open(path, "rb") as f:
        raw = f.read(HEADER.size)
        if len(raw) != HEADER.size:
            raise MigrateError("this is not a KOS migration bundle (too short)")
        magic, salt, n, r, p = HEADER.unpack(raw)
        if magic != MAGIC:
            raise MigrateError("this is not a KOS migration bundle")
        if not (KDF_N_MIN <= n <= KDF_N_MAX and n & (n - 1) == 0 and r == KDF_R and p == KDF_P):
            raise MigrateError("the bundle asks for key settings KOS does not accept")
        aead = ChaCha20Poly1305(_key(passphrase, salt, n, r, p))
        bind = hashlib.sha256(raw).digest()
        counter, ended = 0, False
        while True:
            head = f.read(4)
            if not head:
                if not ended:
                    raise MigrateError("the bundle is cut short (no end record): nothing was imported")
                return
            if ended:
                raise MigrateError("the bundle has data after its end: refused")
            if len(head) != 4:
                raise MigrateError("the bundle is damaged (cut inside a record)")
            (length,) = struct.unpack(">I", head)
            if not 17 <= length <= MAX_RECORD + 16:
                raise MigrateError("the bundle is damaged (bad record size)")
            ct = f.read(length)
            if len(ct) != length:
                raise MigrateError("the bundle is cut short inside a record")
            try:
                body = aead.decrypt(_nonce(counter), ct, bind + counter.to_bytes(8, "big"))
            except InvalidTag:
                raise MigrateError("wrong passphrase, or the bundle was changed, reordered or damaged") from None
            counter += 1
            ended = body[0] == T_END
            yield body[0], body[1:]


def _json(payload: bytes) -> dict:
    def bad(_):
        raise ValueError
    try:
        d = json.loads(payload.decode("utf-8"), parse_float=bad, parse_constant=bad)
    except (ValueError, UnicodeDecodeError):
        raise MigrateError("the bundle holds a record that is not whole-number JSON") from None
    if not isinstance(d, dict):
        raise MigrateError("the bundle holds a malformed record")
    return d


# ---- choosing what goes in -----------------------------------------------------------------------

def _safe_root_name(name: str) -> str:
    out = "".join(c if c.isalnum() or c in "-_." else "-" for c in name).strip(".-") or "folder"
    return out[:60]


def collect(paths: Optional[Paths], roots: list[Path], include_kos: bool = True) -> tuple[list[Source], list[str]]:
    """Everything to pack, and what was left out and why. ``roots`` are folders (each becomes
    ``files/<name>/...``). With ``include_kos`` and a KOS state dir: the installed apps and the permission list."""
    sources: list[Source] = []
    skipped: list[str] = []
    used: set[str] = set()
    for root in roots:
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise MigrateError(f"{root} is not a folder (a symlink is not followed)")
        name = _safe_root_name(root.name)
        while name in used:
            name += "-2"
        used.add(name)
        stack = [(root, "")]
        while stack:
            folder, prefix = stack.pop()
            try:
                entries = sorted(os.scandir(folder), key=lambda e: e.name)
            except OSError as e:
                skipped.append(f"{name}/{prefix}: cannot read ({e.strerror})")
                continue
            for e in entries:
                rel = prefix + e.name                   # the real on-disk name: never rewritten
                try:
                    st = e.stat(follow_symlinks=False)
                    portable.safe_relative(rel)
                except OSError:
                    skipped.append(f"{name}/{rel}: cannot read")
                    continue
                except portable.PathRefused as ex:
                    skipped.append(f"{name}/{rel!r}: {ex}")
                    continue
                if stat.S_ISLNK(st.st_mode):
                    skipped.append(f"{name}/{rel}: a symlink (not preserved)")
                elif stat.S_ISDIR(st.st_mode):
                    stack.append((Path(e.path), rel + "/"))
                elif stat.S_ISREG(st.st_mode):
                    arc = f"files/{name}/{rel}"
                    try:
                        portable.safe_relative(arc)
                    except portable.PathRefused as ex:
                        skipped.append(f"{name}/{rel}: {ex}")
                        continue
                    sources.append(Source(arc, Path(e.path)))
                else:
                    skipped.append(f"{name}/{rel}: not a regular file")
    if include_kos and paths is not None:
        if paths.apps.is_dir():
            for f in sorted(paths.apps.glob("*.kapp")):
                if f.is_file() and not f.is_symlink():
                    sources.append(Source(STAGE_APPS + f.name, f))
        grants = paths.state.joinpath("permissions", "grants.json")
        if grants.is_file() and not grants.is_symlink():
            sources.append(Source(STAGE_GRANTS, grants))
    return sources, skipped


# ---- writing -------------------------------------------------------------------------------------

def write_bundle(sources: list[Source], out: Path, passphrase: str, skipped: Optional[list[str]] = None,
                 source_os: str = "kos", kdf_n: int = KDF_N, now: Optional[int] = None) -> Summary:
    """Write ``out`` (which must not exist). A file that changes while it is being read fails the whole
    export, and the partial output is deleted: a bundle is complete or absent."""
    out = Path(out)
    if out.exists() or out.is_symlink():
        raise MigrateError(f"{out} already exists: pick a new name (a bundle is never overwritten)")
    if len(sources) > MAX_FILES:
        raise MigrateError("too many files for one bundle")
    tmp = out.with_name(f".{out.name}.partial.{os.getpid()}.{secrets.token_hex(4)}")
    summary = Summary(skipped=list((skipped or [])[:MAX_SKIPPED]))
    leaves = hashlib.sha256()
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            w = _Writer(f, passphrase, kdf_n)
            w.put_json(T_META, {"v": VERSION, "created": int(now if now is not None else time.time()),
                                "source_os": source_os, "files": len(sources)})
            for s in sorted(sources, key=lambda s: s.arcname):
                st = os.lstat(s.path)
                if not stat.S_ISREG(st.st_mode):
                    raise MigrateError(f"{s.path} is no longer a regular file")
                w.put_json(T_BEGIN, {"p": s.arcname, "n": st.st_size, "m": stat.S_IMODE(st.st_mode),
                                     "t": st.st_mtime_ns // 1_000_000_000})
                h, seen = hashlib.sha256(), 0
                with open(s.path, "rb") as src:
                    while True:
                        block = src.read(CHUNK)
                        if not block:
                            break
                        h.update(block)
                        seen += len(block)
                        w.put(T_DATA, block)
                if seen != st.st_size:
                    raise MigrateError(f"{s.path} changed while it was being packed: try again when it is quiet")
                w.put_json(T_END_FILE, {"h": h.hexdigest()})
                leaves.update(f"{s.arcname}\0{h.hexdigest()}\n".encode())
                summary.files += 1
                summary.bytes += seen
                if summary.bytes > MAX_TOTAL:
                    raise MigrateError("too much data for one bundle")
            summary.digest = leaves.hexdigest()
            w.put_json(T_END, {"files": summary.files, "bytes": summary.bytes, "digest": summary.digest,
                               "skipped": summary.skipped})
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, out)         # fails if ``out`` appeared meanwhile: never overwrites
            os.unlink(tmp)
        except FileExistsError:
            raise MigrateError(f"{out} appeared while the bundle was being written: not overwritten") from None
        except OSError:               # a file system with no hard links (FAT, some network shares)
            if out.exists() or out.is_symlink():
                raise MigrateError(f"{out} appeared while the bundle was being written: not overwritten") from None
            os.rename(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return summary


# ---- reading -------------------------------------------------------------------------------------

@dataclass
class Meta:
    created: int
    source_os: str
    files: int
    bytes: int
    digest: str
    skipped: list[str]
    names: list[str]


def verify_bundle(path: Path, passphrase: str) -> Meta:
    """Read the whole bundle and check everything: every chunk's authentication, every file's size and
    SHA-256, the file count and total, and the end digest. Writes nothing."""
    meta, cur, h, size, got, leaves = None, None, None, 0, 0, hashlib.sha256()
    files = total = 0
    seen_paths: set[str] = set()
    names: list[str] = []
    end = None
    for kind, payload in _records(path, passphrase):
        if meta is None:
            if kind != T_META:
                raise MigrateError("the bundle does not start with its description")
            meta = _json(payload)
            if meta.get("v") != VERSION:
                raise MigrateError("this bundle is from a newer KOS: update KOS to read it")
            continue
        if kind == T_BEGIN:
            if cur is not None:
                raise MigrateError("a file started before the last one ended")
            d = _json(payload)
            try:
                portable.safe_relative(d["p"])
                if type(d["n"]) is not int or d["n"] < 0 or type(d["m"]) is not int or type(d["t"]) is not int:
                    raise ValueError
            except (KeyError, ValueError, portable.PathRefused) as e:
                raise MigrateError(f"the bundle names a file I refuse ({e})") from None
            if not (d["p"].startswith("files/") or d["p"] == STAGE_GRANTS or d["p"].startswith(STAGE_APPS)):
                raise MigrateError(f"the bundle holds a path KOS does not restore: {d['p']!r}")
            if d["p"] in seen_paths:
                raise MigrateError(f"the bundle holds {d['p']!r} twice: refused")
            seen_paths.add(d["p"])
            cur, h, size, got = d, hashlib.sha256(), d["n"], 0
        elif kind == T_DATA:
            if cur is None or len(payload) > CHUNK:
                raise MigrateError("file data outside a file")
            h.update(payload)
            got += len(payload)
            if got > size:
                raise MigrateError(f"{cur['p']}: more data than its recorded size")
        elif kind == T_END_FILE:
            if cur is None:
                raise MigrateError("a file ended that never started")
            want = _json(payload).get("h")
            if got != size or h.hexdigest() != want:
                raise MigrateError(f"{cur['p']}: its bytes do not match its recorded hash; nothing was imported")
            leaves.update(f"{cur['p']}\0{want}\n".encode())
            names.append(cur["p"])
            files += 1
            total += size
            if files > MAX_FILES or total > MAX_TOTAL:
                raise MigrateError("the bundle is larger than KOS will restore")
            cur = None
        elif kind == T_END:
            if cur is not None:
                raise MigrateError("the bundle ended inside a file")
            end = _json(payload)
        else:
            raise MigrateError("the bundle holds a record type KOS does not know")
    if end is None or meta is None:
        raise MigrateError("the bundle has no end record")
    if (end.get("files"), end.get("bytes"), end.get("digest")) != (files, total, leaves.hexdigest()):
        raise MigrateError("the bundle's totals do not match what it holds: refused")
    skipped = [str(s)[:300] for s in end.get("skipped", [])][:MAX_SKIPPED] if isinstance(end.get("skipped"), list) else []
    return Meta(meta.get("created", 0), str(meta.get("source_os", "?"))[:20], files, total, leaves.hexdigest(), skipped, names)


def restore_bundle(path: Path, passphrase: str, dest: Path, target_os: str = "linux") -> Report:
    """Unpack into ``dest``. Verifies the whole bundle first (``verify_bundle``): if anything is wrong,
    nothing is written. After that only the disk can fail (full, read-only); a temp file is never left
    behind, and files already finished stay (and are listed in ``MIGRATION-REPORT.txt`` on a re-run)."""
    if target_os not in TARGETS:
        raise MigrateError(f"target must be one of {', '.join(TARGETS)}")
    dest = Path(dest)
    if dest.is_symlink() or not dest.is_dir():
        raise MigrateError(f"{dest} must be an existing folder (not a symlink)")
    meta = verify_bundle(path, passphrase)                       # pass 1: nothing is written unless all of it is good
    ap = Applier(dest)
    ap.sweep()
    rep = Report(skipped_at_source=meta.skipped)
    fold = target_os in ("windows", "macos", "ios")              # case- and accent-insensitive targets
    taken: dict[str, str] = {}                                   # folded name -> real name, for this run
    cur: Optional[dict] = None
    try:
        for kind, payload in _records(path, passphrase):         # pass 2: write
            if kind == T_BEGIN:
                d = _json(payload)
                final, note = _destination(d["p"], target_os)
                final, extra = _avoid_collision(final, fold, taken)
                cur = {"d": d, "dest": final, "note": "; ".join(x for x in (note, extra) if x),
                       "spool": _Spool(ap, final)}
            elif kind == T_DATA and cur:
                cur["spool"].write(payload)
            elif kind == T_END_FILE and cur:
                _finish_file(ap, cur, _json(payload)["h"], rep)
                cur = None
    except SyncError as e:
        raise MigrateError(str(e)) from None
    finally:
        if cur is not None:
            cur["spool"].discard()
    name = REPORT_NAME if not dest.joinpath(REPORT_NAME).exists() else f"MIGRATION-REPORT-{meta.digest[:8]}.txt"
    if not dest.joinpath(name).exists():
        dest.joinpath(name).write_text(rep.text(), encoding="utf-8")
    return rep


class _Spool:
    """A temp file inside the destination folder, hashed as it is written. The path is checked for
    symlinks *before* any folder is made, and again after."""

    def __init__(self, ap: Applier, final: str):
        target = ap._target(final)
        target.parent.mkdir(parents=True, exist_ok=True)
        ap._target(final)
        self.path = target.parent.joinpath(f"{TMP}{secrets.token_hex(6)}")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.f = os.fdopen(fd, "wb")
        self.h, self.n = hashlib.sha256(), 0

    def write(self, data: bytes) -> None:
        self.f.write(data)
        self.h.update(data)
        self.n += len(data)

    def close(self) -> tuple[str, int]:
        self.f.flush()
        os.fsync(self.f.fileno())
        self.f.close()
        return self.h.hexdigest(), self.n

    def discard(self) -> None:
        try:
            self.f.close()
        except Exception:
            pass
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


TMP = ".kos-tmp-"


def _destination(arc: str, target_os: str) -> tuple[str, str]:
    """Where an archive path lands inside ``dest`` and a note if the name had to change."""
    if arc == STAGE_GRANTS:
        return f"{STAGING}/permissions-to-review.json", ""
    if arc.startswith(STAGE_APPS):
        return f"{STAGING}/apps/{arc[len(STAGE_APPS):]}", ""
    rel = arc[len("files/"):]
    fixed = portable.portable(rel) if target_os == "windows" else rel
    return fixed, ("name not allowed on Windows" if fixed != rel else "")


def _avoid_collision(final: str, fold: bool, taken: dict) -> tuple[str, str]:
    """Two names that are one file on this target (case, accents) must not overwrite each other."""
    def key(p: str) -> str:
        return portable.normalize(p).casefold() if fold else p
    note = ""
    if key(final) in taken and taken[key(final)] != final:
        tag = hashlib.sha256(final.encode()).hexdigest()[:6]
        head, slash, name = final.rpartition("/")
        stem, dot, ext = name.rpartition(".")
        final = head + slash + (f"{stem} (case {tag}).{ext}" if dot and stem else f"{name} (case {tag})")
        note = "same name as another file once case and accents are ignored"
    taken[key(final)] = final
    return final, note


def _suffixed(final: str, label: str, digest: str) -> str:
    head, slash, name = final.rpartition("/")
    stem, dot, ext = name.rpartition(".")
    tag = f" ({label} {digest[:8]})"
    return head + slash + (f"{stem}{tag}.{ext}" if dot and stem else f"{name}{tag}")


def _finish_file(ap: Applier, cur: dict, want: str, rep: Report) -> None:
    spool: _Spool = cur["spool"]
    digest, n = spool.close()
    d, final = cur["d"], cur["dest"]
    if digest != want or n != d["n"]:                            # cannot happen after pass 1; checked anyway
        spool.discard()
        raise MigrateError(f"{d['p']}: bytes changed between the two passes; stopped")
    existing = ap.current_hash(final)                            # also refuses a symlink or a non-file in the way
    if existing == digest:
        spool.discard()
        rep.identical.append(final)
        return
    if existing is not None:                                     # a different file is there: keep both
        moved = _suffixed(final, "migrated", digest)
        rep.kept_both.append((final, moved))
        here = ap.current_hash(moved)
        if here == digest:
            spool.discard()
            rep.identical.append(moved)
            return
        if here is not None:
            spool.discard()
            raise MigrateError(f"{moved} already exists with other bytes: stopped, nothing overwritten")
        final = moved
    target = ap._target(final)
    os.replace(spool.path, target)
    if os.name == "posix":
        os.chmod(target, (stat.S_IMODE(d["m"]) & 0o755) | 0o600)   # no setuid/setgid/sticky, no world-write
    if d["t"] > 0:
        os.utime(target, (d["t"], d["t"]))
    (rep.staged if final.startswith(STAGING + "/") else rep.written).append(final)
    rep.bytes += n
    if cur["note"]:
        rep.renamed.append((d["p"][len("files/"):] if d["p"].startswith("files/") else d["p"], final, cur["note"]))


# ---- the wrappers the OS calls: each asks for the password before it does anything ------------------

def _ask_passphrase(authority: Authority, again: bool) -> str:
    p = authority.prompter
    first = p.password("Passphrase for the bundle (you will need it on the new computer): ")
    if first is None:
        raise MigrateError("cancelled")
    pw = first.decode() if isinstance(first, (bytes, bytearray)) else first
    if again:
        second = p.password("Type it again: ")
        if second is None or (second.decode() if isinstance(second, (bytes, bytearray)) else second) != pw:
            raise MigrateError("the two passphrases differ: nothing was written")
    return pw


def export_bundle(paths: Paths, authority: Authority, roots: list[Path], out: Path,
                  include_kos: bool = True, kdf_n: int = KDF_N, label: str = "") -> Summary:
    """``migrate.export``: the password first (its prompt says what will be read), then the passphrase
    (twice), then the bundle."""
    with authority.authorize("migrate.export", label or f"{out} (reads {', '.join(str(r) for r in roots)[:150]})"):
        pass
    passphrase = _ask_passphrase(authority, again=True)
    sources, skipped = collect(paths, roots, include_kos)
    log = AuditLog(paths)
    try:
        summary = write_bundle(sources, out, passphrase, skipped, "kos", kdf_n)
    except (MigrateError, OSError) as e:
        log.record("migrate.export", str(out), "failed")
        raise MigrateError(str(e)) from None
    log.record("migrate.export", f"{summary.files} files", "done")
    return summary


def import_bundle(paths: Paths, authority: Authority, bundle: Path, dest: Path, target_os: str = "kos") -> Report:
    """``migrate.import``: the password first, then the passphrase, then verify-all-then-write."""
    with authority.authorize("migrate.import", str(dest)):
        pass
    passphrase = _ask_passphrase(authority, again=False)
    log = AuditLog(paths)
    try:
        rep = restore_bundle(bundle, passphrase, dest, "linux" if target_os == "kos" else target_os)
    except (MigrateError, SyncError, OSError) as e:
        log.record("migrate.import", str(dest), "failed")
        raise MigrateError(str(e)) from None
    log.record("migrate.import", f"{len(rep.written)} files", "done")
    return rep
