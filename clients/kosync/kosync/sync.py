"""Sync: keep one local folder identical on several machines through any shared folder.

The shared folder (a USB stick, an SMB share, a cloud-drive folder, Syncthing...) is only a dumb mailbox. It
holds ciphertext, so whoever runs it learns file sizes and when you sync, never names or contents:

    kosync.json          key settings + a password check (plain, tamper = the password check fails)
    objects/ab/<id>      one encrypted file body; <id> is a keyed hash of the content (names never leak)
    index/<device>.idx   each device's encrypted list of its files; a device writes only its own list

Each run is a three-way merge against what this device last agreed on. It never silently loses data:
* both sides changed a file  -> the other device's version takes the name, yours is kept as
  ``name (conflict DEVICE DATE).ext`` and is synced too;
* one side deleted, the other edited -> the edit wins (the file comes back);
* a name that is illegal here, or that would land on a different file on a case-insensitive disk, is skipped and
  reported, never renamed or overwritten.
Not handled (see README): empty folders, permissions, deleting unused objects, and rollback of the *whole* shared
folder to an older state that this device has never seen.
"""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import stat as S
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import paths as P
from .crypto import (CryptoError, DEFAULT_KDF, HashingReader, SALT_LEN, check_kdf, decrypt_stream, encrypt_stream,
                     master_key, new_password_ok, subkey)

FORMAT = 1
DEVICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
ID_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_DIR = ".kosync"
DEFAULT_MAX_FILE = 1 << 30
MAX_INDEX = 64 << 20
CHECK_TEXT = b"kosync vault check"


class SyncError(Exception):
    pass


@dataclass
class Keys:
    enc: bytes
    ident: bytes
    index: bytes


@dataclass
class Vault:
    folder: Path
    keys: Keys
    vault_id: str


@dataclass
class SyncReport:
    uploaded: list = field(default_factory=list)
    downloaded: list = field(default_factory=list)
    deleted_here: list = field(default_factory=list)
    deleted_there: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)         # [(path, conflict copy path)]
    skipped: list = field(default_factory=list)           # [(path, reason)]
    errors: list = field(default_factory=list)
    unchanged: int = 0
    dry_run: bool = False


def _atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp-{secrets.token_hex(4)}")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _derive(password: str, salt: bytes, kdf: dict) -> Keys:
    m = master_key(password, salt, kdf)
    return Keys(subkey(m, "vault-enc"), subkey(m, "vault-id"), subkey(m, "vault-index"))


def _seal(key: bytes, aad: bytes, data: bytes) -> bytes:
    out = io.BytesIO()
    encrypt_stream(key, aad, io.BytesIO(data), out)
    return out.getvalue()


def _open(key: bytes, aad: bytes, blob: bytes, limit=MAX_INDEX) -> bytes:
    out = io.BytesIO()
    decrypt_stream(key, aad, io.BytesIO(blob), out)
    if out.tell() > limit:
        raise CryptoError("data larger than allowed")
    return out.getvalue()


def create_vault(folder, password: str, kdf=None) -> Vault:
    """Make a new shared folder. Refuses to touch one that already has a vault."""
    new_password_ok(password)
    folder = Path(folder)
    cfg = folder / "kosync.json"
    if cfg.exists():
        raise SyncError(f"{folder} already holds a vault")
    kdf = check_kdf(kdf or DEFAULT_KDF)
    salt = secrets.token_bytes(SALT_LEN)
    keys = _derive(password, salt, kdf)
    vid = secrets.token_hex(16)
    meta = {"format": FORMAT, "vault": vid, "kdf": {"alg": "scrypt", **kdf}, "salt": salt.hex(),
            "check": _seal(keys.index, b"check:" + vid.encode(), CHECK_TEXT).hex()}
    _atomic_write(cfg, json.dumps(meta, sort_keys=True, indent=1).encode())
    (folder / "objects").mkdir(exist_ok=True)
    (folder / "index").mkdir(exist_ok=True)
    return Vault(folder, keys, vid)


def open_vault(folder, password: str) -> Vault:
    folder = Path(folder)
    try:
        meta = json.loads((folder / "kosync.json").read_bytes())
        if meta["format"] != FORMAT:
            raise SyncError(f"vault format {meta['format']!r} is not supported by this version")
        vid = meta["vault"]
        if not isinstance(vid, str) or not re.fullmatch(r"[0-9a-f]{32}", vid):
            raise ValueError
        keys = _derive(password, bytes.fromhex(meta["salt"]), meta["kdf"])
        ok = _open(keys.index, b"check:" + vid.encode(), bytes.fromhex(meta["check"]), 1024) == CHECK_TEXT
    except FileNotFoundError:
        raise SyncError(f"{folder} holds no kosync vault") from None
    except CryptoError:
        raise SyncError("wrong password, or the vault was tampered with") from None
    except (ValueError, KeyError, TypeError):
        raise SyncError("kosync.json is damaged") from None
    if not ok:
        raise SyncError("wrong password")
    return Vault(folder, keys, vid)


# ---- reading the local folder -----------------------------------------------------------------------------

def _file_id(keys: Keys, path: Path) -> str:
    r = HashingReader(open(path, "rb"), keys.ident)
    with r.src:
        while r.read(1 << 20):
            pass
    return r.hexdigest()


def _scan(local: Path, keys: Keys, cache: dict, report: SyncReport, osname: str, max_file: int) -> dict:
    """{path: {"id", "size", "mtime_ns"}} for every regular file; ids are reused while size and time agree."""
    out: dict = {}

    def walk(rel: str):
        here = local / rel if rel else local
        try:
            names = sorted(os.listdir(here))
        except OSError as e:
            report.skipped.append((rel or ".", f"cannot list: {e.strerror}"))
            return
        for name in names:
            r = f"{rel}/{name}" if rel else name
            if not rel and name == STATE_DIR:
                continue
            full = here / name
            try:
                st = os.lstat(full)
            except OSError as e:
                report.skipped.append((r, f"cannot read: {e.strerror}"))
                continue
            if S.S_ISDIR(st.st_mode):
                walk(r)
                continue
            if not S.S_ISREG(st.st_mode):
                report.skipped.append((r, "not a regular file (links are not synced)"))
                continue
            if not P.is_portable(r, osname):
                report.skipped.append((r, f"name is not legal on {osname}"))
                continue
            if st.st_size > max_file:
                report.skipped.append((r, "file is larger than the size limit"))
                continue
            c = cache.get(r)
            if c and c["size"] == st.st_size and c["mtime_ns"] == st.st_mtime_ns:
                fid = c["id"]
            else:
                try:
                    fid = _file_id(keys, full)
                except OSError as e:
                    report.skipped.append((r, f"cannot read: {e.strerror}"))
                    continue
            out[r] = {"id": fid, "size": st.st_size, "mtime_ns": st.st_mtime_ns}
    walk("")
    return out


# ---- the other devices' lists -----------------------------------------------------------------------------

def _entry_ok(path, e) -> bool:
    try:
        P.validate(path)
    except P.PathError:
        return False
    return (isinstance(e, dict) and (e.get("id") is None or (isinstance(e.get("id"), str) and ID_RE.match(e["id"])))
            and type(e.get("at")) is int and type(e.get("size")) is int and e["size"] >= 0
            and type(e.get("mtime")) is int)


def _load_indexes(v: Vault, me: str, seen: dict) -> tuple[dict, dict]:
    """({device: {path: entry}}, {device: seq}) from every other device. A bad or rolled-back list stops the run."""
    lists, seqs = {}, {}
    d = v.folder / "index"
    if not d.is_dir():
        return lists, seqs
    for f in sorted(d.iterdir()):
        m = re.fullmatch(r"([a-z0-9][a-z0-9-]{0,31})\.idx", f.name)
        if not m or m.group(1) == me:
            continue
        dev = m.group(1)
        try:
            doc = json.loads(_open(v.keys.index, b"index:" + dev.encode(), f.read_bytes()))
            if doc["device"] != dev or doc["vault"] != v.vault_id or type(doc["seq"]) is not int:
                raise ValueError
            entries = doc["entries"]
            if not isinstance(entries, dict) or any(not _entry_ok(p, e) for p, e in entries.items()):
                raise ValueError
        except (CryptoError, ValueError, KeyError, TypeError, OSError):
            raise SyncError(f"the list from device {dev!r} is damaged or not from this vault; stopping") from None
        if doc["seq"] < seen.get(dev, 0):
            raise SyncError(f"the list from device {dev!r} went back in time (an older copy of the shared folder?); "
                            "stopping")
        lists[dev], seqs[dev] = entries, doc["seq"]
    return lists, seqs


def _winner(lists: dict, path: str):
    best = None
    for dev, entries in lists.items():
        e = entries.get(path)
        if e is not None and (best is None or (e["at"], dev) > (best[0]["at"], best[1])):
            best = (e, dev)
    return best[0] if best else None


# ---- objects ----------------------------------------------------------------------------------------------

def _object(v: Vault, oid: str) -> Path:
    return v.folder / "objects" / oid[:2] / oid


def _upload(v: Vault, src: Path, oid: str):
    dest = _object(v, oid)
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + f".tmp-{secrets.token_hex(4)}")
    try:
        with open(src, "rb") as s, open(tmp, "wb") as d:
            r = HashingReader(s, v.keys.ident)
            encrypt_stream(v.keys.enc, b"object:" + oid.encode(), r, d)
            d.flush()
            os.fsync(d.fileno())
        if r.hexdigest() != oid:
            raise SyncError("changed while it was being copied; it will be picked up on the next run")
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _check_dest(local: Path, rel: str) -> Path:
    """The place a downloaded file goes, after checking no symlink or folder is in the way."""
    cur = local
    for part in rel.split("/")[:-1]:
        cur = cur / part
        if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
            raise SyncError("a link or file is in the way")
    final = cur / rel.rsplit("/", 1)[-1]
    if final.is_symlink() or final.is_dir():
        raise SyncError("a link or folder is in the way")
    return final


def _download(v: Vault, local: Path, rel: str, entry: dict) -> os.stat_result:
    oid = entry["id"]
    src = _object(v, oid)
    if not src.is_file():
        raise SyncError("the file's data is not in the shared folder yet")
    final = _check_dest(local, rel)
    stage = local / STATE_DIR / "tmp"
    stage.mkdir(parents=True, exist_ok=True)
    tmp = stage / f"{secrets.token_hex(8)}.part"
    try:
        with open(src, "rb") as s, open(tmp, "wb") as d:
            decrypt_stream(v.keys.enc, b"object:" + oid.encode(), s, d)
        if _file_id(v.keys, tmp) != oid:
            raise SyncError("the stored data does not match its name (swapped or damaged)")
        os.utime(tmp, (entry["mtime"], entry["mtime"]))
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, final)
    except CryptoError as e:
        raise SyncError(str(e)) from None
    finally:
        tmp.unlink(missing_ok=True)
    return os.stat(final)


def _prune_empty(local: Path, rel: str):
    cur = local / rel
    while True:
        cur = cur.parent
        if cur == local:
            return
        try:
            cur.rmdir()
        except OSError:
            return


# ---- state ------------------------------------------------------------------------------------------------

def _load_state(local: Path, vid: str, device: str) -> dict:
    f = local / STATE_DIR / "state.json"
    if f.exists():
        try:
            st = json.loads(f.read_bytes())
            if st["vault"] != vid:
                raise SyncError("this folder is already synced with a different vault")
            if st["device"] != device:
                raise SyncError(f"this folder is synced as device {st['device']!r}, not {device!r}")
            return st
        except (ValueError, KeyError, TypeError):
            raise SyncError(f"{f} is damaged; remove the {STATE_DIR} folder to start this device over") from None
    return {"vault": vid, "device": device, "seq": 0, "base": {}, "mine": {}, "seen": {}, "cache": {}}


def _conflict_name(rel: str, device: str, now_ns: int) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(now_ns // 10**9))
    stem, dot, ext = rel.rpartition(".")
    tag = f"conflict {device} {stamp}"
    if not dot or not stem or "/" in ext:
        return f"{rel} ({tag})"
    return f"{stem} ({tag}).{ext}"


# ---- the run ----------------------------------------------------------------------------------------------

def sync(v: Vault, local, device: str, *, os_name=None, now_ns=None, dry_run=False,
         max_file: int = DEFAULT_MAX_FILE) -> SyncReport:
    if not DEVICE_RE.match(device):
        raise SyncError("device name: lowercase letters, digits and dashes, 1-32 characters")
    local = Path(local)
    if not local.is_dir() or local.is_symlink():
        raise SyncError(f"{local} is not a plain folder")
    os_name = os_name or P.detect_os()
    now = now_ns if now_ns is not None else time.time_ns()
    report = SyncReport(dry_run=dry_run)
    st = _load_state(local, v.vault_id, device)
    base, mine = st["base"], st["mine"]
    lists, seqs = _load_indexes(v, device, st["seen"])
    cur = _scan(local, v.keys, st["cache"], report, os_name, max_file)
    paths = set(cur) | set(base) | {p for lst in lists.values() for p in lst}

    def set_mine(p, entry_id, at, size, mtime):
        mine[p] = {"id": entry_id, "at": at, "size": size, "mtime": mtime}

    for p in sorted(paths):
        l = cur.get(p, {}).get("id")
        b = base.get(p)
        w = _winner(lists, p)
        r = w["id"] if w is not None else b
        if not P.is_portable(p, os_name) and (l is None):
            report.skipped.append((p, f"name is not legal on {os_name}"))
            continue
        try:
            if l == r:
                if l is None and w is None:
                    base.pop(p, None)
                    continue
                if l is not None:
                    report.unchanged += 1
                if not dry_run:
                    if l is not None and mine.get(p, {}).get("id") != l:
                        set_mine(p, l, w["at"] if w and w["id"] == l else now, cur[p]["size"],
                                 cur[p]["mtime_ns"] // 10**9)
                    elif l is None and w is not None:
                        mine[p] = dict(w)
                    base[p] = l
            elif l == b:                                     # only the other side changed: take it
                if r is None:
                    report.deleted_here.append(p)
                    if not dry_run:
                        os.unlink(local / p)
                        _prune_empty(local, p)
                        mine[p] = dict(w)
                        base[p] = None
                else:
                    if l is None and os.path.lexists(local / p):
                        report.skipped.append((p, "a different file already has this name here (case?)"))
                        continue
                    report.downloaded.append(p)
                    if not dry_run:
                        stt = _download(v, local, p, w)
                        mine[p] = dict(w)
                        base[p] = r
                        st["cache"][p] = {"id": r, "size": stt.st_size, "mtime_ns": stt.st_mtime_ns}
            elif r == b:                                     # only this side changed: publish it
                if l is None:
                    report.deleted_there.append(p)
                    if not dry_run:
                        set_mine(p, None, max(now, (w["at"] + 1) if w else 0), 0, 0)
                        base[p] = None
                else:
                    report.uploaded.append(p)
                    if not dry_run:
                        _upload(v, local / p, l)
                        set_mine(p, l, max(now, (w["at"] + 1) if w else 0), cur[p]["size"],
                                 cur[p]["mtime_ns"] // 10**9)
                        base[p] = l
            elif l is None:                                  # deleted here, edited there: the edit wins
                report.downloaded.append(p)
                if not dry_run:
                    stt = _download(v, local, p, w)
                    mine[p] = dict(w)
                    base[p] = r
                    st["cache"][p] = {"id": r, "size": stt.st_size, "mtime_ns": stt.st_mtime_ns}
            elif r is None:                                  # edited here, deleted there: the edit wins
                report.uploaded.append(p)
                if not dry_run:
                    _upload(v, local / p, l)
                    set_mine(p, l, max(now, w["at"] + 1), cur[p]["size"], cur[p]["mtime_ns"] // 10**9)
                    base[p] = l
            else:                                            # both edited: theirs keeps the name, ours is kept too
                q = _conflict_name(p, device, now)
                n = 1
                while os.path.lexists(local / q) or q in cur:
                    n += 1
                    q = _conflict_name(p, device, now + n * 10**9)
                report.conflicts.append((p, q))
                if not dry_run:
                    _upload(v, local / p, l)
                    os.replace(local / p, _check_dest(local, q))
                    set_mine(q, l, now, cur[p]["size"], cur[p]["mtime_ns"] // 10**9)
                    base[q] = l
                    stt = _download(v, local, p, w)
                    mine[p] = dict(w)
                    base[p] = r
                    st["cache"][p] = {"id": r, "size": stt.st_size, "mtime_ns": stt.st_mtime_ns}
                    st["cache"][q] = {"id": l, "size": cur[p]["size"], "mtime_ns": cur[p]["mtime_ns"]}
        except (SyncError, OSError) as e:
            report.errors.append((p, str(e)))
    if dry_run:
        return report
    for p, c in cur.items():
        if p not in st["cache"] or st["cache"][p]["id"] != c["id"]:
            st["cache"][p] = {"id": c["id"], "size": c["size"], "mtime_ns": c["mtime_ns"]}
    st["cache"] = {p: c for p, c in st["cache"].items() if (local / p).is_file()}
    st["seq"] += 1
    index = {"device": device, "vault": v.vault_id, "seq": st["seq"], "entries": mine}
    _atomic_write(v.folder / "index" / f"{device}.idx",
                  _seal(v.keys.index, b"index:" + device.encode(), json.dumps(index, sort_keys=True).encode()))
    st["seen"] = {**st["seen"], **seqs}
    _atomic_write(local / STATE_DIR / "state.json", json.dumps(st, sort_keys=True).encode())
    return report
