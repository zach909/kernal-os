"""Sync one folder between linked devices without losing a byte.

The engine is deliberately boring: a *manifest* (path -> SHA-256 and size) from each side, the manifest
of the last agreed state (*base*), and a three-way comparison. It never trusts a peer's path, never
overwrites a file that changed since it was listed, and never deletes: a file that goes away is moved
into ``.kos-trash/`` under its content hash, where it can be brought back.

========== the rules ==========
For every path with local hash L, remote hash R and base hash B (``None`` = absent):

* L == R                  nothing to do, it is now the base.
* L == B, R != B          only the remote changed: take the remote (a new or changed file is pulled; a
                          file the remote removed is moved to the trash here).
* R == B, L != B          only this side changed: send it (or ask the remote to trash its copy).
* all three different     both changed. **Nothing is lost**: the remote's version is saved here beside
                          the original as ``name (conflict <peer> <hash8>).ext``, then this side's
                          version is sent. If one side *deleted* and the other *edited*, the edit wins.

Every write goes through ``Applier``: a safe relative path (``portable.safe_relative``), no symlink
anywhere on the way down, a temporary file in the same folder, the SHA-256 and size checked *before* the
file is moved into place, and a compare-and-swap on the old content (a file that changed after the
manifest was read is refused and re-planned, not overwritten).

The folder itself is a KOS *space*; who may use it is the permission store's business (kos/spaces.py).
Moving bytes between machines is the link's business (kos/linkdev.py, every request audited and the
owner of the receiving device types the password). This file touches neither.

Not done, and said so: no rename detection (a rename is a delete plus a new file, which is correct but
re-sends the bytes), no delta transfer (whole files), no partial-sync resume across connections, no
file modes or timestamps or extended attributes, and symlinks are skipped, not synced.
Whole numbers only. Standard library only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import portable
from .linkdev import LinkClient, LinkError, Refusal

TRASH = ".kos-trash"
TMP_PREFIX = ".kos-tmp-"
CHUNK = 192 * 1024                 # raw bytes per message; base64 makes it 256 KiB, well under crypt.MAX_PLAIN
PAGE = 1500                        # manifest entries per message
MAX_FILES = 100_000
MAX_FILE = 1 << 30
MAX_TOTAL = 64 << 30
TRASH_KEEP = 1000
_HEX = set("0123456789abcdef")


class SyncError(Refusal):
    """A refusal with a reason. Nothing was changed for the thing that was refused."""


def sha256_file(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            block = f.read(1 << 20)
            if not block:
                return h.hexdigest(), n
            h.update(block)
            n += len(block)


def _is_hash(h) -> bool:
    return isinstance(h, str) and len(h) == 64 and set(h) <= _HEX


# ---- manifests ----------------------------------------------------------------------------------

@dataclass
class Manifest:
    files: dict[str, dict] = field(default_factory=dict)       # path -> {"h": hex, "n": size}
    skipped: list[str] = field(default_factory=list)           # what was left out and why (never silent)

    def hashes(self) -> dict[str, str]:
        return {p: v["h"] for p, v in self.files.items()}


def snapshot(root: Path) -> Manifest:
    """What is in ``root`` right now. Symlinks, devices, sockets and KOS's own bookkeeping are skipped
    and reported; so is any name a peer would have to refuse. Walks with a stack, never recursion."""
    root = Path(root)
    m = Manifest()
    stack = [(root, "")]
    total = 0
    while stack:
        folder, prefix = stack.pop()
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError as e:
            m.skipped.append(f"{prefix or '.'}: cannot read ({e.strerror})")
            continue
        for e in entries:
            rel = prefix + e.name                       # the real on-disk name: never rewritten (Linux can hold both
                                                        # 'é' spellings; only a target that folds them cares)
            if e.name.startswith((portable.RESERVED_PREFIX, TMP_PREFIX)) or e.name == TRASH:
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                m.skipped.append(f"{rel}: cannot read")
                continue
            if stat.S_ISLNK(st.st_mode):
                m.skipped.append(f"{rel}: a symlink (not synced)")
                continue
            try:
                portable.safe_relative(rel)
            except portable.PathRefused as ex:
                m.skipped.append(f"{rel!r}: {ex}")
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append((Path(e.path), rel + "/"))
            elif stat.S_ISREG(st.st_mode):
                if st.st_size > MAX_FILE:
                    m.skipped.append(f"{rel}: bigger than {MAX_FILE >> 30} GiB")
                    continue
                if len(m.files) >= MAX_FILES or total + st.st_size > MAX_TOTAL:
                    m.skipped.append(f"{rel}: over the size limit for one sync")
                    continue
                h, n = sha256_file(Path(e.path))
                m.files[rel] = {"h": h, "n": n}
                total += n
            else:
                m.skipped.append(f"{rel}: not a regular file")
    return m


# ---- the plan -----------------------------------------------------------------------------------

@dataclass
class Plan:
    pull: list[str] = field(default_factory=list)
    push: list[str] = field(default_factory=list)
    trash_local: list[str] = field(default_factory=list)
    trash_remote: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)       # paths where both changed: remote copy kept beside
    same: int = 0

    def empty(self) -> bool:
        return not (self.pull or self.push or self.trash_local or self.trash_remote or self.conflicts)

    def summary(self) -> str:
        return (f"{len(self.pull)} to receive, {len(self.push)} to send, {len(self.trash_local) + len(self.trash_remote)}"
                f" to move to the trash, {len(self.conflicts)} conflicts kept both ways")


def plan(local: dict[str, str], remote: dict[str, str], base: dict[str, str]) -> Plan:
    """The three-way comparison. Pure: hashes in, a plan out."""
    out = Plan()
    for p in sorted(set(local) | set(remote)):
        L, R, B = local.get(p), remote.get(p), base.get(p)
        if L == R:
            out.same += 1
        elif L == B:                                   # only the remote moved
            (out.pull if R is not None else out.trash_local).append(p)
        elif R == B:                                   # only this side moved
            (out.push if L is not None else out.trash_remote).append(p)
        elif L is None:                                # deleted here, edited there: the edit wins
            out.pull.append(p)
        elif R is None:                                # edited here, deleted there: the edit wins
            out.push.append(p)
        else:                                          # both edited: keep both, send ours
            out.conflicts.append(p)
            out.push.append(p)
    return out


def conflict_name(rel: str, peer: str, remote_hash: str) -> str:
    """``dir/name.ext`` -> ``dir/name (conflict <peer> <hash8>).ext``; never collides with the original."""
    head, slash, name = rel.rpartition("/")
    stem, dot, ext = name.rpartition(".")
    tag = f" (conflict {peer[:8]} {remote_hash[:8]})"
    new = f"{stem}{tag}.{ext}" if dot and stem else f"{name}{tag}"
    return head + slash + new


def blocked_for(platform: str, paths) -> dict[str, str]:
    """{path: why} for paths a device of ``platform`` cannot hold. They are *not* sent and are reported,
    never renamed on the sync path (a rename would make the two sides disagree for ever)."""
    out: dict[str, str] = {}
    if platform in ("windows", "macos", "ios"):
        for a, b in portable.collisions(paths):
            out[b] = f"same name as {a} once case and accents are ignored"
    if platform == "windows":
        for p in paths:
            found = portable.problems(p)
            if found:
                out.setdefault(p, found[0])
    return out


# ---- applying changes (the only code here that writes) --------------------------------------------

class Applier:
    """Writes into one sync folder, and only safely. Used for the local side directly and by the
    ``sync.apply`` handler for a peer's writes."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._open: dict[str, tuple[Path, "hashlib._Hash", int, int, str]] = {}

    # -- paths
    def _target(self, rel: str) -> Path:
        portable.safe_relative(rel)
        cur = self.root
        parts = rel.split("/")
        for i, part in enumerate(parts):
            cur = cur.joinpath(part)
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                return self.root.joinpath(*parts)         # the rest does not exist yet, so cannot be a symlink
            if stat.S_ISLNK(st.st_mode):
                raise SyncError(f"{rel}: a symlink is in the way ({'/'.join(parts[:i + 1])})")
            if i < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
                raise SyncError(f"{rel}: {'/'.join(parts[:i + 1])} is a file, not a folder")
        return self.root.joinpath(*parts)

    def current_hash(self, rel: str) -> Optional[str]:
        t = self._target(rel)
        try:
            if not stat.S_ISREG(os.lstat(t).st_mode):
                raise SyncError(f"{rel}: not a regular file")
        except FileNotFoundError:
            return None
        return sha256_file(t)[0]

    def sweep(self) -> int:
        """Remove half-written temp files an interrupted transfer left behind. Returns how many."""
        n = 0
        stack = [self.root]
        while stack:
            cur = stack.pop()
            try:
                entries = list(os.scandir(cur))
            except OSError:
                continue
            for e in entries:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.name != TRASH:
                        stack.append(e.path)
                elif e.name.startswith(TMP_PREFIX):
                    try:
                        os.unlink(e.path)
                        n += 1
                    except OSError:
                        pass
        return n

    # -- trash
    def trash(self, rel: str, expect: Optional[str]) -> bool:
        """Move a file out of the way, keeping it. ``expect`` is the hash it must still have."""
        t = self._target(rel)
        have = self.current_hash(rel)
        if have is None:
            return False
        if expect is not None and have != expect:
            raise SyncError(f"{rel}: changed since it was listed; not touched")
        bin_ = self.root.joinpath(TRASH)
        bin_.mkdir(exist_ok=True)
        dest = bin_.joinpath(have)
        if dest.exists():
            os.unlink(t)                                 # identical bytes are already in the trash
        else:
            os.replace(t, dest)
        self._prune_trash(bin_)
        return True

    @staticmethod
    def _prune_trash(bin_: Path) -> None:
        items = sorted(bin_.iterdir(), key=lambda p: p.stat().st_mtime_ns)
        for old in items[:max(0, len(items) - TRASH_KEEP)]:
            old.unlink()

    # -- writing a file in chunks
    def begin(self, rel: str, size: int, digest: str, replaces: Optional[str]) -> None:
        if not _is_hash(digest) or type(size) is not int or not 0 <= size <= MAX_FILE:
            raise SyncError(f"{rel}: bad size or hash")
        if replaces is not None and not _is_hash(replaces):
            raise SyncError(f"{rel}: bad hash")
        if rel in self._open:
            raise SyncError(f"{rel}: already being written")
        if len(self._open) >= 8:
            raise SyncError("too many files open at once")
        if self.current_hash(rel) != replaces:
            raise SyncError(f"{rel}: changed since it was listed; not overwritten")
        target = self._target(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._target(rel)                                # re-check after creating folders
        tmp = target.parent.joinpath(f"{TMP_PREFIX}{secrets.token_hex(6)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self._open[rel] = (tmp, hashlib.sha256(), 0, size, digest + ":" + (replaces or ""))

    def chunk(self, rel: str, offset: int, data: bytes) -> None:
        if rel not in self._open:
            raise SyncError(f"{rel}: not open")
        tmp, h, have, size, tag = self._open[rel]
        if offset != have or len(data) > CHUNK or have + len(data) > size:
            self.abort(rel)
            raise SyncError(f"{rel}: out of order or too large")
        with open(tmp, "ab") as f:
            f.write(data)
        h.update(data)
        self._open[rel] = (tmp, h, have + len(data), size, tag)

    def finish(self, rel: str) -> str:
        if rel not in self._open:
            raise SyncError(f"{rel}: not open")
        tmp, h, have, size, tag = self._open[rel]
        digest, replaces = tag.split(":")
        if have != size or h.hexdigest() != digest:
            self.abort(rel)
            raise SyncError(f"{rel}: the bytes do not match their hash; nothing was written")
        del self._open[rel]
        try:
            if self.current_hash(rel) != (replaces or None):
                raise SyncError(f"{rel}: changed while it was being received; not overwritten")
            if replaces:
                self.trash(rel, replaces)
            os.replace(tmp, self._target(rel))
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        return digest

    def abort(self, rel: str) -> None:
        item = self._open.pop(rel, None)
        if item:
            item[0].unlink(missing_ok=True)

    def abort_all(self) -> None:
        for rel in list(self._open):
            self.abort(rel)

    def write_whole(self, rel: str, data: bytes, replaces: Optional[str] = None) -> str:
        """Convenience for the local side (a conflict copy): the same checks, in one call."""
        digest = hashlib.sha256(data).hexdigest()
        self.begin(rel, len(data), digest, replaces)
        for i in range(0, max(len(data), 1), CHUNK):
            self.chunk(rel, i, data[i:i + CHUNK])
        return self.finish(rel)


# ---- the handler the *serving* device registers (kos/linkdev.py LinkHost) ------------------------

def make_handlers(resolve_space: Callable[[str], Path]) -> dict[str, Callable[[dict], dict]]:
    """``sync.read`` and ``sync.apply`` for the device that holds a folder. ``resolve_space(name)`` gives
    the folder or raises; it is the OS's, so a peer can only ever name a space, never a path."""
    appliers: dict[str, Applier] = {}
    snaps: dict[str, Manifest] = {}                      # one snapshot per run, so paging is consistent

    def space_of(args: dict) -> tuple[str, Path]:
        name = args.get("space")
        if not isinstance(name, str) or not 0 < len(name) <= 32:
            raise SyncError("name the shared folder")
        return name, Path(resolve_space(name))

    def read(args: dict) -> dict:
        name, root = space_of(args)
        mode = args.get("mode")
        if mode == "manifest":
            after, limit = args.get("after", ""), args.get("limit", PAGE)
            if not isinstance(after, str) or type(limit) is not int or not 0 < limit <= PAGE:
                raise SyncError("bad page")
            if after == "" or name not in snaps:
                Applier(root).sweep()
                snaps[name] = snapshot(root)
            snap = snaps[name]
            keys = [k for k in sorted(snap.files) if k > after][:limit + 1]
            page = keys[:limit]
            return {"files": {k: snap.files[k] for k in page}, "next": page[-1] if len(keys) > limit else "",
                    "skipped": snap.skipped[:50] if after == "" else []}
        if mode == "chunk":
            rel, off, n = args.get("path"), args.get("offset"), args.get("length", CHUNK)
            if type(off) is not int or off < 0 or type(n) is not int or not 0 < n <= CHUNK:
                raise SyncError("bad range")
            path = Applier(root)._target(rel)             # safe_relative + no symlink on the way down
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    raise SyncError(f"{rel}: not a regular file")
                with open(path, "rb") as f:
                    f.seek(off)
                    data = f.read(n)
                    eof = f.read(1) == b""
            except FileNotFoundError:
                raise SyncError(f"{rel}: gone") from None
            return {"data": base64.b64encode(data).decode(), "eof": eof}
        raise SyncError("mode is manifest or chunk")

    def apply(args: dict) -> dict:
        name, root = space_of(args)
        ap = appliers.setdefault(name, Applier(root))
        op, rel = args.get("op"), args.get("path")
        try:
            if op == "begin":
                ap.begin(rel, args.get("size"), args.get("hash"), args.get("replaces"))
                return {}
            if op == "chunk":
                try:
                    data = base64.b64decode(args.get("data", ""), validate=True)
                except (binascii.Error, ValueError, TypeError):
                    raise SyncError("bad chunk") from None
                ap.chunk(rel, args.get("offset"), data)
                return {}
            if op == "end":
                return {"hash": ap.finish(rel)}
            if op == "trash":
                h = args.get("hash")
                if not _is_hash(h):
                    raise SyncError("bad hash")
                return {"trashed": ap.trash(rel, h)}
        except SyncError:
            if isinstance(rel, str):
                ap.abort(rel)
            raise
        raise SyncError("op is begin, chunk, end or trash")

    class Handlers(dict):
        def close(self) -> None:
            """The connection ended: drop every half-written file and forget the snapshots."""
            for ap in appliers.values():
                ap.abort_all()
            appliers.clear()
            snaps.clear()

    return Handlers({"sync.read": read, "sync.apply": apply})


# ---- the asking side ------------------------------------------------------------------------------

def remote_manifest(client: LinkClient, space: str) -> Manifest:
    out, after = Manifest(), ""
    while True:
        d = client.call("sync.read", f"space {space}", {"space": space, "mode": "manifest", "after": after, "limit": PAGE})
        files = d.get("files")
        if not isinstance(files, dict):
            raise SyncError("the other device sent a bad manifest")
        for p, v in files.items():
            try:
                portable.safe_relative(p)
            except portable.PathRefused as e:
                raise SyncError(f"the other device listed a path I refuse ({e})") from None
            if not (isinstance(v, dict) and _is_hash(v.get("h")) and type(v.get("n")) is int and 0 <= v["n"] <= MAX_FILE):
                raise SyncError(f"the other device sent a bad entry for {p!r}")
            out.files[p] = {"h": v["h"], "n": v["n"]}
        out.skipped += [str(s)[:200] for s in d.get("skipped", [])][:50]
        if len(out.files) > MAX_FILES:
            raise SyncError("the other device has more files than one sync handles")
        after = d.get("next", "")
        if not after:
            return out


def _pull(client: LinkClient, space: str, rel: str, entry: dict, local: Applier, dest: str,
          replaces: Optional[str]) -> None:
    local.begin(dest, entry["n"], entry["h"], replaces)
    try:
        off = 0
        while True:
            d = client.call("sync.read", f"space {space}", {"space": space, "mode": "chunk", "path": rel,
                                                             "offset": off, "length": CHUNK})
            try:
                data = base64.b64decode(d.get("data", ""), validate=True)
            except (binascii.Error, ValueError):
                raise SyncError(f"{rel}: bad data from the other device") from None
            local.chunk(dest, off, data)
            off += len(data)
            if d.get("eof") is True:
                break
            if not data:
                raise SyncError(f"{rel}: the other device stopped early")
        local.finish(dest)
    except Exception:
        local.abort(dest)
        raise


def _push(client: LinkClient, space: str, rel: str, root: Path, entry: dict, replaces: Optional[str]) -> None:
    target = f"space {space}"
    client.call("sync.apply", target, {"space": space, "op": "begin", "path": rel, "size": entry["n"],
                                       "hash": entry["h"], "replaces": replaces})
    with open(Applier(root)._target(rel), "rb") as f:
        off = 0
        while True:
            block = f.read(CHUNK)
            if not block and off:
                break
            client.call("sync.apply", target, {"space": space, "op": "chunk", "path": rel, "offset": off,
                                               "data": base64.b64encode(block).decode()})
            off += len(block)
            if len(block) < CHUNK:
                break
    client.call("sync.apply", target, {"space": space, "op": "end", "path": rel})


@dataclass
class Report:
    pulled: list[str] = field(default_factory=list)
    pushed: list[str] = field(default_factory=list)
    trashed: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)       # (path, why): re-planned next run
    skipped: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.refused


def sync_once(client: LinkClient, space: str, root: Path, base: dict[str, str], peer_id: str,
              peer_platform: str = "kos", dry_run: bool = False) -> tuple[Report, dict[str, str]]:
    """One full pass. Returns the report and the new base (what both sides agree on now). A path that
    fails is reported and left out of the new base, so the next run sees it as unfinished, not done."""
    local_m = snapshot(root)
    remote_m = remote_manifest(client, space)
    blocked = blocked_for(peer_platform, list(local_m.files))
    local_m.skipped += [f"{p}: not sent, the other device cannot hold it ({why})" for p, why in sorted(blocked.items())]
    local_h = {p: h for p, h in local_m.hashes().items() if p not in blocked}
    remote_h = remote_m.hashes()
    pl = plan(local_h, remote_h, base)
    rep = Report(skipped=local_m.skipped[:100] + [f"(other device) {s}" for s in remote_m.skipped[:50]])
    new_base = dict(base)
    if dry_run:
        rep.pulled, rep.pushed = pl.pull, pl.push
        rep.trashed, rep.conflicts = pl.trash_local + pl.trash_remote, pl.conflicts
        return rep, base
    local = Applier(root)
    local.sweep()

    def done(p: str, h: Optional[str]) -> None:
        if h is None:
            new_base.pop(p, None)
        else:
            new_base[p] = h

    for p in sorted(set(local_h) & set(remote_h)):
        if local_h[p] == remote_h[p]:
            done(p, local_h[p])
    try:
        for p in pl.conflicts:                                  # save the remote's version beside ours first
            copy = conflict_name(p, peer_id, remote_h[p])
            if copy in local_h or copy in remote_h:
                copy = conflict_name(copy, peer_id, remote_h[p])
            try:
                _pull(client, space, p, remote_m.files[p], local, copy, None)
                rep.conflicts.append(copy)
                done(p, remote_h[p])                            # so the push below is "only we changed"
            except (SyncError, LinkError) as e:
                rep.refused.append((p, str(e)))
        for p in pl.pull:
            if any(r[0] == p for r in rep.refused):
                continue
            try:
                _pull(client, space, p, remote_m.files[p], local, p, local_h.get(p))
                rep.pulled.append(p)
                done(p, remote_h[p])
            except (SyncError, LinkError, OSError) as e:
                rep.refused.append((p, str(e)))
        for p in pl.trash_local:
            try:
                local.trash(p, local_h.get(p))
                rep.trashed.append(p)
                done(p, None)
            except (SyncError, OSError) as e:
                rep.refused.append((p, str(e)))
        for p in pl.push:
            if any(r[0] == p for r in rep.refused):
                continue
            try:
                _push(client, space, p, root, {"n": local_m.files[p]["n"], "h": local_h[p]}, remote_h.get(p))
                rep.pushed.append(p)
                done(p, local_h[p])
            except (SyncError, LinkError, OSError) as e:
                rep.refused.append((p, str(e)))
        for p in pl.trash_remote:
            try:
                client.call("sync.apply", f"space {space}", {"space": space, "op": "trash", "path": p, "hash": remote_h[p]})
                rep.trashed.append(p)
                done(p, None)
            except (SyncError, LinkError) as e:
                rep.refused.append((p, str(e)))
    finally:
        local.abort_all()
    return rep, new_base


# ---- remembering the base ------------------------------------------------------------------------

def load_base(state_dir: Path, peer_id: str, space: str) -> dict[str, str]:
    import json
    try:
        d = json.loads(Path(state_dir).joinpath("sync", peer_id, f"{space}.json").read_text())
        return {p: h for p, h in d.items() if _is_hash(h) and _safe(p)}
    except (FileNotFoundError, ValueError, AttributeError):
        return {}


def save_base(state_dir: Path, peer_id: str, space: str, base: dict[str, str]) -> None:
    import json
    from .paths import atomic_write
    f = Path(state_dir).joinpath("sync", peer_id, f"{space}.json")
    f.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(f.parent, 0o700)
    atomic_write(f, json.dumps(base, sort_keys=True).encode())


def _safe(p) -> bool:
    try:
        portable.safe_relative(p)
        return True
    except portable.PathRefused:
        return False


# ---- the folders the owner has chosen to sync ----------------------------------------------------

FOLDER_NAME_RE = __import__("re").compile(r"^[a-z][a-z0-9-]{0,31}$")
MAX_FOLDERS = 64


class FolderStore:
    """name -> real folder, chosen by the owner with the password and sealed (HMAC) like the link list and
    the firewall rules. A linked device only ever names a *folder name*; it can never name a path.
    The OS's own state and the root of the disk cannot be shared."""

    def __init__(self, state_dir: Path, forbidden: tuple = ()):
        self.file = Path(state_dir).joinpath("sync", "folders.json")
        self.forbidden = tuple(Path(x).resolve() for x in (*forbidden, state_dir))

    @staticmethod
    def _mac(key: bytes, folders: dict) -> str:
        import hashlib, hmac, json
        body = json.dumps(folders, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(key, b"kos:sync:folders" + body, hashlib.sha256).hexdigest()

    def load(self, key: bytes) -> tuple[dict, str]:
        import hmac, json
        try:
            raw = json.loads(self.file.read_text())
            folders = raw["folders"]
            if not isinstance(folders, dict) or len(folders) > MAX_FOLDERS or not isinstance(raw["mac"], str):
                raise ValueError
            for n, p in folders.items():
                if not FOLDER_NAME_RE.match(n) or not isinstance(p, str) or not os.path.isabs(p):
                    raise ValueError
        except FileNotFoundError:
            return {}, "empty"
        except (ValueError, KeyError, TypeError, OSError):
            return {}, "tampered"
        if not hmac.compare_digest(raw["mac"], self._mac(key, folders)):
            return {}, "tampered"
        return folders, "ok"

    def _save(self, key: bytes, folders: dict) -> None:
        import json
        from .paths import atomic_write
        self.file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.file.parent, 0o700)
        atomic_write(self.file, json.dumps({"folders": folders, "mac": self._mac(key, folders)}).encode())

    def folders(self, key: bytes) -> dict:
        folders, state = self.load(key)
        if state == "tampered":
            raise SyncError("the list of shared folders does not match its seal; remove it and share again")
        return folders

    def check_path(self, path: str) -> Path:
        p = Path(path)
        if not p.is_absolute():
            raise SyncError("a shared folder is a full path (it starts with /)")
        if p.is_symlink() or not p.is_dir():
            raise SyncError(f"{path} is not a folder (a symlink is not followed)")
        real = p.resolve()
        if real == Path(real.anchor):
            raise SyncError("the root of the disk cannot be shared")
        for bad in self.forbidden:
            if real == bad or bad in real.parents or real in bad.parents:
                raise SyncError(f"{path} overlaps KOS's own state ({bad}): it cannot be shared")
        return real

    def add(self, key: bytes, name: str, path: str) -> Path:
        if not isinstance(name, str) or not FOLDER_NAME_RE.match(name):
            raise SyncError("a folder name is lowercase letters, digits and -, starting with a letter")
        real = self.check_path(path)
        folders = self.folders(key)
        if name not in folders and len(folders) >= MAX_FOLDERS:
            raise SyncError(f"at most {MAX_FOLDERS} shared folders")
        self._save(key, {**folders, name: str(real)})
        return real

    def remove(self, key: bytes, name: str) -> bool:
        folders = self.folders(key)
        if name not in folders:
            return False
        folders.pop(name)
        self._save(key, folders)
        return True

    def resolve(self, key: bytes, name: str) -> Path:
        """The folder for ``name`` as it is *now* (re-checked: it may have been swapped for a symlink)."""
        folders = self.folders(key)
        if name not in folders:
            raise SyncError(f"no shared folder called {name!r}")
        return self.check_path(folders[name])
