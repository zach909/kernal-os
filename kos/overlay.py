"""A priority overlay: mods sit above an untouchable base, the OS merges them at read time.

Nothing here writes to a layer. A **layer** is a read-only map of clean relative paths to bytes.
The **base** layer is the core files and is always at the bottom. Each mod ships its files as a
layer (the ``overlay/`` folder of its ``.kapp``, read straight out of the zip, never extracted).
The :class:`Overlay` answers "what is the file at this path?" by asking the layers in load order,
last one wins. Because the merge happens when you ask, a mod can hide or replace a file for the
view without any other layer's bytes changing, and removing the mod puts everything back.

* **Load order** is explicit, owner-chosen and persisted (:class:`OverlayConfig`). A layer that is
  not in the order is off. Changing the order is the password action ``overlay.order``.
* **Rules** (the priority matrix) let one path prefix use a different order, e.g. the texture mod
  wins under ``ui/`` while the sound mod wins under ``audio/``.
* **Whiteouts**: a layer file named ``X.kos-delete`` hides ``X`` from every layer below it.
* **Copy-on-write**: writes go to the in-memory ``user`` layer on top (:meth:`Overlay.write`).
  The base and the mods are never modified, and nothing is written to disk.
* **Conflicts** are never silent: :meth:`Overlay.conflicts` lists every path provided by more than
  one active layer, who wins and who is hidden.
* **Protected prefixes** (default ``core/``): a mod that ships a file there is refused whole, so a
  mod cannot replace the files the OS itself depends on.

Every layer comes from an untrusted zip: paths, counts and sizes are checked before anything is
stored, and names are shown to the owner only through ``escape_text``.
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional

from .auth import Authority
from .kapp import KApp, KAppError, NAME_RE
from .paths import Paths, atomic_write
from .permit import PermitStore
from .protocol import escape_text

BASE = "base"
USER = "user"
WHITEOUT = ".kos-delete"
OVERLAY_DIR = "overlay/"
PROTECTED = ("core/",)

MAX_PATH = 240
MAX_DEPTH = 24
MAX_FILES = 4096
MAX_FILE = 4 << 20
MAX_LAYER = 64 << 20
MAX_LAYERS = 32
MAX_RULES = 64
MAX_RATIO = 200

_BIDI = "‎‏‪‫‬‭‮⁦⁧⁨⁩"


class OverlayError(Exception):
    pass


def check_path(p) -> str:
    """A clean relative posix path, or :class:`OverlayError`. Nothing is repaired."""
    if not isinstance(p, str) or not p or len(p) > MAX_PATH:
        raise OverlayError("a path is 1-%d characters" % MAX_PATH)
    if p.startswith("/") or p.endswith("/") or "\\" in p or "//" in p:
        raise OverlayError(f"bad path {escape_text(p, 80)!r}")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 or c in _BIDI for c in p):
        raise OverlayError(f"bad path {escape_text(p, 80)!r}: control characters")
    parts = p.split("/")
    if len(parts) > MAX_DEPTH or any(s in ("", ".", "..") for s in parts):
        raise OverlayError(f"bad path {escape_text(p, 80)!r}")
    return p


def check_prefix(p) -> str:
    """A rule prefix: a folder ending in ``/``, or ``/`` alone for everything."""
    if p == "/":
        return p
    if not isinstance(p, str) or not p.endswith("/"):
        raise OverlayError("a rule prefix is a folder ending in '/'")
    check_path(p[:-1])
    return p


def _under(path: str, prefix: str) -> bool:
    return prefix == "/" or path.startswith(prefix)


class Layer:
    """Read-only map of path -> bytes. ``None`` as a value is a whiteout (hides the path below)."""

    def __init__(self, name: str, files: Mapping[str, Optional[bytes]]):
        if name not in (BASE, USER) and not NAME_RE.match(name if isinstance(name, str) else ""):
            raise OverlayError("a layer name looks like an app name")
        if len(files) > MAX_FILES:
            raise OverlayError(f"layer {name}: more than {MAX_FILES} files")
        total = 0
        clean: dict[str, Optional[bytes]] = {}
        for path, data in files.items():
            check_path(path)
            if data is not None:
                if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE:
                    raise OverlayError(f"layer {name}: {escape_text(path, 80)!r} is too large")
                total += len(data)
                data = bytes(data)
            clean[path] = data
        if total > MAX_LAYER:
            raise OverlayError(f"layer {name}: more than {MAX_LAYER >> 20} MiB")
        self.name = name
        self.files: Mapping[str, Optional[bytes]] = MappingProxyType(clean)

    def digest(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.files):
            d = self.files[p]
            h.update(p.encode() + b"\0" + (b"-" if d is None else hashlib.sha256(d).digest()) + b"\0")
        return h.hexdigest()

    @classmethod
    def from_zip(cls, name: str, data: bytes, prefix: str = "") -> "Layer":
        """Read the entries under ``prefix`` straight out of a zip held in memory. Bounded:
        declared sizes, compression ratio and the bytes really read are all checked."""
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise OverlayError(f"layer {name}: not a zip: {e}") from None
        files: dict[str, Optional[bytes]] = {}
        for info in zf.infolist():
            if not info.filename.startswith(prefix) or info.filename.endswith("/"):
                continue
            rel = info.filename[len(prefix):]
            if info.flag_bits & 0x1 or stat.S_ISLNK(info.external_attr >> 16):
                raise OverlayError(f"layer {name}: encrypted entries and symlinks are not allowed")
            if info.file_size > MAX_FILE or (info.compress_size
                                             and info.file_size / info.compress_size > MAX_RATIO):
                raise OverlayError(f"layer {name}: {escape_text(rel, 80)!r} is too large or too compressed")
            with zf.open(info) as f:
                body = f.read(MAX_FILE + 1)
            if len(body) > MAX_FILE:
                raise OverlayError(f"layer {name}: {escape_text(rel, 80)!r} is too large")
            check_path(rel)
            if rel.endswith(WHITEOUT):
                if body:
                    raise OverlayError(f"layer {name}: a {WHITEOUT} marker must be empty")
                target = check_path(rel[:-len(WHITEOUT)])
                if files.get(target) is not None:
                    raise OverlayError(f"layer {name}: {escape_text(target, 80)!r} is both a file and a deletion")
                files[target] = None
            else:
                if rel in files and files[rel] is None:
                    raise OverlayError(f"layer {name}: {escape_text(rel, 80)!r} is both a file and a deletion")
                files[rel] = body
        return cls(name, files)


@dataclass(frozen=True)
class Resolution:
    path: str
    provider: Optional[str]            # the layer whose bytes are seen; None if absent or hidden
    hidden_by: Optional[str]           # the layer whose whiteout hid it, if any
    shadowed: tuple                    # layers that also have it but lose (highest first)


@dataclass(frozen=True)
class Conflict:
    path: str
    winner: Optional[str]              # None: the top decision is a deletion
    losers: tuple
    identical: bool                    # every provider has the same bytes: harmless


class Overlay:
    """The merge. ``order`` is lowest priority first: the **last** layer listed wins."""

    def __init__(self, base: Layer, protected: tuple = PROTECTED):
        if base.name != BASE:
            raise OverlayError("the base layer is called 'base'")
        self._layers: dict[str, Layer] = {BASE: base}
        self._order: list[str] = []
        self._rules: dict[str, list[str]] = {}
        self._protected = tuple(protected)
        self._user: dict[str, Optional[bytes]] = {}

    # ---- layers, order, rules -------------------------------------------------------------
    def add(self, layer: Layer) -> None:
        if layer.name in (BASE, USER) or layer.name in self._layers:
            raise OverlayError(f"a layer called {layer.name!r} already exists")
        if len(self._layers) >= MAX_LAYERS:
            raise OverlayError("too many layers")
        for p in layer.files:
            if self._is_protected(p):
                raise OverlayError(f"layer {layer.name} may not change protected file "
                                   f"{escape_text(p, 80)!r}")
        self._layers[layer.name] = layer

    def remove(self, name: str) -> None:
        if name == BASE or name not in self._layers:
            raise OverlayError(f"no such layer {escape_text(str(name), 40)!r}")
        del self._layers[name]
        self._order = [n for n in self._order if n != name]
        self._rules = {k: [n for n in v if n != name] for k, v in self._rules.items()}

    def _is_protected(self, path: str) -> bool:
        return any(path.startswith(x) for x in self._protected)

    def _known_once(self, names) -> bool:
        return (isinstance(names, list) and len(set(names)) == len(names)
                and all(isinstance(n, str) and n in self._layers and n != BASE for n in names))

    def set_order(self, names: list) -> None:
        if not self._known_once(names):
            raise OverlayError("the order lists each installed layer at most once (never 'base')")
        self._order = list(names)

    def set_rules(self, rules: Mapping[str, list]) -> None:
        if len(rules) > MAX_RULES:
            raise OverlayError(f"at most {MAX_RULES} rules")
        out = {}
        for prefix, names in rules.items():
            check_prefix(prefix)
            if not self._known_once(names):
                raise OverlayError(f"rule {escape_text(str(prefix), 60)!r} lists layers at most once")
            out[prefix] = list(names)
        self._rules = out

    @property
    def order(self) -> list:
        return list(self._order)

    def layer_names(self) -> list:
        return [n for n in self._layers if n != BASE]

    def _chain(self, path: str) -> list:
        """Active layers for ``path``, lowest priority first. A rule moves the layers it names
        above the rest, in the rule's own order; the longest matching prefix wins."""
        chain = [BASE] + self._order
        best = None
        for prefix in self._rules:
            if _under(path, prefix) and (best is None or len(prefix) > len(best)):
                best = prefix
        if best is not None:
            named = [n for n in self._rules[best] if n in self._order]
            chain = [n for n in chain if n not in named] + named
        return chain + [USER]

    def _get(self, layer: str, path: str):
        files = self._user if layer == USER else self._layers[layer].files
        return (path in files), files.get(path)

    # ---- reading ---------------------------------------------------------------------------
    def resolve(self, path: str) -> Resolution:
        check_path(path)
        have = []
        for n in self._chain(path):
            present, data = self._get(n, path)
            if present:
                have.append((n, data))
        if not have:
            return Resolution(path, None, None, ())
        top_name, top = have[-1]
        losers = tuple(n for n, _ in reversed(have[:-1]))
        if top is None:
            return Resolution(path, None, top_name, losers)
        return Resolution(path, top_name, None, losers)

    def read(self, path: str) -> bytes:
        r = self.resolve(path)
        if r.provider is None:
            raise OverlayError(f"no such file {escape_text(path, 80)!r}")
        return self._get(r.provider, path)[1]

    def exists(self, path: str) -> bool:
        return self.resolve(path).provider is not None

    def _all_paths(self) -> set:
        s = set(self._user)
        for n, layer in self._layers.items():
            if n == BASE or n in self._order:
                s.update(layer.files)
        return s

    def files(self) -> list:
        """Every visible path, sorted."""
        return sorted(p for p in self._all_paths() if self.resolve(p).provider is not None)

    def listdir(self, folder: str = "") -> list:
        """The merged listing of one folder: names only; sub-folders end in ``/``. A folder
        appears only while at least one visible file is under it."""
        if folder:
            folder = check_path(folder.rstrip("/")) + "/"
        out = set()
        for p in self.files():
            if p.startswith(folder):
                head, sep, _ = p[len(folder):].partition("/")
                out.add(head + sep)
        return sorted(out)

    def conflicts(self) -> list:
        """Every path that more than one active layer has, with who wins and who is hidden."""
        out = []
        for p in sorted(self._all_paths()):
            r = self.resolve(p)
            if not r.shadowed:
                continue
            top = r.provider or r.hidden_by
            bodies = {self._get(n, p)[1] for n in (top, *r.shadowed)}
            out.append(Conflict(p, r.provider, r.shadowed, len(bodies) == 1))
        return out

    # ---- copy-on-write ---------------------------------------------------------------------
    def write(self, path: str, data: bytes) -> None:
        """Copy-on-write: the change lives in the top ``user`` layer; no other layer changes."""
        check_path(path)
        if self._is_protected(path):
            raise OverlayError(f"{escape_text(path, 80)!r} is protected")
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE:
            raise OverlayError("a file is at most %d bytes" % MAX_FILE)
        if path not in self._user and len(self._user) >= MAX_FILES:
            raise OverlayError("too many changes")
        self._user[path] = bytes(data)

    def delete(self, path: str) -> None:
        check_path(path)
        if self._is_protected(path):
            raise OverlayError(f"{escape_text(path, 80)!r} is protected")
        if not self.exists(path):
            raise OverlayError(f"no such file {escape_text(path, 80)!r}")
        self._user[path] = None

    def revert(self, path: str) -> None:
        """Drop the user's change; the layers below show through again."""
        self._user.pop(check_path(path), None)


# ---- persistence and mods ------------------------------------------------------------------------

class OverlayConfig:
    """The owner's load order and rules, with the sha256 of each mod that was approved.

    ``save`` is the password action ``overlay.order``. ``build`` skips (and says why) any mod
    that is gone, not permitted to run, or changed since it was approved."""

    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.state / "overlay.json"

    def load(self) -> dict:
        try:
            d = json.loads(self.file.read_bytes())
        except FileNotFoundError:
            return {"order": [], "rules": {}}
        except (OSError, ValueError):
            raise OverlayError("overlay.json is unreadable") from None
        if (not isinstance(d, dict) or set(d) != {"order", "rules"} or not isinstance(d["order"], list)
                or not isinstance(d["rules"], dict)):
            raise OverlayError("overlay.json is malformed")
        for e in d["order"]:
            if (not isinstance(e, dict) or set(e) != {"name", "sha256"} or not isinstance(e["name"], str)
                    or not NAME_RE.match(e["name"]) or not isinstance(e["sha256"], str)
                    or len(e["sha256"]) != 64):
                raise OverlayError("overlay.json is malformed")
        names = [e["name"] for e in d["order"]]
        for k, v in d["rules"].items():
            check_prefix(k)
            if not isinstance(v, list) or any(n not in names for n in v):
                raise OverlayError("overlay.json is malformed")
        return d

    def save(self, authority: Authority, mods: list, rules: Optional[Mapping[str, list]] = None) -> dict:
        """Approve ``mods`` (installed app names, lowest priority first) in this order."""
        if (not isinstance(mods, list) or len(set(mods)) != len(mods) or len(mods) > MAX_LAYERS - 2
                or any(not isinstance(n, str) or not NAME_RE.match(n) for n in mods)):
            raise OverlayError("list each mod once, named like an app")
        rules = dict(rules or {})
        if len(rules) > MAX_RULES:
            raise OverlayError(f"at most {MAX_RULES} rules")
        for k, v in rules.items():
            check_prefix(k)
            if not isinstance(v, list) or len(set(v)) != len(v) or any(n not in mods for n in v):
                raise OverlayError("a rule may only name mods that are in the order")
        with authority.authorize("overlay.order"):
            order = []
            for name in mods:
                try:
                    app = KApp.from_file(self.paths.apps / f"{name}.kapp")
                except (FileNotFoundError, KAppError, OSError):
                    raise OverlayError(f"{name} is not an installed app") from None
                if not any(n.startswith(OVERLAY_DIR) for n in app.names()):
                    raise OverlayError(f"{name} has no {OVERLAY_DIR} folder")
                order.append({"name": name, "sha256": app.sha256})
            doc = {"order": order, "rules": rules}
            self.paths.state.mkdir(parents=True, exist_ok=True)
            atomic_write(self.file, json.dumps(doc, indent=1, sort_keys=True).encode())
            return doc

    def build(self, base: Layer, protected: tuple = PROTECTED) -> tuple:
        """-> ``(Overlay, skipped)`` where ``skipped`` is ``[{"name", "why"}]``."""
        cfg = self.load()
        ov = Overlay(base, protected)
        skipped, active = [], []
        permits = PermitStore(self.paths)
        for e in cfg["order"]:
            name, why = e["name"], None
            try:
                app = KApp.from_file(self.paths.apps / f"{name}.kapp")
                if app.sha256 != e["sha256"]:
                    why = "changed since you approved it (run: kos overlay order)"
                elif not permits.is_permitted(name):
                    why = f"no longer permitted to run (run: kos permit {name})"
                else:
                    ov.add(Layer.from_zip(name, app.data, OVERLAY_DIR))
                    active.append(name)
            except FileNotFoundError:
                why = "no longer installed"
            except (KAppError, OSError):
                why = "unreadable"
            except OverlayError as exc:
                why = str(exc)[:100]
            if why:
                skipped.append({"name": name, "why": why})
        ov.set_order(active)
        ov.set_rules({k: [n for n in v if n in active] for k, v in cfg["rules"].items()})
        return ov, skipped
