"""Installed apps: the zip, untouched, plus a password-derived seal.

``<apps>/<name>.kapp``  the exact bytes that were installed
``<apps>/<name>.seal``  {name, version, sha256, seal}

``seal = HMAC(HMAC(master, "kapp-seal"), name | version | sha256(zip))``. The
seal key only exists while someone who knows the password is authorizing an
action, so:

* a modified zip fails verification (sha256 changes),
* a swapped-in different app fails (no valid seal without the password),
* a rolled-back app with a copied old seal file still verifies only if it was
  once legitimately installed; the version is shown on every launch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .auth import Authority, Grant
from .kapp import MAX_ARCHIVE, NAME_RE, KApp, KAppError, Manifest, compute_seal
from .paths import Paths, atomic_write

SEAL_KEY_LABEL = "kapp-seal"


def version_key(v: str) -> tuple:
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in v.replace("-", ".").split("."))


class TamperedError(Exception):
    pass


@dataclass(frozen=True)
class InstalledApp:
    name: str
    version: str
    sha256: str


class AppStore:
    def __init__(self, paths: Paths):
        self.paths = paths

    def _files(self, name: str) -> tuple[Path, Path]:
        if not NAME_RE.match(name):
            raise KAppError(f"invalid app name {name!r}")
        return self.paths.apps / f"{name}.kapp", self.paths.apps / f"{name}.seal"

    def install(self, src: Path, authority: Authority) -> Manifest:
        return self._install(src, authority, update=False)

    def update(self, src: Path, authority: Authority) -> tuple[str, Manifest]:
        """Replace an installed app with a newer version of the same app.

        Downgrades are refused: an attacker can't hand you an old, vulnerable
        version of an app as an "update"."""
        new = KApp.from_file(src).manifest
        old = {a.name: a for a in self.installed()}.get(new.name)
        if old is None:
            raise KAppError(f"{new.name} is not installed (use: kos install)")
        if version_key(new.version) <= version_key(old.version):
            raise KAppError(f"refusing update {old.version} -> {new.version}: not newer")
        return old.version, self._install(src, authority, update=True)

    def _install(self, src: Path, authority: Authority, update: bool) -> Manifest:
        # Validate first so we never ask for a password for garbage.
        app = KApp.from_file(src)
        m = app.manifest
        with authority.authorize("app.update" if update else "app.install", m.name) as grant:
            seal = compute_seal(grant.key(SEAL_KEY_LABEL), m.name, m.version, app.sha256)
        self.paths.ensure()
        kapp_path, seal_path = self._files(m.name)
        atomic_write(kapp_path, app.data)
        atomic_write(seal_path, json.dumps({
            "format": 1, "name": m.name, "version": m.version,
            "sha256": app.sha256, "seal": seal}, indent=2).encode())
        return m

    def remove(self, name: str, authority: Authority) -> None:
        kapp_path, seal_path = self._files(name)
        if not seal_path.exists():
            raise KAppError(f"{name} is not installed")
        with authority.authorize("app.remove", name):
            for p in (kapp_path, seal_path):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass

    def installed(self) -> list[InstalledApp]:
        out = []
        for seal_path in sorted(self.paths.apps.glob("*.seal")):
            try:
                d = json.loads(seal_path.read_text())
                out.append(InstalledApp(d["name"], d["version"], d["sha256"]))
            except (ValueError, KeyError):
                continue
        return out

    def load_verified(self, name: str, grant: Grant) -> KApp:
        """Read the app into memory and prove it is what the owner installed.

        The seal is checked *before* the archive is parsed, so a tampered zip
        never reaches the zip parser.
        """
        if grant.action not in ("app.run", "app.graphical") or grant.target != name:
            raise TamperedError("grant does not cover running this app")
        kapp_path, seal_path = self._files(name)
        try:
            meta = json.loads(seal_path.read_text())
            with open(kapp_path, "rb") as f:
                data = f.read(MAX_ARCHIVE + 1)
        except FileNotFoundError:
            raise KAppError(f"{name} is not installed") from None
        digest = hashlib.sha256(data).hexdigest()
        expected = compute_seal(grant.key(SEAL_KEY_LABEL), meta.get("name", ""),
                                meta.get("version", ""), digest)
        if meta.get("name") != name or not hmac.compare_digest(expected, meta.get("seal", "")):
            raise TamperedError(
                f"{name}: seal check FAILED - the app was modified after install. Refusing to run.")
        app = KApp(data)
        if (app.manifest.name, app.manifest.version) != (meta["name"], meta["version"]):
            raise TamperedError(f"{name}: manifest does not match seal")
        return app

    def reseal_all(self, old: Grant, new_key: bytes) -> int:
        """Re-seal every app under a new password (used by ``kos passwd``)."""
        count = 0
        for app in self.installed():
            kapp_path, seal_path = self._files(app.name)
            data = kapp_path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            meta = json.loads(seal_path.read_text())
            if not hmac.compare_digest(
                    compute_seal(old.key(SEAL_KEY_LABEL), app.name, app.version, digest),
                    meta["seal"]):
                raise TamperedError(f"{app.name}: seal invalid; not re-sealing a tampered app")
            meta["seal"] = compute_seal(new_key, app.name, app.version, digest)
            atomic_write(seal_path, json.dumps(meta, indent=2).encode())
            count += 1
        return count
