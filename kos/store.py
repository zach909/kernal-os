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
from .kapp import ID_RE, MAX_ARCHIVE, KApp, KAppError, Manifest, compute_seal
from .paths import Paths, atomic_write
from .scan import ScanResult, scan_bytes

SEAL_KEY_LABEL = "kapp-seal"


def version_key(v: str) -> tuple:
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in v.replace("-", ".").split("."))


class TamperedError(Exception):
    pass


class VirusFoundError(KAppError):
    def __init__(self, name: str, result: ScanResult, quarantine_path: Path):
        self.result = result
        self.quarantine_path = quarantine_path
        findings = "; ".join(f"{f.rule} ({f.path})" for f in result.findings)
        super().__init__(f"{name}: {result.summary()} - {findings}. "
                         f"Not installed; moved to {quarantine_path}")


@dataclass(frozen=True)
class InstalledApp:
    name: str
    version: str
    sha256: str


class AppStore:
    def __init__(self, paths: Paths):
        self.paths = paths

    def _files(self, name: str) -> tuple[Path, Path]:
        if not ID_RE.match(name):
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

    def update_all(self, src_dir: Path, authority: Authority) -> list[tuple[str, str, object]]:
        """`kos update all --from DIR`: check every .kapp in DIR against
        every installed app and update whichever are both newer and clean.
        Returns one (name, outcome, detail) row per candidate found, so the
        caller can report skips and scan hits, not just successes."""
        installed = {a.name: a for a in self.installed()}
        results: list[tuple[str, str, object]] = []
        for candidate in sorted(Path(src_dir).glob("*.kapp")):
            try:
                m = KApp.from_file(candidate).manifest
            except KAppError as e:
                results.append((candidate.name, "invalid", str(e)))
                continue
            old = installed.get(m.name)
            if old is None:
                results.append((m.name, "not-installed", None))
                continue
            if version_key(m.version) <= version_key(old.version):
                results.append((m.name, "already-current", old.version))
                continue
            try:
                self._install(candidate, authority, update=True)
                results.append((m.name, "updated", f"{old.version} -> {m.version}"))
            except VirusFoundError as e:
                results.append((m.name, "flagged", e.result.summary()))
        return results

    def _install(self, src: Path, authority: Authority, update: bool) -> Manifest:
        # Validate first so we never ask for a password for garbage.
        app = KApp.from_file(src)
        m = app.manifest
        # Every install/update goes through the security scanner before anything
        # else happens - including before the password prompt, so a flagged
        # file never even gets that far.
        result = scan_bytes(app.data, label=m.name)
        if not result.clean:
            self.paths.ensure()
            qdir = self.paths.state / "quarantine"
            qdir.mkdir(parents=True, exist_ok=True)
            import time
            qpath = qdir / f"{m.name}-{int(time.time())}.kapp"
            atomic_write(qpath, app.data)
            raise VirusFoundError(m.name, result, qpath)
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
        if grant.action not in ("app.run", "app.graphical", "app.open", "app.extend", "app.mod") \
                or grant.target != name:
            raise TamperedError("grant does not cover running this app")
        return self._read_sealed(name, grant.key(SEAL_KEY_LABEL))

    def verified_manifest(self, name: str, grant: Grant):
        """The manifest of an installed app, after the same seal check as a
        run. For callers that only *describe* apps (the skill maker): the
        grant must be for ``skill.make``, so a describe-only grant can never
        be used to load an app to run it, and vice versa."""
        if grant.action != "skill.make":
            raise TamperedError("grant does not cover describing apps")
        return self._read_sealed(name, grant.key(SEAL_KEY_LABEL)).manifest

    def verified_help(self, name: str, grant: Grant):
        """``(manifest, help)`` of an installed app, same seal check and same ``skill.make``
        grant as ``verified_manifest``. ``help`` is the validated ``help.json`` or ``None``."""
        if grant.action != "skill.make":
            raise TamperedError("grant does not cover describing apps")
        app = self._read_sealed(name, grant.key(SEAL_KEY_LABEL))
        return app.manifest, app.help

    def _read_sealed(self, name: str, key: bytes) -> KApp:
        kapp_path, seal_path = self._files(name)
        try:
            meta = json.loads(seal_path.read_text())
            with open(kapp_path, "rb") as f:
                data = f.read(MAX_ARCHIVE + 1)
        except FileNotFoundError:
            raise KAppError(f"{name} is not installed") from None
        digest = hashlib.sha256(data).hexdigest()
        expected = compute_seal(key, meta.get("name", ""), meta.get("version", ""), digest)
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
