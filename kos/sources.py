"""Sources and updates: where software comes from, and getting newer versions.

A *source* is a place you chose to get apps from:

    folder   an absolute directory of ``*.kapp`` files
    https    a website that serves ``kapps.json`` next to its ``.kapp`` files
    github   OWNER/REPO whose latest release carries ``kapps.json`` + ``.kapp`` files

``kapps.json``::  {"apps": [{"name": "x", "version": "1.2", "file": "x-1.2.kapp", "sha256": "<64 hex>"}]}

Nothing is automatic. *Checking* contacts your sources, so it needs your
password (``updates.check``). *Installing* runs the same path as ``kos update``:
the download must match the hash the source advertised, then it is scanned
(a flagged file is quarantined), refused if it is a downgrade, sealed with your
password, and recorded in the provenance ledger. An update that asks for **new
permissions** than the installed version is held back until you say so.

KOS itself, if it runs from a git checkout, can be fast-forwarded from its own
remote (``updates.install``); Python, Node.js and the kernel belong to your
operating system, and are only reported (``provenance.runtimes``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import provenance
from .admin import AdminError
from .auth import Authority
from .kapp import NAME_RE, KApp, KAppError
from .paths import Paths, atomic_write
from .store import AppStore, version_key

KINDS = ("folder", "https", "github")
SOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
GITHUB_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
FILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}\.kapp$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_INDEX = 1 << 20
MAX_KAPP = 64 << 20
LOOPBACK = ("127.0.0.1", "localhost", "::1")


class SourceError(AdminError):
    pass


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """A redirect may not downgrade to plain http."""
    allow_http = False

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not (newurl.startswith("https://") or (self.allow_http and urllib.parse.urlparse(newurl).hostname in LOOPBACK)):
            raise SourceError(f"refusing a redirect to {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, limit: int, timeout: float = 15.0, allow_http: bool = False) -> bytes:
    """Download at most ``limit`` bytes over https (loopback http only in tests)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and not (allow_http and parsed.scheme == "http" and parsed.hostname in LOOPBACK):
        raise SourceError("only https sources are allowed")
    if parsed.username or parsed.password:
        raise SourceError("a source URL must not contain a password")
    handler = _HttpsOnly()
    handler.allow_http = allow_http
    opener = urllib.request.build_opener(handler)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "kos-updater"}), timeout=timeout) as r:
            data = r.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SourceError(f"could not fetch {url}: {getattr(e, 'reason', e)}") from None
    if len(data) > limit:
        raise SourceError(f"{url} is larger than {limit >> 20} MiB")
    return data


class Sources:
    def __init__(self, paths: Paths, *, fetcher: Callable[..., bytes] = fetch, allow_http: bool = False,
                 runner: Callable = subprocess.run, core_root: Optional[Path] = None):
        self.paths, self._fetch, self.allow_http, self._run = paths, fetcher, allow_http, runner
        self.config = paths.etc / "sources.json"
        self.cache = paths.state / "updates.json"
        self.core_root = core_root or provenance.KOS_ROOT_DIR

    # ---------------------------------------------------------------- configured sources
    def list(self) -> list[dict]:
        try:
            d = json.loads(self.config.read_text())
            return [s for s in d if isinstance(s, dict) and s.get("name")]
        except (FileNotFoundError, ValueError):
            return []

    def _save(self, rows: list[dict]) -> None:
        self.paths.ensure()
        atomic_write(self.config, json.dumps(rows, indent=2).encode())

    def add(self, authority: Authority, name: str, kind: str, location: str) -> None:
        if not SOURCE_RE.match(name):
            raise SourceError("a source name is lowercase letters, digits and dashes")
        if kind not in KINDS:
            raise SourceError(f"kind must be one of {', '.join(KINDS)}")
        if kind == "folder" and not (os.path.isabs(location) and os.path.isdir(location)):
            raise SourceError("a folder source must be an existing absolute directory")
        if kind == "github" and not GITHUB_RE.match(location):
            raise SourceError("a github source looks like OWNER/REPO")
        if kind == "https":
            p = urllib.parse.urlparse(location)
            ok = p.scheme == "https" or (self.allow_http and p.scheme == "http" and p.hostname in LOOPBACK)
            if not ok or not p.hostname or p.username or p.password or p.query or p.fragment:
                raise SourceError("an https source is a plain https:// address (no password, query or fragment)")
        if any(s["name"] == name for s in self.list()):
            raise SourceError(f"there is already a source called {name}")
        with authority.authorize("sources.change", f"add {name}"):
            self._save([*self.list(), {"name": name, "kind": kind, "location": location.rstrip("/") if kind == "https" else location}])

    def remove(self, authority: Authority, name: str) -> None:
        rows = self.list()
        if not any(s["name"] == name for s in rows):
            raise SourceError(f"no such source: {name}")
        with authority.authorize("sources.change", f"remove {name}"):
            self._save([s for s in rows if s["name"] != name])

    # ----------------------------------------------------------------- what a source offers
    def _base(self, s: dict) -> str:
        return (s["location"] if s["kind"] == "https"
                else f"https://github.com/{s['location']}/releases/latest/download").rstrip("/") + "/"

    def offered(self, s: dict) -> list[dict]:
        out = []
        if s["kind"] == "folder":
            for f in sorted(Path(s["location"]).glob("*.kapp")):
                try:
                    app = KApp.from_file(f)
                except (KAppError, OSError):
                    continue
                out.append({"name": app.manifest.name, "version": app.manifest.version, "sha256": app.sha256,
                            "ref": str(f), "source": s["name"], "kind": "folder"})
            return out
        base = self._base(s)
        try:
            index = json.loads(self._fetch(base + "kapps.json", MAX_INDEX, allow_http=self.allow_http))
        except ValueError:
            raise SourceError(f"{s['name']}: kapps.json is not valid JSON") from None
        for e in (index.get("apps", []) if isinstance(index, dict) else []):
            if (isinstance(e, dict) and NAME_RE.match(str(e.get("name", ""))) and VERSION_RE.match(str(e.get("version", "")))
                    and FILE_RE.match(str(e.get("file", ""))) and SHA_RE.match(str(e.get("sha256", "")))):
                out.append({"name": e["name"], "version": e["version"], "sha256": e["sha256"],
                            "ref": base + e["file"], "source": s["name"], "kind": s["kind"]})
        return out

    # ------------------------------------------------------------------------ checking
    def check(self, authority: Authority, *, include_core: bool = True) -> dict:
        """Ask every source what it has. Contacts the network, so: password."""
        with authority.authorize("updates.check", "all sources"):
            pass
        store = AppStore(self.paths)
        installed = {a.name: a for a in store.installed()}
        best: dict[str, dict] = {}
        errors = []
        for s in self.list():
            try:
                for c in self.offered(s):
                    if c["name"] not in best or version_key(c["version"]) > version_key(best[c["name"]]["version"]):
                        best[c["name"]] = c
            except (SourceError, OSError) as e:
                errors.append(f"{s['name']}: {e}")
        updates, new = [], []
        for name, c in sorted(best.items()):
            have = installed.get(name)
            if have is None:
                new.append({**c, "installed": None})
            elif version_key(c["version"]) > version_key(have.version):
                added = self._added_permissions(name, c)
                updates.append({**c, "installed": have.version, "adds_permissions": added})
        report = {"t": time.time(), "updates": updates, "new": new, "errors": errors,
                  "core": self.core_status() if include_core else None}
        self.paths.ensure()
        atomic_write(self.cache, json.dumps(report).encode())
        return report

    def last_report(self) -> Optional[dict]:
        try:
            return json.loads(self.cache.read_text())
        except (FileNotFoundError, ValueError):
            return None

    def _added_permissions(self, name: str, candidate: dict) -> list[str]:
        try:
            old = KApp.from_file(self.paths.apps / f"{name}.kapp").manifest.permissions
            if candidate["kind"] == "folder":
                new = KApp.from_file(Path(candidate["ref"])).manifest.permissions
            else:
                return []                      # unknown until downloaded; checked again at install
        except (KAppError, OSError):
            return []
        return sorted(set(new) - set(old))

    # ----------------------------------------------------------------------- installing
    def install(self, authority: Authority, name: str, *, allow_new_permissions: bool = False) -> str:
        report = self.last_report()
        cand = next((c for c in (report or {}).get("updates", []) + (report or {}).get("new", [])
                     if c["name"] == name), None)
        if cand is None:
            raise SourceError(f"{name} has no pending update - run a check first")
        if cand["kind"] == "folder":
            data = Path(cand["ref"]).read_bytes()
        else:
            data = self._fetch(cand["ref"], MAX_KAPP, allow_http=self.allow_http)
        if hashlib.sha256(data).hexdigest() != cand["sha256"]:
            raise SourceError(f"{name}: the download does not match the hash {cand['source']} advertised - refusing")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / f"{name}.kapp"
            f.write_bytes(data)
            app = KApp.from_file(f)
            if (app.manifest.name, app.manifest.version) != (name, cand["version"]):
                raise SourceError(f"{name}: the file is {app.manifest.name} {app.manifest.version}, not what the index said")
            origin = {"source": cand["source"], "location": cand["ref"]}
            store = AppStore(self.paths)
            if cand.get("installed"):
                added = sorted(set(app.manifest.permissions) -
                               set(KApp.from_file(self.paths.apps / f"{name}.kapp").manifest.permissions))
                if added and not allow_new_permissions:
                    raise SourceError(f"{name} {cand['version']} asks for NEW permissions ({', '.join(added)}) "
                                      "- held back until you approve them")
                old, m = store.update(f, authority, origin=origin)
                msg = f"updated {name} {old} -> {m.version} (from {cand['source']})"
            else:
                m = store.install(f, authority, origin=origin)
                msg = f"installed {name} {m.version} (from {cand['source']}); it still needs: permit {name}"
        self._drop_from_cache(name)
        return msg

    def install_all(self, authority: Authority) -> list[str]:
        rows = []
        for u in (self.last_report() or {}).get("updates", []):
            try:
                rows.append(self.install(authority, u["name"]))
            except (AdminError, KAppError) as e:
                rows.append(f"{u['name']}: not installed - {e}")
        return rows or ["nothing to update"]

    def _drop_from_cache(self, name: str) -> None:
        r = self.last_report()
        if r:
            r["updates"] = [c for c in r["updates"] if c["name"] != name]
            r["new"] = [c for c in r["new"] if c["name"] != name]
            atomic_write(self.cache, json.dumps(r).encode())

    # ---------------------------------------------------------------------------- KOS itself
    def _git(self, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return self._run(["git", *args], cwd=self.core_root, capture_output=True, text=True, timeout=timeout,
                         stdin=subprocess.DEVNULL, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})

    def core_status(self) -> dict:
        c = provenance.core(self.core_root)
        if c["kind"] != "git":
            return {**c, "behind": 0, "subjects": []}
        try:
            f = self._git("fetch", "--quiet", "origin")
            if f.returncode != 0:
                return {**c, "behind": 0, "subjects": [], "error": (f.stderr or "fetch failed").strip()[-200:]}
            behind = self._git("rev-list", "--count", "HEAD..@{u}").stdout.strip()
            subjects = self._git("log", "--format=%s", "-10", "HEAD..@{u}").stdout.strip().splitlines()
        except (OSError, subprocess.TimeoutExpired) as e:
            return {**c, "behind": 0, "subjects": [], "error": str(e)}
        return {**c, "behind": int(behind) if behind.isdigit() else 0, "subjects": subjects[:10]}

    def core_update(self, authority: Authority) -> str:
        st = self.core_status()
        if st["kind"] != "git":
            raise SourceError("KOS is part of the system image here: update it by installing a new image")
        if st.get("error"):
            raise SourceError(f"cannot reach KOS's remote: {st['error']}")
        if not st["behind"]:
            return "KOS is up to date"
        if st["dirty"]:
            raise SourceError("this KOS checkout has uncommitted changes; not touching it")
        with authority.authorize("updates.install", f"kos core +{st['behind']}"):
            r = self._git("merge", "--ff-only", "@{u}")
            if r.returncode != 0:
                raise SourceError("cannot fast-forward (your branch has its own commits): " + (r.stderr or r.stdout).strip()[-200:])
        return f"KOS updated by {st['behind']} commit(s); restart KOS to use them"
