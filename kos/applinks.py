"""App links: back up an app as an address and a hash instead of the whole app.

A backed-up app does not need its bytes in the vault if there is somewhere to
download the same bytes again. A *link* records that place: the app's name and
version, the https address it can be fetched from, and the SHA-256 of the exact
``.kapp`` that is installed now. A link is a few hundred bytes; the app can be
tens of megabytes. Restoring downloads the file and **refuses it unless its
SHA-256 is the pinned one**, so the server (or anyone on the path) cannot hand
back a different app under the same address.

Rules this follows (see README "Rules"):

* **Password on everything.** ``applink.add``, ``applink.list``, ``applink.remove``
  and ``applink.fetch`` each need the password typed for that action. The index
  is HMAC-sealed with a password-derived key, so an edited or swapped link is
  refused, exactly like the file backup index.
* **Connections blocked by default.** Nothing is ever fetched except one link,
  asked for by name, with the password: one app, one host, one port, one protocol
  (https). With no link there is nothing to fetch. Every attempt is written to the
  audit log as ``net.applink`` (``allowed``, ``blocked`` or ``failed``).
* **Encrypted and verifiable.** https only (no loopback exception, no plain
  ``http://``), certificate and host name verified with no way to turn that off,
  no redirects followed (so no encrypted-to-plain downgrade and no host change),
  no user:password in the address, a size cap and a time limit.
* **Installing is still installing.** Fetching gives bytes, nothing more. The caller
  hands them to ``AppStore.install``, which scans them and asks for the password
  again. A fetched app is never run or installed by this module.

Honest limits: the hash proves the download is the app that was linked, not that
the app is good; the scan and the password prompt at install still decide that. If
the address goes away, so does the app - a link is not a copy. A link records the
address you typed; KOS does not look at what is on the server when it is added
(nothing is fetched until a restore).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

from .auth import Authority, AuditLog, Grant
from .backup import BackupError, VaultTamperedError, _locked
from .kapp import ID_RE, MAX_ARCHIVE, KApp, KAppError
from .paths import Paths, atomic_write
from .store import AppStore

INDEX_KEY_LABEL = "applink-index"
MAX_URL = 300
MAX_LINKS = 1000
TIMEOUT = 60


class AppLinkError(BackupError):
    pass


@dataclass(frozen=True)
class Link:
    name: str
    version: str
    url: str
    sha256: str
    size: int            # bytes of the app that are NOT stored because of this link
    time: float

    def to_json(self) -> dict:
        return {"name": self.name, "version": self.version, "url": self.url,
                "sha256": self.sha256, "size": self.size, "time": self.time}

    @classmethod
    def from_json(cls, d: dict) -> "Link":
        try:
            link = cls(str(d["name"]), str(d["version"]), str(d["url"]), str(d["sha256"]),
                       int(d["size"]), float(d["time"]))
        except (KeyError, TypeError, ValueError):
            raise VaultTamperedError("app link index has a malformed entry") from None
        if not ID_RE.match(link.name) or len(link.sha256) != 64 \
                or any(c not in "0123456789abcdef" for c in link.sha256):
            raise VaultTamperedError("app link index has a malformed entry")
        return link

    @property
    def host(self) -> str:
        p = urllib.parse.urlsplit(self.url)
        return f"{p.hostname}:{p.port or 443}"


def check_url(url) -> str:
    """The address, or AppLinkError. https only; one host; nothing hidden in it."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL \
            or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise AppLinkError("the address must be one https:// address with no spaces or control characters")
    p = urllib.parse.urlsplit(url)
    try:
        p.port
    except ValueError:
        raise AppLinkError("invalid port") from None
    if p.scheme != "https":
        raise AppLinkError("refused: only https:// addresses are allowed (http:// is not encrypted)")
    if not p.hostname or p.username or p.password or p.fragment:
        raise AppLinkError("the address needs a host and no user, password or #fragment")
    return url


# --- the sealed index ------------------------------------------------------------------

def _index_file(paths: Paths):
    return paths.backup / "applinks.json"


def _canonical(links: list) -> bytes:
    return json.dumps([l.to_json() for l in links], sort_keys=True, separators=(",", ":")).encode()


def _mac(key: bytes, links: list) -> str:
    return hmac.new(key, _canonical(links), hashlib.sha256).hexdigest()


def load_links(paths: Paths, grant: Grant) -> list:
    f = _index_file(paths)
    if not f.exists():
        return []
    key = grant.key(INDEX_KEY_LABEL)
    try:
        doc = json.loads(f.read_text())
        links = [Link.from_json(d) for d in doc["links"]]
        mac = str(doc["mac"])
    except (OSError, ValueError, KeyError, TypeError):
        raise VaultTamperedError("app link index is unreadable or malformed") from None
    if not hmac.compare_digest(mac, _mac(key, links)):
        raise VaultTamperedError("app link index does not match its seal - refusing to use it")
    return links


def _save_links(paths: Paths, grant: Grant, links: list) -> None:
    key = grant.key(INDEX_KEY_LABEL)
    atomic_write(_index_file(paths), json.dumps(
        {"links": [l.to_json() for l in links], "mac": _mac(key, links)}, indent=1).encode())


# --- the four actions ------------------------------------------------------------------

def add(paths: Paths, authority: Authority, name: str, url: str) -> Link:
    """Link an installed app to the address it can be downloaded from. The app's own bytes are
    not copied: only its name, version and SHA-256 are kept, so the app takes no space here."""
    url = check_url(url)
    store = AppStore(paths)
    if not isinstance(name, str) or not ID_RE.match(name):
        raise AppLinkError(f"invalid app name {name!r}")
    app = next((a for a in store.installed() if a.name == name), None)
    if app is None:
        raise AppLinkError(f"{name} is not installed, so there is nothing to link (kos list)")
    kapp_path, _ = store._files(name)
    try:
        size = kapp_path.stat().st_size
    except OSError:
        raise AppLinkError(f"{name} is not installed") from None
    with authority.authorize("applink.add", name) as grant, _locked(paths):
        links = load_links(paths, grant)
        if len(links) >= MAX_LINKS and not any(l.name == name for l in links):
            raise AppLinkError(f"at most {MAX_LINKS} app links")
        link = Link(name, app.version, url, app.sha256, size, time.time())
        links = [l for l in links if l.name != name] + [link]      # one link per app: the newest wins
        _save_links(paths, grant, sorted(links, key=lambda l: l.name))
    return link


def snapshot(paths: Paths, authority: Authority, action: str = "applink.list",
             target: str = "") -> list:
    with authority.authorize(action, target) as grant, _locked(paths):
        return load_links(paths, grant)


def remove(paths: Paths, authority: Authority, name: str) -> Link:
    with authority.authorize("applink.remove", name) as grant, _locked(paths):
        links = load_links(paths, grant)
        link = _find(links, name)
        _save_links(paths, grant, [l for l in links if l.name != name])
        return link


def _find(links: list, name: str) -> Link:
    hit = next((l for l in links if l.name == name), None)
    if hit is None:
        raise AppLinkError(f"no app link for {name!r} (see: backup links)")
    return hit


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    ctx = ssl.create_default_context()      # certificate and host name verified; no way to relax it
    ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())


def _log(paths: Paths, link: Link, outcome: str) -> None:
    AuditLog(paths).record("net.applink", f"{link.name} -> {link.host}", outcome)


def fetch(paths: Paths, authority: Authority, name: str, opener=None) -> tuple:
    """Download one linked app and check it is the one that was linked. Password first.

    Returns (link, bytes). Nothing is installed or run: hand the bytes to ``AppStore.install``,
    which scans them and asks for the password again. ``opener`` is for tests."""
    with authority.authorize("applink.fetch", name) as grant, _locked(paths):
        link = _find(load_links(paths, grant), name)
    try:
        check_url(link.url)
    except AppLinkError:
        _log(paths, link, "blocked")
        raise
    req = urllib.request.Request(link.url, headers={"user-agent": "kos-applink"}, method="GET")
    try:
        with (opener or _opener()).open(req, timeout=TIMEOUT) as r:
            data = r.read(MAX_ARCHIVE + 1)
    except urllib.error.HTTPError as e:
        _log(paths, link, "failed")
        raise AppLinkError(f"the server answered HTTP {e.code}"
                           + (" (redirects are not followed)" if 300 <= e.code < 400 else "")) from None
    except urllib.error.URLError as e:
        _log(paths, link, "failed")
        if isinstance(e.reason, ssl.SSLError):
            raise AppLinkError("refused: could not verify the server's certificate") from None
        raise AppLinkError("could not reach the server") from None
    except (OSError, TimeoutError):
        _log(paths, link, "failed")
        raise AppLinkError("could not reach the server") from None
    if len(data) > MAX_ARCHIVE:
        _log(paths, link, "failed")
        raise AppLinkError(f"refused: the download is larger than {MAX_ARCHIVE >> 20} MiB")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), link.sha256):
        _log(paths, link, "failed")
        raise AppLinkError("refused: the download is not the app that was linked (its SHA-256 differs)")
    try:
        m = KApp(data).manifest
    except KAppError as e:
        _log(paths, link, "failed")
        raise AppLinkError(f"refused: the download is not a valid app ({e})") from None
    if (m.name, m.version) != (link.name, link.version):
        _log(paths, link, "failed")
        raise AppLinkError("refused: the download's name or version is not the one that was linked")
    _log(paths, link, "allowed")
    return link, data


def stats(links: list) -> str:
    saved = sum(l.size for l in links)
    return f"{len(links)} app link(s); {saved:,} bytes of apps not stored (downloaded again on restore)"
