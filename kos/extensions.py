"""Extensions and mods: apps that add to other apps, without ever changing them.

Two kinds of add-on, both ordinary ``.kapp`` apps (installed, scanned, sealed, permitted and
opened exactly like any other - everything is an app):

* an **extension** adds to an ordinary app, the way a browser extension adds to a browser;
* a **mod** modifies a *system* app (the taskbar, the App Library).

Neither one is code injected into another app. The host's zip is never touched, so its seal
stays valid. An add-on ships its contributions as *data* in ``extension.json`` (validated when
the add-on is installed, and never executed)::

    {"entries": [{"label": "Notes", "address": "kos://notes"}],      # shortcuts, at most 12
     "colors":  {"accent": "#5a2fa0"}}                                # mods only

and the OS hands that data to the host as an ``extensions`` command right after ``hello``. What
the host does with it is the host's business; the taskbar, the App Library and the ``web``
browser all show the entries.

Nothing happens until the owner switches an add-on on for its host with the password
(``kos extend NAME``). The switch records the sha256 of the exact zip that was approved: if that
add-on is later updated, replaced or tampered with, it silently stops contributing until it is
switched on again, and ``skipped`` says why. A mod needs its own, separately named password
action (``app.mod``): changing a system app is not the same decision as adding a bookmark.
"""

from __future__ import annotations

import json

from .address import AddressError, parse as parse_address
from .kapp import KApp, KAppError, NAME_RE
from .paths import Paths
from .permissions import Permissions
from .permit import PermitStore
from .protocol import ProtocolError, clean_text

MAX_ENTRIES = 12
MAX_ADD_ONS = 8              # most add-ons delivered to one host
MAX_LABEL = 24
COLOR_KEYS = ("accent",)
_KEYS = {"entries", "colors"}


def _color(v) -> str:
    import re
    if not isinstance(v, str) or not re.match(r"^#[0-9a-fA-F]{6}$", v):
        raise KAppError("a color looks like '#5a2fa0'")
    return v.lower()


def parse_contributions(raw: bytes, kind: str) -> dict:
    """Validate ``extension.json``. Returns ``{"entries": [...], "colors": {...}}``; raises
    :class:`KAppError` for anything unexpected (unknown keys included)."""
    try:
        d = json.loads(raw)
    except ValueError as e:
        raise KAppError(f"extension.json is not valid JSON: {e}") from None
    if not isinstance(d, dict) or set(d) - _KEYS:
        raise KAppError(f"extension.json must be an object with only {sorted(_KEYS)}")
    entries = d.get("entries", [])
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise KAppError(f"entries must be a list of at most {MAX_ENTRIES}")
    out_entries = []
    for e in entries:
        if not isinstance(e, dict) or set(e) != {"label", "address"}:
            raise KAppError("each entry is exactly {\"label\": ..., \"address\": ...}")
        label = e["label"]
        try:
            if not isinstance(label, str) or not label.strip() or clean_text(label, MAX_LABEL) != label:
                raise ProtocolError("bad label")
            addr = parse_address(e["address"])
        except (ProtocolError, AddressError):
            raise KAppError(f"bad entry {e!r}: a label of 1-{MAX_LABEL} plain characters "
                            f"and a kos:// address") from None
        out_entries.append({"label": label, "address": str(addr)})
    colors = d.get("colors", {})
    if colors and kind != "mod":
        raise KAppError("only a mod can change colors; an extension adds entries")
    if not isinstance(colors, dict) or set(colors) - set(COLOR_KEYS):
        raise KAppError(f"colors may only set {list(COLOR_KEYS)}")
    return {"entries": out_entries, "colors": {k: _color(v) for k, v in colors.items()}}


def resource_for(kind: str, host: str) -> str:
    """The universal-permission-store resource an add-on's switch lives under."""
    return f"{'mod' if kind == 'mod' else 'extend'}:{host}"


class Extensions:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.perms = Permissions(paths)

    def enable(self, app: KApp) -> str:
        """Switch an add-on on for its host. ``app`` must be the *verified* app (the caller holds
        the password grant). The exact zip approved is pinned by its sha256."""
        m = app.manifest
        if m.kind == "app":
            raise KAppError(f"{m.name} is an ordinary app: only an extension or a mod can be switched on")
        resource = resource_for(m.kind, m.extends)
        self.perms.grant(m.name, resource, "use", pin=app.sha256)
        return resource

    def disable(self, name: str) -> int:
        n = 0
        for e in self.perms.list():
            if e["app"] == name and e["resource"].split(":", 1)[0] in ("extend", "mod"):
                n += self.perms.revoke(name, e["resource"])
        return n

    def enabled(self) -> list[dict]:
        return [e for e in self.perms.list() if e["resource"].split(":", 1)[0] in ("extend", "mod")]

    def payload(self, host: str) -> dict:
        """What the OS tells ``host``: ``{"items": [...], "skipped": [...]}``. An add-on whose zip no
        longer matches what the owner approved - or that is gone, no longer permitted, or no longer
        extends this host - is skipped with a reason, never silently trusted."""
        items, skipped = [], []
        wanted = {f"extend:{host}": "extension", f"mod:{host}": "mod"}
        permits = PermitStore(self.paths)
        for e in sorted(self.perms.list(), key=lambda e: e["app"]):
            kind = wanted.get(e["resource"])
            if kind is None or not NAME_RE.match(e["app"]):
                continue
            name = e["app"]
            why = None
            app = None
            try:
                app = KApp.from_file(self.paths.apps / f"{name}.kapp")
            except FileNotFoundError:
                why = "no longer installed"
            except (KAppError, OSError):
                why = "unreadable"
            if app is not None:
                m = app.manifest
                if app.sha256 != e.get("pin"):
                    why = f"changed since you switched it on (run: kos extend {name})"
                elif (m.kind, m.extends) != (kind, host):
                    why = f"no longer a {kind} of {host}"
                elif not permits.is_permitted(name):
                    why = f"no longer permitted to run (run: kos permit {name})"
            if not why and len(items) >= MAX_ADD_ONS:
                why = f"too many add-ons for one app (the limit is {MAX_ADD_ONS})"
            if why:
                skipped.append({"name": name, "why": clean_text(why, 100)})
            else:
                items.append({"name": name, "version": app.manifest.version, "kind": kind,
                              "entries": app.contributions["entries"],
                              "colors": app.contributions["colors"]})
        return {"items": items, "skipped": skipped}
