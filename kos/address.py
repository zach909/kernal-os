"""Addresses: open an app the way a browser opens a website.

    kos://web                       the app 'web'
    kos://web/news/today            ... told to start at /news/today
    kos://notes?mode=graphical&n=3  ... in graphical mode, with a query

A bare app name (``web``) is an address too, so every place that took a name now takes an
address. The path and query are *data handed to the app* (``App.address`` in the SDK); the OS
never turns them into a file name, a command or a shell string. Like everything an app can send
down the wire, an address is hostile input: it is checked strictly here, in one place, and
anything unexpected is refused rather than repaired.

Allowed: ``kos://`` (optional) + an app name, then optionally ``/path`` and ``?query``.
Refused: other schemes, whitespace, control characters, ``%``-escapes, ``#`` fragments,
``.`` / ``..`` path segments, and anything longer than 256 characters after the name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .kapp import ID_RE, KAppError

SCHEME = "kos://"
MODES = ("tui", "graphical", "text", "cmd")
MAX_LAUNCH = 256
MAX_ADDRESS = 300
# No '%', '#', '?' (only as the query separator), space or control characters.
_DATA = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@/-]*$")


class AddressError(KAppError):
    pass


@dataclass(frozen=True)
class Address:
    app: str
    path: str = ""      # "" or "/a/b"
    query: str = ""     # "a=1&b=2", with any mode=... pulled out
    mode: str = ""      # "" when the address does not say

    @property
    def launch(self) -> str:
        """What the app is told: path and query, e.g. ``/news?n=3`` (``""`` when there is none)."""
        return self.path + (f"?{self.query}" if self.query else "")

    def __str__(self) -> str:
        q = "&".join(p for p in (self.query, f"mode={self.mode}" if self.mode else "") if p)
        return f"{SCHEME}{self.app}{self.path}" + (f"?{q}" if q else "")


def check_launch(launch: str) -> str:
    """Validate the path+query an app will be told at start. Returns it unchanged."""
    if not isinstance(launch, str) or len(launch) > MAX_LAUNCH:
        raise AddressError(f"an address's path and query are at most {MAX_LAUNCH} characters")
    path, sep, query = launch.partition("?")
    if not _DATA.match(path) or not _DATA.match(query) or "?" in query:
        raise AddressError("an address may only use letters, digits and . _ ~ ! $ & ' ( ) * + , ; = : @ / -")
    if path and not path.startswith("/"):
        raise AddressError("an address's path must start with /")
    if any(seg in (".", "..") for seg in path.split("/")[1:]):
        raise AddressError("an address cannot contain . or .. segments")
    return launch


def parse(text: str) -> Address:
    if not isinstance(text, str):
        raise AddressError("an address is text")
    # No trimming: surrounding whitespace is refused like any other, not quietly repaired.
    if not text or len(text) > MAX_ADDRESS or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        raise AddressError("not an address: expected kos://APP[/path][?query] or an app name")
    if text[:len(SCHEME)].lower() == SCHEME:
        text = text[len(SCHEME):]
    elif "://" in text or text.startswith("/"):
        raise AddressError(f"only {SCHEME} addresses open apps")
    head, sep, query = text.partition("?")
    app, slash, rest = head.partition("/")
    if not ID_RE.match(app):
        raise AddressError(f"{app!r} is not an app name (lowercase letters, digits and - , starting with a letter; "
                           "a program of an app is APP.PROGRAM)")
    path = slash + rest if slash else ""
    mode, kept = "", []
    for part in query.split("&") if query else []:
        if part.startswith("mode="):
            if mode:
                raise AddressError("an address names its mode once")
            mode = part[len("mode="):]
            if mode not in MODES:
                raise AddressError(f"mode must be one of {', '.join(MODES)}")
        elif part:
            kept.append(part)
    query = "&".join(kept)
    check_launch(path + (f"?{query}" if query else ""))
    return Address(app=app, path=path, query=query, mode=mode)
