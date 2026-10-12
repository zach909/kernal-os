"""Links: the things you pin - to the sidebar shelf or to the desktop backdrop.

A link is only a *name for something*: an app, a file, a folder or a web address. Storing one gives nobody
access to anything: a file link is just a path, and opening it goes through the same gates as anything
else (viewing a file asks for your password, opening an app asks, a web page is opened by the browser app
in its own sandbox with no network until you allow it). So adding and removing links needs no password -
it can only rearrange your own shortcuts - and the list is plain JSON in the OS's state directory, which no
sandboxed app can read or write; apps only see it through the OS (the ``links`` request).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

from .kapp import NAME_RE
from .paths import Paths, atomic_write

KINDS = ("app", "file", "folder", "url")
PLACES = ("shelf", "desktop")
MAX_LINKS = 80
_URL_RE = re.compile(r"^https?://[^\s\x00-\x1f]{3,290}$")
DEFAULT_PINS = (("app", "files", "Files"), ("app", "terminal", "Terminal"), ("app", "editor", "Editor"),
                ("app", "settings", "Settings"))


class LinkError(ValueError):
    pass


def clean(kind: str, target: str, title: str = "") -> tuple[str, str, str]:
    """Validate one link; returns (kind, target, title)."""
    if kind not in KINDS:
        raise LinkError(f"a link is one of {', '.join(KINDS)}")
    if not isinstance(target, str) or not target or "\x00" in target:
        raise LinkError("a link needs a target")
    target = target.strip()
    if kind == "url":
        if not _URL_RE.match(target):
            raise LinkError("a web link starts with http:// or https://")
        default = re.sub(r"^https?://(www\.)?", "", target).split("/")[0]
    elif kind == "app":
        if not NAME_RE.match(target):
            raise LinkError("an app link is an app name")
        default = target
    else:
        if not target.startswith("/") or len(target) > 1024:
            raise LinkError("a file or folder link is an absolute path")
        target = re.sub(r"/{2,}", "/", target).rstrip("/") or "/"
        default = target.rsplit("/", 1)[-1] or "/"
    title = " ".join(str(title or default).split())[:40] or default
    return kind, target, title


class Links:
    def __init__(self, paths: Paths):
        self.file = Path(paths.state) / "links.json"

    def _load(self) -> list[dict]:
        try:
            raw = json.loads(self.file.read_text())
        except FileNotFoundError:
            return [self._make(k, t, ti, "desktop") for k, t, ti in DEFAULT_PINS]       # first run: a few useful pins
        except (OSError, ValueError):
            return []
        out = []
        for d in raw if isinstance(raw, list) else []:
            try:
                if isinstance(d, dict) and d.get("where") in PLACES:
                    out.append(self._make(d["kind"], d["target"], d.get("title", ""), d["where"]))
            except (LinkError, KeyError, TypeError):
                continue                                    # a hand-edited bad entry is dropped, not trusted
        return out[:MAX_LINKS]

    @staticmethod
    def _make(kind: str, target: str, title: str, where: str) -> dict:
        kind, target, title = clean(kind, target, title)
        lid = hashlib.sha256(f"{where}|{kind}|{target}".encode()).hexdigest()[:10]
        return {"id": lid, "kind": kind, "target": target, "title": title, "where": where}

    def _save(self, links: list[dict]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(links, indent=1).encode())

    def list(self, where: Optional[str] = None) -> list[dict]:
        links = self._load()
        return [l for l in links if where is None or l["where"] == where]

    def add(self, kind: str, target: str, title: str = "", where: str = "shelf") -> dict:
        if where not in PLACES:
            raise LinkError(f"a link goes to {' or '.join(PLACES)}")
        links = self._load()
        link = self._make(kind, target, title, where)
        if any(l["id"] == link["id"] for l in links):
            return next(l for l in links if l["id"] == link["id"])
        if len(links) >= MAX_LINKS:
            raise LinkError(f"at most {MAX_LINKS} links")
        links.append(link)
        self._save(links)
        return link

    def remove(self, link_id: str) -> bool:
        links = self._load()
        keep = [l for l in links if l["id"] != link_id]
        if len(keep) == len(links):
            return False
        self._save(keep)
        return True
