"""Where an app's stuff lives. One folder per app, four jobs:

    <state>/appdata/<app>/cache/   scratch for each run; wiped the instant the app ends
    <state>/appdata/<app>/data/    the app's private user data (the vault); never wiped
    <state>/appdata/<app>/run/     live state of its running instances (record, socket, log)

Permissions are NOT per app. They are one universal store (``permissions.py``)
that every decision goes through: who may run, who owns a shared space, who may
read or write it. Shared folders ("spaces", ``spaces.py``) live beside this tree
under ``<state>/spaces/``.
"""

from __future__ import annotations

import os
from pathlib import Path

from .kapp import ID_RE, KAppError
from .paths import Paths


class AppDirs:
    def __init__(self, paths: Paths, name: str):
        if not ID_RE.match(name):
            raise KAppError(f"invalid app name {name!r}")
        self.name = name
        self.root = paths.state / "appdata" / name

    @property
    def cache(self) -> Path: return self.root / "cache"
    @property
    def data(self) -> Path: return self.root / "data"
    @property
    def run(self) -> Path: return self.root / "run"

    def ensure(self) -> "AppDirs":
        for d in (self.root, self.cache, self.data, self.run):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        return self
