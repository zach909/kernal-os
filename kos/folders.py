"""The standard data folders: one permissioned shared folder per kind of data.

KOS already has shared folders ("spaces", ``spaces.py``): a folder under
``<state>/spaces/NAME/`` whose access is decided only by the permission store
(``<state>/permissions/grants.json``). This module makes the standard set in one
go, so every kind of data a person has - photos, documents, messages, keys,
settings - has a folder with a name, a group and an owner from day one, and **no
app can read or write any of them until the owner of the device grants it**
(``kos grant APP space:documents --level read``, with the password).

* The OS owns these folders. The owner is ``@os``, which is not a valid app name,
  so no app can ever claim one with ``owns:`` (``AppStorage`` refuses: "owned by
  @os"). An app asks for one with ``uses:documents`` and is let in by a grant.
* Creating them is one action, ``folders.create``, behind the password.
  Running it again changes nothing that exists.
* ``sensitive`` marks folders that hold secrets or the means to unlock things
  (keys, biometrics, boot structures). It is a label for people and for ``kos
  folders``; the rule is the same for every folder: nothing is granted without
  the password.

Honest limits: a folder is a place to put data and a rule about who may touch it.
Making the folder does not move anything into it, and it does not give any app a
way to read the real thing (the real keychain, the real boot sector): that would
need a kernel and hardware access KOS apps do not have. Data in a folder is as
protected as any shared folder is - plain files in a 0700 directory on the LUKS2
disk, no cipher of its own.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .auth import Authority
from .paths import Paths
from .permissions import Permissions
from .spaces import SPACE_RE

OWNER = "@os"          # not matched by the app-name pattern, so no app can be it


@dataclass(frozen=True)
class Folder:
    name: str
    group: str
    title: str
    sensitive: bool = False


GROUPS = {
    "user-data": "User data and media",
    "system": "System and environment configuration",
    "apps": "Application ecosystem and state",
    "security": "Security, identity and device integrity",
}

FOLDERS: tuple = (
    # --- user data and media ---------------------------------------------------------
    Folder("media", "user-data", "Captured visual and audio media"),
    Folder("documents", "user-data", "Locally stored personal documents"),
    Folder("messages", "user-data", "Written communication and conversation histories"),
    Folder("contacts", "user-data", "Contact information and relationship directories"),
    Folder("bookmarks", "user-data", "Interests, bookmarks and browsing histories"),
    Folder("calendar", "user-data", "Schedules and calendar management data"),
    Folder("voice-notes", "user-data", "Audio recordings and voice notes"),
    Folder("notes", "user-data", "Personal notes, memos and drafts"),
    # --- system and environment ------------------------------------------------------
    Folder("appearance", "system", "Interface layouts, themes and visual configuration"),
    Folder("os-settings", "system", "Operating system registry and core settings profiles"),
    Folder("network-profiles", "system", "Network access credentials and wireless profiles", True),
    Folder("hardware-config", "system", "Hardware control frameworks and driver configuration"),
    Folder("scheduled-tasks", "system", "Automated system tasks and scripted routines"),
    Folder("peripherals", "system", "Peripheral connectivity profiles and Bluetooth linkages"),
    Folder("locale", "system", "Localization, region and language settings"),
    Folder("shell-env", "system", "Terminal environment variables and shell configuration scripts"),
    # --- application ecosystem -------------------------------------------------------
    Folder("app-inventory", "apps", "Application manifests, licenses and purchase inventories"),
    Folder("app-data", "apps", "Application-specific local storage and saved caches"),
    Folder("game-saves", "apps", "Interactive progress, saved progress and game databases"),
    Folder("browser-addons", "apps", "Extension and add-on configuration for browsers"),
    Folder("accounts", "apps", "Communication accounts, protocols and metadata mapping", True),
    Folder("web-offline", "apps", "Web application local offline storage datasets"),
    # --- security, identity and device integrity -------------------------------------
    Folder("keychain", "security", "Cryptographic keychains, credentials and secure tokens", True),
    Folder("biometrics", "security", "Biometric enrollment templates and multi-factor configuration", True),
    Folder("cloud-identity", "security", "Cloud platform identity certificates and sync keys", True),
    Folder("boot-partitions", "security", "Low-level partition structures and core boot sectors", True),
    Folder("access-rules", "security", "User directory permissions and access control matrix rules", True),
)

BY_NAME = {f.name: f for f in FOLDERS}


def _check_catalogue() -> None:
    """The catalogue is code, but a typo here would be a folder nobody can open. Fail at import."""
    seen = set()
    for f in FOLDERS:
        assert SPACE_RE.match(f.name), f"bad folder name {f.name!r}"
        assert f.name not in seen, f"duplicate folder {f.name!r}"
        assert f.group in GROUPS, f"unknown group for {f.name!r}"
        seen.add(f.name)


_check_catalogue()


@dataclass(frozen=True)
class FolderState:
    folder: Folder
    exists: bool
    owner: str | None
    items: int
    access: tuple          # ((app, level), ...) everyone but the owner


def status(paths: Paths) -> list:
    """Every standard folder and where it stands. Reads only; needs no password."""
    perms = Permissions(paths)
    out = []
    for f in FOLDERS:
        res = f"space:{f.name}"
        d = paths.state / "spaces" / f.name
        entries = perms.list(res)
        owner = next((e["app"] for e in entries if e["level"] == "own"), None)
        access = tuple((e["app"], e["level"]) for e in entries if e["level"] != "own")
        items = len(list(d.glob("*"))) if d.is_dir() else 0
        out.append(FolderState(f, d.is_dir() and owner is not None, owner, items, access))
    return out


def create(paths: Paths, authority: Authority) -> tuple[list, list]:
    """Make every standard folder that does not exist yet. Password first.

    Returns (created, kept). A name already owned by an *app* is left alone and reported in
    ``kept`` - this never takes a folder away from whoever has it."""
    paths.ensure()
    perms = Permissions(paths)
    created, kept = [], []
    with authority.authorize("folders.create", f"{len(FOLDERS)} standard folders"):
        for f in FOLDERS:
            res = f"space:{f.name}"
            owner = perms.owner_of(res)
            if owner not in (None, OWNER):
                kept.append(f.name)
                continue
            d = paths.state / "spaces" / f.name
            existed = d.is_dir() and owner == OWNER
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
            if owner is None:
                perms.grant(OWNER, res, "own")
            if not existed:
                created.append(f.name)
            else:
                kept.append(f.name)
    return created, kept
