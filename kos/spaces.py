"""Shared folders ("spaces"): how apps that belong together share data.

An app whose manifest says ``"owns:contacts"`` *creates* the ``contacts``
space (``<state>/spaces/contacts/``) the first time it touches it, and holds
the ``own`` permission for it. Any other app that says ``"uses:contacts"``
can *look for* it, but only gets in if the owner of the device granted it
(``kos grant email-client space:contacts``, with the password) at the level
it needs: ``read`` to get/list, ``write`` to put/delete.

Both halves are required, like ``network``: the manifest has to ask, and the
universal permission store has to say yes. Nothing is decided by the app. An
app that asks for a name somebody else already owns is refused (no taking over
a space). Everything goes through the same ``Vault`` (plain-name keys, size
caps), so a shared space has the same limits as private data.
"""

from __future__ import annotations

import re
from typing import Optional

from .appdirs import AppDirs
from .paths import Paths
from .permissions import Permissions
from .vault import Vault

SPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
NEED = {"get": "read", "list": "read", "put": "write", "delete": "write"}


class StorageError(Exception):
    pass


class AppStorage:
    """Everything one running app may touch on disk through the OS. Built by the
    OS from the verified manifest - the app cannot widen it."""

    def __init__(self, paths: Paths, app: str, manifest_permissions):
        self.paths, self.app = paths, app
        perms = tuple(manifest_permissions)
        self.has_private = "storage" in perms
        self.stores = {x for x in ("cookies", "passwords") if x in perms}
        self.owns = {p[5:] for p in perms if p.startswith("owns:")}
        self.uses = {p[5:] for p in perms if p.startswith("uses:")}
        self.perms = Permissions(paths)

    def usable(self) -> bool:
        return self.has_private or bool(self.owns or self.uses or self.stores)

    def vault(self, space: Optional[str], op: str, store: Optional[str] = None) -> Vault:
        if store is not None:
            # Its own permission, its own folder: 'storage' never reaches it, and it never reaches 'storage'.
            if store not in ("cookies", "passwords") or space is not None:
                raise StorageError("bad store")
            if store not in self.stores:
                raise StorageError(f"this app does not have the '{store}' permission")
            return Vault(self.paths, directory=AppDirs(self.paths, self.app).root / store)
        if space is None:
            if not self.has_private:
                raise StorageError("this app does not have the 'storage' permission")
            return Vault(self.paths, self.app)
        if not SPACE_RE.match(space):
            raise StorageError("bad space name")
        res, need = f"space:{space}", NEED[op]
        if space in self.owns:
            owner = self.perms.owner_of(res)
            if owner is None:
                self.perms.grant(self.app, res, "own")          # the owner creates the space and its permission
            elif owner != self.app:
                raise StorageError(f"space '{space}' is owned by {owner}")
        elif space in self.uses:
            if not self.perms.has(self.app, res, need):
                raise StorageError(f"no {need} access to space '{space}' "
                                   f"(owner of this device: kos grant {self.app} {res} --level {need})")
        else:
            raise StorageError(f"the manifest does not declare owns:{space} or uses:{space}")
        return Vault(self.paths, directory=self.paths.state.joinpath("spaces", space))

    def visible_spaces(self) -> list:
        """Spaces this app could open right now (for the 'look for contacts' step)."""
        out = []
        for name in sorted(self.owns | self.uses):
            owner = self.perms.owner_of(f"space:{name}")
            if name in self.owns and owner in (None, self.app):
                out.append({"space": name, "access": "own", "owner": owner or self.app})
            elif name in self.uses and owner:
                for lvl in ("write", "read"):
                    if self.perms.has(self.app, f"space:{name}", lvl):
                        out.append({"space": name, "access": lvl, "owner": owner}); break
        return out
