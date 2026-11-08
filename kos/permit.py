"""Run permission: a standing grant, separate from the per-run password.

The password proves it's really you, every single time. A permit is your
standing decision that a given app is *allowed to run at all*, recorded once
so `run`/`open` can refuse an app you never permitted before they even get to
the password prompt. Installing an app does not permit it; you decide
separately, the same way a phone asks you to allow an app before its first
launch.

It lives in the universal permission store (``permissions.py``) as resource
``run``, together with the manifest permissions you approved: if an update asks
for more than you approved, ``check_declared`` refuses until you permit again.
Granting and revoking both still go through the password.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .kapp import ID_RE, KAppError
from .paths import Paths
from .permissions import Permissions


class PermitError(Exception):
    pass


@dataclass(frozen=True)
class Permit:
    name: str
    granted_at: float


class PermitStore:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.perms = Permissions(paths)

    def _check(self, name: str) -> None:
        if not ID_RE.match(name):
            raise KAppError(f"invalid app name {name!r}")

    def _migrate_legacy(self, name: str) -> None:
        """Older installs kept one file per app under <state>/permits/."""
        legacy = self.paths.state / "permits" / f"{name}.json"
        if legacy.exists() and not self.perms.get(name, "run"):
            self.perms.grant(name, "run", "use")
        try:
            legacy.unlink()
        except FileNotFoundError:
            pass

    def grant(self, name: str, declared: Optional[Iterable[str]] = None) -> None:
        self._check(name)
        self.perms.grant(name, "run", "use", declared=list(declared) if declared is not None else None)

    def revoke(self, name: str) -> None:
        self._check(name)
        # Only the run permit. Ownership of a shared folder must outlive it: otherwise revoking
        # (say) Contacts would free the name 'contacts' for any other app to claim.
        self.perms.revoke(name, "run")

    def is_permitted(self, name: str) -> bool:
        self._check(name)
        self._migrate_legacy(name)
        return self.perms.has(name, "run")

    def require(self, name: str) -> None:
        if not self.is_permitted(name):
            raise PermitError(
                f"{name} has not been given permission to run (run: kos permit {name})")

    def check_declared(self, name: str, manifest_permissions: Iterable[str]) -> None:
        """Refuse if the app now asks for permissions you never approved."""
        e = self.perms.get(name, "run")
        if not e or "declared" not in e:      # grants made before this existed are not restricted
            return
        extra = sorted(set(manifest_permissions) - set(e["declared"]))
        if extra:
            raise PermitError(f"{name} now asks for {', '.join(extra)}, which you never approved "
                              f"(run: kos permit {name})")

    def list(self) -> list[Permit]:
        return [Permit(e["app"], e["at"]) for e in self.perms.list("run")]
