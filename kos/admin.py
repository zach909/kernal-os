"""A second, higher-privileged password - the "admin" keyslot.

Modeled on how disk encryption does multiple keyslots (LUKS): the owner's
password and the admin's password are two different passwords that unlock
the *same* master key. Adding an admin slot needs the master key already in
hand (i.e. you must already be authenticated as the owner, or as an
existing admin, to create one) - there is no way to add an admin account
without already holding the keys to everything it would grant.

What "admin" actually changes, concretely:

* Logging in at the console with the admin password instead of the owner's
  gives you a root shell (uid 0) instead of the owner's uid-1000 shell -
  see ``kos/init.py``. This is the literal, deliberate reversal of "no root
  login exists": a real superuser account, gated by its own password, off
  by default until someone with the keys creates one.
* **The admin account itself only lasts until the next reboot.** Its
  keyslot is written to ``paths.runtime`` (``/run/kos`` - tmpfs) rather
  than ``paths.etc`` (``/etc/kos`` - the encrypted, persistent disk), so it
  is gone, unconditionally, the instant the machine restarts: ``kos-init``
  mounts a fresh, empty ``/run`` on every single boot (see ``init.py``'s
  ``MOUNTS``), before anyone has even logged in, so there is no window
  where a stale admin keyslot from a previous boot could be unlocked. Root
  access and privileged autonomy are both something you re-decide every
  session, not a standing account sitting on disk. ``kos admin setup``
  after every reboot you want one; nothing carries over automatically.
* Only the admin password can mint a *privileged* autonomy grant (see
  ``kos/autonomy.py``'s ``issue_privileged``/``redeem_privileged``) - one
  that, unlike a normal grant, carries the actual seal-derivation key and
  so genuinely can install, run, or update apps unattended. That is a much
  larger blast radius than a normal grant if the grant file leaks (it's
  close to a bearer copy of install/run authority until it expires), which
  is exactly why creating one is restricted to the higher-trust admin
  password rather than the everyday owner one.

The wrap
--------
``wrapped_master = master XOR HMAC(admin_slot_key, "admin-wrap")``. HMAC
output is one-way, so nothing here can be run backward to recover the admin
password, the owner's password, or (without the wrap) the master key
itself. Unwrapping needs the *correct* admin password to reproduce the same
keystream.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Optional

from .auth import Authority, AuthorizationDenied, KdfParams, derive_master, subkey
from .paths import Paths, atomic_write
from .secret import SecretBytes

WRAP_LABEL = "admin-wrap"
VERIFIER_LABEL = "admin-verifier"


class AdminError(Exception):
    pass


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass(frozen=True)
class AdminInfo:
    exists: bool
    created_at: float = 0.0


class AdminStore:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.runtime / "admin.json"  # tmpfs: gone at every reboot, by construction

    def exists(self) -> bool:
        return self.file.exists()

    def create(self, admin_password: bytes, master: bytes,
              params: Optional[KdfParams] = None) -> None:
        """Wrap the already-unlocked master key under a new admin password.
        ``master`` comes from ``grant.raw_master()`` on a real
        ``authority.authorize()`` grant, so creating an admin slot always
        needs someone who already has full access to authorize it."""
        if self.exists():
            raise AdminError("an admin account already exists (use: kos admin remove first)")
        if len(admin_password) < 8:
            raise AdminError("admin password must be at least 8 characters")
        params = params or KdfParams.fresh()
        with derive_master(admin_password, params) as slot_key:
            keystream = subkey(slot_key, WRAP_LABEL)
            wrapped = _xor(master, keystream)
            verifier = subkey(slot_key, VERIFIER_LABEL)
        import time
        doc = {
            "version": 1, "kdf": params.to_json(),
            "verifier": verifier.hex(), "wrapped_master": wrapped.hex(),
            "created_at": time.time(),
        }
        self.paths.ensure()
        atomic_write(self.file, json.dumps(doc, indent=2).encode(), mode=0o600)

    def unlock(self, admin_password: bytes) -> Optional[SecretBytes]:
        """Returns the same master key the owner's password would, or None
        if the password is wrong or there's no admin slot at all."""
        try:
            doc = json.loads(self.file.read_text())
        except FileNotFoundError:
            return None
        params = KdfParams.from_json(doc["kdf"])
        with derive_master(admin_password, params) as slot_key:
            expected = bytes.fromhex(doc["verifier"])
            if not hmac.compare_digest(subkey(slot_key, VERIFIER_LABEL), expected):
                return None
            keystream = subkey(slot_key, WRAP_LABEL)
        wrapped = bytes.fromhex(doc["wrapped_master"])
        return SecretBytes(_xor(wrapped, keystream))

    def info(self) -> AdminInfo:
        try:
            doc = json.loads(self.file.read_text())
            return AdminInfo(exists=True, created_at=doc.get("created_at", 0.0))
        except FileNotFoundError:
            return AdminInfo(exists=False)

    def remove(self, authority: Authority) -> None:
        """Removing the admin slot needs the OWNER's password specifically -
        an admin cannot quietly remove the record of their own elevation."""
        if not self.exists():
            raise AdminError("no admin account exists")
        with authority.authorize("admin.remove"):
            pass
        try:
            self.file.unlink()
        except FileNotFoundError:
            pass


def unlock_any(paths: Paths, password: bytes) -> tuple[Optional[SecretBytes], bool]:
    """Try the owner's password first, then the admin's. Returns
    (master_or_None, via_admin)."""
    from .auth import PasswordStore
    master = PasswordStore(paths).verify(password)
    if master is not None:
        return master, False
    admin_master = AdminStore(paths).unlock(password)
    if admin_master is not None:
        return admin_master, True
    return None, False
