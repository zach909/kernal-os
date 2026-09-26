"""Autonomous action: something can run without a human present to type the
password - but never without the password.

This module has two tiers, and the line between them is deliberate, not
provisional:

* A normal grant (``issue``/``redeem``) can never derive master-key
  material - ``RedeemedGrant.key()`` always raises. It cannot install, run,
  update, or optimize anything, no matter what the allowlist changes to.
* A **privileged** grant (``issue_privileged``/``redeem_privileged``) is the
  opposite, by explicit design: it captures the real seal-derivation key at
  issuance and carries it in the grant file, so a redeemed privileged grant
  genuinely *can* install and run apps unattended. Minting one requires the
  admin password specifically (see ``kos/admin.py``) - not the everyday
  owner password - because a leaked privileged grant file is close to a
  bearer copy of full install/run authority until it expires. Use the
  shortest duration and fewest uses the job actually needs.

The rest of this docstring (below) describes the normal-grant tier, which
remains the default and the only tier ``kos autonomy grant`` reaches without
the extra `--privileged` step (`kos autonomy grant-privileged`, which needs
the admin password).
password - but never without the password. The resolution: a human issues a
*temporary permission* in advance, with their password, that spells out
exactly what it authorizes and for how long or how many times. Redeeming
that permission later needs no password and no terminal at all (that's what
makes it usable from a cron job or another process) - but it only ever
authorizes the one exact action it was minted for, it expires, and no one
can read the password back out of it. That is the literal answer to "do
without password authentication so no one can see it, but they can have
temporary permission."

How the "no one can see it" part actually works
------------------------------------------------
Issuing a grant still needs the live password (``authority.authorize`` is
called for real, same as everything else) - a human has to be present for
*that* moment. What gets written to disk is never the password and never
the master key: it's an HMAC tag computed with a separate, non-reversible
*autonomy key* (``HMAC(master, "autonomy-mac")``, generated once and stored
on its own, at ``<etc>/autonomy.key``, 0600). Knowing the tag, or even the
autonomy key itself, gives you no way back to the password or the master
key (HMAC is one-way) - it only lets you *verify* a grant that was already
signed by someone who had the real password at issuance time.

The load-bearing limit, not a bug
----------------------------------
A redeemed grant's ``.key()`` always raises. Grants can never derive
``kapp-seal`` or any other master-key subkey, because the autonomy key is
deliberately not the master key and cannot be turned back into it. That
means autonomous action can start or stop a cell, close an app, start a
scan watch, grant/revoke a permit - but it can never install, update, run,
or open an app, and never optimize (which re-seals). Those all verify or
derive a cryptographic seal, and nothing should ever be able to do that
without the password having been typed for that exact moment. See
``AUTONOMOUS_ACTIONS`` below for the exact, deliberately short allowlist.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .auth import Authority
from .paths import Paths, atomic_write
from .store import SEAL_KEY_LABEL

AUTONOMY_KEY_LABEL = "autonomy-mac"
PRIVILEGED_MAC_LABEL = "autonomy-privileged-mac"

# Deliberately short, and deliberately excludes anything that verifies or
# derives a seal (install/update/run/open/optimize) - see the module
# docstring for why that boundary is permanent, not a TODO.
AUTONOMOUS_ACTIONS = frozenset({
    "cell.start", "cell.stop", "app.close", "scan.watch",
    "app.permit", "app.revoke", "device.desktop",
})

# The tier above: genuinely can install/run/update/optimize, because the
# grant carries the real seal key. Minting one needs the admin password
# specifically - see the module docstring.
PRIVILEGED_ACTIONS = frozenset({
    "app.install", "app.update", "app.run", "app.graphical", "app.open",
    "disk.optimize",
})

MAX_DURATION_S = 30 * 24 * 3600  # 30 days - a grant cannot be "forever"


class AutonomyError(Exception):
    pass


@dataclass(frozen=True)
class AutonomousGrant:
    id: str
    action: str
    target: str
    issued_at: float
    expires_at: float
    max_uses: int
    uses_remaining: int
    mac: str


def _mac(key: bytes, g_id: str, action: str, target: str, expires_at: float,
        max_uses: int) -> str:
    msg = "\x00".join([g_id, action, target, f"{expires_at:.3f}", str(max_uses)]).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class AutonomyKey:
    """The one non-reversible, non-password key that makes verifying a
    grant possible without the password. Created once, on first issue."""

    def __init__(self, paths: Paths):
        self.file = paths.etc / "autonomy.key"

    def exists(self) -> bool:
        return self.file.exists()

    def read(self) -> bytes:
        try:
            return bytes.fromhex(self.file.read_text().strip())
        except FileNotFoundError:
            raise AutonomyError(
                "no autonomous grants have ever been issued on this system") from None

    def create_from(self, master_subkey: bytes) -> bytes:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, master_subkey.hex().encode(), mode=0o600)
        return master_subkey


class RedeemedGrant:
    """What ``AutonomyStore.redeem`` hands back: shaped like ``auth.Grant``
    enough to drop into the same call sites, but ``.key()`` always refuses -
    see the module docstring for why that's permanent."""

    def __init__(self, action: str, target: str):
        self.action = action
        self.target = target

    def check(self, action: str, target: str) -> None:
        if (action, target) != (self.action, self.target):
            raise AutonomyError(f"grant is for {self.action}:{self.target}, not {action}:{target}")

    def key(self, label: str) -> bytes:
        raise AutonomyError(
            "an autonomous grant cannot derive master-key material (no seal, no install, "
            "no run) - that always needs the real password, typed, at that moment")

    def close(self) -> None:
        pass

    def __enter__(self) -> "RedeemedGrant":
        return self

    def __exit__(self, *exc) -> None:
        pass


class RedeemedPrivilegedGrant:
    """The higher tier: `.key()` actually works, but only for the one
    label (`kapp-seal`) captured at issuance - not an arbitrary label the
    way a live `auth.Grant` allows, which keeps this to exactly what
    install/run/update/optimize need and nothing more general."""

    def __init__(self, action: str, target: str, sealed_key: bytes):
        self.action = action
        self.target = target
        self._sealed_key = sealed_key
        self.via_admin = True

    def check(self, action: str, target: str) -> None:
        if (action, target) != (self.action, self.target):
            raise AutonomyError(f"grant is for {self.action}:{self.target}, not {action}:{target}")

    def key(self, label: str) -> bytes:
        if label != SEAL_KEY_LABEL:
            raise AutonomyError(f"a privileged grant only ever carries the {SEAL_KEY_LABEL!r} "
                               f"key, not {label!r}")
        return self._sealed_key

    def raw_master(self) -> bytes:
        raise AutonomyError("a privileged grant never carries the raw master key, "
                           "only the one derived seal key it was issued for")

    def close(self) -> None:
        pass

    def __enter__(self) -> "RedeemedPrivilegedGrant":
        return self

    def __exit__(self, *exc) -> None:
        pass


class AutonomyStore:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.dir = paths.state / "autonomy"
        self.key = AutonomyKey(paths)

    def _file(self, grant_id: str) -> Path:
        if "/" in grant_id or grant_id in ("", ".", ".."):
            raise AutonomyError(f"invalid grant id {grant_id!r}")
        return self.dir / f"{grant_id}.json"

    def issue(self, action: str, target: str, authority: Authority, *,
             duration_s: float, max_uses: int) -> AutonomousGrant:
        """Mint a grant. Needs the real password - this is the one moment a
        human has to actually be present for anything this grant will later
        let happen unattended."""
        if action not in AUTONOMOUS_ACTIONS:
            raise AutonomyError(
                f"{action!r} can never be granted for autonomous use - it needs the "
                f"password every time (allowed: {', '.join(sorted(AUTONOMOUS_ACTIONS))})")
        if not 0 < duration_s <= MAX_DURATION_S:
            raise AutonomyError(f"duration must be 1..{MAX_DURATION_S} seconds")
        if not 1 <= max_uses <= 100000:
            raise AutonomyError("max_uses must be 1..100000")

        with authority.authorize("autonomy.grant", f"{action}:{target}") as grant:
            akey = self.key.read() if self.key.exists() else \
                self.key.create_from(grant.key(AUTONOMY_KEY_LABEL))
            g_id = secrets.token_hex(8)
            now = time.time()
            expires_at = now + duration_s
            mac = _mac(akey, g_id, action, target, expires_at, max_uses)

        g = AutonomousGrant(id=g_id, action=action, target=target, issued_at=now,
                            expires_at=expires_at, max_uses=max_uses,
                            uses_remaining=max_uses, mac=mac)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        atomic_write(self._file(g_id), json.dumps(asdict(g), indent=2).encode())
        return g

    def get(self, grant_id: str) -> AutonomousGrant:
        try:
            return AutonomousGrant(**json.loads(self._file(grant_id).read_text()))
        except FileNotFoundError:
            raise AutonomyError(f"no such grant {grant_id!r}") from None

    # --- the privileged tier: separate storage, separate everything -------

    def _pdir(self) -> Path:
        return self.paths.state / "autonomy_privileged"

    def _pfile(self, grant_id: str) -> Path:
        if "/" in grant_id or grant_id in ("", ".", ".."):
            raise AutonomyError(f"invalid grant id {grant_id!r}")
        return self._pdir() / f"{grant_id}.json"

    @staticmethod
    def _pmac(akey: bytes, g_id: str, action: str, target: str, expires_at: float,
             max_uses: int, sealed_key_hex: str) -> str:
        msg = "\x00".join([g_id, action, target, f"{expires_at:.3f}", str(max_uses),
                          sealed_key_hex]).encode()
        return hmac.new(akey, msg, hashlib.sha256).hexdigest()

    def issue_privileged(self, action: str, target: str, authority: Authority, *,
                         duration_s: float, max_uses: int) -> str:
        """Needs the ADMIN password specifically - see the module docstring
        for why this tier is gated tighter than a normal grant."""
        if action not in PRIVILEGED_ACTIONS:
            raise AutonomyError(
                f"{action!r} is not a privileged action (allowed: "
                f"{', '.join(sorted(PRIVILEGED_ACTIONS))}) - use 'kos autonomy grant' "
                f"if it's in the normal allowlist instead")
        if not 0 < duration_s <= MAX_DURATION_S:
            raise AutonomyError(f"duration must be 1..{MAX_DURATION_S} seconds")
        if not 1 <= max_uses <= 100000:
            raise AutonomyError("max_uses must be 1..100000")

        with authority.authorize("autonomy.grant.privileged", f"{action}:{target}") as grant:
            if not grant.via_admin:
                raise AutonomyError(
                    "a privileged grant needs the ADMIN password specifically, not the "
                    "owner's - see: kos admin setup")
            akey = self.key.read() if self.key.exists() else \
                self.key.create_from(grant.key(AUTONOMY_KEY_LABEL))
            sealed_key_hex = grant.key(SEAL_KEY_LABEL).hex()
            g_id = secrets.token_hex(8)
            now = time.time()
            expires_at = now + duration_s
            mac = self._pmac(akey, g_id, action, target, expires_at, max_uses, sealed_key_hex)

        self._pdir().mkdir(parents=True, exist_ok=True)
        os.chmod(self._pdir(), 0o700)
        doc = {"id": g_id, "action": action, "target": target, "issued_at": now,
              "expires_at": expires_at, "max_uses": max_uses, "uses_remaining": max_uses,
              "sealed_key_hex": sealed_key_hex, "mac": mac}
        atomic_write(self._pfile(g_id), json.dumps(doc, indent=2).encode())
        return g_id

    def redeem_privileged(self, grant_id: str, action: str, target: str) -> RedeemedPrivilegedGrant:
        try:
            g = json.loads(self._pfile(grant_id).read_text())
        except FileNotFoundError:
            raise AutonomyError(f"no such privileged grant {grant_id!r}") from None
        akey = self.key.read()
        expected = self._pmac(akey, g["id"], g["action"], g["target"], g["expires_at"],
                              g["max_uses"], g["sealed_key_hex"])
        if not hmac.compare_digest(expected, g["mac"]):
            raise AutonomyError(f"privileged grant {grant_id!r} failed integrity check - "
                               f"tampered or forged, refusing")
        if (g["action"], g["target"]) != (action, target):
            raise AutonomyError(f"grant {grant_id!r} is for {g['action']}:{g['target']}, "
                               f"not {action}:{target}")
        if time.time() > g["expires_at"]:
            raise AutonomyError(f"privileged grant {grant_id!r} expired")
        if g["uses_remaining"] <= 0:
            raise AutonomyError(f"privileged grant {grant_id!r} has no uses left")

        remaining = g["uses_remaining"] - 1
        if remaining <= 0:
            self._pfile(grant_id).unlink(missing_ok=True)
        else:
            g["uses_remaining"] = remaining
            atomic_write(self._pfile(grant_id), json.dumps(g, indent=2).encode())
        return RedeemedPrivilegedGrant(action, target, bytes.fromhex(g["sealed_key_hex"]))

    def revoke_privileged(self, grant_id: str, authority: Authority) -> None:
        try:
            g = json.loads(self._pfile(grant_id).read_text())
        except FileNotFoundError:
            raise AutonomyError(f"no such privileged grant {grant_id!r}") from None
        with authority.authorize("autonomy.revoke", f"{g['action']}:{g['target']}"):
            self._pfile(grant_id).unlink(missing_ok=True)

    def list_privileged(self) -> list[dict]:
        if not self._pdir().exists():
            return []
        out = []
        for f in sorted(self._pdir().glob("*.json")):
            try:
                d = json.loads(f.read_text())
                out.append({k: v for k, v in d.items() if k != "sealed_key_hex"})
            except (ValueError, KeyError):
                continue
        return out

    def revoke(self, grant_id: str, authority: Authority) -> None:
        g = self.get(grant_id)
        with authority.authorize("autonomy.revoke", f"{g.action}:{g.target}"):
            try:
                self._file(grant_id).unlink()
            except FileNotFoundError:
                pass

    def list(self) -> list[AutonomousGrant]:
        if not self.dir.exists():
            return []
        out = []
        for f in sorted(self.dir.glob("*.json")):
            try:
                out.append(AutonomousGrant(**json.loads(f.read_text())))
            except (ValueError, TypeError, KeyError):
                continue
        return out

    def redeem(self, grant_id: str, action: str, target: str) -> RedeemedGrant:
        """No password, no terminal, no human. Only what a live password
        already, explicitly, narrowly authorized in advance - and only until
        it expires or runs out of uses, whichever comes first."""
        g = self.get(grant_id)
        akey = self.key.read()
        expected = _mac(akey, g.id, g.action, g.target, g.expires_at, g.max_uses)
        if not hmac.compare_digest(expected, g.mac):
            raise AutonomyError(f"grant {grant_id!r} failed integrity check - tampered "
                               f"or forged, refusing")
        if (g.action, g.target) != (action, target):
            raise AutonomyError(f"grant {grant_id!r} is for {g.action}:{g.target}, "
                               f"not {action}:{target}")
        if time.time() > g.expires_at:
            raise AutonomyError(f"grant {grant_id!r} expired "
                               f"{time.time() - g.expires_at:.0f}s ago")
        if g.uses_remaining <= 0:
            raise AutonomyError(f"grant {grant_id!r} has no uses left")

        remaining = g.uses_remaining - 1
        if remaining <= 0:
            self._file(grant_id).unlink(missing_ok=True)
        else:
            updated = AutonomousGrant(**{**asdict(g), "uses_remaining": remaining})
            atomic_write(self._file(grant_id), json.dumps(asdict(updated), indent=2).encode())
        return RedeemedGrant(action, target)
