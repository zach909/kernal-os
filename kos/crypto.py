"""Encryption at rest: one vetted library, no home-made crypto.

Everything here is ``cryptography``'s AES-256-GCM (``hazmat.primitives.ciphers.aead``) and, for subkeys,
its HKDF. KOS writes NO cipher, KDF, MAC or padding of its own. If the library is missing or broken the
caller gets a CryptoError: there is never a fall back to plaintext.

Envelope
--------
* The owner's password -> scrypt master key (kos/auth.py) -> ``keyring-wrap`` key. That one is derived with
  ``auth.subkey`` (HMAC-SHA256 under the master, the same PRF construction every other KOS label key already
  uses; the master is already a uniformly random 256-bit scrypt output, so a PRF with a fixed label is a
  sound derivation and needs no extra salt). ``Grant.key`` exposes exactly this, so the master itself is
  never handed around: a Grant exists only while the password was just typed.
* A random 32-byte data key (DEK) is made once. It lives sealed in ``<state>/keyring.bin`` under the wrap key.
* Every other secret is sealed under a *purpose-specific* subkey of the DEK (HKDF-SHA256, ``info`` = the
  purpose). Changing the password re-wraps only the DEK; the data files stay as they are.

Blob: ``b"KOS\\x01"`` (magic + version) | 12-byte random nonce (``os.urandom``) | AES-GCM ciphertext+tag.
The AAD is the purpose string, so a blob sealed for one purpose can never be opened as another.

Every failure to open (wrong key, tampering, truncation, wrong purpose, bad magic) is the SAME
``CryptoError('cannot decrypt')``: the caller learns nothing about which. No message, anywhere, holds a key,
a secret, a label or plaintext. Python cannot promise to erase a secret from memory (README); the DEK is
a bytearray that is zeroed as soon as the password-granted block that needed it ends.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .paths import Paths, atomic_write

MAGIC = b"KOS\x01"
NONCE_LEN = 12
TAG_LEN = 16
MIN_BLOB = len(MAGIC) + NONCE_LEN + TAG_LEN
KEYRING_PURPOSE = "keyring"
WRAP_LABEL = "keyring-wrap"
DEK_LEN = 32
_NO_LIB = "encryption library unavailable (install python3-cryptography); nothing was written"


class CryptoError(Exception):
    """Fixed text: ``cannot decrypt``, or ``encryption library unavailable ...`` for a missing library."""

    def __init__(self, msg: str = "cannot decrypt"):
        super().__init__(msg)


def _aead(key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(bytes(key))
    except ImportError:
        raise CryptoError(_NO_LIB) from None
    except Exception:
        raise CryptoError() from None


def available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: F401
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        AESGCM(bytes(32)).encrypt(bytes(12), b"", None)       # the library really works, not just imports
        return True
    except Exception:
        return False


def _purpose(purpose) -> bytes:
    if not isinstance(purpose, str) or not (1 <= len(purpose) <= 64) or not purpose.isascii() or not purpose.isprintable():
        raise CryptoError()
    return purpose.encode()


def _subkey(dek, purpose: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise CryptoError(_NO_LIB) from None
    if len(dek) != DEK_LEN:
        raise CryptoError()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"kos:v1:dek:" + purpose).derive(bytes(dek))


def _seal(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError()
    nonce = os.urandom(NONCE_LEN)
    return MAGIC + nonce + _aead(key).encrypt(nonce, bytes(plaintext), aad)


def _open(key: bytes, aad: bytes, blob: bytes) -> bytes:
    ok, out = False, b""
    if isinstance(blob, (bytes, bytearray)) and len(blob) >= MIN_BLOB and bytes(blob[:4]) == MAGIC:
        aead = _aead(key)            # a missing library is reported as such, not as 'cannot decrypt'
        try:
            out = aead.decrypt(bytes(blob[4:4 + NONCE_LEN]), bytes(blob[4 + NONCE_LEN:]), aad)
            ok = True
        except Exception:
            ok = False
    if not ok:
        raise CryptoError()          # raised outside the except block: no chained cause
    return out


def seal(dek, purpose: str, plaintext: bytes) -> bytes:
    p = _purpose(purpose)
    return _seal(_subkey(dek, p), p, plaintext)


def open_(dek, purpose: str, blob: bytes) -> bytes:
    p = _purpose(purpose)
    return _open(_subkey(dek, p), p, blob)


# ---------------------------------------------------------------- the keyring ----
def wrap_key(master) -> bytes:
    """The key that seals the DEK. ``master`` is a Grant (kos.auth) or the SecretBytes master key."""
    key = getattr(master, "key", None)
    if callable(key):
        return key(WRAP_LABEL)
    from .auth import subkey
    return subkey(master, WRAP_LABEL)


def _staged(paths: Paths) -> Path:
    """Where a password change puts the NEW keyring before the new password file exists (see cmd_passwd)."""
    return paths.keyring_file.with_name(paths.keyring_file.name + ".new")


def keyring_exists(paths: Paths) -> bool:
    return paths.keyring_file.exists() or _staged(paths).exists()


def keyring_state(paths: Paths) -> str:
    return "present" if keyring_exists(paths) else "absent"


def wipe(dek) -> None:
    if isinstance(dek, bytearray):
        for i in range(len(dek)):
            dek[i] = 0


def _write_keyring(paths: Paths, blob: bytes, staged: bool = False) -> None:
    paths.state.mkdir(parents=True, exist_ok=True)
    atomic_write(_staged(paths) if staged else paths.keyring_file, blob, mode=0o600)


# LIMIT (README): changing the password re-wraps the data key, it does not replace it. Anyone holding the OLD password and an
# OLD copy of keyring.bin (a backup, or the file itself in the short crash window below) can still open the data key. If the old
# password was compromised, also remove the credentials and set the assistant key again.
# A password change must never leave the owner unable to open their own data, whatever stops it. So the new
# keyring is STAGED beside the old one, the password file is written, and only then is it swapped in:
#   crash before the password file : old password + old keyring still agree; the staged file is ignored
#   crash after it, before the swap: the old keyring no longer opens, the staged one does, and unlock() finishes
#                                    the swap (it can only be opened by the new password, so it is not a way in)
def stage_keyring(paths: Paths, blob: Optional[bytes]) -> None:
    if blob is not None:
        _write_keyring(paths, blob, staged=True)


def finish_keyring(paths: Paths) -> None:
    st = _staged(paths)
    if st.exists():
        os.replace(st, paths.keyring_file)            # atomic


def abandon_keyring(paths: Paths) -> None:
    try:
        _staged(paths).unlink()
    except OSError:
        pass


def create_keyring(paths: Paths, master) -> bytearray:
    """Make the DEK and store it sealed. Refuses to replace an existing keyring (that would make everything
    sealed under the old DEK unreadable)."""
    if keyring_exists(paths):
        raise CryptoError("a keyring already exists")
    dek = bytearray(os.urandom(DEK_LEN))
    try:
        blob = _seal(wrap_key(master), KEYRING_PURPOSE.encode(), dek)
        _write_keyring(paths, blob)
    except BaseException:
        wipe(dek)
        raise
    return dek


def _read(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except OSError:
        return None


def unlock(paths: Paths, master) -> bytearray:
    key, dek, recovered = wrap_key(master), None, False
    for path, staged in ((paths.keyring_file, False), (_staged(paths), True)):
        blob = _read(path)
        if blob is None:
            continue
        try:
            dek, recovered = _open(key, KEYRING_PURPOSE.encode(), blob), staged
            break
        except CryptoError as e:
            if str(e) != "cannot decrypt":            # a missing library is not a wrong key: say so
                raise
    if dek is None or len(dek) != DEK_LEN:
        raise CryptoError()
    if recovered:                                     # a password change stopped before the swap: finish it
        try:
            finish_keyring(paths)
        except OSError:
            pass                                      # the staged file still opens; the next unlock tries again
    return bytearray(dek)


def prepare_rewrap(paths: Paths, old_master, new_master) -> Optional[bytes]:
    """The keyring sealed under the new master, NOT yet written (None if there is no keyring). Fails if the
    old master cannot open the present one, so a bad state is found before anything is changed."""
    if not keyring_exists(paths):
        return None
    dek = unlock(paths, old_master)
    try:
        return _seal(wrap_key(new_master), KEYRING_PURPOSE.encode(), dek)
    finally:
        wipe(dek)


def rewrap(paths: Paths, old_master, new_master) -> None:
    blob = prepare_rewrap(paths, old_master, new_master)
    if blob is not None:
        _write_keyring(paths, blob)


def commit_keyring(paths: Paths, blob: Optional[bytes]) -> None:
    if blob is not None:
        _write_keyring(paths, blob)


def _has_sealed_data(paths: Paths) -> bool:
    if paths.credentials_file.exists():
        return True
    try:
        return b'"key_enc"' in (paths.state / "assistant.json").read_bytes()
    except OSError:
        return False


def dek_for(paths: Paths, master, create: bool = False) -> bytearray:
    """Open the DEK inside a password-granted block (the caller wipes it). ``create`` makes the keyring if
    there is none - but never when sealed data already exists without one (a deleted keyring must not be
    silently replaced: that data is unreadable and stays so, loudly)."""
    if keyring_exists(paths):
        return unlock(paths, master)
    if not create or _has_sealed_data(paths):
        raise CryptoError()
    if not available():
        raise CryptoError(_NO_LIB)
    return create_keyring(paths, master)
