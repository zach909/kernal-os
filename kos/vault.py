"""Encryption for data that leaves the encrypted disk: a backup pushed off-site is sealed before it goes.

* AES-256-GCM from the ``cryptography`` package (a vetted implementation; KOS writes no cipher of its own). Without that
  package nothing is sent: encryption fails closed.
* The key comes from your password: ``Grant.key("offsite:v1")`` (HMAC of the scrypt-derived master), then a fresh random
  16-byte salt per file, so no two files share a key. Nothing is stored that could recover it.
* The file is cut into 1 MiB chunks. Each chunk's nonce is an 8-byte random prefix plus a counter, and its
  authenticated data includes the chunk number and whether it is the last one, so chunks cannot be reordered, dropped or
  truncated without the open failing.
* Format: ``KOSENC1\\n`` | salt(16) | nonce prefix(8) | chunks of (length(4) | ciphertext+tag).

Honest limits: if you change your password, files sealed earlier open only with the password you had then. File names and
sizes are visible to the host; contents are not.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path

MAGIC = b"KOSENC1\n"
CHUNK = 1 << 20
LABEL = "offsite:v1"


class VaultError(Exception):
    pass


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultError("encryption needs the Python 'cryptography' package (nothing was sent): "
                         "install python3-cryptography") from None
    return AESGCM


def _key(master_key: bytes, salt: bytes) -> bytes:
    return hmac.new(master_key, b"kos:file:" + salt, hashlib.sha256).digest()


def _aad(index: int, last: bool) -> bytes:
    return struct.pack(">QB", index, 1 if last else 0)


def encrypt_file(src: Path, dest: Path, master_key: bytes) -> None:
    AESGCM = _aes()
    salt, prefix = os.urandom(16), os.urandom(8)
    aes = AESGCM(_key(master_key, salt))
    size = src.stat().st_size
    tmp = dest.with_name(dest.name + ".part")
    with open(src, "rb") as f, open(tmp, "wb") as out:
        out.write(MAGIC + salt + prefix)
        index = 0
        while True:
            block = f.read(CHUNK)
            last = f.tell() >= size
            ct = aes.encrypt(prefix + struct.pack(">I", index), block, _aad(index, last))
            out.write(struct.pack(">I", len(ct)) + ct)
            index += 1
            if last:
                break
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, dest)


def decrypt_file(src: Path, dest: Path, master_key: bytes) -> None:
    AESGCM = _aes()
    from cryptography.exceptions import InvalidTag
    tmp = dest.with_name(dest.name + ".part")
    try:
        with open(src, "rb") as f:
            head = f.read(len(MAGIC) + 24)
            if len(head) != len(MAGIC) + 24 or not head.startswith(MAGIC):
                raise VaultError("not a KOS-encrypted file")
            salt, prefix = head[len(MAGIC):len(MAGIC) + 16], head[len(MAGIC) + 16:]
            aes = AESGCM(_key(master_key, salt))
            total = src.stat().st_size
            with open(tmp, "wb") as out:
                index = 0
                while True:
                    raw = f.read(4)
                    if len(raw) != 4:
                        raise VaultError("the file is cut short")
                    (n,) = struct.unpack(">I", raw)
                    if not 16 <= n <= CHUNK + 16:
                        raise VaultError("the file is damaged")
                    ct = f.read(n)
                    if len(ct) != n:
                        raise VaultError("the file is cut short")
                    last = f.tell() >= total
                    try:
                        out.write(aes.decrypt(prefix + struct.pack(">I", index), ct, _aad(index, last)))
                    except InvalidTag:
                        raise VaultError("wrong password, or the file was changed") from None
                    index += 1
                    if last:
                        break
                out.flush()
                os.fsync(out.fileno())
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
