"""Keys and the encrypted stream. Vetted primitives only (scrypt, HKDF-SHA256, ChaCha20-Poly1305).

The stream is chunked so a large file never has to fit in memory, and every chunk is authenticated with
its position and whether it is the last one, so a cut, reordered, duplicated, extended or altered stream
fails. Output of ``decrypt_stream`` must not be trusted until the call has returned: earlier chunks were
already written when a later one fails. Callers write to a temporary file and move it only after success.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CHUNK = 1 << 20
TAG = 16
MAX_CT = CHUNK + TAG
SALT_LEN = 16
DEFAULT_KDF = {"n": 1 << 15, "r": 8, "p": 1}
MIN_PASSWORD = 8


class CryptoError(Exception):
    """Wrong password, damaged or tampered data, or a refused setting."""


def check_kdf(kdf: dict) -> dict:
    """The key-derivation settings come from a file anyone could have edited: bound them."""
    try:
        n, r, p = kdf["n"], kdf["r"], kdf["p"]
    except (KeyError, TypeError):
        raise CryptoError("key settings are missing") from None
    if not all(type(v) is int for v in (n, r, p)):
        raise CryptoError("key settings must be whole numbers")
    if n < (1 << 12) or n > (1 << 20) or n & (n - 1):
        raise CryptoError("scrypt n must be a power of two from 4096 to 1048576")
    if not 1 <= r <= 16 or not 1 <= p <= 4 or 128 * n * r > (1 << 29):
        raise CryptoError("scrypt settings out of range")
    return {"n": n, "r": r, "p": p}


def master_key(password: str, salt: bytes, kdf: dict) -> bytes:
    kdf = check_kdf(kdf)
    if not isinstance(password, str) or not password:
        raise CryptoError("a password is needed")
    if len(salt) != SALT_LEN:
        raise CryptoError("salt must be 16 bytes")
    pw = unicodedata.normalize("NFC", password).encode("utf-8")
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(pw)


def new_password_ok(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise CryptoError(f"use a password of at least {MIN_PASSWORD} characters")


def subkey(master: bytes, label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"kosync/v1/" + label.encode()).derive(master)


def _nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")


def read_full(src, n: int) -> bytes:
    """Exactly ``n`` bytes, fewer only at the end of the stream."""
    out = bytearray()
    while len(out) < n:
        b = src.read(n - len(out))
        if not b:
            break
        out += b
    return bytes(out)


def _stream_key(key: bytes, salt: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                                 info=b"kosync/v1/stream").derive(key))


def encrypt_stream(key: bytes, aad: bytes, src, dst, _salt: bytes | None = None) -> int:
    """Encrypt ``src`` into ``dst``; returns the number of plaintext bytes. ``_salt`` is for test vectors."""
    if len(key) != 32:
        raise CryptoError("key must be 32 bytes")
    salt = _salt if _salt is not None else os.urandom(SALT_LEN)
    dst.write(salt)
    aead = _stream_key(key, salt)
    total = counter = 0
    cur = read_full(src, CHUNK)
    while True:
        nxt = read_full(src, CHUNK) if len(cur) == CHUNK else b""
        final = not nxt
        ct = aead.encrypt(_nonce(counter), cur, aad + counter.to_bytes(8, "big") + (b"\x01" if final else b"\x00"))
        dst.write(len(ct).to_bytes(4, "big") + ct)
        total += len(cur)
        if final:
            return total
        cur, counter = nxt, counter + 1


def decrypt_stream(key: bytes, aad: bytes, src, dst) -> int:
    """Decrypt ``src`` into ``dst``; returns the plaintext length or raises ``CryptoError``."""
    if len(key) != 32:
        raise CryptoError("key must be 32 bytes")
    salt = read_full(src, SALT_LEN)
    if len(salt) != SALT_LEN:
        raise CryptoError("data is too short (cut off)")
    aead = _stream_key(key, salt)
    total = counter = 0
    hdr = read_full(src, 4)
    while True:
        if len(hdr) != 4:
            raise CryptoError("data ends before its last block (cut off)")
        length = int.from_bytes(hdr, "big")
        if not TAG <= length <= MAX_CT:
            raise CryptoError("block size out of range (damaged)")
        ct = read_full(src, length)
        if len(ct) != length:
            raise CryptoError("data ends inside a block (cut off)")
        nxt = read_full(src, 4)
        if len(nxt) not in (0, 4):
            raise CryptoError("trailing bytes after the last block (damaged)")
        final = not nxt
        try:
            pt = aead.decrypt(_nonce(counter), ct, aad + counter.to_bytes(8, "big") + (b"\x01" if final else b"\x00"))
        except InvalidTag:
            raise CryptoError("wrong password, or the data was damaged, reordered, cut or changed") from None
        dst.write(pt)
        total += len(pt)
        if final:
            return total
        hdr, counter = nxt, counter + 1


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


class HashingReader:
    """Wraps a file object and computes a keyed (or plain) SHA-256 of what is read through it."""

    def __init__(self, src, key: bytes | None = None):
        self.src = src
        self.h = hmac.new(key, digestmod=hashlib.sha256) if key is not None else hashlib.sha256()
        self.size = 0

    def read(self, n: int = -1) -> bytes:
        b = self.src.read(n)
        self.h.update(b)
        self.size += len(b)
        return b

    def hexdigest(self) -> str:
        return self.h.hexdigest()
