"""Encrypted, authenticated channel for the parties that are not parent and child.

Built only from primitives in the vetted ``cryptography`` library; nothing here
is a cipher of our own.

* key agreement: X25519, a fresh key pair per connection (forward secrecy)
* authentication: both sides hold a 32-byte secret derived from the owner's
  password (``Grant.key(label)``); it is mixed in with HKDF, so a peer that
  does not know it cannot derive the keys and its first record fails to open
* key derivation: HKDF-SHA256, salt = the secret, info = protocol label + both
  public keys, giving one key per direction (a record can never be replayed
  back at its sender)
* records: ChaCha20-Poly1305, nonce = 4 zero bytes + 64-bit counter, the length
  header is authenticated, the counter can only go up by one, a close record
  ends the stream so a cut connection is told from a finished one

What this does not do: hide how big a message is or when it is sent; protect
a machine whose password key is already stolen; or make Python wipe copies of
keys (see ``secret.py``). ``kos/proofs.py`` proves the framing and nonce rules.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LABEL = b"kos:crypt:v1"
KEY_LEN = 32
TAG_LEN = 16
MAX_PLAIN = 1 << 20           # biggest message in one record
MAX_RECORD = MAX_PLAIN + 1 + TAG_LEN
COUNTER_LIMIT = (1 << 64) - 1  # the counter may never reach this
DATA, CLOSE = 0, 1
_HEADER = struct.Struct(">I")


class CryptError(Exception):
    """Anything that makes the channel untrustworthy. The channel is dead after it."""


def nonce_for(counter: int) -> bytes:
    """12-byte nonce: 4 zero bytes then the counter. Different counters give different nonces."""
    if not 0 <= counter < COUNTER_LIMIT:
        raise CryptError("message counter used up; open a new connection")
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")


def frame_header(length: int) -> bytes:
    if not 0 < length <= MAX_RECORD:
        raise CryptError("record size out of range")
    return _HEADER.pack(length)


def parse_header(header: bytes) -> int:
    (length,) = _HEADER.unpack(header)
    if not 0 < length <= MAX_RECORD:
        raise CryptError("record size out of range")
    return length


def derive_keys(secret: bytes, mine: bytes, theirs: bytes, shared: bytes, initiator: bool) -> tuple[bytes, bytes]:
    """(key I send with, key I receive with). The initiator's public key always comes first."""
    if len(secret) != KEY_LEN:
        raise CryptError("the password key must be 32 bytes")
    first, second = (mine, theirs) if initiator else (theirs, mine)
    okm = HKDF(algorithm=hashes.SHA256(), length=2 * KEY_LEN, salt=secret,
               info=LABEL + first + second).derive(shared)
    i2r, r2i = okm[:KEY_LEN], okm[KEY_LEN:]
    return (i2r, r2i) if initiator else (r2i, i2r)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise CryptError("connection ended before the stream was closed (cut off)")
        buf += chunk
    return bytes(buf)


class SecureChannel:
    """A connected socket, encrypted. Blocking. One thread per direction at most."""

    def __init__(self, sock: socket.socket, secret: bytes, initiator: bool):
        self.sock = sock
        self._initiator = initiator
        self._send_n = 0
        self._recv_n = 0
        self._dead = False
        self._closed_by_peer = False
        private = X25519PrivateKey.generate()
        mine = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        try:
            if initiator:
                sock.sendall(mine)
                theirs = _recv_exact(sock, 32)
            else:
                theirs = _recv_exact(sock, 32)
                sock.sendall(mine)
            shared = private.exchange(X25519PublicKey.from_public_bytes(theirs))
        except (OSError, ValueError, CryptError) as e:
            self._dead = True
            raise CryptError(f"handshake failed: {e}") from None
        send_key, recv_key = derive_keys(secret, mine, theirs, shared, initiator)
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)

    def _seal(self, kind: int, payload: bytes) -> None:
        if self._dead:
            raise CryptError("channel is closed")
        if len(payload) > MAX_PLAIN:
            raise CryptError("message too large")
        body = bytes([kind]) + payload
        header = frame_header(len(body) + TAG_LEN)
        record = header + self._send.encrypt(nonce_for(self._send_n), body, header)
        self._send_n += 1
        try:
            self.sock.sendall(record)
        except OSError as e:
            self._dead = True
            raise CryptError(f"send failed: {e}") from None

    def send(self, payload: bytes) -> None:
        self._seal(DATA, payload)

    def close(self) -> None:
        """Say goodbye (so the other side knows nothing was cut) and close the socket."""
        if not self._dead:
            try:
                self._seal(CLOSE, b"")
            except CryptError:
                pass
        self._dead = True
        try:
            self.sock.close()
        except OSError:
            pass

    def recv(self) -> Optional[bytes]:
        """The next message, or ``None`` after the peer's close record.

        Anything else wrong - tampering, replay, reorder, a dropped record, the
        wrong key, a cut connection - raises ``CryptError`` and kills the channel.
        """
        if self._closed_by_peer:
            return None
        if self._dead:
            raise CryptError("channel is closed")
        try:
            header = _recv_exact(self.sock, _HEADER.size)
            length = parse_header(header)
            blob = _recv_exact(self.sock, length)
            body = self._recv.decrypt(nonce_for(self._recv_n), blob, header)
        except InvalidTag:
            self._dead = True
            raise CryptError("record failed authentication (tampered, replayed, reordered or wrong key)") from None
        except (OSError, CryptError) as e:
            self._dead = True
            raise e if isinstance(e, CryptError) else CryptError(f"receive failed: {e}") from None
        self._recv_n += 1
        kind, payload = body[0], body[1:]
        if kind == CLOSE:
            self._closed_by_peer = True
            return None
        if kind != DATA:
            self._dead = True
            raise CryptError("unknown record type")
        return payload
