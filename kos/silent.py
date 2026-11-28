"""KOS-SILENT/1: the protocol every connection speaks. It grants nothing and tells nothing.

One protocol for any stream connection (TCP, a unix socket, vsock to a cell, a socketpair).
It needs no VPN: the content and the shape of the content are protected by the protocol
itself, whatever network carries the bytes.

**Grants no permissions.** The channel is a pipe for opaque bytes and nothing else:

* the only operations are ``send``, ``recv`` and ``close``. There is no message type that
  carries a permission, a capability, a name, a request or an acknowledgement of one;
  a record type this file does not know kills the connection;
* it does not open, bind, listen or accept: it is handed a socket that is already
  connected, which means the firewall already allowed that connection. Wrapping a
  connection in it adds no hole and removes none;
* it does not say who is on the other end: no peer name, id or address leaves this module,
  so nothing can be authorised "because it came over the channel". What arrives is
  untrusted bytes; the caller still validates them (``kos/protocol.py``) and every action
  still needs ``Authority.authorize`` and the password;
* it imports nothing that decides anything (auth, firewall, kapp, services, session);
  ``tests/test_silent.py`` fails if that changes.

**Gives no information away.**

* nothing readable is ever on the wire: no banner, no version, no name, no length field,
  no record type, no padding in the clear. The first bytes of a connection are random
  looking, so a watcher cannot tell it is this protocol, cannot see what is being agreed,
  and cannot tell a handshake from noise;
* every handshake message is the same size, every record is the same size (1040 bytes).
  A message is cut into records and the last is padded, so the wire shows the size of a
  message only to the nearest record, never exactly;
* nothing is negotiated, so nothing can be downgraded: one suite, no fallback, no
  "classical only" mode;
* a peer that does not hold the shared secret gets **nothing back**: no error, no
  reset reason, no different timing path to learn from. The listener just closes. A
  scanner cannot tell this listener from a closed or a dead one;
* a failure is one message (``connection failed``) whatever the cause, so the error
  text cannot be used as an oracle.

**Encrypted, and quantum resistant.**

* key agreement is a hybrid of **X25519 and ML-KEM-768** (FIPS 203). Both are mandatory
  and both are mixed into every key: an attacker must break both. A quantum computer
  breaks X25519 (Shor); it is not known to break ML-KEM. A flaw found later in ML-KEM
  still leaves X25519, and the reverse;
* both ends hold a 32-byte secret (``Grant.key(label)``, derived from the owner's
  password). It is mixed into the key schedule and into the key that hides the
  handshake, so the connection is authenticated by symmetric cryptography, which a
  quantum computer only halves (Grover): 256 bits stay 128;
* records are ChaCha20-Poly1305 (256-bit key), one key per direction, a counter that
  can only go up by one, so tampering, replay, reordering, dropping, reflecting and
  truncating all kill the channel. A close record tells a finished stream from a cut one;
* every key is fresh per connection (forward secrecy): stealing the password key later
  does not open a recorded connection, because the ephemeral X25519 and ML-KEM secrets
  were never stored.

Built only from the vetted ``cryptography`` library (>= 47, the first with ML-KEM); nothing
here is a cipher or key exchange of our own. If the library cannot do ML-KEM, importing
this file fails; there is no fallback to X25519 alone.

What this does **not** do (stated so nobody assumes it): it does not hide that a
connection exists or the IP addresses at both ends (that needs a mixnet, not a VPN, and
a VPN only moves the problem to the VPN's operator); it does not hide when records are
sent or how many (no cover traffic); it does not protect a machine whose password key is
already stolen, and a stolen key lets its holder open *new* connections to a listener;
it cannot talk to an ordinary website (the other end must hold the shared secret; a site
needs TLS 1.3 with an X25519MLKEM768 group instead); Python may keep copies of keys in
memory (see ``secret.py``); a replay of a first message is refused only while the process
remembers it (the last 4096).

The mathematics of the sizes and the counter are in ``kos/proofs.py`` (Z3). The library
and Python are not proved.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
from collections import OrderedDict
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt import CryptError, KEY_LEN, nonce_for

PROTOCOL = "KOS-SILENT/1"        # a name for humans; it is never sent
_LABEL = b"kos:silent:v1"

SALT_LEN = 16
TAG_LEN = 16
X_LEN = 32                        # X25519 public key
EK_LEN = 1184                     # ML-KEM-768 public (encapsulation) key
CT_LEN = 1088                     # ML-KEM-768 ciphertext
HS_PLAIN = X_LEN + EK_LEN         # both handshake messages carry exactly this much inside
HS_PAD = HS_PLAIN - X_LEN - CT_LEN  # the answer is shorter than the question: padded up
HS_LEN = SALT_LEN + HS_PLAIN + TAG_LEN   # bytes on the wire for each handshake message

CELL_PLAIN = 1024                 # one record, inside
CELL_HEAD = 3                     # type (1 byte) + length (2 bytes), inside the encryption
CELL_CAP = CELL_PLAIN - CELL_HEAD  # message bytes one record can carry
CELL_LEN = CELL_PLAIN + TAG_LEN   # bytes on the wire for each record
MAX_MESSAGE = 1 << 20

MORE, END, CLOSE, CONFIRM = 0, 1, 2, 3   # the only record types there are

HANDSHAKE_SECONDS = 10
REPLAY_MEMORY = 4096
FAILED = "connection failed"      # the only text a handshake failure ever gives

_ZERO_NONCE = bytes(12)
_seen: "OrderedDict[bytes, None]" = OrderedDict()
_seen_lock = threading.Lock()


class SilentError(CryptError):
    """Anything that makes the channel untrustworthy. The channel is dead after it."""


def _fail(why: str = FAILED) -> SilentError:
    return SilentError(why)


def _hs_key(secret: bytes, step: bytes, salts: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salts, info=_LABEL + b"|hs|" + step).derive(secret)


def session_keys(secret: bytes, ss_x: bytes, ss_k: bytes, m1: bytes, m2: bytes,
                 initiator: bool) -> tuple[bytes, bytes]:
    """(key I send with, key I receive with). Both shared secrets and the password key go in,
    and so does everything either side sent, so changing any one of them changes every key."""
    if len(secret) != KEY_LEN or len(ss_x) != 32 or len(ss_k) != 32:
        raise _fail()
    transcript = hashlib.sha3_256(m1 + m2).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=2 * KEY_LEN, salt=secret,
               info=_LABEL + b"|keys|" + transcript).derive(ss_x + ss_k)
    i2r, r2i = okm[:KEY_LEN], okm[KEY_LEN:]
    return (i2r, r2i) if initiator else (r2i, i2r)


def _read(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            raise _fail() from None
        if not chunk:
            raise _fail()
        buf += chunk
    return bytes(buf)


def _raw(public) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _remember_first_message(salt: bytes) -> bool:
    """False if this first message was already seen (a replay)."""
    with _seen_lock:
        if salt in _seen:
            return False
        _seen[salt] = None
        while len(_seen) > REPLAY_MEMORY:
            _seen.popitem(last=False)
        return True


class SilentChannel:
    """A connected socket speaking KOS-SILENT/1. Blocking. One thread per direction at most.

    ``SilentChannel(sock, secret, initiator)``: the caller connected (or accepted) ``sock``
    already, through whatever the firewall allowed. If the handshake fails for any reason the
    socket is closed, nothing was sent to a peer that failed, and ``SilentError`` says only
    "connection failed".
    """

    def __init__(self, sock: socket.socket, secret: bytes, initiator: bool):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) != KEY_LEN:
            raise _fail()
        secret = bytes(secret)
        self._sock = sock
        self._send_n = 0
        self._recv_n = 0
        self._dead = False
        self._closed_by_peer = False
        self._send_lock = threading.Lock()
        saved = sock.gettimeout()
        try:
            sock.settimeout(HANDSHAKE_SECONDS)
            send_key, recv_key = (self._initiate(sock, secret) if initiator
                                  else self._respond(sock, secret))
            self._send = ChaCha20Poly1305(send_key)
            self._recv = ChaCha20Poly1305(recv_key)
            # Key confirmation, initiator first: a peer without the right keys cannot make this record.
            if initiator:
                self._put(CONFIRM, b"")
                self._expect_confirm()
            else:
                self._expect_confirm()
                self._put(CONFIRM, b"")
            sock.settimeout(saved)
        except SilentError:
            self._die()
            raise
        except Exception:                     # anything unexpected is the same failure
            self._die()
            raise _fail() from None

    # ---- handshake ------------------------------------------------------------------

    @staticmethod
    def _initiate(sock: socket.socket, secret: bytes) -> tuple[bytes, bytes]:
        x = X25519PrivateKey.generate()
        k = MLKEM768PrivateKey.generate()
        s1 = os.urandom(SALT_LEN)
        inner = _raw(x.public_key()) + k.public_key().public_bytes_raw()
        m1 = s1 + ChaCha20Poly1305(_hs_key(secret, b"m1", s1)).encrypt(_ZERO_NONCE, inner, s1)
        sock.sendall(m1)
        m2 = _read(sock, HS_LEN)
        s2 = m2[:SALT_LEN]
        try:
            plain = ChaCha20Poly1305(_hs_key(secret, b"m2", s1 + s2)).decrypt(
                _ZERO_NONCE, m2[SALT_LEN:], s2 + hashlib.sha3_256(m1).digest())
        except InvalidTag:
            raise _fail() from None
        peer_x, ct, pad = plain[:X_LEN], plain[X_LEN:X_LEN + CT_LEN], plain[X_LEN + CT_LEN:]
        if any(pad):
            raise _fail()
        try:
            ss_x = x.exchange(X25519PublicKey.from_public_bytes(peer_x))
            ss_k = k.decapsulate(ct)
        except ValueError:
            raise _fail() from None
        return session_keys(secret, ss_x, ss_k, m1, m2, True)

    @staticmethod
    def _respond(sock: socket.socket, secret: bytes) -> tuple[bytes, bytes]:
        m1 = _read(sock, HS_LEN)
        s1 = m1[:SALT_LEN]
        try:
            plain = ChaCha20Poly1305(_hs_key(secret, b"m1", s1)).decrypt(_ZERO_NONCE, m1[SALT_LEN:], s1)
        except InvalidTag:
            raise _fail() from None          # nothing is sent: the caller closes
        if not _remember_first_message(s1):
            raise _fail()
        peer_x, ek = plain[:X_LEN], plain[X_LEN:]
        try:
            ss_k, ct = MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
            y = X25519PrivateKey.generate()
            ss_x = y.exchange(X25519PublicKey.from_public_bytes(peer_x))
        except ValueError:
            raise _fail() from None
        s2 = os.urandom(SALT_LEN)
        inner = _raw(y.public_key()) + ct + bytes(HS_PAD)
        m2 = s2 + ChaCha20Poly1305(_hs_key(secret, b"m2", s1 + s2)).encrypt(
            _ZERO_NONCE, inner, s2 + hashlib.sha3_256(m1).digest())
        try:
            sock.sendall(m2)
        except OSError:
            raise _fail() from None
        return session_keys(secret, ss_x, ss_k, m1, m2, False)

    # ---- records --------------------------------------------------------------------

    def _put(self, kind: int, chunk: bytes) -> None:
        self._send_bytes(self._cell(kind, chunk))

    def _cell(self, kind: int, chunk: bytes) -> bytes:
        if not 0 <= len(chunk) <= CELL_CAP:
            raise _fail()
        plain = bytes([kind]) + len(chunk).to_bytes(2, "big") + chunk + bytes(CELL_CAP - len(chunk))
        sealed = self._send.encrypt(nonce_for(self._send_n), plain, b"")
        self._send_n += 1
        return sealed

    def _send_bytes(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError:
            self._dead = True
            raise _fail("send failed") from None

    def _get(self) -> tuple[int, bytes]:
        blob = _read(self._sock, CELL_LEN)
        try:
            plain = self._recv.decrypt(nonce_for(self._recv_n), blob, b"")
        except InvalidTag:
            raise _fail("record failed authentication (tampered, replayed, reordered, dropped or wrong key)") from None
        self._recv_n += 1
        kind, length = plain[0], int.from_bytes(plain[1:CELL_HEAD], "big")
        if length > CELL_CAP or any(plain[CELL_HEAD + length:]):
            raise _fail("malformed record")
        return kind, plain[CELL_HEAD:CELL_HEAD + length]

    def _expect_confirm(self) -> None:
        kind, body = self._get()
        if kind != CONFIRM or body:
            raise _fail()

    def _die(self) -> None:
        self._dead = True
        try:
            self._sock.close()
        except OSError:
            pass

    # ---- the whole interface --------------------------------------------------------

    def send(self, payload: bytes) -> None:
        """Send one message (up to 1 MiB). Opaque bytes: nothing in it is ever interpreted here."""
        if self._dead:
            raise _fail("channel is closed")
        if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_MESSAGE:
            raise _fail("message too large or not bytes")
        payload = bytes(payload)
        pieces = [payload[i:i + CELL_CAP] for i in range(0, len(payload), CELL_CAP)] or [b""]
        with self._send_lock:
            try:
                wire = b"".join(self._cell(END if i == len(pieces) - 1 else MORE, p)
                                for i, p in enumerate(pieces))
            except CryptError:
                self._dead = True
                raise
            self._send_bytes(wire)

    def recv(self) -> Optional[bytes]:
        """The next whole message, or ``None`` after the peer's close record.

        Anything else wrong - tampering, replay, reorder, a dropped record, the wrong key, a
        cut connection, an unknown record type, a message over 1 MiB - raises ``SilentError``
        and kills the channel.
        """
        if self._closed_by_peer:
            return None
        if self._dead:
            raise _fail("channel is closed")
        parts: list[bytes] = []
        size = 0
        try:
            while True:
                kind, body = self._get()
                if kind == CLOSE:
                    if parts or body:
                        raise _fail("connection ended in the middle of a message")
                    self._closed_by_peer = True
                    return None
                if kind not in (MORE, END):
                    raise _fail("unknown record type")
                size += len(body)
                if size > MAX_MESSAGE:
                    raise _fail("message too large")
                parts.append(body)
                if kind == END:
                    return b"".join(parts)
        except CryptError:
            self._die()
            raise

    def close(self) -> None:
        """Say goodbye (so the other side knows nothing was cut) and close the socket."""
        if not self._dead:
            try:
                with self._send_lock:
                    self._send_bytes(self._cell(CLOSE, b""))
            except CryptError:
                pass
        self._die()
