"""Linked devices: two of your devices trust each other's keys, and every permission can be asked of
the other one. Nothing is automatic, nothing is cloud, nothing runs in the background.

What "linked" means here, exactly
---------------------------------
* **Pairing is in person.** Each device has one long-term Ed25519 identity key, sealed under the
  owner's password. Pairing runs a signed, ephemeral X25519 key exchange, then *both screens show the
  same 6-digit code* and the owner types the password on *each* device. A man in the middle gets a
  different code on each side, so the codes differ and the owner says no. There is no account and no
  third party that holds the trust root (docs/MESH.md, decision 3).
* **A link grants every permission** (scope ``all``): a linked device may *ask* the other for any
  action the OS has, except the few that would let one device take over the other for good
  (``NEVER_REMOTE``: changing the password, linking or unlinking devices, logging in, the
  administrator keyboard, booting input devices).
* **Asking is not getting.** The device that owns the resource still types its own password
  (``Authority.authorize``, README rule 1): once per action *and target* (for example one shared folder) per connection, and for the high-impact
  ones (``ASK_EVERY_TIME``: every ``app.*`` action but the listing, writing files, running code, firewall, grants) *every time*.
  A stolen laptop that is linked to your phone can send requests; it cannot answer the phone's prompt.
* **Every request is audited on the device that receives it**, whether it is granted, refused or
  blocked, and a link can be paused or removed at any time (removing works with the peer offline).

The wire format is in docs/SYNC.md so a phone or desktop client that is not KOS can speak it. What this
file does not do: it opens no socket by itself (``open_client`` / ``serve_socket`` take the OS's own
checked path), it does not hide message sizes or timing, and it cannot make a non-KOS peer honour any
of this: a peer that is not KOS is a remote party holding a key (MESH.md, scope limit).

Primitives are the vetted ``cryptography`` ones only: Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305.
Whole numbers only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypt, firewall
from .auth import ACTIONS, AuditLog, AuthorizationDenied, Authority
from .guard import Guard, GuardRefused
from .paths import Paths, atomic_write

LABEL = b"kos:link:v1"
PLATFORMS = ("kos", "linux", "windows", "macos", "android", "ios")
SCOPES = ("all", "paused")
SYNC_APP = "sync"                      # the firewall rule that lets a link open a connection names this app
MAX_PEERS = 32
MAX_NAME = 40
HANDSHAKE_TIMEOUT = 15
MAX_MESSAGE = crypt.MAX_PLAIN
MAX_ID = (1 << 31) - 1

# Actions a linked device can never ask for. Each one would let a single compromised device take the
# other for good (new password, a new device the owner never saw, an unlinked owner) or needs a person
# physically at the machine (the administrator keyboard, booting the mouse and keyboard).
NEVER_REMOTE = frozenset({
    "auth.change", "session.login", "admin.boot", "device.mouse", "device.keyboard", "device.desktop",
    "link.add", "link.remove", "link.list", "link.connect", "link.listen", "link.identity", "link.scope",
})

# Actions that ask for the password on every use, not once per connection: they write, run, install
# or open the machine up. Every ``app.*`` action is in (it is derived from ``ACTIONS``, not spelled out: the
# names of the actions for using an app belong to kos/layers.py alone, and a new ``app.*`` action added later is
# then every-time by default) except ``app.list``, which only reads. Documented in docs/SYNC.md.
ASK_EVERY_TIME_EXTRA = frozenset({
    "file.write", "code.run", "space.grant", "space.revoke", "firewall.change", "backup.restore", "disk.optimize",
    "cell.start", "cell.stop", "runtime.add", "runtime.remove", "scan.watch", "migrate.import",
})
ASK_EVERY_TIME = frozenset(a for a in ACTIONS if a.startswith("app.") and a != "app.list") | ASK_EVERY_TIME_EXTRA

_ACTION_RE = re.compile(r"^[a-z][a-z0-9.]{0,63}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


class LinkError(Exception):
    """A refusal or a failure, with a reason fit to show the owner."""


class Refusal(Exception):
    """What a handler raises to say no with a reason (a bad path, a changed file). It becomes a refusal
    reply and an audit line; the connection stays up. Any other exception from a handler is a bug: it is
    answered as an internal error with no traceback, and audited as failed."""


def clean_label(text, limit: int = MAX_NAME) -> str:
    """Text a *peer* chose (its name). Printable, short, one line: it is shown, never obeyed."""
    if not isinstance(text, str):
        raise LinkError("a device name must be text")
    out = _CONTROL.sub("", text).strip()[:limit]
    if not out:
        raise LinkError("a device needs a name")
    return out


def device_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:32]


def _raw_public(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _loads(raw: bytes):
    """JSON with no decimals: the command protocol refuses any number with a point or exponent."""
    def bad(token):
        raise ValueError("non-whole number")
    try:
        return json.loads(raw.decode("utf-8"), parse_float=bad, parse_constant=bad)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise LinkError("a message was not valid whole-number JSON") from None


def _dumps(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), allow_nan=False).encode("utf-8")


# ---- identity ------------------------------------------------------------------------------------

class Identity:
    """This device's long-term key. On disk only as a ChaCha20-Poly1305 blob under the password."""

    def __init__(self, seed: bytes, name: str, platform: str):
        if platform not in PLATFORMS:
            raise LinkError(f"platform must be one of {', '.join(PLATFORMS)}")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self._seed = seed
        self.name = clean_label(name)
        self.platform = platform
        self.public = _raw_public(self._key)
        self.device_id = device_id(self.public)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    @staticmethod
    def _file(paths: Paths):
        return paths.state.joinpath("links", "identity.bin")

    @classmethod
    def exists(cls, paths: Paths) -> bool:
        return cls._file(paths).is_file()

    @classmethod
    def create(cls, paths: Paths, grant, name: str, platform: str) -> "Identity":
        grant.check(grant.action, grant.target)
        if cls.exists(paths):
            raise LinkError("this device already has an identity; unlink every peer to replace it")
        ident = cls(os.urandom(32), name, platform)
        body = _dumps({"seed": ident._seed.hex(), "name": ident.name, "platform": ident.platform})
        nonce = os.urandom(12)
        blob = nonce + ChaCha20Poly1305(grant.key("link-identity")).encrypt(nonce, body, LABEL + b":identity")
        f = cls._file(paths)
        f.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(f.parent, 0o700)
        atomic_write(f, blob)
        return ident

    @classmethod
    def load(cls, paths: Paths, grant) -> "Identity":
        try:
            blob = cls._file(paths).read_bytes()
        except FileNotFoundError:
            raise LinkError("this device has no identity yet; link a device first") from None
        try:
            body = ChaCha20Poly1305(grant.key("link-identity")).decrypt(blob[:12], blob[12:], LABEL + b":identity")
            d = _loads(body)
            return cls(bytes.fromhex(d["seed"]), d["name"], d["platform"])
        except (InvalidTag, KeyError, ValueError, TypeError):
            raise LinkError("the device identity is damaged or was sealed under another password") from None


# ---- the link store -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Peer:
    device_id: str
    name: str
    platform: str
    public: str          # hex of the Ed25519 public key; this is what is pinned
    scope: str
    linked_at: int

    @property
    def key_bytes(self) -> bytes:
        return bytes.fromhex(self.public)


class LinkStore:
    """The pinned peers, sealed (HMAC under a password-derived key) like the firewall's rules: a file
    edited by someone without the password is not believed, so it grants nothing."""

    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.state.joinpath("links", "links.json")

    @staticmethod
    def _mac(key: bytes, peers: list[Peer]) -> str:
        body = _dumps([asdict(p) for p in sorted(peers, key=lambda p: p.device_id)])
        return hmac.new(key, LABEL + b":store" + body, hashlib.sha256).hexdigest()

    def load(self, key: bytes) -> tuple[list[Peer], str]:
        """(peers, state): state is 'ok', 'empty' or 'tampered'. Tampered gives no peers."""
        try:
            raw = _loads(self.file.read_bytes())
            peers = [Peer(**p) for p in raw["peers"]]
            if len(peers) > MAX_PEERS or not isinstance(raw["mac"], str):
                raise ValueError
            for p in peers:
                if p.scope not in SCOPES or p.platform not in PLATFORMS or device_id(p.key_bytes) != p.device_id:
                    raise ValueError
        except FileNotFoundError:
            return [], "empty"
        except (ValueError, TypeError, KeyError, LinkError, OSError):
            return [], "tampered"
        if not hmac.compare_digest(raw["mac"], self._mac(key, peers)):
            return [], "tampered"
        return peers, "ok"

    def _save(self, key: bytes, peers: list[Peer]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.file.parent, 0o700)
        atomic_write(self.file, _dumps({"peers": [asdict(p) for p in peers], "mac": self._mac(key, peers)}))

    def peers(self, key: bytes) -> list[Peer]:
        peers, state = self.load(key)
        if state == "tampered":
            raise LinkError("the link list does not match its seal; unlink everything and pair again")
        return peers

    def get(self, key: bytes, public: bytes) -> Optional[Peer]:
        pid = device_id(public)
        return next((p for p in self.peers(key) if p.device_id == pid), None)

    def add(self, key: bytes, peer: Peer) -> None:
        peers = self.peers(key)
        if len(peers) >= MAX_PEERS and all(p.device_id != peer.device_id for p in peers):
            raise LinkError(f"at most {MAX_PEERS} linked devices")
        self._save(key, [p for p in peers if p.device_id != peer.device_id] + [peer])

    def remove(self, key: bytes, ident: str) -> bool:
        peers = self.peers(key)
        keep = [p for p in peers if p.device_id != ident and not p.device_id.startswith(ident)]
        if len(keep) == len(peers):
            return False
        self._save(key, keep)
        return True

    def set_scope(self, key: bytes, ident: str, scope: str) -> bool:
        if scope not in SCOPES:
            raise LinkError(f"scope must be one of {', '.join(SCOPES)}")
        peers = self.peers(key)
        hit = [p for p in peers if p.device_id.startswith(ident)]
        if len(hit) != 1:
            return False
        self._save(key, [p for p in peers if p is not hit[0]] + [Peer(**{**asdict(hit[0]), "scope": scope})])
        return True


# ---- the handshake ------------------------------------------------------------------------------
# I -> R : ephI(32) idI(32) nonceI(16)
# R -> I : ephR(32) idR(32) nonceR(16) sigR(64)      sigR signs  LABEL "R" ephI ephR idI idR nonceI nonceR
# I -> R : sigI(64)                                  sigI signs  LABEL "I" (same transcript)
# keys   : HKDF-SHA256(DH(ephI, ephR), salt = SHA-256(transcript), info = LABEL "keys") -> 64 bytes
# Both signatures cover both ephemeral keys, so a signature cannot be replayed into another exchange
# and a man in the middle who swaps ephemeral keys breaks them (or, if pairing, changes the code).

class _Keyed(crypt.SecureChannel):
    """kos.crypt's record layer (length header, counter nonces, close record, replay and reorder
    detection) over keys this module derived, instead of crypt's own anonymous handshake."""

    def __init__(self, sock: socket.socket, send_key: bytes, recv_key: bytes):
        self.sock = sock
        self._initiator = True
        self._send_n = 0
        self._recv_n = 0
        self._dead = False
        self._closed_by_peer = False
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)


@dataclass
class Session:
    channel: crypt.SecureChannel
    peer_public: bytes
    sas: str                    # 6 digits both owners compare when pairing
    initiator: bool

    @property
    def peer_id(self) -> str:
        return device_id(self.peer_public)


def _transcript(eph_i, eph_r, id_i, id_r, n_i, n_r) -> bytes:
    return eph_i + eph_r + id_i + id_r + n_i + n_r


def _verify(public: bytes, sig: bytes, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
    except (InvalidSignature, ValueError):
        raise LinkError("the other device could not prove who it is (bad signature)") from None


def handshake(sock: socket.socket, identity: Identity, initiator: bool,
              expect: Optional[bytes] = None) -> Session:
    """Mutually authenticated key exchange over ``sock``. ``expect`` is the pinned public key of the
    device we mean to reach; a different key is refused. With ``expect=None`` (pairing only) any
    identity is accepted, and *the owner comparing ``Session.sas`` on both screens is what authenticates it*."""
    try:
        return _handshake(sock, identity, initiator, expect)
    except LinkError:
        try:
            sock.close()                  # a refused handshake leaves nothing open and lets the other side know at once
        except OSError:
            pass
        raise


def _handshake(sock, identity: Identity, initiator: bool, expect: Optional[bytes]) -> Session:
    sock.settimeout(HANDSHAKE_TIMEOUT)
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_public(eph)
    nonce = os.urandom(16)
    try:
        if initiator:
            sock.sendall(eph_pub + identity.public + nonce)
            reply = crypt._recv_exact(sock, 144)
            eph_r, id_r, n_r, sig_r = reply[:32], reply[32:64], reply[64:80], reply[80:144]
            eph_i, id_i, n_i = eph_pub, identity.public, nonce
            peer_id, peer_eph = id_r, eph_r
            tr = _transcript(eph_i, eph_r, id_i, id_r, n_i, n_r)
            _check_peer(identity, peer_id, expect)
            _verify(id_r, sig_r, LABEL + b"R" + tr)
            sock.sendall(identity.sign(LABEL + b"I" + tr))
        else:
            hello = crypt._recv_exact(sock, 80)
            eph_i, id_i, n_i = hello[:32], hello[32:64], hello[64:80]
            eph_r, id_r, n_r = eph_pub, identity.public, nonce
            peer_id, peer_eph = id_i, eph_i
            _check_peer(identity, peer_id, expect)
            tr = _transcript(eph_i, eph_r, id_i, id_r, n_i, n_r)
            sock.sendall(eph_r + id_r + n_r + identity.sign(LABEL + b"R" + tr))
            sig_i = crypt._recv_exact(sock, 64)
            _verify(id_i, sig_i, LABEL + b"I" + tr)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(peer_eph))
    except (OSError, crypt.CryptError, ValueError) as e:
        raise LinkError(f"handshake failed: {e}") from None
    salt = hashlib.sha256(LABEL + tr).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=LABEL + b"keys").derive(shared)
    i2r, r2i = okm[:32], okm[32:]
    sas = HKDF(algorithm=hashes.SHA256(), length=4, salt=salt, info=LABEL + b"sas").derive(shared)
    code = f"{int.from_bytes(sas, 'big') % 1_000_000:06d}"
    send_key, recv_key = (i2r, r2i) if initiator else (r2i, i2r)
    sock.settimeout(None)
    return Session(_Keyed(sock, send_key, recv_key), peer_id, code, initiator)


def _check_peer(identity: Identity, peer_public: bytes, expect: Optional[bytes]) -> None:
    if peer_public == identity.public:
        raise LinkError("refused: that is this device talking to itself")
    if expect is not None and not hmac.compare_digest(peer_public, expect):
        raise LinkError("refused: that is not the device this link was made with")


# ---- messages -----------------------------------------------------------------------------------

def send_msg(channel: crypt.SecureChannel, obj: dict) -> None:
    raw = _dumps(obj)
    if len(raw) > MAX_MESSAGE:
        raise LinkError("message too large")
    try:
        channel.send(raw)
    except crypt.CryptError as e:
        raise LinkError(str(e)) from None


def recv_msg(channel: crypt.SecureChannel) -> Optional[dict]:
    """The next message as a dict, ``None`` when the peer closed cleanly, ``LinkError`` for anything else."""
    try:
        raw = channel.recv()
    except crypt.CryptError as e:
        raise LinkError(str(e)) from None
    if raw is None:
        return None
    msg = _loads(raw)
    if not isinstance(msg, dict):
        raise LinkError("a message must be an object")
    return msg


# ---- pairing ------------------------------------------------------------------------------------

@dataclass
class PairOffer:
    """What the owner sees before saying yes: compare ``sas`` with the other screen."""
    session: Session
    peer_name: str
    peer_platform: str

    @property
    def sas(self) -> str:
        return self.session.sas

    @property
    def peer_id(self) -> str:
        return self.session.peer_id


def start_pairing(sock: socket.socket, identity: Identity, initiator: bool) -> PairOffer:
    """Run the handshake with an unknown device and swap names. Stores nothing."""
    session = handshake(sock, identity, initiator, expect=None)
    send_msg(session.channel, {"t": "hello", "name": identity.name, "platform": identity.platform})
    msg = recv_msg(session.channel)
    if not msg or msg.get("t") != "hello" or set(msg) - {"t", "name", "platform"}:
        raise LinkError("the other device did not introduce itself")
    platform = msg.get("platform")
    if platform not in PLATFORMS:
        raise LinkError("the other device named a platform KOS does not know")
    return PairOffer(session, clean_label(msg.get("name")), platform)


def finish_pairing(paths: Paths, authority: Authority, offer: PairOffer, accept: bool) -> Peer:
    """The owner's decision. ``accept`` is whether the codes matched. Needs the password (``link.add``)
    on this device, and the other owner's yes: nothing is stored unless both said yes."""
    ch = offer.session.channel
    ok = False
    grant = None
    try:
        if accept:
            grant = authority.authorize("link.add", f"{offer.peer_name} {offer.peer_id[:8]}")
            ok = True
    except AuthorizationDenied:
        ok = False
    try:
        send_msg(ch, {"t": "pair", "ok": ok})
        reply = recv_msg(ch)
    except LinkError:
        if grant:
            grant.close()
        raise
    both = bool(ok and reply and reply.get("t") == "pair" and reply.get("ok") is True)
    log = AuditLog(authority.paths)
    if not both:
        if grant:
            grant.close()
        log.record("link.add", f"{offer.peer_name} {offer.peer_id[:8]}", "not-linked")
        raise LinkError("not linked: " + ("you said no" if not ok else "the other owner said no or left"))
    peer = Peer(offer.peer_id, offer.peer_name, offer.peer_platform, offer.session.peer_public.hex(),
                "all", int(time.time()))
    try:
        LinkStore(authority.paths).add(grant.key("link-store"), peer)
    finally:
        grant.close()
    log.record("link.add", f"{offer.peer_name} {offer.peer_id[:8]}", "linked")
    ch.close()
    return peer


# ---- the OS-owned way to a connection (rule 3: blocked unless the firewall has a rule) -------------

def _firewall_allows(paths: Paths, grant, direction: str, host: str, port: int) -> bool:
    try:
        rule = firewall.check_entry(SYNC_APP, "tcp", direction, host, port)
    except firewall.FirewallError:
        return False
    entries, state = firewall.FirewallStore(paths).load(grant.key(firewall.KEY_LABEL))
    return state == "ok" and rule in entries


def open_client(paths: Paths, authority: Authority, host: str, port: int,
                connect: Callable[[str, int], socket.socket] | None = None) -> socket.socket:
    """Connect to a linked device. Refused unless the owner typed the password for it *and* the firewall
    has a rule letting ``sync`` connect to exactly this address and port. Attempts are audited either way."""
    log = AuditLog(paths)
    target = f"{host}:{port}"
    with authority.authorize("link.connect", target) as grant:
        if not _firewall_allows(paths, grant, "connect", host, port):
            log.record("net.link", target, "blocked")
            raise LinkError(f"blocked: the firewall has no rule letting sync connect to {target} "
                            f"(kos firewall: allow app {SYNC_APP}, tcp, connect, {host}, {port})")
    try:
        sock = (connect or (lambda h, p: socket.create_connection((h, p), timeout=HANDSHAKE_TIMEOUT)))(host, port)
    except OSError as e:
        log.record("net.link", target, "failed")
        raise LinkError(f"could not reach {target}: {e}") from None
    log.record("net.link", target, "allowed")
    return sock


def open_listener(paths: Paths, authority: Authority, host: str, port: int) -> socket.socket:
    """A listening socket, only if the firewall allows ``sync`` to listen on exactly this address and port."""
    log = AuditLog(paths)
    target = f"{host}:{port}"
    with authority.authorize("link.listen", target) as grant:
        if not _firewall_allows(paths, grant, "listen", host, port):
            log.record("net.link", target, "blocked")
            raise LinkError(f"blocked: the firewall has no rule letting sync listen on {target}")
    srv = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind((host, port))
        srv.listen(1)
    except OSError as e:
        srv.close()
        log.record("net.link", target, "failed")
        raise LinkError(f"could not listen on {target}: {e}") from None
    log.record("net.link", target, "allowed")
    return srv


# ---- serving requests from a linked device ------------------------------------------------------

Handler = Callable[[dict], dict]


def check_scope(peer: Peer, action: str) -> None:
    """May this linked device ask for ``action`` at all? (It still needs this device's password.)"""
    if not isinstance(action, str) or not _ACTION_RE.match(action) or action not in ACTIONS:
        raise LinkError("unknown action")
    if peer.scope != "all":
        raise LinkError("this link is paused")
    if action in NEVER_REMOTE:
        raise LinkError(f"a linked device can never ask for '{action}': it would let one device take over the other")


class LinkHost:
    """One connection from one linked device. Every request: scope check, then *this* owner's password,
    then the handler, then an audit line. ``handlers`` maps an action to the function that does it; an
    action with no handler is refused as not wired rather than pretended."""

    def __init__(self, paths: Paths, authority: Authority, peer: Peer, channel: crypt.SecureChannel,
                 handlers: dict[str, Handler], guard: Optional[Guard] = None):
        self.paths, self.authority, self.peer, self.channel = paths, authority, peer, channel
        self.handlers = handlers
        self._asked: set[tuple[str, str]] = set()
        self._log = AuditLog(paths)
        self.handled = 0
        # A linked device is one more source of commands, so it meets the same commands-layer guard as an app
        # (kos/guard.py): a flood of messages ends the connection, and a device that makes the owner type the
        # password too often (prompt fatigue is how people get tricked) or keeps asking for what is refused is
        # answered "no" without a prompt. The guard audits as ``guard.commands.*`` with ``link:NAME``.
        self.guard = guard or Guard(f"link:{peer.name} {peer.device_id[:8]}", audit=self._log, pid=None)

    def _label(self) -> str:
        return f"{self.peer.name} {self.peer.device_id[:8]}"

    def _reply(self, rid, ok: bool, detail: str = "", data: Optional[dict] = None) -> None:
        send_msg(self.channel, {"t": "res", "id": rid, "ok": ok, "detail": detail[:300], "data": data or {}})

    def _refuse(self, rid, who: str, outcome: str, detail: str, *, counts: bool = True) -> None:
        if counts:
            self.guard.request_failed()
        self._log.record("link.request", who, outcome)
        self._reply(rid, False, detail)

    def _one(self, msg: dict) -> None:
        self.guard.message()                                     # a flood ends the connection (GuardRefused)
        rid = msg.get("id")
        if (msg.get("t") != "req" or type(rid) is not int or not 0 < rid <= MAX_ID
                or set(msg) - {"t", "id", "action", "target", "args"}):
            raise LinkError("malformed request")                 # kills the connection: a peer that sends it is broken or hostile
        action, args = msg.get("action"), msg.get("args", {})
        target = msg.get("target", "")
        if not isinstance(args, dict) or not isinstance(target, str) or len(target) > 200 or _CONTROL.search(target):
            raise LinkError("malformed request")
        who = f"{self._label()}: {action}"
        try:
            check_scope(self.peer, action)
        except LinkError as e:
            return self._refuse(rid, who, "refused", str(e))
        handler = self.handlers.get(action)
        if handler is None:
            return self._refuse(rid, who, "unwired", f"this device cannot do '{action}' for a linked device yet")
        needs_password = action in ASK_EVERY_TIME or (action, target) not in self._asked
        why = self.guard.request(action if needs_password else "apps")      # "apps" = a request that asks for no password
        if why:
            return self._refuse(rid, who, "refused", why, counts=False)
        if needs_password:
            try:
                self.authority.authorize(action, f"for {self._label()} {target}".strip()).close()
            except AuthorizationDenied as e:
                return self._refuse(rid, who, "refused", f"the owner of this device said no ({e})")
            self._asked.add((action, target))
        try:
            data = handler(args)
        except (Refusal, LinkError, ValueError, OSError, KeyError, TypeError) as e:
            self._log.record("link.request", who, "failed")
            return self._reply(rid, False, f"failed: {type(e).__name__}: {_CONTROL.sub('', str(e))[:200]}")
        except Exception as e:                                   # a handler bug must not take the connection down
            self._log.record("link.request", who, "failed")
            return self._reply(rid, False, f"internal error in {action}: {type(e).__name__}")
        self._log.record("link.request", who, "granted")
        self.handled += 1
        self._reply(rid, True, "", data if isinstance(data, dict) else {})

    def serve(self) -> int:
        """Answer requests until the peer closes. Returns how many were done. A broken connection or a
        malformed message ends it (the channel is dead after any integrity failure)."""
        try:
            while True:
                msg = recv_msg(self.channel)
                if msg is None:
                    return self.handled
                self._one(msg)
        except LinkError:
            self._log.record("link.request", self._label(), "dropped")
            raise
        except GuardRefused as e:
            self._log.record("link.request", self._label(), "dropped")
            raise LinkError(f"connection ended: {e.why}") from None
        finally:
            try:
                self.channel.close()
            except Exception:
                pass
            close = getattr(self.handlers, "close", None)       # a handler set may hold per-connection state
            if callable(close):
                close()


class LinkClient:
    """The asking side. One request at a time; the answer carries the other owner's decision."""

    def __init__(self, channel: crypt.SecureChannel):
        self.channel = channel
        self._id = 0

    def call(self, action: str, target: str = "", args: Optional[dict] = None) -> dict:
        self._id += 1
        send_msg(self.channel, {"t": "req", "id": self._id, "action": action, "target": target, "args": args or {}})
        msg = recv_msg(self.channel)
        if msg is None:
            raise LinkError("the other device closed the connection")
        if (msg.get("t") != "res" or msg.get("id") != self._id or type(msg.get("ok")) is not bool
                or not isinstance(msg.get("detail"), str) or not isinstance(msg.get("data"), dict)
                or set(msg) - {"t", "id", "ok", "detail", "data"}):
            raise LinkError("the other device sent an answer that does not match the question")
        if not msg["ok"]:
            raise LinkError(msg["detail"] or "refused")
        return msg["data"]

    def close(self) -> None:
        self.channel.close()


def serve_socket(paths: Paths, authority: Authority, identity: Identity, sock: socket.socket,
                 handlers: dict[str, Handler], store_key: Optional[bytes] = None) -> int:
    """A peer connected. Prove it is a *linked* device, then serve it.

    ``store_key`` is the link list's key from a password the owner already typed *before* listening (the
    ``sync.serve`` service does this), so a stranger who reaches the port cannot make the owner's screen ask for
    a password: it is turned away before anything is asked. Without it the password is asked here, which is
    only right when the caller knows a linked device is expected."""
    if store_key is None:
        with authority.authorize("link.list", "to check who is connecting") as grant:
            store_key = grant.key("link-store")
    key = store_key
    store = LinkStore(paths)
    known = {bytes.fromhex(p.public): p for p in store.peers(key)}
    # The handshake needs to know which key to expect *before* it can check: read the claimed identity, look
    # it up, and refuse strangers. A stranger learns nothing beyond "no".
    sock.settimeout(HANDSHAKE_TIMEOUT)
    try:
        hello = crypt._recv_exact(sock, 80)
    except (OSError, crypt.CryptError) as e:
        raise LinkError(f"handshake failed: {e}") from None
    peer = known.get(hello[32:64])
    log = AuditLog(paths)
    if peer is None:
        log.record("link.request", f"stranger {device_id(hello[32:64])[:8]}", "refused")
        sock.close()
        raise LinkError("refused: that device is not linked to this one")
    session = handshake(_Replay(sock, hello), identity, initiator=False, expect=peer.key_bytes)
    return LinkHost(paths, authority, peer, session.channel, handlers).serve()


class _Replay:
    """A socket whose first bytes were already read (so ``handshake`` can read them again)."""

    def __init__(self, sock: socket.socket, first: bytes):
        self._sock, self._buf = sock, bytearray(first)

    def recv(self, n: int) -> bytes:
        if self._buf:
            out, self._buf = bytes(self._buf[:n]), self._buf[n:]
            return out
        return self._sock.recv(n)

    def __getattr__(self, name):
        return getattr(self._sock, name)


def connect_linked(sock: socket.socket, identity: Identity, peer: Peer) -> LinkClient:
    """The client side for an already linked device: only that device's pinned key is accepted."""
    return LinkClient(handshake(sock, identity, initiator=True, expect=peer.key_bytes).channel)
