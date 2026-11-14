"""docs/SYNC.md is a specification a native client is built from, so it must not drift from the code.

Three checks: (1) the vectors and lists printed in the document are read back out of the document and compared
with what the real code does; (2) a clean-room implementation of sections 2 to 4, written here from the document
with nothing but raw cryptography calls, derives the same bytes from the same inputs; (3) that clean-room client can
complete a handshake and a request against the real server."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from kos import linkdev, migrate, portable, syncer  # noqa: E402
from test_linkdev import PW_B, Device  # noqa: E402

DOC = (Path(__file__).resolve().parent.parent / "docs" / "SYNC.md").read_text()


def vec(label: str) -> str:
    """One value from the vectors block of the document, by its label."""
    m = re.search(rf"^{re.escape(label)}\s+(\S+)\s*$", DOC, re.M)
    assert m, f"the document has no vector called {label!r}"
    return m.group(1)


def doc_set(first_line: str) -> set:
    """The names in the fenced block of the document that starts with ``first_line`` (whitespace separated)."""
    m = re.search(rf"```\n({re.escape(first_line)}.*?)\n```", DOC, re.S)
    assert m, f"no block starting {first_line!r}"
    return set(m.group(1).split())


SEED_I, SEED_R = bytes.fromhex(vec("initiator identity seed")), bytes.fromhex(vec("responder identity seed"))
EPH_I, EPH_R = bytes.fromhex(vec("initiator eph private")), bytes.fromhex(vec("responder eph private"))
NONCE_I, NONCE_R = bytes.fromhex(vec("nonce_i")), bytes.fromhex(vec("nonce_r"))
LABEL = b"kos:link:v1"


def raw_pub(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def hkdf(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


# ---- a clean-room implementation of sections 2.1 and 2.2, from the document only -----------------

class SpecPeer:
    """Initiator or responder, using nothing but the primitives the document names."""

    def __init__(self, sock, seed: bytes, eph: bytes, nonce: bytes, initiator: bool, expect: bytes | None = None):
        self.sock, self.initiator = sock, initiator
        self.idk = Ed25519PrivateKey.from_private_bytes(seed)
        self.eph = X25519PrivateKey.from_private_bytes(eph)
        self.id_pub, self.eph_pub, self.nonce = raw_pub(self.idk), raw_pub(self.eph), nonce
        self.wire = bytearray()                                   # everything this side sent, for the vectors
        self.sent = self.recvd = 0
        self.expect = expect

    def send_raw(self, b: bytes):
        self.wire += b
        self.sock.sendall(b)

    def read(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            assert chunk, "connection closed"
            buf += chunk
        return buf

    def handshake(self):
        if self.initiator:
            self.send_raw(self.eph_pub + self.id_pub + self.nonce)
            m2 = self.read(144)
            eph_r, id_r, n_r, sig_r = m2[:32], m2[32:64], m2[64:80], m2[80:144]
            T = self.eph_pub + eph_r + self.id_pub + id_r + self.nonce + n_r
            assert id_r != self.id_pub
            if self.expect is not None:
                assert id_r == self.expect
            Ed25519PublicKey.from_public_bytes(id_r).verify(sig_r, LABEL + b"R" + T)
            self.send_raw(self.idk.sign(LABEL + b"I" + T))
            peer_eph, self.peer_id = eph_r, id_r
        else:
            m1 = self.read(80)
            eph_i, id_i, n_i = m1[:32], m1[32:64], m1[64:80]
            T = eph_i + self.eph_pub + id_i + self.id_pub + n_i + self.nonce
            assert id_i != self.id_pub
            self.send_raw(self.eph_pub + self.id_pub + self.nonce + self.idk.sign(LABEL + b"R" + T))
            Ed25519PublicKey.from_public_bytes(id_i).verify(self.read(64), LABEL + b"I" + T)
            peer_eph, self.peer_id = eph_i, id_i
        shared = self.eph.exchange(X25519PublicKey.from_public_bytes(peer_eph))
        salt = hashlib.sha256(LABEL + T).digest()
        okm = hkdf(shared, salt, LABEL + b"keys", 64)
        i2r, r2i = okm[:32], okm[32:]
        self.send_key, self.recv_key = (i2r, r2i) if self.initiator else (r2i, i2r)
        self.code = f"{int.from_bytes(hkdf(shared, salt, LABEL + b'sas', 4), 'big') % 1000000:06d}"
        self.transcript = T
        return self

    def send(self, payload: bytes, kind: int = 0) -> bytes:
        body = bytes([kind]) + payload
        header = (len(body) + 16).to_bytes(4, "big")
        nonce = b"\x00\x00\x00\x00" + self.sent.to_bytes(8, "big")
        rec = header + ChaCha20Poly1305(self.send_key).encrypt(nonce, body, header)
        self.sent += 1
        self.send_raw(rec)
        return rec

    def recv(self):
        header = self.read(4)
        ct = self.read(int.from_bytes(header, "big"))
        nonce = b"\x00\x00\x00\x00" + self.recvd.to_bytes(8, "big")
        body = ChaCha20Poly1305(self.recv_key).decrypt(nonce, ct, header)
        self.recvd += 1
        return body[0], body[1:]

    def call(self, rid: int, action: str, target: str, args: dict) -> dict:
        self.send(json.dumps({"t": "req", "id": rid, "action": action, "target": target, "args": args},
                             separators=(",", ":")).encode())
        kind, payload = self.recv()
        assert kind == 0
        return json.loads(payload)


class TestTheVectorsInTheDocument(unittest.TestCase):
    def test_the_clean_room_implementation_reproduces_every_vector_from_the_inputs(self):
        a, b = socket.socketpair()
        init = SpecPeer(a, SEED_I, EPH_I, NONCE_I, True)
        resp = SpecPeer(b, SEED_R, EPH_R, NONCE_R, False)
        t = threading.Thread(target=resp.handshake)
        t.start()
        init.handshake()
        t.join(10)
        self.assertEqual(raw_pub(init.idk).hex(), vec("initiator identity public"))
        self.assertEqual(raw_pub(resp.idk).hex(), vec("responder identity public"))
        self.assertEqual(hashlib.sha256(init.id_pub).hexdigest()[:32], vec("initiator device_id"))
        self.assertEqual(hashlib.sha256(resp.id_pub).hexdigest()[:32], vec("responder device_id"))
        self.assertEqual(bytes(init.wire[:80]).hex(), vec("message 1 (I -> R)"))
        self.assertEqual(bytes(resp.wire[:144]).hex(), vec("message 2 (R -> I)"))
        self.assertEqual(bytes(init.wire[80:144]).hex(), vec("message 3 (I -> R)"))
        self.assertEqual((init.code, resp.code), (vec("code (both screens)"),) * 2)
        first = json.loads(re.search(r"^  (\{\"t\":\"req\".*\})$", DOC, re.M).group(1))
        raw = json.dumps(first, separators=(",", ":")).encode()
        self.assertEqual(len(raw), 127)
        self.assertEqual(init.send(raw).hex(), vec("record on the wire"))

    def test_the_real_code_produces_the_same_bytes(self):
        """kos.linkdev with the document's fixed keys must put the document's bytes on the wire."""
        who = threading.local()
        eph = {"init": EPH_I, "resp": EPH_R}
        nonce = {"init": NONCE_I, "resp": NONCE_R}
        ident_i, ident_r = linkdev.Identity(SEED_I, "laptop", "linux"), linkdev.Identity(SEED_R, "phone", "android")

        class Tap:
            def __init__(self, s):
                self.s, self.sent = s, bytearray()

            def sendall(self, b):
                self.sent += b
                self.s.sendall(b)

            def __getattr__(self, n):
                return getattr(self.s, n)

        a, b = socket.socketpair()
        ta, tb = Tap(a), Tap(b)
        out = {}

        def side(tag, ident, sock, initiator):
            who.tag = tag
            out[tag] = linkdev.handshake(sock, ident, initiator)

        def gen():
            return X25519PrivateKey.from_private_bytes(eph[who.tag])

        def rnd(n):
            return nonce[who.tag]
        with mock.patch.object(linkdev.X25519PrivateKey, "generate", side_effect=gen), \
                mock.patch.object(linkdev.os, "urandom", side_effect=rnd):
            ts = [threading.Thread(target=side, args=("init", ident_i, ta, True)),
                  threading.Thread(target=side, args=("resp", ident_r, tb, False))]
            [t.start() for t in ts]
            [t.join(10) for t in ts]
        self.assertEqual(bytes(ta.sent[:80]).hex(), vec("message 1 (I -> R)"))
        self.assertEqual(bytes(tb.sent[:144]).hex(), vec("message 2 (R -> I)"))
        self.assertEqual(bytes(ta.sent[80:144]).hex(), vec("message 3 (I -> R)"))
        self.assertEqual((out["init"].sas, out["resp"].sas), (vec("code (both screens)"),) * 2)
        mark = len(ta.sent)
        linkdev.send_msg(out["init"].channel, json.loads(re.search(r"^  (\{\"t\":\"req\".*\})$", DOC, re.M).group(1)))
        self.assertEqual(bytes(ta.sent[mark:]).hex(), vec("record on the wire"))


class TestTheListsInTheDocumentAreTheCodesLists(unittest.TestCase):
    def test_actions_that_are_never_remote(self):
        self.assertEqual(doc_set("auth.change"), set(linkdev.NEVER_REMOTE))

    def test_actions_that_ask_every_time(self):
        from kos.auth import ACTIONS
        listed = doc_set("file.write")
        self.assertEqual(listed, set(linkdev.ASK_EVERY_TIME_EXTRA))
        app_family = {a for a in ACTIONS if a.startswith("app.") and a != "app.list"}
        self.assertEqual(set(linkdev.ASK_EVERY_TIME), listed | app_family)
        self.assertIn("every action whose name starts with `app.`\nexcept `app.list`", DOC)
        self.assertNotIn("app.list", set(linkdev.ASK_EVERY_TIME))

    def test_platforms_and_numbers(self):
        self.assertIn("`" + "`, `".join(linkdev.PLATFORMS) + "`", DOC)
        self.assertEqual(syncer.CHUNK, 196_608)
        self.assertIn("196 608 bytes", DOC)
        self.assertEqual(syncer.PAGE, 1500)
        self.assertIn("1 to 1500", DOC)
        self.assertEqual((syncer.MAX_FILES, syncer.MAX_FILE), (100_000, 1 << 30))
        self.assertEqual((portable.MAX_PATH, portable.MAX_COMPONENT, portable.MAX_DEPTH), (1024, 255, 64))
        self.assertEqual(syncer.TRASH_KEEP, 1000)
        self.assertEqual((migrate.KDF_N, migrate.KDF_N_MIN, migrate.KDF_N_MAX), (2 ** 15, 2 ** 10, 2 ** 17))
        self.assertEqual((migrate.MIN_PASSPHRASE, migrate.CHUNK), (12, 196_608))
        self.assertRegex(DOC, r"3 DATA\s+at most 196608 bytes")                   # the bundle's chunk is the sync chunk
        self.assertEqual(linkdev.HANDSHAKE_TIMEOUT, 15)
        self.assertEqual(linkdev.MAX_NAME, 40)
        self.assertEqual(migrate.HEADER.size, 36)

    def test_the_paths_the_document_says_are_refused_are_refused(self):
        for bad in ("", "a/../b", "/x", "C:/x", "a:b", "a\\b", "a//b", ".kos-x", "a/.kos-x", "x" * 256, "a/" * 65 + "b"):
            with self.assertRaises(portable.PathRefused, msg=bad):
                portable.safe_relative(bad)


class TestACleanRoomClientAgainstTheRealServer(unittest.TestCase):
    def setUp(self):
        self.server = Device(self, "phone", PW_B, "android")
        self.server.make_identity()
        self.client_id = Ed25519PrivateKey.from_private_bytes(SEED_I)
        pub = raw_pub(self.client_id)
        linkdev.LinkStore(self.server.paths).add(self.server.key(), linkdev.Peer(
            linkdev.device_id(pub), "spec-client", "ios", pub.hex(), "all", 1_700_000_000))

    def start(self, handlers, answers):
        a, b = socket.socketpair()
        done = {}
        t = threading.Thread(target=lambda: done.update(n=linkdev.serve_socket(
            self.server.paths, self.server.authority(*answers), self.server.identity, b, handlers)))
        t.start()
        return SpecPeer(a, SEED_I, EPH_I, NONCE_I, True, expect=self.server.identity.public), t, done

    def test_handshake_request_answer_close(self):
        client, t, done = self.start({"file.view": lambda args: {"echo": args["v"]}}, [PW_B, PW_B])
        client.handshake()
        r = client.call(1, "file.view", "notes", {"v": 7})
        self.assertEqual(r, {"t": "res", "id": 1, "ok": True, "detail": "", "data": {"echo": 7}})
        r = client.call(2, "auth.change", "", {})
        self.assertEqual((r["ok"], "never ask" in r["detail"]), (False, True))
        client.send(b"", kind=1)                                              # CLOSE, as the document says
        t.join(10)
        self.assertEqual(done["n"], 1)

    def test_the_owner_of_the_server_was_asked_with_the_target_the_client_chose(self):
        client, t, done = self.start({"file.view": lambda args: {}}, [PW_B, PW_B])
        client.handshake()
        client.call(1, "file.view", "space docs", {})
        client.send(b"", kind=1)
        t.join(10)
        self.assertTrue(any("spec-client" in q and "space docs" in q for q in self.server.prompter.asked),
                        self.server.prompter.asked)

    def test_a_device_that_is_not_linked_is_closed_on_before_it_is_answered(self):
        stranger = Ed25519PrivateKey.generate()
        a, b = socket.socketpair()
        res = {}

        def serve():
            try:
                linkdev.serve_socket(self.server.paths, self.server.authority(PW_B), self.server.identity, b, {})
            except linkdev.LinkError as e:
                res["err"] = str(e)
        t = threading.Thread(target=serve)
        t.start()
        eph = X25519PrivateKey.generate()
        a.sendall(raw_pub(eph) + raw_pub(stranger) + b"\x00" * 16)
        t.join(10)
        self.assertIn("not linked", res["err"])
        self.assertEqual(a.recv(1), b"")                                     # closed, nothing sent back


if __name__ == "__main__":
    unittest.main()
