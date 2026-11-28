"""The encrypted channel: it must refuse every way of tampering, not just work."""

import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

from kos import crypt  # noqa: E402
from kos.crypt import CryptError, SecureChannel  # noqa: E402

KEY = bytes(range(32))


def pair(k1=KEY, k2=KEY):
    a, b = socket.socketpair()
    out = {}

    def far():
        try:
            out["c"] = SecureChannel(b, k2, False)
        except CryptError as e:
            out["e"] = e
    t = threading.Thread(target=far)
    t.start()
    near = SecureChannel(a, k1, True)
    t.join()
    return near, out["c"], a, b


class Spy:
    """Sits between two sockets, can change what passes."""

    def __init__(self):
        self.a_in, self.a_out = socket.socketpair()   # client <-> spy
        self.b_in, self.b_out = socket.socketpair()   # spy <-> server

    def forward_handshake(self):
        self.b_in.sendall(self._read(self.a_in, 32))
        self.a_in.sendall(self._read(self.b_in, 32))

    @staticmethod
    def _read(s, n):
        buf = b""
        while len(buf) < n:
            buf += s.recv(n - len(buf))
        return buf

    def record(self, src):
        h = self._read(src, 4)
        return h, self._read(src, struct.unpack(">I", h)[0])


def spied(k1=KEY, k2=KEY):
    spy = Spy()
    out = {}
    t1 = threading.Thread(target=lambda: out.setdefault("c", SecureChannel(spy.a_out, k1, True)))
    t2 = threading.Thread(target=lambda: out.setdefault("s", SecureChannel(spy.b_out, k2, False)))
    t1.start(); t2.start()
    spy.forward_handshake()
    t1.join(); t2.join()
    return spy, out["c"], out["s"]


class TestKnownAnswers(unittest.TestCase):
    """The library gives the published answers (RFC 7748 section 6.1, RFC 8439 section 2.8.2)."""

    def test_x25519_rfc7748(self):
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        want = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        got = X25519PrivateKey.from_private_bytes(a).exchange(X25519PublicKey.from_public_bytes(b_pub))
        self.assertEqual(got, want)

    def test_chacha20poly1305_rfc8439(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
              b"for the future, sunscreen would be it.")
        out = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        self.assertEqual(out[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")


class TestChannel(unittest.TestCase):
    def test_messages_arrive_in_order_both_ways(self):
        c, s, *_ = pair()
        for i in range(50):
            c.send(b"to-server-%d" % i)
            s.send(b"to-client-%d" % i)
        for i in range(50):
            self.assertEqual(s.recv(), b"to-server-%d" % i)
            self.assertEqual(c.recv(), b"to-client-%d" % i)

    def test_nothing_readable_on_the_wire(self):
        spy, c, s = spied()
        c.send(b"top secret password hunter2")
        _, blob = spy.record(spy.a_in)
        self.assertNotIn(b"hunter2", blob)
        self.assertEqual(len(blob), 1 + len(b"top secret password hunter2") + 16)

    def test_two_connections_get_different_keys(self):
        spy1, ca, _ = spied()
        spy2, cb, _ = spied()
        ca.send(b"same"); cb.send(b"same")
        self.assertNotEqual(spy1.record(spy1.a_in), spy2.record(spy2.a_in))

    def test_wrong_password_key_is_refused(self):
        spy, c, s = spied(KEY, bytes(32))
        c.send(b"hello")
        h, blob = spy.record(spy.a_in)
        spy.b_in.sendall(h + blob)
        with self.assertRaises(CryptError):
            s.recv()

    def test_flipped_bit_is_refused_and_the_channel_dies(self):
        spy, c, s = spied()
        c.send(b"pay 10")
        h, blob = spy.record(spy.a_in)
        bad = bytearray(blob); bad[2] ^= 1
        spy.b_in.sendall(h + bytes(bad))
        with self.assertRaises(CryptError):
            s.recv()
        with self.assertRaises(CryptError):
            s.recv()           # dead for good, never recovers

    def test_changed_length_header_is_refused(self):
        # the header is authenticated: a header that is still valid but was changed is refused
        spy, c, s = spied()
        c.send(b"x" * 8)
        h, blob = spy.record(spy.a_in)
        spy.b_in.sendall(struct.pack(">I", len(blob) + 1) + blob + b"\x00")
        with self.assertRaises(CryptError):
            s.recv()

    def test_replayed_record_is_refused(self):
        spy, c, s = spied()
        c.send(b"once")
        rec = b"".join(spy.record(spy.a_in))
        spy.b_in.sendall(rec)
        self.assertEqual(s.recv(), b"once")
        spy.b_in.sendall(rec)
        with self.assertRaises(CryptError):
            s.recv()

    def test_reordered_records_are_refused(self):
        spy, c, s = spied()
        c.send(b"one"); c.send(b"two")
        r1 = b"".join(spy.record(spy.a_in)); r2 = b"".join(spy.record(spy.a_in))
        spy.b_in.sendall(r2 + r1)
        with self.assertRaises(CryptError):
            s.recv()

    def test_dropped_record_is_refused(self):
        spy, c, s = spied()
        c.send(b"one"); c.send(b"two")
        spy.record(spy.a_in)
        spy.b_in.sendall(b"".join(spy.record(spy.a_in)))
        with self.assertRaises(CryptError):
            s.recv()

    def test_a_record_cannot_be_reflected_back_at_its_sender(self):
        spy, c, s = spied()
        c.send(b"mine")
        rec = b"".join(spy.record(spy.a_in))
        spy.a_in.sendall(rec)          # bounce it back to the client
        with self.assertRaises(CryptError):
            c.recv()

    def test_cut_connection_is_not_mistaken_for_a_clean_close(self):
        spy, c, s = spied()
        c.send(b"partial")
        spy.b_in.sendall(b"".join(spy.record(spy.a_in)))
        self.assertEqual(s.recv(), b"partial")
        spy.b_in.close()
        with self.assertRaises(CryptError):
            s.recv()

    def test_clean_close_is_told_apart(self):
        c, s, *_ = pair()
        c.send(b"last")
        c.close()
        self.assertEqual(s.recv(), b"last")
        self.assertIsNone(s.recv())
        self.assertIsNone(s.recv())

    def test_truncated_close_is_refused(self):
        spy, c, s = spied()
        c.close()
        h, blob = spy.record(spy.a_in)
        spy.b_in.sendall(h + blob[:-3])
        spy.b_in.close()
        with self.assertRaises(CryptError):
            s.recv()

    def test_hostile_headers(self):
        for n in (0, crypt.MAX_RECORD + 1, 0xFFFFFFFF):
            spy, c, s = spied()
            spy.b_in.sendall(struct.pack(">I", n))
            with self.assertRaises(CryptError):
                s.recv()

    def test_oversize_message_refused_before_sending(self):
        c, s, *_ = pair()
        with self.assertRaises(CryptError):
            c.send(b"x" * (crypt.MAX_PLAIN + 1))
        t = threading.Thread(target=c.send, args=(b"x" * crypt.MAX_PLAIN,))   # bigger than the socket buffer
        t.start()
        self.assertEqual(len(s.recv()), crypt.MAX_PLAIN)
        t.join()

    def test_secret_must_be_32_bytes(self):
        a, b = socket.socketpair()
        with self.assertRaises(CryptError):
            crypt.derive_keys(b"short", b"a" * 32, b"b" * 32, b"c" * 32, True)

    def test_a_bad_peer_key_is_refused(self):
        a, b = socket.socketpair()
        b.sendall(bytes(32))                     # all-zero point: shared secret is all zeros
        with self.assertRaises(CryptError):
            SecureChannel(a, KEY, True)

    def test_counter_use_up_is_refused(self):
        c, s, *_ = pair()
        c._send_n = crypt.COUNTER_LIMIT
        with self.assertRaises(CryptError):
            c.send(b"x")

    def test_nonce_and_keys(self):
        self.assertNotEqual(crypt.nonce_for(1), crypt.nonce_for(2))
        k = crypt.derive_keys(KEY, b"a" * 32, b"b" * 32, b"c" * 32, True)
        r = crypt.derive_keys(KEY, b"b" * 32, b"a" * 32, b"c" * 32, False)
        self.assertEqual(k[0], r[1]); self.assertEqual(k[1], r[0])   # they agree
        self.assertNotEqual(k[0], k[1])                               # one key per direction


if __name__ == "__main__":
    unittest.main()
