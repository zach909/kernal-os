"""KOS-SILENT/1: it must grant nothing, tell nothing and refuse every way of tampering."""

import ast
import json
import os
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import crypt, silent  # noqa: E402
from kos.silent import (CELL_CAP, CELL_LEN, CLOSE, CONFIRM, END, FAILED, HS_LEN, MAX_MESSAGE,  # noqa: E402
                        MORE, SilentChannel, SilentError, session_keys)

KEY = bytes(range(32))
OTHER = bytes(range(1, 33))


class Tap:
    """Sits on the wire between initiator and responder and records every byte."""

    def __init__(self):
        self.a, a2 = socket.socketpair()
        b2, self.b = socket.socketpair()
        self.up = bytearray()      # initiator -> responder
        self.down = bytearray()    # responder -> initiator
        self._socks = [self.a, a2, b2, self.b]
        for src, dst, log in ((a2, b2, self.up), (b2, a2, self.down)):
            threading.Thread(target=self._pump, args=(src, dst, log), daemon=True).start()

    @staticmethod
    def _pump(src, dst, log):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                log += chunk
                dst.sendall(chunk)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


def connect(a, b, k1=KEY, k2=KEY):
    """Run both ends; returns (initiator or exception, responder or exception)."""
    out = {}

    def far():
        try:
            out["r"] = SilentChannel(b, k2, False)
        except Exception as e:      # noqa: BLE001 - the test inspects it
            out["r"] = e
    t = threading.Thread(target=far)
    t.start()
    try:
        near = SilentChannel(a, k1, True)
    except Exception as e:          # noqa: BLE001
        near = e
    t.join()
    return near, out["r"]


class Base(unittest.TestCase):
    def pair(self, k1=KEY, k2=KEY):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        c, r = connect(a, b, k1, k2)
        self.assertIsInstance(c, SilentChannel)
        self.assertIsInstance(r, SilentChannel)
        return c, r, a, b

    def tapped(self, k1=KEY, k2=KEY):
        tap = Tap()
        self.addCleanup(tap.close)
        c, r = connect(tap.a, tap.b, k1, k2)
        return tap, c, r


class TestWorks(Base):
    def test_messages_of_every_size_both_ways(self):
        c, r, *_ = self.pair()
        for n in (0, 1, 2, CELL_CAP - 1, CELL_CAP, CELL_CAP + 1, 2 * CELL_CAP, 5000, 70000):
            m = bytes((i * 7 + n) % 256 for i in range(n))
            c.send(m)
            self.assertEqual(r.recv(), m)
            r.send(m[::-1])
            self.assertEqual(c.recv(), m[::-1])

    def test_the_biggest_message_and_one_more(self):
        c, r, *_ = self.pair()
        big = bytes(MAX_MESSAGE)
        t = threading.Thread(target=c.send, args=(big,))
        t.start()
        self.assertEqual(r.recv(), big)
        t.join()
        with self.assertRaises(SilentError):
            c.send(bytes(MAX_MESSAGE + 1))

    def test_close_is_told_from_a_cut(self):
        c, r, *_ = self.pair()
        c.send(b"last")
        c.close()
        self.assertEqual(r.recv(), b"last")
        self.assertIsNone(r.recv())
        self.assertIsNone(r.recv())

    def test_two_connections_do_not_share_keys(self):
        t1, c1, r1 = self.tapped()
        t2, c2, r2 = self.tapped()
        c1.send(b"same")
        c2.send(b"same")
        r1.recv()
        r2.recv()
        self.assertNotEqual(bytes(t1.up), bytes(t2.up))

    def test_the_old_secret_key_does_not_open_a_recorded_connection(self):
        """Forward secrecy: the password key alone cannot rebuild the keys of a recorded connection."""
        t, c, r = self.tapped()
        c.send(b"private" * 10)
        r.recv()
        wire = bytes(t.up)
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        guess = ChaCha20Poly1305(session_keys(KEY, bytes(32), bytes(32), wire[:HS_LEN],
                                              bytes(t.down)[:HS_LEN], True)[0])
        with self.assertRaises(Exception):
            guess.decrypt(crypt.nonce_for(1), wire[HS_LEN + CELL_LEN:HS_LEN + 2 * CELL_LEN], b"")


class TestGivesNothingAway(Base):
    def test_both_handshake_messages_and_every_record_have_one_size(self):
        t, c, r = self.tapped()
        self.assertEqual(len(t.up), HS_LEN + CELL_LEN)       # first message + confirm
        self.assertEqual(len(t.down), HS_LEN + CELL_LEN)     # answer + confirm
        for n in (0, 1, 500, CELL_CAP):
            before = len(t.up)
            c.send(b"x" * n)
            r.recv()
            self.assertEqual(len(t.up) - before, CELL_LEN, n)    # 0 and 1021 bytes look alike
        before = len(t.up)
        c.send(b"x" * (CELL_CAP + 1))
        r.recv()
        self.assertEqual(len(t.up) - before, 2 * CELL_LEN)

    def test_nothing_readable_on_the_wire(self):
        marker = b"SECRET-MARKER-" * 20
        keys = {}
        real = silent.MLKEM768PrivateKey

        class Rec:
            @staticmethod
            def generate():
                keys["k"] = real.generate()
                return keys["k"]
        with mock.patch.object(silent, "MLKEM768PrivateKey", Rec):
            t, c, r = self.tapped()
        c.send(marker)
        r.recv()
        wire = bytes(t.up) + bytes(t.down)
        ek = keys["k"].public_key().public_bytes_raw()
        self.assertNotIn(marker[:14], wire)
        self.assertNotIn(ek[:32], wire)
        self.assertNotIn(ek[-32:], wire)
        for word in (b"KOS", b"kos", b"SILENT", b"silent", b"v1", b"HTTP", b"TLS"):
            self.assertNotIn(word, bytes(t.up)[:HS_LEN] + bytes(t.down)[:HS_LEN])

    def test_a_handshake_looks_like_random_bytes(self):
        ups = []
        for _ in range(20):
            t, c, r = self.tapped()
            ups.append(bytes(t.up))
            c.close()
        # no byte position is the same in every run (no fixed header, tag or magic number)
        for pos in range(64):
            self.assertGreater(len({u[pos] for u in ups}), 1, pos)
        self.assertEqual(len({u[:16] for u in ups}), 20)
        # about half the bits are ones (within 1 point), over ~25,000 bytes
        data = b"".join(ups)
        ones = sum(bin(x).count("1") for x in data)
        total = len(data) * 8
        self.assertLess(abs(ones * 100 - total * 50), total)

    def test_a_peer_without_the_secret_gets_nothing_back(self):
        tap, c, r = self.tapped(OTHER, KEY)
        self.assertIsInstance(c, SilentError)
        self.assertIsInstance(r, SilentError)
        self.assertEqual(len(tap.down), 0)                  # the listener never said a word

    def test_garbage_truncation_and_silence_get_nothing_back_and_one_message(self):
        messages = set()
        cases = {"garbage": b"\x17" * HS_LEN, "short": b"\x01" * 100, "empty": b""}
        for name, data in cases.items():
            a, b = socket.socketpair()
            self.addCleanup(a.close)
            self.addCleanup(b.close)
            a.sendall(data)
            a.shutdown(socket.SHUT_WR)
            with self.assertRaises(SilentError) as ctx:
                SilentChannel(b, KEY, False)
            messages.add(str(ctx.exception))
            self.assertEqual(a.recv(10), b"", name)         # closed, nothing sent
        a, b = socket.socketpair()                          # a peer that connects and says nothing
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with mock.patch.object(silent, "HANDSHAKE_SECONDS", 1):
            with self.assertRaises(SilentError) as ctx:
                SilentChannel(b, KEY, False)
        messages.add(str(ctx.exception))
        self.assertEqual(a.recv(10), b"")
        self.assertEqual(messages, {FAILED})

    def test_a_replayed_first_message_gets_nothing_back(self):
        t, c, r = self.tapped()
        first = bytes(t.up)[:HS_LEN]
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.sendall(first)
        with self.assertRaises(SilentError) as ctx:
            SilentChannel(b, KEY, False)
        self.assertEqual(str(ctx.exception), FAILED)
        a.settimeout(2)
        self.assertEqual(a.recv(10), b"")

    def test_every_handshake_failure_is_the_same_message(self):
        _, c, r = self.tapped(OTHER, KEY)
        self.assertEqual({str(c), str(r)}, {FAILED})

    def test_a_classical_only_peer_cannot_connect(self):
        """No downgrade: the older X25519-only channel cannot talk to this one."""
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(5)
        res = {}

        def old():
            try:
                crypt.SecureChannel(a, KEY, True)
            except crypt.CryptError as e:
                res["old"] = e
        t = threading.Thread(target=old)
        t.start()
        with mock.patch.object(silent, "HANDSHAKE_SECONDS", 1):
            with self.assertRaises(SilentError):
                SilentChannel(b, KEY, False)
        t.join()
        self.assertIn("old", res)


class TestQuantumResistance(unittest.TestCase):
    def setUp(self):
        self.args = (KEY, bytes([1]) * 32, bytes([2]) * 32, b"m1" * 10, b"m2" * 10)

    def test_every_input_changes_every_key(self):
        base = session_keys(*self.args, True)
        variants = [(OTHER,) + self.args[1:],
                    (KEY, bytes([9]) * 32) + self.args[2:],              # the X25519 secret
                    self.args[:2] + (bytes([9]) * 32,) + self.args[3:],  # the ML-KEM secret
                    self.args[:3] + (b"xx",) + self.args[4:],
                    self.args[:4] + (b"xx",)]
        for v in variants:
            other = session_keys(*v, True)
            self.assertNotEqual(base[0], other[0])
            self.assertNotEqual(base[1], other[1])

    def test_the_two_ends_agree_and_the_directions_differ(self):
        i = session_keys(*self.args, True)
        r = session_keys(*self.args, False)
        self.assertEqual(i, (r[1], r[0]))
        self.assertNotEqual(i[0], i[1])

    def test_a_wrong_ml_kem_secret_breaks_the_connection(self):
        """If ML-KEM did not feed the keys, tampering with it would not matter. It must."""
        real = silent.MLKEM768PublicKey

        class Liar:
            @staticmethod
            def from_public_bytes(ek):
                pub = real.from_public_bytes(ek)

                class Wrapped:
                    @staticmethod
                    def encapsulate():
                        _, ct = pub.encapsulate()
                        return bytes(32), ct          # a secret that does not match the ciphertext
                return Wrapped()
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with mock.patch.object(silent, "MLKEM768PublicKey", Liar):
            c, r = connect(a, b)
        self.assertIsInstance(c, SilentError)
        self.assertIsInstance(r, SilentError)

    def test_a_wrong_x25519_secret_breaks_the_connection(self):
        real = silent.X25519PrivateKey

        class Wrapped:
            def __init__(self):
                self._k = real.generate()

            def public_key(self):
                return self._k.public_key()

            def exchange(self, peer):
                return os.urandom(32)                # each end gets a different secret

        class Liar:
            @staticmethod
            def generate():
                return Wrapped()
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with mock.patch.object(silent, "X25519PrivateKey", Liar):
            c, r = connect(a, b)
        self.assertIsInstance(c, SilentError)
        self.assertIsInstance(r, SilentError)

    def test_the_suite_is_the_hybrid_and_nothing_weaker(self):
        self.assertEqual((silent.EK_LEN, silent.CT_LEN), (1184, 1088))    # ML-KEM-768 (FIPS 203)
        self.assertEqual(silent.KEY_LEN, 32)                              # 256-bit keys
        src = (ROOT / "kos" / "silent.py").read_text()
        self.assertIn("MLKEM768", src)
        self.assertIn("X25519", src)
        for weak in ("RSA", "DiffieHellman", "ECDH(", "MD5", "SHA1()", "AES128", "RC4", "ECB"):
            self.assertNotIn(weak, src)


class TestRecords(Base):
    """Every way of changing what is on the wire kills the channel."""

    def dead_after(self, ch, wire_sock, data):
        wire_sock.sendall(data)
        with self.assertRaises(SilentError):
            ch.recv()
        with self.assertRaises(SilentError):
            ch.recv()
        with self.assertRaises(SilentError):
            ch.send(b"x")

    def test_tampering(self):
        c, r, a, b = self.pair()
        cell = bytearray(c._cell(END, b"hello"))
        cell[100] ^= 1
        self.dead_after(r, a, bytes(cell))

    def test_replay(self):
        c, r, a, b = self.pair()
        cell = c._cell(END, b"pay 5")
        a.sendall(cell)
        self.assertEqual(r.recv(), b"pay 5")
        self.dead_after(r, a, cell)

    def test_reordering(self):
        c, r, a, b = self.pair()
        c._cell(END, b"1")
        second = c._cell(END, b"2")
        self.dead_after(r, a, second)                 # the first never arrived, or came later

    def test_dropping(self):
        c, r, a, b = self.pair()
        c.send(b"one")
        self.assertEqual(r.recv(), b"one")
        c._cell(END, b"dropped")
        self.dead_after(r, a, c._cell(END, b"three"))

    def test_reflection(self):
        c, r, a, b = self.pair()
        self.dead_after(c, b, c._cell(END, b"mine"))  # my own record sent back to me

    def test_a_cut_in_the_middle_of_a_record(self):
        c, r, a, b = self.pair()
        a.sendall(c._cell(END, b"x")[:500])
        a.shutdown(socket.SHUT_WR)
        with self.assertRaises(SilentError):
            r.recv()

    def test_a_cut_with_no_goodbye_is_not_a_finish(self):
        c, r, a, b = self.pair()
        c.send(b"hello")
        a.shutdown(socket.SHUT_WR)
        self.assertEqual(r.recv(), b"hello")
        with self.assertRaises(SilentError):
            r.recv()

    def test_unknown_record_types_kill_the_channel(self):
        """There is no record that carries a permission, a name or a request: only data and goodbye."""
        for kind in (4, 5, 9, 127, 255):
            c, r, a, b = self.pair()
            self.dead_after(r, a, c._cell(kind, b'{"grant":"system"}'))

    def test_a_confirm_in_the_middle_of_a_stream_is_refused(self):
        c, r, a, b = self.pair()
        self.dead_after(r, a, c._cell(CONFIRM, b""))

    def test_a_goodbye_in_the_middle_of_a_message_is_refused(self):
        c, r, a, b = self.pair()
        a.sendall(c._cell(MORE, b"half") + c._cell(CLOSE, b""))
        with self.assertRaises(SilentError):
            r.recv()

    def test_nonzero_padding_is_refused(self):
        c, r, a, b = self.pair()
        plain = bytes([END]) + (1).to_bytes(2, "big") + b"x" + b"\x01" * (CELL_CAP - 1)
        sealed = c._send.encrypt(crypt.nonce_for(c._send_n), plain, b"")
        self.dead_after(r, a, sealed)

    def test_a_length_longer_than_a_record_is_refused(self):
        c, r, a, b = self.pair()
        plain = bytes([END]) + (CELL_CAP + 1).to_bytes(2, "big") + bytes(CELL_CAP)
        sealed = c._send.encrypt(crypt.nonce_for(c._send_n), plain, b"")
        self.dead_after(r, a, sealed)

    def test_a_message_over_the_limit_is_refused_while_it_arrives(self):
        c, r, a, b = self.pair()
        wire = b"".join(c._cell(MORE, bytes(CELL_CAP)) for _ in range(MAX_MESSAGE // CELL_CAP + 2))
        t = threading.Thread(target=lambda: a.sendall(wire), daemon=True)
        t.start()
        with self.assertRaises(SilentError):
            r.recv()
        b.close()
        t.join(5)

    def test_a_used_up_counter_stops_sending(self):
        c, r, a, b = self.pair()
        c._send_n = (1 << 64) - 1
        with self.assertRaises(crypt.CryptError):
            c.send(b"x")
        with self.assertRaises(crypt.CryptError):
            c.send(b"x")

    def test_a_wrong_key_on_one_side_fails_the_first_record_not_later(self):
        # the confirm records prove the keys at connect time, so a bad connection never gets this far
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        c, r = connect(a, b, KEY, OTHER)
        self.assertIsInstance(c, SilentError)
        self.assertIsInstance(r, SilentError)

    def test_secret_must_be_32_bytes(self):
        for bad in (b"", b"short", bytes(31), bytes(33), "x" * 32, None):
            a, b = socket.socketpair()
            self.addCleanup(a.close)
            self.addCleanup(b.close)
            with self.assertRaises(SilentError):
                SilentChannel(a, bad, True)


class TestGrantsNothing(unittest.TestCase):
    """The channel is a pipe: it gives no authority to what comes through it, or to anything else."""

    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((ROOT / "kos" / "silent.py").read_text())

    def test_it_imports_nothing_that_decides_anything(self):
        mods = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add(("." * node.level) + (node.module or "").split(".")[0])
        allowed = {"__future__", "hashlib", "os", "socket", "threading", "collections", "typing",
                   "cryptography", ".crypt"}
        self.assertEqual(mods - allowed, set())

    def test_it_never_opens_or_names_a_connection(self):
        names = {n.attr for n in ast.walk(self.tree) if isinstance(n, ast.Attribute)}
        for forbidden in ("connect", "connect_ex", "bind", "listen", "accept", "getpeername",
                          "getsockname", "gethostbyname", "getaddrinfo", "create_connection",
                          "socketpair", "setsockopt", "system", "popen", "environ"):
            self.assertNotIn(forbidden, names)
        calls = {n.func.id for n in ast.walk(self.tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        for forbidden in ("open", "eval", "exec", "compile", "__import__"):
            self.assertNotIn(forbidden, calls)

    def test_the_whole_interface_is_send_recv_close(self):
        self.assertEqual(sorted(n for n in dir(SilentChannel) if not n.startswith("_")),
                         ["close", "recv", "send"])
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        c, r = connect(a, b)
        for ch in (c, r):
            self.assertEqual([n for n in vars(ch) if not n.startswith("_")], [])   # no peer name, id or address

    def test_text_that_looks_like_a_grant_is_just_bytes(self):
        c, r = connect(*socket.socketpair())
        self.addCleanup(c._die)
        self.addCleanup(r._die)
        hostile = json.dumps({"cmd": "request", "action": "open", "permissions": ["system", "network"],
                              "authorized": True, "password": "x"}).encode()
        c.send(hostile)
        got = r.recv()
        self.assertEqual(got, hostile)             # delivered as inert bytes; nothing was decided
        self.assertIsInstance(got, bytes)

    def test_authorisation_does_not_depend_on_the_channel(self):
        src = (ROOT / "kos" / "auth.py").read_text()
        self.assertNotIn("silent", src)            # the password path knows nothing of this protocol


if __name__ == "__main__":
    unittest.main()
