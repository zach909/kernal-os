"""Linked devices (kos/linkdev.py): pairing, the pinned-key handshake, scope, and both-ends authorization.

Each allowance sits next to the refusal that proves the rule: a stranger, a man in the middle, a wrong
password, a paused link, an action that would let one device take over the other, a peer that sends junk.
Two devices here are two separate KOS roots, each with its own password, run over a real socket pair."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos import crypt, firewall, guard, linkdev  # noqa: E402
from kos.auth import AuditLog, Authority, AuthorizationDenied, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402

PW_A, PW_B = "alpha correct horse", "bravo battery staple"


class Device:
    """One KOS machine: its own root, password and (once created) identity."""

    def __init__(self, test: unittest.TestCase, name: str, pw: str, platform: str = "linux"):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        self.pw, self.name, self.platform = pw, name, platform
        PasswordStore(self.paths).create(pw.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.identity = None
        self.prompters = []

    def authority(self, *answers) -> Authority:
        self.prompter = ScriptedPrompter(answers)
        self.prompters.append(self.prompter)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def make_identity(self) -> linkdev.Identity:
        with self.authority(self.pw).authorize("link.identity") as g:
            self.identity = linkdev.Identity.create(self.paths, g, self.name, self.platform)
        return self.identity

    def key(self, label="link-store") -> bytes:
        with self.authority(self.pw).authorize("link.list") as g:
            return g.key(label)

    def peers(self):
        return linkdev.LinkStore(self.paths).peers(self.key())

    def audit(self, n=50):
        return AuditLog(self.paths).tail(n)


def run_pair(test, a: Device, b: Device, a_answers, b_answers):
    """Pair a and b over a socket pair. Returns (offer_a, offer_b, result_a, result_b)."""
    sa, sb = socket.socketpair()
    out = {}

    def side(tag, dev, sock, initiator, answers, accept):
        try:
            offer = linkdev.start_pairing(sock, dev.identity, initiator)
            out[tag + "_offer"] = offer
            out[tag] = linkdev.finish_pairing(dev.paths, dev.authority(*answers), offer, accept)
        except Exception as e:      # the test reads it; a thread must not die silently
            out[tag + "_err"] = e

    ta = threading.Thread(target=side, args=("a", a, sa, True, a_answers, True))
    tb = threading.Thread(target=side, args=("b", b, sb, False, b_answers, True))
    ta.start(), tb.start()
    ta.join(20), tb.join(20)
    test.assertFalse(ta.is_alive() or tb.is_alive(), "pairing hung")
    return out


class TestIdentity(unittest.TestCase):
    def test_the_identity_is_sealed_under_the_password_and_wrong_password_cannot_open_it(self):
        a = Device(self, "laptop", PW_A)
        ident = a.make_identity()
        raw = (a.paths.state / "links" / "identity.bin").read_bytes()
        self.assertNotIn(ident._seed, raw)                       # the key is not on disk in the clear
        with a.authority(PW_A).authorize("link.identity") as g:
            self.assertEqual(linkdev.Identity.load(a.paths, g).device_id, ident.device_id)
        # a grant made under a different password derives a different key: the blob will not open
        other = Device(self, "other", PW_B)
        with other.authority(PW_B).authorize("link.identity") as g:
            os.makedirs(other.paths.state / "links", exist_ok=True)
            (other.paths.state / "links" / "identity.bin").write_bytes(raw)
            with self.assertRaises(linkdev.LinkError):
                linkdev.Identity.load(other.paths, g)

    def test_a_second_identity_is_refused_so_one_device_cannot_quietly_become_another(self):
        a = Device(self, "laptop", PW_A)
        a.make_identity()
        with self.assertRaises(linkdev.LinkError):
            a.make_identity()

    def test_a_peer_chosen_name_is_cleaned_and_must_exist(self):
        self.assertEqual(linkdev.clean_label("my\x1b[31m phone‮"), "my[31m phone")
        with self.assertRaises(linkdev.LinkError):
            linkdev.clean_label("\x00\x01")
        with self.assertRaises(linkdev.LinkError):
            linkdev.clean_label(5)


class TestPairing(unittest.TestCase):
    def setUp(self):
        self.a = Device(self, "laptop", PW_A, "linux")
        self.b = Device(self, "phone", PW_B, "android")
        self.a.make_identity(), self.b.make_identity()

    def test_both_screens_show_the_same_code_and_both_owners_type_their_own_password(self):
        out = run_pair(self, self.a, self.b, [PW_A], [PW_B])
        self.assertNotIn("a_err", out), self.assertNotIn("b_err", out)
        self.assertEqual(out["a_offer"].sas, out["b_offer"].sas)
        self.assertRegex(out["a_offer"].sas, r"^\d{6}$")
        pa, pb = self.a.peers(), self.b.peers()
        self.assertEqual([(p.name, p.platform, p.scope) for p in pa], [("phone", "android", "all")])
        self.assertEqual([(p.name, p.platform, p.scope) for p in pb], [("laptop", "linux", "all")])
        self.assertEqual(pa[0].device_id, self.b.identity.device_id)
        for d in (self.a, self.b):                                # each side was asked for its own password
            asked = [q for pr in d.prompters for q in pr.asked if "link another device" in q]
            self.assertEqual(len(asked), 1, d.name)

    def test_one_owner_saying_no_links_nothing_on_either_side(self):
        sa, sb = socket.socketpair()
        out = {}

        def side(tag, dev, sock, init, accept, answers):
            try:
                offer = linkdev.start_pairing(sock, dev.identity, init)
                out[tag] = linkdev.finish_pairing(dev.paths, dev.authority(*answers), offer, accept)
            except Exception as e:
                out[tag + "_err"] = e

        ts = [threading.Thread(target=side, args=("a", self.a, sa, True, True, [PW_A])),
              threading.Thread(target=side, args=("b", self.b, sb, False, False, []))]    # b: "the codes differ"
        [t.start() for t in ts], [t.join(20) for t in ts]
        self.assertIsInstance(out.get("a_err"), linkdev.LinkError)
        self.assertIsInstance(out.get("b_err"), linkdev.LinkError)
        self.assertEqual(self.a.peers(), [])
        self.assertEqual(self.b.peers(), [])

    def test_a_wrong_password_on_one_side_links_nothing(self):
        out = run_pair(self, self.a, self.b, ["nope", "nope", "nope"], [PW_B])
        self.assertIn("a_err", out)
        self.assertEqual(self.a.peers(), [])
        self.assertEqual(self.b.peers(), [])

    def test_a_man_in_the_middle_gets_a_different_code_on_each_side(self):
        """M relays between A and B running a handshake with each. The signatures check out (M has real
        keys), so the *only* thing that catches it is that the two owners see different codes."""
        m = Device(self, "mallory", "mallory long password")
        m_ident = m.make_identity()
        a_end, m_a = socket.socketpair()
        m_b, b_end = socket.socketpair()
        got = {}
        ta = threading.Thread(target=lambda: got.update(a=linkdev.handshake(a_end, self.a.identity, True)))
        tm1 = threading.Thread(target=lambda: got.update(m1=linkdev.handshake(m_a, m_ident, False)))
        tm2 = threading.Thread(target=lambda: got.update(m2=linkdev.handshake(m_b, m_ident, True)))
        tb = threading.Thread(target=lambda: got.update(b=linkdev.handshake(b_end, self.b.identity, False)))
        for t in (ta, tm1, tm2, tb):
            t.start()
        for t in (ta, tm1, tm2, tb):
            t.join(20)
        self.assertNotEqual(got["a"].sas, got["b"].sas)
        self.assertEqual(got["a"].sas, got["m1"].sas)             # what M can do: be a *different* endpoint

    def test_a_device_cannot_pair_with_itself(self):
        sa, sb = socket.socketpair()
        errs = []

        def go(sock, init):
            try:
                linkdev.handshake(sock, self.a.identity, init)
            except linkdev.LinkError as e:
                errs.append(str(e))

        ts = [threading.Thread(target=go, args=(sa, True)), threading.Thread(target=go, args=(sb, False))]
        [t.start() for t in ts], [t.join(20) for t in ts]
        self.assertEqual(len(errs), 2)                              # both ends fail at once, neither waits for a timeout
        self.assertTrue(any("itself" in e for e in errs))

    def test_a_hostile_introduction_is_refused_before_anything_is_shown_to_the_owner(self):
        hostile = [{"t": "hello", "name": "x", "platform": "toaster"},        # a platform KOS does not know
                   {"t": "hello", "name": "\x00\x1b", "platform": "kos"},     # a name that is only control characters
                   {"t": "hello", "name": "x", "platform": "kos", "extra": 1},  # a field that is not in the format
                   {"t": "bye"}]
        for hello in hostile:
            sa, sb = socket.socketpair()

            def peer(sock=sb, msg=hello):
                s = linkdev.handshake(sock, self.b.identity, False)
                linkdev.recv_msg(s.channel)                                   # a's own introduction
                linkdev.send_msg(s.channel, msg)

            t = threading.Thread(target=peer)
            t.start()
            with self.assertRaises(linkdev.LinkError, msg=hello):
                linkdev.start_pairing(sa, self.a.identity, True)
            t.join(20)


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.a = Device(self, "laptop", PW_A)
        self.b = Device(self, "phone", PW_B)
        self.a.make_identity(), self.b.make_identity()

    def shake(self, expect_a=None, expect_b=None):
        sa, sb = socket.socketpair()
        got = {}

        def side(tag, ident, sock, init, expect):
            try:
                got[tag] = linkdev.handshake(sock, ident, init, expect)
            except linkdev.LinkError as e:
                got[tag] = e

        ts = [threading.Thread(target=side, args=("a", self.a.identity, sa, True, expect_a)),
              threading.Thread(target=side, args=("b", self.b.identity, sb, False, expect_b))]
        [t.start() for t in ts], [t.join(20) for t in ts]
        return got

    def test_messages_cross_encrypted_both_ways(self):
        got = self.shake(self.b.identity.public, self.a.identity.public)
        linkdev.send_msg(got["a"].channel, {"hello": "phone"})
        self.assertEqual(linkdev.recv_msg(got["b"].channel), {"hello": "phone"})
        linkdev.send_msg(got["b"].channel, {"n": 7})
        self.assertEqual(linkdev.recv_msg(got["a"].channel), {"n": 7})
        got["a"].channel.close()
        self.assertIsNone(linkdev.recv_msg(got["b"].channel))      # a clean close is told from a cut

    def test_a_pinned_key_that_does_not_match_is_refused(self):
        stranger = Device(self, "stranger", "stranger password")
        stranger.make_identity()
        got = self.shake(expect_a=stranger.identity.public)
        self.assertIsInstance(got["a"], linkdev.LinkError)
        self.assertIn("not the device", str(got["a"]))

    def test_a_tampered_record_kills_the_channel(self):
        sa, sb = socket.socketpair()
        got = {}
        ts = [threading.Thread(target=lambda: got.update(a=linkdev.handshake(sa, self.a.identity, True))),
              threading.Thread(target=lambda: got.update(b=linkdev.handshake(sb, self.b.identity, False)))]
        [t.start() for t in ts], [t.join(20) for t in ts]
        send_key_ch = got["a"].channel
        # build a record, flip one ciphertext bit, deliver it raw
        body = bytes([crypt.DATA]) + b'{"x":1}'
        header = crypt.frame_header(len(body) + crypt.TAG_LEN)
        rec = bytearray(header + send_key_ch._send.encrypt(crypt.nonce_for(0), body, header))
        rec[-1] ^= 1
        sa.sendall(bytes(rec))
        with self.assertRaises(linkdev.LinkError):
            linkdev.recv_msg(got["b"].channel)
        with self.assertRaises(linkdev.LinkError):                 # and it stays dead
            linkdev.recv_msg(got["b"].channel)

    def test_a_replayed_record_is_refused(self):
        sa, sb = socket.socketpair()
        got = {}
        ts = [threading.Thread(target=lambda: got.update(a=linkdev.handshake(sa, self.a.identity, True))),
              threading.Thread(target=lambda: got.update(b=linkdev.handshake(sb, self.b.identity, False)))]
        [t.start() for t in ts], [t.join(20) for t in ts]
        ch = got["a"].channel
        body = bytes([crypt.DATA]) + b'{"x":1}'
        header = crypt.frame_header(len(body) + crypt.TAG_LEN)
        rec = header + ch._send.encrypt(crypt.nonce_for(0), body, header)
        sa.sendall(rec + rec)                                      # the same record twice
        self.assertEqual(linkdev.recv_msg(got["b"].channel), {"x": 1})
        with self.assertRaises(linkdev.LinkError):
            linkdev.recv_msg(got["b"].channel)

    def test_a_decimal_in_a_message_is_refused_like_everywhere_else_in_kos(self):
        got = self.shake()
        got["a"].channel.send(b'{"n": 1.5}')
        with self.assertRaises(linkdev.LinkError):
            linkdev.recv_msg(got["b"].channel)
        got["a"].channel.send(b'{"n": NaN}')
        with self.assertRaises(linkdev.LinkError):
            linkdev.recv_msg(got["b"].channel)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.a = Device(self, "laptop", PW_A)
        self.a.make_identity()
        self.b = Device(self, "phone", PW_B, "ios")
        self.b.make_identity()
        run_pair(self, self.a, self.b, [PW_A], [PW_B])

    def test_the_list_is_sealed_so_an_edit_without_the_password_grants_nothing(self):
        f = self.a.paths.state / "links" / "links.json"
        f.write_text(f.read_text().replace('"scope":"all"', '"scope":"all" '))       # any change at all
        # (whitespace is part of nothing signed, so flip the real thing: the name)
        f.write_text(f.read_text().replace("phone", "pho_e"))
        peers, state = linkdev.LinkStore(self.a.paths).load(self.a.key())
        self.assertEqual((peers, state), ([], "tampered"))
        with self.assertRaises(linkdev.LinkError):
            linkdev.LinkStore(self.a.paths).peers(self.a.key())

    def test_a_key_that_does_not_match_the_device_id_is_not_believed(self):
        import json
        f = self.a.paths.state / "links" / "links.json"
        d = json.loads(f.read_text())
        d["peers"][0]["public"] = "00" * 32
        f.write_text(json.dumps(d))
        self.assertEqual(linkdev.LinkStore(self.a.paths).load(self.a.key())[1], "tampered")

    def test_unlinking_works_with_the_peer_offline_and_by_id_prefix(self):
        key = self.a.key()
        pid = self.a.peers()[0].device_id
        self.assertTrue(linkdev.LinkStore(self.a.paths).remove(key, pid[:8]))
        self.assertEqual(self.a.peers(), [])
        self.assertFalse(linkdev.LinkStore(self.a.paths).remove(key, pid[:8]))

    def test_pausing_a_link_is_a_scope_not_a_deletion(self):
        key, pid = self.a.key(), self.a.peers()[0].device_id
        self.assertTrue(linkdev.LinkStore(self.a.paths).set_scope(key, pid[:8], "paused"))
        self.assertEqual(self.a.peers()[0].scope, "paused")
        with self.assertRaises(linkdev.LinkError):
            linkdev.LinkStore(self.a.paths).set_scope(key, pid[:8], "everything-and-more")

    def test_at_most_32_devices(self):
        store, key = linkdev.LinkStore(self.a.paths), self.a.key()
        for i in range(linkdev.MAX_PEERS):
            pub = os.urandom(32)
            try:
                store.add(key, linkdev.Peer(linkdev.device_id(pub), f"d{i}", "linux", pub.hex(), "all", 1))
            except linkdev.LinkError:
                break
        pub = os.urandom(32)
        with self.assertRaises(linkdev.LinkError):
            store.add(key, linkdev.Peer(linkdev.device_id(pub), "one-too-many", "linux", pub.hex(), "all", 1))


class TestRequests(unittest.TestCase):
    """The receiving owner's side: scope, password, handler, audit."""

    def setUp(self):
        self.a = Device(self, "laptop", PW_A)     # asks
        self.b = Device(self, "phone", PW_B)      # receives
        self.a.make_identity(), self.b.make_identity()
        run_pair(self, self.a, self.b, [PW_A], [PW_B])
        self.calls = []

        def make(name):
            def h(args):
                self.calls.append((name, args))
                return {"echo": args.get("v", 0)}
            return h
        self.handlers = {"file.view": make("view"), "file.write": make("write"), "backup.list": make("list")}

    def serve(self, answers, scope="all", guard_=None):
        if scope != "all":
            linkdev.LinkStore(self.b.paths).set_scope(self.b.key(), self.b.peers()[0].device_id[:8], scope)
        peer = self.b.peers()[0]
        sa, sb = socket.socketpair()
        got = {}
        authority = self.b.authority(*answers)
        host = linkdev.LinkHost(self.b.paths, authority, peer, None, self.handlers, guard_)

        def side_b():
            sess = linkdev.handshake(sb, self.b.identity, False, expect=peer.key_bytes)
            host.channel = sess.channel
            try:
                got["n"] = host.serve()
            except linkdev.LinkError as e:
                got["err"] = e

        t = threading.Thread(target=side_b)
        t.start()
        a_peer = self.a.peers()[0]
        client = linkdev.connect_linked(sa, self.a.identity, a_peer)
        return client, t, got, authority

    def test_a_linked_device_can_ask_and_the_owner_is_asked_once_per_action_and_target(self):
        client, t, got, auth = self.serve([PW_B])
        self.assertEqual(client.call("file.view", "notes", {"v": 1}), {"echo": 1})
        self.assertEqual(client.call("file.view", "notes", {"v": 2}), {"echo": 2})     # same action and target: no 2nd prompt
        self.assertEqual(len(self.b.prompter.asked), 1)
        self.assertIn("phone"[:0] + "laptop", self.b.prompter.asked[0])                 # the prompt names who is asking
        client.close(), t.join(20)
        self.assertEqual(got["n"], 2)

    def test_a_different_target_is_a_new_question_for_the_owner(self):
        client, t, got, auth = self.serve([PW_B, PW_B])
        client.call("file.view", "notes")
        client.call("file.view", "photos")
        self.assertEqual(len(self.b.prompter.asked), 2)
        client.close(), t.join(20)

    def test_high_impact_actions_ask_every_single_time(self):
        client, t, got, auth = self.serve([PW_B, PW_B, PW_B])
        for i in range(3):
            client.call("file.write", "x", {"v": i})
        self.assertEqual(len(self.b.prompter.asked), 3)
        client.close(), t.join(20)

    def test_the_owner_refusing_the_prompt_runs_nothing_and_says_so(self):
        client, t, got, auth = self.serve([None])                 # cancelled
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.write", "x", {"v": 1})
        self.assertIn("said no", str(cm.exception))
        self.assertEqual(self.calls, [])
        client.close(), t.join(20)

    def test_a_wrong_password_on_the_receiving_device_runs_nothing(self):
        client, t, got, auth = self.serve(["x", "y", "z"])
        with self.assertRaises(linkdev.LinkError):
            client.call("backup.list")
        self.assertEqual(self.calls, [])
        client.close(), t.join(20)

    def test_actions_that_would_let_one_device_take_over_the_other_are_never_remote(self):
        client, t, got, auth = self.serve([])                    # no password answers: it must not even ask
        for action in sorted(linkdev.NEVER_REMOTE):
            with self.assertRaises(linkdev.LinkError, msg=action) as cm:
                client.call(action)
            self.assertIn("never ask", str(cm.exception))
        self.assertEqual(self.b.prompter.asked, [])
        client.close(), t.join(20)

    def test_every_never_remote_name_is_a_real_action(self):
        from kos.auth import ACTIONS
        self.assertTrue(linkdev.NEVER_REMOTE <= set(ACTIONS))
        self.assertTrue(linkdev.ASK_EVERY_TIME <= set(ACTIONS))

    def test_an_unknown_action_is_refused_before_a_password_is_asked(self):
        client, t, got, auth = self.serve([])
        for bad in ("rm.everything", "FILE.VIEW", "file view", "a" * 80):
            with self.assertRaises(linkdev.LinkError, msg=bad):
                client.call(bad)
        self.assertEqual(self.b.prompter.asked, [])
        client.close(), t.join(20)

    def test_a_paused_link_grants_nothing(self):
        client, t, got, auth = self.serve([], scope="paused")
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "notes")
        self.assertIn("paused", str(cm.exception))
        self.assertEqual((self.calls, self.b.prompter.asked), ([], []))
        client.close(), t.join(20)

    def test_an_action_with_no_handler_is_refused_as_not_wired_never_pretended(self):
        client, t, got, auth = self.serve([])
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("cell.list")
        self.assertIn("cannot do", str(cm.exception))
        client.close(), t.join(20)

    def test_every_request_is_audited_on_the_receiving_device(self):
        client, t, got, auth = self.serve([PW_B, None])
        client.call("file.view", "notes")
        with self.assertRaises(linkdev.LinkError):
            client.call("file.write", "x")
        with self.assertRaises(linkdev.LinkError):
            client.call("auth.change")
        client.close(), t.join(20)
        rows = [(r["action"], r["outcome"]) for r in self.b.audit() if r["action"] == "link.request"]
        outcomes = [o for _, o in rows]
        self.assertEqual(outcomes, ["granted", "refused", "refused"])
        targets = [r["target"] for r in self.b.audit() if r["action"] == "link.request"]
        self.assertTrue(all("laptop" in x for x in targets))

    def test_a_malformed_request_ends_the_connection(self):
        client, t, got, auth = self.serve([])
        linkdev.send_msg(client.channel, {"t": "req", "id": "one", "action": "file.view"})
        t.join(20)
        self.assertIsInstance(got.get("err"), linkdev.LinkError)

    def test_a_request_with_extra_fields_ends_the_connection(self):
        client, t, got, auth = self.serve([])
        linkdev.send_msg(client.channel, {"t": "req", "id": 1, "action": "file.view", "sudo": True})
        t.join(20)
        self.assertIsInstance(got.get("err"), linkdev.LinkError)

    def test_a_handler_that_blows_up_is_a_refusal_not_a_crash_and_leaks_no_traceback(self):
        def boom(args):
            raise KeyError("secret-internal-name")
        self.handlers["file.view"] = boom
        client, t, got, auth = self.serve([PW_B])
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "x")
        self.assertNotIn("Traceback", str(cm.exception))
        client.close(), t.join(20)

    # ---- the commands-layer guard: a linked device is one more source of commands (kos/guard.py) --------

    def test_a_linked_device_cannot_flood_the_owner_with_password_prompts(self):
        client, t, got, auth = self.serve([PW_B] * 6)
        for i in range(guard.MAX_PROMPTS_PER_MIN):
            client.call("file.view", f"target{i}")
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "one-more")
        self.assertIn("asked for your password", str(cm.exception))
        self.assertEqual(len(self.b.prompter.asked), guard.MAX_PROMPTS_PER_MIN)      # the seventh never reached the owner
        client.close(), t.join(20)
        self.assertIn(("guard.commands.prompt-budget", "refused"), [(r["action"], r["outcome"]) for r in self.b.audit()])

    def test_asking_again_for_what_was_already_approved_costs_no_prompt_and_no_budget(self):
        client, t, got, auth = self.serve([PW_B])
        for i in range(40):
            client.call("file.view", "notes", {"v": i})
        self.assertEqual(len(self.b.prompter.asked), 1)
        client.close(), t.join(20)
        self.assertEqual(got["n"], 40)

    def test_the_every_time_actions_are_held_to_the_same_budget(self):
        client, t, got, auth = self.serve([PW_B] * 6)
        for i in range(guard.MAX_PROMPTS_PER_MIN):
            client.call("file.write", "x", {"v": i})
        with self.assertRaises(linkdev.LinkError):
            client.call("file.write", "x", {"v": 99})
        self.assertEqual(len([c for c in self.calls if c[0] == "write"]), guard.MAX_PROMPTS_PER_MIN)
        client.close(), t.join(20)

    def test_a_device_whose_requests_keep_failing_is_answered_no_without_a_prompt(self):
        client, t, got, auth = self.serve([PW_B])                              # one answer is available, and must not be used
        for _ in range(guard.MAX_FAILED_REQUESTS):
            with self.assertRaises(linkdev.LinkError):
                client.call("auth.change")                                       # refused by scope: counts as a failure
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "notes")                                    # a perfectly good request is now refused
        self.assertIn("already failed", str(cm.exception))
        self.assertEqual((self.b.prompter.asked, self.calls), ([], []))
        client.close(), t.join(20)
        self.assertIn(("guard.commands.failed-requests", "refused"), [(r["action"], r["outcome"]) for r in self.b.audit()])

    def test_an_owner_saying_no_counts_as_a_failure_so_a_pest_stops_being_asked(self):
        client, t, got, auth = self.serve([None] * 5)
        for i in range(guard.MAX_FAILED_REQUESTS):
            with self.assertRaises(linkdev.LinkError):
                client.call("file.view", f"t{i}")
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "once more")
        self.assertIn("already failed", str(cm.exception))
        self.assertEqual(len(self.b.prompter.asked), guard.MAX_FAILED_REQUESTS)          # the owner was not asked a sixth time
        client.close(), t.join(20)

    def test_a_message_flood_ends_the_connection(self):
        with mock.patch.object(guard, "MAX_MESSAGES_PER_SEC", 3):
            g = guard.Guard("flood-test", audit=None, pid=None)
        client, t, got, auth = self.serve([PW_B], guard_=g)
        for _ in range(3):
            client.call("file.view", "notes")
        with self.assertRaises(linkdev.LinkError):
            client.call("file.view", "notes")                                    # the fourth within the second
        t.join(20)
        self.assertIsInstance(got.get("err"), linkdev.LinkError)
        self.assertIn("connection ended", str(got["err"]))

    def test_a_handler_refusal_and_a_handler_bug_are_both_replies_and_the_connection_survives(self):
        def refuse(args):
            raise linkdev.Refusal("that path is not allowed")

        def bug(args):
            raise RuntimeError("secret internals /home/user/.ssh")
        self.handlers["file.view"], self.handlers["backup.list"] = refuse, bug
        client, t, got, auth = self.serve([PW_B, PW_B, PW_B])
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("file.view", "x")
        self.assertIn("not allowed", str(cm.exception))
        with self.assertRaises(linkdev.LinkError) as cm:
            client.call("backup.list", "y")
        self.assertIn("internal error", str(cm.exception))
        self.assertNotIn("secret", str(cm.exception))                    # a bug's message is not passed on
        client.close(), t.join(20)
        self.assertNotIn("err", got)
        self.assertEqual([r["outcome"] for r in self.b.audit() if r["action"] == "link.request"], ["failed", "failed"])

    def test_a_handler_set_is_told_when_the_connection_ends(self):
        class Handlers(dict):
            closed = 0

            def close(self):
                Handlers.closed += 1
        self.handlers = Handlers(self.handlers)
        client, t, got, auth = self.serve([])
        client.close(), t.join(20)
        self.assertEqual(Handlers.closed, 1)

    def test_the_answer_must_match_the_question(self):
        sa, sb = socket.socketpair()
        got = {}
        t = threading.Thread(target=lambda: got.update(b=linkdev.handshake(sb, self.b.identity, False)))
        t.start()
        client = linkdev.connect_linked(sa, self.a.identity, self.a.peers()[0])
        t.join(20)

        def evil():
            linkdev.recv_msg(got["b"].channel)
            linkdev.send_msg(got["b"].channel, {"t": "res", "id": 99, "ok": True, "detail": "", "data": {}})
        t2 = threading.Thread(target=evil)
        t2.start()
        with self.assertRaises(linkdev.LinkError):
            client.call("file.view")
        t2.join(20)


class TestServeSocket(unittest.TestCase):
    def setUp(self):
        self.a = Device(self, "laptop", PW_A)
        self.b = Device(self, "phone", PW_B)
        self.a.make_identity(), self.b.make_identity()
        run_pair(self, self.a, self.b, [PW_A], [PW_B])

    def test_a_linked_device_is_served_and_a_stranger_is_turned_away(self):
        handlers = {"file.view": lambda args: {"ok": 1}}
        # linked laptop -> phone
        sa, sb = socket.socketpair()
        got = {}
        t = threading.Thread(target=lambda: got.update(n=linkdev.serve_socket(
            self.b.paths, self.b.authority(PW_B, PW_B), self.b.identity, sb, handlers)))
        t.start()
        client = linkdev.connect_linked(sa, self.a.identity, self.a.peers()[0])
        self.assertEqual(client.call("file.view", "x"), {"ok": 1})
        client.close(), t.join(20)
        self.assertEqual(got["n"], 1)
        # a device that was never paired
        eve = Device(self, "eve", "eve long password")
        eve.make_identity()
        sa, sb = socket.socketpair()
        res = {}

        def serve():
            try:
                linkdev.serve_socket(self.b.paths, self.b.authority(PW_B), self.b.identity, sb, handlers)
            except linkdev.LinkError as e:
                res["err"] = e

        t = threading.Thread(target=serve)
        t.start()
        sa.sendall(os.urandom(32) + eve.identity.public + os.urandom(16))
        t.join(20)
        self.assertIn("not linked", str(res["err"]))
        self.assertIn(("link.request", "refused"),
                      [(r["action"], r["outcome"]) for r in self.b.audit()])


class TestAStrangerAtTheDoorCannotMakeTheOwnerTypeAPassword(unittest.TestCase):
    def test_with_the_key_in_hand_a_stranger_is_turned_away_before_any_prompt(self):
        a, b = Device(self, "laptop", PW_A), Device(self, "phone", PW_B)
        a.make_identity(), b.make_identity()
        run_pair(self, a, b, [PW_A], [PW_B])
        eve = Device(self, "eve", "eve long password")
        eve.make_identity()
        key = b.key()                                    # typed once, before listening
        sa, sb = socket.socketpair()
        res = {}
        authority = b.authority()                         # no answers at all: any prompt would raise
        t = threading.Thread(target=lambda: res.update(err=_serve_error(b, authority, sb, key)))
        t.start()
        sa.sendall(os.urandom(32) + eve.identity.public + os.urandom(16))
        t.join(20)
        self.assertIn("not linked", res["err"])
        self.assertEqual(b.prompter.asked, [])

    def test_a_linked_device_is_still_served_with_the_key_and_no_extra_prompt(self):
        a, b = Device(self, "laptop", PW_A), Device(self, "phone", PW_B)
        a.make_identity(), b.make_identity()
        run_pair(self, a, b, [PW_A], [PW_B])
        key = b.key()
        sa, sb = socket.socketpair()
        got = {}
        authority = b.authority(PW_B)                     # exactly one answer: the first request's own prompt
        t = threading.Thread(target=lambda: got.update(n=linkdev.serve_socket(
            b.paths, authority, b.identity, sb, {"file.view": lambda args: {"ok": 1}}, key)))
        t.start()
        client = linkdev.connect_linked(sa, a.identity, a.peers()[0])
        self.assertEqual(client.call("file.view", "x"), {"ok": 1})
        client.close(), t.join(20)
        self.assertEqual(len(b.prompter.asked), 1)        # the request's prompt, not a "who is connecting" prompt


def _serve_error(dev, authority, sock, key):
    try:
        linkdev.serve_socket(dev.paths, authority, dev.identity, sock, {}, key)
    except linkdev.LinkError as e:
        return str(e)
    return ""


class TestTheFirewallStillDecides(unittest.TestCase):
    """Rule 3 for the OS's own sockets: no firewall rule for ``sync`` means no connection, and it is logged."""

    def setUp(self):
        self.a = Device(self, "laptop", PW_A)
        self.a.make_identity()

    def test_connecting_is_blocked_by_default_and_logged_even_with_the_password(self):
        called = []
        with self.assertRaises(linkdev.LinkError) as cm:
            linkdev.open_client(self.a.paths, self.a.authority(PW_A), "10.0.0.5", 7007,
                                connect=lambda h, p: called.append((h, p)))
        self.assertIn("blocked", str(cm.exception))
        self.assertEqual(called, [])
        self.assertIn(("net.link", "blocked"), [(r["action"], r["outcome"]) for r in self.a.audit()])

    def test_a_rule_for_one_address_and_port_allows_exactly_that(self):
        with self.a.authority(PW_A).authorize("firewall.change") as g:
            firewall.FirewallStore(self.a.paths).add(
                g.key(firewall.KEY_LABEL), firewall.check_entry("sync", "tcp", "connect", "10.0.0.5", 7007))
        called = []
        sock = linkdev.open_client(self.a.paths, self.a.authority(PW_A), "10.0.0.5", 7007,
                                   connect=lambda h, p: called.append((h, p)) or "socket")
        self.assertEqual((sock, called), ("socket", [("10.0.0.5", 7007)]))
        for host, port in (("10.0.0.5", 7008), ("10.0.0.6", 7007)):      # a different port, a different host
            with self.assertRaises(linkdev.LinkError):
                linkdev.open_client(self.a.paths, self.a.authority(PW_A), host, port,
                                    connect=lambda h, p: called.append((h, p)))
        self.assertEqual(len(called), 1)

    def test_a_rule_for_another_app_does_not_count(self):
        with self.a.authority(PW_A).authorize("firewall.change") as g:
            firewall.FirewallStore(self.a.paths).add(
                g.key(firewall.KEY_LABEL), firewall.check_entry("browser", "tcp", "connect", "10.0.0.5", 7007))
        with self.assertRaises(linkdev.LinkError):
            linkdev.open_client(self.a.paths, self.a.authority(PW_A), "10.0.0.5", 7007, connect=lambda h, p: None)

    def test_listening_is_blocked_by_default_too(self):
        with self.assertRaises(linkdev.LinkError):
            linkdev.open_listener(self.a.paths, self.a.authority(PW_A), "127.0.0.1", 47007)

    def test_the_password_is_asked_before_anything_else(self):
        with self.assertRaises(AuthorizationDenied):
            linkdev.open_client(self.a.paths, self.a.authority(None), "10.0.0.5", 7007, connect=lambda h, p: None)


if __name__ == "__main__":
    unittest.main()
