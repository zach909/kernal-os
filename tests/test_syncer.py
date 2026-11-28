"""The sync engine (kos/syncer.py) and the path rules (kos/portable.py).

Sync is tested end to end over a real encrypted link between two separate KOS roots. The rules under
test are the ones that protect data: nothing is overwritten unseen, nothing is deleted (it goes to the
trash), a peer's path or bytes are never believed, and an owner who says no changes nothing."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos import linkdev, portable, syncer  # noqa: E402
from test_linkdev import PW_A, PW_B, Device, run_pair  # noqa: E402


def write(root: Path, rel: str, data: bytes | str) -> Path:
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def tree(root: Path) -> dict[str, bytes]:
    out = {}
    for p in sorted(Path(root).rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and not rel.startswith(".kos-trash"):
            out[rel] = p.read_bytes()
    return out


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class TestPortable(unittest.TestCase):
    def test_safe_paths_are_accepted(self):
        for ok in ("a.txt", "dir/a.txt", "dir/sub/ünïcode.txt", "a b/c d", "..hidden-not-parent", "x.."):
            self.assertEqual(portable.safe_relative(ok), ok)

    def test_hostile_paths_are_refused_not_repaired(self):
        for bad in ("", "/etc/passwd", "../x", "a/../b", "a/./b", "a//b", "a/", "C:/x", "c:\\x", "a\\b", "a\x00b",
                    "a\x1bb", "a\u202eb", ".kos-trash/x", "dir/.kos-sync", "a/" * 70 + "b", "x" * 300, 5, None):
            with self.assertRaises(portable.PathRefused, msg=repr(bad)):
                portable.safe_relative(bad)

    def test_windows_problems_are_named(self):
        self.assertEqual(portable.problems("fine/name.txt"), [])
        for bad in ("a:b", "a<b", 'q"q', "x|y", "what?", "star*", "con", "NUL.txt", "dir/aux", "com1.log", "trail.", "sp "):
            self.assertTrue(portable.problems(bad), bad)

    def test_the_portable_spelling_is_deterministic_injective_and_a_no_op_for_good_names(self):
        self.assertEqual(portable.portable("fine/name.txt"), "fine/name.txt")
        names = ["a:b", "a_b", "a?b", "a*b", "con", "_con", "trail.", "trail", "x |y", "x _y"]
        mapped = [portable.portable(n) for n in names]
        self.assertEqual(mapped, [portable.portable(n) for n in names])           # deterministic
        for m in mapped:
            self.assertEqual(portable.problems(m), [], m)                          # and now legal everywhere
        self.assertEqual(len(set(mapped)), len(set(names)))                        # never two originals, one file
        self.assertNotEqual(portable.portable("a:b"), portable.portable("a_b"))

    def test_collisions_on_case_and_accent_insensitive_systems(self):
        self.assertEqual(portable.collisions(["A.txt", "a.txt", "b.txt"]), [("A.txt", "a.txt")])
        composed, decomposed = "caf\u00e9.txt", "cafe\u0301.txt"
        self.assertEqual(len(portable.collisions([composed, decomposed])), 1)
        self.assertEqual(portable.normalize(decomposed), composed)
        self.assertEqual(portable.collisions(["a", "b"]), [])


class TestPlan(unittest.TestCase):
    """The three-way rule, one case per row of the table in syncer.py."""

    def p(self, L=None, R=None, B=None):
        return syncer.plan({"f": L} if L else {}, {"f": R} if R else {}, {"f": B} if B else {})

    def test_every_row_of_the_table(self):
        self.assertEqual(self.p("x", "x", "x").same, 1)
        self.assertEqual(self.p("x", "x", None).same, 1)                          # both added the same file
        self.assertEqual(self.p("x", "y", "x").pull, ["f"])                       # only remote changed
        self.assertEqual(self.p(None, "y", None).pull, ["f"])                     # remote added
        self.assertEqual(self.p("x", None, "x").trash_local, ["f"])               # remote deleted
        self.assertEqual(self.p("y", "x", "x").push, ["f"])                       # only we changed
        self.assertEqual(self.p("y", None, None).push, ["f"])                     # we added
        self.assertEqual(self.p(None, "x", "x").trash_remote, ["f"])              # we deleted
        c = self.p("a", "b", "x")                                                 # both changed
        self.assertEqual((c.conflicts, c.push, c.pull), (["f"], ["f"], []))
        c = self.p("a", "b", None)                                                # both added different
        self.assertEqual(c.conflicts, ["f"])

    def test_an_edit_always_beats_a_delete(self):
        self.assertEqual(self.p(None, "edited", "x").pull, ["f"])                 # we deleted, they edited
        self.assertEqual(self.p("edited", None, "x").push, ["f"])                 # they deleted, we edited
        self.assertEqual(self.p(None, "edited", "x").trash_local, [])

    def test_nothing_is_ever_planned_for_a_converged_tree(self):
        h = {"a": "1", "b": "2"}
        self.assertTrue(syncer.plan(h, dict(h), dict(h)).empty())

    def test_conflict_names_keep_the_extension_and_the_folder(self):
        self.assertEqual(syncer.conflict_name("d/n.txt", "abcdef123456", "0123456789"), "d/n (conflict abcdef12 01234567).txt")
        self.assertEqual(syncer.conflict_name("README", "abcdef123456", "0123456789"), "README (conflict abcdef12 01234567)")
        self.assertEqual(syncer.conflict_name(".env", "abcdef123456", "0123456789"), ".env (conflict abcdef12 01234567)")


class TestApplier(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ap = syncer.Applier(self.root)

    def test_a_file_is_written_only_when_its_hash_and_size_match(self):
        data = b"hello" * 100
        self.ap.write_whole("a/b.txt", data)
        self.assertEqual((self.root / "a" / "b.txt").read_bytes(), data)
        self.assertEqual([p.name for p in (self.root / "a").iterdir()], ["b.txt"])      # no temp file left

    def test_wrong_bytes_write_nothing_and_leave_no_temp_file(self):
        self.ap.begin("x.txt", 5, sha(b"right"), None)
        self.ap.chunk("x.txt", 0, b"wrong")
        with self.assertRaises(syncer.SyncError):
            self.ap.finish("x.txt")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_a_short_file_is_refused(self):
        self.ap.begin("x.txt", 10, sha(b"0123456789"), None)
        self.ap.chunk("x.txt", 0, b"0123")
        with self.assertRaises(syncer.SyncError):
            self.ap.finish("x.txt")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_chunks_must_arrive_in_order_and_not_overflow_the_declared_size(self):
        self.ap.begin("x.txt", 4, sha(b"abcd"), None)
        with self.assertRaises(syncer.SyncError):
            self.ap.chunk("x.txt", 2, b"cd")                                           # skipped ahead
        self.assertEqual(list(self.root.iterdir()), [])                                # and it cleaned up
        self.ap.begin("y.txt", 2, sha(b"ab"), None)
        with self.assertRaises(syncer.SyncError):
            self.ap.chunk("y.txt", 0, b"abcd")                                         # more than it said

    def test_an_oversized_declaration_is_refused_up_front(self):
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("x", syncer.MAX_FILE + 1, sha(b""), None)
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("x", 1, "not-a-hash", None)

    def test_an_existing_file_that_changed_since_it_was_listed_is_not_overwritten(self):
        write(self.root, "f.txt", "mine")
        with self.assertRaises(syncer.SyncError) as cm:
            self.ap.begin("f.txt", 3, sha(b"new"), sha(b"what-the-list-said"))
        self.assertIn("changed since", str(cm.exception))
        self.assertEqual((self.root / "f.txt").read_text(), "mine")
        with self.assertRaises(syncer.SyncError):                                      # and a "new" file that exists is not new
            self.ap.begin("f.txt", 3, sha(b"new"), None)

    def test_a_replaced_file_is_kept_in_the_trash_by_content_hash(self):
        write(self.root, "f.txt", "old content")
        self.ap.write_whole("f.txt", b"new content", replaces=sha(b"old content"))
        self.assertEqual((self.root / "f.txt").read_bytes(), b"new content")
        self.assertEqual((self.root / ".kos-trash" / sha(b"old content")).read_bytes(), b"old content")

    def test_trash_never_deletes_a_file_that_changed_and_never_unlinks_unseen_data(self):
        write(self.root, "f.txt", "v2")
        with self.assertRaises(syncer.SyncError):
            self.ap.trash("f.txt", sha(b"v1"))
        self.assertTrue((self.root / "f.txt").exists())
        self.assertTrue(self.ap.trash("f.txt", sha(b"v2")))
        self.assertFalse((self.root / "f.txt").exists())
        self.assertEqual((self.root / ".kos-trash" / sha(b"v2")).read_bytes(), b"v2")
        self.assertFalse(self.ap.trash("f.txt", None))                                 # already gone: nothing to do

    def test_hostile_paths_never_touch_the_disk(self):
        outside = self.root.parent / "outside.txt"
        for bad in ("../outside.txt", "/tmp/abs.txt", "a/../../outside.txt", "..", ".kos-trash/x"):
            with self.assertRaises((syncer.SyncError, portable.PathRefused), msg=bad):
                self.ap.begin(bad, 1, sha(b"x"), None)
        self.assertFalse(outside.exists())

    def test_a_symlink_in_the_way_is_never_followed(self):
        victim = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(victim, ignore_errors=True))
        os.symlink(victim, self.root / "link")                                          # a folder symlink
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("link/pwned.txt", 1, sha(b"x"), None)
        self.assertEqual(list(victim.iterdir()), [])
        os.symlink("/etc/passwd", self.root / "file-link")                              # a file symlink
        with self.assertRaises(syncer.SyncError):
            self.ap.current_hash("file-link")
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("file-link", 1, sha(b"x"), None)

    def test_a_file_where_a_folder_is_needed_is_refused(self):
        write(self.root, "a", "I am a file")
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("a/b.txt", 1, sha(b"x"), None)

    def test_sweep_removes_only_stale_temp_files(self):
        write(self.root, "keep.txt", "x")
        write(self.root, "d/.kos-tmp-abc123", "half")
        write(self.root, ".kos-tmp-zzz", "half")
        self.assertEqual(self.ap.sweep(), 2)
        self.assertEqual(sorted(tree(self.root)), ["keep.txt"])

    def test_at_most_eight_files_open_at_once(self):
        for i in range(8):
            self.ap.begin(f"f{i}", 1, sha(b"x"), None)
        with self.assertRaises(syncer.SyncError):
            self.ap.begin("f8", 1, sha(b"x"), None)
        self.ap.abort_all()
        self.assertEqual([p.name for p in self.root.iterdir()], [])


class TestSnapshot(unittest.TestCase):
    def test_what_is_listed_and_what_is_skipped_with_a_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "a.txt", "A")
            write(root, "d/b.txt", "B")
            write(root, ".kos-trash/old", "trash")                                     # bookkeeping: not synced, not listed
            write(root, ".kos-tmp-1", "half")
            os.symlink("/etc/hostname", root / "link")
            os.symlink(tmp, root / "dirlink")
            m = syncer.snapshot(root)
            self.assertEqual(sorted(m.files), ["a.txt", "d/b.txt"])
            self.assertEqual(m.files["a.txt"], {"h": sha(b"A"), "n": 1})
            self.assertTrue(any("link" in s and "symlink" in s for s in m.skipped), m.skipped)
            self.assertEqual(len([s for s in m.skipped if "symlink" in s]), 2)

    def test_a_name_a_peer_would_refuse_is_skipped_and_said_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            # every component is legal here, but the whole path is longer than a peer will accept
            write(Path(tmp), "/".join(["y" * 250] * 5) + "/f.txt", "too long a path")
            write(Path(tmp), "ok.txt", "fine")
            m = syncer.snapshot(Path(tmp))
            self.assertEqual(sorted(m.files), ["ok.txt"])
            self.assertEqual(len(m.skipped), 1)
            self.assertIn("longer than", m.skipped[0])

    def test_two_spellings_of_one_accent_are_two_files_here_and_a_collision_only_where_they_fold(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "caf\u00e9.txt", "composed")
            write(Path(tmp), "cafe\u0301.txt", "decomposed")
            m = syncer.snapshot(Path(tmp))
            self.assertEqual(len(m.files), 2)                                         # neither shadows the other
            self.assertEqual(syncer.blocked_for("linux", list(m.files)), {})
            self.assertEqual(len(syncer.blocked_for("macos", list(m.files))), 1)      # a Mac cannot hold both

    def test_windows_cannot_hold_everything_so_those_files_are_not_sent_and_are_reported(self):
        blocked = syncer.blocked_for("windows", ["ok.txt", "a:b.txt", "con", "A.TXT", "a.txt"])
        self.assertEqual(sorted(blocked), ["a.txt", "a:b.txt", "con"])
        self.assertEqual(syncer.blocked_for("linux", ["a:b.txt", "con"]), {})
        self.assertEqual(sorted(syncer.blocked_for("macos", ["A.TXT", "a.txt", "a:b"])), ["a.txt"])


class TwoDevices(unittest.TestCase):
    """Two linked KOS devices, each with a folder called ``docs``. ``self.sync()`` runs one pass from A to B."""

    def setUp(self):
        self.a = Device(self, "laptop", PW_A)
        self.b = Device(self, "phone", PW_B)
        self.a.make_identity(), self.b.make_identity()
        run_pair(self, self.a, self.b, [PW_A], [PW_B])
        self.ra, self.rb = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        for r in (self.ra, self.rb):
            self.addCleanup(lambda r=r: __import__("shutil").rmtree(r, ignore_errors=True))
        self.base: dict = {}

    def sync(self, b_answers=None, handlers=None, peer_platform="kos", dry_run=False, base=None):
        handlers = handlers or syncer.make_handlers(lambda name: self.rb if name == "docs" else (_ for _ in ()).throw(
            syncer.SyncError("no such shared folder")))
        peer_b = self.b.peers()[0]
        sa, sb = socket.socketpair()
        res = {}
        host = linkdev.LinkHost(self.b.paths, self.b.authority(*(b_answers if b_answers is not None else [PW_B, PW_B])),
                                peer_b, None, handlers)

        def serve():
            sess = linkdev.handshake(sb, self.b.identity, False, expect=peer_b.key_bytes)
            host.channel = sess.channel
            try:
                host.serve()
            except linkdev.LinkError as e:
                res["serve_err"] = e

        t = threading.Thread(target=serve)
        t.start()
        client = linkdev.connect_linked(sa, self.a.identity, self.a.peers()[0])
        try:
            rep, new_base = syncer.sync_once(client, "docs", self.ra, self.base if base is None else base,
                                             peer_b.device_id, peer_platform, dry_run)
            if not dry_run:
                self.base = new_base
            return rep
        finally:
            client.close()
            t.join(20)


class TestSyncEndToEnd(TwoDevices):
    def test_new_files_flow_both_ways_and_a_second_pass_is_a_no_op(self):
        write(self.ra, "a.txt", "from laptop")
        write(self.ra, "dir/deep/x.bin", os.urandom(1000))
        write(self.rb, "b.txt", "from phone")
        rep = self.sync()
        self.assertEqual(sorted(rep.pushed), ["a.txt", "dir/deep/x.bin"])
        self.assertEqual(rep.pulled, ["b.txt"])
        self.assertTrue(rep.ok())
        self.assertEqual(tree(self.ra), tree(self.rb))
        again = self.sync()
        self.assertEqual((again.pushed, again.pulled, again.trashed, again.conflicts), ([], [], [], []))
        self.assertEqual(set(self.base), {"a.txt", "b.txt", "dir/deep/x.bin"})

    def test_an_edit_travels_and_the_old_version_stays_recoverable(self):
        write(self.ra, "n.txt", "v1")
        self.sync()
        write(self.ra, "n.txt", "v2")
        rep = self.sync()
        self.assertEqual(rep.pushed, ["n.txt"])
        self.assertEqual((self.rb / "n.txt").read_text(), "v2")
        self.assertEqual((self.rb / ".kos-trash" / sha(b"v1")).read_bytes(), b"v1")

    def test_a_delete_travels_as_a_move_to_the_trash_never_an_unlink(self):
        write(self.ra, "gone.txt", "precious")
        self.sync()
        (self.ra / "gone.txt").unlink()
        rep = self.sync()
        self.assertEqual(rep.trashed, ["gone.txt"])
        self.assertFalse((self.rb / "gone.txt").exists())
        self.assertEqual((self.rb / ".kos-trash" / sha(b"precious")).read_bytes(), b"precious")
        # and the other way round
        write(self.rb, "also.txt", "also precious")
        self.sync()
        (self.rb / "also.txt").unlink()
        self.sync()
        self.assertFalse((self.ra / "also.txt").exists())
        self.assertEqual((self.ra / ".kos-trash" / sha(b"also precious")).read_bytes(), b"also precious")

    def test_both_sides_edited_keeps_both_versions_and_converges(self):
        write(self.ra, "plan.txt", "start")
        self.sync()
        write(self.ra, "plan.txt", "laptop edit")
        write(self.rb, "plan.txt", "phone edit")
        rep = self.sync()
        self.assertEqual(len(rep.conflicts), 1)
        self.assertRegex(rep.conflicts[0], r"^plan \(conflict [0-9a-f]{8} [0-9a-f]{8}\)\.txt$")
        self.assertEqual((self.ra / rep.conflicts[0]).read_text(), "phone edit")        # the loser is kept, not lost
        self.assertEqual((self.ra / "plan.txt").read_text(), "laptop edit")
        self.assertEqual((self.rb / "plan.txt").read_text(), "laptop edit")
        self.assertEqual(sha(b"phone edit"), (self.rb / ".kos-trash" / sha(b"phone edit")).name)  # and on the phone too
        self.sync()                                                                      # the copy reaches the phone
        self.sync()
        self.assertEqual(tree(self.ra), tree(self.rb))
        self.assertEqual(self.sync().conflicts, [])                                      # converged: it does not re-conflict

    def test_a_delete_loses_to_an_edit_on_the_other_side(self):
        write(self.ra, "keep.txt", "v1")
        self.sync()
        (self.ra / "keep.txt").unlink()
        write(self.rb, "keep.txt", "edited on phone")
        self.sync()
        self.assertEqual((self.ra / "keep.txt").read_text(), "edited on phone")
        self.assertEqual((self.rb / "keep.txt").read_text(), "edited on phone")

    def test_a_big_file_crosses_in_many_chunks_intact(self):
        data = os.urandom(syncer.CHUNK * 3 + 17)
        write(self.ra, "big.bin", data)
        write(self.ra, "empty", b"")
        self.sync()
        self.assertEqual((self.rb / "big.bin").read_bytes(), data)
        self.assertEqual((self.rb / "empty").read_bytes(), b"")
        write(self.rb, "exact.bin", os.urandom(syncer.CHUNK * 2))                        # an exact multiple of the chunk
        self.sync()
        self.assertEqual((self.ra / "exact.bin").read_bytes(), (self.rb / "exact.bin").read_bytes())

    def test_a_dry_run_changes_nothing_anywhere(self):
        write(self.ra, "a.txt", "A")
        write(self.rb, "b.txt", "B")
        rep = self.sync(dry_run=True)
        self.assertEqual((rep.pushed, rep.pulled), (["a.txt"], ["b.txt"]))
        self.assertEqual((sorted(tree(self.ra)), sorted(tree(self.rb))), (["a.txt"], ["b.txt"]))
        self.assertEqual(self.base, {})

    def test_the_receiving_owner_is_asked_once_for_the_folder_and_says_which(self):
        write(self.ra, "a.txt", "A")
        write(self.rb, "b.txt", "B")
        self.sync()
        asked = self.b.prompter.asked
        self.assertEqual(len(asked), 2)                                                  # one for read, one for apply: not per file
        self.assertTrue(all("space docs" in q and "laptop" in q for q in asked), asked)

    def test_the_owner_refusing_changes_nothing_on_either_side(self):
        write(self.ra, "a.txt", "A")
        write(self.rb, "b.txt", "B")
        with self.assertRaises(linkdev.LinkError):
            self.sync(b_answers=[None])
        self.assertEqual((sorted(tree(self.ra)), sorted(tree(self.rb))), (["a.txt"], ["b.txt"]))
        self.assertEqual(self.base, {})

    def test_a_peer_can_name_a_folder_never_a_path(self):
        with self.assertRaises(linkdev.LinkError):
            self.sync(handlers=syncer.make_handlers(lambda name: (_ for _ in ()).throw(syncer.SyncError("no such folder"))))

    def test_a_windows_peer_is_not_sent_what_it_cannot_hold_and_is_told_why(self):
        write(self.ra, "ok.txt", "fine")
        write(self.ra, "bad:name.txt", "colon")
        write(self.ra, "con", "device")
        rep = self.sync(peer_platform="windows")
        self.assertEqual(rep.pushed, ["ok.txt"])
        self.assertEqual(sorted(tree(self.rb)), ["ok.txt"])
        self.assertEqual(len([s for s in rep.skipped if "cannot hold" in s]), 2)
        self.assertTrue((self.ra / "bad:name.txt").exists())                              # nothing renamed or deleted here

    def test_an_interrupted_transfer_leaves_no_partial_file_to_be_synced_later(self):
        write(self.ra, "big.bin", os.urandom(syncer.CHUNK * 2))
        real = syncer.make_handlers(lambda n: self.rb)
        count = {"n": 0}

        def flaky_apply(args):
            if args.get("op") == "chunk":
                count["n"] += 1
                if count["n"] == 2:
                    raise syncer.SyncError("disk full")                                  # dies halfway
            return real["sync.apply"](args)

        class Flaky(dict):
            def close(self):
                real.close()                                                              # the connection ends: clean up

        rep = self.sync(handlers=Flaky({"sync.read": real["sync.read"], "sync.apply": flaky_apply}))
        self.assertEqual([p for p, _ in rep.refused], ["big.bin"])
        self.assertNotIn("big.bin", tree(self.rb))
        self.assertEqual([p.name for p in self.rb.iterdir()], [])                         # not even a temp file
        self.assertNotIn("big.bin", self.base)                                             # so the next run retries it
        self.assertEqual(self.sync(handlers=real).pushed, ["big.bin"])
        self.assertEqual(tree(self.ra), tree(self.rb))


class TestHostilePeer(TwoDevices):
    """The other device is the attacker: it lists bad paths, sends the wrong bytes, lies about hashes."""

    def handlers(self, manifest=None, chunk=None):
        real = syncer.make_handlers(lambda n: self.rb)

        def read(args):
            if args.get("mode") == "manifest" and manifest is not None:
                return manifest
            if args.get("mode") == "chunk" and chunk is not None:
                return chunk
            return real["sync.read"](args)
        return {"sync.read": read, "sync.apply": real["sync.apply"]}

    def entry(self):
        return {"h": sha(b"x"), "n": 1}

    def test_a_peer_cannot_make_us_write_outside_the_folder(self):
        for bad in ("../../etc/cron.d/x", "/etc/passwd", "a/../../x", "C:/Windows/x", "a\\b", ".kos-trash/h"):
            with self.assertRaises(syncer.SyncError, msg=bad):
                self.sync(handlers=self.handlers(manifest={"files": {bad: self.entry()}, "next": ""}))
            self.assertEqual(tree(self.ra), {})

    def test_a_peer_cannot_send_a_malformed_manifest(self):
        for bad in ({"files": [], "next": ""}, {"files": {"a": {"h": "zz", "n": 1}}, "next": ""},
                    {"files": {"a": {"h": sha(b"x"), "n": -1}}, "next": ""},
                    {"files": {"a": {"h": sha(b"x"), "n": syncer.MAX_FILE + 1}}, "next": ""},
                    {"files": {"a": "not a dict"}, "next": ""}):
            with self.assertRaises(syncer.SyncError, msg=str(bad)):
                self.sync(handlers=self.handlers(manifest=bad))

    def test_wrong_bytes_are_caught_by_the_hash_and_nothing_is_written(self):
        write(self.rb, "f.txt", "real")
        evil = {"data": base64.b64encode(b"EVIL").decode(), "eof": True}
        rep = self.sync(handlers=self.handlers(chunk=evil))
        self.assertEqual(rep.pulled, [])
        self.assertEqual([p for p, _ in rep.refused], ["f.txt"])
        self.assertEqual(list(self.ra.iterdir()), [])

    def test_endless_data_cannot_fill_the_disk(self):
        write(self.rb, "f.txt", "tiny")
        endless = {"data": base64.b64encode(b"A" * syncer.CHUNK).decode(), "eof": False}
        rep = self.sync(handlers=self.handlers(chunk=endless))
        self.assertEqual([p for p, _ in rep.refused], ["f.txt"])
        self.assertEqual(list(self.ra.iterdir()), [])

    def test_bad_base64_is_refused(self):
        write(self.rb, "f.txt", "tiny")
        rep = self.sync(handlers=self.handlers(chunk={"data": "!!!not base64!!!", "eof": True}))
        self.assertEqual([p for p, _ in rep.refused], ["f.txt"])

    def test_the_serving_side_refuses_what_a_hostile_client_asks(self):
        h = syncer.make_handlers(lambda n: self.rb)
        write(self.rb, "secret.txt", "s")
        os.symlink("/etc/passwd", self.rb / "pw")
        for args in ({"space": "docs", "mode": "chunk", "path": "../secret.txt", "offset": 0},
                     {"space": "docs", "mode": "chunk", "path": "/etc/passwd", "offset": 0},
                     {"space": "docs", "mode": "chunk", "path": "pw", "offset": 0},          # a symlink out of the folder
                     {"space": "docs", "mode": "chunk", "path": "secret.txt", "offset": -1},
                     {"space": "docs", "mode": "chunk", "path": "secret.txt", "offset": 0, "length": 10 ** 9},
                     {"space": "docs", "mode": "manifest", "limit": 10 ** 6},
                     {"space": "docs", "mode": "nope"}, {"space": 5}, {}):
            with self.assertRaises((syncer.SyncError, portable.PathRefused), msg=str(args)):
                h["sync.read"](args)
        for args in ({"space": "docs", "op": "begin", "path": "../x", "size": 1, "hash": sha(b"x")},
                     {"space": "docs", "op": "chunk", "path": "never-begun", "offset": 0, "data": ""},
                     {"space": "docs", "op": "trash", "path": "secret.txt", "hash": "not-a-hash"},
                     {"space": "docs", "op": "trash", "path": "secret.txt", "hash": sha(b"someone else's")},
                     {"space": "docs", "op": "format-disk", "path": "x"}):
            with self.assertRaises((syncer.SyncError, portable.PathRefused), msg=str(args)):
                h["sync.apply"](args)
        self.assertEqual((self.rb / "secret.txt").read_text(), "s")                          # untouched by all of it

    def test_manifest_paging_covers_a_big_tree_and_is_consistent(self):
        for i in range(3200):
            (self.rb / f"f{i:05d}").write_bytes(b"x")
        h = syncer.make_handlers(lambda n: self.rb)
        seen, after = [], ""
        while True:
            d = h["sync.read"]({"space": "docs", "mode": "manifest", "after": after, "limit": syncer.PAGE})
            seen += list(d["files"])
            after = d["next"]
            if not after:
                break
        self.assertEqual(len(seen), 3200)
        self.assertEqual(seen, sorted(set(seen)))


class TestBaseFile(unittest.TestCase):
    def test_the_base_round_trips_and_a_hostile_base_file_is_ignored_entry_by_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = {"a.txt": sha(b"a")}
            syncer.save_base(Path(tmp), "peer1", "docs", good)
            self.assertEqual(syncer.load_base(Path(tmp), "peer1", "docs"), good)
            f = Path(tmp) / "sync" / "peer1" / "docs.json"
            f.write_text('{"a.txt": "%s", "../x": "%s", "b": "short", "c": 5}' % (sha(b"a"), sha(b"b")))
            self.assertEqual(syncer.load_base(Path(tmp), "peer1", "docs"), good)
            f.write_text("not json")
            self.assertEqual(syncer.load_base(Path(tmp), "peer1", "docs"), {})
            self.assertEqual(syncer.load_base(Path(tmp), "nobody", "docs"), {})
            self.assertEqual(oct(os.stat(f.parent).st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main()
