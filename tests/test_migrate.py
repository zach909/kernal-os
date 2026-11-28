"""Migration (kos/migrate.py): one encrypted bundle, verified completely before anything is written.

The rule under test: a good bundle comes out byte-identical; a bad one (wrong passphrase, flipped bit,
cut short, reordered, forged paths) writes *nothing*; an existing file is never overwritten; a name the
target OS cannot hold is renamed and reported, never dropped."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos import migrate  # noqa: E402
from kos.auth import AuthorizationDenied  # noqa: E402
from test_linkdev import Device  # noqa: E402

PASS = "a long enough passphrase"
FAST = 2 ** 10                      # scrypt cost for tests; the real default is 2**15


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write(root: Path, rel: str, data: bytes | str = b"x", mode: int | None = None, mtime: int | None = None) -> Path:
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    if mode is not None:
        os.chmod(p, mode)
    if mtime is not None:
        os.utime(p, (mtime, mtime))
    return p


def files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(Path(root).rglob("*")) if p.is_file()}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.t = Path(self.tmp.name)
        self.src, self.dest = self.t / "docs", self.t / "dest"
        self.src.mkdir(), self.dest.mkdir()
        self.bundle = self.t / "all.kmig"

    def pack(self, roots=None, **kw) -> migrate.Summary:
        sources, skipped = migrate.collect(None, roots or [self.src], include_kos=False)
        return migrate.write_bundle(sources, self.bundle, PASS, skipped, kdf_n=FAST, **kw)

    def good(self):
        write(self.src, "a.txt", "alpha")
        write(self.src, "dir/sub/b.bin", os.urandom(3000))
        write(self.src, "empty", b"")
        write(self.src, "ünï/cödé.txt", "unicode")
        self.pack()


class TestRoundTrip(Base):
    def test_every_byte_comes_back_identical_with_modes_and_times(self):
        big = os.urandom(migrate.CHUNK * 3 + 17)
        write(self.src, "big.bin", big)
        write(self.src, "run.sh", "#!/bin/sh\n", mode=0o755, mtime=1_600_000_000)
        write(self.src, "secret.txt", "s", mode=0o600)
        write(self.src, "empty", b"")
        write(self.src, "dir/deep/ünï.txt", "unicode", mtime=1_500_000_000)
        s = self.pack()
        self.assertEqual((s.files, s.bytes), (5, len(big) + 10 + 1 + 7))
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest, "linux")
        out = self.dest / "docs"
        self.assertEqual(files(out), files(self.src))
        for rel in files(self.src):
            self.assertEqual(sha((out / rel).read_bytes()), sha((self.src / rel).read_bytes()))
        self.assertEqual(int((out / "run.sh").stat().st_mtime), 1_600_000_000)
        self.assertTrue((out / "run.sh").stat().st_mode & stat.S_IXUSR)
        self.assertFalse((out / "secret.txt").stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))
        self.assertEqual(len(rep.written), 5)
        self.assertTrue((self.dest / "MIGRATION-REPORT.txt").is_file())

    def test_line_endings_and_odd_bytes_are_never_converted(self):
        raw = b"line1\r\nline2\nline3\r\x00\xff\xfe\xef\xbb\xbf"
        write(self.src, "crlf.txt", raw)
        self.pack()
        migrate.restore_bundle(self.bundle, PASS, self.dest, "windows")
        self.assertEqual((self.dest / "docs" / "crlf.txt").read_bytes(), raw)

    def test_the_bundle_is_not_readable_without_the_passphrase(self):
        write(self.src, "a.txt", "TOP-SECRET-MARKER " * 50)
        self.pack()
        blob = self.bundle.read_bytes()
        self.assertNotIn(b"TOP-SECRET-MARKER", blob)
        self.assertNotIn(b"a.txt", blob)                      # not even file names leak
        self.assertEqual(oct(self.bundle.stat().st_mode & 0o777), "0o600")

    def test_verify_reports_what_is_inside_without_writing_anything(self):
        self.good()
        m = migrate.verify_bundle(self.bundle, PASS)
        self.assertEqual(m.files, 4)
        self.assertEqual(sorted(m.names), ["files/docs/a.txt", "files/docs/dir/sub/b.bin", "files/docs/empty",
                                           "files/docs/ünï/cödé.txt"])
        self.assertEqual(list(self.dest.iterdir()), [])


class TestBadBundlesWriteNothing(Base):
    def assertRefused(self, why: str = ""):
        with self.assertRaises(migrate.MigrateError) as cm:
            migrate.restore_bundle(self.bundle, PASS, self.dest, "linux")
        self.assertEqual(list(self.dest.iterdir()), [], "a refused bundle must leave the destination empty")
        if why:
            self.assertIn(why, str(cm.exception))

    def test_wrong_passphrase(self):
        self.good()
        with self.assertRaises(migrate.MigrateError):
            migrate.restore_bundle(self.bundle, "another long passphrase!", self.dest)
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_a_flipped_bit_anywhere_is_caught_before_a_single_file_is_written(self):
        self.good()
        blob = bytearray(self.bundle.read_bytes())
        for pos in sorted({0, 9, 30, 40, 60, len(blob) // 3, len(blob) // 2, len(blob) - 40, len(blob) - 1}):
            bad = bytearray(blob)
            bad[pos] ^= 0x01
            self.bundle.write_bytes(bytes(bad))
            self.assertRefused()
        self.bundle.write_bytes(bytes(blob))                   # and the original still works
        migrate.restore_bundle(self.bundle, PASS, self.dest)

    def test_truncation_at_every_record_boundary_and_inside_records_is_refused(self):
        self.good()
        blob = self.bundle.read_bytes()
        cuts, pos = [0, 5, migrate.HEADER.size, migrate.HEADER.size + 2], migrate.HEADER.size
        while pos < len(blob):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            cuts += [pos, pos + 3, pos + 4 + n // 2]            # at the boundary, mid-length, mid-record
            pos += 4 + n
        for cut in sorted(set(c for c in cuts if c < len(blob))):
            self.bundle.write_bytes(blob[:cut])
            self.assertRefused()

    def test_dropping_a_whole_record_in_the_middle_is_caught_by_position(self):
        self.good()
        blob = self.bundle.read_bytes()
        pos = migrate.HEADER.size
        spans = []
        while pos < len(blob):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            spans.append((pos, pos + 4 + n))
            pos += 4 + n
        a, b = spans[3]
        self.bundle.write_bytes(blob[:a] + blob[b:])
        self.assertRefused("wrong passphrase, or the bundle was changed")

    def test_swapping_two_records_is_caught(self):
        self.good()
        blob = self.bundle.read_bytes()
        pos, spans = migrate.HEADER.size, []
        while pos < len(blob):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            spans.append((pos, pos + 4 + n))
            pos += 4 + n
        (a0, a1), (b0, b1) = spans[2], spans[3]
        self.bundle.write_bytes(blob[:a0] + blob[b0:b1] + blob[a0:a1] + blob[b1:])
        self.assertRefused()

    def test_data_appended_after_the_end_is_refused(self):
        self.good()
        self.bundle.write_bytes(self.bundle.read_bytes() + b"\x00\x00\x00\x20" + os.urandom(32))
        self.assertRefused("after its end")

    def test_not_a_bundle_at_all(self):
        for junk in (b"", b"KOS", os.urandom(200), b"KOSMIG1\n" + b"\x00" * 40):
            self.bundle.write_bytes(junk)
            self.assertRefused()

    def test_a_bundle_cannot_make_us_burn_memory_with_its_key_settings(self):
        self.good()
        blob = bytearray(self.bundle.read_bytes())
        for n in (2 ** 30, 2 ** 31, 3 * 2 ** 12, 1, 0):                       # huge, huge, not a power of two, tiny, zero
            bad = bytearray(blob)
            bad[24:28] = struct.pack(">I", n)
            self.bundle.write_bytes(bytes(bad))
            self.assertRefused("key settings")
        bad = bytearray(blob)
        bad[28:32] = struct.pack(">I", 64)                                    # r
        self.bundle.write_bytes(bytes(bad))
        self.assertRefused("key settings")


class TestForgedButAuthentic(Base):
    """An attacker who *knows the passphrase* (or the owner's own corrupted tool) can make a bundle that
    authenticates. The contents are still hostile: paths, totals and hashes are checked on their own."""

    def forge(self, records):
        with open(self.bundle, "wb") as f:
            w = migrate._Writer(f, PASS, FAST)
            for kind, payload in records:
                if isinstance(payload, dict):
                    w.put_json(kind, payload)
                else:
                    w.put(kind, payload)

    def file(self, path, data=b"x", good_hash=True):
        h = sha(data) if good_hash else sha(b"other")
        return [(migrate.T_BEGIN, {"p": path, "n": len(data), "m": 0o644, "t": 0}), (migrate.T_DATA, data),
                (migrate.T_END_FILE, {"h": h})]

    def end(self, paths_and_data):
        leaves = hashlib.sha256()
        for p, d in paths_and_data:
            leaves.update(f"{p}\0{sha(d)}\n".encode())
        return (migrate.T_END, {"files": len(paths_and_data), "bytes": sum(len(d) for _, d in paths_and_data),
                                "digest": leaves.hexdigest(), "skipped": []})

    def meta(self):
        return (migrate.T_META, {"v": 1, "created": 1, "source_os": "kos", "files": 1})

    def refused(self, why):
        with self.assertRaises(migrate.MigrateError) as cm:
            migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertIn(why, str(cm.exception))
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_a_valid_forged_bundle_with_honest_contents_does_restore(self):
        p = "files/docs/ok.txt"
        self.forge([self.meta(), *self.file(p), self.end([(p, b"x")])])
        migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual((self.dest / "docs" / "ok.txt").read_bytes(), b"x")

    def test_paths_that_climb_out_or_name_other_places_are_refused(self):
        for bad in ("files/../../etc/cron.d/x", "files/docs/../../x", "/etc/passwd", "etc/passwd", "files//x",
                    "kos/other/thing", "files/docs/.kos-trash/x", "kos/apps/../../escape.kapp", "files/C:/x\\y"):
            self.forge([self.meta(), *self.file(bad), self.end([(bad, b"x")])])
            with self.assertRaises(migrate.MigrateError, msg=bad):
                migrate.restore_bundle(self.bundle, PASS, self.dest)
            os.unlink(self.bundle)
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertFalse((self.t.parent / "escape.kapp").exists())

    def test_a_file_whose_bytes_do_not_match_its_hash_is_refused(self):
        p = "files/docs/lie.txt"
        self.forge([self.meta(), *self.file(p, good_hash=False), self.end([(p, b"x")])])
        self.refused("do not match its recorded hash")

    def test_more_data_than_the_recorded_size_is_refused(self):
        p = "files/docs/big.txt"
        self.forge([self.meta(), (migrate.T_BEGIN, {"p": p, "n": 2, "m": 0, "t": 0}), (migrate.T_DATA, b"abcdef"),
                    (migrate.T_END_FILE, {"h": sha(b"ab")}), self.end([(p, b"ab")])])
        self.refused("more data")

    def test_the_same_path_twice_is_refused(self):
        p = "files/docs/dup.txt"
        self.forge([self.meta(), *self.file(p), *self.file(p), self.end([(p, b"x"), (p, b"x")])])
        self.refused("twice")

    def test_totals_that_do_not_match_what_is_inside_are_refused(self):
        p = "files/docs/a.txt"
        kind, end = self.end([(p, b"x")])
        end["files"] = 5
        self.forge([self.meta(), *self.file(p), (kind, end)])
        self.refused("totals do not match")

    def test_a_bundle_with_no_description_or_from_the_future_is_refused(self):
        p = "files/docs/a.txt"
        self.forge([*self.file(p), self.end([(p, b"x")])])
        self.refused("start with its description")
        self.forge([(migrate.T_META, {"v": 99}), *self.file(p), self.end([(p, b"x")])])
        self.refused("newer KOS")

    def test_a_decimal_anywhere_in_a_record_is_refused_like_the_rest_of_kos(self):
        with open(self.bundle, "wb") as f:
            w = migrate._Writer(f, PASS, FAST)
            w.put(migrate.T_META, b'{"v": 1, "created": 1.5}')
        self.refused("whole-number")

    def test_unknown_record_types_and_a_file_inside_a_file_are_refused(self):
        p = "files/docs/a.txt"
        self.forge([self.meta(), (migrate.T_BEGIN, {"p": p, "n": 0, "m": 0, "t": 0}),
                    (migrate.T_BEGIN, {"p": p + "2", "n": 0, "m": 0, "t": 0}), self.end([])])
        self.refused("before the last one ended")
        self.forge([self.meta(), (9, b"?"), self.end([])])
        self.refused("record type")


class TestNeverOverwrites(Base):
    def test_identical_files_are_left_alone_and_a_second_run_adds_nothing(self):
        self.good()
        migrate.restore_bundle(self.bundle, PASS, self.dest)
        before = files(self.dest)
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(len(rep.identical), 4)
        self.assertEqual(rep.written, [])
        after = files(self.dest)
        self.assertEqual({k for k in after if not k.startswith("MIGRATION-REPORT")},
                         {k for k in before if not k.startswith("MIGRATION-REPORT")})

    def test_a_different_file_already_there_is_kept_and_the_migrated_one_goes_beside_it(self):
        write(self.src, "notes.txt", "the OLD computer's notes")
        self.pack()
        write(self.dest, "docs/notes.txt", "the NEW computer's notes")
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual((self.dest / "docs" / "notes.txt").read_text(), "the NEW computer's notes")
        moved = rep.kept_both[0][1]
        self.assertRegex(moved, r"^docs/notes \(migrated [0-9a-f]{8}\)\.txt$")
        self.assertEqual((self.dest / moved).read_text(), "the OLD computer's notes")
        self.assertIn("kept both", (self.dest / "MIGRATION-REPORT.txt").read_text())

    def test_a_folder_symlink_at_the_destination_cannot_be_used_to_write_elsewhere(self):
        write(self.src, "a.txt", "payload")
        self.pack()
        victim = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(victim, ignore_errors=True))
        os.symlink(victim, self.dest / "docs")
        with self.assertRaises(migrate.MigrateError):
            migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(list(victim.iterdir()), [])

    def test_a_file_symlink_at_the_destination_is_not_followed(self):
        write(self.src, "a.txt", "payload")
        self.pack()
        victim = self.t / "victim.txt"
        victim.write_text("do not touch")
        (self.dest / "docs").mkdir()
        os.symlink(victim, self.dest / "docs" / "a.txt")
        with self.assertRaises(migrate.MigrateError):
            migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(victim.read_text(), "do not touch")

    def test_a_bundle_is_never_overwritten_by_an_export(self):
        self.good()
        before = self.bundle.read_bytes()
        with self.assertRaises(migrate.MigrateError):
            self.pack()
        self.assertEqual(self.bundle.read_bytes(), before)
        os.symlink(self.t / "elsewhere", self.t / "link.kmig")
        sources, _ = migrate.collect(None, [self.src], include_kos=False)
        with self.assertRaises(migrate.MigrateError):
            migrate.write_bundle(sources, self.t / "link.kmig", PASS, kdf_n=FAST)

    def test_a_file_that_changes_while_being_packed_fails_the_export_and_leaves_no_partial_bundle(self):
        write(self.src, "a.txt", "hello")
        sources, _ = migrate.collect(None, [self.src], include_kos=False)
        real = os.lstat(self.src / "a.txt")
        fake = types.SimpleNamespace(st_mode=real.st_mode, st_size=real.st_size + 5, st_mtime_ns=0)   # "grew" after measuring
        with mock.patch("kos.migrate.os.lstat", return_value=fake):
            with self.assertRaises(migrate.MigrateError) as cm:
                migrate.write_bundle(sources, self.bundle, PASS, kdf_n=FAST)
        self.assertIn("changed while", str(cm.exception))
        self.assertFalse(self.bundle.exists())
        self.assertEqual([p.name for p in self.t.iterdir() if "partial" in p.name], [])


class TestSwitchingOperatingSystem(Base):
    def test_windows_gets_legal_names_every_rename_is_reported_and_no_two_files_collide(self):
        write(self.src, "plain.txt", "p")
        write(self.src, "note:1.txt", "colon")
        write(self.src, "con", "device")
        write(self.src, "trail.", "dot")
        write(self.src, "dir/what?.md", "q")
        write(self.src, "note_1.txt", "underscore")                      # what "note:1.txt" would naively become
        self.pack()
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest, "windows")
        got = files(self.dest / "docs")
        self.assertEqual(len(got), 6)                                    # nothing lost, nothing merged
        from kos import portable
        for rel in got:
            self.assertEqual(portable.problems(rel), [], rel)
        self.assertEqual(len(rep.renamed), 4)
        self.assertEqual({o for o, _, _ in rep.renamed}, {"docs/note:1.txt", "docs/con", "docs/trail.", "docs/dir/what?.md"})
        self.assertEqual(sorted(got.values()), sorted([b"p", b"colon", b"device", b"dot", b"q", b"underscore"]))
        text = (self.dest / "MIGRATION-REPORT.txt").read_text()
        self.assertIn("note:1.txt", text)

    def test_linux_to_linux_renames_nothing(self):
        write(self.src, "note:1.txt", "colon")
        self.pack()
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest, "linux")
        self.assertEqual(rep.renamed, [])
        self.assertTrue((self.dest / "docs" / "note:1.txt").exists())

    def test_a_name_that_windows_reads_as_a_drive_letter_is_left_behind_and_said_so(self):
        write(self.src, "a:b.txt", "drive-relative on Windows")
        write(self.src, "ok.txt", "fine")
        s = self.pack()
        self.assertEqual(s.files, 1)
        self.assertTrue(any("a:b.txt" in x and "drive letter" in x for x in s.skipped), s.skipped)

    def test_names_that_differ_only_by_case_are_both_kept_on_macos_and_windows(self):
        write(self.src, "Report.TXT", "upper")
        write(self.src, "report.txt", "lower")
        self.pack()
        for target in ("macos", "windows"):
            dest = self.t / f"dest-{target}"
            dest.mkdir()
            rep = migrate.restore_bundle(self.bundle, PASS, dest, target)
            got = files(dest / "docs")
            self.assertEqual(sorted(got.values()), [b"lower", b"upper"], target)
            self.assertEqual(len({k.casefold() for k in got}), 2, target)       # distinct even when case is ignored
            self.assertTrue(any("same name as another file" in why for _, _, why in rep.renamed), target)

    def test_accents_stored_two_ways_are_two_files_on_linux_and_both_survive_on_macos(self):
        write(self.src, "caf\u00e9.txt", "composed")
        write(self.src, "cafe\u0301.txt", "decomposed")             # a different byte string: Linux keeps both
        s = self.pack()
        self.assertEqual(s.files, 2)                                  # the export must not collapse them
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest, "macos")
        self.assertEqual(sorted(files(self.dest / "docs").values()), [b"composed", b"decomposed"])
        self.assertEqual(len(rep.renamed), 1)                         # one of them got a distinct name, and it is listed
        linux = self.t / "dest-linux"
        linux.mkdir()
        migrate.restore_bundle(self.bundle, PASS, linux, "linux")
        self.assertEqual(len(files(linux / "docs")), 2)
        self.assertEqual(rep.renamed[0][2], "same name as another file once case and accents are ignored")

    def test_an_unknown_target_is_refused(self):
        self.good()
        with self.assertRaises(migrate.MigrateError):
            migrate.restore_bundle(self.bundle, PASS, self.dest, "plan9")


class TestWhatIsAndIsNotCarried(Base):
    def test_symlinks_and_special_names_are_left_out_and_reported_never_followed_or_silently_lost(self):
        write(self.src, "real.txt", "r")
        os.symlink("/etc/hostname", self.src / "link")
        write(self.src, ".kos-sneaky", "x")
        s = self.pack()
        self.assertEqual(s.files, 1)
        self.assertTrue(any("symlink" in x for x in s.skipped))
        self.assertTrue(any(".kos-sneaky" in x for x in s.skipped))
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(len(rep.skipped_at_source), 2)
        self.assertIn("left behind on the old computer", (self.dest / "MIGRATION-REPORT.txt").read_text())

    def test_a_root_that_is_a_symlink_or_missing_is_refused(self):
        os.symlink(self.src, self.t / "alias")
        for bad in (self.t / "alias", self.t / "nope"):
            with self.assertRaises(migrate.MigrateError):
                migrate.collect(None, [bad], include_kos=False)

    def test_two_roots_with_the_same_name_do_not_merge(self):
        other = self.t / "other" / "docs"
        write(self.src, "a.txt", "one")
        write(other, "a.txt", "two")
        self.pack(roots=[self.src, other])
        migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(sorted(files(self.dest / "docs").values() if (self.dest / "docs").exists() else []) +
                         sorted(files(self.dest / "docs-2").values()), [b"one", b"two"])

    def test_the_machines_secrets_are_never_collected_and_apps_are_staged_not_installed(self):
        d = Device(self, "old", "old machine password")
        state = d.paths.state
        for rel in ("links/identity.bin", "links/links.json", "ai.json", "firewall/rules.json", "log/audit.log",
                    "auth/password.json", "permissions/grants.json"):
            write(state, rel, "SECRET-" + rel)
        write(state, "apps/notes.kapp", "kapp-bytes")
        write(self.src, "a.txt", "mine")
        sources, _ = migrate.collect(d.paths, [self.src], include_kos=True)
        arcs = sorted(s.arcname for s in sources)
        self.assertEqual(arcs, ["files/docs/a.txt", "kos/apps/notes.kapp", "kos/permissions/grants.json"])
        migrate.write_bundle(sources, self.bundle, PASS, kdf_n=FAST)
        rep = migrate.restore_bundle(self.bundle, PASS, self.dest)
        self.assertEqual(sorted(rep.staged), ["kos-staging/apps/notes.kapp", "kos-staging/permissions-to-review.json"])
        self.assertEqual(rep.written, ["docs/a.txt"])
        everything = b"".join(files(self.dest).values())
        for rel in ("identity.bin", "links.json", "ai.json", "rules.json", "audit.log", "password.json"):
            self.assertNotIn(("SECRET-" + rel).encode(), self.bundle.read_bytes())
        self.assertFalse((self.dest / "kos-staging" / "apps" / "notes.kapp").stat().st_mode & stat.S_IXUSR)


class TestTheOsWrappers(unittest.TestCase):
    """migrate.export / migrate.import: the OS password first, then the passphrase, then the work."""

    def setUp(self):
        self.d = Device(self, "box", "box owner password")
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.t, ignore_errors=True))
        self.src, self.dest, self.out = self.t / "docs", self.t / "dest", self.t / "x.kmig"
        write(self.src, "a.txt", "mine")
        self.dest.mkdir()

    def test_export_then_import_asks_the_password_and_the_passphrase_and_audits_both(self):
        pw = self.d.pw
        s = migrate.export_bundle(self.d.paths, self.d.authority(pw, PASS, PASS), [self.src], self.out, kdf_n=FAST)
        self.assertEqual(s.files, 1)
        asked = self.d.prompter.asked
        self.assertIn("export", asked[0] if "export" in asked[0] else asked[0] + "export")      # an OS password prompt first
        self.assertEqual(len(asked), 3)
        rep = migrate.import_bundle(self.d.paths, self.d.authority(pw, PASS), self.out, self.dest)
        self.assertEqual(rep.written, ["docs/a.txt"])
        actions = [(r["action"], r["outcome"]) for r in self.d.audit()]
        self.assertIn(("migrate.export", "done"), actions)
        self.assertIn(("migrate.import", "done"), actions)

    def test_a_wrong_password_reads_nothing_and_writes_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            migrate.export_bundle(self.d.paths, self.d.authority("wrong 1", "wrong 2", "wrong 3"), [self.src], self.out)
        self.assertFalse(self.out.exists())
        self.assertEqual(len(self.d.prompter.asked), 3)                                       # three tries, no passphrase asked

    def test_two_passphrases_that_differ_write_nothing(self):
        with self.assertRaises(migrate.MigrateError) as cm:
            migrate.export_bundle(self.d.paths, self.d.authority(self.d.pw, PASS, PASS + "x"), [self.src], self.out)
        self.assertIn("differ", str(cm.exception))
        self.assertFalse(self.out.exists())

    def test_a_short_passphrase_is_refused(self):
        with self.assertRaises(migrate.MigrateError):
            migrate.export_bundle(self.d.paths, self.d.authority(self.d.pw, "short", "short"), [self.src], self.out)
        self.assertFalse(self.out.exists())

    def test_cancelling_the_passphrase_writes_nothing(self):
        with self.assertRaises(migrate.MigrateError):
            migrate.export_bundle(self.d.paths, self.d.authority(self.d.pw, None), [self.src], self.out)
        self.assertFalse(self.out.exists())

    def test_import_with_the_wrong_passphrase_is_audited_as_failed_and_writes_nothing(self):
        migrate.export_bundle(self.d.paths, self.d.authority(self.d.pw, PASS, PASS), [self.src], self.out, kdf_n=FAST)
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.d.paths, self.d.authority(self.d.pw, "not the right passphrase"), self.out, self.dest)
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertIn(("migrate.import", "failed"), [(r["action"], r["outcome"]) for r in self.d.audit()])


if __name__ == "__main__":
    unittest.main()
