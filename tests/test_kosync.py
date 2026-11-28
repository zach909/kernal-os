"""kosync: the portable migration and sync client (clients/kosync).

Mostly refusal tests: every byte that comes from a bundle or a shared folder is hostile input."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "clients" / "kosync"))

from kosync import apps, migrate, paths as P, sync as S  # noqa: E402
from kosync.crypto import (CHUNK, CryptoError, check_kdf, decrypt_stream, encrypt_stream,  # noqa: E402
                           master_key, subkey)

FAST = {"n": 4096, "r": 8, "p": 1}
PW = "correct horse battery"


def seal(key, aad, data, salt=None):
    out = io.BytesIO()
    encrypt_stream(key, aad, io.BytesIO(data), out, _salt=salt)
    return out.getvalue()


def unseal(key, aad, blob):
    out = io.BytesIO()
    decrypt_stream(key, aad, io.BytesIO(blob), out)
    return out.getvalue()


class TestStream(unittest.TestCase):
    key = bytes(range(32))

    def test_round_trip_at_every_chunk_edge(self):
        for n in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 5):
            data = os.urandom(n)
            self.assertEqual(unseal(self.key, b"a", seal(self.key, b"a", data)), data, n)

    def test_any_changed_byte_is_refused(self):
        blob = seal(self.key, b"a", b"hello world" * 100)
        for i in (0, 15, 16, 20, len(blob) - 1):
            bad = bytearray(blob)
            bad[i] ^= 1
            with self.assertRaises(CryptoError, msg=i):
                unseal(self.key, b"a", bytes(bad))

    def test_wrong_key_wrong_aad_are_refused(self):
        blob = seal(self.key, b"a", b"x")
        with self.assertRaises(CryptoError):
            unseal(bytes(32), b"a", blob)
        with self.assertRaises(CryptoError):
            unseal(self.key, b"b", blob)

    def test_cut_at_a_chunk_boundary_is_refused(self):
        blob = seal(self.key, b"a", os.urandom(2 * CHUNK + 10))
        first_len = 16 + 4 + int.from_bytes(blob[16:20], "big")
        with self.assertRaises(CryptoError):            # a clean cut after chunk 1: the 'last' flag is missing
            unseal(self.key, b"a", blob[:first_len])
        with self.assertRaises(CryptoError):
            unseal(self.key, b"a", blob[:-1])
        with self.assertRaises(CryptoError):
            unseal(self.key, b"a", blob[:10])

    def test_extended_reordered_and_duplicated_streams_are_refused(self):
        blob = seal(self.key, b"a", os.urandom(2 * CHUNK + 10))
        with self.assertRaises(CryptoError):
            unseal(self.key, b"a", blob + b"\x00")
        with self.assertRaises(CryptoError):
            unseal(self.key, b"a", blob + blob[16:])
        l1 = 4 + int.from_bytes(blob[16:20], "big")
        c1, rest = blob[16:16 + l1], blob[16 + l1:]
        l2 = 4 + int.from_bytes(rest[:4], "big")
        swapped = blob[:16] + rest[:l2] + c1 + rest[l2:]
        with self.assertRaises(CryptoError):
            unseal(self.key, b"a", swapped)

    def test_every_stream_gets_its_own_salt(self):
        self.assertNotEqual(seal(self.key, b"a", b"same")[:16], seal(self.key, b"a", b"same")[:16])

    def test_fixed_vector_so_other_languages_can_check_themselves(self):
        v = json.loads((ROOT / "clients" / "kosync" / "vectors.json").read_text())
        key = bytes.fromhex(v["key"])
        blob = seal(key, bytes.fromhex(v["aad"]), bytes.fromhex(v["plaintext"]), salt=bytes.fromhex(v["salt"]))
        self.assertEqual(blob.hex(), v["stream"])
        self.assertEqual(unseal(key, bytes.fromhex(v["aad"]), bytes.fromhex(v["stream"])).hex(), v["plaintext"])
        m = v["master"]
        mk = master_key(m["password"], bytes.fromhex(m["salt"]), m["kdf"])
        self.assertEqual(mk.hex(), m["master_key"])
        self.assertEqual(subkey(mk, "bundle").hex(), m["bundle_key"])

    def test_hostile_key_settings_are_refused(self):
        for bad in ({"n": 3, "r": 8, "p": 1}, {"n": 1 << 30, "r": 8, "p": 1}, {"n": 4096, "r": 64, "p": 1},
                    {"n": 4096, "r": 8, "p": 99}, {"n": 4096.0, "r": 8, "p": 1}, {"n": "4096", "r": 8, "p": 1}, {}):
            with self.assertRaises(CryptoError):
                check_kdf(bad)


class TestPaths(unittest.TestCase):
    def test_windows_gets_legal_names_and_reports_every_change(self):
        got = P.plan(["Docs/CON.txt", "Docs/a:b?.txt", "trail. /f", "nul", "ok.txt"], "windows")
        self.assertEqual(got["Docs/CON.txt"], "Docs/_CON.txt")
        self.assertEqual(got["Docs/a:b?.txt"], "Docs/a_b_.txt")
        self.assertEqual(got["trail. /f"], "trail/f")
        self.assertEqual(got["nul"], "_nul")
        self.assertEqual(got["ok.txt"], "ok.txt")

    def test_names_that_collide_after_cleaning_or_by_case_are_both_kept(self):
        got = P.plan(["a:b", "a_b", "X", "x"], "windows")
        self.assertEqual(len(set(map(str.casefold, got.values()))), 4)
        got = P.plan(["X", "x"], "macos")
        self.assertEqual(len(set(map(str.casefold, got.values()))), 2)
        self.assertEqual(P.plan(["X", "x"], "linux"), {"X": "X", "x": "x"})

    def test_a_renamed_folder_takes_its_files_with_it(self):
        got = P.plan(["bad:dir/one", "bad:dir/two", "bad_dir/three"], "windows")
        self.assertEqual(got["bad:dir/one"].split("/")[0], got["bad:dir/two"].split("/")[0])
        self.assertNotEqual(got["bad:dir/one"].split("/")[0].casefold(), got["bad_dir/three"].split("/")[0].casefold())

    def test_result_does_not_depend_on_order(self):
        a = ["x", "X", "a:b", "a_b", "d/y", "D/y"]
        self.assertEqual(P.plan(a, "windows"), P.plan(list(reversed(a)), "windows"))

    def test_hostile_paths_are_refused(self):
        for bad in ("", "/etc/passwd", "../x", "a/../../x", "a//b", "a/./b", "a\x00b", "a\nb", "x" * 5000, None, 5):
            with self.assertRaises(P.PathError, msg=repr(bad)):
                P.validate(bad)

    def test_long_names_are_cut_keeping_the_extension(self):
        new = P.plan(["a" * 300 + ".txt"], "windows")["a" * 300 + ".txt"]
        self.assertLessEqual(len(new), 255)
        self.assertTrue(new.endswith(".txt"))

    def test_unknown_os_refused(self):
        with self.assertRaises(P.PathError):
            P.plan(["a"], "plan9")


def tree(root):
    return {str(p.relative_to(root)).replace(os.sep, "/"): (p.read_bytes() if p.is_file() else None)
            for p in sorted(Path(root).rglob("*"))}


class MigrateBase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.src = self.t / "src"
        (self.src / "sub").mkdir(parents=True)
        (self.src / "a.txt").write_text("alpha")
        (self.src / "sub" / "b:c.txt").write_text("beta")
        (self.src / "empty").write_bytes(b"")
        (self.src / "big.bin").write_bytes(os.urandom(CHUNK + 123))
        (self.src / "emptydir").mkdir()
        self.bundle = self.t / "x.kmig"

    def tearDown(self):
        self._t.cleanup()

    def export(self, **kw):
        return migrate.export_bundle({"documents": self.src}, self.bundle, PW, kdf=FAST, source_os="linux", **kw)


class TestMigrate(MigrateBase):
    def test_round_trip_keeps_every_file_byte_for_byte(self):
        rep = self.export()
        self.assertEqual((rep.files, rep.dirs), (4, 2))
        dst = self.t / "dst"
        migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="linux")
        self.assertEqual(tree(dst), tree(self.src))

    def test_moving_to_windows_fixes_names_and_says_so(self):
        self.export()
        dst = self.t / "dst"
        rep = migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="windows")
        self.assertEqual(rep.renamed, [("documents/sub/b:c.txt", "documents/sub/b_c.txt")])
        self.assertEqual((dst / "sub" / "b_c.txt").read_text(), "beta")
        self.assertFalse(list(dst.glob(".kosync-import-*")), "the staging folder is removed")

    def test_dry_run_and_inspect_write_nothing_but_verify_everything(self):
        self.export()
        dst = self.t / "dst"
        rep = migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="windows", dry_run=True)
        self.assertEqual(rep.files, 4)
        self.assertFalse(dst.exists())
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.bundle, {"documents": dst}, "wrong password", dry_run=True)

    def test_wrong_password_writes_nothing(self):
        self.export()
        dst = self.t / "dst"
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.bundle, {"documents": dst}, "not the password", target_os="linux")
        self.assertFalse(dst.exists())

    def test_a_damaged_or_cut_bundle_leaves_the_destination_untouched(self):
        self.export()
        raw = self.bundle.read_bytes()
        for name, bad in (("flip", raw[:-5] + bytes([raw[-5] ^ 1]) + raw[-4:]), ("cut", raw[:-40]),
                          ("magic", b"X" + raw[1:]), ("garbage", b"not a bundle"), ("empty", b""),
                          ("extend", raw + b"zz")):
            f = self.t / f"bad-{name}.kmig"
            f.write_bytes(bad)
            dst = self.t / f"dst-{name}"
            with self.assertRaises(migrate.MigrateError, msg=name):
                migrate.import_bundle(f, {"documents": dst}, PW, target_os="linux")
            self.assertEqual(tree(dst) if dst.exists() else {}, {}, name)

    def test_the_header_is_authenticated(self):
        self.export()
        raw = bytearray(self.bundle.read_bytes())
        i = raw.index(b'"p":1')                       # a plain-text field of the header
        raw[i + 4] = ord("2")
        self.bundle.write_bytes(bytes(raw))
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.bundle, {"documents": self.t / "d"}, PW)

    def test_symlinks_are_listed_as_skipped_and_never_followed(self):
        secret = self.t / "secret.txt"
        secret.write_text("TOP SECRET")
        os.symlink(secret, self.src / "link.txt")
        os.symlink(self.t, self.src / "dirlink")
        rep = self.export()
        self.assertEqual({p for p, _ in rep.skipped}, {"documents/link.txt", "documents/dirlink"})
        dst = self.t / "dst"
        migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="linux")
        self.assertFalse((dst / "link.txt").exists())
        self.assertNotIn(b"TOP SECRET", self.bundle.read_bytes())

    def test_export_never_overwrites_and_cleans_up_when_a_file_changes(self):
        self.export()
        with self.assertRaises(migrate.MigrateError):
            self.export()
        real = migrate._scan

        def lying(role, root, report):
            ents = real(role, root, report)
            for e in ents:
                if e["kind"] == "file":
                    e["sha256"] = "0" * 64
            return ents
        migrate._scan = lying
        try:
            out = self.t / "y.kmig"
            with self.assertRaises(migrate.MigrateError):
                migrate.export_bundle({"documents": self.src}, out, PW, kdf=FAST)
        finally:
            migrate._scan = real
        self.assertFalse(out.exists())
        self.assertFalse(list(self.t.glob("y.kmig.part-*")))

    def test_import_never_overwrites(self):
        self.export()
        dst = self.t / "dst"
        dst.mkdir()
        (dst / "a.txt").write_text("MINE")                   # different: keep both
        (dst / "empty").write_bytes(b"")                     # identical: leave alone
        rep = migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="linux")
        self.assertEqual((dst / "a.txt").read_text(), "MINE")
        self.assertEqual((dst / "a (imported 1).txt").read_text(), "alpha")
        self.assertEqual(rep.already_there, 1)
        self.assertEqual(rep.kept_both, [("a.txt", "a (imported 1).txt")])

    def test_overwrite_is_only_done_when_asked(self):
        self.export()
        dst = self.t / "dst"
        dst.mkdir()
        (dst / "a.txt").write_text("MINE")
        migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="linux", overwrite=True)
        self.assertEqual((dst / "a.txt").read_text(), "alpha")

    def test_import_refuses_to_write_through_a_symlink(self):
        self.export()
        outside = self.t / "outside"
        outside.mkdir()
        dst = self.t / "dst"
        dst.mkdir()
        os.symlink(outside, dst / "sub")
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.bundle, {"documents": dst}, PW, target_os="linux")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(list(dst.glob(".kosync-import-*")))

    def test_a_bundle_with_a_hostile_manifest_is_refused(self):
        """An attacker who knows the password could still not make an import write outside its folder."""
        salt = bytes(16)
        header = json.dumps({"v": 1, "kdf": {"alg": "scrypt", **FAST}, "salt": salt.hex()},
                            sort_keys=True, separators=(",", ":")).encode()
        key = subkey(master_key(PW, salt, FAST), "bundle")
        for evil in ("../escape", "/abs", "a/../../b", "a\x00b"):
            body = b"x"
            import hashlib
            entry = {"role": "documents", "path": evil, "kind": "file", "size": 1,
                     "sha256": hashlib.sha256(body).hexdigest(), "mode": 420, "mtime": 0}
            man = json.dumps({"format": 1, "entries": [entry]}).encode()
            plain = len(man).to_bytes(4, "big") + man + body
            f = self.t / "evil.kmig"
            f.write_bytes(migrate.MAGIC + len(header).to_bytes(4, "big") + header
                          + seal(key, migrate.MAGIC + header, plain))
            with self.assertRaises(migrate.MigrateError, msg=evil):
                migrate.import_bundle(f, {"documents": self.t / "d"}, PW)
            self.assertFalse((self.t / "escape").exists())

    def craft(self, entries, bodies, trailing=b"", name="crafted.kmig"):
        """An authentic bundle (made with the right password) whose manifest says whatever the test wants."""
        import hashlib
        salt = bytes(16)
        header = json.dumps({"v": 1, "kdf": {"alg": "scrypt", **FAST}, "salt": salt.hex()},
                            sort_keys=True, separators=(",", ":")).encode()
        key = subkey(master_key(PW, salt, FAST), "bundle")
        ents = []
        for e, body in zip(entries, bodies):
            ents.append({"role": "documents", "mode": 420, "mtime": 0, **e,
                         **({"size": len(body), "sha256": hashlib.sha256(body).hexdigest()} if e["kind"] == "file" else {})})
        man = json.dumps({"format": 1, "entries": ents}).encode()
        f = self.t / name
        f.write_bytes(migrate.MAGIC + len(header).to_bytes(4, "big") + header
                      + seal(key, migrate.MAGIC + header, len(man).to_bytes(4, "big") + man + b"".join(bodies) + trailing))
        return f

    def test_a_symlinked_folder_is_refused_even_when_the_bundle_lists_no_folder_entry(self):
        outside = self.t / "outside"
        outside.mkdir()
        dst = self.t / "dst"
        dst.mkdir()
        os.symlink(outside, dst / "sub")
        f = self.craft([{"path": "sub/f.txt", "kind": "file"}], [b"data"])
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(f, {"documents": dst}, PW, target_os="linux")
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_file_where_a_folder_is_needed_is_refused(self):
        dst = self.t / "dst"
        dst.mkdir()
        (dst / "sub").write_text("i am a file")
        f = self.craft([{"path": "sub/f.txt", "kind": "file"}], [b"data"])
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(f, {"documents": dst}, PW, target_os="linux")
        self.assertEqual((dst / "sub").read_text(), "i am a file")

    def test_data_after_the_last_file_is_refused(self):
        f = self.craft([{"path": "f", "kind": "file"}], [b"data"], trailing=b"smuggled")
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(f, {"documents": self.t / "d"}, PW, target_os="linux")
        self.assertFalse((self.t / "d" / "f").exists())

    def test_a_manifest_that_promises_more_bytes_than_the_stream_holds_is_refused(self):
        """Authentic chunks, but the manifest and the bodies disagree: the importer must not write a short file."""
        import hashlib
        salt = bytes(16)
        header = json.dumps({"v": 1, "kdf": {"alg": "scrypt", **FAST}, "salt": salt.hex()},
                            sort_keys=True, separators=(",", ":")).encode()
        key = subkey(master_key(PW, salt, FAST), "bundle")
        entry = {"role": "documents", "path": "f", "kind": "file", "size": 10,
                 "sha256": hashlib.sha256(b"0123456789").hexdigest(), "mode": 420, "mtime": 0}
        man = json.dumps({"format": 1, "entries": [entry]}).encode()
        f = self.t / "short.kmig"
        f.write_bytes(migrate.MAGIC + len(header).to_bytes(4, "big") + header
                      + seal(key, migrate.MAGIC + header, len(man).to_bytes(4, "big") + man + b"01234"))
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(f, {"documents": self.t / "d"}, PW, target_os="linux")
        self.assertFalse((self.t / "d" / "f").exists())

    def test_a_body_that_does_not_match_its_checksum_is_refused(self):
        salt = bytes(16)
        header = json.dumps({"v": 1, "kdf": {"alg": "scrypt", **FAST}, "salt": salt.hex()},
                            sort_keys=True, separators=(",", ":")).encode()
        key = subkey(master_key(PW, salt, FAST), "bundle")
        entry = {"role": "documents", "path": "f", "kind": "file", "size": 1, "sha256": "0" * 64, "mode": 420, "mtime": 0}
        man = json.dumps({"format": 1, "entries": [entry]}).encode()
        f = self.t / "evil.kmig"
        f.write_bytes(migrate.MAGIC + len(header).to_bytes(4, "big") + header
                      + seal(key, migrate.MAGIC + header, len(man).to_bytes(4, "big") + man + b"x"))
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(f, {"documents": self.t / "d"}, PW)

    def test_short_password_and_unknown_role_are_refused_at_export(self):
        with self.assertRaises(CryptoError):
            migrate.export_bundle({"documents": self.src}, self.t / "s.kmig", "short", kdf=FAST)
        with self.assertRaises(migrate.MigrateError):
            migrate.export_bundle({"../x": self.src}, self.t / "s.kmig", PW, kdf=FAST)

    def test_the_bundle_does_not_contain_names_or_contents(self):
        self.export()
        raw = self.bundle.read_bytes()
        for needle in (b"alpha", b"beta", b"a.txt", b"b:c.txt", b"documents"):
            self.assertNotIn(needle, raw)

    def test_a_role_with_no_folder_must_be_named(self):
        self.export()
        with self.assertRaises(migrate.MigrateError):
            migrate.import_bundle(self.bundle, {}, PW, target_os="ios")
        rep = migrate.import_bundle(self.bundle, {}, PW, target_os="ios", dry_run=True)
        self.assertEqual(rep.files, 4)

    def test_default_folders(self):
        h = Path("/h")
        self.assertEqual(migrate.default_dir("documents", "windows", h), h / "Documents")
        self.assertEqual(migrate.default_dir("videos", "macos", h), h / "Movies")
        self.assertEqual(migrate.default_dir("config", "windows", h, {"APPDATA": "/appdata"}), Path("/appdata"))
        self.assertEqual(migrate.default_dir("config", "macos", h), h / "Library" / "Application Support")
        self.assertEqual(migrate.default_dir("config", "linux", h, {}), h / ".config")
        self.assertIsNone(migrate.default_dir("documents", "android", h))
        self.assertIsNone(migrate.default_dir("other", "linux", h))


class TestApps(unittest.TestCase):
    def test_collect_keeps_only_package_like_names_and_survives_missing_tools(self):
        def run(argv, timeout=60):
            if argv[0] == "apt-mark":
                return "git\nfirefox\n$(rm -rf ~)\n; ls\nvlc\n\n" + "x" * 500
            raise FileNotFoundError(argv[0])
        got = apps.collect("linux", run=run)
        self.assertEqual([a["name"] for a in got], ["git", "firefox", "vlc"])
        self.assertEqual(apps.collect("macos", run=lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())), [])

    def test_hints_are_text_for_the_target_os_and_unknown_apps_are_listed(self):
        cmds, unknown = apps.install_hints([{"manager": "apt", "name": "firefox"}, {"manager": "apt", "name": "git"},
                                            {"manager": "apt", "name": "obscure-tool"}], "windows")
        self.assertIn("winget install --id Mozilla.Firefox", cmds)
        self.assertIn("winget install --id Git.Git", cmds)
        self.assertEqual(unknown, ["obscure-tool (apt)"])
        cmds, _ = apps.install_hints([{"manager": "winget", "name": "Mozilla.Firefox"}], "linux")
        self.assertEqual(cmds, ["sudo apt install firefox"])

    def test_apps_travel_in_the_bundle(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "d").mkdir()
            (t / "d" / "f").write_text("x")
            migrate.export_bundle({"documents": t / "d"}, t / "b.kmig", PW, kdf=FAST, source_os="linux", include_apps=True,
                                  apps_runner=lambda argv, timeout=60: "firefox\n" if argv[0] == "apt-mark" else "")
            rep = migrate.import_bundle(t / "b.kmig", {"documents": t / "o"}, PW, target_os="macos")
            self.assertEqual(rep.install_commands, ["brew install --cask firefox"])


class SyncBase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.shared = self.t / "shared"
        self.shared.mkdir()
        S.create_vault(self.shared, PW, kdf=FAST)
        self.a, self.b = self.t / "a", self.t / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.clock = 1_000 * 10**9

    def tearDown(self):
        self._t.cleanup()

    def run_sync(self, local, device, **kw):
        self.clock += 10 * 10**9
        kw.setdefault("os_name", "linux")
        return S.sync(S.open_vault(self.shared, PW), local, device, now_ns=self.clock, **kw)

    def both(self):
        for _ in range(2):
            self.run_sync(self.a, "dev-a")
            self.run_sync(self.b, "dev-b")

    def visible(self, root):
        return {k: v for k, v in tree(root).items() if v is not None and not k.startswith(".kosync")}


class TestSync(SyncBase):
    def test_files_edits_and_deletes_travel_both_ways(self):
        (self.a / "d").mkdir()
        (self.a / "d" / "one.txt").write_text("1")
        (self.b / "two.txt").write_text("2")
        self.both()
        self.assertEqual(self.visible(self.a), self.visible(self.b))
        self.assertEqual(set(self.visible(self.a)), {"d/one.txt", "two.txt"})
        (self.a / "d" / "one.txt").write_text("one, edited")
        self.both()
        self.assertEqual((self.b / "d" / "one.txt").read_text(), "one, edited")
        (self.b / "two.txt").unlink()
        self.both()
        self.assertFalse((self.a / "two.txt").exists())
        self.assertEqual(self.visible(self.a), self.visible(self.b))

    def test_a_third_device_catches_up(self):
        (self.a / "f").write_text("x")
        self.both()
        c = self.t / "c"
        c.mkdir()
        self.run_sync(c, "dev-c")
        self.assertEqual((c / "f").read_text(), "x")

    def test_both_edited_keeps_both_and_loses_nothing(self):
        (self.a / "f.txt").write_text("v0")
        self.both()
        (self.a / "f.txt").write_text("from a")
        (self.b / "f.txt").write_text("from b")
        self.run_sync(self.a, "dev-a")
        rb = self.run_sync(self.b, "dev-b")
        self.assertEqual(len(rb.conflicts), 1)
        self.both()
        self.both()
        va, vb = self.visible(self.a), self.visible(self.b)
        self.assertEqual(va, vb)
        self.assertEqual(sorted(va.values()), [b"from a", b"from b"])
        self.assertEqual(va["f.txt"], b"from a")
        self.assertTrue(any("conflict dev-b" in k for k in va))

    def test_delete_against_edit_brings_the_file_back(self):
        (self.a / "f").write_text("v0")
        self.both()
        (self.a / "f").unlink()
        (self.b / "f").write_text("edited on b")
        self.run_sync(self.a, "dev-a")
        self.run_sync(self.b, "dev-b")
        self.both()
        self.assertEqual((self.a / "f").read_text(), "edited on b")
        self.assertEqual(self.visible(self.a), self.visible(self.b))

    def test_the_shared_folder_holds_no_names_and_no_contents(self):
        (self.a / "tax-return-2026.pdf").write_text("SSN 123-45-6789")
        self.both()
        blob = b"".join(p.read_bytes() for p in self.shared.rglob("*") if p.is_file())
        for needle in (b"tax-return", b"123-45-6789", b"pdf"):
            self.assertNotIn(needle, blob)
        self.assertNotIn("tax-return", " ".join(str(p) for p in self.shared.rglob("*")))

    def test_wrong_password_and_missing_vault(self):
        with self.assertRaises(S.SyncError):
            S.open_vault(self.shared, "not the password")
        with self.assertRaises(S.SyncError):
            S.open_vault(self.t / "nowhere", PW)
        with self.assertRaises(S.SyncError):
            S.create_vault(self.shared, PW, kdf=FAST)

    def test_a_tampered_list_stops_the_run_and_changes_nothing(self):
        (self.a / "f").write_text("x")
        self.run_sync(self.a, "dev-a")
        idx = self.shared / "index" / "dev-a.idx"
        raw = bytearray(idx.read_bytes())
        raw[-3] ^= 1
        idx.write_bytes(bytes(raw))
        with self.assertRaises(S.SyncError):
            self.run_sync(self.b, "dev-b")
        self.assertEqual(self.visible(self.b), {})

    def test_a_list_copied_from_another_device_is_refused(self):
        (self.a / "f").write_text("x")
        self.run_sync(self.a, "dev-a")
        (self.shared / "index" / "dev-evil.idx").write_bytes((self.shared / "index" / "dev-a.idx").read_bytes())
        with self.assertRaises(S.SyncError):
            self.run_sync(self.b, "dev-b")

    def test_an_older_copy_of_a_list_is_refused(self):
        (self.a / "f").write_text("1")
        self.run_sync(self.a, "dev-a")
        old = (self.shared / "index" / "dev-a.idx").read_bytes()
        self.run_sync(self.b, "dev-b")
        (self.a / "f").write_text("2")
        self.run_sync(self.a, "dev-a")
        self.run_sync(self.b, "dev-b")
        (self.shared / "index" / "dev-a.idx").write_bytes(old)
        with self.assertRaises(S.SyncError):
            self.run_sync(self.b, "dev-b")

    def test_a_swapped_object_is_caught_and_the_local_file_is_kept(self):
        (self.a / "one").write_text("first")
        (self.a / "two").write_text("second")
        self.run_sync(self.a, "dev-a")
        objs = sorted(p for p in (self.shared / "objects").rglob("*") if p.is_file())
        self.assertEqual(len(objs), 2)
        objs[0].write_bytes(objs[1].read_bytes())             # a valid object under the wrong name
        r = self.run_sync(self.b, "dev-b")
        self.assertEqual(len(r.errors), 1)
        self.assertEqual(len(self.visible(self.b)), 1)

    def test_an_object_validly_sealed_for_its_name_but_holding_other_content_is_caught(self):
        (self.a / "f").write_text("real")
        self.run_sync(self.a, "dev-a")
        v = S.open_vault(self.shared, PW)
        (obj,) = [p for p in (self.shared / "objects").rglob("*") if p.is_file()]
        obj.write_bytes(S._seal(v.keys.enc, b"object:" + obj.name.encode(), b"forged content"))
        r = self.run_sync(self.b, "dev-b")
        self.assertEqual(len(r.errors), 1)
        self.assertEqual(self.visible(self.b), {})

    def test_a_hostile_path_in_a_list_is_refused(self):
        (self.a / "f").write_text("x")
        self.run_sync(self.a, "dev-a")
        v = S.open_vault(self.shared, PW)
        for evil in ("../escape", "/abs", "a/../b"):
            doc = {"device": "dev-evil", "vault": v.vault_id, "seq": 1,
                   "entries": {evil: {"id": "0" * 64, "at": 5, "size": 1, "mtime": 0}}}
            (self.shared / "index" / "dev-evil.idx").write_bytes(
                S._seal(v.keys.index, b"index:dev-evil", json.dumps(doc).encode()))
            with self.assertRaises(S.SyncError, msg=evil):
                self.run_sync(self.b, "dev-b")
        self.assertFalse((self.t / "escape").exists())

    def test_download_never_goes_through_a_symlink_or_over_a_different_file(self):
        (self.a / "d").mkdir()
        (self.a / "d" / "f").write_text("x")
        (self.a / "Readme").write_text("a's")
        self.run_sync(self.a, "dev-a")
        outside = self.t / "outside"
        outside.mkdir()
        os.symlink(outside, self.b / "d")
        r = self.run_sync(self.b, "dev-b")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(r.errors or r.skipped)
        self.assertEqual((self.b / "Readme").read_text(), "a's")

    def test_a_name_that_would_land_on_another_file_is_skipped_not_overwritten(self):
        (self.b / "readme.md").write_text("B's own")
        (self.a / "README.md").write_text("A's")
        self.run_sync(self.a, "dev-a", os_name="windows")
        # on a case-insensitive disk 'README.md' would be the same file as 'readme.md': simulate that file system
        real = os.path.lexists
        S_os = S.os.path
        S_os.lexists = lambda p: real(p) or str(p).endswith("README.md") and real(str(p)[:-9] + "readme.md")
        try:
            r = self.run_sync(self.b, "dev-b", os_name="windows")
        finally:
            S_os.lexists = real
        self.assertEqual((self.b / "readme.md").read_text(), "B's own")
        self.assertTrue(any("different file" in why for _, why in r.skipped))

    def test_names_illegal_here_are_skipped_and_reported(self):
        (self.a / "a:b.txt").write_text("x")
        (self.a / "ok.txt").write_text("y")
        self.run_sync(self.a, "dev-a", os_name="linux")
        r = self.run_sync(self.b, "dev-b", os_name="windows")
        self.assertEqual(set(self.visible(self.b)), {"ok.txt"})
        self.assertTrue(any(p == "a:b.txt" for p, _ in r.skipped))

    def test_links_are_not_synced_and_dry_run_changes_nothing(self):
        (self.a / "f").write_text("x")
        os.symlink(self.t, self.a / "lnk")
        r = self.run_sync(self.a, "dev-a", dry_run=True)
        self.assertEqual(r.uploaded, ["f"])
        self.assertEqual([p for p in (self.shared / "objects").rglob("*") if p.is_file()], [])
        self.assertEqual(list((self.shared / "index").glob("*.idx")), [])
        self.assertFalse((self.a / ".kosync").exists())
        r = self.run_sync(self.a, "dev-a")
        self.assertTrue(any(p == "lnk" for p, _ in r.skipped))
        self.run_sync(self.b, "dev-b")
        self.assertEqual(set(self.visible(self.b)), {"f"})

    def test_a_file_that_changes_while_being_copied_is_not_published_wrongly(self):
        (self.a / "f").write_text("before")
        real = S._file_id
        calls = {"n": 0}

        def changing(keys, path):
            r = real(keys, path)
            calls["n"] += 1
            if calls["n"] == 1:
                Path(path).write_text("after!")
            return r
        S._file_id = changing
        try:
            r = self.run_sync(self.a, "dev-a")
        finally:
            S._file_id = real
        self.assertEqual(len(r.errors), 1)
        self.run_sync(self.a, "dev-a")
        self.run_sync(self.b, "dev-b")
        self.assertEqual((self.b / "f").read_text(), "after!")

    def test_device_names_and_folder_binding(self):
        for bad in ("", "A", "../x", "a b", "x" * 40):
            with self.assertRaises(S.SyncError):
                self.run_sync(self.a, bad)
        self.run_sync(self.a, "dev-a")
        with self.assertRaises(S.SyncError):
            self.run_sync(self.a, "dev-z")                    # a folder belongs to one device
        other = self.t / "other-shared"
        other.mkdir()
        S.create_vault(other, PW, kdf=FAST)
        with self.assertRaises(S.SyncError):
            S.sync(S.open_vault(other, PW), self.a, "dev-a", now_ns=self.clock)

    def test_size_limit_skips_and_says_so(self):
        (self.a / "huge").write_bytes(b"x" * 100)
        r = self.run_sync(self.a, "dev-a", max_file=10)
        self.assertEqual(r.uploaded, [])
        self.assertTrue(any("size limit" in why for _, why in r.skipped))

    def test_a_large_file_crosses_chunks(self):
        (self.a / "big").write_bytes(os.urandom(2 * CHUNK + 7))
        self.both()
        self.assertEqual((self.a / "big").read_bytes(), (self.b / "big").read_bytes())


class TestCommandLine(unittest.TestCase):
    def run_cli(self, *args, pwfile):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "clients" / "kosync")}
        return subprocess.run([sys.executable, "-m", "kosync", *args, "--password-file", str(pwfile)],
                              capture_output=True, text=True, env=env, timeout=120)

    def test_export_inspect_import_and_sync_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            pw = t / "pw"
            pw.write_text(PW + "\n")
            (t / "src").mkdir()
            (t / "src" / "n.txt").write_text("note")
            out = self.run_cli("migrate", "export", "--root", f"documents={t / 'src'}", "--out", str(t / "b.kmig"), pwfile=pw)
            self.assertEqual(out.returncode, 0, out.stderr)
            ins = self.run_cli("migrate", "inspect", str(t / "b.kmig"), "--target-os", "windows", pwfile=pw)
            self.assertEqual(ins.returncode, 0, ins.stderr)
            self.assertIn("Would import 1 files", ins.stdout)
            imp = self.run_cli("migrate", "import", str(t / "b.kmig"), "--dest", f"documents={t / 'dst'}", pwfile=pw)
            self.assertEqual(imp.returncode, 0, imp.stderr)
            self.assertEqual((t / "dst" / "n.txt").read_text(), "note")
            bad = t / "badpw"
            bad.write_text("wrong wrong wrong\n")
            r = self.run_cli("migrate", "inspect", str(t / "b.kmig"), pwfile=bad)
            self.assertEqual(r.returncode, 2)
            self.assertIn("kosync:", r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            (t / "sh").mkdir()
            (t / "loc").mkdir()
            (t / "loc" / "f").write_text("x")
            self.assertEqual(self.run_cli("sync", "init", str(t / "sh"), pwfile=pw).returncode, 0)
            r = self.run_cli("sync", "run", str(t / "sh"), str(t / "loc"), "--device", "laptop", pwfile=pw)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("1 up", r.stdout)


if __name__ == "__main__":
    unittest.main()
