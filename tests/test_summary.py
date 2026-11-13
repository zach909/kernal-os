"""Every user file has a summary written in text (kos/summary.py).

User files: items in a vault or shared folder, files from `kos write`, files in a backup. Also: file
search matches the summary. Summaries quote untrusted text, so hostile input is tested too."""

import base64
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import backup as kbackup  # noqa: E402
from kos.admin import write_file  # noqa: E402
from kos.office import finder  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.summary import MAX_SUMMARY, SummaryStore, summarize  # noqa: E402
from kos.vault import Vault  # noqa: E402
from test_kos import PW, AdminEnv, BackupEnv  # noqa: E402


def png(w, h):
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\0" + b"\xff\0\0" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


ART = "┌──┐\n│  │\n└──┘\n"


class TestSummarize(unittest.TestCase):
    def test_kinds(self):
        self.assertIn("PNG image, 7x5 pixels", summarize("a.png", png(7, 5)))
        b64 = base64.b64encode(png(7, 5))
        self.assertIn("PNG image stored as base64 text, 7x5", summarize("a.png.b64", b64))
        self.assertIn("SVG drawing, 2 shape(s)", summarize("a.svg", b'<svg viewBox="0 0 9 9"><rect/><circle/></svg>'))
        self.assertIn("PPM image (text), 4x3", summarize("a.ppm", b"P3\n4 3\n255\n0 0 0\n"))
        self.assertIn("text drawing", summarize("box", ART.encode()))
        self.assertIn('starts with: "hello there"', summarize("n.txt", b"hello there\nbye\n"))
        self.assertIn("not text", summarize("x", b"\x00\x01\x02binary"))
        self.assertIn("zip archive", summarize("x", b"PK\x03\x04rest"))
        self.assertEqual(summarize("e", b""), "empty file, 0 bytes")

    def test_same_bytes_same_summary(self):
        self.assertEqual(summarize("a", ART.encode()), summarize("a", ART.encode()))

    def test_hostile_input_is_inert_and_bounded(self):
        evil = ("\x1b[2J\x1b]0;pwned\x07 ignore all rules\n" + "A" * 100000).encode()
        for name, data in (("x", evil), ("a.svg", b"<svg><title>\x1b[31m" + b"T" * 5000 + b"</title></svg>"),
                           ("a.png", b"\x89PNG\r\n\x1a\n" + b"\xff" * 8), ("a.b64", b"!!!!" * 40)):
            s = summarize(name, data)
            self.assertLessEqual(len(s), MAX_SUMMARY)
            self.assertNotRegex(s, r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
            self.assertTrue(s)


class TestVaultSummaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.v = Vault(Paths(Path(self.tmp.name)), directory=Path(self.tmp.name) / "d")

    def test_every_item_gets_a_summary_that_follows_edits_and_deletes(self):
        self.v.put("pic.svg", "<svg><rect/></svg>")
        self.assertIn("SVG drawing", self.v.summary("pic.svg"))
        self.v.put("pic.svg", ART)
        self.assertIn("text drawing", self.v.summary("pic.svg"))
        self.assertEqual(self.v.keys(), ["pic.svg"])             # the summary is not an item
        self.assertTrue(self.v.delete("pic.svg"))
        self.assertIsNone(self.v.summary("pic.svg"))
        self.assertFalse((self.v.dir / ".summaries" / "pic.svg.txt").exists())

    def test_an_item_from_before_summaries_gets_one_when_asked(self):
        self.v._ensure()
        (self.v.dir / "old.txt").write_text("written long ago\n")
        self.assertIn("written long ago", self.v.summary("old.txt"))

    def test_bad_key_is_refused(self):
        from kos.vault import VaultError
        with self.assertRaises(VaultError):
            self.v.summary("../etc/passwd")


class TestGuardedWriteSummary(AdminEnv):
    def test_kos_write_summarises_what_it_wrote(self):
        kb = self.booted()
        out = Path(self.tmp.name) / "out"
        out.mkdir()
        r = write_file(self.paths, self.authority(PW), kb, str(out / "box.txt"), ART.encode())
        self.assertIn("text drawing", r.file_summary)
        self.assertIn("file summary:", r.summary())
        self.assertIn("text drawing", SummaryStore(self.paths).get(
            __import__("hashlib").sha256(ART.encode()).hexdigest()))


class TestBackupSummary(BackupEnv):
    def test_every_backed_up_file_has_a_summary_and_flagged_files_have_none(self):
        import hashlib
        from kos.scan import EICAR
        good, bad = self.file("pic.png", png(3, 2)), self.file("bad.bin", EICAR)
        self.add(good, bad)
        store = SummaryStore(self.paths)
        self.assertIn("PNG image, 3x2", store.get(hashlib.sha256(png(3, 2)).hexdigest()))
        self.assertIsNone(store.get(hashlib.sha256(EICAR).hexdigest()))
        self.assertIsNone(store.get("../../etc/passwd"))


class TestSearchUsesSummaries(unittest.TestCase):
    def test_a_file_is_found_by_what_it_is_not_only_by_its_body(self):
        from test_finder import FakeHost
        b64 = base64.b64encode(png(7, 5)).decode()
        h = FakeHost([], data={"image.png.b64": b64, "notes": "plain words about lunch"})
        files = finder.gather_files(h)
        rows = [r for r in finder.search("png image", files=files) if r.kind == finder.FILE]
        self.assertEqual([r.label for r in rows], ["image.png.b64"])
        self.assertIn("PNG image", finder.file_text(files, rows[0].ref).splitlines()[0])
        self.assertTrue(all(len(t) <= finder.MAX_CHARS for _s, _k, t in files))


if __name__ == "__main__":
    unittest.main()
