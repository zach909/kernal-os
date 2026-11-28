"""What the OS reads for an app that maps the world: cameras (kos/camera.py), plain sensors (kos/sensors.py),
a folder tree (kos/filewalk.py), and the services that hand them over (camera.*, sensor.*, files.walk).

Honest about what ran: the camera code is driven against a fake V4L2 driver built from the same structure
layouts. No real camera was ever opened. The ioctl numbers are checked against the values 64-bit Linux uses.
Each allowance has its refusal next to it: a wrong password opens nothing, a bad driver closes everything."""

from __future__ import annotations

import os
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite"))
sys.path.insert(0, str(ROOT / "tests"))

import atlas_core as core  # noqa: E402
from kos import camera, filewalk, sensors  # noqa: E402
from kos.auth import AuditLog  # noqa: E402
from test_atlas_core import H, W, two_layer_pair  # noqa: E402
from kos.protocol import ProtocolError  # noqa: E402
from test_services import PW, Base  # noqa: E402


class FakeMap(bytearray):
    closed = False

    def close(self):
        self.closed = True


class FakeKernel:
    """A V4L2 driver in memory. It speaks the real structures (the same layouts, written out again here) so the
    stream's packing and unpacking is exercised, and it records everything the stream does to it."""

    BUF = struct.Struct("=IIIII4xqq16sIIQIIi4x")

    def __init__(self, frames=None, native=None, fmt=camera.PIX_YUYV, major=81, stall=False, bad=None, fail_at=None):
        self.frames = frames or (lambda node, seq, w, h: bytes([(node * 40 + seq) & 255]) * (w * h))
        self.native, self.fmt, self.major, self.stall, self.bad, self.fail_at = native, fmt, major, stall, bad, fail_at
        self.dev, self.opened, self.closed, self.log, self.next_fd = {}, [], set(), [], 100

    def open(self, path):
        node = int(path.rsplit("video", 1)[1])
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.dev[fd] = {"node": node, "queue": [], "w": 0, "h": 0, "seq": 0, "maps": {}}
        self.opened.append(path)
        return fd

    def fstat(self, fd):
        return SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_rdev=os.makedev(self.major, self.dev[fd]["node"]))

    def ioctl(self, fd, req, data):
        d = self.dev[fd]
        self.log.append((d["node"], req))
        if self.fail_at == req:
            raise OSError(5, "I/O error")
        if req == camera.VIDIOC_S_FMT:
            w, h = struct.unpack_from("=II", data, 8)
            d["w"], d["h"] = self.native or (w, h)
            pix = struct.pack("=12I", d["w"], d["h"], self.fmt, 1, 0, 0, 0, 0, 0, 0, 0, 0)
            return struct.pack("=I4x", 1) + pix + bytes(200 - len(pix))
        if req == camera.VIDIOC_REQBUFS:
            return struct.pack("=IIII4B", 3, 1, 1, 0, 0, 0, 0, 0)
        size = d["w"] * d["h"] * 2
        if req == camera.VIDIOC_QUERYBUF:
            idx = self.BUF.unpack(data)[0]
            return self.BUF.pack(idx, 1, 0, 0, 1, 0, 0, bytes(16), 0, 1, idx * size, size, 0, 0)
        if req == camera.VIDIOC_QBUF:
            d["queue"].append(self.BUF.unpack(data)[0])
            return data
        if req == camera.VIDIOC_DQBUF:
            idx = d["queue"].pop(0)
            y = self.frames(d["node"], d["seq"], d["w"], d["h"])
            d["seq"] += 1
            yuyv = bytearray(size)
            yuyv[0::2] = y
            yuyv[1::2] = bytes([128]) * (d["w"] * d["h"])
            d["maps"][idx][:] = yuyv
            used = size
            if self.bad == "index":
                idx = 99
            elif self.bad == "used":
                used = size + 10
            elif self.bad == "zero":
                used = 0
            return self.BUF.pack(idx, 1, used, 0, 1, 0, 0, bytes(16), d["seq"], 1, 0, 0, 0, 0)
        if req in (camera.VIDIOC_STREAMON, camera.VIDIOC_STREAMOFF):
            return data
        raise AssertionError(f"unexpected ioctl {req:#x}")

    def mmap(self, fd, length, offset):
        m = FakeMap(length)
        self.dev[fd]["maps"][offset // length] = m
        return m

    def wait(self, fd, ms):
        return not self.stall

    def close(self, fd):
        self.closed.add(fd)


class TestTheKernelsStructures(unittest.TestCase):
    def test_the_ioctl_numbers_are_the_ones_64_bit_linux_uses(self):
        self.assertEqual(
            (camera.VIDIOC_S_FMT, camera.VIDIOC_REQBUFS, camera.VIDIOC_QUERYBUF, camera.VIDIOC_QBUF,
             camera.VIDIOC_DQBUF, camera.VIDIOC_STREAMON, camera.VIDIOC_STREAMOFF),
            (0xC0D05605, 0xC0145608, 0xC0585609, 0xC058560F, 0xC0585611, 0x40045612, 0x40045613))

    def test_the_structures_have_the_kernels_sizes(self):
        self.assertEqual(camera.BUF.size, 88)
        self.assertEqual(len(camera.format_request(160, 120)), 208)
        self.assertEqual(camera.format_answer(camera.format_request(160, 120)), (160, 120, camera.PIX_YUYV))
        with self.assertRaises(camera.CameraError):
            camera.format_answer(b"short")


class TestStream(unittest.TestCase):
    def test_it_returns_the_brightness_bytes_exactly_and_closes_everything(self):
        k = FakeKernel(frames=lambda node, seq, w, h: bytes(range(256)) * (w * h // 256))
        with camera.V4L2Stream(0, 64, 48, k) as s:
            grey = s.grab()
            self.assertEqual(s.size, (64, 48))
        self.assertEqual(grey, bytes(range(256)) * 12)
        self.assertEqual(k.closed, {100})
        self.assertIn((0, camera.VIDIOC_STREAMOFF), k.log)
        self.assertTrue(all(m.closed for m in k.dev[100]["maps"].values()))

    def test_warm_up_pictures_are_taken_and_thrown_away(self):
        k = FakeKernel(frames=lambda node, seq, w, h: bytes([seq]) * (w * h))
        with camera.V4L2Stream(0, 32, 24, k) as s:
            self.assertEqual(s.grab(skip=3)[0], 3)
            self.assertEqual(s.grab()[0], 4)

    def test_the_driver_may_pick_another_size_and_it_is_used(self):
        k = FakeKernel(native=(48, 36))
        with camera.V4L2Stream(0, 64, 48, k) as s:
            self.assertEqual(len(s.grab()), 48 * 36)

    def test_a_camera_that_only_does_mjpeg_is_refused_and_closed(self):
        k = FakeKernel(fmt=0x47504A4D)
        with self.assertRaises(camera.CameraError) as e:
            with camera.V4L2Stream(0, 64, 48, k):
                pass
        self.assertIn("YUYV", str(e.exception))
        self.assertEqual(k.closed, {100})

    def test_a_node_that_is_not_a_camera_is_refused_and_closed(self):
        k = FakeKernel(major=4)                                # a terminal, say, or a symlink to anything else
        with self.assertRaises(camera.CameraError):
            with camera.V4L2Stream(0, 64, 48, k):
                pass
        self.assertEqual(k.closed, {100})
        self.assertNotIn((0, camera.VIDIOC_S_FMT), k.log, "nothing was asked of it")

    def test_a_driver_error_midway_closes_what_was_opened(self):
        k = FakeKernel(fail_at=camera.VIDIOC_STREAMON)
        with self.assertRaises(camera.CameraError):
            with camera.V4L2Stream(0, 64, 48, k):
                pass
        self.assertEqual(k.closed, {100})
        self.assertTrue(all(m.closed for m in k.dev[100]["maps"].values()))

    def test_no_picture_in_time_is_an_error_and_it_still_closes(self):
        k = FakeKernel(stall=True)
        with self.assertRaises(camera.CameraError) as e:
            with camera.V4L2Stream(0, 64, 48, k) as s:
                s.grab(timeout_ms=10)
        self.assertIn("no picture", str(e.exception))
        self.assertEqual(k.closed, {100})

    def test_a_lying_driver_is_not_believed(self):
        for bad in ("index", "used", "zero"):
            k = FakeKernel(bad=bad)
            with self.assertRaises(camera.CameraError, msg=bad):
                with camera.V4L2Stream(0, 64, 48, k) as s:
                    s.grab()
            self.assertEqual(k.closed, {100}, bad)
        k = FakeKernel(native=(3, 3))
        with self.assertRaises(camera.CameraError):
            with camera.V4L2Stream(0, 64, 48, k):
                pass

    def test_a_bad_node_number_never_reaches_the_kernel(self):
        for node in (-1, 1000, "video0", None):
            with self.assertRaises(camera.CameraError):
                camera.V4L2Stream(node, 64, 48, FakeKernel())


class TestShrink(unittest.TestCase):
    def test_blocks_are_averaged_with_whole_numbers(self):
        grey = bytes([10, 20, 30, 40, 50, 60, 70, 80] * 4)           # 8 x 4 -> 4 x 2, blocks of 2 x 2
        self.assertEqual(camera.shrink(grey, 8, 4, 4, 2), bytes([15, 35, 55, 75] * 2))
        self.assertEqual(camera.shrink(bytes([0, 100] * 8), 4, 4, 2, 2), bytes([50, 50, 50, 50]))
        self.assertEqual(camera.shrink(bytes(range(16)), 4, 4, 4, 4), bytes(range(16)), "same size: unchanged")

    def test_it_never_returns_more_than_asked_for_and_refuses_nonsense(self):
        for w, h, tw, th in ((100, 75, 30, 20), (640, 480, 160, 120), (641, 479, 128, 96), (50, 50, 49, 49), (7, 5, 3, 2)):
            ow, oh = camera.shrunk_size(w, h, tw, th)
            out = camera.shrink(bytes(w * h), w, h, tw, th)
            self.assertEqual(len(out), ow * oh)
            self.assertTrue(ow <= tw and oh <= th, (w, h, tw, th, ow, oh))
        with self.assertRaises(camera.CameraError):
            camera.shrink(b"abc", 2, 2, 1, 1)
        with self.assertRaises(camera.CameraError):
            camera.shrink(bytes(4), 2, 2, 0, 1)


class TestCapture(unittest.TestCase):
    def test_two_cameras_are_read_one_after_the_other_and_closed(self):
        k = FakeKernel()
        r = camera.capture([0, 1], 32, 24, 2, 0, kernel=k, now=lambda: 1234)
        self.assertEqual((r["w"], r["h"], len(r["sets"])), (32, 24, 2))
        self.assertEqual([s["t"] for s in r["sets"]], [1234, 1234])
        first = r["sets"][0]["frames"]
        self.assertEqual(len(first), 2)
        self.assertEqual(bytes.fromhex(first[0])[0], 0 * 40 + camera.WARM_UP)      # camera 0, after the warm-up
        self.assertEqual(bytes.fromhex(first[1])[0], 1 * 40 + camera.WARM_UP)
        self.assertEqual(k.closed, {100, 101})

    def test_cameras_that_cannot_be_compared_are_refused_and_closed(self):
        k = FakeKernel()
        k.native = (32, 24)
        orig_open = k.open

        def open_second_bigger(path):
            fd = orig_open(path)
            return fd
        real_ioctl = k.ioctl

        def ioctl(fd, req, data):
            out = real_ioctl(fd, req, data)
            if req == camera.VIDIOC_S_FMT and k.dev[fd]["node"] == 1:
                k.dev[fd]["w"], k.dev[fd]["h"] = 64, 48
                pix = struct.pack("=12I", 64, 48, camera.PIX_YUYV, 1, 0, 0, 0, 0, 0, 0, 0, 0)
                return struct.pack("=I4x", 1) + pix + bytes(200 - len(pix))
            return out
        k.ioctl = ioctl
        with self.assertRaises(camera.CameraError) as e:
            camera.capture([0, 1], 32, 24, 1, 0, kernel=k)
        self.assertIn("different picture sizes", str(e.exception))
        self.assertEqual(k.closed, {100, 101})

    def test_the_budget_is_enforced_before_anything_is_opened(self):
        k = FakeKernel()
        for args in (([0], 320, 240, 8, 0), ([0] * 2, 32, 24, 1, 0), ([0, 1, 2, 3, 4], 32, 24, 1, 0), ([], 32, 24, 1, 0),
                     ([0], 32, 24, 5, 10_000)):
            with self.assertRaises(camera.CameraError, msg=str(args)):
                camera.capture(*args, kernel=k)
        self.assertEqual(k.opened, [])

    def test_a_picture_pair_survives_the_whole_road_and_gives_the_right_depth(self):
        """Two cameras (fake), through the stream, the hex answer, and the Atlas core: the nearer square comes out at
        500 mm and the wall behind at 1500 mm. The camera path and the maths agree about what a picture is."""
        left, right = two_layer_pair(4, 12)
        pics = {0: bytes(left), 1: bytes(right)}
        k = FakeKernel(frames=lambda node, seq, w, h: pics[node])
        r = camera.capture([0, 1], W, H, 1, 0, kernel=k)
        l, rr = (list(bytes.fromhex(f)) for f in r["sets"][0]["frames"])
        d = core.disparity(l, rr, W, H, max_disp=20)
        fg = core.median([d[y * W + x] for y in range(26, 46) for x in range(36, 64) if d[y * W + x]])
        self.assertLessEqual(abs(core.depth_mm(fg, 100, 60) - 500), 25)


class TestListing(unittest.TestCase):
    def test_only_capture_nodes_of_real_names_are_listed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for name, index, label in (("video0", "0", "Front Cam"), ("video1", "1", "Front Cam metadata"),
                                       ("video2", "0", "Rear\x1b[2J Cam"), ("videox", "0", "bad"), ("video3", "0", None)):
                (root / name).mkdir()
                (root / name / "index").write_text(index + "\n")
                if label is not None:
                    (root / name / "name").write_text(label + "\n")
            got = camera.list_cameras(root)
        self.assertEqual([c["node"] for c in got], [0, 2])
        self.assertEqual(got[0]["name"], "Front Cam")
        self.assertEqual(camera.list_cameras(Path("/nonexistent-path")), [])


class TestSensors(unittest.TestCase):
    def tree(self, t):
        root = Path(t)
        d0 = root / "iio:device0"
        d0.mkdir()
        for name, text in (("name", "bme680\n"), ("in_temp_input", "23500\n"), ("in_humidityrelative_input", "45123\n"),
                           ("in_pressure_input", "101.325\n"), ("in_resistance_raw", "12345\n"),
                           ("serial", "SECRET-1234\n"), ("in_temp_secret", "7\n")):
            (d0 / name).write_text(text)
        d1 = root / "iio:device1"
        d1.mkdir()
        (d1 / "name").write_text("odd\n")
        for name, text in (("in_temp_input", "1e5\n"), ("in_pressure_input", "NaN\n"), ("in_resistance_raw", "9" * 100),
                           ("in_illuminance_input", "12.5\n")):
            (d1 / name).write_text(text)
        (root / "not-a-sensor").mkdir()
        return root

    def test_decimals_become_whole_numbers_without_a_float(self):
        for text, want in (("101.325", 101325), ("-1.5", -1500), ("0.0005", 0), ("12", 12000), ("+7.25", 7250),
                           ("0.9999", 999), (" 3.1\n", 3100)):
            self.assertEqual(sensors.to_milli(text), want, text)
        for bad in ("1e5", "nan", "inf", "", "1.2.3", "٣", "1,5", "--1", "0x10", "1" * 20):
            with self.assertRaises(sensors.SensorError, msg=bad):
                sensors.to_milli(bad)
        self.assertEqual(sensors.to_whole("-42\n"), -42)
        with self.assertRaises(sensors.SensorError):
            sensors.to_whole("4.5")

    def test_listing_shows_known_channels_only_and_never_the_serial(self):
        with tempfile.TemporaryDirectory() as t:
            got = sensors.list_sensors(self.tree(t))
        self.assertEqual([s["index"] for s in got], [0, 1])
        self.assertEqual(got[0]["name"], "bme680")
        attrs = {c["attr"] for c in got[0]["channels"]}
        self.assertEqual(attrs, {"in_temp_input", "in_humidityrelative_input", "in_pressure_input", "in_resistance_raw"})
        self.assertNotIn("serial", repr(got))

    def test_reading_gives_whole_numbers_in_named_units(self):
        with tempfile.TemporaryDirectory() as t:
            r = sensors.read_sensor(0, self.tree(t))
        got = {x["kind"]: (x["v"], x["unit"]) for x in r["readings"]}
        self.assertEqual(got, {"heat": (23500, "mC"), "humidity": (45123, "m%"), "pressure": (101325, "Pa"),
                               "smell": (12345, "ohm")})
        self.assertTrue(all(type(x["v"]) is int for x in r["readings"]))
        self.assertEqual(r["skipped"], 0)

    def test_a_channel_that_makes_no_sense_is_skipped_and_counted_not_believed(self):
        with tempfile.TemporaryDirectory() as t:
            r = sensors.read_sensor(1, self.tree(t))
        self.assertEqual([(x["kind"], x["v"]) for x in r["readings"]], [("light", 12500)])
        self.assertEqual(r["skipped"], 3)

    def test_an_unknown_sensor_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(sensors.SensorError):
                sensors.read_sensor(7, self.tree(t))
            self.assertEqual(sensors.list_sensors(Path(t) / "missing"), [])


class TestFileWalk(unittest.TestCase):
    def make(self, t):
        root = Path(t) / "proj"
        (root / "src" / "deep" / "deeper").mkdir(parents=True)
        (root / "src" / "main.py").write_text("import util\nprint('coffee coffee coffee')\n")
        (root / "src" / "deep" / "deeper" / "x.txt").write_text("far down")
        (root / "notes.md").write_text("# espresso notes\n")
        (root / ".env").write_text("API_KEY=hunter2\n")
        (root / "my_token.txt").write_text("tok-abc\n")
        (root / "key.pem").write_text("-----BEGIN-----\n")
        (root / "blob.bin").write_bytes(b"\x00\x01\x02hello")
        (root / "big.txt").write_text("x" * (filewalk.MAX_HEAD_FILE + 10))
        outside = Path(t) / "outside"
        outside.mkdir()
        (outside / "private.txt").write_text("TOP SECRET")
        os.symlink(outside, root / "link-to-outside")
        os.symlink(outside / "private.txt", root / "link-file")
        return root

    def test_a_tree_in_one_call_with_relative_paths(self):
        with tempfile.TemporaryDirectory() as t:
            r = filewalk.walk(str(self.make(t)), limit=100, depth=4)
        paths = {e["path"]: e for e in r["entries"]}
        self.assertIn("src", paths)
        self.assertTrue(paths["src"]["dir"])
        self.assertIn("src/main.py", paths)
        self.assertEqual(paths["notes.md"]["size"], 17)
        self.assertFalse(r["truncated"])
        self.assertNotIn("head", paths["notes.md"], "heads are not read unless asked for")

    def test_symlinks_are_never_followed_and_nothing_outside_leaks(self):
        with tempfile.TemporaryDirectory() as t:
            r = filewalk.walk(str(self.make(t)), 100, 4, heads=True)
        blob = repr(r)
        self.assertNotIn("link-to-outside", blob)
        self.assertNotIn("link-file", blob)
        self.assertNotIn("TOP SECRET", blob)
        self.assertNotIn("private.txt", blob)

    def test_heads_are_read_for_text_and_a_sample_for_anything_else_but_never_for_secrets(self):
        with tempfile.TemporaryDirectory() as t:
            r = filewalk.walk(str(self.make(t)), 100, 4, heads=True)
        got = {e["path"]: e for e in r["entries"]}
        self.assertIn("coffee", got["src/main.py"]["head"])
        self.assertIn("espresso", got["notes.md"]["head"])
        self.assertEqual(bytes.fromhex(got["blob.bin"]["sample"]), b"\x00\x01\x02hello", "any other file: its first bytes")
        self.assertEqual(len(got["big.txt"].get("sample", "")), filewalk.SAMPLE_BYTES * 2, "too big for a head, so a sample")
        self.assertNotIn("head", got["big.txt"])
        for hidden in (".env", "my_token.txt", "key.pem"):
            self.assertNotIn("head", got[hidden], hidden)
            self.assertNotIn("sample", got[hidden], hidden)
        self.assertNotIn("hunter2", repr(r))
        self.assertNotIn("tok-abc", repr(r))
        self.assertIsInstance(r["t"], int)

    def test_one_call_can_never_return_more_than_a_reply_can_carry(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for i in range(200):
                (root / f"f{i}.bin").write_bytes(bytes([i % 256]) * 9000)
            with mock.patch.object(filewalk, "HEAD_BUDGET", 50_000):
                r = filewalk.walk(str(root), 300, 2, heads=True)
        total = sum(len(e.get("head", "")) + len(e.get("sample", "")) for e in r["entries"])
        self.assertLessEqual(total, 50_000 + filewalk.SAMPLE_BYTES * 2)
        self.assertGreater(sum(1 for e in r["entries"] if "sample" in e), 0)
        self.assertGreater(sum(1 for e in r["entries"] if "sample" not in e), 0, "the budget ran out")

    def test_depth_and_count_are_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            root = str(self.make(t))
            shallow = filewalk.walk(root, 100, depth=1)
            self.assertNotIn("src/main.py", {e["path"] for e in shallow["entries"]})
            self.assertNotIn("src/deep/deeper/x.txt", {e["path"] for e in filewalk.walk(root, 100, depth=3)["entries"]})
            self.assertIn("src/deep/deeper/x.txt", {e["path"] for e in filewalk.walk(root, 100, depth=4)["entries"]})
            few = filewalk.walk(root, limit=3, depth=4)
            self.assertEqual((len(few["entries"]), few["truncated"]), (3, True))

    def test_a_file_or_a_missing_path_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "a.txt"
            f.write_text("x")
            for p in (str(f), str(Path(t) / "nope")):
                with self.assertRaises(ValueError):
                    filewalk.walk(p)


class TestTheServices(Base):
    def setUp(self):
        super().setUp()
        self.kernel = FakeKernel()
        patcher = mock.patch.object(camera, "_Kernel", lambda: self.kernel)
        # the stream calls the kernel through attribute access on the class: hand it the instance's methods
        patcher.stop()
        self.p = mock.patch.object(camera, "_Kernel", self.kernel)
        self.p.start()
        self.addCleanup(self.p.stop)

    def test_the_group_must_be_in_the_manifest(self):
        r = self.call(self.host("files"), "camera.capture", {"cams": ["video0"]})
        self.assertFalse(r["ok"])
        self.assertIn("service:camera", r["detail"])
        self.assertEqual(self.kernel.opened, [])

    def test_a_wrong_or_cancelled_password_opens_no_camera(self):
        for answers in (("no", "no", "no"), (None,)):
            r = self.call(self.host("camera"), "camera.capture", {"cams": ["video0", "video1"], "width": 32, "height": 24},
                          *answers)
            self.assertFalse(r["ok"])
            self.assertEqual(r["data"], {})
        self.assertEqual(self.kernel.opened, [], "the camera was never touched")
        self.assertTrue(any(e["action"] == "camera.capture" and e["outcome"] in ("denied", "cancelled")
                            for e in AuditLog(self.paths).entries()))

    def test_with_the_password_two_cameras_answer_and_it_is_logged_with_their_names(self):
        r = self.call(self.host("camera"), "camera.capture", {"cams": ["video0", "video1"], "width": 32, "height": 24,
                                                               "count": 2}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["data"]["w"], r["data"]["h"], len(r["data"]["sets"])), (32, 24, 2))
        self.assertEqual(self.kernel.closed, {100, 101})
        self.assertIn(("camera.capture", "video0,video1"),
                      [(e["action"], e["target"]) for e in AuditLog(self.paths).entries()])

    def test_what_cannot_fit_is_refused_before_the_password_is_asked(self):
        h = self.host("camera")
        for args in ({"cams": ["video0"], "width": 320, "height": 240, "count": 8},
                     {"cams": ["video0"], "count": 5, "every_ms": 10_000},
                     {"cams": ["video0", "video1", "video2", "video3", "video0"]},
                     {"cams": ["../../etc/passwd"]}, {"cams": ["video0; rm -rf /"]}, {"cams": []}):
            r = self.call(h, "camera.capture", args)                      # no answers given: asking would raise
            self.assertFalse(r["ok"], args)
            self.assertEqual(self.prompter.asked, [], f"the owner was asked for a password for {args}")
            self.assertNotIn("internal error", r["detail"], "a refusal with a reason, not a crash")
        self.assertEqual(self.kernel.opened, [])

    def test_a_camera_fault_is_a_refusal_the_app_can_show(self):
        self.kernel.fmt = 0x47504A4D
        r = self.call(self.host("camera"), "camera.capture", {"cams": ["video0"], "width": 32, "height": 24}, PW)
        self.assertFalse(r["ok"])
        self.assertIn("YUYV", r["detail"])
        self.assertEqual(self.kernel.closed, {100})

    def test_listing_cameras_needs_the_password_too(self):
        with mock.patch.object(camera, "list_cameras", lambda: [{"node": 0, "name": "Cam"}]):
            self.assertFalse(self.call(self.host("camera"), "camera.list", {}, "no", "no", "no")["ok"])
            r = self.call(self.host("camera"), "camera.list", {}, PW)
        self.assertEqual(r["data"]["cameras"], [{"node": 0, "name": "Cam"}])

    def test_sensor_services(self):
        with tempfile.TemporaryDirectory() as t:
            root = TestSensors().tree(t)
            with mock.patch.object(sensors, "IIO", root):
                h = self.host("sensor")
                self.assertFalse(self.call(h, "sensor.read", {"index": 0}, "no", "no", "no")["ok"])
                r = self.call(h, "sensor.read", {"index": 0}, PW)
                self.assertTrue(r["ok"], r)
                self.assertEqual({x["kind"] for x in r["data"]["readings"]}, {"heat", "humidity", "pressure", "smell"})
                self.assertEqual(len(self.call(h, "sensor.list", {}, PW)["data"]["sensors"]), 2)
                bad = self.call(h, "sensor.read", {"index": 9}, PW)
                self.assertFalse(bad["ok"])
                with self.assertRaises(ProtocolError, msg="a decimal is refused by the protocol, before any service sees it"):
                    self.call(h, "sensor.read", {"index": 1.5}, PW)
                with self.assertRaises(ProtocolError):
                    self.call(h, "sensor.read", {"index": -1}, PW)

    def test_a_sweep_reads_every_sensor_under_one_password(self):
        with tempfile.TemporaryDirectory() as t:
            root = TestSensors().tree(t)
            with mock.patch.object(sensors, "IIO", root):
                h = self.host("sensor")
                self.assertFalse(self.call(h, "sensor.sweep", {}, "no", "no", "no")["ok"])
                r = self.call(h, "sensor.sweep", {}, PW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(self.prompter.asked), 1, "one password for all the sensors")
        self.assertEqual([s["index"] for s in r["data"]["sensors"]], [0, 1])
        self.assertIsInstance(r["data"]["t"], int)
        self.assertTrue(all(type(x["v"]) is int for s in r["data"]["sensors"] for x in s["readings"]))

    def test_the_clock_is_whole_seconds_and_needs_the_password(self):
        h = self.host("clock")
        self.assertFalse(self.call(h, "clock.now", {}, "no", "no", "no")["ok"])
        r = self.call(h, "clock.now", {}, PW)
        self.assertTrue(r["ok"] and type(r["data"]["t"]) is int and r["data"]["t"] > 1_700_000_000, r)
        self.assertFalse(self.call(self.host("files"), "clock.now", {})["ok"], "the group must be asked for")

    def test_files_walk_asks_once_for_the_whole_tree(self):
        with tempfile.TemporaryDirectory() as t:
            root = TestFileWalk().make(t)
            r = self.call(self.host("files"), "files.walk", {"path": str(root), "heads": True}, PW)
            self.assertTrue(r["ok"], r)
            self.assertEqual(len(self.prompter.asked), 1, "one password for the tree, not one per folder")
            self.assertIn("whole tree", self.prompter.asked[0])
            self.assertIn("src/main.py", {e["path"] for e in r["data"]["entries"]})
            self.assertFalse(self.call(self.host("files"), "files.walk", {"path": str(root)}, "no", "no", "no")["ok"])

    def test_files_walk_output_is_scrubbed_of_terminal_tricks(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "r"
            root.mkdir()
            (root / "evil\x1b[2Jname.txt").write_text("a\x1b]0;pwned\x07b")
            r = self.call(self.host("files"), "files.walk", {"path": str(root), "heads": True}, PW)
        self.assertNotIn("\x1b", repr(r["data"]).replace("\\x1b", ""))
        self.assertTrue(r["ok"], r)


if __name__ == "__main__":
    unittest.main()
