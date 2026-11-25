"""Drop in a zip, it runs: an agent (or any program) shipped as a zip file, run sandboxed with nothing.

``kos`` apps are already zip files, but they must be packed, proven, installed and permitted first. This is
the short road for a zip you were just handed: you name the file, the OS reads it (never unzipping it onto
disk), and in this order:

1. **scan** it for known-bad patterns (a flagged zip is refused before any prompt);
2. **inspect** it: how many entries, how big, no ``..`` or absolute names, no symlinks, no encrypted entries,
   no zip bomb, a ``manifest.json`` at the top (or inside the one folder that holds everything);
3. **prove** it: the zip must carry a valid ``proof.json`` (a packed ``.kapp``), or else it is a plain source
   zip and the OS works the proof out itself from the exact bytes, which is what ``kos pack`` does. Code with
   a decimal, a banned call, or that does not compile is refused. Compiled programs are refused: they
   cannot be checked;
4. **ask for the password**, once, naming the program, the zip's SHA-256 and what it *asked for*;
5. **run it** like a line of code (``coderun.py``): one sandboxed process, unprivileged, no network, no files,
   no devices, no OS functions; it can only print (``log``) and finish (``exit``), and a request for anything
   else stops it; a time limit; the scratch folder wiped after. Every line it prints starts ``app| ``.

What it will not do: give the program anything it asked for. Whatever the manifest lists under
``permissions`` is shown in the prompt and **not granted**. A program that needs the network, a shared folder
or the OS's functions must be installed (``kos install``) and permitted the usual way, where every grant has its
own password. The zip must support ``cmd`` mode (a program that only draws a screen has nothing to print).
Nothing it prints can pass for the OS: control and bidi characters are shown as visible escapes.

This is the runner's contract, not a proof that the program is safe: the scan is heuristic, the proof is a static
rule check, and the sandbox is what contains it. See the README gaps table.
"""

from __future__ import annotations

import hashlib
import io
import os
import select
import socket
import stat
import time
import zipfile
from pathlib import Path
from typing import Callable, Optional

from . import cache, loader, proof
from .auth import Authority
from .kapp import MANIFEST, KApp, KAppError, Manifest, _check_member_name, supports_mode
from .paths import Paths
from .protocol import Channel, ProtocolError, escape_text, validate_app_message
from .sandbox import SandboxPolicy
from .scan import scan_bytes

MAX_ZIP = 8 << 20
MAX_ENTRIES = 300
MAX_ENTRY = 4 << 20
MAX_TOTAL = 24 << 20
MAX_RATIO = 200                 # an entry may not expand to more than this many times its stored size
TIMED_OUT, PROTOCOL, REFUSED = 124, 125, 3


class ZipRunError(Exception):
    """The zip is refused. The message says why, in words the owner can read."""


def _now_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def _wait(files, ms: int) -> bool:
    p = select.poll()
    for f in files:
        p.register(f, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(p.poll(max(0, ms)))


class Prepared:
    """A zip that passed every check before the password: what it is, and the kapp that will run."""

    def __init__(self, app: KApp, sha256: str, asked: tuple, packed: bool):
        self.app, self.sha256, self.asked, self.packed = app, sha256, asked, packed

    @property
    def name(self) -> str:
        return self.app.manifest.name


def _read_zip(path: Path) -> bytes:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise ZipRunError("that is not a plain file")
        if st.st_size > MAX_ZIP:
            raise ZipRunError(f"that zip is bigger than {MAX_ZIP >> 20} MiB")
        with open(path, "rb") as f:
            data = f.read(MAX_ZIP + 1)
    except OSError as e:
        raise ZipRunError(f"cannot read that: {e.strerror or 'refused'}") from None
    if len(data) > MAX_ZIP:
        raise ZipRunError(f"that zip is bigger than {MAX_ZIP >> 20} MiB")
    return data


def prepare(data: bytes, label: str = "<zip>") -> Prepared:
    """Everything that can be checked without the password. Raises ``ZipRunError``."""
    try:
        result = scan_bytes(data, label=label)
    except Exception as e:                  # a zip the scanner cannot read is a zip nobody has looked inside
        raise ZipRunError(f"it could not be scanned ({type(e).__name__}), so it is not run") from None
    if not result.clean:
        raise ZipRunError(f"blocked by the security scan: {result.summary()}")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ZipRunError(f"not a zip file: {e}") from None
    infos = zf.infolist()
    if not infos:
        raise ZipRunError("the zip is empty")
    if len(infos) > MAX_ENTRIES:
        raise ZipRunError(f"more than {MAX_ENTRIES} entries")
    names, total = set(), 0
    for i in infos:
        try:
            _check_member_name(i.filename)
        except KAppError as e:
            raise ZipRunError(str(e)) from None
        if i.filename in names:
            raise ZipRunError(f"two entries are both called {i.filename!r}")
        names.add(i.filename)
        if i.flag_bits & 0x1:
            raise ZipRunError("encrypted entries are not allowed")
        if stat.S_ISLNK(i.external_attr >> 16):
            raise ZipRunError(f"{i.filename!r} is a symlink")
        if i.file_size > MAX_ENTRY:
            raise ZipRunError(f"{i.filename!r} is too big")
        if i.file_size > 4096 and i.file_size > MAX_RATIO * max(1, i.compress_size):
            raise ZipRunError(f"{i.filename!r} expands {i.file_size // max(1, i.compress_size)} times: a zip bomb")
        total += i.file_size
    if total > MAX_TOTAL:
        raise ZipRunError("too much once unpacked")
    prefix = _root_prefix(names)
    contents: dict = {}
    for i in infos:
        if i.is_dir() or not i.filename.startswith(prefix):
            continue
        with zf.open(i) as f:
            raw = f.read(MAX_ENTRY + 1)
        if len(raw) != i.file_size:
            raise ZipRunError(f"{i.filename!r} is not the size it says")
        contents[i.filename[len(prefix):]] = raw
    if MANIFEST not in contents:
        raise ZipRunError("no manifest.json at the top of the zip (or inside its one folder)")
    try:
        m = Manifest.parse(contents[MANIFEST][:64 << 10])
    except KAppError as e:
        raise ZipRunError(str(e)) from None
    if m.runtime != "python":
        raise ZipRunError("only Python programs can be checked; a compiled program cannot")
    if not supports_mode(m.modes, "cmd"):
        raise ZipRunError("this program has no 'cmd' mode: it only draws a screen, so there is nothing to print. "
                          "Install it (kos install) to use it")
    packed = proof.PROOF_FILE in contents
    try:
        if not packed:
            contents[proof.PROOF_FILE] = proof.make_proof(contents, m.runtime, m.name)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for rel in sorted(contents):
                zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(zi, contents[rel])
        app = KApp(buf.getvalue())
        proof.require(app)
    except KAppError as e:                  # ProofError is one
        raise ZipRunError(str(e)) from None
    return Prepared(app, hashlib.sha256(data).hexdigest(), tuple(m.permissions), packed)


def _root_prefix(names: set) -> str:
    """"" when manifest.json is at the top; ``"dir/"`` when everything lives in one folder."""
    if MANIFEST in names:
        return ""
    tops = {n.split("/", 1)[0] for n in names}
    if len(tops) == 1:
        top = next(iter(tops))
        if f"{top}/{MANIFEST}" in names:
            return top + "/"
    return ""


def describe(p: Prepared) -> str:
    """What the password prompt shows: the program, the zip's fingerprint, and what it asked for and will not get."""
    asked = ", ".join(p.asked) if p.asked else "nothing"
    return (f"{p.name} (zip sha256 {p.sha256[:16]}; asked for: {asked}; it gets none of it; "
            f"{'already proven' if p.packed else 'proof made now'})")[:300]


def _default_launcher(app: KApp, cache_dir: Path, paths: Paths):
    policy = SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    mine, theirs = socket.socketpair()
    proc = loader.launch(loader.plan(app, theirs.fileno(), "cmd", cache_dir), policy,
                         paths.logs.joinpath("ziprun.log"))
    theirs.close()
    return proc, Channel(mine)


def run_zip(paths: Paths, get_authority: Callable[[], Authority], path: str, seconds: int = 30, *,
            out: Callable[[str], None] = print, launcher: Optional[Callable] = None) -> dict:
    """Check, ask, run. Returns ``{"status", "name", "sha256", "asked"}``; ``out`` gets each line printed."""
    p = prepare(_read_zip(Path(path)), label=os.path.basename(path)[:80])
    with get_authority().authorize("zip.run", describe(p)) as _grant:
        pass                                    # the password is the permission; nothing to derive
    paths.ensure()
    cache_dir = cache.alloc(paths, "ziprun")
    status = 0
    proc = channel = None
    try:
        proc, channel = (launcher or (lambda a, c: _default_launcher(a, c, paths)))(p.app, cache_dir)
        channel.send({"cmd": "hello", "mode": "cmd", "width": 80, "height": 24})
        deadline = _now_ms() + seconds * 1000
        lines = 0
        while True:
            left = deadline - _now_ms()
            if left <= 0:
                out(f"stopped: ran longer than {seconds} seconds")
                status = TIMED_OUT
                break
            _wait([channel], min(left, 250))
            try:
                for raw in channel.receive():
                    msg = validate_app_message(raw, "cmd")
                    if msg["cmd"] == "log":
                        if msg["msg"]:
                            lines += 1
                            out("app| " + escape_text(msg["msg"], 2000))      # a program's line never looks like the OS's
                        if lines > 500:
                            out("stopped: more than 500 lines printed")
                            return {"status": 123, "name": p.name, "sha256": p.sha256, "asked": list(p.asked)}
                    elif msg["cmd"] == "exit":
                        return {"status": int(msg.get("code", 0)), "name": p.name, "sha256": p.sha256,
                                "asked": list(p.asked)}
                    else:                      # it may print and finish; asking the OS for anything is not allowed here
                        out(f"stopped: the program asked the OS for '{msg['cmd']}', which a zip run is not given")
                        status = PROTOCOL
                        break
                if status:
                    break
            except ProtocolError as e:
                out(f"stopped: the program broke the protocol ({e})")
                status = PROTOCOL
                break
            if channel.closed or (proc is not None and proc.poll() is not None):
                break
    finally:
        if channel is not None:
            try:
                channel.send({"cmd": "quit"})
            except OSError:
                pass
        if proc is not None:
            try:
                os.killpg(proc.pid, 9)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
        if channel is not None:
            channel.close()
        cache.wipe(cache_dir)
    return {"status": status, "name": p.name, "sha256": p.sha256, "asked": list(p.asked)}
