"""Input devices, and what "booting" a device means.

KOS never hands a device to an app. The OS reads the device and forwards
*commands* ("key a", "pointer 10,20", "click left") to the app, and only after
the owner has booted that device for that app with the password.

* Mouse: before it is booted the OS does not even open it (evdev) or turn on
  mouse reporting (terminal). After booting, it is opened with ``EVIOCGRAB``,
  which makes KOS its *exclusive* reader: nothing else on the system (e.g. a
  keylogger or another app) can read it at the same time.
* Keyboard: the OS itself has to read the keyboard, because that is how you
  type the password that boots it. So "booting the keyboard" means "start
  forwarding keystrokes to the app". Until then keystrokes only ever reach the
  OS's secure prompt.

Ctrl-C is reserved by the OS in every mode: it always ends the app session, so
an app can never trap you.
"""

from __future__ import annotations

import fcntl
import os
import struct
from pathlib import Path
from typing import Optional

from .term import KeyParser, RawTerminal

EV_SYN, EV_KEY, EV_REL = 0x00, 0x01, 0x02
REL_X, REL_Y, REL_WHEEL = 0x00, 0x01, 0x08
BTN_LEFT, BTN_RIGHT, BTN_MIDDLE = 0x110, 0x111, 0x112
EVIOCGRAB = 0x40044590
INPUT_EVENT = struct.Struct("llHHi")  # struct input_event on 64-bit

_US = {
    2: "1!", 3: "2@", 4: "3#", 5: "4$", 6: "5%", 7: "6^", 8: "7&", 9: "8*", 10: "9(",
    11: "0)", 12: "-_", 13: "=+", 16: "qQ", 17: "wW", 18: "eE", 19: "rR", 20: "tT",
    21: "yY", 22: "uU", 23: "iI", 24: "oO", 25: "pP", 26: "[{", 27: "]}", 30: "aA",
    31: "sS", 32: "dD", 33: "fF", 34: "gG", 35: "hH", 36: "jJ", 37: "kK", 38: "lL",
    39: ";:", 40: "'\"", 41: "`~", 43: "\\|", 44: "zZ", 45: "xX", 46: "cC", 47: "vV",
    48: "bB", 49: "nN", 50: "mM", 51: ",<", 52: ".>", 53: "/?", 57: "  ",
}
_NAMED = {1: "escape", 14: "backspace", 15: "tab", 28: "enter", 96: "enter",
          102: "home", 103: "up", 104: "pageup", 105: "left", 106: "right",
          107: "end", 108: "down", 109: "pagedown", 111: "delete"}
_SHIFT = {42, 54}
_CTRL = {29, 97}


class DeviceError(RuntimeError):
    pass


class TerminalDevices:
    """Keyboard and mouse as seen through a terminal (xterm SGR mouse)."""

    kind = "terminal"

    def __init__(self, term: RawTerminal, cell_to_pixels: bool):
        self.term = term
        self.parser = KeyParser()
        # In graphical mode, one cell = 1 pixel wide, 2 pixels tall.
        self.cell_to_pixels = cell_to_pixels

    def fds(self) -> list[int]:
        return [self.term.in_fd]

    def read(self, fd: int) -> list[dict]:
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            return []
        if not data:
            return [{"type": "interrupt"}]
        events = self.parser.feed(data)
        if self.cell_to_pixels:
            for e in events:
                if "y" in e:
                    e["y"] *= 2
        return events

    def boot_mouse(self) -> str:
        self.term.enable_mouse()
        return "terminal mouse"

    def boot_keyboard(self) -> str:
        return "terminal keyboard"

    def close(self) -> None:
        pass


def _read_proc_devices(text: str) -> list[dict]:
    devs, cur = [], {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if cur:
                devs.append(cur)
            cur = {}
            continue
        tag, _, rest = line.partition(": ")
        if tag == "N":
            cur["name"] = rest.split("=", 1)[1].strip('"')
        elif tag == "H":
            cur["handlers"] = rest.split("=", 1)[1].split()
        elif tag == "B":
            k, _, v = rest.partition("=")
            cur[k] = int(v.split()[-1], 16) if v else 0
    return devs


def find_evdev(kind: str, proc_text: Optional[str] = None) -> list[str]:
    if proc_text is None:
        proc_text = Path("/proc/bus/input/devices").read_text()
    out = []
    for d in _read_proc_devices(proc_text):
        events = [h for h in d.get("handlers", []) if h.startswith("event")]
        if not events:
            continue
        ev = d.get("EV", 0)
        is_mouse = bool(ev & (1 << EV_REL)) and any(h.startswith("mouse") for h in d["handlers"])
        is_kbd = "kbd" in d["handlers"] and bool(ev & (1 << EV_KEY)) and not is_mouse \
            and d.get("KEY", 0) != 0
        if (kind == "mouse" and is_mouse) or (kind == "keyboard" and is_kbd):
            out.append(f"/dev/input/{events[0]}")
    return out


class EvdevTranslator:
    """Turns raw ``struct input_event`` records into KOS input events."""

    def __init__(self, width: int, height: int):
        self.w, self.h = width, height
        self.x, self.y = width // 2, height // 2
        self.moved = False
        self.shift = self.ctrl = False

    def feed(self, raw: bytes) -> list[dict]:
        out: list[dict] = []
        for off in range(0, len(raw) - INPUT_EVENT.size + 1, INPUT_EVENT.size):
            _, _, etype, code, value = INPUT_EVENT.unpack_from(raw, off)
            if etype == EV_REL:
                if code == REL_X:
                    self.x = max(0, min(self.w - 1, self.x + value))
                    self.moved = True
                elif code == REL_Y:
                    self.y = max(0, min(self.h - 1, self.y + value))
                    self.moved = True
                elif code == REL_WHEEL:
                    out.append({"type": "scroll", "dy": -value, "x": self.x, "y": self.y})
            elif etype == EV_KEY:
                if code in (BTN_LEFT, BTN_RIGHT, BTN_MIDDLE):
                    name = {BTN_LEFT: "left", BTN_RIGHT: "right", BTN_MIDDLE: "middle"}[code]
                    if value in (0, 1):
                        out.append({"type": "button", "button": name, "pressed": value == 1,
                                    "x": self.x, "y": self.y})
                elif code in _SHIFT:
                    self.shift = value != 0
                elif code in _CTRL:
                    self.ctrl = value != 0
                elif value in (1, 2):  # press or autorepeat
                    ev = self._key(code)
                    if ev:
                        out.append(ev)
            elif etype == EV_SYN and self.moved:
                self.moved = False
                out.append({"type": "pointer", "x": self.x, "y": self.y})
        return out

    def _key(self, code: int) -> Optional[dict]:
        if code in _NAMED:
            return {"type": "key", "key": _NAMED[code]}
        pair = _US.get(code)
        if not pair:
            return None
        ch = pair[1] if self.shift else pair[0]
        if self.ctrl:
            if ch.lower() == "c":
                return {"type": "interrupt"}
            return {"type": "key", "key": "ctrl-" + ch.lower()}
        return {"type": "key", "key": ch}


class EvdevDevices:
    """Real hardware on a KOS console. Keyboards are grabbed from the start
    (only the OS reads them); mice are opened only when booted."""

    kind = "evdev"

    def __init__(self, width: int, height: int):
        self.tr = EvdevTranslator(width, height)
        self._fds: list[int] = []
        kbds = find_evdev("keyboard")
        if not kbds:
            raise DeviceError("no keyboard found")
        for path in kbds:
            self._open(path)

    def _open(self, path: str) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, EVIOCGRAB, 1)
        except OSError:
            os.close(fd)
            raise DeviceError(f"{path} is already grabbed by someone else - refusing")
        self._fds.append(fd)

    def fds(self) -> list[int]:
        return list(self._fds)

    def read(self, fd: int) -> list[dict]:
        try:
            raw = os.read(fd, INPUT_EVENT.size * 64)
        except BlockingIOError:
            return []
        return self.tr.feed(raw)

    def boot_mouse(self) -> str:
        mice = find_evdev("mouse")
        if not mice:
            raise DeviceError("no mouse found")
        for path in mice:
            self._open(path)
        return ", ".join(mice)

    def boot_keyboard(self) -> str:
        return "keyboard"

    def close(self) -> None:
        for fd in self._fds:
            try:
                fcntl.ioctl(fd, EVIOCGRAB, 0)
            except OSError:
                pass
            os.close(fd)
        self._fds.clear()


class ScriptedDevices:
    """Test double: events are written into a pipe by the test."""

    kind = "scripted"

    def __init__(self) -> None:
        import json
        self._json = json
        self.r, self.w = os.pipe()
        os.set_blocking(self.r, False)
        self.booted: list[str] = []
        self._buf = b""

    def push(self, *events: dict) -> None:
        for e in events:
            os.write(self.w, self._json.dumps(e).encode() + b"\n")

    def fds(self) -> list[int]:
        return [self.r]

    def read(self, fd: int) -> list[dict]:
        try:
            self._buf += os.read(fd, 65536)
        except BlockingIOError:
            pass
        *lines, self._buf = self._buf.split(b"\n")
        return [self._json.loads(l) for l in lines if l]

    def boot_mouse(self) -> str:
        self.booted.append("mouse")
        return "scripted mouse"

    def boot_keyboard(self) -> str:
        self.booted.append("keyboard")
        return "scripted keyboard"

    def close(self) -> None:
        os.close(self.r)
        os.close(self.w)
