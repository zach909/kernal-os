"""``kos control ID mouse|keyboard ...``: drive a booted device with a
command instead of your hands.

This is not a new door into an app - it's the same door. A real mouse click
becomes ``{"cmd": "button", ...}`` sent down the app's channel after that
device was booted with the password (see ``session.py``); this module builds
the exact same command shapes and sends them down the same channel, and
asking to send one requires the same password as booting the device would.
The app cannot tell the difference between a click that came from your hand
and one that came from ``kos control`` - which is the point: it is not a
second, weaker input path, it is a scriptable way to use the one input path
that already exists.
"""

from __future__ import annotations

import argparse
import json
import socket

from .protocol import MAX_COORD

_KEY_NAMES = {"enter", "backspace", "tab", "escape", "up", "down", "left", "right",
             "home", "end", "pageup", "pagedown", "insert", "delete"}


class ControlError(Exception):
    pass


def _coord(v: int) -> int:
    v = int(v)
    if not -MAX_COORD <= v <= MAX_COORD:
        raise ControlError(f"coordinate {v} out of range")
    return v


def build_key(key: str) -> dict:
    if key not in _KEY_NAMES and (len(key) != 1 or not key.isprintable()):
        raise ControlError(f"not a single printable character or a known key name: {key!r}")
    return {"cmd": "key", "key": key}


def build_pointer(x: int, y: int) -> dict:
    return {"cmd": "pointer", "x": _coord(x), "y": _coord(y)}


def build_click(button: str, x: int, y: int, pressed: bool = True) -> dict:
    if button not in ("left", "middle", "right"):
        raise ControlError(f"button must be left/middle/right, not {button!r}")
    return {"cmd": "button", "button": button, "pressed": pressed, "x": _coord(x), "y": _coord(y)}


def build_scroll(dy: int, x: int, y: int) -> dict:
    dy = int(dy)
    if dy not in (-1, 1):
        raise ControlError("dy must be -1 or 1")
    return {"cmd": "scroll", "dy": dy, "x": _coord(x), "y": _coord(y)}


def parse_args(device: str, args: list[str]) -> list[dict]:
    """Turn the words after `kos control ID mouse|keyboard` into the exact
    device-attach notice plus command(s) a real boot+click would send."""
    attach = {"cmd": "device", "device": device, "state": "attached"}
    if device == "keyboard":
        if not args:
            raise ControlError("usage: kos control ID keyboard KEY [KEY...]")
        return [attach] + [build_key(k) for k in args]
    if device == "mouse":
        if not args:
            raise ControlError("usage: kos control ID mouse move X Y | click left X Y | scroll -1 X Y")
        sub, rest = args[0], args[1:]
        if sub == "move" and len(rest) == 2:
            return [attach, build_pointer(*rest)]
        if sub == "click" and len(rest) == 3:
            button, x, y = rest
            return [attach, build_click(button, x, y, pressed=True),
                   build_click(button, x, y, pressed=False)]
        if sub == "scroll" and len(rest) == 3:
            return [attach, build_scroll(*rest)]
        raise ControlError("usage: kos control ID mouse move X Y | click BUTTON X Y | scroll DY X Y")
    raise ControlError(f"device must be 'mouse' or 'keyboard', not {device!r}")


def send(sock_path: str, commands: list[dict]) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
        for cmd in commands:
            s.sendall(json.dumps(cmd, separators=(",", ":")).encode() + b"\n")
    finally:
        s.close()
