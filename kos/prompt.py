"""Ways of asking the human something.

There is deliberately no way to feed a password from a file, an environment
variable or a pipe: the only production prompter reads from the controlling
terminal (``/dev/tty``) with echo off. Inside a running app session the
session's own on-screen prompter is used instead (see ``session.py``), which
draws the prompt as a trusted overlay the app cannot draw over or read.
"""

from __future__ import annotations

import os
import sys
import termios
from typing import Iterable, Optional, Protocol


class Prompter(Protocol):
    def password(self, prompt: str) -> Optional[bytes]: ...
    def confirm(self, question: str) -> bool: ...
    def info(self, message: str) -> None: ...


class NoTTY(RuntimeError):
    pass


class TTYPrompter:
    def __init__(self, tty_path: str = "/dev/tty"):
        try:
            self.fd = os.open(tty_path, os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        except OSError as e:
            raise NoTTY("KOS only accepts passwords typed on a terminal") from e

    def _write(self, s: str) -> None:
        os.write(self.fd, s.encode())

    def _readline(self) -> Optional[bytes]:
        buf = bytearray()
        while True:
            ch = os.read(self.fd, 1)
            if not ch or ch == b"\x04":  # EOF / Ctrl-D
                return None if not buf else bytes(buf)
            if ch in (b"\n", b"\r"):
                return bytes(buf)
            buf += ch

    def password(self, prompt: str) -> Optional[bytes]:
        self._write(prompt)
        old = termios.tcgetattr(self.fd)
        new = termios.tcgetattr(self.fd)
        new[3] &= ~(termios.ECHO | termios.ECHONL)
        try:
            termios.tcsetattr(self.fd, termios.TCSAFLUSH, new)
            line = self._readline()
        except KeyboardInterrupt:
            line = None
        finally:
            termios.tcsetattr(self.fd, termios.TCSAFLUSH, old)
            self._write("\n")
        return line

    def confirm(self, question: str) -> bool:
        self._write(f"{question} [y/N] ")
        line = self._readline() or b""
        return line.strip().lower() in (b"y", b"yes")

    def info(self, message: str) -> None:
        self._write(message + "\n")

    def close(self) -> None:
        os.close(self.fd)


class ScriptedPrompter:
    """Test double. Answers come from a list; every question is recorded."""

    def __init__(self, answers: Iterable):
        self.answers = list(answers)
        self.asked: list[str] = []
        self.messages: list[str] = []

    def _next(self, prompt: str):
        self.asked.append(prompt)
        if not self.answers:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return self.answers.pop(0)

    def password(self, prompt: str) -> Optional[bytes]:
        a = self._next(prompt)
        return a.encode() if isinstance(a, str) else a

    def confirm(self, question: str) -> bool:
        return bool(self._next(question))

    def info(self, message: str) -> None:
        self.messages.append(message)


def eprint(*a) -> None:
    print(*a, file=sys.stderr)
