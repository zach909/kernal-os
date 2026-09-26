"""``cmd`` mode: no drawing at all - the raw command stream, visible.

This is the mode for "command based": once you boot the mouse, every click
and key is turned into the same JSON command a graphical or TUI app would
receive, but instead of the OS turning the app's replies into pixels or
text, it just prints each command as it crosses the wire. Useful for driving
an app from a script, or for seeing exactly what KOS sends.

Still goes through the same gate as everything else: nothing is shown to the
app, and nothing from the app is printed, until the device that produced it
has been booted with the password, and every line still passes through
``validate_app_message``/``clean_text`` so an app can't use escape sequences
to take over the terminal.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .display import Modal, render_text_modal


class CmdSurface:
    """Drop-in replacement for TUISurface/GraphicalSurface in cmd mode."""

    def __init__(self, out_fd: int, cols: int, rows: int, app_name: str):
        self.fd = out_fd
        self.cols, self.rows = cols, rows
        self.app = app_name
        self.has_content = True  # no "first frame" to wait for; commands print as they arrive
        self.modal: Optional[Modal] = None
        self.pointer = None
        self._status = ""

    def hello_size(self) -> tuple[int, int]:
        return self.cols, self.rows

    def to_app_coords(self, x: int, y: int) -> tuple[int, int]:
        return x, y

    def present(self, msg: dict) -> None:
        pass  # cmd mode has no screen/frame; see protocol.validate_app_message

    def set_pointer(self, x: int, y: int) -> None:
        self.pointer = (x, y)

    def set_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal

    def set_status(self, text: str) -> None:
        self._status = text

    def emit(self, direction: str, cmd: dict) -> None:
        """Called by the session for every command sent to, or received from,
        the app - the one place cmd-mode output happens."""
        line = f"{direction} {json.dumps(cmd, separators=(',', ':'))}\n"
        os.write(self.fd, line.encode())

    def render(self) -> None:
        if self.modal:
            os.write(self.fd, render_text_modal(self.modal, self.cols, self.rows).encode())

    def close(self) -> None:
        pass
