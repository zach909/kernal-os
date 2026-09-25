"""TUI mode: the "non-graphical but kind of graphical" page.

The app sends ``screen`` commands (a title, some lines, a status). The OS lays
them out full-screen with its own title bar and status bar. The status bar
always shows which devices the app has been given, and it is drawn by the OS,
so an app cannot pretend it has no keyboard access.
"""

from __future__ import annotations

import os
from typing import Optional

from .display import Modal, render_text_modal


class TUISurface:
    def __init__(self, out_fd: int, cols: int, rows: int, app_name: str):
        self.fd = out_fd
        self.cols, self.rows = cols, rows
        self.app = app_name
        self.title = ""
        self.lines: list[str] = []
        self.app_status = ""
        self.status = ""
        self.modal: Optional[Modal] = None
        self.has_content = False
        self.pointer = None

    def hello_size(self) -> tuple[int, int]:
        return self.cols, self.rows - 2

    def present(self, msg: dict) -> None:
        self.title, self.lines, self.app_status = msg["title"], msg["lines"], msg["status"]
        self.has_content = True

    def set_pointer(self, x: int, y: int) -> None:
        self.pointer = (x, y)

    def set_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal

    def set_status(self, text: str) -> None:
        self.status = text

    def to_app_coords(self, x: int, y: int) -> tuple[int, int]:
        return x, y - 1  # row 0 is the OS title bar

    def render(self) -> None:
        w = self.cols
        out = ["\x1b[H"]
        header = f" KOS > {self.app}" + (f" - {self.title}" if self.title else "")
        out.append("\x1b[0;1;37;44m" + header[:w].ljust(w) + "\x1b[0m")
        body = self.rows - 2
        for i in range(body):
            line = self.lines[i] if i < len(self.lines) else ""
            out.append(f"\x1b[{i + 2};1H\x1b[0m" + line[:w] + "\x1b[K")
        footer = self.status + (f" | {self.app_status}" if self.app_status else "")
        out.append(f"\x1b[{self.rows};1H\x1b[0;7m" + footer[:w].ljust(w) + "\x1b[0m")
        if self.modal:
            out.append(render_text_modal(self.modal, self.cols, self.rows))
        os.write(self.fd, "".join(out).encode())

    def close(self) -> None:
        pass
