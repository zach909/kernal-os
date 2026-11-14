"""The text layer: non-graphical, plain text, nothing but characters.

Where the layers sit (see README "The pipeline"):

    graphical   pixels (``display.py``)
    text        THIS: plain lines of characters, no pixels, no colours, no cursor movement
    button      clicks, keys (``devices.py``)

``tui.py`` is "non-graphical but kind of graphical": it takes over the whole screen, positions things
with escape sequences and paints colours. This is the layer under it. The OS prints a *transcript*,
one plain line after another, on the ordinary terminal screen, so it works where a full screen does
not: a serial console, a screen reader, a pipe into a file, a terminal that cannot do escape
sequences. The app is the same app: it sends ``screen`` commands (it is told ``tui``) and does not
know which layer is showing them.

Security, in this layer:

* **Who said it is always visible.** Every line the OS prints starts ``KOS| ``. Every line that came
  from the app starts ``app| ``, including each wrapped continuation. An app's text cannot contain a
  newline (``protocol.clean_text`` removes them, and this layer replaces anything unprintable again),
  so an app cannot write a line that starts ``KOS| `` and so cannot fake a password prompt, a
  device notice or an error. The password prompt is printed by the OS, as ``KOS| `` lines, and what
  you type for it is never echoed and never printed.
* **Plain characters only.** Anything that is not printable becomes ``?``: escape sequences, the
  bidi controls that reorder text, zero-width characters, a non-breaking space. Nothing can move the
  cursor, clear the screen, recolour a line or hide text.
* **No pointer.** There is nothing to point at. Mouse events are not forwarded to a text session and
  the mouse is not even offered for booting (``has_pointer`` is False).
* **A page is printed once.** An unchanged page is not printed again, and a changing page is held
  back to one print per ``MIN_GAP_MS`` (the latest wins), so an app cannot flood the terminal or a
  screen reader. ``deferred`` tells the session there is something still to print.

Standard library only; whole numbers only.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from .display import Modal

OS_PREFIX = "KOS| "
APP_PREFIX = "app| "
MIN_GAP_MS = 250
MIN_WIDTH = 20


def plain(s: str) -> str:
    """Printable characters only; every other character becomes '?'. The second line of defence
    behind ``protocol.clean_text``, so the guarantee does not depend on the caller."""
    return "".join(c if c.isprintable() else "?" for c in str(s))


def wrap(text: str, width: int) -> list[str]:
    """Split ``text`` into pieces of at most ``width`` characters (an empty line stays one empty line)."""
    width = max(1, width)
    return [text[i:i + width] for i in range(0, len(text), width)] or [""]


class TextSurface:
    """Drop-in replacement for ``TUISurface`` in ``text`` mode."""

    has_pointer = False

    def __init__(self, out_fd: int, cols: int, rows: int, app_name: str, *,
                 clock: Callable[[], int] = time.monotonic_ns):
        self.fd = out_fd
        self.cols, self.rows = max(MIN_WIDTH, cols), rows
        self.app = plain(app_name)
        self.clock = clock
        self.title = ""
        self.lines: list[str] = []
        self.app_status = ""
        self.status = ""
        self.modal: Optional[Modal] = None
        self.has_content = False
        self.pointer = None
        self.deferred = False
        self._page: Optional[tuple] = None          # (title, lines) the app wants shown
        self._printed_page: Optional[tuple] = None
        self._printed_status: Optional[str] = None
        self._printed_modal: Optional[tuple] = None
        self._last_print_ms = -MIN_GAP_MS

    # --- what the session asks of every surface ------------------------------------------
    def hello_size(self) -> tuple[int, int]:
        return self.cols - len(APP_PREFIX), self.rows

    def present(self, msg: dict) -> None:
        self.title, self.lines, self.app_status = msg["title"], msg["lines"], msg["status"]
        self._page = (self.title, tuple(self.lines), self.app_status)
        self.has_content = True

    def set_pointer(self, x: int, y: int) -> None:
        pass            # nothing to point at; the session never sends pointer events here

    def set_modal(self, modal: Optional[Modal]) -> None:
        self.modal = modal

    def set_status(self, text: str) -> None:
        self.status = text

    def to_app_coords(self, x: int, y: int) -> tuple[int, int]:
        return x, y

    def close(self) -> None:
        pass

    # --- output -------------------------------------------------------------------------
    def _os(self, text: str) -> list[str]:
        return [OS_PREFIX + part for part in wrap(plain(text), self.cols - len(OS_PREFIX))]

    def _app(self, text: str) -> list[str]:
        return [APP_PREFIX + part for part in wrap(plain(text), self.cols - len(APP_PREFIX))]

    def _prompt_block(self, modal: Modal) -> list[str]:
        out = self._os("== SECURE PROMPT: what you type next goes to KOS, never to the app ==")
        out += self._os(modal.title)
        for line in modal.lines:
            out += self._os(line)
        if modal.secret_len is not None:
            out += self._os("(a password is not shown or counted on screen)")
        return out

    def render(self) -> None:
        out: list[str] = []
        # 1. The OS's own prompt comes first and is never held back. It is printed once, when it
        #    appears; typing into it prints nothing (a password's length is not a secret to share).
        if self.modal is not None:
            shown = (self.modal.title, tuple(self.modal.lines), self.modal.secret_len is not None)
            if shown != self._printed_modal:
                self._printed_modal = shown
                out += self._prompt_block(self.modal)
        elif self._printed_modal is not None:
            self._printed_modal = None
            out += self._os("== prompt closed ==")
        # 2. The app's page, if it changed and the last print was long enough ago.
        self.deferred = False
        if self._page is not None and self._page != self._printed_page:
            now = self.clock() // 1_000_000
            if now - self._last_print_ms >= MIN_GAP_MS:
                title, lines, app_status = self._page
                self._printed_page, self._last_print_ms = self._page, now
                out += self._os(f"page from {self.app}")
                if title:
                    out += self._app("== " + title + " ==")
                for line in lines:
                    out += self._app(line)
                if app_status:
                    out += self._app("status: " + app_status)
            else:
                self.deferred = True
        # 3. The OS's status line (which devices are on), when it changes.
        if self.status != self._printed_status:
            self._printed_status = self.status
            out += self._os(self.status.strip())
        if out:
            self._write(("\r\n".join(out) + "\r\n").encode("utf-8", "replace"))

    def _write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            n = os.write(self.fd, view)
            view = view[n:]
