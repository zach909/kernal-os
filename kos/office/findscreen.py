"""The Ctrl-N box: type, and commands, files and the assistant answer in one list.

See ``finder.py`` for the rules. This file is only the screen: it keeps the text you typed, shows
the rows ``finder.search`` returns under their headings, and on Enter

  * a command  -> shows what it does and the exact line to type (it never runs anything);
  * a file     -> shows the file's text;
  * the assistant row -> opens the assistant (this app's Agent) with your words already sent.

Esc from any of those comes back here with your text still in the box.
"""

from __future__ import annotations

from . import finder
from .ui import ListNav, Message, Screen, TextInput, wrap


class Finder(Screen):
    is_agent = True      # run() must not stack a second box on top of this one when Ctrl-N is pressed again

    def __init__(self, host, title: str, make_agent, commands=finder.COMMANDS):
        """``make_agent(text)`` -> the assistant screen with ``text`` already said (or "" to just talk)."""
        self.host, self.title, self.make_agent, self.commands = host, f"Search: {title}", make_agent, commands
        self.inp = TextInput()
        self.nav = ListNav(0)
        self.files = None            # read lazily: opening the box costs nothing until you type
        self.rows: list = []
        self.help = "type to search   Up/Down choose   Enter open   Esc back"
        self.refresh()

    def refresh(self) -> None:
        if self.files is None and self.inp.value.strip():
            self.files = finder.gather_files(self.host)
        self.rows = finder.search(self.inp.value, files=self.files or (), commands=self.commands)
        self.nav.resize(len(self.rows))

    def render(self, w, h):
        out = ["  " + "find> " + self.inp.render(), ""]
        last = None
        for i, r in enumerate(self.rows):
            if r.kind != last:
                out.append("  " + finder.HEADINGS[r.kind]); last = r.kind
            out.append(("  > " if i == self.nav.sel else "    ") + r.label[:max(10, w - 8)])
            if i == self.nav.sel and r.detail:
                out.append("      " + r.detail[:max(10, w - 10)])
        return out[:max(3, h)]

    def key(self, k):
        if k == "escape":
            return ("pop", None)
        if k == "enter":
            return self.open(self.rows[self.nav.sel]) if self.rows else None
        if k in ("up", "down", "pageup", "pagedown"):
            self.nav.key(k); return None
        if self.inp.key(k):
            self.refresh()
        return None

    def open(self, r):
        if r.kind == finder.ASK:
            return ("push", self.make_agent(r.ref))
        if r.kind == finder.ACTION:
            return ("push", Message("kos " + r.ref, finder.describe_command(self.commands, r.ref)))
        if r.kind == finder.FILE:
            text = finder.file_text(self.files or (), r.ref)
            return ("push", Message(r.label, [finder.plain(l, 400) for l in text[:4000].splitlines()] or ["(empty)"]))
        return None
