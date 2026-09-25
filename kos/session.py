"""An app session: one running app, one surface, the owner's devices.

Flow for ``run graphical <app>`` (``run <app>`` is the same with a TUI page):

  1. (already done by the caller) password -> seal verified -> app launched
     in its sandbox, from its zip, in RAM.
  2. The OS sends ``hello`` and shows the app's first frame.
  3. The OS asks, in a trusted overlay:  "Boot mouse for <app>?"  -> password
  4. The OS asks:                        "Boot keyboard for <app>?" -> password
  5. Loop: device events become commands to the app; the app's commands
     become pixels / text on screen. Ctrl-C always ends the session.

While a trusted prompt is on screen the app receives no input at all and
cannot draw over the prompt.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import time
from collections import deque
from typing import Optional

from .auth import AuthError, Authority, AuthorizationDenied
from .display import Modal
from .devices import DeviceError
from .protocol import Channel, ProtocolError, validate_app_message

BOOT_ORDER = ("mouse", "keyboard")


class SessionPrompter:
    """Prompter that asks through the session's trusted overlay."""

    def __init__(self, session: "Session"):
        self.s = session

    def _read_keys(self):
        """Yield input events from the OS's own input path (never the app's)."""
        while True:
            if self.s.surface_dirty:
                self.s.render()
            if not self.s.pending:
                self.s.pull_input(0.5, include_app=False)
            while self.s.pending:
                yield self.s.pending.popleft()

    def confirm(self, question: str) -> bool:
        self.s.show_modal(Modal(question, ["Press Y for yes, N for no."]))
        try:
            for ev in self._read_keys():
                if ev["type"] == "interrupt":
                    self.s.stop_requested = True
                    return False
                if ev["type"] == "key" and ev["key"].lower() in ("y", "n", "escape", "enter"):
                    return ev["key"].lower() == "y"
        finally:
            self.s.show_modal(None)
        return False

    def password(self, prompt: str) -> Optional[bytes]:
        buf = bytearray()
        modal = Modal(prompt, ["Type your password, then Enter. Esc cancels."], secret_len=0)
        self.s.show_modal(modal)
        try:
            for ev in self._read_keys():
                if ev["type"] == "interrupt":
                    self.s.stop_requested = True
                    return None
                if ev["type"] != "key":
                    continue
                k = ev["key"]
                if k == "enter":
                    return bytes(buf)
                if k == "escape":
                    return None
                if k == "backspace":
                    if buf:
                        buf.pop()
                elif len(k) == 1:
                    buf += k.encode()
                modal.secret_len = len(buf)
                self.s.show_modal(modal)
        finally:
            for i in range(len(buf)):
                buf[i] = 0
            self.s.show_modal(None)
        return None

    def info(self, message: str) -> None:
        self.s.show_modal(Modal(message))
        self.s.render()
        time.sleep(1.0)
        self.s.show_modal(None)


class Session:
    def __init__(self, *, name: str, mode: str, channel: Channel,
                 proc: Optional[subprocess.Popen], surface, devices, authority: Authority,
                 boot_devices: tuple[str, ...] = BOOT_ORDER, log=None, prompter=None):
        self.name, self.mode = name, mode
        self.channel = channel
        self.proc = proc
        self.surface = surface
        self.devices = devices
        self.authority = authority
        self.boot_queue = list(boot_devices)
        self.booted: set[str] = set()
        self.log = log
        self.stop_requested = False
        self.surface_dirty = True
        self.exit_code: Optional[int] = None
        self.notice = ""
        self._notice_until = 0.0
        self.pending: deque = deque()
        self.prompter = prompter or SessionPrompter(self)
        # Every password asked during the session goes through the trusted overlay.
        self.authority.prompter = self.prompter

    # --- helpers -----------------------------------------------------------
    def show_modal(self, modal: Optional[Modal]) -> None:
        self.surface.set_modal(modal)
        self.surface_dirty = True

    def render(self) -> None:
        devs = " ".join(f"{d}:{'ON' if d in self.booted else 'off'}" for d in BOOT_ORDER)
        notice = self.notice if time.monotonic() < self._notice_until else ""
        self.surface.set_status(f" {self.name} [{self.mode}] {devs} | Ctrl-C quits"
                                + (f" | {notice}" if notice else ""))
        self.surface.render()
        self.surface_dirty = False

    def flash(self, text: str) -> None:
        self.notice = text
        self._notice_until = time.monotonic() + 3
        self.surface_dirty = True

    def _app_alive(self) -> bool:
        if self.channel.closed:
            return False
        return self.proc is None or self.proc.poll() is None

    # --- device booting ----------------------------------------------------
    def boot_next_device(self) -> None:
        dev = self.boot_queue.pop(0)
        if not self.prompter.confirm(f"Boot {dev} for '{self.name}'?"):
            self.flash(f"{dev} not booted")
            return
        try:
            with self.authority.authorize(f"device.{dev}", self.name):
                how = getattr(self.devices, f"boot_{dev}")()
        except AuthorizationDenied:
            self.flash(f"{dev}: not authorized")
            return
        except (AuthError, DeviceError) as e:
            self.flash(f"{dev}: {e}")
            return
        self.booted.add(dev)
        self.channel.send({"cmd": "device", "device": dev, "state": "attached"})
        self._log(f"booted {dev} ({how})")
        self.flash(f"{dev} booted")

    # --- event routing -----------------------------------------------------
    def route(self, ev: dict) -> None:
        t = ev["type"]
        if t == "interrupt":
            self.stop_requested = True
            return
        if t == "key":
            if "keyboard" not in self.booted:
                self.flash("keyboard not booted for this app")
                return
            self.channel.send({"cmd": "key", "key": ev["key"]})
            return
        if "mouse" not in self.booted:
            return
        x, y = ev.get("x", 0), ev.get("y", 0)
        if hasattr(self.surface, "to_app_coords"):
            x, y = self.surface.to_app_coords(x, y)
        if t == "pointer":
            self.surface.set_pointer(ev["x"], ev["y"])
            self.surface_dirty = True
            self.channel.send({"cmd": "pointer", "x": x, "y": y})
        elif t == "button":
            self.surface.set_pointer(ev["x"], ev["y"])
            self.surface_dirty = True
            self.channel.send({"cmd": "button", "button": ev["button"],
                               "pressed": ev["pressed"], "x": x, "y": y})
        elif t == "scroll":
            self.channel.send({"cmd": "scroll", "dy": ev["dy"], "x": x, "y": y})

    def handle_app(self) -> None:
        for raw in self.channel.receive():
            msg = validate_app_message(raw, self.mode)
            if msg["cmd"] in ("screen", "frame"):
                self.surface.present(msg)
                self.surface_dirty = True
            elif msg["cmd"] == "log":
                self._log("app: " + msg["msg"])
            elif msg["cmd"] == "exit":
                self.exit_code = msg["code"]
                self.stop_requested = True

    def _log(self, text: str) -> None:
        if self.log:
            self.log.write(text + "\n")
            self.log.flush()

    def pull_input(self, timeout: float, include_app: bool) -> None:
        fds = list(self.devices.fds())
        if include_app and not self.channel.closed:
            fds.append(self.channel.fileno())
        r, _, _ = select.select(fds, [], [], timeout)
        for fd in r:
            if include_app and fd == self.channel.fileno():
                self.handle_app()
            else:
                self.pending.extend(self.devices.read(fd))

    # --- main loop ---------------------------------------------------------
    def run(self, first_frame_timeout: float = 1.5) -> int:
        w, h = self.surface.hello_size()
        self.channel.send({"cmd": "hello", "mode": self.mode, "width": w, "height": h})
        started = time.monotonic()
        try:
            while not self.stop_requested and self._app_alive():
                if self.surface_dirty:
                    self.render()
                ready_for_boot = self.surface.has_content or \
                    time.monotonic() - started > first_frame_timeout
                if self.boot_queue and ready_for_boot:
                    self.boot_next_device()
                    continue
                self.pull_input(0.25, include_app=True)
                if any(e["type"] == "interrupt" for e in self.pending):
                    self.stop_requested = True
                # While boot prompts are still due, keep input for the trusted prompt.
                while self.pending and not self.boot_queue and not self.stop_requested:
                    self.route(self.pending.popleft())
            # drain anything the app sent right before exiting
            if not self.channel.closed:
                try:
                    self.handle_app()
                except ProtocolError:
                    pass
        except ProtocolError as e:
            self._log(f"protocol violation, killing app: {e}")
            self.exit_code = 125
        finally:
            self.shutdown()
        if self.exit_code is None and self.proc is not None:
            self.exit_code = self.proc.returncode or 0
        return self.exit_code or 0

    def shutdown(self) -> None:
        self.channel.send({"cmd": "quit"})
        if self.proc is not None:
            try:
                self.proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.proc.wait()
        self.channel.close()
