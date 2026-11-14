"""An app session: one running app, one surface, the owner's devices.

Flow for ``run graphical <app>`` (``run <app>`` is the same with a TUI page):

  1. (already done by the caller) password -> seal verified -> app launched
     in its sandbox, from its zip, in RAM.
  2. The OS sends ``hello`` and shows the app's first frame.
  3. The OS asks, in a trusted overlay:  "Boot mouse for <app>?"  -> password
  4. The OS asks:                        "Boot keyboard for <app>?" -> password
  5. Loop: device events become commands to the app; the app's commands
     become pixels / text on screen. Ctrl-C always ends the session.

Desktop sessions add three things, all driven by the OS and never by the app:
``preboot`` (devices already booted by the desktop's own password carry over
from one app to the next), ``right_click_to`` (the right mouse button is the
OS's: it switches to the App Library and is never forwarded), and ``bridge``
(an app with the ``system`` permission may *ask* the OS to open, close or
switch apps - see ``system.py``). ``outcome`` reports where to go next.

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
from .guard import Guard
from .kapp import wire_mode
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
                    if self.s.detach_on_interrupt:
                        self.s.detached = True
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
                    if self.s.detach_on_interrupt:
                        self.s.detached = True
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
                 boot_devices: tuple[str, ...] = BOOT_ORDER, log=None, prompter=None,
                 detach_on_interrupt: bool = False, bridge=None,
                 preboot: tuple[str, ...] = (), right_click_to: Optional[str] = None,
                 outcome: Optional[dict] = None, vault=None, extensions: Optional[dict] = None,
                 guard: Optional[Guard] = None, allow_network: Optional[bool] = None,
                 app_pid: Optional[int] = None, status_ok: bool = False, services=None):
        self.name, self.mode = name, mode
        # A layer with no pointer (the text layer) is never offered the mouse.
        self.has_pointer = getattr(surface, "has_pointer", True)
        self.device_names = tuple(d for d in BOOT_ORDER if self.has_pointer or d != "mouse")
        boot_devices = tuple(d for d in boot_devices if d in self.device_names)
        preboot = tuple(d for d in preboot if d in self.device_names)
        self.extensions = extensions       # {"items": [...], "skipped": [...]} - see extensions.py
        self.channel = channel
        self.proc = proc
        self.surface = surface
        self.devices = devices
        self.authority = authority
        self.preboot = tuple(d for d in preboot if d in BOOT_ORDER)
        self.boot_queue = [d for d in boot_devices if d not in self.preboot]
        self.booted: set[str] = set()
        self.bridge = bridge
        self.vault = vault
        self.status_ok = status_ok       # from the verified manifest ('ask:status' or 'system'), never the app
        self.services = services           # a services.ServiceHost, or None: no 'service:' permission
        self.right_click_to = right_click_to
        self.outcome = outcome
        self.switch: Optional[tuple[str, str]] = None
        self.log = log
        self.stop_requested = False
        self.surface_dirty = True
        self.exit_code: Optional[int] = None
        self.notice = ""
        self._notice_until = 0.0
        self.detach_on_interrupt = detach_on_interrupt
        self.detached = False
        self.pending: deque = deque()
        self.prompter = prompter or SessionPrompter(self)
        # Every password asked during the session goes through the trusted overlay.
        self.authority.prompter = self.prompter
        # The security system of each layer (guard.py): graphics, text, input, commands, kernel, hardware.
        pid = app_pid if app_pid is not None else (proc.pid if proc is not None else None)
        self.guard = guard or Guard(name, audit=getattr(authority, "audit", None), pid=pid,
                                    allow_network=allow_network)

    # --- helpers -----------------------------------------------------------
    def show_modal(self, modal: Optional[Modal]) -> None:
        self.surface.set_modal(modal)
        self.surface_dirty = True

    def render(self) -> None:
        devs = " ".join(f"{d}:{'ON' if d in self.booted else 'off'}" for d in self.device_names)
        notice = self.notice if time.monotonic() < self._notice_until else ""
        self.surface.set_status(f" {self.name} [{self.mode}] {devs} | Ctrl-C quits"
                                + (f" | {notice}" if notice else ""))
        self.surface.render()
        # a surface that held a change back (the text layer prints a page at most every 250 ms)
        # says so, and is asked again on the next turn of the loop
        self.surface_dirty = bool(getattr(self.surface, "deferred", False))

    def flash(self, text: str) -> None:
        self.notice = text
        self._notice_until = time.monotonic() + 3
        self.surface_dirty = True

    def _send(self, cmd: dict) -> None:
        emit = getattr(self.surface, "emit", None)
        if emit:
            emit(">", cmd)
        self.channel.send(cmd)

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
        self._send({"cmd": "device", "device": dev, "state": "attached"})
        self._log(f"booted {dev} ({how})")
        self.flash(f"{dev} booted")

    # --- event routing -----------------------------------------------------
    def route(self, ev: dict) -> None:
        # input guard: only a well-formed event of a kind the OS sends goes any further
        ev = self.guard.input_event(ev, *self._bounds(), pointer=self.has_pointer)
        if ev is None:
            return
        t = ev["type"]
        if t == "interrupt":
            if self.detach_on_interrupt:
                self.detached = True
            self.stop_requested = True
            return
        if t == "key":
            if "keyboard" not in self.booted:
                self.flash("keyboard not booted for this app")
                return
            self._send({"cmd": "key", "key": ev["key"]})
            return
        if "mouse" not in self.booted:
            return
        if t == "button" and ev["button"] == "right" and self.right_click_to:
            if ev["pressed"]:
                self._switch(("instance", self.right_click_to))
            return  # the right button is the OS's here; the app never sees it
        x, y = ev.get("x", 0), ev.get("y", 0)
        if hasattr(self.surface, "to_app_coords"):
            x, y = self.surface.to_app_coords(x, y)
        if t == "pointer":
            self.surface.set_pointer(ev["x"], ev["y"])
            self.surface_dirty = True
            self._send({"cmd": "pointer", "x": x, "y": y})
        elif t == "button":
            self.surface.set_pointer(ev["x"], ev["y"])
            self.surface_dirty = True
            self._send({"cmd": "button", "button": ev["button"],
                        "pressed": ev["pressed"], "x": x, "y": y})
        elif t == "scroll":
            self._send({"cmd": "scroll", "dy": ev["dy"], "x": x, "y": y})

    def _bounds(self) -> tuple[int, int]:
        """The size of the screen an event's coordinates must fall in."""
        s = self.surface
        return (getattr(s, "width", getattr(s, "cols", 1 << 14)),
                getattr(s, "height", getattr(s, "rows", 1 << 14)))

    def handle_app(self) -> None:
        for raw in self.channel.receive():
            self.guard.message()                       # commands layer: how many, before anything else
            msg = validate_app_message(raw, self.mode)
            if msg["cmd"] == "frame":
                self.guard.frame(len(msg["ops"]))      # graphics layer
            elif msg["cmd"] == "screen":
                self.guard.page(len(msg["lines"]))     # text layer
            emit = getattr(self.surface, "emit", None)
            if emit:
                emit("<", msg)
            if msg["cmd"] in ("screen", "frame"):
                self.surface.present(msg)
                self.surface_dirty = True
            elif msg["cmd"] == "log":
                self._log("app: " + msg["msg"])
            elif msg["cmd"] == "request":
                self._on_request(msg)
            elif msg["cmd"] == "vault":
                self._on_vault(msg)
            elif msg["cmd"] == "service":
                self._on_service(msg)
            elif msg["cmd"] == "exit":
                self.exit_code = msg["code"]
                self.stop_requested = True

    def _switch(self, target: tuple[str, str]) -> None:
        """Leave this app for another one. An attached app keeps running
        (we only detach); a foreground app we own is told to quit."""
        self.switch = target
        if self.detach_on_interrupt:
            self.detached = True
        self.stop_requested = True

    def _on_vault(self, msg: dict) -> None:
        """Durable storage for the app, done by the OS. Never prompts: the grant
        is the manifest plus the universal permission store (see spaces.py)."""
        from .spaces import StorageError
        from .vault import VaultError
        reply = {"cmd": "vault", "op": msg["op"], "id": msg["id"], "ok": False, "detail": ""}
        if self.vault is None:
            reply["detail"] = "this app does not have the 'storage' permission"
            self._send(reply)
            return
        try:
            if msg["op"] == "spaces":
                reply["spaces"] = self.vault.visible_spaces()
            else:
                store = msg.get("store")
                v = self.vault.vault(msg.get("space"), msg["op"], store)
                if store:       # cookies and passwords are sensitive: every use is logged (never the value)
                    self._log(f"{store}: {msg['op']} {msg.get('key', '')}".rstrip())
                if msg["op"] == "put":
                    v.put(msg["key"], msg["value"])
                elif msg["op"] == "get":
                    value = v.get(msg["key"])
                    if value is None:
                        reply["detail"] = "no such key"
                        self._send(reply)
                        return
                    reply["value"] = value
                elif msg["op"] == "list":
                    reply["keys"] = v.keys()
                else:
                    v.delete(msg["key"])
            reply["ok"] = True
        except (StorageError, VaultError, OSError) as e:
            reply["detail"] = str(e)[:200]
            if msg.get("store"):
                self._log(f"{msg['store']}: {msg['op']} refused: {reply['detail']}")
        self._send(reply)

    def status_fields(self, topic: str) -> list:
        """What the OS tells an app about one part of this session. Read-only, made here, never
        taken from the app. Values are short plain text."""
        backend = str(getattr(self.devices, "kind", "unknown"))
        if topic == "mouse":
            return [["state", "booted" if "mouse" in self.booted else "not booted"],
                    ["backend", backend],
                    ["right button", "App Library (the OS keeps it)" if self.right_click_to else "sent to the app"]]
        if topic == "keyboard":
            return [["state", "booted" if "keyboard" in self.booted else "not booted"],
                    ["backend", backend],
                    ["Ctrl-C", "always the OS's"]]
        w, h = self.surface.hello_size()
        return [["mode", self.mode], ["width", str(w)], ["height", str(h)],
                ["surface", type(self.surface).__name__.lower()]]

    def _on_status(self, msg: dict) -> None:
        if not self.status_ok:
            self._send({"cmd": "result", "action": "status", "ok": False,
                        "detail": "this app does not have the 'ask:status' or 'system' permission"})
            return
        self._send({"cmd": "status", "topic": msg["topic"], "ok": True,
                    "fields": self.status_fields(msg["topic"])})
    def _on_service(self, msg: dict) -> None:
        """An app asks the OS for one of its functions (services.py). The password, where the service
        needs one, is typed in the OS's own prompt; this app can neither see nor answer it."""
        if self.services is None:
            self._send({"cmd": "service", "id": msg["id"], "ok": False, "data": {},
                        "detail": "this app has no 'service:' permission in its manifest"})
            return
        self._send(self.services.call(msg, self.authority))
        self.surface_dirty = True

    def _on_request(self, msg: dict) -> None:
        if msg["action"] == "status":
            self._on_status(msg)
            return
        if self.bridge is None:
            self._send({"cmd": "result", "action": msg["action"], "ok": False,
                        "detail": "this app does not have the 'system' permission"})
            return
        why = self.guard.request(msg["action"])        # commands layer: not too often, not after too many failures
        if why:
            self._send({"cmd": "result", "action": msg["action"], "ok": False, "detail": why})
            return

        def reply(out: dict) -> None:
            if out.get("cmd") in ("result", "answer") and not out.get("ok", True) and msg["action"] != "apps":
                self.guard.request_failed()
            self._send(out)

        target = self.bridge.handle(msg, reply, self.authority)
        self.surface_dirty = True
        if target:
            self._switch(target)

    def _preboot_devices(self) -> None:
        """Devices the desktop already booted with the password stay booted
        as the desktop moves between apps: re-enable them, no new prompt."""
        for dev in self.preboot:
            try:
                how = getattr(self.devices, f"boot_{dev}")()
            except DeviceError as e:
                self.flash(f"{dev}: {e}")
                continue
            self.booted.add(dev)
            self._send({"cmd": "device", "device": dev, "state": "attached"})
            self._log(f"{dev} carried over from the desktop ({how})")

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
        self._send({"cmd": "hello", "mode": wire_mode(self.mode), "width": w, "height": h})
        if self.extensions and (self.extensions.get("items") or self.extensions.get("skipped")):
            # Data the owner switched on for this app. Only ever sent to the host it names;
            # an app with nothing switched on is told nothing.
            self._send({"cmd": "extensions", "items": self.extensions.get("items", []),
                        "skipped": self.extensions.get("skipped", [])})
        self._preboot_devices()
        started = time.monotonic()
        try:
            self.guard.attest(force=True)        # kernel + hardware: is the app really confined, holding no device?
            while not self.stop_requested and self._app_alive():
                self.guard.attest()              # ... and again every couple of seconds
                if self.surface_dirty:
                    self.render()
                ready_for_boot = self.surface.has_content or \
                    time.monotonic() - started > first_frame_timeout
                if self.boot_queue and ready_for_boot:
                    self.boot_next_device()
                    continue
                self.pull_input(0.25, include_app=True)
                # An interrupt that arrives before boot prompts have even started
                # must still stop us; once boot_queue is empty the drain below finds
                # it in order via route(), so this only needs to fire here.
                if self.boot_queue and any(e["type"] == "interrupt" for e in self.pending):
                    if self.detach_on_interrupt:
                        self.detached = True
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
            if self.outcome is not None:
                self.outcome.update(booted=sorted(self.booted), switch=self.switch,
                                    detached=self.detached, exit_code=self.exit_code or 0)
        if self.exit_code is None and self.proc is not None:
            self.exit_code = self.proc.returncode or 0
        return self.exit_code or 0

    def shutdown(self) -> None:
        if not self.detached:
            self._send({"cmd": "quit"})
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
