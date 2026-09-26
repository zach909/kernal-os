"""The broker: what actually keeps a ``kos open``ed app running in the
background, and the only thing that ever touches its command channel.

One broker per opened app. It owns the OS-side end of the app's socketpair
(the same channel a foreground ``run`` would use directly) and listens on
two Unix sockets:

* the **attach** socket - one live, held-open connection at a time, for a
  real terminal (``kos attach``). A second attach simply replaces the
  first, which is how you move an app from one terminal to another.
* the **control** socket (``control_sock_path``) - a separate door for
  ``kos control``: each connection is read until it closes and forwarded
  straight to the app, then discarded. It never touches ``self.attached``,
  so sending a control command no longer bumps a real attached terminal off
  the way it would if both shared one slot.

While nobody is attached the app keeps running; the broker just has nowhere
to forward its output, so that output is dropped rather than blocking the
app for long.

``kos close`` stops a broker with SIGTERM: it asks the app to exit over the
protocol, gives it a moment, then kills its whole process group.
"""

from __future__ import annotations

import os
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import cache, loader
from .kapp import KApp
from .registry import Instance, Registry
from .sandbox import SandboxPolicy

MAX_APP_READ = 1 << 16


def control_sock_path(sock_path: str) -> str:
    return sock_path + ".control"


def daemonize(log_path: Path) -> None:
    """Detach the current (already-forked) process from the controlling
    terminal so a closed shell can't send it SIGHUP."""
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    if log_fd > 2:
        os.close(log_fd)


class Broker:
    def __init__(self, inst: Instance, registry: Registry, app_channel: socket.socket,
                 app_proc: subprocess.Popen, cache_dir: Optional[Path] = None):
        self.inst = inst
        self.registry = registry
        self.app_channel = app_channel
        self.app_proc = app_proc
        self.cache_dir = cache_dir
        self.listener = self._bind(inst.sock_path)
        self.control_listener = self._bind(control_sock_path(inst.sock_path))
        self.attached: Optional[socket.socket] = None
        self._control_pending: dict[socket.socket, bytearray] = {}
        self._stop = False

    @staticmethod
    def _bind(path: str) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        s.bind(path)
        os.chmod(path, 0o600)
        s.listen(4)
        return s

    def _handle_sigterm(self, signum, frame) -> None:
        self._stop = True

    def _pump_app(self) -> bool:
        """Read whatever the app sent. Returns False if the app is gone."""
        try:
            data = self.app_channel.recv(MAX_APP_READ)
        except OSError:
            data = b""
        if not data:
            return False
        if self.attached is not None:
            try:
                self.attached.sendall(data)
            except OSError:
                self.attached = None  # the attach dropped; app output is simply lost
        return True

    def _pump_attach(self) -> None:
        assert self.attached is not None
        try:
            data = self.attached.recv(65536)
        except OSError:
            data = b""
        if not data:
            self.attached.close()
            self.attached = None
            return
        try:
            self.app_channel.sendall(data)
        except OSError:
            pass

    def _accept(self) -> None:
        conn, _ = self.listener.accept()
        if self.attached is not None:
            try:
                self.attached.close()
            except OSError:
                pass
        self.attached = conn

    def _accept_control(self) -> None:
        conn, _ = self.control_listener.accept()
        self._control_pending[conn] = bytearray()

    def _pump_control(self, conn: socket.socket) -> None:
        """A control connection is read-until-close and forwarded whole -
        it never becomes `self.attached`, so it can never bump a real
        attach off its slot."""
        try:
            data = conn.recv(65536)
        except OSError:
            data = b""
        if not data:
            buf = self._control_pending.pop(conn, b"")
            if buf:
                try:
                    self.app_channel.sendall(bytes(buf))
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass
            return
        self._control_pending[conn] += data

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # only `kos close` stops a broker
        self.inst.app_pid = self.app_proc.pid
        self.inst.status = "running"
        self.registry.write(self.inst)
        app_alive = True
        try:
            while not self._stop:
                if self.app_proc.poll() is not None:
                    break
                fds = ([self.listener, self.control_listener, self.app_channel]
                      + ([self.attached] if self.attached else [])
                      + list(self._control_pending))
                try:
                    r, _, _ = select.select(fds, [], [], 1.0)
                except InterruptedError:
                    continue
                if self.listener in r:
                    self._accept()
                if self.control_listener in r:
                    self._accept_control()
                if self.app_channel in r:
                    if not self._pump_app():
                        app_alive = False
                        break
                if self.attached is not None and self.attached in r:
                    self._pump_attach()
                for conn in [c for c in self._control_pending if c in r]:
                    self._pump_control(conn)
        finally:
            self._shutdown(app_alive)

    def _shutdown(self, app_alive: bool) -> None:
        if app_alive and self._stop:
            try:
                self.app_channel.sendall(b'{"cmd":"quit"}\n')
            except OSError:
                pass
            time.sleep(0.3)
        if self.app_proc.poll() is None:
            try:
                os.killpg(self.app_proc.pid, signal.SIGTERM)
                self.app_proc.wait(timeout=1.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.app_proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        else:
            self.app_proc.wait()
        for s in [self.attached, self.app_channel, self.listener,
                 self.control_listener, *self._control_pending]:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        self._control_pending.clear()
        for path in (self.inst.sock_path, control_sock_path(self.inst.sock_path)):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        if self.cache_dir is not None:
            cache.wipe(self.cache_dir)
        self.registry.remove(self.inst.id)


def spawn(inst: Instance, app: KApp, mode: str, policy: SandboxPolicy,
          registry: Registry, log_path: Path, cache_dir: Optional[Path] = None) -> None:
    """Fork the broker for one instance. Called from the foreground CLI
    process right after the app has been verified with the password; the
    parent returns immediately (your shell comes back), the child becomes
    the detached broker."""
    a, b = socket.socketpair()
    pid = os.fork()
    if pid:  # parent: hand off and return to the caller
        a.close()
        b.close()
        inst.broker_pid = pid
        registry.write(inst)  # visible to `kos ps` immediately, status "starting"
        return
    # child: becomes the broker; keeps `a` as its OS-side app channel
    try:
        inst.broker_pid = os.getpid()
        daemonize(log_path)
        proc = loader.launch(loader.plan(app, b.fileno(), mode, cache_dir), policy, log_path)
        b.close()
        Broker(inst, registry, a, proc, cache_dir).run()
    except BaseException as e:  # pragma: no cover - last-resort broker crash path
        try:
            print(f"kos-broker: {e!r}", file=sys.stderr)
        finally:
            registry.remove(inst.id)
        os._exit(1)
    os._exit(0)
