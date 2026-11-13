"""The broker: what actually keeps a ``kos open``ed app running in the
background, and the only thing that ever touches its command channel.

One broker per opened app. It owns the OS-side end of the app's socketpair
(the same channel a foreground ``run`` would use directly) and listens on a
Unix socket for a terminal to ``attach``. At most one attach connection is
served at a time - a second attach simply replaces the first, which is how
you move an app from one terminal to another. While nobody is attached the
app keeps running; the broker just has nowhere to forward its output, so
that output is dropped rather than blocking the app for long.

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
from typing import Callable, Optional

from . import cache, loader
from .kapp import KApp
from .registry import Instance, Registry
from .sandbox import SandboxPolicy

MAX_APP_READ = 1 << 16
FALLBACK_POLL = 1.0   # only used on kernels without pidfd_open (< 5.3)


def _pidfd(pid: int) -> Optional[int]:
    """A descriptor that becomes readable the moment ``pid`` exits, or None."""
    try:
        return os.pidfd_open(pid)
    except (AttributeError, OSError):
        return None


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
                 app_proc: subprocess.Popen, cache_dir: Optional[Path] = None,
                 on_exit: Optional[Callable[[], None]] = None):
        self.on_exit = on_exit
        self.inst = inst
        self.registry = registry
        self.app_channel = app_channel
        self.app_proc = app_proc
        self.cache_dir = cache_dir
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(inst.sock_path)
        except FileNotFoundError:
            pass
        self.listener.bind(inst.sock_path)
        os.chmod(inst.sock_path, 0o600)
        self.listener.listen(1)
        self.attached: Optional[socket.socket] = None
        self._stop = False
        # Everything the broker waits for is a file descriptor, so an idle broker
        # sleeps in select() with no timeout and wakes zero times per second:
        # the app exiting (pidfd) and SIGTERM (a pipe the signal handler writes to).
        self._pidfd = _pidfd(app_proc.pid)
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)

    def _handle_sigterm(self, signum, frame) -> None:
        self._stop = True

    def _drain_wake(self) -> None:
        try:
            while os.read(self._wake_r, 64):
                pass
        except (BlockingIOError, InterruptedError):
            pass

    def _wait_exit(self, seconds: float) -> None:
        """Give the app up to ``seconds`` to leave on its own; return as soon as it has."""
        if self._pidfd is not None:
            select.select([self._pidfd], [], [], seconds)
        else:
            time.sleep(seconds)

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

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # only `kos close` stops a broker
        # A handler alone only sets a flag - select() is restarted after it - so also
        # have the signal poke the pipe: select() returns at once, with no race
        # between "check the flag" and "go to sleep".
        signal.set_wakeup_fd(self._wake_w, warn_on_full_buffer=False)
        self.inst.app_pid = self.app_proc.pid
        self.inst.status = "running"
        self.registry.write(self.inst)
        app_alive = True
        timeout = None if self._pidfd is not None else FALLBACK_POLL
        try:
            while not self._stop:
                if self.app_proc.poll() is not None:
                    break
                fds = [self.listener, self.app_channel, self._wake_r]
                if self._pidfd is not None:
                    fds.append(self._pidfd)
                if self.attached:
                    fds.append(self.attached)
                try:
                    r, _, _ = select.select(fds, [], [], timeout)
                except InterruptedError:
                    continue
                if self._wake_r in r:
                    self._drain_wake()
                    continue            # the loop condition looks at _stop
                if self._pidfd is not None and self._pidfd in r:
                    break               # the app exited
                if self.listener in r:
                    self._accept()
                if self.app_channel in r:
                    if not self._pump_app():
                        app_alive = False
                        break
                if self.attached is not None and self.attached in r:
                    self._pump_attach()
        finally:
            self._shutdown(app_alive)

    def _shutdown(self, app_alive: bool) -> None:
        if app_alive and self._stop:
            try:
                self.app_channel.sendall(b'{"cmd":"quit"}\n')
            except OSError:
                pass
            self._wait_exit(0.3)
            # up to 0.3s for a clean exit, but stop waiting the moment it happens
            end = time.monotonic() + 0.3
            while self.app_proc.poll() is None and time.monotonic() < end:
                time.sleep(0.01)
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
        for s in (self.attached, self.app_channel, self.listener):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        try:
            signal.set_wakeup_fd(-1)
        except (ValueError, OSError):
            pass
        for fd in (self._pidfd, self._wake_r, self._wake_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        try:
            os.unlink(self.inst.sock_path)
        except FileNotFoundError:
            pass
        if self.cache_dir is not None:
            cache.wipe(self.cache_dir)
        if self.on_exit is not None:
            try:
                self.on_exit()
            except Exception as e:      # never let bookkeeping stop the instance from being removed
                print(f"kos-broker: on_exit: {e!r}", file=sys.stderr)
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
        proc = loader.launch(loader.plan(app, b.fileno(), mode, cache_dir, inst.address),
                             policy, log_path)
        b.close()
        Broker(inst, registry, a, proc, cache_dir, on_exit=policy.on_exit).run()
    except BaseException as e:  # pragma: no cover - last-resort broker crash path
        try:
            print(f"kos-broker: {e!r}", file=sys.stderr)
        finally:
            registry.remove(inst.id)
        os._exit(1)
    os._exit(0)
