"""The desktop: not a program, a way of moving between apps.

KOS has no window manager. ``kos boot desktop`` opens two ordinary apps - the
**taskbar** (home) and the **App Library** - as background instances, then
attaches your terminal to one of them at a time:

* start on the taskbar;
* the taskbar (or the App Library) asks the OS to ``focus`` an app -> attach there;
* the right mouse button, anywhere, -> the App Library (the OS handles it; no
  app ever sees it);
* Ctrl-C detaches from an app and returns to the taskbar; Ctrl-C on the
  taskbar leaves the desktop. Nothing is closed by leaving.

The devices (mouse, keyboard) are booted once, with your password, in the
first session; they carry over as you move, so switching apps is free. Opening
a new app still costs a password, in the OS's own prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .kapp import KAppError
from .registry import RegistryError

SYSTEM_APPS = ("taskbar", "app-library")


class DesktopError(Exception):
    pass


@dataclass
class Desktop:
    home: str      # instance id of the taskbar
    library: str   # instance id of the App Library
    attach: Callable[[str, dict], dict]
    """attach(instance_id, ctx) runs one attached session and returns its
    outcome: {"switch": ("instance", id) | None, "booted": [...], "exit_code": n}"""

    def run(self) -> int:
        target, booted = self.home, ()
        while True:
            ctx = {"preboot": booted,
                   "right_click_to": None if target == self.library else self.library}
            try:
                out = self.attach(target, ctx)
            except (KAppError, RegistryError, OSError) as e:
                if target == self.home:
                    raise DesktopError(f"the taskbar is gone: {e}") from None
                target = self.home        # the app we were heading to has vanished
                continue
            booted = tuple(out.get("booted") or booted)
            switch = out.get("switch")
            if switch and switch[0] == "instance":
                target = switch[1]
                continue
            if target == self.home:
                return int(out.get("exit_code", 0))
            target = self.home
