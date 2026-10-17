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

SYSTEM_APPS = ("wallpaper", "pins", "search", "sidebar", "launcher", "widgets", "widget-clock", "widget-calendar",
               "widget-network", "widget-system", "menubar", "dock", "effects", "cursor", "taskbar", "appearance", "passwords", "mods", "autoupdate", "commands", "encryption", "services", "interface-normal", "interface-3d", "browser", "app-library", "files", "editor", "backup", "settings", "security",
               "terminal", "processes", "memory", "filesystem", "devices", "network", "isolation",
               "health", "resources", "updates")
DESKTOP_CORE = ("taskbar", "app-library")      # what `boot desktop` opens; the rest launch from the library


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


# ---------------------------------------------------------------------------- the shell
def boot_core(paths, authority, *, mode: str = "graphical", devices: tuple = ("mouse", "keyboard")) -> dict:
    """Make sure the desktop's own apps are running. Anything missing is started with
    ONE password that names every app (``authorize_batch``): the prompt reads
    "Password to start the desktop (desktop, taskbar, ...)". Returns {name: Instance}."""
    from .kapp import KAppError
    from .registry import Registry
    from .shell import CORE
    from .store import AppStore
    from .system import open_background

    from .heal import quick
    from .mods import core_names
    quick(paths)                                              # corrupt preference files aside, dead records dropped: no password needed
    installed = {a.name for a in AppStore(paths).installed()}
    wanted = core_names(paths, CORE, installed)               # the built-in core, each slot swapped for its enabled mod
    iface = interface_apps(paths).get(saved_look(paths))      # the interface app that draws the look the person last chose
    if iface and iface in installed and iface not in wanted:
        wanted = list(wanted) + [iface]
    running = {i.name: i for i in Registry(paths).list() if i.status == "running" and i.mode == mode}
    need = [n for n in wanted if n not in running]
    missing = [n for n in need if n not in installed]
    if missing:
        raise KAppError(f"{', '.join(missing)} not installed (run: kos desktop install)")
    action = "app.graphical" if mode == "graphical" else "app.open"
    items = [(action, n) for n in need] + [(f"device.{d}", "desktop") for d in devices]
    if items:
        label = f"start the desktop ({', '.join(need)})" if need else "boot the desktop"
        label += f" and boot the {' and '.join(devices)}" if devices else ""
        grants = authority.authorize_batch(items, label)
        for name, grant in zip(need, grants):
            running[name] = open_background(paths, authority, name, mode, grant=grant)
        for grant in grants[len(need):]:
            grant.close()
    return {n: running[n] for n in wanted if n in running}


def interface_apps(paths) -> dict:
    """{look: app name} for every installed interface app (driver kind ``interface``): the apps that draw the running apps."""
    from .kapp import KApp
    out = {}
    for f in sorted(paths.apps.glob("*.kapp")):
        try:
            m = KApp.from_file(f).manifest
        except Exception:
            continue
        if m.driver == "interface" and m.look:
            out.setdefault(m.look, m.name)
    return out


def saved_look(paths) -> str:
    import json
    try:
        return json.loads((paths.state / "shell.json").read_text()).get("look", "")
    except (OSError, ValueError, AttributeError):
        return ""


def slot_of(paths, name: str) -> str:
    """The interface slot an installed app fills: a mod's declared slot, else its own name."""
    from .kapp import KApp
    try:
        return KApp.from_file(paths.apps / f"{name}.kapp").manifest.slot or name
    except Exception:
        return name


def attach_core(paths, shell, core: dict) -> None:
    """Add each running interface app to the shell in the slot it fills."""
    for inst in core.values():
        shell.add_core(inst, slot=slot_of(paths, inst.name))


def make_shell(paths, authority, backend, devices, **kw):
    """A :class:`kos.shell.Shell` wired to this machine's apps."""
    from .shell import Shell
    from .store import AppStore
    from .system import close_instance, list_apps, open_background
    from .kapp import KApp

    def modes_of(name: str) -> list[str]:
        return next((a["modes"] for a in list_apps(paths) if a["name"] == name), [])

    def commands_of(name: str) -> dict:
        try:
            m = KApp.from_file(paths.apps / f"{name}.kapp").manifest
        except Exception:
            return {}
        return {c.id: c.line for c in m.commands}

    holder: dict = {}

    def opener(name: str, mode: str, new: bool = False, taken: frozenset = frozenset()):
        """An instance to show in a window. Unless a fresh one is wanted (``new``), an already-running instance that no
        window shows yet - say one you started with ``kos open`` in a terminal - is adopted, with no password."""
        from .registry import Registry
        if not new:
            for i in Registry(paths).list():
                if i.name == name and i.status == "running" and i.id not in taken and i.mode in ("graphical", "tui"):
                    return i
        return open_background(paths, holder["shell"].authority, name, mode)

    def closer(instance_id: str) -> None:
        close_instance(paths, holder["shell"].authority, instance_id)

    def restarter(name: str):
        """Start an interface app again (an instance that is still running is reused with no password; a dead one
        needs a new start, which asks - or is covered by a sudo window)."""
        from .registry import Registry
        taken = set(holder["shell"].layers)
        for i in Registry(paths).list():
            if i.name == name and i.status == "running" and i.id not in taken and i.mode == "graphical":
                return i
        return open_background(paths, holder["shell"].authority, name, "graphical")

    shell = Shell(paths, authority, backend, devices, opener=opener, closer=closer, restarter=restarter,
                  modes_of=modes_of, commands_of=commands_of,
                  interfaces_of=lambda: interface_apps(paths), **kw)
    holder["shell"] = shell
    return shell
