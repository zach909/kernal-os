"""Where does each OS command live now?

Three groups, and every command in ``kos help`` is in exactly one (tests/test_system_apps.py checks):

``APP_FOR_COMMAND``  the command is an app now. The command line only launches it
                     (kos/office/pack_system.py, and five titles in pack_os.py).
``BOOTSTRAP``        the command stays in the command line because a new machine needs it before
                     any app exists: you cannot install the package manager with the package
                     manager. An app with the same job is the front end once it is installed.
``STILL_THE_OS``     the OS's own, with the reason. These are the enforcement and the machinery
                     that starts, connects and seals apps.

Pure data: loaded by the command line and by sandboxed apps alike."""

APP_FOR_COMMAND = {
    "audit": "audit-log",
    "activity": "activity",
    "security": "security-check",
    "doctor": "system-info",
    "firmware": "system-info",
    "ls": "files",
    "cat": "files",
    "explore": "files",
    "view": "files",
    "scan": "scanner",              # `scan file`; `scan watch` keeps running in the OS (it is a watcher)
    "optimize": "disk-care",
    "settle": "disk-care",
    "owed": "disk-care",
    "cell": "cells",
    "convert": "deb-converter",
    "skills": "skill-maker",        # the preview; `skills --out DIR` writes files and stays in the OS
    "grant": "permissions",
    "spaces": "permissions",
}

BOOTSTRAP = {
    "install": "software-updates",
    "update": "software-updates",
    "remove": "software-updates",
    "permit": "software-updates",
    "list": "software-updates",
    "help": "kos-help",
    "line": "terminal",
}

STILL_THE_OS = {
    "setup": "chooses the password before any app can run",
    "passwd": "re-seals every app under a new key",
    "pack": "builds an app file; needs no OS state",
    "run": "starts an app: it is the OS",
    "open": "starts an app: it is the OS",
    "go": "starts an app: it is the OS",
    "ps": "lists what the OS has started",
    "attach": "connects the terminal and devices to a running app",
    "close": "stops what the OS started",
    "boot": "starts the desktop",
    "desktop": "installs the desktop and the OS's own apps",
    "extend": "records a pinned grant in the permission store",
    "dirs": "shows where the OS keeps an app's folders",
    "admin": "the exclusive administrator keyboard",
    "write": "the guarded write needs the exclusive administrator keyboard",
    "usb": "writes a boot image to a disk",
    "aios": "the AI OS engine layers",
    "do": "interprets one line and runs it",
    "exec": "runs code as a sandboxed one-shot app",
    "backup": "a restore is a guarded write (administrator keyboard); the backup app covers list, add and remove",
}


def app_for(command: str) -> str:
    """The app that holds (or fronts) this command, or '' if it is the OS's own."""
    return APP_FOR_COMMAND.get(command) or BOOTSTRAP.get(command, "")
