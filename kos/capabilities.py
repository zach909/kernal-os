"""What an app may ask the OS to do - in pieces, never as "everything".

The old ``system`` permission was one switch: an app that could list the apps could also signal processes, push a backup, read your
files, change the password policy. That is exactly what KOS is built to avoid - nothing gets power over everything, the system
included. So the permission is now a list of **scopes**, each opening a few related requests and nothing else:

    "system:apps"       list, open, focus and close apps; see the windows
    "system:os"         read-only facts about the machine (cpu, memory, disks, the network check)
    "system:files"      list, read, scan and (through the guarded write) save files, and watch them change
    "system:backup"     make and list backups, restore a file, set the off-site repository, push
    "system:processes"  signal and renice processes
    "system:security"   permit and revoke apps
    "system:passwords"  the sudo window and the password policy
    "system:run"        run one line of code or a command
    "system:updates"    check for and install updates, the auto-update policy, settle what is owed
    "system:maintenance"  optimise the disk
    "system:heal"       check and repair the state on disk
    "system:mods"       list, enable and disable interface mods
    "system:links"      the pinned links
    "system:notify"     post to and read the notifications
    "system:hardware"   run a job on a hardware driver

Whatever an app is allowed to ask, the action still needs its own password where it changes anything. A scope only decides
whether the question reaches the OS. The bare ``system`` permission still exists (every scope) for old apps; the built-in apps do not
use it, and ``kos services`` flags any app that does.
"""

from __future__ import annotations

ACTION_SCOPE: dict[str, str] = {
    "apps": "apps", "open": "apps", "focus": "apps", "close": "apps",
    "info": "os", "sys": "os", "netcheck": "os",
    "ls": "files", "view": "files", "scan": "files", "save": "files", "fschange": "files",
    "backups": "backup", "backup": "backup", "restore": "backup", "push": "backup", "remote": "backup",
    "signal": "processes", "renice": "processes",
    "permit": "security", "revoke": "security",
    "sudo": "passwords", "policy": "passwords",
    "line": "run",
    "updates": "updates", "autoupdate": "updates", "settle": "updates",
    "optimize": "maintenance",
    "heal": "heal",
    "mods": "mods",
    "links": "links", "openlink": "links",
    "notify": "notify",
    "quantum": "hardware",
}
SCOPES = frozenset(ACTION_SCOPE.values())
PREFIX = "system:"


def valid(permission: str) -> bool:
    """Is this a permission string a manifest may carry?"""
    if permission.startswith(PREFIX):
        return permission[len(PREFIX):] in SCOPES
    return True


def scopes_of(permissions) -> frozenset[str]:
    """The scopes a manifest's permissions grant: ``{"*"}`` for the bare ``system``, else the named ones."""
    out = set()
    for p in permissions:
        if p == "system":
            return frozenset({"*"})
        if p.startswith(PREFIX):
            out.add(p[len(PREFIX):])
    return frozenset(out)


def allows(scopes, action: str) -> bool:
    """May an app holding ``scopes`` make this request? Actions with no scope are not governed by this permission."""
    need = ACTION_SCOPE.get(action)
    return need is None or "*" in scopes or need in scopes


def needed(action: str) -> str:
    return PREFIX + ACTION_SCOPE[action] if action in ACTION_SCOPE else ""
