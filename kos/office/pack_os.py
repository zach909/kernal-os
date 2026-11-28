"""pack_os: OS-management titles.

A sandboxed app cannot read or change system state by itself. Five of these are built anyway, because the
OS now answers an app's *questions* (kos/servicespec.py): the app formats what it is told and the OS asks the
owner's password, in its own prompt, for every one. The rest cannot be built and say why."""

from __future__ import annotations

from .packkit import app, none
from .pack_system import make_activity, make_disk, make_firewall, make_packages, make_system

ENTRIES: list = [
    none("Device Settings",
         "Not an app: sandboxed apps cannot read or change device or system settings, and the OS has no settings "
         "layer yet. Nothing covers it today; `kos passwd` changes only your password."),
    none("Battery and Power",
         "Not an app: a sandboxed app cannot read the battery or change power state, and the OS has no power "
         "management yet. No `kos` command covers it; nothing in KOS reads battery or sets sleep."),
    app("Storage and Disk Management", make_disk, "partial",
        "Shows what earlier writes still owe and does it: the security scan, then the disk optimize (recompress apps, "
        "prune dead state, trim the audit log). Replaces `kos owed`, `settle`, `optimize`. It cannot see or partition disks; "
        "`kos usb list` still lists USB disks.", name="disk-care", services=["maintenance"]),
    none("Network and Wireless",
         "Not an app: apps run in an empty network namespace and cannot configure networks. KOS has no "
         "network or Wi-Fi manager; connection rules are the Firewall Management app. Nothing manages networks or Wi-Fi."),
    none("Printer Management",
         "Not an app: apps cannot reach printers or drivers, and KOS has no printing support. No `kos` "
         "command or other app covers it; nothing in KOS talks to a printer."),
    app("Process and Resource Monitor", make_activity, "partial",
        "One feed of the apps KOS has open and the recent password decisions. Replaces `kos activity`. It sees only what "
        "KOS started, not other processes, and shows no CPU or memory figures.", name="activity", services=["activity"]),
    app("System Information and Diagnostics", make_system, "partial",
        "Which kernel protections this machine has, whether this is the KOS kernel, firmware control and the firmware "
        "plan. Replaces `kos doctor` and `kos firmware`. It reports only what KOS checks; it is not a hardware inventory.",
        name="system-info", services=["system"]),
    app("Software Updates", make_packages, "partial",
        "Installed apps with their run permits: install, update, remove, permit and revoke. Each scans first, then asks "
        "your password. Replaces `kos install`, `update`, `remove`, `permit`, `list`. Apps only: there is no OS update, and "
        "`kos update all` is not here.", name="software-updates", services=["packages"]),
    app("Firewall Management", make_firewall, "partial",
        "Rules that let one app make one kind of connection to one typed-out address and port; everything else is blocked "
        "by the KOS kernel. The OS's own connections and connections from outside the sandbox are not covered yet, and a "
        "change reaches an app the next time it is opened.", name="firewall", services=["firewall"]),
    none("Credential Manager",
         "Not built: nothing in KOS is encrypted yet, and storing secrets safely needs a vetted crypto "
         "library, which is an open owner decision (README). No `kos` command covers it."),
    none("Device Pairing",
         "Not an app: apps cannot reach Bluetooth or other devices, and KOS has no pairing support. "
         "Nothing covers it; `kos usb` only writes boot images to USB sticks."),
    none("Window and Desktop Management",
         "Not an app: there is no window manager. `kos boot desktop` runs the taskbar and App Library, "
         "which are themselves apps that ask the OS to open, close or focus apps."),
]
