"""pack_os: OS-management titles. Apps are sandboxed and cannot read or change system state, so none are built."""

from __future__ import annotations

from .packkit import none

ENTRIES: list = [
    none("Device Settings",
         "Not an app: sandboxed apps cannot read or change device or system settings, and the OS has no settings "
         "layer yet. Nothing covers it today; `kos passwd` changes only your password."),
    none("Battery and Power",
         "Not an app: a sandboxed app cannot read the battery or change power state, and the OS has no power "
         "management yet. No `kos` command covers it; nothing in KOS reads battery or sets sleep."),
    none("Storage and Disk Management",
         "Not an app: apps cannot see or change disks. Partly covered by OS commands: `kos ls` lists "
         "directories, `kos optimize` reclaims app disk space, `kos usb list` lists USB disks."),
    none("Network and Wireless",
         "Not an app: apps run in an empty network namespace and cannot configure networks. KOS has no "
         "network or Wi-Fi manager and no firewall yet (a README gap); nothing covers it."),
    none("Printer Management",
         "Not an app: apps cannot reach printers or drivers, and KOS has no printing support. No `kos` "
         "command or other app covers it; nothing in KOS talks to a printer."),
    none("Process and Resource Monitor",
         "Not an app: sandboxed apps cannot see processes. Partly covered by the OS: `kos ps` lists apps "
         "opened with `kos open`, and `kos activity` shows them with recent password decisions."),
    none("System Information and Diagnostics",
         "Not an app: apps cannot inspect the host. Covered in part by OS commands: `kos doctor` reports "
         "kernel security features, `kos security` checks KOS itself, `kos firmware` lists chips."),
    none("Software Updates",
         "Not an app: apps cannot replace themselves or the OS. `kos update` updates installed apps only "
         "(newer version, scanned first, downgrades refused). There is no OS update mechanism."),
    none("Firewall Management",
         "Not an app yet: there is no firewall. README lists this as an open Rule 3 gap: an app has all "
         "hosts or none, and OS traffic is not blocked or logged. A firewall app would need OS support."),
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
