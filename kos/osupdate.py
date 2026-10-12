"""What the operating system underneath has waiting: packages, the kernel, drivers and firmware.

KOS runs as an ordinary user, so it can *see* what your package manager would upgrade but cannot apply it - installing a
kernel or a driver is a root action, and KOS does not hold root. This module only reads: it asks the package manager what
is upgradable (from the lists it already has; refreshing them is ``apt update`` / ``dnf makecache``, also root), sorts the
answer into kernel, drivers/firmware, security and other, and gives you the exact command to run as root. That is the honest
limit of "update everything" from an unprivileged desktop.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable, Optional

_KERNEL = re.compile(r"^(linux-(image|headers|modules|generic|virtual|kvm|cloud)|linux$|linux-lts|kernel(-core|-modules)?$|kernel-)", re.I)
_DRIVER = re.compile(r"(firmware|nvidia|amdgpu|mesa|xserver-xorg-video|-dkms$|intel-microcode|amd64-microcode|^linux-firmware|"
                     r"broadcom|realtek|bluez|libdrm|vulkan)", re.I)


def manager() -> Optional[str]:
    for m in ("apt", "dnf", "pacman"):
        if shutil.which(m):
            return m
    return None


def classify(name: str, source: str = "") -> str:
    if _KERNEL.search(name):
        return "kernel"
    if _DRIVER.search(name):
        return "drivers"
    if "security" in source.lower():
        return "security"
    return "other"


def parse_apt(text: str) -> list[dict]:
    """``apt list --upgradable`` lines: ``name/suite ver arch [upgradable from: old]``."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^([a-z0-9][a-z0-9+.\-]*)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]", line)
        if m:
            name, suite, new, old = m.groups()
            out.append({"name": name, "from": old, "to": new, "kind": classify(name, suite)})
    return out


def parse_dnf(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and "." in parts[0] and re.match(r"^[0-9]", parts[1]):
            name = parts[0].rsplit(".", 1)[0]
            out.append({"name": name, "from": "", "to": parts[1], "kind": classify(name)})
    return out


def parse_pacman(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+->\s+(\S+)", line)
        if m:
            out.append({"name": m.group(1), "from": m.group(2), "to": m.group(3), "kind": classify(m.group(1))})
    return out


COMMANDS = {"apt": (["apt", "list", "--upgradable"], parse_apt, "apt-get update && apt-get upgrade"),
            "dnf": (["dnf", "--cacheonly", "check-update", "-q"], parse_dnf, "dnf upgrade"),
            "pacman": (["pacman", "-Qu"], parse_pacman, "pacman -Syu")}


def pending(run: Callable = subprocess.run, which: Optional[str] = None) -> dict:
    """What is upgradable, by kind, plus the root command that would apply it. Never raises."""
    m = which or manager()
    if m is None:
        return {"manager": None, "packages": [], "counts": {}, "apply": "", "note": "no apt, dnf or pacman found"}
    argv, parse, apply = COMMANDS[m]
    try:
        r = run(argv, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"})
        pkgs = parse(r.stdout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"manager": m, "packages": [], "counts": {}, "apply": f"sudo {apply}", "note": f"could not ask {m}: {e}"}
    counts: dict[str, int] = {}
    for p in pkgs:
        counts[p["kind"]] = counts.get(p["kind"], 0) + 1
    return {"manager": m, "packages": pkgs[:200], "counts": counts, "apply": f"sudo {apply}",
            "note": "KOS cannot apply these (it holds no root); run the command as root to update the kernel, drivers and the rest"}
