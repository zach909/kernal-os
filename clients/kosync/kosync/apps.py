"""The list of apps on this machine, for a person to reinstall on the new OS.

Nothing here installs anything. It asks the package managers what is installed (a fixed argument list, no
shell, a time limit, a size limit), keeps only names that look like package names, and for a few well known
programs it knows the name each package manager uses so the importer can print the install command.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,127}$")
MAX_APPS = 5000
MAX_OUT = 4_000_000

# package-manager names of programs that exist on every OS; the importer shows this as a hint, not a promise
EQUIVALENTS = {
    "firefox": {"apt": "firefox", "brew": "--cask firefox", "winget": "Mozilla.Firefox", "flatpak": "org.mozilla.firefox"},
    "vlc": {"apt": "vlc", "brew": "--cask vlc", "winget": "VideoLAN.VLC", "flatpak": "org.videolan.VLC"},
    "git": {"apt": "git", "brew": "git", "winget": "Git.Git"},
    "python": {"apt": "python3", "brew": "python", "winget": "Python.Python.3.12"},
    "vscode": {"apt": "code", "brew": "--cask visual-studio-code", "winget": "Microsoft.VisualStudioCode",
               "flatpak": "com.visualstudio.code"},
    "libreoffice": {"apt": "libreoffice", "brew": "--cask libreoffice", "winget": "TheDocumentFoundation.LibreOffice",
                    "flatpak": "org.libreoffice.LibreOffice"},
    "gimp": {"apt": "gimp", "brew": "--cask gimp", "winget": "GIMP.GIMP", "flatpak": "org.gimp.GIMP"},
    "inkscape": {"apt": "inkscape", "brew": "--cask inkscape", "winget": "Inkscape.Inkscape", "flatpak": "org.inkscape.Inkscape"},
    "blender": {"apt": "blender", "brew": "--cask blender", "winget": "BlenderFoundation.Blender", "flatpak": "org.blender.Blender"},
    "obs-studio": {"apt": "obs-studio", "brew": "--cask obs", "winget": "OBSProject.OBSStudio", "flatpak": "com.obsproject.Studio"},
    "keepassxc": {"apt": "keepassxc", "brew": "--cask keepassxc", "winget": "KeePassXCTeam.KeePassXC", "flatpak": "org.keepassxc.KeePassXC"},
    "thunderbird": {"apt": "thunderbird", "brew": "--cask thunderbird", "winget": "Mozilla.Thunderbird", "flatpak": "org.mozilla.Thunderbird"},
    "7zip": {"apt": "p7zip-full", "brew": "sevenzip", "winget": "7zip.7zip"},
    "wireshark": {"apt": "wireshark", "brew": "--cask wireshark", "winget": "WiresharkFoundation.Wireshark"},
}
_MANAGER_FOR_OS = {"linux": ("apt", "flatpak"), "macos": ("brew",), "windows": ("winget",)}
_ALIASES = {}
for _k, _v in EQUIVALENTS.items():
    _ALIASES[_k] = _k
    for _name in _v.values():
        _ALIASES[_name.replace("--cask ", "").lower()] = _k


def _run(argv, timeout=60) -> str:
    out = subprocess.run(argv, capture_output=True, timeout=timeout, check=False, shell=False)
    return out.stdout[:MAX_OUT].decode("utf-8", "replace")


def collect(osname: str, run=_run) -> list[dict]:
    """What is installed, as ``[{"manager": ..., "name": ...}]``. A missing package manager gives nothing."""
    found: list[dict] = []

    def add(manager: str, names):
        for n in names:
            n = n.strip()
            if NAME_RE.match(n) and len(found) < MAX_APPS:
                found.append({"manager": manager, "name": n})

    def attempt(manager, argv, parse=lambda s: s.splitlines()):
        try:
            add(manager, parse(run(argv)))
        except (OSError, subprocess.SubprocessError):
            pass

    if osname == "linux":
        attempt("apt", ["apt-mark", "showmanual"])
        attempt("flatpak", ["flatpak", "list", "--app", "--columns=application"])
    elif osname == "macos":
        attempt("brew", ["brew", "leaves"])
        attempt("brew-cask", ["brew", "list", "--cask"])
    elif osname == "windows":
        try:
            with tempfile.TemporaryDirectory() as d:
                target = os.path.join(d, "winget.json")
                run(["winget", "export", "-o", target, "--accept-source-agreements"])
                with open(target, encoding="utf-8") as fh:
                    data = json.load(fh)
            add("winget", [p.get("PackageIdentifier", "") for s in data.get("Sources", [])
                           for p in s.get("Packages", []) if isinstance(p, dict)])
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    return found


def install_hints(apps: list[dict], target: str) -> tuple[list[str], list[str]]:
    """(install commands to print for ``target``, names with no known equivalent). Commands are text only."""
    managers = _MANAGER_FOR_OS.get(target, ())
    commands: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for a in apps:
        key = _ALIASES.get(str(a.get("name", "")).lower().replace("--cask ", ""))
        if key is None:
            unknown.append(f"{a.get('name')} ({a.get('manager')})")
            continue
        if key in seen:
            continue
        seen.add(key)
        for m in managers:
            name = EQUIVALENTS[key].get(m)
            if name:
                commands.append({"apt": f"sudo apt install {name}", "flatpak": f"flatpak install {name}",
                                 "brew": f"brew install {name}", "winget": f"winget install --id {name}"}[m])
                break
        else:
            unknown.append(f"{key} (no package name known for {target})")
    return commands, unknown
