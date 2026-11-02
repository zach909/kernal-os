"""``kos security``: one read-only check of everything KOS can verify about
itself *without* your password.

It starts nothing, changes nothing and runs once, when you ask - there is no
security daemon, by the same rule as the rest of KOS. Each check answers a
question you could otherwise only answer by running half a dozen commands:

* kernel      do the protections apps depend on exist on this machine?
* password    is one set, and is the key-stretching strong?
* files       are KOS's folders and secrets private to you?
* audit log   is the hash chain intact (nothing edited, deleted or reordered)?
* apps        does every installed app still scan clean and match what was installed?
* permissions what can apps reach; are there grants nothing uses any more?
* owed        does an earlier write still owe a scan or an optimize?
* leftovers   did a crash leave temporary files behind?

What it cannot do without the password is check the seals themselves (an HMAC
under a password-derived key) and the audit log's password anchors; it says so
and points at ``kos audit --verify`` and ``kos run`` (which verify them).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .auth import AuditLog
from .kapp import KApp, KAppError
from .paths import Paths
from .permissions import Permissions
from .requires import Ledger
from .sandbox import report as kernel_report
from .scan import scan_bytes

PASS, WARN, FAIL = "pass", "warn", "fail"
MIN_KDF_N = 2 ** 15            # below this, guessing a password is cheap enough to worry about
STALE_TEMP_SECONDS = 600


@dataclass(frozen=True)
class Check:
    level: str
    name: str
    detail: str


def _names(items, limit: int = 8) -> str:
    items = sorted(items)
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


# --- the checks ----------------------------------------------------------------

def _kernel(paths: Paths) -> list[Check]:
    r = kernel_report()
    if not r["landlock_abi"]:
        return [Check(FAIL, "kernel", "Landlock is missing: KOS refuses to run apps unconfined")]
    if not r["user_namespaces"]:
        return [Check(FAIL, "kernel", "user namespaces are missing: apps cannot be isolated")]
    have = [f"Landlock ABI {r['landlock_abi']}", "user namespaces"]
    if r["seccomp_filter"]:
        return [Check(PASS, "kernel", ", ".join(have + ["seccomp filter"]))]
    return [Check(WARN, "kernel", ", ".join(have) + "; no seccomp filter for this CPU architecture")]


def _password(paths: Paths) -> list[Check]:
    if not paths.auth_file.exists():
        return [Check(FAIL, "password", "none set (run: kos setup)")]
    try:
        kdf = json.loads(paths.auth_file.read_text())["kdf"]
        n, r = int(kdf["n"]), int(kdf["r"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [Check(FAIL, "password", f"the password file cannot be read ({e!r})")]
    ram = 128 * r * n >> 20
    if n < MIN_KDF_N:
        return [Check(WARN, "password", f"key-stretching is weak (scrypt N={n}, ~{ram} MiB per guess)")]
    return [Check(PASS, "password", f"set; every guess costs scrypt N={n} (~{ram} MiB of memory)")]


def _files(paths: Paths) -> list[Check]:
    folders = [paths.etc, paths.state, paths.apps, paths.logs, paths.state / "appdata",
               paths.state / "spaces", paths.state / "permissions"]
    secrets = [paths.auth_file, paths.logs / "audit.log", paths.state / "permissions" / "grants.json",
               paths.state / "owed.json", paths.state / "auth-throttle.json"]
    loose = []
    for p in folders + secrets:
        try:
            mode = p.stat().st_mode & 0o777
        except FileNotFoundError:
            continue
        if mode & 0o077:
            loose.append(f"{p.relative_to(paths.root)} ({mode:03o})")
    if loose:
        return [Check(FAIL, "files", f"others can reach: {_names(loose)}")]
    return [Check(PASS, "files", "KOS's folders and secrets are private to you")]


def _audit(paths: Paths) -> list[Check]:
    log = AuditLog(paths)
    rep = log.verify()
    if not rep.ok:
        return [Check(FAIL, "audit log", f"TAMPERED at line {rep.bad_line}: {rep.problem}")]
    if not rep.entries:
        return [Check(PASS, "audit log", "nothing recorded yet")]
    note = f"{rep.entries} lines, chain intact; {rep.anchored} anchored to your password " \
           f"(check them: kos audit --verify)"
    if rep.legacy:
        note += f"; {rep.legacy} older lines predate tamper-evidence"
    return [Check(PASS, "audit log", note)]


def _installed(paths: Paths) -> dict[str, dict]:
    """name -> {"data": bytes|None, "meta": dict|None, "problem": str|None} for what is on disk."""
    out: dict[str, dict] = {}
    for seal in sorted(paths.apps.glob("*.seal")):
        name = seal.stem
        entry = {"data": None, "meta": None, "problem": None}
        try:
            entry["meta"] = json.loads(seal.read_text())
            entry["data"] = seal.with_suffix(".kapp").read_bytes()
        except FileNotFoundError:
            entry["problem"] = "its .kapp file is missing"
        except (OSError, ValueError):
            entry["problem"] = "its seal file is unreadable"
        out[name] = entry
    for kapp in paths.apps.glob("*.kapp"):
        out.setdefault(kapp.stem, {"data": None, "meta": None, "problem": "it has no seal (never installed properly)"})
    return out


def _apps(paths: Paths) -> list[Check]:
    apps = _installed(paths)
    if not apps:
        return [Check(PASS, "apps", "none installed")]
    changed, flagged, broken = [], [], []
    for name, a in apps.items():
        if a["problem"]:
            broken.append(f"{name} ({a['problem']})")
            continue
        if hashlib.sha256(a["data"]).hexdigest() != a["meta"].get("sha256"):
            changed.append(name)
            continue
        res = scan_bytes(a["data"], label=name)
        if not res.clean:
            flagged.append(f"{name} ({', '.join(sorted({f.rule for f in res.findings}))})")
    checks = []
    if changed:
        checks.append(Check(FAIL, "apps", f"modified since install: {_names(changed)}"))
    if flagged:
        checks.append(Check(FAIL, "apps", f"the scanner now flags: {_names(flagged)}"))
    if broken:
        checks.append(Check(FAIL, "apps", f"incomplete: {_names(broken)}"))
    if not checks:
        checks.append(Check(PASS, "apps", f"{len(apps)} installed: all rescanned clean and unchanged since "
                                          f"install (the seals need your password; 'run' checks them)"))
    return checks


def _manifest_permissions(paths: Paths, name: str) -> set[str]:
    try:
        return set(KApp.from_file(paths.apps / f"{name}.kapp").manifest.permissions)
    except (OSError, KAppError):
        return set()


def _permissions(paths: Paths) -> list[Check]:
    grants = Permissions(paths).list()
    installed = {p.stem for p in paths.apps.glob("*.kapp")}
    checks = []
    orphans = sorted({g["app"] for g in grants} - installed)
    if orphans:
        checks.append(Check(WARN, "permissions",
                            f"grants for apps that are not installed: {_names(orphans)} - a new app "
                            f"with the same name would inherit them (kos permit --revoke NAME)"))
    unpinned = sorted(g["app"] for g in grants
                      if g["resource"] == "run" and "declared" not in g and g["app"] in installed)
    if unpinned:
        checks.append(Check(WARN, "permissions",
                            f"approved before permissions were recorded, so an update could add network "
                            f"or system access unasked: {_names(unpinned)} (re-approve: kos permit NAME)"))
    permitted = sorted(g["app"] for g in grants if g["resource"] == "run" and g["app"] in installed)
    wide: dict[str, list[str]] = {"network": [], "system": []}
    for name in permitted:
        for perm in _manifest_permissions(paths, name) & set(wide):
            wide[perm].append(name)
    if not checks:
        summary = f"{len(permitted)} app(s) may run"
        if wide["network"]:
            summary += f"; can use the network: {_names(wide['network'])}"
        if wide["system"]:
            summary += f"; can open/close other apps: {_names(wide['system'])}"
        checks.append(Check(PASS, "permissions", summary))
    return checks


def _owed(paths: Paths) -> list[Check]:
    owed = Ledger(paths).owed()
    if owed:
        return [Check(WARN, "owed", f"{len(owed)} earlier write(s) still owe a scan or optimize (kos settle)")]
    return [Check(PASS, "owed", "nothing owed")]


def _leftovers(paths: Paths) -> list[Check]:
    cutoff = time.time() - STALE_TEMP_SECONDS
    stale = []
    for d in (paths.etc, paths.state, paths.apps, paths.logs, paths.state / "permissions"):
        for f in d.glob(".*.tmp.*"):
            try:
                if f.stat().st_mtime < cutoff:
                    stale.append(f.name)
            except OSError:
                pass
    quarantined = len(list((paths.state / "quarantine").glob("*.kapp"))) if (paths.state / "quarantine").is_dir() else 0
    checks = []
    if stale:
        checks.append(Check(WARN, "leftovers", f"{len(stale)} temporary file(s) from an interrupted write "
                                               f"(safe to delete): {_names(stale, 3)}"))
    else:
        checks.append(Check(PASS, "leftovers", "no interrupted writes" + (
            f"; {quarantined} flagged file(s) in quarantine (kos optimize clears old ones)" if quarantined else "")))
    return checks


CHECKS = (_kernel, _password, _files, _audit, _apps, _permissions, _owed, _leftovers)


def run_checks(paths: Paths) -> list[Check]:
    out: list[Check] = []
    for fn in CHECKS:
        try:
            out.extend(fn(paths))
        except Exception as e:      # a check that breaks must show up as a failure, never vanish
            out.append(Check(FAIL, fn.__name__.lstrip("_"), f"could not be run: {e!r}"))
    return out


def render(checks: list[Check]) -> str:
    from .protocol import escape_text
    tag = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL"}
    lines = ["KOS security check - needs no password and changes nothing"]
    for c in checks:
        lines.append(f"  {tag[c.level]}  {c.name:12} {escape_text(c.detail)}")
    n = {lvl: sum(1 for c in checks if c.level == lvl) for lvl in (PASS, WARN, FAIL)}
    lines.append(f"Result: {n[PASS]} passed, {n[WARN]} warning(s), {n[FAIL]} failed")
    return "\n".join(lines)
