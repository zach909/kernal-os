"""Command line: ``python -m kosync migrate ...`` and ``python -m kosync sync ...``.

The password is never taken from the command line (it would show in the process list): it is asked for, or read
from the first line of a file given with ``--password-file``.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__, migrate, paths as P
from .crypto import CryptoError
from . import sync as syncmod


def _password(args, confirm=False) -> str:
    if args.password_file:
        text = Path(args.password_file).read_text(encoding="utf-8")
        return text.split("\n", 1)[0].rstrip("\r")
    pw = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Again: ") != pw:
        raise SystemExit("The two passwords differ.")
    return pw


def _pairs(items, what):
    out = {}
    for it in items or []:
        role, eq, path = it.partition("=")
        if not eq or not role or not path:
            raise SystemExit(f"{what} must look like ROLE=FOLDER, not {it!r}")
        out[role] = Path(path).expanduser()
    return out


def _show_list(title, rows, limit=20):
    if rows:
        print(f"{title}: {len(rows)}")
        for r in rows[:limit]:
            print("   ", r if isinstance(r, str) else "  ->  ".join(map(str, r)))
        if len(rows) > limit:
            print(f"    ... and {len(rows) - limit} more")


def run_migrate(a) -> int:
    if a.action == "export":
        roots = _pairs(a.root, "--root")
        if not roots:
            raise SystemExit("give at least one --root ROLE=FOLDER, e.g. --root documents=~/Documents")
        rep = migrate.export_bundle(roots, a.out, _password(a, confirm=True), include_apps=a.apps)
        print(f"Exported {rep.files} files, {rep.dirs} folders, {rep.bytes} bytes, {rep.apps} apps to {a.out}")
        _show_list("Skipped (not in the bundle)", [f"{p}: {why}" for p, why in rep.skipped])
        return 0
    target = a.target_os or P.detect_os()
    dests = _pairs(a.dest, "--dest")
    if a.action == "inspect":
        a.dry_run = True
    rep = migrate.import_bundle(a.bundle, dests, _password(a), target_os=target, overwrite=a.overwrite,
                                dry_run=a.dry_run, default_dest=lambda r: migrate.default_dir(r, target))
    verb = "Would import" if rep.dry_run else "Imported"
    print(f"{verb} {rep.files} files, {rep.dirs} folders, {rep.bytes} bytes (bundle made on {rep.source_os}; target {target})")
    _show_list("Renamed to be legal here", rep.renamed)
    _show_list("Kept both (a different file was already there)", rep.kept_both)
    if rep.already_there:
        print(f"Already there, identical: {rep.already_there}")
    _show_list("Install on this OS (commands are only printed)", rep.install_commands, 50)
    _show_list("Apps with no known equivalent", rep.no_equivalent, 50)
    return 0


def run_sync(a) -> int:
    if a.action == "init":
        syncmod.create_vault(a.vault, _password(a, confirm=True))
        print(f"Vault created in {a.vault}. Run 'sync run' on each machine with the same password.")
        return 0
    v = syncmod.open_vault(a.vault, _password(a))
    rep = syncmod.sync(v, a.local, a.device, dry_run=a.dry_run)
    head = "Would do" if rep.dry_run else "Done"
    print(f"{head}: {len(rep.uploaded)} up, {len(rep.downloaded)} down, {len(rep.deleted_here)} deleted here, "
          f"{len(rep.deleted_there)} deleted there, {len(rep.conflicts)} conflicts, {rep.unchanged} unchanged")
    _show_list("Conflicts (yours was kept as the second name)", rep.conflicts)
    _show_list("Skipped", [f"{p}: {why}" for p, why in rep.skipped])
    _show_list("Errors (retried next run)", [f"{p}: {why}" for p, why in rep.errors])
    return 1 if rep.errors else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kosync", description="Migrate and sync your data across operating systems.")
    ap.add_argument("--version", action="version", version=__version__)
    top = ap.add_subparsers(dest="program", required=True)

    m = top.add_parser("migrate", help="export to / import from an encrypted bundle")
    ms = m.add_subparsers(dest="action", required=True)
    e = ms.add_parser("export")
    e.add_argument("--root", action="append", metavar="ROLE=FOLDER", help="documents, pictures, music, videos, downloads, desktop, config, other")
    e.add_argument("--out", required=True)
    e.add_argument("--apps", action="store_true", help="also record the installed apps (a reinstall list)")
    e.add_argument("--password-file")
    for name in ("import", "inspect"):
        i = ms.add_parser(name, help="verify the bundle and show what would happen" if name == "inspect" else "restore a bundle")
        i.add_argument("bundle")
        i.add_argument("--dest", action="append", metavar="ROLE=FOLDER")
        i.add_argument("--target-os", choices=P.OS_NAMES)
        i.add_argument("--password-file")
        if name == "import":
            i.add_argument("--overwrite", action="store_true")
            i.add_argument("--dry-run", action="store_true")
    m.set_defaults(fn=run_migrate)

    s = top.add_parser("sync", help="keep a folder identical on several machines")
    ss = s.add_subparsers(dest="action", required=True)
    si = ss.add_parser("init")
    si.add_argument("vault")
    si.add_argument("--password-file")
    sr = ss.add_parser("run")
    sr.add_argument("vault")
    sr.add_argument("local")
    sr.add_argument("--device", required=True)
    sr.add_argument("--dry-run", action="store_true")
    sr.add_argument("--password-file")
    s.set_defaults(fn=run_sync)

    a = ap.parse_args(argv)
    for attr in ("overwrite", "dry_run", "target_os", "dest"):
        if not hasattr(a, attr):
            setattr(a, attr, None)
    try:
        return a.fn(a)
    except (migrate.MigrateError, syncmod.SyncError, CryptoError, P.PathError, OSError) as e:
        print(f"kosync: {e}", file=sys.stderr)
        return 2
