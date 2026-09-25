"""Command line: ``kos <command>`` and the ``run`` shortcut.

    kos setup                       choose your password (first boot)
    kos passwd                      change it (re-seals every installed app)
    kos pack DIR -o APP.kapp        build an app zip from a directory
    kos install APP.kapp            install (the zip is stored as-is, sealed)
    kos update APP.kapp             update to a newer version (no downgrades)
    kos view FILE                   view a file (password first)
    kos remove NAME
    kos list
    run NAME                        run the app as a text (TUI) page
    run graphical NAME              run the app's graphical version
    run [graphical] NAME --cell C   run it inside kernel cell C
    kos cell start NAME --kernel K --initrd I [--cpus 2,3] [--memory 256]
    kos cell list | kos cell stop NAME
    kos doctor                      which kernel protections are available
    kos audit                       show the authorization log
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

from . import loader
from .auth import (AuthError, Authority, AuthorizationDenied, KdfParams, PasswordStore,
                   derive_master, subkey)
from .cells import CellError
from .kapp import KAppError, pack
from .paths import Paths
from .prompt import NoTTY, TTYPrompter, eprint
from .sandbox import SandboxError, SandboxPolicy, report
from .store import SEAL_KEY_LABEL, AppStore, TamperedError


def _authority(paths: Paths) -> tuple[Authority, TTYPrompter]:
    prompter = TTYPrompter()
    return Authority(paths, prompter), prompter


def _new_password(prompter: TTYPrompter) -> bytes:
    for _ in range(3):
        a = prompter.password("New password: ")
        b = prompter.password("Type it again: ")
        if a and a == b:
            if len(a) < 8:
                prompter.info("Use at least 8 characters.")
                continue
            return a
        prompter.info("Passwords did not match.")
    raise AuthError("password not set")


def _kdf(args) -> KdfParams:
    if getattr(args, "fast_kdf", False):
        eprint("WARNING: --fast-kdf makes password guessing ~8x cheaper. Development only.")
        return KdfParams.fresh(n=2**14)
    return KdfParams.fresh()


def cmd_setup(args, paths: Paths) -> int:
    store = PasswordStore(paths)
    if store.exists():
        raise AuthError("already set up; use 'kos passwd' to change the password")
    prompter = TTYPrompter()
    prompter.info("Choose the password that will protect everything on this system.\n"
                  "You will type it to boot, to log in, to run apps and to boot devices.")
    store.create(_new_password(prompter), params=_kdf(args)).wipe()
    print("Password set. Nothing on this system will run without it.")
    return 0


def cmd_passwd(args, paths: Paths) -> int:
    authority, prompter = _authority(paths)
    store = AppStore(paths)
    with authority.authorize("auth.change") as old:
        new_pw = _new_password(prompter)
        params = _kdf(args)
        with derive_master(new_pw, params) as master:
            n = store.reseal_all(old, subkey(master, SEAL_KEY_LABEL))
            authority.store.write(params, master, authority.store.throttle_base())
    print(f"Password changed; {n} app(s) re-sealed.")
    print("Remember to also change the disk password: cryptsetup luksChangeKey <root device>")
    return 0


def cmd_pack(args, paths: Paths) -> int:
    m = pack(Path(args.dir), Path(args.output))
    print(f"packed {m.name} {m.version} -> {args.output}")
    return 0


def cmd_install(args, paths: Paths) -> int:
    authority, _ = _authority(paths)
    m = AppStore(paths).install(Path(args.file), authority)
    print(f"installed {m.name} {m.version} (modes: {', '.join(m.modes)}) - kept zipped, sealed")
    return 0


def cmd_update(args, paths: Paths) -> int:
    authority, _ = _authority(paths)
    old, m = AppStore(paths).update(Path(args.file), authority)
    print(f"updated {m.name} {old} -> {m.version} (re-sealed)")
    return 0


def cmd_view(args, paths: Paths) -> int:
    """Show a file. Viewing files is an action like any other: password first."""
    from .protocol import clean_text
    path = os.path.realpath(args.file)
    authority, _ = _authority(paths)
    authority.authorize("file.view", path).close()
    with open(path, "rb") as f:
        data = f.read(4 << 20)
    text = data.decode("utf-8", errors="replace")
    # strip terminal escapes so a file can't take over your terminal
    for line in text.splitlines():
        print(clean_text(line.replace("\t", "    "), 10_000))
    return 0


def cmd_remove(args, paths: Paths) -> int:
    authority, _ = _authority(paths)
    AppStore(paths).remove(args.name, authority)
    print(f"removed {args.name}")
    return 0


def cmd_list(args, paths: Paths) -> int:
    apps = AppStore(paths).installed()
    if not apps:
        print("no apps installed")
    for a in apps:
        print(f"{a.name:20} {a.version:10} sha256:{a.sha256[:16]}")
    return 0


def _parse_run_target(words: list[str]) -> tuple[str, str]:
    if len(words) == 1:
        return "tui", words[0]
    if len(words) == 2 and words[0] == "graphical":
        return "graphical", words[1]
    raise KAppError("usage: run [graphical] APP")


def cmd_run(args, paths: Paths) -> int:
    from .protocol import Channel
    mode, name = _parse_run_target(args.target)
    authority, prompter = _authority(paths)
    store = AppStore(paths)
    action = "app.graphical" if mode == "graphical" else "app.run"
    with authority.authorize(action, name) as grant:
        app = store.load_verified(name, grant)
    m = app.manifest
    if mode not in m.modes:
        other = "run " + name if "tui" in m.modes else "run graphical " + name
        raise KAppError(f"{name} has no {mode} version; try: {other}")
    allow_net = False
    if "network" in m.permissions and not args.cell:
        if prompter.confirm(f"{name} asks for network access. Allow for this run?"):
            authority.authorize("app.network", name).close()
            allow_net = True
    policy = SandboxPolicy(allow_network=allow_net,
                           weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    paths.ensure()
    log_path = paths.logs / f"{name}.log"
    if args.cell:
        from .cells import CellManager, connect_cell, send_app
        rec = CellManager(paths).get(args.cell)
        sock = connect_cell(rec["cid"])
        send_app(sock, app, mode)
        proc = None
    else:
        sock, child = socket.socketpair()
        proc = loader.launch(loader.plan(app, child.fileno(), mode), policy, log_path)
        child.close()
    prompter.close()
    code = _run_session(name, mode, Channel(sock), proc, authority, open(log_path, "a"))
    print(f"{name} exited ({code})")
    return code


def _on_console_vt() -> bool:
    try:
        name = os.ttyname(0)
    except OSError:
        return False
    return name.startswith("/dev/tty") and name[8:].isdigit()


def _run_session(name, mode, channel, proc, authority, log) -> int:
    from .devices import EvdevDevices, TerminalDevices
    from .display import FbdevBackend, GraphicalSurface, TerminalBackend
    from .session import Session
    from .term import RawTerminal
    from .tui import TUISurface

    use_fb = (mode == "graphical" and os.path.exists("/dev/fb0") and _on_console_vt()
              and os.environ.get("KOS_DISPLAY") != "terminal")
    with RawTerminal() as term:
        cols, rows = term.size()
        if mode == "tui":
            surface = TUISurface(1, cols, rows, name)
            devices = TerminalDevices(term, cell_to_pixels=False)
        elif use_fb:
            backend = FbdevBackend(tty_fd=0)
            surface = GraphicalSurface(backend, status_in_frame=True)
            devices = EvdevDevices(backend.width, backend.height)
        else:
            surface = GraphicalSurface(TerminalBackend(1, cols, rows))
            devices = TerminalDevices(term, cell_to_pixels=True)
        try:
            return Session(name=name, mode=mode, channel=channel, proc=proc, surface=surface,
                           devices=devices, authority=authority, log=log).run()
        finally:
            devices.close()
            surface.close()


def cmd_cell(args, paths: Paths) -> int:
    from .cells import CellManager, CellSpec
    mgr = CellManager(paths)
    if args.cell_cmd == "list":
        for c in mgr.cells():
            state = "running" if c["running"] else "dead"
            print(f"{c['name']:16} cid={c['cid']:<4} cpus={c['cpus']} {c['memory_mb']}M {state}")
        return 0
    authority, _ = _authority(paths)
    if args.cell_cmd == "start":
        spec = CellSpec(name=args.name, kernel=args.kernel, initrd=args.initrd,
                        memory_mb=args.memory, cpus=[int(c) for c in args.cpus.split(",")])
        rec = mgr.start(spec, authority)
        print(f"cell {rec['name']} started: its own kernel on cores {rec['cpus']}, "
              f"vsock cid {rec['cid']}")
    else:
        mgr.stop(args.name, authority)
        print(f"cell {args.name} stopped")
    return 0


def cmd_doctor(args, paths: Paths) -> int:
    r = report()
    ok = lambda b: "yes" if b else "NO"
    print(f"Landlock ABI          : {r['landlock_abi'] or 'NOT AVAILABLE (apps will refuse to run)'}")
    print(f"user namespaces       : {ok(r['user_namespaces'])}")
    print(f"KVM (kernel cells)    : {ok(r['kvm'])}")
    print(f"vhost-vsock (cells)   : {ok(r['vhost_vsock'])}")
    print(f"framebuffer /dev/fb0  : {ok(r['framebuffer'])}")
    print(f"evdev /dev/input      : {ok(r['evdev'])}")
    print(f"password configured   : {ok(PasswordStore(paths).exists())}")
    return 0


def cmd_audit(args, paths: Paths) -> int:
    import time
    from .auth import AuditLog
    for e in AuditLog(paths).entries()[-args.n:]:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["t"]))
        print(f"{t}  {e['outcome']:13} {e['action']:15} {e['target']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kos", description="KOS security layer")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="choose your password")
    s.add_argument("--fast-kdf", action="store_true", help=argparse.SUPPRESS)
    s = sub.add_parser("passwd", help="change your password")
    s.add_argument("--fast-kdf", action="store_true", help=argparse.SUPPRESS)
    s = sub.add_parser("pack", help="build a .kapp from a directory")
    s.add_argument("dir")
    s.add_argument("-o", "--output", required=True)
    s = sub.add_parser("install", help="install a .kapp")
    s.add_argument("file")
    s = sub.add_parser("update", help="update an installed app to a newer .kapp")
    s.add_argument("file")
    s = sub.add_parser("view", help="view a file (asks for the password)")
    s.add_argument("file")
    s = sub.add_parser("remove", help="remove an app")
    s.add_argument("name")
    sub.add_parser("list", help="list installed apps")
    s = sub.add_parser("run", help="run an app: run [graphical] NAME")
    s.add_argument("target", nargs="+")
    s.add_argument("--cell", help="run inside this kernel cell")
    s = sub.add_parser("cell", help="manage parallel kernel cells")
    cs = s.add_subparsers(dest="cell_cmd", required=True)
    c = cs.add_parser("start")
    c.add_argument("name")
    c.add_argument("--kernel", required=True)
    c.add_argument("--initrd", required=True)
    c.add_argument("--cpus", default="1")
    c.add_argument("--memory", type=int, default=256)
    cs.add_parser("list")
    c = cs.add_parser("stop")
    c.add_argument("name")
    sub.add_parser("doctor", help="report kernel security features")
    s = sub.add_parser("audit", help="show the authorization log")
    s.add_argument("-n", type=int, default=30)
    return p


COMMANDS = {"setup": cmd_setup, "passwd": cmd_passwd, "pack": cmd_pack,
            "install": cmd_install, "update": cmd_update, "view": cmd_view, "remove": cmd_remove, "list": cmd_list, "run": cmd_run,
            "cell": cmd_cell, "doctor": cmd_doctor, "audit": cmd_audit}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths.from_env()
    try:
        return COMMANDS[args.cmd](args, paths)
    except TamperedError as e:
        eprint(f"\x1b[1;31mSECURITY: {e}\x1b[0m")
        return 3
    except (AuthorizationDenied, AuthError) as e:
        eprint(f"denied: {e}")
        return 2
    except (KAppError, SandboxError, CellError, NoTTY, OSError) as e:
        eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        return 130


def run_main() -> int:
    """Entry point for the bare ``run`` command."""
    return main(["run", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
