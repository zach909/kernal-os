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
    run cmd NAME                    run it with no drawing: raw command stream
    run [graphical|cmd] NAME --cell C   run it inside kernel cell C
    kos open [graphical|cmd] NAME   open an app in the background, return immediately
    kos ps                          list apps opened with 'kos open'
    kos attach ID                   connect your terminal to an open app (Ctrl-C detaches)
    kos close ID                    stop an app opened with 'kos open'
    kos control ID mouse move X Y / click BUTTON X Y / scroll DY X Y
    kos control ID keyboard KEY [KEY...]   drive a booted device with a command
    kos boot desktop                choose among open apps (no desktop otherwise)
    kos ls PATH / kos cat PATH      browse/view real dirs and zips - never extracted
    kos explore [PATH]              interactive cd/ls/cat, straight into zip files
    kos activity                    one feed: open apps + recent password decisions
    kos permit NAME                 give an app permission to run (password still needed every run)
    kos permit --revoke NAME        take that away
    kos scan file PATH              scan a file or zip right now (no password needed)
    kos scan watch DIR...           scan every file written here until Ctrl-C (password to start)
    kos update all --from DIR       update every installed app that's newer in DIR, scanned first
    kos optimize                    recompress apps, prune dead state, reclaim disk space
    kos mv SRC DST                  move a file: separate passwords for move, optimize, scan
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
from .permit import PermitError
from .protect import ProtectError
from .prompt import NoTTY, TTYPrompter, eprint
from .registry import RegistryError
from .sandbox import SandboxError, SandboxPolicy, report
from .store import SEAL_KEY_LABEL, AppStore, TamperedError, VirusFoundError
from .vfs import VFSError


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
    if args.file == "all":
        if not args.from_dir:
            raise KAppError("usage: kos update all --from DIR")
        authority.authorize("app.update.all").close()
        rows = AppStore(paths).update_all(Path(args.from_dir), authority)
        if not rows:
            print("nothing to update")
        for name, outcome, detail in rows:
            print(f"{name:20} {outcome:15} {detail if detail is not None else ''}")
        flagged = [r for r in rows if r[1] == "flagged"]
        return 3 if flagged else 0
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
    if len(words) == 2 and words[0] in ("graphical", "cmd"):
        return words[0], words[1]
    raise KAppError("usage: run [graphical|cmd] APP")


def _authorize_app_action(name: str, app, mode: str, authority: Authority, prompter) -> SandboxPolicy:
    """Shared by `run` and `open`: mode check + optional network grant."""
    m = app.manifest
    if mode not in m.modes:
        raise KAppError(f"{name} has no {mode} mode (it has: {', '.join(m.modes)})")
    allow_net = False
    if "network" in m.permissions:
        if prompter.confirm(f"{name} asks for network access. Allow?"):
            authority.authorize("app.network", name).close()
            allow_net = True
    return SandboxPolicy(allow_network=allow_net,
                         weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")


def cmd_run(args, paths: Paths) -> int:
    from . import cache
    from .permit import PermitStore
    from .protocol import Channel
    mode, name = _parse_run_target(args.target)
    PermitStore(paths).require(name)  # refused before we even ask for the password
    authority, prompter = _authority(paths)
    store = AppStore(paths)
    action = "app.graphical" if mode == "graphical" else "app.run"
    with authority.authorize(action, name) as grant:
        app = store.load_verified(name, grant)
    policy = _authorize_app_action(name, app, mode, authority, prompter) if not args.cell else \
        SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    paths.ensure()
    log_path = paths.logs / f"{name}.log"
    cache_dir = None
    if args.cell:
        from .cells import CellManager, connect_cell, send_app
        rec = CellManager(paths).get(args.cell)
        sock = connect_cell(rec["cid"])
        send_app(sock, app, mode)
        proc = None
    else:
        cache_dir = cache.alloc(paths, name)
        policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
        sock, child = socket.socketpair()
        proc = loader.launch(loader.plan(app, child.fileno(), mode, cache_dir), policy, log_path)
        child.close()
    prompter.close()
    try:
        code = _run_session(name, mode, Channel(sock), proc, authority, open(log_path, "a"))
    finally:
        if cache_dir is not None:
            cache.wipe(cache_dir)
    print(f"{name} exited ({code})")
    return code


def cmd_open(args, paths: Paths) -> int:
    """Launch an app in the background. Returns your shell immediately;
    `kos ps` lists it, `kos attach ID` connects your terminal to it."""
    from . import cache
    from .broker import spawn
    from .permit import PermitStore
    from .registry import Instance, Registry

    mode, name = args.mode or "tui", args.name
    PermitStore(paths).require(name)  # refused before we even ask for the password
    authority, prompter = _authority(paths)
    store = AppStore(paths)
    action = "app.graphical" if mode == "graphical" else "app.open"
    with authority.authorize(action, name) as grant:
        app = store.load_verified(name, grant)
    policy = _authorize_app_action(name, app, mode, authority, prompter)
    prompter.close()

    paths.ensure()
    cache_dir = cache.alloc(paths, name)
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    registry = Registry(paths)
    registry.prune()
    inst_id = registry.new_id(name)
    inst = Instance(id=inst_id, name=name, mode=mode, broker_pid=0,
                    sock_path=str(paths.state / "instances" / f"{inst_id}.sock"),
                    log_path=str(paths.logs / f"{inst_id}.log"), started=__import__("time").time())
    spawn(inst, app, mode, policy, registry, Path(inst.log_path), cache_dir)
    print(f"opened {name} [{mode}] as {inst_id}")
    print(f"  kos attach {inst_id}   (or: kos boot desktop)")
    return 0


def cmd_ps(args, paths: Paths) -> int:
    from .registry import Registry
    insts = Registry(paths).list()
    if not insts:
        print("no apps open")
    for i in insts:
        print(f"{i.id:24} {i.name:14} {i.mode:9} {i.status:9} pid={i.app_pid or '-'}")
    return 0


def cmd_attach(args, paths: Paths) -> int:
    """Connect your terminal to an app already opened with `kos open`. No
    new password is needed just to reconnect - it was already authorized
    when it was opened - but every device still has to be booted again for
    this terminal, with the password, same as any other session."""
    from .protocol import Channel
    from .registry import Registry

    authority, prompter = _authority(paths)
    inst = Registry(paths).get(args.id)
    if inst.status != "running":
        raise KAppError(f"{args.id} is not running (status: {inst.status})")
    prompter.close()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(inst.sock_path)
    except OSError as e:
        raise KAppError(f"could not attach to {inst.id}: {e}") from None
    log = open(inst.log_path, "a") if os.path.exists(inst.log_path) else None
    code = _run_session(inst.name, inst.mode, Channel(sock), None, authority, log,
                        detach_on_interrupt=True)
    print(f"detached from {inst.id}" if code == 0 else f"{inst.id} exited ({code})")
    return 0


def cmd_control(args, paths: Paths) -> int:
    """Send commands to a booted device on an open app instead of touching
    a real mouse/keyboard - the same wire commands, the same password gate
    (`device.control`, once per invocation) as physically booting one."""
    from .control import ControlError, parse_args, send
    from .registry import Registry

    inst = Registry(paths).get(args.id)
    if inst.status != "running":
        raise KAppError(f"{args.id} is not running (status: {inst.status})")
    commands = parse_args(args.device, args.words)  # validate before asking for the password
    authority, _ = _authority(paths)
    with authority.authorize("device.control", f"{inst.id} {args.device}"):
        try:
            send(inst.sock_path, commands)
        except OSError as e:
            raise ControlError(f"could not reach {inst.id}: {e}") from None
    print(f"sent {len(commands) - 1} command(s) to {inst.id}'s {args.device}")
    return 0


def cmd_close(args, paths: Paths) -> int:
    import signal
    import time as _time
    from .registry import Registry

    authority, _ = _authority(paths)
    registry = Registry(paths)
    inst = registry.get(args.id)
    with authority.authorize("app.close", inst.id):
        if inst.status == "running":
            try:
                os.kill(inst.broker_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(20):  # give the broker a moment to shut the app down cleanly
                if not os.path.exists(str(paths.state / "instances" / f"{inst.id}.json")):
                    break
                _time.sleep(0.1)
        registry.remove(inst.id)
    print(f"closed {inst.id}")
    return 0


def cmd_boot(args, paths: Paths) -> int:
    """`kos boot desktop`: the only way a chooser of open apps ever appears.
    Without it, `kos attach ID` still works - there is no windowing desktop
    unless you explicitly ask for one."""
    if args.what != "desktop":
        raise KAppError("usage: kos boot desktop")
    from .registry import Registry
    from .term import RawTerminal

    authority, prompter = _authority(paths)
    authority.authorize("device.desktop").close()
    registry = Registry(paths)
    insts = [i for i in registry.list() if i.status == "running"]
    prompter.close()
    if not insts:
        print("no apps open (kos open NAME first)")
        return 0
    with RawTerminal() as term:
        term.write("\x1b[?1049l")  # desktop chooser is plain scrollback, not alt-screen
    print("\r\nKOS desktop - open apps:\r\n")
    for n, i in enumerate(insts, 1):
        print(f"  {n}. {i.name} [{i.mode}]  ({i.id})\r")
    print("\r\nq to cancel\r\n")
    choice = input("attach to: ").strip()
    if not choice or choice == "q":
        return 0
    try:
        inst = insts[int(choice) - 1]
    except (ValueError, IndexError):
        raise KAppError("no such entry") from None
    args.id = inst.id
    return cmd_attach(args, paths)


def _print_text(data: bytes, clean_text) -> None:
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        print(clean_text(line.replace("\t", "    "), 10_000))


def _resolve_mixed(path: str):
    """Walk a path that may cross from the real disk into a zip and, once
    inside, into further nested zips - e.g. ``apps/hello.kapp/manifest.json``.
    ``VFS.cd`` already treats a zip entry as just another directory, so this
    is a plain walk down the real, absolute path one component at a time.
    Returns (VFS positioned at the parent, final component name)."""
    from .vfs import VFS

    parts = [p for p in os.path.abspath(path).split(os.sep) if p]
    if not parts:
        raise KAppError("no path given")
    vfs = VFS("/")
    for part in parts[:-1]:
        vfs.cd(part)
    return vfs, parts[-1]


def cmd_ls(args, paths: Paths) -> int:
    vfs, last = _resolve_mixed(args.path)
    vfs.cd(last)
    for e in vfs.list():
        tag = "/" if e.is_dir else (" (zip)" if e.is_archive else "")
        print(f"{e.name}{tag}")
    return 0


def cmd_cat(args, paths: Paths) -> int:
    """View a file - including one living inside a zip, without extracting it."""
    from .protocol import clean_text
    authority, _ = _authority(paths)
    authority.authorize("file.view", os.path.abspath(args.path)).close()
    vfs, last = _resolve_mixed(args.path)
    _print_text(vfs.read_bytes(last), clean_text)
    return 0


def cmd_explore(args, paths: Paths) -> int:
    """An interactive shell for walking real directories and zip files as one
    tree: `cd something.kapp` steps straight into the archive. Browsing
    (`cd`/`ls`) needs no password; `cat` does, same as `kos view`."""
    from .protocol import clean_text
    from .vfs import VFS

    vfs = VFS(args.start)
    print(f"kos explore - {vfs.pwd()}  (cd, ls, cat FILE, up, exit)")
    while True:
        try:
            line = input(f"{vfs.pwd()}> ").strip()
        except EOFError:
            print()
            return 0
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        rest = rest.strip()
        try:
            if cmd in ("exit", "quit"):
                return 0
            elif cmd == "pwd":
                print(vfs.pwd())
            elif cmd == "ls":
                for e in vfs.list():
                    tag = "/" if e.is_dir else (" (zip)" if e.is_archive else "")
                    print(f"{e.name}{tag}")
            elif cmd in ("cd", "up") and (cmd == "up" or not rest):
                vfs.up()
            elif cmd == "cd":
                vfs.cd(rest)
            elif cmd == "cat" and rest:
                authority, _ = _authority(paths)
                authority.authorize("file.view", f"{vfs.pwd()}/{rest}").close()
                _print_text(vfs.read_bytes(rest), clean_text)
            else:
                print("commands: cd NAME | cd .. | ls | cat FILE | pwd | exit")
        except VFSError as e:
            print(f"error: {e}")


def cmd_activity(args, paths: Paths) -> int:
    from .activity import build_feed, render_feed
    print(render_feed(build_feed(paths, limit=args.n)))
    return 0


def _on_console_vt() -> bool:
    try:
        name = os.ttyname(0)
    except OSError:
        return False
    return name.startswith("/dev/tty") and name[8:].isdigit()


def _build_surface(mode, name, term):
    from .cmdsurface import CmdSurface
    from .devices import EvdevDevices, TerminalDevices
    from .display import FbdevBackend, GraphicalSurface, TerminalBackend
    from .tui import TUISurface

    cols, rows = term.size()
    use_fb = (mode == "graphical" and os.path.exists("/dev/fb0") and _on_console_vt()
              and os.environ.get("KOS_DISPLAY") != "terminal")
    if mode == "cmd":
        return CmdSurface(1, cols, rows, name), TerminalDevices(term, cell_to_pixels=False)
    if mode == "tui":
        return TUISurface(1, cols, rows, name), TerminalDevices(term, cell_to_pixels=False)
    if use_fb:
        backend = FbdevBackend(tty_fd=0)
        return (GraphicalSurface(backend, status_in_frame=True),
                EvdevDevices(backend.width, backend.height))
    return GraphicalSurface(TerminalBackend(1, cols, rows)), TerminalDevices(term, cell_to_pixels=True)


def _run_session(name, mode, channel, proc, authority, log, **session_kwargs) -> int:
    from .session import Session
    from .term import RawTerminal

    with RawTerminal() as term:
        surface, devices = _build_surface(mode, name, term)
        try:
            return Session(name=name, mode=mode, channel=channel, proc=proc, surface=surface,
                           devices=devices, authority=authority, log=log,
                           **session_kwargs).run()
        finally:
            devices.close()
            surface.close()


def cmd_permit(args, paths: Paths) -> int:
    """A permit is separate from the password: it's your standing decision
    that an app may run at all. It never skips the password - `run`/`open`
    still ask for it every single time, same as everything else."""
    from .permit import PermitStore
    store = PermitStore(paths)
    if args.list:
        permits = store.list()
        if not permits:
            print("no apps permitted to run")
        for p in permits:
            import time as _t
            print(f"{p.name:20} granted {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(p.granted_at))}")
        return 0
    if not args.name:
        raise KAppError("usage: kos permit NAME | kos permit --revoke NAME | kos permit --list")
    authority, _ = _authority(paths)
    action = "app.revoke" if args.revoke else "app.permit"
    with authority.authorize(action, args.name):
        if args.revoke:
            PermitStore(paths).revoke(args.name)
            print(f"revoked: {args.name} may no longer run")
        else:
            PermitStore(paths).grant(args.name)
            print(f"permitted: {args.name} may now run (still asks for your password every time)")
    return 0


def cmd_scan(args, paths: Paths) -> int:
    """`kos scan file PATH` checks one file or zip right now, no password
    needed (it's read-only, like `kos list`). `kos scan watch DIR...` is
    different: starting it needs the password, the same as starting a
    kernel cell, because from that point on it keeps running and acting -
    scanning every file written under those directories - until you stop
    it. `kos scan protect DIR` goes further: the directory is locked (no
    write access for anyone, not even you) the instant you protect it, and
    stays locked except while a `kos scan watch` covering it is actively
    running - that's what "needs the password to start, but blocks you from
    moving a file in if you don't let it start" means literally."""
    from .protect import ProtectStore, held_unlock
    from .scan import scan_file

    if args.scan_cmd == "protect":
        ProtectStore(paths).protect(args.dir, _authority(paths)[0])
        print(f"locked: {os.path.realpath(args.dir)} - nothing can be written there "
              f"until 'kos scan watch' is running against it")
        return 0

    if args.scan_cmd == "unprotect":
        ProtectStore(paths).unprotect(args.dir, _authority(paths)[0])
        print(f"unlocked permanently: {os.path.realpath(args.dir)}")
        return 0

    if args.scan_cmd == "protected":
        rows = ProtectStore(paths).list()
        if not rows:
            print("no protected directories")
        for r in rows:
            print(r.path)
        return 0

    if args.scan_cmd == "watch":
        from .watch import ScanHit, run_watch
        for d in args.dirs:
            if not os.path.isdir(d):
                raise KAppError(f"not a directory: {d}")
        authority, prompter = _authority(paths)
        authority.authorize("scan.watch", ", ".join(args.dirs)).close()
        prompter.close()
        store = ProtectStore(paths)
        real_dirs = [os.path.realpath(d) for d in args.dirs]
        protected_flags = [store.is_protected(d) for d in real_dirs]
        for d, was_protected in zip(real_dirs, protected_flags):
            if was_protected:
                print(f"unlocked (protected): {d}")
        print(f"watching {', '.join(args.dirs)} - every file written here is scanned. "
              "Ctrl-C to stop; a protected directory relocks the instant this stops.")

        def on_hit(hit: "ScanHit") -> None:
            qdir = paths.state / "quarantine"
            qdir.mkdir(parents=True, exist_ok=True)
            import time as _t
            qpath = qdir / f"{Path(hit.path).name}-{int(_t.time())}"
            try:
                os.replace(hit.path, qpath)
                where = f"quarantined to {qpath}"
            except OSError as e:
                where = f"could NOT be quarantined ({e}) - still on disk at {hit.path}"
            print(f"\x1b[1;31mFLAGGED\x1b[0m {hit.path}: {hit.result.summary()} - {where}")

        def on_scan(path: str) -> None:
            print(f"scanned: {path}")

        contexts = [held_unlock(d, p) for d, p in zip(real_dirs, protected_flags)]
        try:
            for ctx in contexts:
                ctx.__enter__()
            try:
                run_watch(args.dirs, on_hit, lambda: False, on_scan=on_scan)
            except KeyboardInterrupt:
                print("\nstopped")
        finally:
            for ctx in reversed(contexts):
                ctx.__exit__(None, None, None)
            for d, was_protected in zip(real_dirs, protected_flags):
                if was_protected:
                    print(f"relocked (protected): {d}")
        return 0

    result = scan_file(Path(args.path))
    print(f"{args.path}: {result.summary()}")
    for f in result.findings:
        print(f"  [{f.severity}] {f.rule} in {f.path}: {f.note}")
    return 0 if result.clean else 3


def cmd_optimize(args, paths: Paths) -> int:
    from .optimize import optimize
    authority, _ = _authority(paths)
    report = optimize(paths, authority)
    print(report.summary())
    return 0


def cmd_mv(args, paths: Paths) -> int:
    """Move or rename a file through KOS instead of around it: three
    separate password prompts, one per step - move, then optimize, then
    scan the new location - and declining any one of them stops the whole
    command right there (raises, same as every other declined action in
    KOS). Whatever already happened before the decline stands; it is never
    undone, because undoing something already done would itself be an
    action nobody authorized. So: decline step 1 and nothing moves at all;
    decline step 2 and the move already happened but nothing is optimized;
    decline step 3 and the move (and optimize, if you allowed it) already
    happened but the moved file is left unscanned.
    """
    import shutil
    from .optimize import optimize
    from .scan import scan_file

    src, dst = os.path.abspath(args.src), os.path.abspath(args.dst)
    if not os.path.exists(src):
        raise KAppError(f"no such file: {args.src}")
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))

    authority, _ = _authority(paths)
    with authority.authorize("fs.move", f"{src} -> {dst}"):
        try:
            os.replace(src, dst)
        except OSError:
            shutil.move(src, dst)
    print(f"moved: {src} -> {dst}")

    report = optimize(paths, authority)
    print(f"optimize: {report.summary()}")

    with authority.authorize("fs.verify", dst):
        if os.path.isdir(dst):
            results = [scan_file(p) for p in Path(dst).rglob("*") if p.is_file()]
            flagged = [r for r in results if not r.clean]
            print(f"scan: {len(results)} file(s) checked, {len(flagged)} flagged")
            for r in flagged:
                print(f"  {r.summary()}")
        else:
            result = scan_file(Path(dst))
            print(f"scan: {result.summary()}")
    return 0


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
    s = sub.add_parser("update", help="update an app (or all of them): update APP.kapp | update all --from DIR")
    s.add_argument("file", help="a .kapp path, or the literal word 'all'")
    s.add_argument("--from", dest="from_dir", help="directory to check for updates (with 'all')")
    s = sub.add_parser("view", help="view a file (asks for the password)")
    s.add_argument("file")
    s = sub.add_parser("remove", help="remove an app")
    s.add_argument("name")
    sub.add_parser("list", help="list installed apps")
    s = sub.add_parser("run", help="run an app: run [graphical|cmd] NAME")
    s.add_argument("target", nargs="+")
    s.add_argument("--cell", help="run inside this kernel cell")
    s = sub.add_parser("open", help="open an app in the background: open [graphical|cmd] NAME")
    s.add_argument("mode", nargs="?", choices=["graphical", "cmd"], default=None)
    s.add_argument("name")
    sub.add_parser("ps", help="list apps opened with 'kos open'")
    s = sub.add_parser("attach", help="attach your terminal to an open app")
    s.add_argument("id")
    s = sub.add_parser("close", help="stop an app opened with 'kos open'")
    s.add_argument("id")
    s = sub.add_parser("boot", help="boot desktop: choose among open apps")
    s.add_argument("what", choices=["desktop"])
    s = sub.add_parser("ls", help="list a directory or a zip, without extracting")
    s.add_argument("path")
    s = sub.add_parser("cat", help="view a file, including one inside a zip")
    s.add_argument("path")
    s = sub.add_parser("explore", help="interactively cd/ls/cat through real dirs and zips")
    s.add_argument("start", nargs="?", default=".")
    s = sub.add_parser("activity", help="one feed: open apps + recent password decisions")
    s.add_argument("-n", type=int, default=30)
    s = sub.add_parser("permit", help="give (or revoke) an app permission to run at all")
    s.add_argument("name", nargs="?")
    s.add_argument("--revoke", action="store_true", help="take away permission instead of granting it")
    s.add_argument("--list", action="store_true", help="list every app with permission to run")
    s = sub.add_parser("scan", help="scan a file/zip for known-bad patterns, or watch a directory")
    ss = s.add_subparsers(dest="scan_cmd", required=True)
    sf = ss.add_parser("file", help="scan one file or zip right now (no password needed)")
    sf.add_argument("path")
    sw = ss.add_parser("watch", help="scan every file written under these directories until Ctrl-C")
    sw.add_argument("dirs", nargs="+")
    sp = ss.add_parser("protect", help="lock a directory: no writes until a watch covers it")
    sp.add_argument("dir")
    su_ = ss.add_parser("unprotect", help="unlock a directory permanently")
    su_.add_argument("dir")
    ss.add_parser("protected", help="list locked directories (no password needed)")
    s = sub.add_parser("optimize", help="reclaim disk space: recompress apps, prune dead state")
    s = sub.add_parser("mv", help="move/rename a file: separate passwords for move, optimize, scan")
    s.add_argument("src")
    s.add_argument("dst")
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
            "install": cmd_install, "update": cmd_update, "view": cmd_view, "remove": cmd_remove,
            "list": cmd_list, "run": cmd_run, "open": cmd_open, "ps": cmd_ps, "attach": cmd_attach,
            "close": cmd_close, "boot": cmd_boot, "ls": cmd_ls, "cat": cmd_cat,
            "explore": cmd_explore, "activity": cmd_activity,
            "permit": cmd_permit, "scan": cmd_scan, "optimize": cmd_optimize, "mv": cmd_mv,
            "cell": cmd_cell, "doctor": cmd_doctor, "audit": cmd_audit}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths.from_env()
    try:
        return COMMANDS[args.cmd](args, paths)
    except (TamperedError, VirusFoundError) as e:
        eprint(f"\x1b[1;31mSECURITY: {e}\x1b[0m")
        return 3
    except (AuthorizationDenied, AuthError, PermitError, ProtectError) as e:
        eprint(f"denied: {e}")
        return 2
    except (KAppError, SandboxError, CellError, RegistryError, VFSError, NoTTY, OSError) as e:
        eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        return 130


def run_main() -> int:
    """Entry point for the bare ``run`` command."""
    return main(["run", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
