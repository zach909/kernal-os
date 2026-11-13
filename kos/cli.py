"""Command line: ``kos <command>`` and the ``run`` shortcut.

    kos setup                       choose your password (first boot)
    kos passwd                      change it (re-seals every installed app)
    kos pack DIR -o APP.kapp        build an app zip from a directory
    kos pack APPDIR -o FOLDER       an app made of programs: one .kapp per program, each with only its own permissions
    kos install APP.kapp            install (the zip is stored as-is, sealed); a folder installs every .kapp in it
    kos update APP.kapp             update to a newer version (no downgrades)
    kos view FILE                   view a file (password first)
    kos remove NAME
    kos list
    run NAME                        run the app as a text (TUI) page
    run graphical NAME              run the app's graphical version
    run cmd NAME                    run it with no drawing: raw command stream
    run [graphical|cmd] NAME --cell C   run it inside kernel cell C
    kos open [graphical|cmd] NAME   open an app in the background, return immediately
    kos go kos://NAME[/path][?q]    open an address, like a browser's address bar (run/open take them too)
    kos extend NAME                 switch an extension or mod on for the app it extends (password)
    kos extend --revoke NAME / --list
    kos overlay order MOD...        set the load order of mod file layers, last wins (password)
    kos overlay show [FOLDER]       the merged files and who provides each (password)
    kos overlay conflicts           every file more than one mod provides, who wins (password)
    kos ps                          list apps opened with 'kos open'
    kos attach ID                   connect your terminal to an open app (Ctrl-C detaches)
    kos close ID                    stop an app opened with 'kos open'
    kos desktop install             pack, scan, install + permit the taskbar, App Library, mouse, keyboard, display, wallpaper
    kos boot desktop [--graphical]  the desktop: taskbar + App Library apps; right mouse = App Library
    kos ls PATH / kos cat PATH      browse/view real dirs and zips - never extracted
    kos explore [PATH]              interactive cd/ls/cat, straight into zip files
    kos activity                    one feed: open apps + recent password decisions
    kos permit NAME                 give an app permission to run (password still needed every run)
    kos permit --revoke NAME        take that away
    kos scan file PATH              scan a file or zip right now (no password needed)
    kos scan watch DIR...           scan every file written here until Ctrl-C (password to start)
    kos update all --from DIR       update every installed app that's newer in DIR, scanned first
    kos optimize                    recompress apps, prune dead state, reclaim disk space
    kos cell start NAME --kernel K --initrd I [--cpus 2,3] [--memory 256]
    kos cell list | kos cell stop NAME
    kos doctor                      which kernel protections are available
    kos firmware                    management processors (Intel ME, AMD PSP, BMC) and whether the OS may boot
    kos audit                       show the authorization log
    kos admin [status|boot|lock]    the elevated administrator keyboard (boots at login)
    kos write PATH --text T         write a file: admin keyboard + security scan + disk optimize
    kos backup add PATH...          back up files/folders: scanned, stored once per content (password)
    kos backup [list]               what is backed up and how much deduplication saved (password)
    kos backup restore ID DIR       put one item back in DIR; guarded write, never overwrites
    kos backup remove ID            forget one item (its body goes when nothing else uses it)
    kos backup link APP URL         back up an app as its https address + SHA-256, not its bytes (password)
    kos backup links                the linked apps and the space saved
    kos backup fetch APP            download a linked app, verify the hash, scan, install (password)
    kos backup unlink APP           forget a link
    kos folders [create]            the standard data folders; create makes them (password)
    kos do WORDS...                 one line of human language, run as one command
    kos line [--explain]            the line shell: every line you type is a command
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

from . import loader
from .admin import AdminError, WriteBlocked
from .ai import AIError
from .backup import BackupError, VaultTamperedError
from .auth import (AuthError, Authority, AuthorizationDenied, KdfParams, PasswordStore,
                   derive_master, subkey)
from .cells import CellError
from .kapp import MANIFEST, KApp, KAppError, has_program_below, pack, pack_tree
from .paths import Paths
from .permit import PermitError
from .prompt import NoTTY, TTYPrompter, eprint
from .registry import RegistryError
from .runtimes import LanguageError
from .sandbox import SandboxError, report
from .store import SEAL_KEY_LABEL, AppStore, TamperedError, VirusFoundError
from .system import SystemBridge, bridge_for, close_instance, open_background
from .vfs import VFSError


def _authority(paths: Paths) -> tuple[Authority, TTYPrompter]:
    prompter = TTYPrompter()
    return Authority(paths, prompter), prompter


def _view(paths: Paths, what: str) -> None:
    """Looking at what is installed, open, logged or owed needs the password too: the audit log and
    the activity feed show what you did and which apps you run. Refused before anything is printed."""
    authority, _ = _authority(paths)
    authority.authorize("state.view", what).close()


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
    src = Path(args.dir)
    if (src / MANIFEST).is_file() and not has_program_below(src):
        m = pack(src, Path(args.output))
        print(f"packed {m.name} {m.version} -> {args.output}")
        return 0
    # An app made of programs (a folder with no manifest, or a program with sub-programs):
    # one .kapp per program in the folder OUTPUT, each with only its own permissions.
    out = Path(args.output)
    if out.suffix == ".kapp":
        raise KAppError(f"{src} is made of programs: give -o a folder, one .kapp is written per program")
    for m in pack_tree(src, out):
        perms = ", ".join(m.permissions) or "none"
        print(f"packed {m.name} {m.version} -> {out / (m.name + '.kapp')}   permissions: {perms}")
    if not (src / MANIFEST).is_file():
        print(f"{src.name} itself is not a program and has no permissions; install and permit each program")
    return 0


def cmd_install(args, paths: Paths) -> int:
    authority, _ = _authority(paths)
    src = Path(args.file)
    # A folder of programs (what `kos pack` wrote): each one is installed on its own, scanned and
    # sealed on its own, and asks for the password on its own.
    files = sorted(src.glob("*.kapp")) if src.is_dir() else [src]
    if not files:
        raise KAppError(f"no .kapp files in {src}")
    for f in files:
        m = AppStore(paths).install(f, authority)
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
    from .system import list_apps
    _view(paths, "apps")
    apps = AppStore(paths).installed()
    if not apps:
        print("no apps installed")
    kinds = {r["name"]: r for r in list_apps(paths)}
    for a in apps:
        row = kinds.get(a.name, {})
        tag = f"  [{row['kind']} of {row['extends']}]" if row.get("kind", "app") != "app" else ""
        if "." in a.name:       # a program: show what IT may do, which is all that matters
            tag += f"  [program of {a.name.rpartition('.')[0]}; permissions: {', '.join(row.get('permissions', [])) or 'none'}]"
        print(f"{a.name:20} {a.version:10} sha256:{a.sha256[:16]}{tag}")
    return 0


def _parse_run_target(words: list[str]) -> tuple[str, str]:
    if len(words) == 1:
        return "tui", words[0]
    if len(words) == 2 and words[0] in ("graphical", "cmd"):
        return words[0], words[1]
    raise KAppError("usage: run [graphical|cmd] APP")


def _address_and_mode(explicit: str | None, text: str):
    """An app name or a kos:// address, and the mode: a word you typed (graphical, cmd) wins,
    the address's ?mode= comes next, tui last. Saying two different modes is an error."""
    from .address import AddressError, parse
    addr = parse(text)
    if explicit and addr.mode and explicit != addr.mode:
        raise AddressError(f"you said {explicit} but the address says mode={addr.mode}")
    return addr, explicit or addr.mode or "tui"


def _lazy_authority(paths: Paths):
    """(get, made): ``get()`` builds the authority - which opens the terminal - the first time it
    is called. The layers only call it once they reach the kernel layer, so an app that is not
    permitted is refused without ever touching a terminal. ``made['a']`` is (authority, prompter)."""
    made: dict = {}

    def get():
        if "a" not in made:
            made["a"] = _authority(paths)
        return made["a"][0]
    return get, made


def cmd_run(args, paths: Paths) -> int:
    from . import cache, layers
    from .protocol import Channel
    explicit, target = _parse_run_target(args.target)
    addr, mode = _address_and_mode(None if explicit == "tui" else explicit, target)
    name = addr.app
    # gui -> app -> kernel (layers.py). An app with no permit stops at "app": no terminal, no password.
    get, made = _lazy_authority(paths)
    passage = layers.traverse(paths, get, layers.Request("run", name, mode, sandbox_prompt=not args.cell))
    app, policy = passage.app, passage.policy
    authority, prompter = made["a"]
    paths.ensure()
    from .appdirs import AppDirs
    log_path = AppDirs(paths, name).ensure().run / f"{name}.log"
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
        proc = loader.launch(loader.plan(app, child.fileno(), mode, cache_dir, addr.launch),
                             policy, log_path)
        child.close()
    prompter.close()
    try:
        bridge = _bridge_for(paths, name, app.manifest.permissions)
        bridge = bridge_for(paths, name, app.manifest.permissions)
        vault = _vault_for(paths, name, app.manifest.permissions) if not args.cell else None
        code = _run_session(name, mode, Channel(sock), proc, authority, open(log_path, "a"),
                            bridge=bridge, vault=vault, extensions=_extensions_for(paths, name),
                            status_ok=_may_status(app.manifest.permissions))
    finally:
        if cache_dir is not None:
            cache.wipe(cache_dir)
    print(f"{name} exited ({code})")
    return code


def _may_status(permissions) -> bool:
    """May this app ask the OS how its mouse, keyboard and screen stand? From the verified manifest."""
    return "system" in permissions or "ask:status" in permissions


def _bridge_for(paths: Paths, name: str, permissions):
    """The bridge an app gets: only if its manifest has 'system' or 'ai', and only for those powers."""
    perms = {p for p in permissions if p in ("system", "ai")}
    return SystemBridge(paths, app=name, permissions=perms) if perms else None


def cmd_open(args, paths: Paths) -> int:
    """Launch an app in the background. Returns your shell immediately;
    `kos ps` lists it, `kos attach ID` connects your terminal to it. NAME may be an address
    (``kos://web/page``): the app is opened and told the path."""
    addr, mode = _address_and_mode(args.mode, args.name)
    get, made = _lazy_authority(paths)
    inst = open_background(paths, get, addr.app, mode, address=addr.launch,
                           release=lambda: made["a"][1].close())
    print(f"opened {addr.app} [{mode}] as {inst.id}" + (f" at {addr.launch}" if addr.launch else ""))
    print(f"  kos attach {inst.id}   (or: kos boot desktop)")
    return 0


def cmd_go(args, paths: Paths) -> int:
    """`kos go kos://web/page` - the address bar. The same as `kos open`, any address."""
    import argparse as _a
    return cmd_open(_a.Namespace(mode=None, name=args.address), paths)

def cmd_ps(args, paths: Paths) -> int:
    from .registry import Registry
    _view(paths, "open apps")
    insts = Registry(paths).list()
    if not insts:
        print("no apps open")
    for i in insts:
        print(f"{i.id:24} {i.name:14} {i.mode:9} {i.status:9} pid={i.app_pid or '-'}")
    return 0


def _attach_session(paths: Paths, authority: Authority, inst, **session_kwargs) -> int:
    """Connect this terminal to an app already running under a broker."""
    from .protocol import Channel

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(inst.sock_path)
    except OSError as e:
        raise KAppError(f"could not attach to {inst.id}: {e}") from None
    log = open(inst.log_path, "a") if os.path.exists(inst.log_path) else None
    # what the bridge allows was recorded by the OS at open time, from the verified manifest
    bridge = bridge_for(paths, inst.name, ["system"] if inst.system else [f"ask:{a}" for a in inst.asks])
    perms = ()
    try:
        perms = KApp.from_file(paths.apps / f"{inst.name}.kapp").manifest.permissions
    except (KAppError, OSError):
        pass
    # 'system' was recorded by the OS at open time; the manifest (sealed, checked at launch) adds 'ai'
    bridge = _bridge_for(paths, inst.name, set(perms) | ({"system"} if inst.system else set()))
    return _run_session(inst.name, inst.mode, Channel(sock), None, authority, log,
                        detach_on_interrupt=True, bridge=bridge,
                        vault=_vault_for(paths, inst.name, perms),
                        extensions=_extensions_for(paths, inst.name),
                        status_ok=inst.system or _may_status(perms), **session_kwargs)


def cmd_attach(args, paths: Paths) -> int:
    """Connect your terminal to an app already opened with `kos open`. No
    new password is needed just to reconnect - it was already authorized
    when it was opened - but every device still has to be booted again for
    this terminal, with the password, same as any other session."""
    from . import layers

    get, made = _lazy_authority(paths)
    inst = layers.traverse(paths, get, layers.Request("focus", args.id)).instance
    authority, prompter = made["a"] if "a" in made else _authority(paths)
    prompter.close()
    code = _attach_session(paths, authority, inst)
    print(f"detached from {inst.id}" if code == 0 else f"{inst.id} exited ({code})")
    return 0


def cmd_close(args, paths: Paths) -> int:
    authority, _ = _authority(paths)
    inst = close_instance(paths, authority, args.id)
    print(f"closed {inst.id}")
    return 0


def _ensure_open(paths: Paths, name: str, mode: str) -> str:
    """The instance id of a running ``name``; opens it (password) if it isn't."""
    from .registry import Registry
    for inst in Registry(paths).list():
        if inst.name == name and inst.mode == mode and inst.status == "running":
            return inst.id
    if name not in {a.name for a in AppStore(paths).installed()}:
        raise KAppError(f"{name} is not installed (run: kos desktop install)")
    authority, prompter = _authority(paths)
    return open_background(paths, authority, name, mode, release=prompter.close).id


def cmd_boot(args, paths: Paths) -> int:
    """`kos boot desktop`: the desktop is just two apps - the taskbar and the
    App Library - and a way of moving between running apps (kos/desktop.py).
    There is no windowing system; the taskbar *is* the home screen."""
    if args.what != "desktop":
        raise KAppError("usage: kos boot desktop")
    from .desktop import Desktop, DesktopError
    from .registry import Registry

    mode = "graphical" if args.graphical else "tui"
    authority, prompter = _authority(paths)
    authority.authorize("device.desktop").close()
    prompter.close()
    home = _ensure_open(paths, "taskbar", mode)
    library = _ensure_open(paths, "app-library", mode)

    def attach(instance_id: str, ctx: dict) -> dict:
        from . import layers
        authority, prompter = _authority(paths)
        inst = layers.traverse(paths, authority, layers.Request("focus", instance_id)).instance
        prompter.close()
        outcome: dict = {}
        _attach_session(paths, authority, inst, outcome=outcome,
                        preboot=tuple(ctx["preboot"]), right_click_to=ctx["right_click_to"])
        return outcome

    try:
        return Desktop(home, library, attach).run()
    except DesktopError as e:
        raise KAppError(str(e)) from None


def cmd_desktop(args, paths: Paths) -> int:
    """`kos desktop install`: pack, scan, install and permit the two apps the
    desktop is made of. Same gates as any other app: each install is scanned
    first and asks for the password; permitting asks once more."""
    import tempfile
    from .desktop import FUNCTION_APPS, SYSTEM_APPS
    every = SYSTEM_APPS + FUNCTION_APPS
    from .permit import PermitStore

    src = Path(args.src) if args.src else Path(loader.SDK_DIR) / "apps"
    authority, _ = _authority(paths)
    store, have = AppStore(paths), {a.name for a in AppStore(paths).installed()}
    with tempfile.TemporaryDirectory() as tmp:
        for name in every:
            if name in have:
                print(f"{name}: already installed")
                continue
            kapp = Path(tmp) / f"{name}.kapp"
            pack(src / name, kapp)
            m = store.install(kapp, authority)
            print(f"installed {m.name} {m.version}")
    permits = PermitStore(paths)
    need = [n for n in every if not permits.is_permitted(n)]
    if need:
        with authority.authorize("app.permit", " ".join(need)):
            for n in need:
                permits.grant(n)
        print(f"permitted: {', '.join(need)}")
    print("desktop ready: kos boot desktop   (or just say: desktop)")
    return 0


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
    from .protocol import escape_text
    vfs, last = _resolve_mixed(args.path)
    vfs.cd(last)
    for e in vfs.list():
        tag = "/" if e.is_dir else (" (zip)" if e.is_archive else "")
        print(f"{escape_text(e.name)}{tag}")
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
    from .protocol import clean_text, escape_text
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
                    print(f"{escape_text(e.name)}{tag}")
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
    _view(paths, "activity")
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


def _extensions_for(paths: Paths, name: str) -> dict:
    """What extensions (or mods) the owner switched on for this app: told to it after hello."""
    from .extensions import Extensions
    return Extensions(paths).payload(name)


def _vault_for(paths: Paths, name: str, permissions):
    from .spaces import AppStorage
    st = AppStorage(paths, name, permissions)
    return st if st.usable() else None


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


def cmd_extend(args, paths: Paths) -> int:
    """`kos extend NAME`: switch an extension (for an ordinary app) or a mod (for a system app) on.
    The add-on is itself an app - it must be installed and permitted - and goes through the layers
    like everything else; the password pins the exact build you approved."""
    from . import layers
    from .extensions import Extensions
    ext = Extensions(paths)
    if args.list:
        rows = ext.enabled()
        if not rows:
            print("no extensions or mods are switched on")
        for e in rows:
            print(f"{e['app']:20} {e['resource']:24} pinned {e.get('pin', '-')[:12]}")
        return 0
    if not args.name:
        raise KAppError("usage: kos extend NAME | kos extend --revoke NAME | kos extend --list")
    get, made = _lazy_authority(paths)
    if args.revoke:
        layers.traverse(paths, get, layers.Request("unextend", args.name))
        print(f"switched off {args.name}" if ext.disable(args.name) else f"{args.name} was not switched on")
        return 0
    passage = layers.traverse(paths, get, layers.Request("extend", args.name))
    resource = ext.enable(passage.app)
    host = resource.split(":", 1)[1]
    what = "modifies" if passage.app.manifest.kind == "mod" else "extends"
    print(f"{args.name} now {what} {host} ({resource}); it takes effect the next time {host} starts")
    return 0


def cmd_overlay(args, paths: Paths) -> int:
    """Mod file layers. The base is empty here: KOS has no core file set yet (see the README gaps),
    so this merges mods only. Nothing is written but the load order, and that needs the password."""
    from .overlay import BASE, Layer, OverlayConfig, OverlayError
    from .protocol import escape_text
    cfg = OverlayConfig(paths)
    authority, _ = _authority(paths)
    try:
        if args.ovact == "order":
            rules = {}
            for r in args.rule or []:
                prefix, _, names = r.partition("=")
                rules[prefix] = [n for n in names.split(",") if n]
            doc = cfg.save(authority, args.mods, rules)
            print("load order (last wins): " + (" < ".join(e["name"] for e in doc["order"]) or "(none)"))
            return 0
        with authority.authorize("overlay.view"):
            ov, skipped = cfg.build(Layer(BASE, {}))
        for s in skipped:
            eprint(f"  skipped {escape_text(s['name'], 40)}: {escape_text(s['why'], 100)}")
        if args.ovact == "show":
            folder = (args.folder or "").rstrip("/")
            prefix = folder + "/" if folder else ""
            names = ov.files() if args.deep else ov.listdir(folder)
            for name in names:
                if name.endswith("/"):
                    print(f"  {escape_text(name, 240)}")
                    continue
                r = ov.resolve(name if args.deep else prefix + name)
                print(f"  {escape_text(name, 240):40} {r.provider}"
                      + (f"  (hides {', '.join(r.shadowed)})" if r.shadowed else ""))
            return 0
        found = ov.conflicts()
        for c in found:
            print(f"  {escape_text(c.path, 240)}: {c.winner or 'deleted'} wins over {', '.join(c.losers)}"
                  + ("  (same bytes)" if c.identical else ""))
        print(f"{len(found)} conflict(s)")
        return 0
    except OverlayError as e:
        raise KAppError(str(e)) from None
def _refuse_group(paths: Paths, name: str) -> None:
    """An app made of programs has no permissions, so there is nothing to permit on it: say which
    programs it is made of instead of failing with "no such file"."""
    if (paths.apps / f"{name}.kapp").exists():
        return
    parts = sorted(a.name for a in AppStore(paths).installed() if a.name.startswith(name + "."))
    if parts:
        raise KAppError(f"{name} is an app made of programs and has no permission of its own. "
                        f"Permit a program: {', '.join(parts)}")


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
    if not args.revoke:
        _refuse_group(paths, args.name)       # before any password: there is nothing to approve
    authority, _ = _authority(paths)
    action = "app.revoke" if args.revoke else "app.permit"
    with authority.authorize(action, args.name):
        if args.revoke:
            PermitStore(paths).revoke(args.name)
            print(f"revoked: {args.name} may no longer run")
        else:
            declared = KApp.from_file(paths.apps / f"{args.name}.kapp").manifest.permissions
            PermitStore(paths).grant(args.name, declared)
            print(f"permitted: {args.name} may now run (still asks for your password every time)")
            if declared:
                print(f"  approved permissions: {', '.join(declared)}  (an update asking for more is refused until you permit again)")
    return 0


def cmd_grant(args, paths: Paths) -> int:
    """`kos grant APP space:NAME [--level read|write]` lets an app that *uses* a shared folder in.
    Everyone holding a grant of at least the level asked for may do it - that is the whole rule."""
    from .permissions import LEVELS, Permissions
    if args.list or not args.app:
        entries = Permissions(paths).list("space:")
        if not entries:
            print("no shared-folder access granted yet")
        for e in sorted(entries, key=lambda e: (e["resource"], e["app"])):
            print(f"{e['resource']:24} {e['app']:24} {e['level']}")
        return 0
    if not args.resource or not args.resource.startswith("space:"):
        raise KAppError("usage: kos grant APP space:NAME [--level read|write]   |   kos grant --list")
    if args.level not in ("read", "write"):
        raise KAppError("--level must be read or write (only the app that creates a space owns it)")
    authority, _ = _authority(paths)
    with authority.authorize("space.revoke" if args.revoke else "space.grant", f"{args.app}:{args.resource}"):
        if args.revoke:
            n = Permissions(paths).revoke(args.app, args.resource)
            print(f"revoked {args.app} from {args.resource}" if n else "nothing to revoke")
        else:
            if Permissions(paths).get(args.app, args.resource) and \
                    Permissions(paths).get(args.app, args.resource)["level"] == "own":
                raise KAppError(f"{args.app} owns {args.resource}")
            Permissions(paths).grant(args.app, args.resource, args.level)
            print(f"{args.app} may now {args.level} {args.resource}")
    return 0


def cmd_spaces(args, paths: Paths) -> int:
    """Shared folders: who created each one and who else is let in."""
    from .permissions import Permissions
    entries = Permissions(paths).list("space:")
    names = sorted({e["resource"] for e in entries})
    if not names:
        print("no shared folders yet (an app with 'owns:NAME' creates one the first time it uses it)")
    for r in names:
        owner = next((e["app"] for e in entries if e["resource"] == r and e["level"] == "own"), "(none)")
        others = ", ".join(f"{e['app']}({e['level']})" for e in entries if e["resource"] == r and e["level"] != "own") or "nobody else"
        n = len(list((paths.state / "spaces" / r[6:]).glob("*"))) if (paths.state / "spaces" / r[6:]).is_dir() else 0
        print(f"{r[6:]:20} owner {owner:20} items {n:<4} access: {others}")
    return 0


def cmd_dirs(args, paths: Paths) -> int:
    """Where an app's stuff lives: cache (wiped), data (kept), run (live state)."""
    from .appdirs import AppDirs
    d = AppDirs(paths, args.name)
    for label, p, note in (("cache", d.cache, "scratch, wiped when the app ends"), ("data", d.data, "private user data, kept"),
                           ("run", d.run, "running instances: record, socket, log")):
        n = len(list(p.glob("*"))) if p.is_dir() else 0
        print(f"{label:6} {p}  [{n} entries]  {note}")
    print(f"perms  {paths.state / 'permissions' / 'grants.json'}  universal, for every app")
    return 0


def cmd_aios(args, paths: Paths) -> int:
    """AI OS: `kos aios status` lists the four layers; `kos aios gui|app|kernel|skill WORDS...` runs one
    request on a layer. No password: NeuroClaw's own approvals decide what happens."""
    from . import aios
    if args.layer == "status":
        info = aios.status()
        for l in info.get("layers", []):
            print(f"{'ok ' if l.get('available') else 'no '} {l['id']:7} {l['label']}" + (f" ({l['reason']})" if l.get("reason") else ""))
        return 0
    out = aios.run_layer(args.layer, args.words)
    print(out.get("text", ""))
    status = out.get("status")
    return 0 if status == "ran" else 4 if status == "held" else 1


def cmd_ai(args, paths: Paths) -> int:
    """`kos ai set|show|clear`: the one model endpoint the OS may send text to. Every form needs the
    password. Asking the AI is not a command: it is the `ai` app, or any app with the `ai` permission."""
    from . import ai
    if args.what == "set":
        ai.check_endpoint(args.url)                       # refuse a bad address before any prompt
        key = os.environ.get("KOS_AI_KEY", "")         # never on the command line: argv is public
        if not key and not args.url.startswith("http://") and sys.stdin.isatty():
            import getpass
            key = getpass.getpass("API key (hidden): ")
        authority, _ = _authority(paths)
        with authority.authorize("ai.config", "set"):
            ep = ai.save(paths, args.url, args.provider, args.model, key.strip())
        print(f"AI set: {ep.provider} {ep.model} at {ep.host} ({'this computer' if ep.local else 'https'})")
        return 0
    authority, _ = _authority(paths)
    if args.what == "clear":
        with authority.authorize("ai.config", "clear"):
            print("AI removed" if ai.clear(paths) else "no AI was set up")
        return 0
    with authority.authorize("ai.config", "show"):
        ep = ai.load(paths)
    print(f"{ep.provider} {ep.model} at {ep.url} (key {'set' if ep.key else 'none'})")
    return 0


def cmd_scan(args, paths: Paths) -> int:
    """`kos scan file PATH` checks one file or zip right now, no password
    needed (it's read-only, like `kos list`). `kos scan watch DIR...` is
    different: starting it needs the password, the same as starting a
    kernel cell, because from that point on it keeps running and acting -
    scanning every file written under those directories - until you stop
    it."""
    from .scan import scan_file

    if args.scan_cmd == "watch":
        from .watch import ScanHit, run_watch
        for d in args.dirs:
            if not os.path.isdir(d):
                raise KAppError(f"not a directory: {d}")
        authority, prompter = _authority(paths)
        authority.authorize("scan.watch", ", ".join(args.dirs)).close()
        prompter.close()
        print(f"watching {', '.join(args.dirs)} - every file written here is scanned. "
              "Ctrl-C to stop.")

        def on_hit(hit: "ScanHit") -> None:
            print(f"\x1b[1;31mFLAGGED\x1b[0m {hit.path}: {hit.result.summary()}")

        def on_scan(path: str) -> None:
            print(f"scanned: {path}")

        try:
            run_watch(args.dirs, on_hit, lambda: False, on_scan=on_scan)
        except KeyboardInterrupt:
            print("\nstopped")
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


def cmd_cell(args, paths: Paths) -> int:
    from .cells import CellManager, CellSpec
    mgr = CellManager(paths)
    if args.cell_cmd == "list":
        _view(paths, "cells")
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


def cmd_usb(args, paths: Paths) -> int:
    from . import usb
    return usb.cmd_usb(args, paths)


def cmd_doctor(args, paths: Paths) -> int:
    r = report()
    ok = lambda b: "yes" if b else "NO"
    print(f"Landlock ABI          : {r['landlock_abi'] or 'NOT AVAILABLE (apps will refuse to run)'}")
    print(f"seccomp filter (apps) : {ok(r['seccomp_filter'])}" if r["seccomp_filter"]
          else "seccomp filter (apps) : not built for this CPU architecture (Landlock + namespaces still apply)")
    print(f"user namespaces       : {ok(r['user_namespaces'])}")
    print(f"KVM (kernel cells)    : {ok(r['kvm'])}")
    print(f"vhost-vsock (cells)   : {ok(r['vhost_vsock'])}")
    print(f"framebuffer /dev/fb0  : {ok(r['framebuffer'])}")
    print(f"evdev /dev/input      : {ok(r['evdev'])}")
    from . import firmware
    fw = firmware.probe()
    running = ", ".join(f.name for f in fw.blocking)
    print(f"firmware control      : {'NO - ' + running + ' running' if running else 'yes'}")
    print(f"password configured   : {ok(PasswordStore(paths).exists())}")
    return 0


def cmd_firmware(args, paths: Paths) -> int:
    """Read-only: what management processors are visible and what the boot
    gate would do. Needs no password and changes nothing."""
    from . import firmware
    v = firmware.probe()
    print(f"policy: kos.firmware={v.policy}")
    print("\n".join(v.lines()))
    print("boot: " + ("allowed" if v.ok else "REFUSED - " + (v.reason() or "")))
    if getattr(args, "fw_cmd", None) == "plan":
        print("\n" + firmware.platform_firmware())
        items = firmware.plan(verdict=v)
        for i in items:
            print(f"\n- {i.name} [{i.state}] open replacement: {i.open_replacement}\n    {i.advice}")
        print("\n" + firmware.plan_summary(items))
        print("\nThis plan is read-only. KOS never writes to a chip; flashing is an offline job.")
        return 0 if v.ok else 1
    print("\nwhat the chips we cannot remove can still see:")
    for name, status, note in firmware.protections():
        print(f"  {name:24} {status}\n      {note}")
    return 0 if v.ok else 1


def cmd_audit(args, paths: Paths) -> int:
    import time
    from .auth import AuditLog
    from .protocol import escape_text
    log = AuditLog(paths)
    if args.verify:
        return _audit_verify(log, paths)
    _view(paths, "audit log")
    for e in log.tail(args.n):
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["t"]))
        # targets can hold names that came from disks and zips: print them escaped
        print(f"{t}  {escape_text(e['outcome']):13} {escape_text(e['action']):15} {escape_text(e['target'])}")
    return 0


def cmd_security(args, paths: Paths) -> int:
    """`kos security`: every check KOS can run on itself without your password."""
    from .secure import FAIL, render, run_checks
    checks = run_checks(paths)
    print(render(checks))
    return 3 if any(c.level == FAIL for c in checks) else 0


def _audit_verify(log, paths: Paths) -> int:
    """`kos audit --verify`: check the hash chain, and with the password every anchor."""
    from .auth import AUDIT_KEY_LABEL
    authority, _ = _authority(paths)
    with authority.authorize("audit.verify") as grant:
        rep = log.verify(grant.key(AUDIT_KEY_LABEL))
    print(f"{rep.entries} line(s): {rep.chained} chained, {rep.anchored} anchored to your password, "
          f"{rep.legacy} older unprotected")
    if rep.trimmed:
        print("note: older lines were trimmed by 'kos optimize'; the chain is checked from the first one left")
    if not rep.ok:
        print(f"TAMPERED at line {rep.bad_line}: {rep.problem}")
        return 3
    print("intact: no line was edited, deleted or reordered, and every anchor matches your password")
    print("(a log cut short at the very end cannot be detected - nothing else remembers its length)")
    return 0


def cmd_admin(args, paths: Paths) -> int:
    """The elevated administrator keyboard. It is booted by the password you
    type to unlock (see kos/init.py); `admin boot` boots it again with the
    password if the lease ran out. `admin lock` drops it - taking privilege
    away never needs a password."""
    from .admin import AdminKeyboard
    kb = AdminKeyboard(paths)
    action = args.admin_cmd or "status"
    if action == "status":
        print(kb.status())
        return 0
    if action == "lock":
        kb.shutdown()
        print("administrator keyboard locked")
        return 0
    authority, prompter = _authority(paths)
    with authority.authorize("admin.boot") as grant:
        lease = kb.boot(grant)
    prompter.close()
    print(kb.status())
    if lease.weak:
        eprint("WARNING: KOS_DEV_ADMIN_WEAK=1 - not on the KOS kernel; keyboard is not exclusive.")
    return 0


def cmd_owed(args, paths: Paths) -> int:
    from .requires import Ledger
    _view(paths, "owed work")
    owed = Ledger(paths).owed()
    if not owed:
        print("nothing is owed")
    for e in owed:
        print(f"{e['target']}  ({e['trigger']}) still owes: {', '.join(e['pending'])}")
    return 0


def cmd_settle(args, paths: Paths) -> int:
    """Do what earlier writes still owe: the security scan and the disk optimize."""
    from .admin import settle
    authority, prompter = _authority(paths)
    for line in settle(paths, authority):
        print(line)
    prompter.close()
    return 0


def cmd_write(args, paths: Paths) -> int:
    """Write a file. Needs the booted administrator keyboard, the password
    typed on it, a clean security scan, and a disk optimize - in that order."""
    from .admin import (AdminKeyboard, AdminPrompter, open_admin_devices, write_file)
    kb = AdminKeyboard(paths)
    if args.text is not None and args.stdin:
        raise KAppError("give the text with --text or --stdin, not both")
    if args.text is None and not args.stdin:
        raise KAppError("nothing to write: write FILE TEXT  (or --stdin)")
    data = (sys.stdin.buffer.read() if args.stdin else args.text.encode())
    lease = kb.require_booted()          # refuse before any password prompt
    devices = open_admin_devices(lease)  # exclusive keyboards, or None on a WEAK lease
    try:
        prompter = AdminPrompter(devices) if devices is not None else TTYPrompter()
        report = write_file(paths, Authority(paths, prompter), kb, args.path, data)
    finally:
        if devices is not None:
            devices.close()
    print(report.summary())
    return 0


def cmd_backup(args, paths: Paths) -> int:
    """Deduplicated backups. Every action asks for the password; a restore is a
    guarded write (admin keyboard, scan, optimize) and asks again for that."""
    from . import backup
    from .summary import SummaryStore
    authority, prompter = _authority(paths)
    action = args.bkact or "list"
    if action == "add":
        report = backup.add(paths, authority, args.paths)
        for it in report.stored:
            print(f"  {it.id}  {it.size:>10,}  {it.path}")
        for path, rules in report.flagged:
            eprint(f"  FLAGGED (not stored) {path}: {rules}")
        for path, why in report.skipped:
            eprint(f"  skipped {path}: {why}")
        print(report.summary())
        return 3 if report.flagged else 0
    if action == "list":
        items, stats = backup.snapshot(paths, authority)
        for it in items:
            print(f"  {it.id}  {it.size:>10,}  {it.sha256[:12]}  {it.path}")
            note = SummaryStore(paths).get(it.sha256)
            if note:
                print(f"      {note}")
        print(stats.summary())
        return 0
    if action == "remove":
        item, gone = backup.remove(paths, authority, args.id)
        print(f"removed {item.id} ({item.path}); " + ("its body was deleted" if gone
              else "its body is still used by another item"))
        return 0
    if action == "restore":
        from .admin import AdminKeyboard, AdminPrompter, open_admin_devices
        kb = AdminKeyboard(paths)
        lease = kb.require_booted()              # refuse before any password prompt
        devices = open_admin_devices(lease)
        try:
            writer = Authority(paths, AdminPrompter(devices) if devices is not None
                               else TTYPrompter())
            item, report = backup.restore(paths, authority, writer, kb, args.id, args.dest)
        finally:
            if devices is not None:
                devices.close()
        print(f"restored {item.id} -> {report.summary()}")
        return 0
    if action in ("link", "links", "unlink", "fetch"):
        return _cmd_applinks(args, paths, authority, action)
    raise KAppError(f"unknown backup action {action!r}")


def _cmd_applinks(args, paths: Paths, authority, action: str) -> int:
    """Apps backed up as an address and a hash. Fetching only downloads and verifies; the install
    that follows scans the app and asks for the password again."""
    import tempfile
    from . import applinks
    if action == "link":
        link = applinks.add(paths, authority, args.app, args.url)
        print(f"linked {link.name} {link.version} -> {link.url}")
        print(f"  pinned sha256 {link.sha256[:16]}...; {link.size:,} bytes are not stored")
        return 0
    if action == "links":
        links = applinks.snapshot(paths, authority)
        for l in links:
            print(f"  {l.name:20} {l.version:10} {l.sha256[:12]}  {l.size:>12,}  {l.url}")
        print(applinks.stats(links))
        return 0
    if action == "unlink":
        link = applinks.remove(paths, authority, args.app)
        print(f"forgot the link for {link.name} (the installed app is untouched)")
        return 0
    link, data = applinks.fetch(paths, authority, args.app)
    print(f"downloaded {link.name} {link.version} from {link.host}: sha256 matches")
    paths.ensure()
    with tempfile.TemporaryDirectory(dir=paths.state) as tmp:
        src = Path(tmp) / f"{link.name}.kapp"
        src.write_bytes(data)
        store = AppStore(paths)
        if any(a.name == link.name for a in store.installed()):
            raise KAppError(f"{link.name} is already installed; remove it first (kos remove {link.name})")
        m = store.install(src, authority)
    print(f"installed {m.name} {m.version} - kept zipped, sealed")
    return 0


def cmd_folders(args, paths: Paths) -> int:
    """The standard data folders: one permissioned shared folder per kind of data."""
    from . import folders
    if args.folders_cmd == "create":
        authority, _ = _authority(paths)
        created, kept = folders.create(paths, authority)
        print(f"created {len(created)} folder(s); {len(kept)} already there")
        for n in created:
            print(f"  + {n}")
        return 0
    state = {s.folder.name: s for s in folders.status(paths)}
    for key, title in folders.GROUPS.items():
        print(f"{title}:")
        for f in (f for f in folders.FOLDERS if f.group == key):
            s = state[f.name]
            who = ", ".join(f"{a}({lv})" for a, lv in s.access) or "nobody"
            mark = "sensitive" if f.sensitive else ""
            print(f"  {f.name:18} {'made' if s.exists else 'not made':9} owner {s.owner or '-':8} "
                  f"items {s.items:<4} access: {who:24} {mark}")
    if not any(s.exists for s in state.values()):
        print("none made yet: kos folders create")
    return 0
def cmd_convert(args, paths: Paths) -> int:
    """Convert a Debian .deb into a .kapp. The package is analysed and scanned
    first (a bad or unconvertible one is refused before any password prompt);
    then the password is needed to write the result. Nothing is installed."""
    from .debconv import MAX_DEB, DebError, convert
    src, out = Path(args.file), Path(args.output)
    if os.path.lexists(out):
        raise KAppError(f"{out} already exists; refusing to overwrite it")
    with open(src, "rb") as f:
        data = f.read(MAX_DEB + 1)
    try:
        kapp, report = convert(data, args.exe)
    except DebError as e:
        raise KAppError(str(e)) from None
    authority, prompter = _authority(paths)
    authority.authorize("app.convert", report.kapp_name).close()
    prompter.close()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(kapp)
    print(report.summary())
    print(f"wrote {out}. Next: kos install {out}   (scans again, asks for the password, seals)")
    return 0


def cmd_skills(args, paths: Paths) -> int:
    """Make agent skills from the installed apps and the commands. One password
    (``skill.make``) verifies every app's seal. Printing writes nothing; with
    --out, each SKILL.md is a guarded write (admin keyboard, scan, optimize)."""
    from .skillmaker import collect_apps, command_inventory, make_skills
    authority, prompter = _authority(paths)
    helps: dict = {}
    manifests, skipped = collect_apps(paths, authority, helps)
    prompter.close()
    files, refused = make_skills(command_inventory(build_parser()), manifests, helps)
    for line in skipped + refused:
        print(line, file=sys.stderr)
    if not args.out:
        for rel, text in files.items():
            print(f"=== {rel}\n{text}")
        return 0
    from .admin import AdminKeyboard, AdminPrompter, open_admin_devices, write_file
    out = Path(os.path.abspath(args.out))
    if not out.is_dir() or out.is_symlink():
        raise KAppError(f"{out} must be an existing directory (not a symlink)")
    kb = AdminKeyboard(paths)
    lease = kb.require_booted()          # refuse before any password prompt
    devices = open_admin_devices(lease)
    try:
        wprompter = AdminPrompter(devices) if devices is not None else TTYPrompter()
        wauth = Authority(paths, wprompter)
        for rel, text in files.items():
            target = out / rel
            target.parent.mkdir(exist_ok=True)   # an empty directory; the content is a guarded write
            print(write_file(paths, wauth, kb, str(target), text.encode()).summary())
    finally:
        if devices is not None:
            devices.close()
    return 0


def _execute_line(argv: list[str]) -> int:
    """Run one interpreted command in-process. argparse exits on bad usage;
    in the line shell that must not end the shell."""
    try:
        return main(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2


def cmd_do(args, paths: Paths) -> int:
    """Interpret one line of human language and run it as exactly one command."""
    from .lang import HELP, interpret
    line = interpret(" ".join(args.words))
    if args.explain:
        print(line.explain())
    if line.kind in ("command", "code"):
        return _execute_line(list(line.argv))
    if line.kind == "help":
        print(HELP)
        return 0
    if line.kind == "unknown":
        eprint("I don't know that command." + (f" Did you mean '{line.hint}'?" if line.hint else ""))
        return 65
    return 0


def cmd_exec(args, paths: Paths) -> int:
    """A line of code is a command: run it as a sandboxed one-shot app."""
    from .coderun import run_code
    opened = []

    def get_authority() -> Authority:        # only asked for when there is something to run
        authority, prompter = _authority(paths)
        opened.append(prompter)
        return authority

    try:
        return run_code(paths, get_authority, args.code, args.lang)
    finally:
        for prompter in opened:
            prompter.close()


def cmd_runtimes(args, paths: Paths) -> int:
    """`kos runtimes` lists the languages code can run in; `add` and `remove` change that list.
    All three need the password: a language is a program the OS will start for you."""
    from . import runtimes
    if args.rt_cmd == "add":
        name, real, rargs = runtimes.prepare_add(args.name, args.program, args.arg or runtimes.DEFAULT_ARGS)
        authority, _ = _authority(paths)
        with authority.authorize("runtime.add", f"{name}: {real}"):
            digest = runtimes.add(paths, name, real, rargs)
        print(f"added {name}: {real} (pinned sha256 {digest[:16]}...)")
        return 0
    authority, _ = _authority(paths)
    if args.rt_cmd == "remove":
        with authority.authorize("runtime.remove", args.name):
            ok = runtimes.remove(paths, args.name)
        print(f"removed {args.name}" if ok else f"{args.name} was not added by you")
        return 0 if ok else 1
    authority.authorize("state.view", "languages").close()
    for name, program, state in runtimes.describe(paths):
        print(f"{name:12} {state:28} {program}")
    return 0


def cmd_line(args, paths: Paths) -> int:
    """The line shell. Every line is a command - in any language in the
    lexicon - or it is refused. Code is never run here."""
    from .lang import HELP, run_shell
    if sys.stdin.isatty():
        print("KOS - every line is a command, in your own language. Type 'help'.")
    return run_shell(_execute_line, input, print, explain=args.explain)


def cmd_help(args, paths: Paths) -> int:
    """`kos help` lists every command; `kos help COMMAND` explains one. Read-only, needs no password."""
    sub = next(a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    if args.topic:
        sp = sub.choices.get(args.topic)
        if sp is None:
            eprint(f"no command called {args.topic!r}. Try: kos help")
            return 2
        print(sp.format_help().rstrip())
        return 0
    helps = {a.dest: a.help for a in sub._choices_actions if a.help != argparse.SUPPRESS}
    width = max(map(len, helps)) + 2
    print("kos COMMAND ...   (kos help COMMAND explains one; in the line shell, type 'help')\n")
    for name in sorted(helps):
        print(f"  {name:<{width}}{helps[name]}")
    print("\nHelp inside KOS: the 'KOS Help' and 'Get to Know KOS' apps; press Ctrl-N in any app to search commands and files or talk to its assistant (/help).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kos", description="KOS security layer")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="choose your password")
    s.add_argument("--fast-kdf", action="store_true", help=argparse.SUPPRESS)
    s = sub.add_parser("passwd", help="change your password")
    s.add_argument("--fast-kdf", action="store_true", help=argparse.SUPPRESS)
    s = sub.add_parser("pack", help="build a .kapp from a directory; an app made of programs: -o FOLDER gets one .kapp per program")
    s.add_argument("dir")
    s.add_argument("-o", "--output", required=True)
    s = sub.add_parser("install", help="install a .kapp, or every .kapp in a folder (each asks for the password)")
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
    s = sub.add_parser("go", help="open an address, like a browser's address bar: go kos://NAME[/path][?query]")
    s.add_argument("address")
    s = sub.add_parser("extend", help="switch an extension or a mod on (or --revoke / --list)")
    s.add_argument("name", nargs="?")
    s.add_argument("--revoke", action="store_true", help="switch it off")
    s.add_argument("--list", action="store_true", help="list what is switched on")
    s = sub.add_parser("overlay", help="mod file layers: order | show | conflicts")
    os_ = s.add_subparsers(dest="ovact", required=True)
    o = os_.add_parser("order", help="set the load order (last wins); password")
    o.add_argument("mods", nargs="*")
    o.add_argument("--rule", action="append", metavar="PREFIX/=mod,mod",
                   help="under PREFIX these mods win, last listed first priority")
    o = os_.add_parser("show", help="the merged files and who provides each")
    o.add_argument("folder", nargs="?")
    o.add_argument("--deep", action="store_true", help="list every file, not one folder")
    os_.add_parser("conflicts", help="files more than one mod provides")
    sub.add_parser("ps", help="list apps opened with 'kos open'")
    s = sub.add_parser("attach", help="attach your terminal to an open app")
    s.add_argument("id")
    s = sub.add_parser("close", help="stop an app opened with 'kos open'")
    s.add_argument("id")
    s = sub.add_parser("boot", help="boot the desktop: the taskbar + App Library, made of apps")
    s.add_argument("what", choices=["desktop"])
    s.add_argument("--graphical", action="store_true", help="draw the desktop graphically")
    s = sub.add_parser("desktop", help="set up the desktop apps")
    s.add_argument("desktop_cmd", choices=["install"])
    s.add_argument("--from", dest="src", help="directory holding taskbar/ and app-library/")
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
    s = sub.add_parser("grant", help="let an app into a shared folder (space:NAME), or list who has access")
    s.add_argument("app", nargs="?")
    s.add_argument("resource", nargs="?")
    s.add_argument("--level", default="read", help="read or write (default read)")
    s.add_argument("--revoke", action="store_true")
    s.add_argument("--list", action="store_true")
    sub.add_parser("spaces", help="list shared folders, their owner and who has access")
    s = sub.add_parser("dirs", help="show an app's cache / data / run folders")
    s.add_argument("name")
    s = sub.add_parser("scan", help="scan a file/zip for known-bad patterns, or watch a directory")
    ss = s.add_subparsers(dest="scan_cmd", required=True)
    sf = ss.add_parser("file", help="scan one file or zip right now (no password needed)")
    sf.add_argument("path")
    sw = ss.add_parser("watch", help="scan every file written under these directories until Ctrl-C")
    sw.add_argument("dirs", nargs="+")
    s = sub.add_parser("optimize", help="reclaim disk space: recompress apps, prune dead state")
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
    sub.add_parser("security", help="check everything KOS can verify about itself (no password, read-only)")
    s = sub.add_parser("firmware", help="management processors (Intel ME, AMD PSP, BMC) and the boot gate")
    s.add_argument("fw_cmd", nargs="?", choices=["status", "plan"],
                   help="plan: read-only advice on what each blocking chip would need")
    s = sub.add_parser("audit", help="show the authorization log")
    s.add_argument("-n", type=int, default=30)
    s.add_argument("--verify", action="store_true",
                   help="check the log for tampering (needs your password to check the anchors)")
    s = sub.add_parser("admin", help="the elevated administrator keyboard")
    s.add_argument("admin_cmd", nargs="?", choices=["status", "boot", "lock"])
    sub.add_parser("owed", help="what earlier writes still owe (a scan, an optimize)")
    sub.add_parser("settle", help="do what is owed: security scan + disk optimize")
    s = sub.add_parser("write", help="write a file (admin keyboard, security scan, disk optimize)")
    s.add_argument("path")
    s.add_argument("--text", help="the text to write")
    s.add_argument("--stdin", action="store_true", help="read the content from standard input")
    s = sub.add_parser("backup", help="deduplicated backups: add | list | restore | remove")
    bs = s.add_subparsers(dest="bkact")
    b = bs.add_parser("add", help="back up files or folders (scanned first, stored once per content)")
    b.add_argument("paths", nargs="+")
    bs.add_parser("list", help="what is backed up, and what deduplication saved")
    b = bs.add_parser("restore", help="put one item back in a directory (guarded write, never overwrites)")
    b.add_argument("id")
    b.add_argument("dest")
    b = bs.add_parser("remove", help="forget one item")
    b.add_argument("id")
    b = bs.add_parser("link", help="back up an installed app as its https address + SHA-256 (not its bytes)")
    b.add_argument("app")
    b.add_argument("url")
    bs.add_parser("links", help="the linked apps and the space saved")
    b = bs.add_parser("unlink", help="forget an app link")
    b.add_argument("app")
    b = bs.add_parser("fetch", help="download a linked app, verify its hash, scan and install it")
    b.add_argument("app")
    s = sub.add_parser("folders", help="the standard data folders (create makes them; password)")
    s.add_argument("folders_cmd", nargs="?", choices=["list", "create"], default="list")
    s = sub.add_parser("convert", help="convert a Debian .deb package into a .kapp (static programs only)")
    s.add_argument("file", help="the .deb to convert")
    s.add_argument("-o", "--output", required=True, help="the .kapp to create (must not exist)")
    s.add_argument("--exe", help="which program in the package to run, e.g. usr/bin/hello")
    s = sub.add_parser("skills", help="make agent skills from the installed apps and commands")
    s.add_argument("--out", help="write SKILL.md files into this existing directory (guarded writes)")
    s = sub.add_parser("do", help="run one line of human language as one command")
    s.add_argument("words", nargs="+")
    s.add_argument("--explain", action="store_true", help="show how the line was understood")
    s = sub.add_parser("exec", help="run one line of code as a sandboxed command")
    s.add_argument("--lang", default="python")
    s.add_argument("--code", required=True)
    s = sub.add_parser("runtimes", help="the programming languages code runs in: list | add NAME PROGRAM | remove NAME")
    rs = s.add_subparsers(dest="rt_cmd")
    rs.add_parser("list", help="every language and whether it is ready")
    r = rs.add_parser("add", help="add a language: a trusted program that takes code after a flag (password)")
    r.add_argument("name")
    r.add_argument("program", help="absolute path of the interpreter")
    r.add_argument("--arg", action="append", help="one argument, repeatable; {code} is the line (default: -e {code})")
    r = rs.add_parser("remove", help="remove a language you added (password)")
    r.add_argument("name")
    s = sub.add_parser("usb", help="boot KOS from a USB stick: list | check IMG | write IMG /dev/sdX | test IMG")
    us = s.add_subparsers(dest="usb_cmd", required=True)
    u = us.add_parser("list", help="USB disks it would be willing to write")
    u.add_argument("--all", action="store_true", help="show every disk, not just USB ones")
    u.add_argument("--allow-non-usb", action="store_true")
    u = us.add_parser("check", help="verify an image can boot from removable media")
    u.add_argument("image")
    u = us.add_parser("write", help="write an image to a USB disk, then read it back and compare")
    u.add_argument("image")
    u.add_argument("device", help="whole disk such as /dev/sdb (or a plain file)")
    u.add_argument("--yes", action="store_true", help="skip the type-the-device-name confirmation")
    u.add_argument("--allow-non-usb", action="store_true", help="permit a non-USB disk (still never a mounted one)")
    u.add_argument("--no-verify", action="store_true", help="skip the read-back comparison")
    u = us.add_parser("test", help="boot the image in QEMU attached as a USB stick")
    u.add_argument("image")
    s = sub.add_parser("aios", help="AI OS: button clicker, app commands, kernel commands, skill maker")
    s.add_argument("layer", choices=["status", "gui", "app", "kernel", "skill"])
    s.add_argument("words", nargs="*")
    s = sub.add_parser("ai", help="set up the AI connection: set, show, clear (password)")
    s.add_argument("what", choices=["set", "show", "clear"])
    s.add_argument("--url", default="", help="https://... or http://127.0.0.1:PORT/... (a model on this computer)")
    s.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    s.add_argument("--model", default="")
    s = sub.add_parser("help", help="list the commands, or explain one")
    s.add_argument("topic", nargs="?", help="a command name, e.g. install")
    s = sub.add_parser("line", help="the line shell: every line you type is a command")
    s.add_argument("--explain", action="store_true", help="show how each line was understood")
    return p


COMMANDS = {
    "setup": cmd_setup, "passwd": cmd_passwd, "pack": cmd_pack, "install": cmd_install, "update": cmd_update,
    "view": cmd_view, "remove": cmd_remove, "list": cmd_list, "run": cmd_run, "open": cmd_open, "go": cmd_go,
    "extend": cmd_extend, "overlay": cmd_overlay, "ps": cmd_ps, "attach": cmd_attach, "close": cmd_close, "boot": cmd_boot, "ls": cmd_ls,
    "cat": cmd_cat, "explore": cmd_explore, "activity": cmd_activity, "permit": cmd_permit, "grant": cmd_grant,
    "spaces": cmd_spaces, "dirs": cmd_dirs, "scan": cmd_scan, "optimize": cmd_optimize, "cell": cmd_cell,
    "doctor": cmd_doctor, "firmware": cmd_firmware, "audit": cmd_audit, "security": cmd_security, "do": cmd_do,
    "line": cmd_line, "exec": cmd_exec, "owed": cmd_owed, "settle": cmd_settle, "admin": cmd_admin,
    "write": cmd_write, "skills": cmd_skills, "convert": cmd_convert, "desktop": cmd_desktop, "backup": cmd_backup, "folders": cmd_folders,
    "aios": cmd_aios, "usb": cmd_usb, "help": cmd_help, "ai": cmd_ai,
    "runtimes": cmd_runtimes}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths.from_env()
    try:
        return COMMANDS[args.cmd](args, paths)
    except (TamperedError, VirusFoundError, WriteBlocked, VaultTamperedError) as e:
        eprint(f"\x1b[1;31mSECURITY: {e}\x1b[0m")
        return 3
    except (AuthorizationDenied, AuthError, PermitError, AdminError) as e:
        eprint(f"denied: {e}")
        return 2
    except (KAppError, SandboxError, CellError, RegistryError, VFSError, NoTTY, BackupError,
            AIError, LanguageError, OSError) as e:
        eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        return 130


def run_main() -> int:
    """Entry point for the bare ``run`` command."""
    return main(["run", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
