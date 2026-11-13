"""The KOS command list the search box looks in: (name, one line of help, usage).

Generated from the real command parser by ``python3 -m kos.office.cmdindex --write`` and checked by
tests/test_finder.py, so it cannot quietly drift from ``kos help``. It is a static table because an
app is sandboxed and must not import the command-line program just to list its commands.
Searching it only *shows* a command; nothing here can run one (the password is typed in the shell)."""

COMMANDS = (
# -- begin generated --
    ('activity', 'one feed: open apps + recent password decisions', 'kos activity [-h] [-n N]'),
    ('admin', 'the elevated administrator keyboard', 'kos admin [-h] [{status,boot,lock}]'),
    ('ai', 'set up the AI connection: set, show, clear (password)', 'kos ai [-h] [--url URL] [--provider {openai,anthropic}] [--model MODEL] {set,show,clear}'),
    ('aios', 'AI OS: button clicker, app commands, kernel commands, skill maker', 'kos aios [-h] {status,gui,app,kernel,skill} [words ...]'),
    ('attach', 'attach your terminal to an open app', 'kos attach [-h] id'),
    ('audit', 'show the authorization log', 'kos audit [-h] [-n N] [--verify]'),
    ('backup', 'deduplicated backups: add | list | restore | remove', 'kos backup [-h] {add,list,restore,remove,link,links,unlink,fetch} ...'),
    ('boot', 'boot the desktop: the taskbar + App Library, made of apps', 'kos boot [-h] [--graphical] {desktop}'),
    ('cat', 'view a file, including one inside a zip', 'kos cat [-h] path'),
    ('cell', 'manage parallel kernel cells', 'kos cell [-h] {start,list,stop} ...'),
    ('close', "stop an app opened with 'kos open'", 'kos close [-h] id'),
    ('convert', 'convert a Debian .deb package into a .kapp (static programs only)', 'kos convert [-h] -o OUTPUT [--exe EXE] file'),
    ('desktop', 'set up the desktop apps', 'kos desktop [-h] [--from SRC] {install}'),
    ('dirs', "show an app's cache / data / run folders", 'kos dirs [-h] name'),
    ('do', 'run one line of human language as one command', 'kos do [-h] [--explain] words [words ...]'),
    ('doctor', 'report kernel security features', 'kos doctor [-h]'),
    ('exec', 'run one line of code as a sandboxed command', 'kos exec [-h] [--lang LANG] --code CODE'),
    ('explore', 'interactively cd/ls/cat through real dirs and zips', 'kos explore [-h] [start]'),
    ('extend', 'switch an extension or a mod on (or --revoke / --list)', 'kos extend [-h] [--revoke] [--list] [name]'),
    ('firmware', 'management processors (Intel ME, AMD PSP, BMC) and the boot gate', 'kos firmware [-h] [{status,plan}]'),
    ('folders', 'the standard data folders (create makes them; password)', 'kos folders [-h] [{list,create}]'),
    ('go', "open an address, like a browser's address bar: go kos://NAME[/path][?query]", 'kos go [-h] address'),
    ('grant', 'let an app into a shared folder (space:NAME), or list who has access', 'kos grant [-h] [--level LEVEL] [--revoke] [--list] [app] [resource]'),
    ('hardware', 'map every device and connection into the permission store: scan | show | links', 'kos hardware [-h] [{scan,show,links}] [match]'),
    ('help', 'list the commands, or explain one', 'kos help [-h] [topic]'),
    ('install', 'install a .kapp, or every .kapp in a folder (each asks for the password)', 'kos install [-h] file'),
    ('line', 'the line shell: every line you type is a command', 'kos line [-h] [--explain]'),
    ('list', 'list installed apps', 'kos list [-h]'),
    ('ls', 'list a directory or a zip, without extracting', 'kos ls [-h] path'),
    ('open', 'open an app in the background: open [graphical|cmd] NAME', 'kos open [-h] [{graphical,cmd}] name'),
    ('optimize', 'reclaim disk space: recompress apps, prune dead state', 'kos optimize [-h]'),
    ('overlay', 'mod file layers: order | show | conflicts', 'kos overlay [-h] {order,show,conflicts} ...'),
    ('owed', 'what earlier writes still owe (a scan, an optimize)', 'kos owed [-h]'),
    ('pack', 'build a .kapp from a directory; an app made of programs: -o FOLDER gets one .kapp per program', 'kos pack [-h] -o OUTPUT dir'),
    ('passwd', 'change your password', 'kos passwd [-h]'),
    ('permit', 'give (or revoke) an app permission to run at all', 'kos permit [-h] [--revoke] [--list] [name]'),
    ('ps', "list apps opened with 'kos open'", 'kos ps [-h]'),
    ('remove', 'remove an app', 'kos remove [-h] name'),
    ('run', 'run an app: run [graphical|cmd] NAME', 'kos run [-h] [--cell CELL] target [target ...]'),
    ('runtimes', 'the programming languages code runs in: list | add NAME PROGRAM | remove NAME', 'kos runtimes [-h] {list,add,remove} ...'),
    ('scan', 'scan a file/zip for known-bad patterns, or watch a directory', 'kos scan [-h] {file,watch} ...'),
    ('security', 'check everything KOS can verify about itself (no password, read-only)', 'kos security [-h]'),
    ('settle', 'do what is owed: security scan + disk optimize', 'kos settle [-h]'),
    ('setup', 'choose your password', 'kos setup [-h]'),
    ('skills', 'make agent skills from the installed apps and commands', 'kos skills [-h] [--out OUT]'),
    ('spaces', 'list shared folders, their owner and who has access', 'kos spaces [-h]'),
    ('update', 'update an app (or all of them): update APP.kapp | update all --from DIR', 'kos update [-h] [--from FROM_DIR] file'),
    ('usb', 'boot KOS from a USB stick: list | check IMG | write IMG /dev/sdX | test IMG', 'kos usb [-h] {list,check,write,test} ...'),
    ('view', 'view a file (asks for the password)', 'kos view [-h] file'),
    ('write', 'write a file (admin keyboard, security scan, disk optimize)', 'kos write [-h] [--text TEXT] [--stdin] path'),
# -- end generated --
)


def _live() -> list:
    import argparse
    import re

    from kos import cli
    sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    helps = {a.dest: a.help for a in sub._choices_actions if a.help != argparse.SUPPRESS}
    one = lambda t: re.sub(r"\s+", " ", t).strip()
    return [(n, one(helps[n]), one(sub.choices[n].format_usage().replace("usage:", "", 1))) for n in sorted(helps)]


if __name__ == "__main__":
    import sys
    from pathlib import Path
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 -m kos.office.cmdindex --write   (rewrites the table above from the parser)")
    f = Path(__file__)
    text = f.read_text()
    a, b = text.index("# -- begin generated --\n"), text.index("# -- end generated --")
    f.write_text(text[:a] + "# -- begin generated --\n" + "".join("    %r,\n" % (r,) for r in _live()) + text[b:])
