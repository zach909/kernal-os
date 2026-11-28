"""Language runtimes for ``kos exec``: a table, not code.

A language is *data*: which program runs it, the one argument list that hands it
a line of code, and the little it needs to start. Adding or changing a language
means changing a row, never the engine, so the OS core stays small and every
language runs through the same confinement (``coderun.py``: the sandbox, a
scratch directory, a time limit, an output limit).

Three rules keep a row from becoming a hole:

* **The program must be trusted by the filesystem.** It is a regular file, owned
  by root or by you, and neither it nor any directory above it can be changed
  by anyone else. Otherwise it is refused, not run.
* **The argument list cannot be turned into flags.** ``{code}`` is exactly one
  argument, never the first, and always right after a ``-flag`` (``-e``), so
  code that starts with ``-`` is a value, not an option.
* **A language you add is pinned.** ``kos runtimes add`` (password) records the
  program's SHA-256; every run checks it again, so a swapped program is refused.
  A row can never set environment variables, memory or time limits: those come
  from the engine, not from a file anyone with your user id could edit.

Python is not in this table: it runs through the fast path in ``coderun.py``
(the host interpreter in isolated mode, as a one-shot app).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .paths import Paths, atomic_write

NAME_RE = re.compile(r"^[a-z][a-z0-9+-]{0,15}$")
CODE_SLOT = "{code}"
DEFAULT_ARGS = ("-e", CODE_SLOT)
MAX_ARGS = 8
MAX_ARG_LEN = 64
MAX_FILE = 512 << 20            # refuse to hash or pin something larger than this
REGISTRY_FILE = "runtimes.json"

PYTHON_NAMES = {"python", "py", "python3", "assignment", "code call", "comment"}


class LanguageError(Exception):
    """A language row is unusable: untrusted, changed, missing, or malformed."""


@dataclass(frozen=True)
class Spec:
    """What the engine knows about a language before it looks for the program."""
    name: str
    candidates: tuple[str, ...]
    args: tuple[str, ...] = DEFAULT_ARGS
    aliases: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()


# Built-in languages. To support another interpreter that takes code with a flag,
# add a row (or use ``kos runtimes add``); nothing else changes.
BUILTIN: dict[str, Spec] = {s.name: s for s in (
    # OPENSSL_CONF: node reads a config file at start-up that the sandbox rightly hides.
    Spec("javascript", ("node", "nodejs"), aliases=("js", "node", "nodejs"),
         env=(("OPENSSL_CONF", "/dev/null"),)),
    # The disabled features need gem directories the sandbox hides; skipping them also starts faster.
    Spec("ruby", ("ruby",), aliases=("rb",),
         args=("--disable=gems,error_highlight,did_you_mean,syntax_suggest", "-e", CODE_SLOT)),
    Spec("perl", ("perl",), aliases=("pl",)),
    Spec("lua", ("lua", "lua5.4", "lua5.3", "luajit")),
)}

_ALIASES = {a: s.name for s in BUILTIN.values() for a in (s.name, *s.aliases)}


@dataclass(frozen=True)
class Runtime:
    """A language ready to run: a trusted program plus how to call it."""
    name: str
    exe: str
    args: tuple[str, ...]
    read_paths: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    custom: bool = False
    sha256: str = field(default="", repr=False)

    def argv(self, code: str) -> list[str]:
        if "\x00" in code:
            raise LanguageError("code cannot contain a NUL byte")
        return [self.exe, *(code if a == CODE_SLOT else a for a in self.args)]


def canonical(language: str) -> str:
    """The table name for what the line shell or the user called the language."""
    lang = (language or "").strip().lower()
    if lang in PYTHON_NAMES:
        return "python"
    return _ALIASES.get(lang, lang)


# --------------------------------------------------------------------------
# Trust
# --------------------------------------------------------------------------

def _unsafe_mode(st: os.stat_result) -> bool:
    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def check_trusted(path: str) -> str:
    """Return the real path of a program the filesystem lets us trust, or raise."""
    if not os.path.isabs(path):
        raise LanguageError("the program must be given as an absolute path")
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError as e:
        raise LanguageError(f"cannot use {path}: {e.strerror}") from e
    if not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
        raise LanguageError(f"{real} is not an executable file")
    if st.st_uid not in (0, os.geteuid()):
        raise LanguageError(f"{real} belongs to another user")
    if _unsafe_mode(st):
        raise LanguageError(f"{real} can be changed by other users")
    d = os.path.dirname(real)
    while True:
        dst = os.stat(d)
        # A shared directory with the sticky bit (/tmp) is fine: nobody can rename or delete
        # an entry they do not own there. A plain world-writable directory is not.
        sticky = bool(dst.st_mode & stat.S_ISVTX)
        if (_unsafe_mode(dst) and not sticky) or (not sticky and dst.st_uid not in (0, os.geteuid())):
            raise LanguageError(f"{d} can be changed by other users, so {real} is not trusted")
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return real


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            size += len(chunk)
            if size > MAX_FILE:
                raise LanguageError(f"{path} is too large to pin")
            h.update(chunk)
    return h.hexdigest()


def _read_paths(real_exe: str) -> tuple[str, ...]:
    """What the sandbox must let the program read: its install prefix (``/opt/node22``
    for ``/opt/node22/bin/node``). Programs under /usr are already readable."""
    prefix = os.path.dirname(os.path.dirname(real_exe))
    if prefix in ("/", "") or prefix == "/usr" or prefix.startswith("/usr/") or real_exe.startswith("/bin/"):
        return ()
    return (prefix,)


def _env_for(spec_env: tuple[tuple[str, str], ...], real_exe: str) -> tuple[tuple[str, str], ...]:
    """A relocatable install (``/opt/ruby/bin/ruby``) keeps its shared library next to it."""
    env = dict(spec_env)
    prefix = os.path.dirname(os.path.dirname(real_exe))
    lib = os.path.join(prefix, "lib")
    if _read_paths(real_exe) and os.path.isdir(lib):
        env["LD_LIBRARY_PATH"] = lib
    return tuple(sorted(env.items()))


# --------------------------------------------------------------------------
# Custom languages (kos runtimes add / remove)
# --------------------------------------------------------------------------

def validate_args(args) -> tuple[str, ...]:
    if not isinstance(args, (list, tuple)) or not args or len(args) > MAX_ARGS:
        raise LanguageError(f"arguments: 1 to {MAX_ARGS} items, one of them {CODE_SLOT}")
    out = []
    for a in args:
        if not isinstance(a, str) or len(a) > MAX_ARG_LEN or "\x00" in a:
            raise LanguageError("each argument must be short text")
        out.append(a)
    if out.count(CODE_SLOT) != 1:
        raise LanguageError(f"exactly one argument must be {CODE_SLOT}")
    i = out.index(CODE_SLOT)
    if i == 0 or not out[i - 1].startswith("-"):
        raise LanguageError(f"{CODE_SLOT} must come right after a flag such as -e, so code can never be read as a flag")
    if any(CODE_SLOT in a for a in out if a != CODE_SLOT):
        raise LanguageError(f"{CODE_SLOT} must be a whole argument")
    return tuple(out)


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise LanguageError("a language name is lowercase letters, digits, + or -, up to 16 characters")
    if canonical(name) == "python":
        raise LanguageError("python is built in and cannot be replaced")
    if name in _ALIASES and name not in BUILTIN:
        raise LanguageError(f"{name} is an alias of {_ALIASES[name]}")
    return name


def _registry_path(paths: Paths) -> Path:
    return paths.state.joinpath(REGISTRY_FILE)


def load_custom(paths: Paths) -> dict[str, dict]:
    """The languages you added. A damaged or tampered file yields no languages, never a crash
    and never a half-trusted row."""
    try:
        data = json.loads(_registry_path(paths).read_text())
        rows = data["runtimes"]
        if data.get("version") != 1 or not isinstance(rows, dict):
            return {}
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    good = {}
    for name, row in rows.items():
        try:
            validate_name(name)
            if not (isinstance(row, dict) and isinstance(row.get("exe"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))):
                continue
            good[name] = {"exe": row["exe"], "args": list(validate_args(row.get("args"))),
                          "sha256": row["sha256"]}
        except LanguageError:
            continue
    return good


def _save_custom(paths: Paths, rows: dict[str, dict]) -> None:
    paths.ensure()
    atomic_write(_registry_path(paths), json.dumps({"version": 1, "runtimes": rows}, indent=1,
                                                   sort_keys=True).encode())


def prepare_add(name: str, exe: str, args=DEFAULT_ARGS) -> tuple[str, str, tuple[str, ...]]:
    """Check everything that can be checked before the password is asked for."""
    name = validate_name(name)
    real = check_trusted(exe)
    return name, real, validate_args(list(args))


def add(paths: Paths, name: str, real_exe: str, args: tuple[str, ...]) -> str:
    """Record a language (call after the password). Returns the pinned SHA-256."""
    digest = file_sha256(real_exe)
    rows = load_custom(paths)
    rows[name] = {"exe": real_exe, "args": list(args), "sha256": digest}
    _save_custom(paths, rows)
    return digest


def remove(paths: Paths, name: str) -> bool:
    rows = load_custom(paths)
    if name not in rows:
        return False
    del rows[name]
    _save_custom(paths, rows)
    return True


# --------------------------------------------------------------------------
# Finding a language
# --------------------------------------------------------------------------

def _search(candidates: tuple[str, ...], path_env: Optional[str] = None) -> Optional[str]:
    """First trusted program with one of these names. Untrusted hits are skipped, not run."""
    for d in (path_env if path_env is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if not d or not os.path.isabs(d):
            continue                      # a relative PATH entry means "the current directory"
        for name in candidates:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                try:
                    return check_trusted(p)
                except LanguageError:
                    continue
    return None


def find(paths: Paths, language: str) -> Optional[Runtime]:
    """The runtime for a language, or None if there is none here. Raises
    ``LanguageError`` when you added the language but its program changed or is no longer trusted."""
    name = canonical(language)
    custom = load_custom(paths)
    if name in custom:
        row = custom[name]
        real = check_trusted(row["exe"])
        if file_sha256(real) != row["sha256"]:
            raise LanguageError(f"{name}: the program changed since it was added ({real}); "
                                f"remove it and add it again if that was you")
        return Runtime(name, real, tuple(row["args"]), _read_paths(real), _env_for((), real), True, row["sha256"])
    spec = BUILTIN.get(name)
    if spec is None:
        return None
    real = _search(spec.candidates)
    if real is None:
        return None
    return Runtime(name, real, spec.args, _read_paths(real), _env_for(spec.env, real))


def available(paths: Paths) -> list[str]:
    """Names of the languages that would run right now (python first). No program is executed."""
    names = ["python"]
    for name, spec in BUILTIN.items():
        if _search(spec.candidates):
            names.append(name)
    names += [n for n in sorted(load_custom(paths)) if n not in names]
    return names


def describe(paths: Paths) -> list[tuple[str, str, str]]:
    """(name, program, state) for every language, for ``kos runtimes``."""
    rows = [("python", os.path.realpath(sys.executable), "built in (fast path)")]
    custom = load_custom(paths)
    for name, spec in BUILTIN.items():
        if name in custom:
            continue
        found = _search(spec.candidates)
        rows.append((name, found or "-", "ready" if found else "not installed"))
    for name, row in sorted(custom.items()):
        try:
            real = check_trusted(row["exe"])
            state = "added, pinned" if file_sha256(real) == row["sha256"] else "CHANGED since added - refused"
        except LanguageError as e:
            state = f"refused: {e}"
        rows.append((name, row["exe"], state))
    return rows
