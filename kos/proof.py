"""The proof gate: a program that carries no valid proof does not run.

Two rules, enforced here and nowhere else:

1. **No decimals.** Code in an app uses whole numbers only: no float or complex
   literals, no ``float``/``complex``/``Decimal``/``Fraction``, no ``/`` or ``/=``
   (use ``//``), no float-returning ``math`` functions, no clock or random calls
   that return a float.
2. **Nothing runs unproven.** Every ``.kapp`` ships ``proof.json``. At install and
   again at every launch the OS re-derives the proof from the zip's own bytes and
   compares. Any difference, any missing file, any rule broken, any ``.py`` file
   that does not compile, or a native binary (which cannot be checked) means the app
   is refused. The proof is never trusted: it is recomputed. It only names what was
   checked, so a change shows up as a mismatch.

What this is, honestly: a *static check against a fixed rule set, plus a successful
compile*, bound to the exact bytes. It is not a formal proof that an app is secure
or correct. It proves "this code has none of the forbidden constructs and compiles",
and the OS still sandboxes it. See the README gaps table for what it does not cover.

This module uses whole numbers only, by its own rule.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys

from .kapp import KApp, KAppError

PROOF_FILE = "proof.json"
VERIFIER = 1                       # bump when the rules change: old proofs then stop being valid
MAX_SOURCE = 4 << 20

# Names that mean a decimal (or code made at run time, which no static check can see).
BANNED_NAMES = frozenset({"float", "complex", "Decimal", "Fraction", "eval", "exec", "compile",
                          "__import__", "breakpoint", "globals", "locals", "vars"})
# Attributes that reach out of the language's own guard rails.
BANNED_ATTRS = frozenset({"__subclasses__", "__globals__", "__builtins__", "__code__", "__closure__",
                          "__mro__", "__bases__", "__loader__", "__spec__"})
# Modules that hold decimals, or load code by name, or leave the sandbox's rules behind.
BANNED_MODULES = frozenset({"decimal", "fractions", "cmath", "statistics", "ctypes", "_ctypes",
                            "importlib", "imp", "marshal", "pickle", "shelve", "subprocess",
                            "multiprocessing", "code", "codeop", "runpy", "builtins"})
MATH_WHOLE = frozenset({"gcd", "lcm", "isqrt", "comb", "perm", "factorial", "prod"})
FLOAT_CALLS = {"time": frozenset({"time", "monotonic", "perf_counter", "process_time"}),
               "random": frozenset({"random", "uniform", "gauss", "normalvariate", "triangular",
                                    "betavariate", "expovariate"})}
DECIMAL_TYPES = ("float", "complex")      # by name: this file may not name the types either
STDLIB = frozenset(sys.stdlib_module_names)
TRUSTED_OS_PACKAGE = "kos"        # OS code the app imports; not covered by the app's proof (a gap)


class ProofError(KAppError):
    """The app has no valid proof. It is not installed and does not run."""


def violations(source: bytes, filename: str, local_modules: frozenset = frozenset()) -> list:
    """Every rule the source breaks, as ``"file:line: what"``. Empty means none."""
    if len(source) > MAX_SOURCE:
        return [f"{filename}: source too large to check"]
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as e:
        return [f"{filename}: does not compile ({e})"]
    out: list = []

    def bad(node, what: str) -> None:
        out.append(f"{filename}:{getattr(node, 'lineno', 0)}: {what}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and type(node.value).__name__ in DECIMAL_TYPES:
            bad(node, "decimal literal (use whole numbers)")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            bad(node, "'/' makes a decimal (use '//')")
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Div):
            bad(node, "'/=' makes a decimal (use '//=')")
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            bad(node, f"'{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute):
            if node.attr in BANNED_ATTRS:
                bad(node, f"attribute '{node.attr}' is not allowed")
            base = node.value.id if isinstance(node.value, ast.Name) else ""
            if base == "math" and node.attr not in MATH_WHOLE:
                bad(node, f"math.{node.attr} is not a whole-number function")
            if node.attr in FLOAT_CALLS.get(base, ()):
                bad(node, f"{base}.{node.attr} returns a decimal")
        elif isinstance(node, ast.Import):
            for a in node.names:
                _module(node, a.name, local_modules, out, filename)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                bad(node, "relative imports are not allowed")
            elif node.module:
                _module(node, node.module, local_modules, out, filename)
                if node.module == "math":
                    for a in node.names:
                        if a.name not in MATH_WHOLE:
                            bad(node, f"math.{a.name} is not a whole-number function")
                for a in node.names:
                    if a.name in BANNED_NAMES or a.name in FLOAT_CALLS.get(node.module, ()):
                        bad(node, f"'{a.name}' is not allowed")
    return out


def decimal_uses(source: bytes) -> int:
    """How many places in ``source`` make or name a decimal. The OS's own code is held to a
    ratchet on this number (tests/test_proof.py): it may fall, never rise."""
    n = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and type(node.value).__name__ in DECIMAL_TYPES:
            n += 1
        elif isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, ast.Div):
            n += 1
        elif isinstance(node, ast.Name) and node.id in ("float", "complex"):
            n += 1
    return n


def _module(node, name: str, local: frozenset, out: list, filename: str) -> None:
    top = name.split(".")[0]
    line = getattr(node, "lineno", 0)
    if top in BANNED_MODULES:
        out.append(f"{filename}:{line}: module '{top}' is not allowed")
    elif top not in STDLIB and top != TRUSTED_OS_PACKAGE and top not in local:
        out.append(f"{filename}:{line}: module '{top}' is not standard, not the OS's, and not in the app")


def _local_modules(app_names) -> frozenset:
    return frozenset(n.split("/")[0].removesuffix(".py") for n in app_names if n.endswith(".py"))


UNCHECKABLE_SUFFIXES = (".so", ".pyc", ".pyo", ".pyd", ".dll", ".dylib", ".exe")


def _unchecked_code(names_and_heads) -> list:
    """Compiled code cannot be checked by reading it, so a Python app may not carry any: an ELF
    binary (whatever its name) or a compiled-code file would run with no proof behind it."""
    return [f"{n}: compiled code cannot be checked, so it cannot ship in an app"
            for n, head in names_and_heads
            if head.startswith(b"\x7fELF") or n.lower().endswith(UNCHECKABLE_SUFFIXES)]


def _sources(app: KApp) -> dict:
    return {n: app.read(n, limit=MAX_SOURCE + 1) for n in app.names() if n.endswith(".py")}


def derive(app: KApp) -> tuple:
    """``(proof dict, violations)`` computed from the app's own bytes."""
    if app.manifest.runtime != "python":
        return {}, [f"{app.manifest.name}: a native program cannot be checked, so it cannot run"]
    sources = _sources(app)
    if not sources:
        return {}, [f"{app.manifest.name}: no Python source to check"]
    local = _local_modules(sources)
    found: list = _unchecked_code((n, app.read(n, limit=1 << 30)[:4]) for n in app.names())
    files = {}
    for name in sorted(sources):
        data = sources[name]
        found += violations(data, name, local)
        files[name] = hashlib.sha256(data).hexdigest()
    return {"format": 1, "verifier": VERIFIER, "files": files}, found


def make_proof(files: dict, runtime: str, name: str) -> bytes:
    """The proof.json for a source tree (``files``: relative path -> bytes), or raise
    ProofError saying every rule broken. Used by ``pack``; the OS never trusts the result."""
    if runtime != "python":
        raise ProofError(f"{name}: a native program cannot be checked, so it cannot run")
    sources = {n: d for n, d in files.items() if n.endswith(".py")}
    if not sources:
        raise ProofError(f"{name}: no Python source to check")
    local = _local_modules(sources)
    found: list = _unchecked_code((n, d[:4]) for n, d in files.items())
    for n in sorted(sources):
        found += violations(sources[n], n, local)
    if found:
        raise ProofError(f"{name}: cannot be proven, so it cannot be packed:\n  " + "\n  ".join(found))
    proof = {"format": 1, "verifier": VERIFIER,
             "files": {n: hashlib.sha256(sources[n]).hexdigest() for n in sorted(sources)}}
    return json.dumps(proof, sort_keys=True, indent=1).encode()


def _no_decimal(token: str):
    raise ValueError("decimal in proof")


def require(app: KApp) -> None:
    """Refuse (ProofError) unless the app carries a proof that the bytes in hand reproduce."""
    name = app.manifest.name
    if PROOF_FILE not in app.names():
        raise ProofError(f"{name}: no {PROOF_FILE}. An app that cannot show a proof does not run")
    try:
        claimed = json.loads(app.read(PROOF_FILE, limit=1 << 20), parse_float=_no_decimal,
                             parse_constant=_no_decimal)
    except (ValueError, KAppError):
        raise ProofError(f"{name}: {PROOF_FILE} is not valid") from None
    derived, found = derive(app)
    if found:
        raise ProofError(f"{name}: failed verification, it does not run:\n  " + "\n  ".join(found))
    if claimed != derived:
        raise ProofError(f"{name}: the proof does not match the code in the app. It does not run")
