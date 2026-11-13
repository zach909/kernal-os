"""The lean profile: what an installed KOS actually needs, as small as it can honestly be.

Three cuts, none of which changes what the code does:

1. Only the OS core ships: ``bin/kos``, ``bin/run``, ``kos/*.py`` and ``examples/system`` (the two
   system apps ``kos desktop install`` packs). The productivity suite (``kos/office``), the apps in
   ``examples/``, the tests, the docs and the image-building scripts are separate; everything else is
   an app you install, which is the point.
2. Docstrings and comments are removed from the shipped Python (``strip_source``). Nothing in KOS
   reads ``__doc__``; the test suite is run against the stripped tree to prove it still behaves the
   same. The side effect: tracebacks in the lean build have different line numbers. The readable
   source stays in the repository.
3. The package is xz-compressed instead of gzip.

``ast.unparse`` output depends on the Python that built the package, so the lean package is
byte-for-byte reproducible with the same Python, not across versions. That is stated, not hidden.
"""

from __future__ import annotations

import ast

LEAN_FILES_TOP = ("bin/kos", "bin/run")
LEAN_PREFIXES = ("examples/system/",)


def in_lean(path: str) -> bool:
    if path in LEAN_FILES_TOP or path.startswith(LEAN_PREFIXES):
        return True
    return path.startswith("kos/") and path.count("/") == 1 and path.endswith(".py")


def strip_source(src: str) -> str:
    """The same program without docstrings and comments."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree) + "\n"


def lean_bytes(path: str, data: bytes) -> bytes:
    """What ships for ``path`` in the lean package."""
    if path.startswith("kos/") and path.endswith(".py"):
        return strip_source(data.decode("utf-8")).encode("utf-8")
    return data
