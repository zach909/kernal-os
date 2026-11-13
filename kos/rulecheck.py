"""Source checker for the fractions rule (no decimals).

Finds, with the ``ast`` module, the places a decimal sneaks in:

* a decimal literal (``0.5``, ``1e3``)
* a call to ``float(...)``
* true division ``/`` or ``/=`` where an operand is a number literal or a call
  to ``len``/``int``/``sum``/``abs``/``min``/``max``/``round``

``a / b`` between two plain names is *not* flagged: it may be a ``Path`` join,
and the checker cannot tell. It is a scan, not a type system. Use ``//`` or
``Fraction`` there; reviewers and the proofs in ``kos/proofs.py`` cover the rest.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

_NUMERIC_CALLS = {"len", "int", "sum", "abs", "min", "max", "round"}


def _numeric_operand(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _NUMERIC_CALLS
    if isinstance(node, ast.UnaryOp):
        return _numeric_operand(node.operand)
    return False


def breaches(source: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, what)`` for each decimal in ``source``."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, float):
            yield node.lineno, f"decimal literal {node.value!r}"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "float":
            yield node.lineno, "float()"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if _numeric_operand(node.left) or _numeric_operand(node.right):
                yield node.lineno, "true division / (use // or Fraction)"
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Div):
            yield node.lineno, "true division /= (use //= or Fraction)"


def scan_file(path: Path) -> list[tuple[int, str]]:
    try:
        return sorted(breaches(path.read_text(encoding="utf-8")))
    except (SyntaxError, UnicodeDecodeError):
        return []


def scan_tree(root: Path, dirs=("kos", "apps", "examples", "suite", "bin")) -> dict[str, int]:
    """Count of breaches per file, only files with at least one."""
    out: dict[str, int] = {}
    for d in dirs:
        base = root / d
        if not base.exists():
            continue
        files = [base] if base.is_file() else sorted(base.rglob("*"))
        for p in files:
            if p.is_file() and (p.suffix == ".py" or (d == "bin" and not p.suffix)):
                n = len(scan_file(p))
                if n:
                    out[str(p.relative_to(root))] = n
    return out
