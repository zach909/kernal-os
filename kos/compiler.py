"""The compiler path: a line (or a few) of C, C++, Go, Rust, JavaScript, Ruby, Perl or PHP, built and run inside the sandbox.

KOS writes no compiler of its own - it drives the ones the machine already has, and drives them *as an app*: the line becomes a
one-shot app (like a Python line, see ``coderun``) that runs under the same sandbox as every other app - an unprivileged user, no
network, no files of yours, no signals, Landlock - and does the whole job in its private scratch directory: write the source, call
the host compiler, run what it made, print what came out. The scratch directory is wiped when it ends. It needs your password
(``code.run``), is security-scanned first, and has a time limit.

What the sandbox is allowed to see is decided here, by the OS, and nothing the line says can change it: the toolchain's own install
directory (read and execute, never write) and the scratch directory (read, write, execute: the compiled program runs from it). A
toolchain installed somewhere the sandbox's user cannot read (a home directory, say) is reported as unavailable rather than
widened for.

A line that is not a whole program is wrapped into one: ``printf("hi\\n");`` gets ``main`` and the usual includes, ``fmt.Println(1)`` gets
``package main`` and the packages it names, and so on. ``c: ...``, ``cpp: ...``, ``go: ...``, ``rust: ...``, ``js: ...``, ``ruby: ...``,
``perl: ...`` or ``php: ...`` at the start of a line says which language when it cannot be guessed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Optional

# what lang.detect_code calls them -> our name
ALIASES = {"c": "c", "c++": "c++", "cpp": "c++", "go": "go", "golang": "go", "rust": "rust", "rs": "rust", "js": "javascript",
           "javascript": "javascript", "node": "javascript", "ruby": "ruby", "rb": "ruby", "perl": "perl", "pl": "perl", "php": "php"}
BUILD_LIMIT, RUN_LIMIT = 40, 8           # seconds the compile step and the program may each take
UNREADABLE = ("/root", "/home")          # the sandbox runs as another user: tools living here cannot be used

TOOLS = {
    "c": ("gcc", "cc", "clang"), "c++": ("g++", "clang++", "c++"), "go": ("go",), "rust": ("rustc",),
    "javascript": ("node",), "ruby": ("ruby",), "perl": ("perl",), "php": ("php",),
}
EXT = {"c": "c", "c++": "cpp", "go": "go", "rust": "rs", "javascript": "js", "ruby": "rb", "perl": "pl", "php": "php"}


class CompilerError(Exception):
    pass


@dataclass
class Plan:
    language: str
    source: str                                        # the whole program, after wrapping
    filename: str
    build: Optional[list] = None                       # argv of the compile step, run in the scratch directory
    run: list = field(default_factory=list)            # argv of the program
    env: dict = field(default_factory=dict)
    read_paths: list = field(default_factory=list)     # extra read+execute access the sandbox gets (the toolchain)
    tool: str = ""


def canonical(language: str, code: str = "") -> Optional[str]:
    """Which of our languages does this detected language name mean? ('rust/go' is told apart by its words.)"""
    lang = (language or "").lower()
    if lang == "rust/go":
        return "go" if re.search(r"\bfunc\b|\bpackage\s+main\b|\bfmt\.", code) else "rust"
    if lang == "c" and re.search(r"\bstd::|\bcout\b|<iostream>|\busing\s+namespace\b|\bnullptr\b|\bclass\s+\w+\s*[{:]", code):
        return "c++"
    return ALIASES.get(lang)


def _wrap(language: str, code: str) -> str:
    c = code.strip()
    if language in ("c", "c++"):
        if re.search(r"\bmain\s*\(", c):
            return c + "\n"
        if not c.endswith((";", "}")):
            c += ";"
        head = ("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n" if language == "c"
                else "#include <iostream>\n#include <string>\n#include <vector>\n#include <cmath>\n#include <cstdio>\nusing namespace std;\n")
        return f"{head}int main(void) {{\n{c}\nreturn 0;\n}}\n"
    if language == "go":
        if re.search(r"^\s*package\s+\w+", c, re.M):
            return c + "\n"
        pkgs = sorted(set(re.findall(r"\b(fmt|os|strings|math|sort|time|strconv|errors|bufio|bytes|unicode)\.", c)))
        imports = "import (\n" + "".join(f'\t"{p}"\n' for p in pkgs) + ")\n" if pkgs else ""
        body = c if re.search(r"\bfunc\s+main\s*\(", c) else f"func main() {{\n{c}\n}}"
        return f"package main\n{imports}{body}\n"
    if language == "rust":
        return c + "\n" if re.search(r"\bfn\s+main\s*\(", c) else f"fn main() {{\n{c}\n}}\n"
    if language == "php":
        return c + "\n" if "<?php" in c else f"<?php\n{c}\n"
    return c + "\n"


def find_tool(language: str) -> tuple[Optional[str], str]:
    """(path, why not): the first toolchain for the language that the sandbox's user could actually run."""
    why = f"no {language} toolchain is installed ({', '.join(TOOLS[language])})"
    for name in TOOLS[language]:
        found = shutil.which(name)
        if not found:
            continue
        real = os.path.realpath(found)
        if real.startswith(UNREADABLE) or found.startswith(UNREADABLE):
            why = f"{name} is installed at {found}, which the sandbox's user cannot read (move or copy it under /usr or /opt)"
            continue
        return real, why
    return None, why


def plan(language: str, code: str, scratch: str = "$SCRATCH") -> Plan:
    """What to build and run for this line. Raises CompilerError (with the reason) when there is no way to."""
    lang = ALIASES.get(language) or language
    if lang not in TOOLS:
        raise CompilerError(f"there is no {language} compiler or interpreter wired in (C, C++, Go, Rust, JavaScript, Ruby, Perl, PHP are)")
    tool, why = find_tool(lang)
    if tool is None:
        raise CompilerError(why)
    prefix = os.path.dirname(os.path.dirname(tool))
    reads = [prefix] if prefix not in ("/", "/usr", "/usr/bin") else []
    fname = f"main.{EXT[lang]}"
    p = Plan(lang, _wrap(lang, code), fname, tool=tool, read_paths=reads)
    cache = {"HOME": scratch, "TMPDIR": scratch, "GOCACHE": f"{scratch}/gocache", "GOPATH": f"{scratch}/gopath", "GOFLAGS": "-buildvcs=false",
             "GOTOOLCHAIN": "local", "CARGO_HOME": scratch, "LANG": "C.UTF-8"}
    p.env = {**cache, "PATH": f"{os.path.dirname(tool)}:/usr/bin:/bin", "OPENSSL_CONF": os.devnull}      # node reads openssl.cnf; the sandbox says no
    libs = os.path.join(prefix, "lib")
    if prefix not in ("/", "/usr") and os.path.isdir(libs):
        p.env["LD_LIBRARY_PATH"] = libs                                    # a toolchain installed under /opt finds its own libraries
    if lang == "c":
        p.build, p.run = [tool, "-O1", "-w", "-o", "main", fname, "-lm"], ["./main"]
    elif lang == "c++":
        p.build, p.run = [tool, "-O1", "-w", "-std=c++17", "-o", "main", fname], ["./main"]
    elif lang == "rust":
        p.build, p.run = [tool, "-O", "-o", "main", fname], ["./main"]
    elif lang == "go":
        p.run = [tool, "run", fname]
    elif lang == "ruby":
        p.run = [tool, "--disable=gems,error_highlight,did_you_mean,syntax_suggest", fname]       # no gems in a sandbox: do not look for them
    else:
        p.run = [tool, fname]
    return p


RUNNER = '''\
import json, os, subprocess
from kos.sdk import App


def main():
    app = App()
    for ev in app.events():          # wait for the OS's hello, then do the whole job once
        break
    plan = json.loads(app.resource("plan.json").decode())
    scratch = os.environ["KOS_CACHE_DIR"]
    env = {k: v.replace("$SCRATCH", scratch) for k, v in plan["env"].items()}
    open(os.path.join(scratch, plan["filename"]), "w").write(app.resource("source").decode())
    out = []

    def step(argv, limit, label):
        try:
            r = subprocess.run(argv, cwd=scratch, env=env, capture_output=True, text=True, timeout=limit, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            out.append(f"[{label} stopped: it ran longer than {limit}s]")
            return None
        text = (r.stdout or "") + (r.stderr or "")
        if text:
            out.append(text if len(text) < 2400 else text[:2400] + "\\n[output cut]")
        return r.returncode

    code = 0
    if plan["build"]:
        code = step(plan["build"], plan["build_limit"], "build")
        if code:
            out.append(f"[build failed: exit {code}]" if code is not None else "")
    if not code:
        code = step(plan["run"], plan["run_limit"], "program")
        if code:
            out.append(f"[exit {code}]")
    app.log("\\n".join(x for x in out if x)[-3000:] or "(no output)")
    app.exit(0)
'''
