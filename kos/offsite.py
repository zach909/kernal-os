"""Off-site copies: push a backup to *your private* GitHub repository.

Your documents leave this machine here, so every guard is deliberate:

* The destination is one GitHub repository you set yourself (``kos offsite
  remote URL``, password). Only ``https://github.com/OWNER/REPO`` and
  ``git@github.com:OWNER/REPO`` are accepted - nothing else, so git's exotic
  transports (``ext::``, ``file://``, other hosts) can never be reached.
* **Never to a public repository.** Before every push the repository is
  probed *anonymously* (``git ls-remote`` with all credentials and prompts
  disabled). If anyone on the internet could read it, the push is refused.
  A private repository fails that probe, which is the answer we want.
* Each push needs your password (``backup.push``) and sends one backup that
  was already security-scanned when it was made.
* It uses *your* git credentials (credential helper / ssh agent). KOS never
  sees, stores or asks for a GitHub token.

Honest limits: the backup is **not encrypted** - "private" is GitHub's access
control, not cryptography; and the anonymous probe cannot tell a private
repository from one that does not exist (the push then fails). End-to-end
encryption needs a vetted crypto library and is on the backlog.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

from .admin import AdminError
from .auth import Authority
from .backup import NAME_RE, backup_dir
from .paths import Paths, atomic_write

GITHUB_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?$")


class OffsiteError(AdminError):
    pass


def _https(url: str) -> str:
    m = GITHUB_RE.match(url)
    return f"https://github.com/{m.group(1)}/{m.group(2)}.git"


class Offsite:
    def __init__(self, paths: Paths, *, runner: Callable = subprocess.run,
                 public_check: Optional[Callable[[str], bool]] = None,
                 allow_any_remote: bool = False, timeout: float = 90.0):
        self.paths, self._run, self._public = paths, runner, public_check
        self.allow_any, self.timeout = allow_any_remote, timeout
        self.config = paths.etc / "offsite.json"
        self.work = paths.state / "offsite"

    # --- the one remote ---------------------------------------------------
    def remote(self) -> Optional[str]:
        try:
            return json.loads(self.config.read_text()).get("remote")
        except (FileNotFoundError, ValueError):
            return None

    def set_remote(self, authority: Authority, url: str) -> str:
        if not (self.allow_any or GITHUB_RE.match(url)):
            raise OffsiteError("the off-site repository must be a GitHub repository: "
                               "https://github.com/OWNER/REPO (or git@github.com:OWNER/REPO)")
        with authority.authorize("backup.remote", url):
            self.paths.ensure()
            atomic_write(self.config, json.dumps({"remote": url}).encode())
        return url

    # --- the privacy guard ---------------------------------------------------
    def is_public(self, url: str) -> bool:
        """True if anybody could read ``url`` without credentials."""
        if self._public is not None:
            return self._public(url)
        probe = _https(url) if GITHUB_RE.match(url) else url
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true",
               "SSH_ASKPASS": "/bin/true", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        try:
            r = self._run(["git", "ls-remote", "--exit-code", "--heads", probe], env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return r.returncode == 0

    # --- the push -------------------------------------------------------------
    def _git(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        r = self._run(["git", "-c", "user.name=KOS", "-c", "user.email=kos@localhost",
                       "-c", "commit.gpgsign=false", *args], cwd=self.work, env=env,
                      stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=self.timeout)
        if r.returncode != 0:
            raise OffsiteError(f"git {args[0]} failed: {(r.stderr or r.stdout).strip()[-300:]}")
        return r

    def push(self, authority: Authority, backup_name: str) -> str:
        url = self.remote()
        if not url:
            raise OffsiteError("no off-site repository set: kos offsite remote https://github.com/OWNER/REPO")
        if not NAME_RE.match(backup_name):
            raise OffsiteError("not a backup name")
        src = backup_dir(self.paths) / backup_name
        if not src.is_file():
            raise OffsiteError(f"no such backup: {backup_name}")
        if self.is_public(url):
            raise OffsiteError(f"refusing: {url} is publicly readable. Your documents only go to a "
                               "PRIVATE repository - make it private or set a different one.")
        with authority.authorize("backup.push", f"{backup_name} -> {url}"):
            if self.is_public(url):                       # re-check after the password prompt
                raise OffsiteError("refusing: the repository became publicly readable")
            self.work.mkdir(parents=True, exist_ok=True)
            os.chmod(self.work, 0o700)
            if not (self.work / ".git").exists():
                self._git("init", "-q", "-b", "main")
            have = self._git("remote").stdout.split()
            self._git(*(["remote", "set-url", "origin", url] if "origin" in have
                        else ["remote", "add", "origin", url]))
            shutil.copyfile(src, self.work / backup_name)
            self._git("add", backup_name)
            self._git("commit", "-q", "-m", f"backup {backup_name}", "--allow-empty")
            self._git("push", "-q", "origin", "HEAD:main")
        return f"pushed {backup_name} to {url}"
