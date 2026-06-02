from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager

from mimir.crypto import VaultFile


class RemoteError(Exception):
    """Raised when a sync operation cannot be completed."""


class Remote(ABC):
    """A backend that can push/pull the vault file to/from somewhere durable."""

    @abstractmethod
    def push(self, vault_path: str) -> None:
        ...

    @abstractmethod
    def pull(self, vault_path: str, force: bool = False) -> None:
        ...


class GitRemote(Remote):
    """Syncs the vault to a git remote (e.g. a public GitHub repo).

    The vault blob is encrypted, so a public repo is safe and gives free,
    recoverable history. Mimir never touches git credentials — it assumes the
    user's existing git setup can reach the remote.

    The repository is the directory that contains the vault file. Mimir does
    not own a `.gitignore` (the directory may already use one) and only ever
    stages the vault file by explicit path. The vault lives on its own branch,
    created as an orphan when absent so its history stays independent of any
    other branch already in the directory.
    """

    def __init__(self, url: str, branch: str) -> None:
        self.url: str = url
        self.branch: str = branch

    # -- git plumbing -------------------------------------------------------

    @staticmethod
    def _ensure_git() -> None:
        if shutil.which("git") is None:
            raise RemoteError("git is not installed; it is required for push/pull")

    @staticmethod
    def _log(message: str) -> None:
        """Echo git activity to stderr so the user can audit what ran."""
        print(message, file=sys.stderr)

    def _git(
        self, repo_dir: str, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self._log(f"$ git -C {repo_dir} {' '.join(args)}")
        result = subprocess.run(
            ["git", "-C", repo_dir, *args],
            capture_output=True,
            text=True,
        )
        # Log output only on success. A non-zero exit is either an expected
        # probe result (check=False) or a real failure surfaced below as a
        # RemoteError, so its output would just be confusing noise here.
        output = (result.stdout + result.stderr).strip()
        if output and result.returncode == 0:
            self._log(textwrap.indent(output, "  "))
        if check and result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise RemoteError(message or f"git {args[0]} failed")
        return result

    def _git_bytes(self, repo_dir: str, *args: str) -> bytes:
        self._log(f"$ git -C {repo_dir} {' '.join(args)}")
        result = subprocess.run(["git", "-C", repo_dir, *args], capture_output=True)
        if result.returncode != 0:
            raise RemoteError(result.stderr.decode("utf-8", "replace").strip())
        # The payload is the encrypted vault blob; log its size, not its bytes.
        self._log(f"  ({len(result.stdout)} bytes received)")
        return result.stdout

    def _ref_exists(self, repo_dir: str, ref: str) -> bool:
        result = self._git(repo_dir, "rev-parse", "--verify", "--quiet", ref, check=False)
        return result.returncode == 0

    # -- setup --------------------------------------------------------------

    def _ensure_repo(self, repo_dir: str) -> None:
        os.makedirs(repo_dir, exist_ok=True)
        inside = self._git(repo_dir, "rev-parse", "--is-inside-work-tree", check=False)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            self._git(repo_dir, "init")
        self._ensure_origin(repo_dir)

    def _ensure_origin(self, repo_dir: str) -> None:
        existing = self._git(repo_dir, "remote", "get-url", "origin", check=False)
        if existing.returncode != 0:
            self._git(repo_dir, "remote", "add", "origin", self.url)
        elif existing.stdout.strip() != self.url:
            self._git(repo_dir, "remote", "set-url", "origin", self.url)

    def _checkout_branch(self, repo_dir: str) -> None:
        current = self._git(repo_dir, "branch", "--show-current", check=False)
        if current.stdout.strip() == self.branch:
            return
        if self._ref_exists(repo_dir, f"refs/heads/{self.branch}"):
            self._git(repo_dir, "checkout", self.branch)
        elif self._ref_exists(repo_dir, f"refs/remotes/origin/{self.branch}"):
            self._git(repo_dir, "checkout", "-B", self.branch, f"origin/{self.branch}")
        else:
            # No such branch anywhere: start an independent history for the vault.
            self._git(repo_dir, "checkout", "--orphan", self.branch)

    def _has_tracked_changes(self, repo_dir: str) -> bool:
        """True if the working tree has staged or unstaged tracked changes."""
        unstaged = self._git(repo_dir, "diff", "--quiet", check=False).returncode != 0
        staged = self._git(repo_dir, "diff", "--cached", "--quiet", check=False).returncode != 0
        return unstaged or staged

    @contextmanager
    def _preserve_state(self, repo_dir: str) -> Iterator[None]:
        """Run a vault-branch operation without disturbing the user's branch.

        The vault may share a directory with an unrelated repo, so switching to
        the vault branch (and the ``reset --hard`` on pull) must not clobber the
        user's current branch or their uncommitted work. If the operation will
        switch branches, stash any tracked changes first, then restore the
        original branch and pop the stash afterwards. Untracked files (including
        the vault file itself) are left untouched.

        When already on the vault branch this is a no-op, so the pending vault
        changes stay in the working tree to be committed.
        """
        current = self._git(repo_dir, "branch", "--show-current", check=False).stdout.strip()
        if current == self.branch:
            yield
            return

        # Capture where to return: branch name, or the commit if detached/unborn.
        has_head = self._ref_exists(repo_dir, "HEAD")
        stashed = False
        if has_head and self._has_tracked_changes(repo_dir):
            self._git(repo_dir, "stash", "push", "-m", "mimir auto-stash")
            stashed = True
        try:
            yield
        finally:
            target = current or (
                self._git(repo_dir, "rev-parse", "HEAD", check=False).stdout.strip()
            )
            if target:
                self._git(repo_dir, "checkout", target, check=False)
            if stashed:
                self._git(repo_dir, "stash", "pop", check=False)

    # -- operations ---------------------------------------------------------

    def push(self, vault_path: str) -> None:
        self._ensure_git()
        repo_dir = os.path.dirname(vault_path) or "."
        vault_file = os.path.basename(vault_path)

        self._ensure_repo(repo_dir)
        with self._preserve_state(repo_dir):
            self._checkout_branch(repo_dir)

            # -f overrides any .gitignore in the directory: mimir intentionally
            # tracks exactly this one file, whatever ignore rules are in place.
            self._git(repo_dir, "add", "-f", "--", vault_file)
            # Commit only when the vault file actually changed. `diff --cached`
            # returns non-zero when there is something staged to commit; on a
            # repo with no commits yet it compares against the empty tree, so
            # the first add always counts as a change.
            staged = self._git(
                repo_dir, "diff", "--cached", "--quiet", "--", vault_file, check=False
            )
            if staged.returncode != 0:
                self._git(repo_dir, "commit", "-m", "Update vault", "--", vault_file)

            self._git(repo_dir, "push", "-u", "origin", self.branch)

    def pull(self, vault_path: str, force: bool = False) -> None:
        self._ensure_git()
        repo_dir = os.path.dirname(vault_path) or "."
        vault_file = os.path.basename(vault_path)

        self._ensure_repo(repo_dir)
        self._git(repo_dir, "fetch", "origin", self.branch)

        incoming = self._git_bytes(repo_dir, "show", f"origin/{self.branch}:{vault_file}")

        if not force and os.path.exists(vault_path):
            try:
                local_modified = VaultFile.modified(vault_path)
                remote_modified = VaultFile.modified(incoming)
            except ValueError as e:
                raise RemoteError(str(e))
            if local_modified > remote_modified:
                raise RemoteError(
                    "Local vault is newer than the remote; refusing to overwrite. "
                    "Use --force to override."
                )

        with self._preserve_state(repo_dir):
            self._checkout_branch(repo_dir)
            # Fast-forward the branch to the remote and restore the vault file.
            # Only the vault file is tracked on this branch, so untracked files
            # in the directory are left untouched.
            self._git(repo_dir, "reset", "--hard", f"origin/{self.branch}")
