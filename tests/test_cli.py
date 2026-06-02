"""End-to-end integration tests for the mimir CLI.

Each test runs commands as a real subprocess against a fresh, isolated vault:
a temporary HOME (so the config and vault live under it) and a clean session
temp file. Nothing is mocked — these exercise argument parsing, the crypto
layer, the on-disk vault format, and session handling together.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "hunter2"


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = tempfile.mkdtemp(prefix="mimir-test-")
        self.vault_path = os.path.join(self.home, ".config", "mimir", "vault.mimir")
        self.session_path = f"/tmp/mimir-{os.getuid()}"
        self._clear_session()

    def tearDown(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)
        self._clear_session()

    def _clear_session(self) -> None:
        try:
            os.unlink(self.session_path)
        except FileNotFoundError:
            pass

    def mimir(
        self, *args: str, password: Optional[str] = None, home: Optional[str] = None
    ) -> subprocess.CompletedProcess[str]:
        """Run `mimir <args>`. If `password` is given, feed it on stdin.

        `home` overrides HOME for this invocation, which simulates running on a
        different machine (used by the sync/recovery tests). A git committer
        identity is injected so commits work even when no global gitconfig is
        present.
        """
        env = dict(
            os.environ,
            HOME=home or self.home,
            GIT_AUTHOR_NAME="mimir-test",
            GIT_AUTHOR_EMAIL="mimir@test.invalid",
            GIT_COMMITTER_NAME="mimir-test",
            GIT_COMMITTER_EMAIL="mimir@test.invalid",
        )
        return subprocess.run(
            [sys.executable, "-m", "mimir", *args],
            input=password if password is None else password + "\n",
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=env,
        )

    def init_vault(self) -> None:
        r = self.mimir("init", password=f"{PASSWORD}\n{PASSWORD}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.vault_path))


class InitTests(CliTestCase):
    def test_init_creates_vault(self) -> None:
        self.init_vault()

    def test_init_twice_fails(self) -> None:
        self.init_vault()
        r = self.mimir("init", password=f"{PASSWORD}\n{PASSWORD}")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exists", r.stderr)

    def test_init_password_mismatch_fails(self) -> None:
        r = self.mimir("init", password="abc\nxyz")
        self.assertEqual(r.returncode, 1)
        self.assertIn("do not match", r.stderr)
        self.assertFalse(os.path.exists(self.vault_path))

    def test_init_empty_password_fails(self) -> None:
        r = self.mimir("init", password="\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("empty", r.stderr)


class VaultFormatTests(CliTestCase):
    def test_header_layout(self) -> None:
        self.init_vault()
        with open(self.vault_path, "rb") as f:
            raw = f.read()
        self.assertEqual(raw[:5], b"MIMIR")
        self.assertEqual(raw[5], 0x01)  # version
        modified = struct.unpack(">Q", raw[6:14])[0]
        self.assertGreater(modified, 1_700_000_000)  # a plausible recent epoch
        self.assertEqual(len(raw[14:46]), 32)  # salt
        self.assertGreaterEqual(len(raw), 58 + 16)  # header + tag

    def test_no_plaintext_leak(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "alex@example.com")
        with open(self.vault_path, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"gmail", raw)
        self.assertNotIn(b"alex@example.com", raw)

    def test_modified_advances_on_write(self) -> None:
        self.init_vault()
        with open(self.vault_path, "rb") as f:
            first = struct.unpack(">Q", f.read(14)[6:14])[0]
        # A second write must restamp the modified timestamp (>= the first).
        self.mimir("add", "gmail")
        with open(self.vault_path, "rb") as f:
            second = struct.unpack(">Q", f.read(14)[6:14])[0]
        self.assertGreaterEqual(second, first)


class NamespaceTests(CliTestCase):
    def test_add_and_list(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        self.mimir("add", "github")
        r = self.mimir("list")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Namespaces:", r.stdout)
        self.assertIn("gmail", r.stdout)
        self.assertIn("github", r.stdout)

    def test_list_empty(self) -> None:
        self.init_vault()
        r = self.mimir("list")
        self.assertIn("(no namespaces)", r.stdout)

    def test_add_duplicate_fails(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        r = self.mimir("add", "gmail")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exists", r.stderr)

    def test_delete_namespace(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        r = self.mimir("delete", "gmail")
        self.assertEqual(r.returncode, 0)
        self.assertIn("(no namespaces)", self.mimir("list").stdout)

    def test_delete_missing_namespace_fails(self) -> None:
        self.init_vault()
        r = self.mimir("delete", "nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)


class KeyTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.init_vault()
        self.mimir("add", "gmail")

    def test_set_and_get(self) -> None:
        self.mimir("set", "gmail", "user", "alex@example.com")
        r = self.mimir("get", "gmail", "user")
        self.assertEqual(r.stdout.strip(), "alex@example.com")

    def test_sensitive_is_masked_by_default(self) -> None:
        self.mimir("set", "gmail", "password", "s3cret", "-s")
        self.assertEqual(self.mimir("get", "gmail", "password").stdout.strip(), "***")
        revealed = self.mimir("get", "gmail", "password", "-r").stdout.strip()
        self.assertEqual(revealed, "s3cret")

    def test_show_masks_only_sensitive(self) -> None:
        self.mimir("set", "gmail", "user", "alex@example.com")
        self.mimir("set", "gmail", "password", "s3cret", "-s")
        out = self.mimir("show", "gmail").stdout
        self.assertIn("Namespace gmail:", out)
        self.assertIn("user: alex@example.com", out)
        self.assertIn("password: ***", out)
        revealed = self.mimir("show", "gmail", "-r").stdout
        self.assertIn("password: s3cret", revealed)

    def test_set_overwrites(self) -> None:
        self.mimir("set", "gmail", "user", "old")
        self.mimir("set", "gmail", "user", "new")
        self.assertEqual(self.mimir("get", "gmail", "user").stdout.strip(), "new")

    def test_get_missing_key_fails(self) -> None:
        r = self.mimir("get", "gmail", "nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_delete_key(self) -> None:
        self.mimir("set", "gmail", "user", "alex@example.com")
        r = self.mimir("delete", "gmail", "user")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.mimir("get", "gmail", "user").returncode, 1)


class SessionTests(CliTestCase):
    def test_session_reused_without_password(self) -> None:
        self.init_vault()  # init starts a session
        self.assertTrue(os.path.exists(self.session_path))
        # No password supplied: must succeed via the active session.
        r = self.mimir("add", "gmail")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_lock_then_reprompt(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "alex@example.com")
        self.assertEqual(self.mimir("lock").returncode, 0)
        self.assertFalse(os.path.exists(self.session_path))
        # Re-prompt: correct password unlocks again.
        r = self.mimir("get", "gmail", "user", password=PASSWORD)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "alex@example.com")

    def test_wrong_password_fails(self) -> None:
        self.init_vault()
        self.mimir("lock")
        r = self.mimir("get", "gmail", "user", password="wrongpw")
        self.assertEqual(r.returncode, 1)
        self.assertIn("Decryption failed", r.stderr)

    def test_wrong_password_clears_session(self) -> None:
        self.init_vault()
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "alex@example.com")
        self.mimir("lock")
        bad = self.mimir("get", "gmail", "user", password="wrongpw")
        self.assertEqual(bad.returncode, 1)
        # The bad key must not linger and lock the user out.
        self.assertFalse(os.path.exists(self.session_path))
        good = self.mimir("get", "gmail", "user", password=PASSWORD)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(good.stdout.strip(), "alex@example.com")

    def test_command_without_vault_fails(self) -> None:
        r = self.mimir("list")
        self.assertEqual(r.returncode, 1)
        self.assertIn("No vault found", r.stderr)


class ConfigTests(CliTestCase):
    def test_set_get_list(self) -> None:
        self.assertEqual(self.mimir("config", "set", "session-timeout", "60").returncode, 0)
        self.assertEqual(self.mimir("config", "get", "session-timeout").stdout.strip(), "60")
        out = self.mimir("config", "list").stdout
        self.assertIn("session-timeout=60", out)
        self.assertIn("vault=", out)

    def test_set_unknown_key_fails(self) -> None:
        r = self.mimir("config", "set", "bogus", "x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("Unknown config key", r.stderr)

    def test_custom_vault_path_is_used(self) -> None:
        custom = os.path.join(self.home, "my-vault.mimir")
        self.mimir("config", "set", "vault", custom)
        self.mimir("init", password=f"{PASSWORD}\n{PASSWORD}")
        self.assertTrue(os.path.exists(custom))
        self.assertFalse(os.path.exists(self.vault_path))


class SyncTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        # A bare repo on disk acts as the remote (a local path is a valid git
        # URL, so no credentials or network are involved).
        self.remote_dir = tempfile.mkdtemp(prefix="mimir-remote-")
        subprocess.run(
            ["git", "init", "--bare", self.remote_dir],
            check=True,
            capture_output=True,
        )
        self.init_vault()
        self.mimir("config", "set", "remote", self.remote_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.remote_dir, ignore_errors=True)
        super().tearDown()

    def test_push_without_remote_fails(self) -> None:
        home2 = tempfile.mkdtemp(prefix="mimir-noremote-")
        self.addCleanup(shutil.rmtree, home2, ignore_errors=True)
        self._clear_session()
        self.mimir("init", password=f"{PASSWORD}\n{PASSWORD}", home=home2)
        r = self.mimir("push", home=home2)
        self.assertEqual(r.returncode, 1)
        self.assertIn("No remote configured", r.stderr)

    def test_doomsday_recovery(self) -> None:
        # Machine 1: populate the vault and push it.
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "alex@example.com")
        self.mimir("set", "gmail", "password", "s3cret", "-s")
        r = self.mimir("push")
        self.assertEqual(r.returncode, 0, r.stderr)

        # Machine 2: a bare home with no local vault and no session. Configure
        # the same remote and pull — recovery from scratch.
        home2 = tempfile.mkdtemp(prefix="mimir-recover-")
        self.addCleanup(shutil.rmtree, home2, ignore_errors=True)
        self._clear_session()
        self.mimir("config", "set", "remote", self.remote_dir, home=home2)
        pr = self.mimir("pull", home=home2)
        self.assertEqual(pr.returncode, 0, pr.stderr)
        vault2 = os.path.join(home2, ".config", "mimir", "vault.mimir")
        self.assertTrue(os.path.exists(vault2))

        # The recovered vault decrypts with the master password.
        self._clear_session()
        got = self.mimir("get", "gmail", "password", "-r", home=home2, password=PASSWORD)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(got.stdout.strip(), "s3cret")

    def test_pull_refuses_when_local_newer(self) -> None:
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "remote-value")
        self.assertEqual(self.mimir("push").returncode, 0)

        # Advance the local vault past the remote (the header timestamp is
        # second-granular, so wait a beat to guarantee a strictly newer stamp).
        time.sleep(1.1)
        self.mimir("set", "gmail", "user", "local-value")

        refused = self.mimir("pull")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("newer", refused.stderr)
        self.assertEqual(self.mimir("get", "gmail", "user").stdout.strip(), "local-value")

        # --force discards the local change and restores the remote vault.
        forced = self.mimir("pull", "-f")
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertEqual(self.mimir("get", "gmail", "user").stdout.strip(), "remote-value")

    def test_git_commands_are_logged(self) -> None:
        self.mimir("add", "gmail")
        r = self.mimir("push")
        self.assertEqual(r.returncode, 0, r.stderr)
        # Each git invocation is echoed to stderr for auditability.
        self.assertIn("$ git", r.stderr)
        self.assertIn("commit", r.stderr)
        self.assertIn("push", r.stderr)

    def test_push_works_with_gitignore_excluding_vault(self) -> None:
        # The vault directory may already use a .gitignore that excludes the
        # vault file; push must still track it (forced add).
        vault_dir = os.path.dirname(self.vault_path)
        with open(os.path.join(vault_dir, ".gitignore"), "w") as f:
            f.write("*.mimir\n")
        self.mimir("add", "gmail")
        self.mimir("set", "gmail", "user", "alex@example.com")
        r = self.mimir("push")
        self.assertEqual(r.returncode, 0, r.stderr)

        # The vault really reached the remote: recover it on a fresh machine.
        home2 = tempfile.mkdtemp(prefix="mimir-gi-")
        self.addCleanup(shutil.rmtree, home2, ignore_errors=True)
        self._clear_session()
        self.mimir("config", "set", "remote", self.remote_dir, home=home2)
        self.assertEqual(self.mimir("pull", home=home2).returncode, 0)
        self._clear_session()
        got = self.mimir("get", "gmail", "user", home=home2, password=PASSWORD)
        self.assertEqual(got.stdout.strip(), "alex@example.com", got.stderr)

    def test_push_is_idempotent(self) -> None:
        self.mimir("add", "gmail")
        self.assertEqual(self.mimir("push").returncode, 0)
        # A second push with no changes must still succeed (nothing to commit).
        again = self.mimir("push")
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_push_preserves_unrelated_branch_and_changes(self) -> None:
        # The vault may share a directory with an unrelated repo the user is
        # working in. Pushing the vault (on its own branch) must leave the
        # user on their branch with their uncommitted work intact.
        vault_dir = os.path.dirname(self.vault_path)
        git_env = dict(
            os.environ,
            GIT_AUTHOR_NAME="user",
            GIT_AUTHOR_EMAIL="user@test.invalid",
            GIT_COMMITTER_NAME="user",
            GIT_COMMITTER_EMAIL="user@test.invalid",
        )

        def git(*args: str) -> None:
            subprocess.run(
                ["git", "-C", vault_dir, *args],
                check=True,
                capture_output=True,
                text=True,
                env=git_env,
            )

        def current_branch() -> str:
            return subprocess.run(
                ["git", "-C", vault_dir, "branch", "--show-current"],
                capture_output=True,
                text=True,
                env=git_env,
            ).stdout.strip()

        # A pre-existing repo on branch "work" with a committed tracked file...
        git("init")
        git("checkout", "-b", "work")
        work_file = os.path.join(vault_dir, "work.txt")
        with open(work_file, "w") as f:
            f.write("committed\n")
        git("add", "work.txt")
        git("commit", "-m", "work")
        # ...and an uncommitted edit to it.
        with open(work_file, "w") as f:
            f.write("uncommitted edit\n")

        self.mimir("add", "gmail")
        r = self.mimir("push")  # vault branch defaults to "main", distinct from "work"
        self.assertEqual(r.returncode, 0, r.stderr)

        # Back on the user's branch with their uncommitted change restored.
        self.assertEqual(current_branch(), "work")
        with open(work_file) as f:
            self.assertEqual(f.read(), "uncommitted edit\n")


if __name__ == "__main__":
    unittest.main()
