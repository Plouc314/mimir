# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mimir is a minimal CLI vault for personal account secrets: the entire vault is a single AES-256-GCM-encrypted file recoverable anywhere with just the master password. Design priorities, in order: doomsday recoverability, daily-driver ergonomics, portability (Python 3.9+, `pip install`, Unix only), and a small auditable codebase. See `specs.md` for the authoritative spec and `README.md` for the user-facing overview.

## Commands

```bash
uv sync                              # install (deps + the mimir entry point)
uv run python -m mimir <args>        # run the CLI from source
uv run python -m unittest discover tests   # run the full test suite
uv run python -m unittest tests.test_cli.KeyTests.test_set_and_get   # run a single test
```

Tests are **end-to-end integration tests only** (`tests/test_cli.py`); there are no unit tests by design (`conventions.md`). Each test runs `python -m mimir` as a real subprocess with a temporary `HOME`, so it exercises argument parsing, crypto, the on-disk format, and session handling together. Tests share the real session temp file `/tmp/mimir-<uid>` and clear it in setUp/tearDown — be aware they touch global state outside the temp HOME.

## Architecture

The flow for every command is: `cli.py` (argparse) → a `cmd_*` function in `commands.py` → `open_vault()` (session + crypto) → `model.Vault` mutation → `write_vault_file()`.

- **`cli.py`** — builds the argparse tree; each subcommand sets `func` to a `commands.cmd_*` handler. `main()` calls `func(args, Config())`. Note `delete` takes an optional positional `key`, so it dispatches to either namespace- or key-deletion inside `cmd_delete`.
- **`commands.py`** — one `cmd_*(args, config)` per command. `open_vault()` is the shared unlock path: resume an active session or prompt for the password, then decrypt. On a decryption failure it calls `Session.lock()` so a bad key doesn't lock the user out on the next run. Handlers print to stderr and `sys.exit(1)` on errors.
- **`crypto.py`** — the vault file format and the only place that touches `cryptography`. scrypt (`derive_key`, n=2^20, ~1 GiB) for KDF, AESGCM for the blob. Header layout is fixed (`HEADER_SIZE = 58`): magic(5)+version(1)+modified(8)+salt(32)+nonce(12), then ciphertext+tag. The header is passed as AES-GCM associated data (AAD) so all header fields are authenticated, not just the ciphertext. `read_salt()` reads the salt without decrypting (needed before the key exists). A fresh nonce is generated on every write.
- **`session.py`** — the derived 32-byte key is cached in `/tmp/mimir-<uid>` (mode 0600) with an 8-byte last-access timestamp. `resume()` enforces the idle timeout and refreshes the timestamp on each use; `lock()` deletes the file. The plaintext password is never stored — only the derived key. The fixed temp path is opened with `O_NOFOLLOW` (and recreated rather than opened-in-place on write); `resume()` `fstat`-checks it is a regular file owned by the current uid, to defend against symlink pre-planting in `/tmp`.
- **`model.py`** — pure data: `Vault` → `Namespace` → `Entry` dataclasses with JSON (de)serialization. Only `namespaces` is serialized; `salt`/`version`/`modified` live in the file header and are stamped by `crypto.py`, not the JSON. Lookups (`find`/`get`) are linear scans.
- **`config.py`** — plain-text `~/.config/mimir/config` (`key=value`), never encrypted. Only keys in `VALID_KEYS` (`vault`, `session-timeout`, `branch`, `remote`) are accepted; unknown keys raise `KeyError`. Defaults are merged on read, so the file only stores overrides. `remote` is the one valid key with no default (unset until configured), so `VALID_KEYS` is `set(DEFAULTS) | {"remote"}`.
- **`remote.py`** — git-backed vault sync (`mimir push`/`pull`). A `Remote` ABC with a single `GitRemote` implementation that shells out to `git` (no new Python dependency; `git` is detected at runtime, error if missing). The repo is `dirname(vault)`; mimir never creates a `.gitignore` and only ever stages the vault file by explicit path. The vault lives on its own branch, created as an **orphan** when absent so it can coexist with an unrelated repo already in the directory. When a push/pull must switch away from the current branch, `_preserve_state` stashes the user's tracked changes, runs the operation on the vault branch, then restores the original branch and pops the stash (a no-op when already on the vault branch) — so syncing never clobbers unrelated working-tree changes. `pull` compares the incoming vault's `modified` header against the local file and refuses to overwrite a newer local copy unless `--force`. Auth is left entirely to the user's git setup.

## Conventions (from `conventions.md`)

- Target Python **3.9**: every module starts with `from __future__ import annotations`; use builtin generics (`list[str]`) but `Optional`/`Union` from `typing` (not `X | Y`). Use `getuid`, `/tmp`, etc. freely — Windows is explicitly unsupported.
- All imports at the top, no deferred/inline imports (the one exception is `TYPE_CHECKING` for type-only imports, as in `crypto.py`).
- Model every domain concept as a class/dataclass — no bare dicts or tuples for structured data.
- Single external dependency: `cryptography`. Don't add others; everything else is stdlib.
- No mutable module-level globals; constants are `UPPER_SNAKE_CASE`.
