# Mimir

A minimal, self-contained CLI vault for managing personal account secrets. Store all your credentials in a single encrypted file — recoverable anywhere with just a password.

---

## Objectives

### 1. Doomsday Recovery
If all devices are lost, the user must be able to recover every account from scratch using only the vault file and the master password. The vault file can be stored anywhere publicly accessible (cloud storage, git repo, personal server) without risk, since all data is encrypted.

### 2. Daily Driver
The tool must be ergonomic enough for regular, everyday use — not just a break-glass emergency tool. Low friction: single password unlock per session, short commands, readable output.

### 3. Universal Portability
Runs on any Unix-like system (Linux, macOS) with Python 3.9+ and a single `pip install`. No daemon, no account login, no OS-specific integration required to get started.

### 4. Simplicity
Small, auditable codebase. No magic, no abstractions beyond what the task requires. A user should be able to read the full source and understand exactly what the tool does with their data.

---

## Specifications

### Data Model

**Namespaces** are named groups, each representing one account or service (e.g. `gmail`, `github`, `spotify`).

Each namespace contains **key-value pairs**:
- Keys are ASCII strings, always visible once the vault is unlocked
- Values are UTF-8 strings
- Each value is marked either **sensitive** or **non-sensitive** at the time of creation
  - Non-sensitive values are displayed freely (e.g. username, email, recovery URL)
  - Sensitive values are masked as `***` by default; a `--reveal` flag is required to display them

---

### Security

**Encryption:** The entire vault is encrypted as a single blob using **AES-256-GCM** (authenticated encryption). There is no plaintext data in the vault file — namespace names, keys, and all values are encrypted.

**Key derivation:** The master password is stretched using **scrypt** (memory-hard, resistant to brute-force) with a random salt generated at `init` time. Parameters are `n=2**20, r=8, p=1` (~1 GiB of memory per derivation), chosen so the publicly-stored blob resists offline brute-force. The cost is paid once per session unlock, not per command.

**Integrity:** AES-GCM provides built-in authentication. The fixed-size file header (magic, version, modified timestamp, salt, nonce) is passed as **associated data (AAD)** so it is authenticated alongside the ciphertext — tampering with any header field, not just the ciphertext, causes decryption to fail with an explicit error.

**Master password:** Set once at `mimir init`. There is no password recovery — losing the master password means losing access to the vault.

**Dependency:** [`cryptography`](https://cryptography.io) — the single allowed external dependency, used for AES-GCM and scrypt.

---

### Session Management

The master password is required **once per session**. On first use, the user is prompted for their password; the derived encryption key is then written to a temp file (`/tmp/mimir-<uid>`, permissions `600`). Subsequent commands reuse this key without prompting.

- The session temp file is deleted by `mimir lock` or on system reboot
- The session has a configurable idle timeout (default: 15 minutes); after inactivity the temp file is removed and the next command re-prompts
- Any command that needs vault access will auto-prompt if no active session exists
- The temp path is fixed and world-predictable, so it is opened with `O_NOFOLLOW` (and recreated, not opened-in-place, on write) and the read side verifies via `fstat` that the file is a regular file owned by the current user. This prevents a local attacker from pre-planting the path as a symlink to redirect the key write or truncate an arbitrary file.

---

### Vault File Format

A single binary file with the following layout:

```
[ Magic bytes: 5 bytes  ] b"MIMIR"
[ Version:     1 byte   ] format version (currently 0x01)
[ Modified:    8 bytes  ] last-modified timestamp (Unix epoch, big-endian uint64)
[ Salt:       32 bytes  ] scrypt salt
[ Nonce:      12 bytes  ] AES-GCM nonce
[ Ciphertext: N bytes   ] AES-GCM encrypted vault data
[ Tag:        16 bytes  ] AES-GCM authentication tag
```

The encrypted payload is a UTF-8 encoded JSON blob containing the full vault (namespaces, keys, values, sensitive flags). A new nonce is generated on every write.

---

### Configuration

A plain-text config file lives at `~/.config/mimir/config` (key=value format, one per line). It is never encrypted.

Managed via:

```
mimir config set <key> <value>
mimir config get <key>
mimir config list
```

Supported config keys:

| Key | Default | Description |
|---|---|---|
| `vault` | `~/.config/mimir/vault.mimir` | Path to the vault file |
| `session-timeout` | `900` | Session idle timeout in seconds (0 = no timeout) |
| `remote` | _(none)_ | Git remote URL used by `push`/`pull` (e.g. a public GitHub repo) |
| `branch` | `main` | Branch to push to and pull from |

---

### Synchronization

For the doomsday-recovery objective the vault must live somewhere reachable from a bare machine. Mimir syncs the vault file to a **git remote** — typically a public GitHub repository the user creates beforehand. The vault blob is fully encrypted, so a public repo is safe, and git's history gives free, recoverable snapshots of every write.

**Setup:** the user points mimir at an existing remote once:

```
mimir config set remote git@github.com:alice/my-vault.git
mimir config set branch main          # optional, defaults to main
```

**Backend abstraction:** sync is defined behind a small `Remote` interface (`push(vault_path)` / `pull(vault_path)`), with a single `GitRemote` implementation. This keeps `subprocess` calls out of the command layer and leaves room for other backends later. There is exactly one backend today.

**Git is an optional runtime dependency.** It is not required to use mimir locally. `push`/`pull` detect the `git` executable at runtime and exit with a clear error if it is missing; no other command depends on it.

**Authentication is git's job.** Mimir never handles credentials. It assumes the user's existing git setup (SSH key or credential helper) can push to the configured remote.

**Repository location:** the git repository lives in the directory that contains the vault file (`dirname(vault)`), so it follows a custom `vault` path rather than being hardcoded.

**Repository and branch handling:** on each `push`/`pull`, mimir inspects the directory's git state (e.g. `git status`) and adapts rather than assuming ownership of the repo:

- If the directory is **not** a git repository, mimir lazily runs `git init` and configures the `remote`.
- It then checks the current branch against the configured `branch`. If they already match, it proceeds.
- If they differ, mimir checks the branch out — **creating it as an orphan branch** if it does not exist, so the vault's history is independent of any other branch already present (e.g. an unrelated `main`). This lets mimir share a directory that is already a git repo without entangling its history.

Mimir **does not own or create a `.gitignore`** — the directory may already have one in use. Instead it stages **only the vault file** by explicit path (never `git add -A` / `add .`), so nothing else in the directory is ever committed.

**Preserving the user's working state:** because the vault may share a directory with an unrelated repo the user is actively working in, mimir must never disturb their current branch or uncommitted work when it switches to the vault branch (the `pull` path even runs `git reset --hard`). So when a `push`/`pull` will switch *away* from the current branch, mimir:

1. Records the current branch (or commit, if detached/unborn) and, if there are tracked staged/unstaged changes, stashes them (`git stash push` — **tracked changes only**, so the untracked vault file is left in place).
2. Switches to the vault branch and performs the push/pull.
3. In a `finally` step (so it runs even if the operation fails), checks the original branch back out and pops the stash.

When mimir is already on the vault branch (a dedicated vault repo) this is a no-op, so the pending vault changes stay in the working tree to be committed. Untracked files are never at risk: `git checkout`/`reset --hard` leave them untouched.

**Staleness guard:** `pull` compares the incoming vault's `modified` header timestamp against the local file's. If the local file is newer, `pull` refuses to overwrite it (to avoid clobbering un-pushed changes) and tells the user, unless `-f` / `--force` is given. `push` does not need this guard — it always advances history.

---

### CLI Commands

#### Vault lifecycle

| Command | Description |
|---|---|
| `mimir init` | Create a new vault, set the master password |
| `mimir lock` | End the current session (delete session temp file) |

#### Synchronization

| Command | Description |
|---|---|
| `mimir push` | Commit the vault and push it to the configured git `remote`/`branch` |
| `mimir pull` | Fetch the vault from the remote; refuses to overwrite a newer local file unless `-f` / `--force` |

#### Configuration

| Command | Description |
|---|---|
| `mimir config set <key> <value>` | Set a config value |
| `mimir config get <key>` | Get a config value |
| `mimir config list` | Show all config values |

#### Namespaces

| Command | Description |
|---|---|
| `mimir list` | List all namespaces |
| `mimir add <namespace>` | Create a new namespace |
| `mimir delete <namespace>` | Delete a namespace and all its keys |
| `mimir show <namespace> [-r]` | Show all key-value pairs in a namespace; `-r` / `--reveal` unmasks sensitive values |

#### Keys

| Command | Description |
|---|---|
| `mimir get <namespace> <key> [-r]` | Get the value of a key; `-r` / `--reveal` unmasks if sensitive |
| `mimir set <namespace> <key> <value> [-s]` | Set a key-value pair; `-s` / `--sensitive` marks the value as sensitive |
| `mimir delete <namespace> <key>` | Delete a key |

---

### Technical Constraints

- **Language:** Python 3.9+
- **Dependencies:** `cryptography` only (Python). `git` is an optional runtime tool, required only for `push`/`pull`.
- **Platform:** Unix-like systems (Linux, macOS); Windows not supported
- **Stdlib used:** `argparse`, `getpass`, `hashlib`, `os`, `json`, `struct`, `tempfile`
