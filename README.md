# Mimir

A minimal, self-contained CLI vault for your account secrets. Everything lives in a single encrypted file you can store anywhere — recover it on any machine with just your master password.

- **Doomsday recovery** — lose every device and still get all your accounts back from the vault file and your password.
- **Daily driver** — one unlock per session, short commands, readable output.
- **Portable** — Python 3.9+, a single `pip install`, any Linux/macOS box. No daemon, no account, no cloud lock-in.
- **Simple & auditable** — small codebase, one dependency (`cryptography`). The whole vault is one AES-256-GCM blob; nothing is stored in plaintext.

## How it works

The vault is a single file encrypted with **AES-256-GCM**. Your master password is stretched with **scrypt** to derive the key — namespace names, keys, and values are all inside the encrypted blob, so the file is safe to keep anywhere public (a Git repo, cloud storage, a USB stick).

Secrets are organized into **namespaces** (one per account/service), each holding **key–value pairs**. Values can be marked **sensitive**, in which case they are masked as `***` unless you pass `--reveal`.

## Setup

Requires Python 3.9+ on Linux or macOS. `git` is optional and only needed for `push`/`pull`.

```sh
pip install mimir
```

Or run from a checkout with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run mimir --help
```

Create your vault and set the master password (asked once, no recovery if lost):

```sh
mimir init
```

By default the vault lives at `~/.config/mimir/vault.mimir`. Point it elsewhere if you like:

```sh
mimir config set vault ~/Dropbox/secrets/vault.mimir
```

### Sync to a Git remote (recommended for recovery)

So you can recover from scratch, sync the vault to a Git remote — a **public GitHub repo is fine**, since the file is fully encrypted. Create an empty repo, then:

```sh
mimir config set remote git@github.com:you/my-vault.git
mimir config set branch main          # optional, defaults to main
mimir push
```

Mimir uses your existing Git credentials and only ever tracks the vault file. To recover on a fresh machine, install mimir, set the same `remote`, and pull:

```sh
mimir config set remote git@github.com:you/my-vault.git
mimir pull
mimir show gmail --reveal
```

## Usage

The master password is asked once per session (default idle timeout: 15 minutes), then cached so subsequent commands don't prompt. Run `mimir lock` to end the session immediately.

### Namespaces

```sh
mimir add gmail                 # create a namespace
mimir list                      # list all namespaces
mimir show gmail                # show its entries (sensitive values masked)
mimir show gmail --reveal       # ...with sensitive values unmasked
mimir delete gmail              # delete the namespace and all its keys
```

### Keys

```sh
mimir set gmail email alex@example.com        # non-sensitive value
mimir set gmail password 'hunter2' --sensitive   # masked by default
mimir get gmail email                         # -> alex@example.com
mimir get gmail password                      # -> ***
mimir get gmail password --reveal             # -> hunter2
mimir delete gmail password                   # delete a single key
```

`-r` / `-s` are short forms of `--reveal` / `--sensitive`.

### Sync

```sh
mimir push          # commit the vault and push to the configured remote
mimir pull          # fetch the vault; refuses to overwrite a newer local copy
mimir pull --force  # overwrite the local vault regardless
```

### Session & config

```sh
mimir lock                              # end the session now
mimir config list                       # show all config values
mimir config get session-timeout
mimir config set session-timeout 0      # 0 = never time out
```

| Config key | Default | Description |
|---|---|---|
| `vault` | `~/.config/mimir/vault.mimir` | Path to the vault file |
| `session-timeout` | `900` | Session idle timeout in seconds (`0` = no timeout) |
| `remote` | _(unset)_ | Git remote URL for `push`/`pull` |
| `branch` | `main` | Branch to push to and pull from |

Config is a plain-text file at `~/.config/mimir/config` and is never encrypted.

## Security notes

- The master password is set once at `mimir init`. **There is no recovery** — lose it and the vault is unreadable.
- The derived key is cached for the session in `/tmp/mimir-<uid>` (mode `0600`), never the password itself. It is removed by `mimir lock`, on reboot, or after the idle timeout.
- AES-GCM authenticates the file: any tampering causes decryption to fail with an explicit error.
