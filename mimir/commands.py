from __future__ import annotations

import argparse
import getpass
import os
import sys

from mimir.config import Config, VALID_KEYS
from mimir.crypto import SALT_SIZE, VaultFile
from mimir.model import Vault
from mimir.remote import GitRemote, Remote, RemoteError
from mimir.session import Session


def _vault_path(config: Config) -> str:
    return os.path.expanduser(config.require("vault"))


def _timeout(config: Config) -> int:
    return int(config.require("session-timeout"))


def open_vault(config: Config) -> tuple[Vault, Session, str]:
    """Unlock and read the vault. Returns (vault, session, vault_path).

    Reuses the active session if available; otherwise prompts for the master
    password, derives the key, and starts a new session.
    """
    vault_path = _vault_path(config)
    if not os.path.exists(vault_path):
        print("No vault found. Run `mimir init` first.", file=sys.stderr)
        sys.exit(1)

    timeout = _timeout(config)
    session = Session.resume(timeout)
    if session is None:
        salt = VaultFile.salt(vault_path)
        password = getpass.getpass("Master password: ")
        session = Session.start(password, salt, timeout)

    try:
        vault = VaultFile.read(vault_path, session)
    except ValueError as e:
        # The session key is wrong (or the vault is corrupt); drop it so the
        # next command re-prompts instead of locking the user out.
        Session.lock()
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    return vault, session, vault_path


# ---------------------------------------------------------------------------
# Vault lifecycle
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace, config: Config) -> None:
    vault_path = _vault_path(config)
    if os.path.exists(vault_path):
        print(f"Vault already exists at {vault_path}", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Master password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    vault_dir = os.path.dirname(vault_path)
    if vault_dir:
        os.makedirs(vault_dir, exist_ok=True)

    vault = Vault(salt=os.urandom(SALT_SIZE))
    session = Session.start(password, vault.salt, _timeout(config))
    VaultFile.write(vault_path, vault, session)
    print(f"Vault created at {vault_path}")


def cmd_lock(args: argparse.Namespace, config: Config) -> None:
    Session.lock()
    print("Session locked.")


# ---------------------------------------------------------------------------
# Synchronization
# ---------------------------------------------------------------------------

def _remote(config: Config) -> Remote:
    url = config.get("remote")
    if not url:
        print("No remote configured. Run `mimir config set remote <url>`.", file=sys.stderr)
        sys.exit(1)
    return GitRemote(url, config.require("branch"))


def cmd_push(args: argparse.Namespace, config: Config) -> None:
    vault_path = _vault_path(config)
    if not os.path.exists(vault_path):
        print("No vault found. Run `mimir init` first.", file=sys.stderr)
        sys.exit(1)
    remote = _remote(config)
    try:
        remote.push(vault_path)
    except RemoteError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    print("Vault pushed.")


def cmd_pull(args: argparse.Namespace, config: Config) -> None:
    vault_path = _vault_path(config)
    remote = _remote(config)
    try:
        remote.pull(vault_path, force=args.force)
    except RemoteError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    print("Vault pulled.")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def cmd_config_set(args: argparse.Namespace, config: Config) -> None:
    try:
        config.set(args.key, args.value)
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        print(f"Valid keys: {', '.join(sorted(VALID_KEYS))}", file=sys.stderr)
        sys.exit(1)


def cmd_config_get(args: argparse.Namespace, config: Config) -> None:
    value = config.get(args.key)
    if value is None:
        print(f"Unknown config key: {args.key!r}", file=sys.stderr)
        sys.exit(1)
    print(value)


def cmd_config_list(args: argparse.Namespace, config: Config) -> None:
    for key, value in sorted(config.list().items()):
        print(f"{key}={value}")


# ---------------------------------------------------------------------------
# Namespaces and keys
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace, config: Config) -> None:
    vault, _, _ = open_vault(config)
    if not vault.namespaces:
        print("(no namespaces)")
        return
    print("Namespaces:")
    for ns in vault.namespaces:
        print(f"  {ns.name}")


def cmd_add(args: argparse.Namespace, config: Config) -> None:
    vault, session, vault_path = open_vault(config)
    if vault.find(args.namespace) is not None:
        print(f"Namespace '{args.namespace}' already exists.", file=sys.stderr)
        sys.exit(1)
    vault.add(args.namespace)
    VaultFile.write(vault_path, vault, session)
    print(f"Namespace '{args.namespace}' created.")


def cmd_delete(args: argparse.Namespace, config: Config) -> None:
    vault, session, vault_path = open_vault(config)

    if args.key is not None:
        ns = vault.find(args.namespace)
        if ns is None:
            print(f"Namespace '{args.namespace}' not found.", file=sys.stderr)
            sys.exit(1)
        if not ns.delete(args.key):
            print(f"Key '{args.key}' not found in '{args.namespace}'.", file=sys.stderr)
            sys.exit(1)
        VaultFile.write(vault_path, vault, session)
        print(f"Key '{args.key}' deleted from '{args.namespace}'.")
    else:
        if not vault.delete(args.namespace):
            print(f"Namespace '{args.namespace}' not found.", file=sys.stderr)
            sys.exit(1)
        VaultFile.write(vault_path, vault, session)
        print(f"Namespace '{args.namespace}' deleted.")


def cmd_show(args: argparse.Namespace, config: Config) -> None:
    vault, _, _ = open_vault(config)
    ns = vault.find(args.namespace)
    if ns is None:
        print(f"Namespace '{args.namespace}' not found.", file=sys.stderr)
        sys.exit(1)
    if not ns.entries:
        print(f"(no entries in '{args.namespace}')")
        return
    print(f"Namespace {args.namespace}:")
    for entry in ns.entries:
        display = entry.value if (not entry.sensitive or args.reveal) else "***"
        print(f"  {entry.key}: {display}")


def cmd_get(args: argparse.Namespace, config: Config) -> None:
    vault, _, _ = open_vault(config)
    ns = vault.find(args.namespace)
    if ns is None:
        print(f"Namespace '{args.namespace}' not found.", file=sys.stderr)
        sys.exit(1)
    entry = ns.get(args.key)
    if entry is None:
        print(f"Key '{args.key}' not found in '{args.namespace}'.", file=sys.stderr)
        sys.exit(1)
    if entry.sensitive and not args.reveal:
        print("***")
    else:
        print(entry.value)


def cmd_set(args: argparse.Namespace, config: Config) -> None:
    vault, session, vault_path = open_vault(config)
    ns = vault.find(args.namespace)
    if ns is None:
        print(f"Namespace '{args.namespace}' not found.", file=sys.stderr)
        sys.exit(1)
    ns.set(args.key, args.value, args.sensitive)
    VaultFile.write(vault_path, vault, session)
    suffix = " (sensitive)" if args.sensitive else ""
    print(f"Set '{args.key}'{suffix} in '{args.namespace}'.")
