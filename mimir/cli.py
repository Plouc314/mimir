from __future__ import annotations

import argparse

from mimir import commands
from mimir.config import Config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mimir", description="Encrypted CLI vault")
    sub = parser.add_subparsers(dest="command", metavar="command")

    init_p = sub.add_parser("init", help="Create a new vault and set the master password")
    init_p.set_defaults(func=commands.cmd_init)

    lock_p = sub.add_parser("lock", help="End the current session")
    lock_p.set_defaults(func=commands.cmd_lock)

    push_p = sub.add_parser("push", help="Push the vault to the configured git remote")
    push_p.set_defaults(func=commands.cmd_push)

    pull_p = sub.add_parser("pull", help="Pull the vault from the configured git remote")
    pull_p.add_argument(
        "-f", "--force", action="store_true", help="Overwrite a newer local vault"
    )
    pull_p.set_defaults(func=commands.cmd_pull)

    config_p = sub.add_parser("config", help="Manage configuration")
    config_p.set_defaults(func=lambda *_: config_p.print_help())
    config_sub = config_p.add_subparsers(dest="config_command", metavar="subcommand")
    cfg_set = config_sub.add_parser("set", help="Set a config value")
    cfg_set.add_argument("key")
    cfg_set.add_argument("value")
    cfg_set.set_defaults(func=commands.cmd_config_set)
    cfg_get = config_sub.add_parser("get", help="Get a config value")
    cfg_get.add_argument("key")
    cfg_get.set_defaults(func=commands.cmd_config_get)
    cfg_list = config_sub.add_parser("list", help="Show all config values")
    cfg_list.set_defaults(func=commands.cmd_config_list)

    list_p = sub.add_parser("list", help="List all namespaces")
    list_p.set_defaults(func=commands.cmd_list)

    add_p = sub.add_parser("add", help="Create a new namespace")
    add_p.add_argument("namespace")
    add_p.set_defaults(func=commands.cmd_add)

    del_p = sub.add_parser("delete", help="Delete a namespace or a key")
    del_p.add_argument("namespace")
    del_p.add_argument("key", nargs="?", default=None)
    del_p.set_defaults(func=commands.cmd_delete)

    show_p = sub.add_parser("show", help="Show all key-value pairs in a namespace")
    show_p.add_argument("namespace")
    show_p.add_argument("-r", "--reveal", action="store_true", help="Unmask sensitive values")
    show_p.set_defaults(func=commands.cmd_show)

    get_p = sub.add_parser("get", help="Get the value of a key")
    get_p.add_argument("namespace")
    get_p.add_argument("key")
    get_p.add_argument("-r", "--reveal", action="store_true", help="Unmask if sensitive")
    get_p.set_defaults(func=commands.cmd_get)

    set_p = sub.add_parser("set", help="Set a key-value pair")
    set_p.add_argument("namespace")
    set_p.add_argument("key")
    set_p.add_argument("value")
    set_p.add_argument("-s", "--sensitive", action="store_true", help="Mark value as sensitive")
    set_p.set_defaults(func=commands.cmd_set)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return

    func(args, Config())
