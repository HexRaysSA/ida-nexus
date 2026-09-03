"""Command-line interface for ida-nexus."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

_COMMAND_HELP = {
    "mcp": "run the MCP server",
    "dashboard": "inspect MCP session logs",
    "logs": "export MCP session logs to ZIP",
    "reference": "query the ida-domain API reference",
    "python": "execute Python against an IDA database",
}

_COMMAND_HIDDEN = (
    "worker",
    "benchmark",
    "exec",
)


class _HelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # argparse does not include subcommand names when calculating the help
        # column, causing longer names to put their descriptions on a new line.
        self._action_max_length = max(
            self._action_max_length,
            max(map(len, _COMMAND_HELP)) + 4,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-nexus",
        description="IDA Nexus command-line tools",
        formatter_class=_HelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, help_text in _COMMAND_HELP.items():
        commands.add_parser(name, add_help=False, help=help_text)
    return parser


def _command(name: str) -> Callable[[list[str] | None], int]:
    # Imports are intentionally lazy so lightweight commands do not initialize
    # the MCP server, dashboard, or idalib-facing modules unnecessarily.
    if name == "mcp":
        from .mcp import cli

        return cli
    if name == "reference":
        from ida_nexus.reference import cli

        return cli
    if name == "dashboard":
        from .dashboard import cli

        return cli
    if name in {"python", "exec"}:
        from .python import main

        return main
    if name == "logs":
        from .logs import main

        return main
    if name == "benchmark":
        from .benchmark import main

        return main
    if name == "worker":
        from .worker import main

        return main
    raise KeyError(name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not arguments:
        parser.print_help()
        return 0
    if arguments[0] in {"-h", "--help"}:
        parser.print_help()
        return 0

    command = arguments.pop(0)
    if command not in _COMMAND_HELP and command not in _COMMAND_HIDDEN:
        parser.print_help(sys.stderr)
        parser.exit(
            2,
            f"\n{parser.prog}: error: argument COMMAND: invalid choice: {command!r}\n",
        )
    return _command(command)(arguments)
