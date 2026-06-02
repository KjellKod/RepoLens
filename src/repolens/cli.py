"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .config import load_config
from .exit_codes import ExitCode, InputError

TOKEN_PATTERN = re.compile(r"(ghp_|github_pat_|ghs_)[A-Za-z0-9_]+")
PATH_PATTERN = re.compile(r"(/[^\s:]+)+")


class CommandStatus(Enum):
    SUCCESS = "success"
    FINDINGS_OPEN = "findings_open"


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    message: str = ""


CommandHandler = Callable[[argparse.Namespace], CommandResult]


STAGE_COMMANDS = ("discover", "scan", "resolve", "flag", "shortlist", "report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repolens")
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to an untracked local config file.",
    )
    subparsers = parser.add_subparsers(dest="command")

    for command_name in STAGE_COMMANDS:
        subparser = subparsers.add_parser(command_name)
        subparser.add_argument(
            "--findings-open",
            action="store_true",
            help=argparse.SUPPRESS,
        )
        subparser.set_defaults(handler=_stage_stub)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            return int(ExitCode.SUCCESS)

        load_config(Path.cwd(), args.config)
        result = args.handler(args)
        return _exit_code_for_result(result)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.USAGE_OR_INPUT_ERROR)
    except InputError as exc:
        print(_sanitize(str(exc)), file=sys.stderr)
        return int(ExitCode.USAGE_OR_INPUT_ERROR)
    except Exception as exc:
        print(_sanitize(f"Internal error: {exc}"), file=sys.stderr)
        return int(ExitCode.FINDINGS_OPEN)


def _stage_stub(args: argparse.Namespace) -> CommandResult:
    if args.findings_open:
        return CommandResult(CommandStatus.FINDINGS_OPEN, "findings remain open")
    return CommandResult(CommandStatus.SUCCESS, "skeleton command completed")


def _exit_code_for_result(result: CommandResult) -> int:
    if result.status is CommandStatus.SUCCESS:
        return int(ExitCode.SUCCESS)
    if result.status is CommandStatus.FINDINGS_OPEN:
        return int(ExitCode.FINDINGS_OPEN)
    raise InputError("Unknown command result")


def _sanitize(message: str) -> str:
    redacted = TOKEN_PATTERN.sub("[REDACTED_TOKEN]", message)
    return PATH_PATTERN.sub("[REDACTED_PATH]", redacted)
