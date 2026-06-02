"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from repolens.security.redaction import redact_tokens

from .config import load_config
from .data.errors import ArtifactError
from .discovery.gh import DEFAULT_GH_LIMIT, MAX_GH_LIMIT
from .discovery.pipeline import run_discover
from .exit_codes import ExitCode, InputError

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

# One-line help per stage, shown in `repolens --help` and each stage's own --help.
_STAGE_HELP = {
    "discover": "Find and categorize the repos under an owner; you approve the list.",
    "scan": "Inventory each repo's dependencies across all languages (read-only).",
    "resolve": "Resolve every dependency's license, cheapest trusted source first.",
    "flag": "Apply the license policy and flag risky or unresolved licenses.",
    "shortlist": "Resolve the flagged items with anchored evidence and your approval.",
    "report": "Assemble the deduplicated disclosure: main report plus appendices.",
}

_DESCRIPTION = (
    "RepoLens — an open-source license disclosure across every repository under an owner.\n"
    "It inventories dependencies in any language, flags commercial-use risks, and\n"
    "assembles an evidence-backed disclosure. Run the stages below in order."
)

_EPILOG = (
    "typical run:\n"
    "  repolens discover --owner <OWNER>   1. find + approve the repos\n"
    "  repolens scan                       2. inventory dependencies\n"
    "  repolens resolve                    3. resolve licenses\n"
    "  repolens flag                       4. flag risk / unknowns\n"
    "  repolens shortlist                  5. resolve the flags (with you)\n"
    "  repolens report                     6. build the disclosure\n"
    "\n"
    "Discovery and report are the checkpoints where you stay in control; the stages\n"
    "between run automatically and are resumable. Run `repolens <stage> --help` for a\n"
    "single stage. Full guide: docs/usage.md."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repolens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_DESCRIPTION,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="Path to an untracked local config file (owner, categories, policy).",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<stage>",
        title="stages (run in order)",
    )

    for command_name in STAGE_COMMANDS:
        subparser = subparsers.add_parser(
            command_name,
            help=_STAGE_HELP[command_name],
            description=_STAGE_HELP[command_name],
        )
        if command_name == "discover":
            subparser.add_argument(
                "--owner",
                required=True,
                metavar="OWNER",
                help="Runtime owner/org to enumerate with gh; never store this in source.",
            )
            subparser.add_argument(
                "--work-root",
                type=Path,
                default=Path("work"),
                metavar="DIR",
                help="Directory for discovered.json and repos.candidate.md (default: work).",
            )
            subparser.add_argument(
                "--limit",
                type=int,
                default=DEFAULT_GH_LIMIT,
                metavar="N",
                help=(
                    f"Maximum repos to ask gh for, 1-{MAX_GH_LIMIT} "
                    f"(default: {DEFAULT_GH_LIMIT})."
                ),
            )
            subparser.set_defaults(handler=_discover_command)
        else:
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
            parser.print_help()
            return int(ExitCode.SUCCESS)

        args.runtime_config = load_config(Path.cwd(), args.config)
        result = args.handler(args)
        return _exit_code_for_result(result)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.USAGE_OR_INPUT_ERROR)
    except (ArtifactError, InputError) as exc:
        print(_sanitize(str(exc)), file=sys.stderr)
        return int(ExitCode.USAGE_OR_INPUT_ERROR)
    except Exception as exc:
        print(_sanitize(f"Internal error: {exc}"), file=sys.stderr)
        return int(ExitCode.FINDINGS_OPEN)


def _stage_stub(args: argparse.Namespace) -> CommandResult:
    if args.findings_open:
        return CommandResult(CommandStatus.FINDINGS_OPEN, "findings remain open")
    return CommandResult(CommandStatus.SUCCESS, "skeleton command completed")


def _discover_command(args: argparse.Namespace) -> CommandResult:
    result = run_discover(
        owner=args.owner,
        work_root=args.work_root,
        config=args.runtime_config,
        limit=args.limit,
    )
    return CommandResult(
        CommandStatus.SUCCESS,
        (
            f"discovered {result.repository_count} repositories; "
            f"{result.candidate_count} candidates, "
            f"{result.hard_exclusion_count} hard exclusions"
        ),
    )


def _exit_code_for_result(result: CommandResult) -> int:
    if result.status is CommandStatus.SUCCESS:
        return int(ExitCode.SUCCESS)
    if result.status is CommandStatus.FINDINGS_OPEN:
        return int(ExitCode.FINDINGS_OPEN)
    raise InputError("Unknown command result")


def _sanitize(message: str) -> str:
    redacted = redact_tokens(message)
    return PATH_PATTERN.sub("[REDACTED_PATH]", redacted)
