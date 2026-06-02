"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from repolens.security.redaction import redact_tokens

from .config import load_config
from .data.errors import ArtifactError
from .discovery.gh import DEFAULT_GH_LIMIT, MAX_GH_LIMIT
from .discovery.pipeline import run_discover
from .exit_codes import ExitCode, InputError, InternalError

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
                    f"Maximum repos to ask gh for, 1-{MAX_GH_LIMIT} (default: {DEFAULT_GH_LIMIT})."
                ),
            )
            subparser.add_argument(
                "--force",
                action="store_true",
                help="Overwrite an existing repos.candidate.md approval file.",
            )
            subparser.set_defaults(handler=_discover_command)
        elif command_name == "scan":
            _configure_scan_parser(subparser)
        else:
            subparser.add_argument(
                "--findings-open",
                action="store_true",
                help=argparse.SUPPRESS,
            )
            subparser.set_defaults(handler=_stage_stub)

    return parser


def _configure_scan_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        metavar="PATH",
        help="Pipeline work root holding per-repo artifacts and the bootstrapped toolchain.",
    )
    subparser.add_argument(
        "--repos",
        type=Path,
        required=True,
        metavar="PATH",
        help='JSON file of approved repos: {"repos": [{"repo_ref", "clone_url"}, ...]}.',
    )
    subparser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-repo wall-clock budget for the Syft scan (default: clone timeout).",
    )
    subparser.set_defaults(handler=_handle_scan)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            parser.print_help()
            return int(ExitCode.SUCCESS)

        args.runtime_config = load_config(Path.cwd(), args.config)
        result = args.handler(args)
        if result.message:
            print(result.message)
        return _exit_code_for_result(result)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.USAGE_OR_INPUT_ERROR)
    except (ArtifactError, InputError) as exc:
        print(_sanitize(str(exc)), file=sys.stderr)
        return int(ExitCode.USAGE_OR_INPUT_ERROR)
    except InternalError as exc:
        print(_sanitize(f"Internal error: {exc}"), file=sys.stderr)
        return int(ExitCode.FINDINGS_OPEN)
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
        force_candidate=args.force,
    )
    return CommandResult(
        CommandStatus.SUCCESS,
        (
            f"Discovered {result.repository_count} repositories: "
            f"{result.candidate_count} candidates, {result.hard_exclusion_count} hard exclusions.\n"
            f"Created {result.discovered_path} and {result.candidate_path}.\n"
            f"Next: review {result.candidate_path}, tick approved repos, then continue to scan."
        ),
    )


def _handle_scan(args: argparse.Namespace) -> CommandResult:
    # Imported here so the rest of the CLI does not pull the scan/store stack
    # (and jsonschema) unless `scan` actually runs.
    from repolens.scan import runner as scan_runner

    repos = _load_repo_specs(args.repos, scan_runner.RepoSpec)
    syft_path = scan_runner.resolve_syft_path(args.work_root)
    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        raise InputError("--timeout must be a positive number of seconds")
    # scan_repos persists every successful SBOM and raises InternalError (exit 1)
    # if any repository fails; a clean run returns a report (exit 0). A None
    # timeout lets the runner apply its default per-repo budget.
    extra = {"timeout_seconds": args.timeout} if args.timeout is not None else {}
    report = scan_runner.scan_repos(args.work_root, repos, syft_path=syft_path, **extra)
    summary = f"scanned {len(report.scanned)} repositories ({len(report.skipped)} already complete)"
    return CommandResult(CommandStatus.SUCCESS, summary)


def _load_repo_specs(path: Path, repo_spec_cls: type) -> list:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"Repo list not found: {path.name}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError(f"Repo list is not valid JSON: {path.name}") from exc

    records = raw.get("repos") if isinstance(raw, dict) else raw
    if not isinstance(records, list) or not records:
        raise InputError("Repo list must contain a non-empty 'repos' array")

    specs = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise InputError(f"Repo list entry {index} must be an object")
        repo_ref = record.get("repo_ref")
        clone_url = record.get("clone_url")
        if not isinstance(repo_ref, str) or not repo_ref:
            raise InputError(f"Repo list entry {index} is missing a 'repo_ref'")
        if not isinstance(clone_url, str):
            raise InputError(f"Repo list entry {index} needs an https 'clone_url'")
        parsed_clone_url = urlparse(clone_url)
        if parsed_clone_url.scheme != "https" or not parsed_clone_url.hostname:
            raise InputError(f"Repo list entry {index} needs an https 'clone_url'")
        if parsed_clone_url.username or parsed_clone_url.password:
            raise InputError(f"Repo list entry {index} 'clone_url' must not embed credentials")
        specs.append(repo_spec_cls(repo_ref=repo_ref, clone_url=clone_url))
    return specs


def _exit_code_for_result(result: CommandResult) -> int:
    if result.status is CommandStatus.SUCCESS:
        return int(ExitCode.SUCCESS)
    if result.status is CommandStatus.FINDINGS_OPEN:
        return int(ExitCode.FINDINGS_OPEN)
    raise InputError("Unknown command result")


def _sanitize(message: str) -> str:
    redacted = redact_tokens(message)
    return PATH_PATTERN.sub("[REDACTED_PATH]", redacted)
