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

from repolens.report import render_main_report
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


@dataclass(frozen=True)
class StageHelp:
    help: str
    description: str
    epilog: str


def _stage_epilog(before: str, example: str, output: str, next_step: str) -> str:
    return f"Before: {before}\nExample: {example}\nOutput: {output}\nNext: {next_step}"


# Per-stage help, shown in `repolens --help` and each stage's own --help.
_STAGE_HELP = {
    "discover": StageHelp(
        help="Find and categorize the repos under an owner; you approve the list.",
        description=(
            "Stage 1/6 — find every repo under an owner and categorize it; you approve the list."
        ),
        epilog=_stage_epilog(
            "nothing else — this is the entry point; local config may add category rules.",
            "repolens discover --owner <OWNER>",
            "discovered.json (full tagged list) + repos.candidate.md (checkbox approval file).",
            "tick the repos to include in repos.candidate.md, then prepare approved "
            "repo JSON for `repolens scan`.",
        ),
    ),
    "scan": StageHelp(
        help="Inventory each repo's dependencies across all languages (read-only).",
        description=(
            "Stage 2/6 — inventory each approved repo's dependencies, any language (read-only)."
        ),
        epilog=_stage_epilog(
            "an approved repo JSON file derived from discover, plus a verified Syft "
            "binary in the work root.",
            "repolens scan --work-root work --repos approved-repos.json",
            "<WORK>/work/<repo_ref>/sbom.syft.json + scan.status.json per repo "
            "(resumable — safe to re-run).",
            "`repolens resolve --work-root <WORK> --repo-ref <REPO_REF>`.",
        ),
    ),
    "resolve": StageHelp(
        help="Resolve every dependency's license, cheapest trusted source first.",
        description=(
            "Stage 3/6 — determine each dependency's license, cheapest trusted source first."
        ),
        epilog=_stage_epilog(
            "a Syft SBOM from scan at <WORK>/work/<REPO_REF>/sbom.syft.json.",
            "repolens resolve --work-root <WORK> --repo-ref <REPO_REF>",
            "<WORK>/work/<REPO_REF>/resolved.ndjson (license + evidence + tags per dependency).",
            "`repolens flag --work-root <WORK>`.",
        ),
    ),
    "flag": StageHelp(
        help="Apply the license policy and flag risky or unresolved licenses.",
        description=(
            "Stage 4/6 — apply the license policy, flag risky/unknown licenses, and deduplicate."
        ),
        epilog=_stage_epilog(
            "resolved.ndjson files from resolve under <WORK>/work/<repo>/.",
            "repolens flag --work-root work",
            "inventory.json + shortlist.json + shortlist.md (the open BLOCK/REVIEW/UNKNOWN queue).",
            "`repolens shortlist` to settle the open items.",
        ),
    ),
    "shortlist": StageHelp(
        help="Resolve the flagged items with anchored evidence and your approval.",
        description=(
            "Stage 5/6 — settle flagged items with anchored evidence and your approval "
            "(planned — not yet available)."
        ),
        epilog=_stage_epilog(
            "shortlist.md from flag; shortlist resolution is planned but not wired at HEAD.",
            "repolens shortlist",
            "planned — a resolved shortlist.md plus per-item evidence/audit log; "
            "no such artifacts are produced at HEAD.",
            "once the shortlist stage lands and nothing is open, `repolens report`.",
        ),
    ),
    "report": StageHelp(
        help="Assemble the deduplicated main disclosure report.",
        description=(
            "Stage 6/6 — assemble the deduplicated main disclosure from resolved artifacts."
        ),
        epilog=_stage_epilog(
            "resolved.ndjson files from resolve; shortlist gating is planned but not "
            "wired at HEAD.",
            "repolens report --work-root <WORK> --out-dir reports",
            "report.main.md + report.main.csv.",
            "review and share it — you are responsible for validating the result.",
        ),
    ),
}

_DESCRIPTION = (
    "RepoLens — an open-source license disclosure across every repository under an owner.\n"
    "It inventories dependencies in any language, flags commercial-use risks, and\n"
    "assembles an evidence-backed disclosure. Run the stages below in order."
)

_EPILOG = (
    "global options:\n"
    "  Put global options before the stage name, e.g.\n"
    "    repolens --config ./repolens.local.toml discover --owner <OWNER>\n"
    "  Config files hold local taxonomy, policy, and report settings; owner is\n"
    "  still supplied at runtime with --owner.\n"
    "  Use stage options such as --work-root for output directories; --config is\n"
    "  only for local config files.\n"
    "\n"
    "typical run:\n"
    "  1. repolens discover --owner <OWNER>                     find + approve the repos\n"
    "  2. repolens scan --work-root work --repos approved-repos.json\n"
    "                                                           inventory dependencies\n"
    "  3. repolens resolve --work-root work --repo-ref <REPO_REF>\n"
    "                                                           resolve licenses\n"
    "  4. repolens flag --work-root work                        flag risk / unknowns\n"
    "  5. repolens shortlist                                    resolve the flags (planned)\n"
    "  6. repolens report --work-root work --out-dir reports    build the main disclosure\n"
    "\n"
    "Discovery, flag, and report are shipped checkpoints where you stay in control;\n"
    "shortlist is registered but planned. Run `repolens <stage> --help`\n"
    "for one stage. Full guide: docs/usage.md."
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
        help=(
            "Global option before <stage>: path to an untracked local config file "
            "(taxonomy, policy, report settings)."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<stage>",
        title="stages (run in order)",
    )

    for command_name in STAGE_COMMANDS:
        stage_help = _STAGE_HELP[command_name]
        subparser = subparsers.add_parser(
            command_name,
            help=stage_help.help,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=stage_help.description,
            epilog=stage_help.epilog,
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
        elif command_name == "resolve":
            _configure_resolve_parser(subparser)
        elif command_name == "flag":
            _configure_flag_parser(subparser)
        elif command_name == "report":
            _configure_report_parser(subparser)
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


def _configure_resolve_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        required=True,
        type=Path,
        help="Root directory containing RepoLens work artifacts.",
    )
    subparser.add_argument(
        "--repo-ref",
        required=True,
        help="Runtime repository reference used for the work/<repo-ref>/ artifact dir.",
    )
    subparser.set_defaults(handler=_resolve_stage)


def _configure_flag_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root containing work/<repo>/resolved.ndjson; receives inventory + shortlist.",
    )
    subparser.set_defaults(handler=_flag_stage)


def _configure_report_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        default=Path.cwd(),
        help="Root containing work/<repo>/resolved.ndjson artifacts.",
    )
    subparser.add_argument(
        "--out-dir",
        type=Path,
        help="Directory for report.main.md and report.main.csv.",
    )
    subparser.set_defaults(handler=_report)


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


def _resolve_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.resolve import run_resolve

    path = run_resolve(args.work_root, args.repo_ref)
    return CommandResult(CommandStatus.SUCCESS, f"wrote {path.name}")


def _flag_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.flag import run_flag

    result = run_flag(args.work_root)
    summary = (
        f"flagged {result.open_count} open item(s) across {result.component_count} "
        f"component(s); wrote {result.inventory_path.name}, "
        f"{result.shortlist_json_path.name}, {result.shortlist_md_path.name}"
    )
    if result.open_count > 0:
        return CommandResult(CommandStatus.FINDINGS_OPEN, summary)
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


def _report(args: argparse.Namespace) -> CommandResult:
    result = render_main_report(args.work_root, args.out_dir)
    return CommandResult(
        CommandStatus.SUCCESS,
        f"wrote {result.markdown_path} and {result.csv_path}",
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
