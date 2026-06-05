"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shlex
import shutil
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TextIO, TypeVar
from urllib.parse import unquote

from repolens.bootstrap.cache import (
    DOC_LINK,
    SyftCacheResult,
    SyftPinSummary,
    cached_syft_path,
    ensure_syft_cached,
    load_syft_pin,
)
from repolens.bootstrap.errors import IntegrityError, UsageError
from repolens.report import ReportGateOpen, ReportResult, render_main_report
from repolens.security.redaction import redact_tokens

from .config import (
    Config,
    config_discovery_lines,
    human_schema_text,
    load_config,
    local_config_json_schema,
    validate_config_file_message,
    validate_config_values,
)
from .data.errors import ArtifactError
from .discovery.gh import DEFAULT_GH_LIMIT, MAX_GH_LIMIT, parse_repos_option
from .discovery.pipeline import run_discover
from .exit_codes import ExitCode, InputError, InternalError

_ParsedPromptValue = TypeVar("_ParsedPromptValue")

PATH_PATTERN = re.compile(r"(?<![:/])(?:/[^\s:/]+)+")

if TYPE_CHECKING:
    from repolens.scan.runner import ScanProgressEvent, ScanReport


class CommandStatus(Enum):
    SUCCESS = "success"
    FINDINGS_OPEN = "findings_open"


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    message: str = ""
    metadata: object | None = None


CommandHandler = Callable[[argparse.Namespace], CommandResult]


STAGE_COMMANDS = ("discover", "scan", "resolve", "flag", "shortlist", "report")
REPORT_MAIN_DATA_FILENAMES = ("report.main.md", "report.main.csv")
REPORT_MAIN_DOCX_FILENAME = "report.main.docx"
REPORT_MAIN_FILENAMES = (*REPORT_MAIN_DATA_FILENAMES, REPORT_MAIN_DOCX_FILENAME)


@dataclass
class RunFailure:
    stage: str
    repo_ref: str | None
    message: str


@dataclass
class RunSummary:
    repo_refs: set[str] = field(default_factory=set)
    report_rows: int = 0
    failures: list[RunFailure] = field(default_factory=list)
    skipped: int = 0
    reports_dir: Path | None = None
    report_paths: tuple[Path, ...] = ()
    appendix_rows_by_label: dict[str, int] = field(default_factory=dict)
    appendix_paths_by_label: dict[str, tuple[Path, Path]] = field(default_factory=dict)
    coverage_gaps_by_label: dict[str, dict[str, int]] = field(default_factory=dict)
    docx_skipped: bool = False

    @property
    def has_failures(self) -> bool:
        return bool(self.failures)


@dataclass(frozen=True)
class StageHelp:
    help: str
    description: str
    epilog: str


def _stage_epilog(before: str, example: str, output: str, next_step: str) -> str:
    return (
        f"Before: {before}\nExample: {example}\nOutput: {output}\nNext: {next_step}\n"
        "Also: `repolens run --work-root <WORK> --owner <OWNER>` drives the pipeline end-to-end."
    )


_RESOLVE_EPILOG = """\
Before:
  Run scan first.
  Syft SBOMs from scan at <WORK>/work/*/sbom.syft.json.

Default:
  omit to resolve checked discover repos that have SBOMs; use --repo-ref for selected repos.
  If no checked SBOMs are present, resolve every scan output SBOM under <WORK>/work/.

Example:
  Resolve all selected/scanned repos:
    repolens resolve --work-root <WORK>

  Resolve one repo:
    repolens resolve --work-root <WORK> --repo-ref <REPO_NAME>

  Resolve selected repos:
    repolens resolve --work-root <WORK> --repo-ref <REPO_NAME_A> --repo-ref <REPO_NAME_B>

  Retry ScanCode only where prior resolve recorded tool unavailable:
    repolens resolve --work-root <WORK> --retry-scancode

  Retry ScanCode for selected repos only:
    repolens resolve --work-root <WORK> --retry-scancode \\
      --repo-ref <REPO_NAME_A> --repo-ref <REPO_NAME_B>

Output:
  <WORK>/work/<repo_ref>/resolved.ndjson
  Contains license, evidence, and tags per dependency.
  Unresolved records stay schema-valid.

Next:
  repolens flag --work-root <WORK>

Notes:
  --source-root is read-only source input for mobile markers
  and scoped ScanCode fallback.
  --source-root supports exactly one repo, so pass one --repo-ref with it.
  After retrying ScanCode, rerun flag.
  flag preserves matching approved/rejected shortlist decisions.
  `repolens run --work-root <WORK> --owner <OWNER>` drives the pipeline end-to-end.
"""


# Per-stage help, shown in `repolens --help` and each stage's own --help.
_STAGE_HELP = {
    "discover": StageHelp(
        help="Find and categorize the repos under an owner; you confirm the list.",
        description=(
            "Stage 1/6 — find every repo under an owner and categorize it; you confirm the list."
        ),
        epilog=_stage_epilog(
            "nothing else — this is the entry point; local config may add category rules.",
            "repolens discover --owner <OWNER>  (or: --owner <OWNER> "
            '--repos "sentinel-alpha, sentinel-beta")',
            "discovered.json (full tagged list) + repos.candidate.md (checkbox approval file).",
            "review repos.candidate.md, untick any repos you want to exclude, then run "
            "`repolens bootstrap --work-root <WORK>`, then `repolens scan --work-root <WORK>`.",
        ),
    ),
    "scan": StageHelp(
        help="Inventory each repo's dependencies across all languages (read-only).",
        description=(
            "Stage 2/6 — inventory each approved repo's dependencies, any language (read-only)."
        ),
        epilog=_stage_epilog(
            "reviewed discover artifacts at <WORK>/discovered.json and "
            "<WORK>/repos.candidate.md. On first use, scan can acquire RepoLens's "
            "pinned Syft into the shared verified cache.",
            "repolens scan --work-root <WORK>  (automation: --yes; offline: --offline)",
            "<WORK>/work/<repo_ref>/sbom.syft.json + scan.status.json per repo "
            "(resumable — safe to re-run).",
            "`repolens resolve --work-root <WORK>`.",
        ),
    ),
    "resolve": StageHelp(
        help="Resolve every dependency's license with APIs, mobile opt-in, and scoped ScanCode.",
        description=(
            "Stage 3/6 — determine each dependency's license, cheapest trusted source first."
        ),
        epilog=_RESOLVE_EPILOG,
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
        help="Settle grouped flagged items with verified proposals and your approval.",
        description=(
            "Stage 5/6 — emit proposal contexts, verify proposal artifacts, and settle "
            "grouped flagged items with your approval."
        ),
        epilog=_stage_epilog(
            "shortlist.json + shortlist.md from flag under <WORK>.",
            "repolens shortlist --work-root work --emit-contexts work/shortlist.contexts.json",
            "shortlist.contexts.json when requested; shortlist.json + grouped shortlist.md "
            "rewritten with verified candidates and recorded human approvals; exits 1 "
            "while any item is still open.",
            "for UNKNOWNs/open items, emit contexts, ask `$repolens` to write proposals, "
            "ingest them with `--proposals`, then approve/reject remaining rows. Once "
            "nothing is open, `repolens report`.",
        ),
    ),
    "report": StageHelp(
        help="Assemble gated main, appendix, and docx disclosure reports.",
        description=("Stage 6/6 — assemble gated disclosure reports from resolved artifacts."),
        epilog=_stage_epilog(
            "resolved.ndjson files from resolve, discovered.json categories when present, "
            "a clear shortlist.json when present, and report.header config for docx.",
            "repolens report --work-root <WORK>",
            "report.main.{md,csv,docx} + report.appendix.<category>.{md,csv}.",
            "review and share it — you are responsible for validating the result.",
        ),
    ),
}

_DESCRIPTION = (
    "RepoLens — an open-source license disclosure across every repository under an owner.\n"
    "It inventories dependencies in any language, flags commercial-use risks, and\n"
    "assembles an evidence-backed disclosure. Start with `repolens run` for the\n"
    "one-command pipeline, or run the individual stages below when debugging."
)

_DEFAULT_REPORT_LEGAL_TEXT = "Confidential. Prepared for license compliance review."

_EPILOG = (
    "recommended:\n"
    "  repolens run --work-root work --owner <OWNER>\n"
    "\n"
    "step it yourself:\n"
    "  1. repolens discover --owner <OWNER>                     find + approve the repos\n"
    "  2. repolens bootstrap --work-root work                   prepare work-root tools\n"
    "  3. repolens scan --work-root work                        inventory approved dependencies\n"
    "  4. repolens resolve --work-root work                     resolve scanned repos\n"
    "  5. repolens flag --work-root work                        flag risk / unknowns\n"
    "  6. repolens shortlist --work-root work                   settle the flags + approve\n"
    "  7. repolens report --work-root work                      build the main disclosure\n"
    "\n"
    "global options:\n"
    "  Put global options before the command name, e.g.\n"
    "    `repolens --config ./.repolens.local.json discover --owner <OWNER>`\n"
    "\n"
    "  JSON config files hold local taxonomy, scan, and report settings; owner is still "
    "supplied at runtime with --owner.\n"
    "\n"
    "  Use stage options such as --work-root for output directories; --config is only "
    "for local config files.\n"
    "\n"
    "  Use `repolens config init`, `repolens config schema`, and `repolens config "
    "validate <path>` for local config workflows.\n"
    "\n"
    "  Common local config commands:\n"
    "    `repolens config init --work-root work`\n"
    "    `repolens config schema`\n"
    "    `repolens config validate ./.repolens.local.json`\n"
    "\n"
    "  Use a config with the full run:\n"
    "    `repolens run --work-root work --owner <OWNER> --config ./.repolens.local.json`\n"
    "\n"
    "Scan auto-acquires and verifies RepoLens's pinned Syft into a shared cache on\n"
    "first use; `repolens bootstrap` pre-seeds it for offline runs. Run\n"
    "`repolens <command> --help` for details. Full guide: docs/usage.md."
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
        help="JSON local config path; use before <command>.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        title="commands",
    )

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="Pre-seed RepoLens's verified tools for scans and ScanCode fallback.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Pre-seed RepoLens's verified shared Syft cache and, with --work-root, "
            "prepare work-root-local ScanCode fallback tools."
        ),
        epilog=(
            "Before: nothing, an empty shared cache, or a work root missing ScanCode.\n"
            "Example: repolens bootstrap\n"
            "Example: repolens bootstrap --work-root <WORK>\n"
            "Output: shared Syft cache; with --work-root also writes "
            "<WORK>/tools/scancode and <WORK>/tool_versions.json.\n"
            "Next: `repolens scan --work-root <WORK> --offline` or "
            "`repolens resolve --work-root <WORK> --retry-scancode`."
        ),
    )
    bootstrap_parser.add_argument(
        "--work-root",
        type=Path,
        metavar="PATH",
        help="Also prepare work-root-local ScanCode fallback tools.",
    )
    bootstrap_parser.set_defaults(handler=_bootstrap_command)

    config_parser = subparsers.add_parser(
        "config",
        help="Initialize, validate, and display JSON-only local runtime config.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Manage RepoLens JSON-only local runtime config.\n"
            "Local config can set discover taxonomy, scan options, and report options.\n"
            "Owner/repo inputs remain runtime CLI inputs."
        ),
        epilog=(
            "Examples:\n"
            "  repolens config init --work-root work\n"
            "  repolens config schema\n"
            "  repolens config validate ./.repolens.local.json\n"
            "\n"
            "Run `repolens config <action> --help` for action-specific options."
        ),
    )
    _configure_config_parser(config_parser)

    run_parser = subparsers.add_parser(
        "run",
        help="Recommended: run the full pipeline with inline pauses and resume.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Recommended entry point — discover, scan, resolve, flag, shortlist, and report "
            "with human pauses only where review is required."
        ),
        epilog=(
            "Example: repolens run --work-root work --owner <OWNER>\n"
            "Automation: repolens run --work-root work --owner <OWNER> --yes\n"
            "Resume: rerun the same command; existing artifacts decide the next stage.\n"
            "Note: --yes never approves shortlist items."
        ),
    )
    _configure_run_parser(run_parser)

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
                "--repos",
                metavar="LIST",
                help=(
                    "Comma-separated repo names under --owner (spaces around commas "
                    "are fine). A name list, not a file, unlike scan --repos. When "
                    "given, only these repos are discovered and --limit is ignored."
                ),
            )
            subparser.add_argument(
                "--limit",
                type=int,
                default=DEFAULT_GH_LIMIT,
                metavar="N",
                help=(
                    f"Maximum repos to ask gh for, 1-{MAX_GH_LIMIT} (default: "
                    f"{DEFAULT_GH_LIMIT}); applies only to the enumerate path, not --repos."
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
        elif command_name == "shortlist":
            _configure_shortlist_parser(subparser)
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


def _configure_config_parser(subparser: argparse.ArgumentParser) -> None:
    actions = subparser.add_subparsers(
        dest="config_action",
        metavar="<action>",
        title="config actions",
        required=False,
    )
    subparser.set_defaults(handler=_parser_help_command(subparser))
    init_parser = actions.add_parser(
        "init",
        help="Generate a minimal JSON local config through guided prompts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Generate a minimal JSON local config file through guided prompts.\n"
            "RepoLens asks where to save the file, explains each section, and writes\n"
            "only the fields you select.\n"
            "\n"
            "Prompt entries use key=value, for example owner/repo=production or\n"
            "obsolete-*=OBSOLETE. At the interactive prompt, do not add shell quotes\n"
            "around glob patterns; type obsolete-*=OBSOLETE. Category prompts only label\n"
            "repos; use exclude patterns or dead repos to skip scanning. For dead repos,\n"
            "you can enter repo-a,repo-b and then provide one reason for all listed repos.\n"
            "\n"
            "Optional advanced prompts can be left blank. For example, leave Syft\n"
            "catalogers blank to use all catalogers, and leave main report categories\n"
            "blank to include all categories in the main report."
        ),
        epilog=(
            "Examples:\n"
            "  repolens config init\n"
            "  repolens config init --work-root work\n"
            "  repolens config init --out ./.repolens.local.json\n"
            "\n"
            "During init, invalid entries are explained and re-prompted."
        ),
    )
    init_parser.add_argument(
        "--work-root",
        type=Path,
        metavar="DIR",
        help="Default save path is DIR/.repolens.local.json; next commands use DIR.",
    )
    init_parser.add_argument(
        "--out",
        type=Path,
        metavar="PATH",
        help="Exact .json path to write.",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing config without an overwrite confirmation prompt.",
    )
    init_parser.set_defaults(handler=_config_init_command)

    schema_parser = actions.add_parser(
        "schema",
        help="Show supported local config keys and operational impact.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show supported local config keys, types, defaults, and operational impact.\n"
            "Use this before writing .repolens.local.json by hand."
        ),
        epilog=("Examples:\n  repolens config schema\n  repolens config schema --json"),
    )
    schema_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the canonical JSON Schema instead of the human-readable definition.",
    )
    schema_parser.set_defaults(handler=_config_schema_command)

    validate_parser = actions.add_parser(
        "validate",
        help="Validate one JSON local config file and summarize it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Validate exactly one JSON local config file, without discovery or merging.\n"
            "Use this after writing .repolens.local.json by hand."
        ),
        epilog=(
            "Examples:\n"
            "  repolens config validate ./.repolens.local.json\n"
            "  repolens config validate work/.repolens.local.json\n"
            "\n"
            "Validation rejects unknown keys and prints a readable summary of the file."
        ),
    )
    validate_parser.add_argument(
        "path",
        type=Path,
        metavar="PATH",
        help="JSON local config file to validate.",
    )
    validate_parser.set_defaults(handler=_config_validate_command)


def _parser_help_command(
    parser: argparse.ArgumentParser,
) -> Callable[[argparse.Namespace], CommandResult]:
    def command(_args: argparse.Namespace) -> CommandResult:
        parser.print_help()
        return CommandResult(CommandStatus.SUCCESS, "")

    return command


def _configure_scan_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        metavar="PATH",
        help="Pipeline work root holding discover and per-repo scan artifacts.",
    )
    subparser.add_argument(
        "--repos",
        type=Path,
        metavar="PATH",
        help=(
            'Override discover artifacts with an approved repo JSON file: {"repos": '
            '[{"repo_ref", "clone_url"}, ...]}.'
        ),
    )
    subparser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-repo wall-clock budget for the Syft scan.",
    )
    subparser.add_argument(
        "--clone-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-repo wall-clock budget for hardened git clone (default: 300).",
    )
    subparser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Pre-consent to download and verify RepoLens's pinned Syft when the cache is empty.",
    )
    subparser.add_argument(
        "--offline",
        action="store_true",
        help="Require the verified shared Syft cache; never download or prompt.",
    )
    subparser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scan progress output on stderr.",
    )
    subparser.set_defaults(handler=_handle_scan)


def _configure_run_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        metavar="PATH",
        help="Pipeline work root for all artifacts.",
    )
    subparser.add_argument(
        "--owner",
        required=True,
        metavar="OWNER",
        help="Runtime owner/org to enumerate with gh; never store this in source.",
    )
    subparser.add_argument(
        "--repos",
        metavar="LIST",
        help="Comma-separated repo names under --owner; omitted means enumerate the owner.",
    )
    subparser.add_argument(
        "--out-dir",
        type=Path,
        metavar="PATH",
        help=(
            "Directory for report.main.{md,csv,docx} and appendix artifacts "
            "(default: <work-root>/reports)."
        ),
    )
    subparser.add_argument(
        "--config",
        dest="run_config",
        type=Path,
        metavar="PATH",
        help="Local config file; equivalent to global `--config PATH` before `run`.",
    )
    subparser.add_argument(
        "--step",
        action="store_true",
        help="Pause after every stage in interactive mode so artifacts can be inspected.",
    )
    subparser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help=(
            "Automation mode: pass discovery and tool-consent gates, but never approve "
            "shortlist items."
        ),
    )
    subparser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress run stage banners and scan progress output on stderr.",
    )
    subparser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-repo wall-clock budget for the Syft scan.",
    )
    subparser.add_argument(
        "--clone-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-repo wall-clock budget for hardened git clone (default: 300).",
    )
    subparser.set_defaults(handler=_run_command)


def _configure_resolve_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        required=True,
        type=Path,
        help="Root directory containing RepoLens work artifacts.",
    )
    subparser.add_argument(
        "--repo-ref",
        action="append",
        metavar="REPO_NAME",
        help=("Resolve a selected repo; repeat for several repos."),
    )
    subparser.add_argument(
        "--source-root",
        type=Path,
        metavar="PATH",
        help=("Read-only source checkout for mobile markers and scoped ScanCode."),
    )
    subparser.add_argument(
        "--enable-mobile-native",
        action="store_true",
        help="Opt in to sandboxed native mobile license enrichment when mobile markers exist.",
    )
    subparser.add_argument(
        "--detect-conflicts",
        action="store_true",
        help=("Cross-check all API adapters and write CONFLICT on disagreement."),
    )
    subparser.add_argument(
        "--retry-scancode",
        action="store_true",
        help=("Retry only repos with prior unresolved:scancode_tool_unavailable."),
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


def _configure_shortlist_parser(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--work-root",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root containing the shortlist.json + shortlist.md that flag wrote.",
    )
    subparser.add_argument(
        "--identity",
        metavar="REVIEWER",
        help=(
            "Optional reviewer label override recorded as decided_by on approved/rejected "
            "items; default is the logged-in OS user."
        ),
    )
    subparser.add_argument(
        "--emit-contexts",
        type=Path,
        metavar="PATH",
        help=(
            "Write model-free external proposal contexts for open items; RepoLens does "
            "not invoke a model."
        ),
    )
    subparser.add_argument(
        "--proposals",
        type=Path,
        metavar="PATH",
        help=(
            "Read external AI proposal JSON and re-fetch/verify every citation before "
            "recording candidates."
        ),
    )
    subparser.set_defaults(handler=_shortlist_stage)


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
        help="Directory for report.main.{md,csv,docx} and appendix artifacts.",
    )
    subparser.set_defaults(handler=_report)


def _global_config_help_requested(argv: Sequence[str]) -> bool:
    help_flags = {"-h", "--help"}
    return any(
        arg == "--config" and index + 1 < len(argv) and argv[index + 1] in help_flags
        for index, arg in enumerate(argv)
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    try:
        if _global_config_help_requested(argv):
            parser.print_help()
            return int(ExitCode.SUCCESS)

        args = parser.parse_args(argv)
        if args.command is None:
            parser.print_help()
            return int(ExitCode.SUCCESS)

        if args.command in {"config", "bootstrap"}:
            args.runtime_config = Config(values={}, sources=())
        else:
            config_path = getattr(args, "run_config", None) or args.config
            args.runtime_config = load_config(
                Path.cwd(),
                config_path,
                work_root=_config_work_root(args),
            )
        result = args.handler(args)
        if result.message:
            print(result.message)
        return _exit_code_for_result(result)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.USAGE_OR_INPUT_ERROR)
    except (ArtifactError, InputError) as exc:
        print(_sanitize(str(exc), redact_paths=False), file=sys.stderr)
        return int(ExitCode.USAGE_OR_INPUT_ERROR)
    except InternalError as exc:
        print(_sanitize(f"Internal error: {exc}", redact_paths=True), file=sys.stderr)
        return int(ExitCode.FINDINGS_OPEN)
    except Exception as exc:
        print(_sanitize(f"Internal error: {exc}", redact_paths=True), file=sys.stderr)
        return int(ExitCode.FINDINGS_OPEN)


def _config_work_root(args: argparse.Namespace) -> Path | None:
    work_root = getattr(args, "work_root", None)
    return Path(work_root) if work_root is not None else None


def _stage_stub(args: argparse.Namespace) -> CommandResult:
    if args.findings_open:
        return CommandResult(CommandStatus.FINDINGS_OPEN, "findings remain open")
    return CommandResult(CommandStatus.SUCCESS, "skeleton command completed")


def _bootstrap_command(args: argparse.Namespace) -> CommandResult:
    try:
        result = ensure_syft_cached()
    except UsageError as exc:
        raise InputError(str(exc)) from exc
    except IntegrityError as exc:
        raise InternalError(f"Syft bootstrap integrity failure: {exc}") from exc

    status = "acquired and verified" if result.acquired else "already verified"
    lines = [f"Syft {result.pin.version} ({result.pin.short_sha256}...) {status}: {result.path}"]
    work_root = getattr(args, "work_root", None)
    if work_root is not None:
        scancode_path = _bootstrap_scancode_for_work_root(Path(work_root))
        lines.append(
            f"ScanCode fallback ready for {_resolved_path(Path(work_root))}: {scancode_path}"
        )
        lines.append(
            f"Next: repolens resolve --work-root {shlex.quote(str(work_root))} --retry-scancode"
        )
    return CommandResult(CommandStatus.SUCCESS, "\n".join(lines))


def _bootstrap_scancode_for_work_root(work_root: Path) -> Path:
    from repolens.bootstrap.errors import BootstrapError
    from repolens.bootstrap.orchestrate import default_make_executable
    from repolens.bootstrap.pins import load_pins
    from repolens.bootstrap.record import write_tool_versions
    from repolens.bootstrap.scancode import (
        install_scancode_venv,
        scancode_venv_digest,
        scancode_venv_source,
        write_scancode_venv_wrapper,
    )
    from repolens.bootstrap.syft import ResolvedTool

    root = Path(work_root)
    tools_dir = root / "tools"
    try:
        pins = load_pins()
        version = pins.tool("scancode").version
        install_scancode_venv(tools_dir / "scancode-venv", version=version)
        digest = scancode_venv_digest(version)
        wrapper = write_scancode_venv_wrapper(
            tools_dir / "scancode",
            version=version,
            install_digest=digest,
            make_executable=default_make_executable,
        )
        write_tool_versions(
            pins,
            [
                ResolvedTool(
                    name="scancode",
                    version=version,
                    digest=digest,
                    path=wrapper,
                    source=scancode_venv_source(version),
                )
            ],
            root / "tool_versions.json",
        )
    except (BootstrapError, OSError, RuntimeError, ValueError) as exc:
        raise InputError(
            f"ScanCode bootstrap failed for {root}: {exc}\n"
            "Hint: make sure Python venv/pip can run, network access is available, "
            "and the pinned ScanCode version has a binary wheel for this Python/platform; "
            "then rerun `repolens bootstrap --work-root <WORK>`."
        ) from exc
    return wrapper


def _config_schema_command(args: argparse.Namespace) -> CommandResult:
    if args.json:
        return CommandResult(
            CommandStatus.SUCCESS,
            json.dumps(local_config_json_schema(), indent=2, sort_keys=True),
        )
    return CommandResult(CommandStatus.SUCCESS, human_schema_text())


def _config_validate_command(args: argparse.Namespace) -> CommandResult:
    return CommandResult(CommandStatus.SUCCESS, validate_config_file_message(args.path))


def _config_init_command(args: argparse.Namespace) -> CommandResult:
    if args.out is not None and args.out.suffix.lower() != ".json":
        raise InputError(
            f"Config output path must end in .json: {args.out}. "
            "RepoLens local runtime config is JSON-only; use .repolens.local.json."
        )
    path = _prompt_config_path(args, input_stream=sys.stdin, output_stream=sys.stdout)
    if (
        path.exists()
        and not args.force
        and not _confirm(
            f"Overwrite existing {path}?",
            input_stream=sys.stdin,
            output_stream=sys.stdout,
        )
    ):
        raise InputError(f"Refused to overwrite existing config: {path}")

    values = _prompt_config_values(input_stream=sys.stdin, output_stream=sys.stdout)
    validate_config_values(values, path=path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(values, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    work_root = args.work_root if args.work_root is not None else Path("work")
    run_command = (
        f"repolens run --work-root {shlex.quote(str(work_root))} "
        f"--owner <OWNER> --config {shlex.quote(str(path))}"
    )
    discover_command = (
        f"repolens --config {shlex.quote(str(path))} discover "
        f"--owner <OWNER> --work-root {shlex.quote(str(work_root))}"
    )
    return CommandResult(
        CommandStatus.SUCCESS,
        "\n".join(
            (
                f"Wrote config: {path}",
                "Next commands:",
                f"  {run_command}",
                f"  {discover_command}",
            )
        ),
    )


def _prompt_config_path(
    args: argparse.Namespace,
    *,
    input_stream: TextIO,
    output_stream: TextIO,
) -> Path:
    if args.out is not None:
        default = args.out
    elif args.work_root is not None:
        default = args.work_root / ".repolens.local.json"
    else:
        default = Path(".repolens.local.json")
    while True:
        answer = _prompt(
            "Where should RepoLens save the JSON local config?",
            default=str(default),
            input_stream=input_stream,
            output_stream=output_stream,
        )
        path = Path(answer).expanduser()
        if path.suffix.lower() == ".json":
            return path
        print(
            "Invalid input: config output path must end in .json. Try again.",
            file=output_stream,
        )


def _prompt_config_values(*, input_stream: TextIO, output_stream: TextIO) -> dict[str, object]:
    values: dict[str, object] = {}

    taxonomy = _prompt_taxonomy(input_stream=input_stream, output_stream=output_stream)
    if taxonomy:
        values["discover"] = {"taxonomy": taxonomy}

    scan = _prompt_scan_config(input_stream=input_stream, output_stream=output_stream)
    if scan:
        values["scan"] = scan

    report = _prompt_report_config(input_stream=input_stream, output_stream=output_stream)
    if report:
        values["report"] = report

    return values


def _prompt_taxonomy(*, input_stream: TextIO, output_stream: TextIO) -> dict[str, object]:
    taxonomy: dict[str, object] = {}
    print(
        "\nCategories are labels for grouping repositories and report routing; they do not "
        "exclude repos, skip scanning, or remove anything from discovery. Use the exclude "
        "pattern and dead repo prompts below for hard exclusions.",
        file=output_stream,
    )
    default_category = _prompt(
        "Default category (blank keeps RepoLens default)",
        default="",
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if default_category:
        taxonomy["default_category"] = default_category

    print(
        "\nExplicit repos are exact repo or owner/repo category matches.",
        file=output_stream,
    )
    explicit = _prompt_parsed(
        "Explicit repo categories (example owner/repo=production)",
        parser=lambda value: _parse_mapping(value, label="explicit repo category"),
        retry_hint=(
            "Use owner/repo=category pairs such as owner/repo=production. Press Enter to skip."
        ),
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if explicit:
        taxonomy["explicit"] = explicit

    print(
        "\nPatterns are glob rules checked after explicit repo matches. At this prompt, "
        "the left side is a repo-name glob and the right side is any category label "
        "you choose. For example: obsolete-*=OBSOLETE or internal-*=INTERNAL. "
        "Do not add shell quotes around the glob.",
        file=output_stream,
    )
    patterns = _prompt_parsed(
        "Pattern categories (examples obsolete-*=OBSOLETE, internal-*=INTERNAL)",
        parser=_parse_patterns,
        retry_hint=(
            "Use glob=category pairs such as obsolete-*=OBSOLETE or internal-*=INTERNAL. "
            "The category label is your own report/category name. Do not add quotes in the "
            "prompt. Press Enter to skip."
        ),
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if patterns:
        taxonomy["patterns"] = patterns

    print(
        "\nTopics are GitHub repo tags. They appear on the GitHub repo page and can be "
        "checked with `gh repo view OWNER/REPO --json repositoryTopics`.",
        file=output_stream,
    )
    topics = _prompt_parsed(
        "Topic categories (example mobile=apps)",
        parser=lambda value: _parse_mapping(value, label="topic category"),
        retry_hint="Use topic=category pairs such as mobile=apps. Press Enter to skip.",
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if topics:
        taxonomy["topics"] = topics

    print(
        "\nExclude patterns are repo-name glob rules for hard exclusions. Use these when "
        "a whole class of repos should not be scanned, and include a visible reason. "
        "For example: obsolete-*=retired or internal-*=internal-only. Do not add shell "
        "quotes around the glob. These apply during discover; an existing "
        "repos.candidate.md is not rewritten until you rerun discover with --force.",
        file=output_stream,
    )
    exclude_patterns = _prompt_parsed(
        "Exclude repo patterns (examples obsolete-*=retired, internal-*=internal-only)",
        parser=_parse_exclude_patterns,
        retry_hint=(
            "Use glob=reason pairs such as obsolete-*=retired or internal-*=internal-only. "
            "Matching repos are hard-excluded and not scanned. Press Enter to skip."
        ),
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if exclude_patterns:
        taxonomy["exclude_patterns"] = exclude_patterns

    print(
        "\nDead repos are exact repos to hard-exclude with a visible reason; use this only "
        "for retired/dead repos. Enter owner/repo=reason pairs, or enter a comma-separated "
        "repo list and RepoLens will ask for one reason to apply to all of them.",
        file=output_stream,
    )
    dead = _prompt_dead_repos(
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if dead:
        taxonomy["dead"] = dead

    return taxonomy


def _prompt_scan_config(*, input_stream: TextIO, output_stream: TextIO) -> dict[str, object]:
    scan: dict[str, object] = {}

    print(
        "\nscan.exclude_paths are repo-relative path prefixes filtered from SBOM artifacts.",
        file=output_stream,
    )
    exclude_paths = _parse_csv_values(
        _prompt(
            "Exclude path prefixes, comma-separated",
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        )
    )
    if exclude_paths:
        scan["exclude_paths"] = exclude_paths

    print("\nscan.clone_timeout_seconds is a positive clone timeout.", file=output_stream)
    clone_timeout = _prompt_parsed(
        "Clone timeout seconds",
        parser=_parse_optional_positive_timeout,
        retry_hint="Use a positive number such as 300, or press Enter to skip.",
        input_stream=input_stream,
        output_stream=output_stream,
    )
    if clone_timeout is not None:
        scan["clone_timeout_seconds"] = clone_timeout

    print(
        "\nscan.syft.catalogers is optional and advanced. A Syft cataloger is a scanner "
        "for one package ecosystem or manifest type. Leave this blank to use all Syft "
        "catalogers, which is recommended for most runs. Restrict it only when you want "
        "a narrower scan, less noise, or faster scanning for known ecosystems. Examples: "
        "python-package-cataloger, java-gradle-lockfile-cataloger. Too narrow can miss "
        "dependencies. RepoLens still adds mobile catalogers for Gradle, CocoaPods, and "
        "Swift Package Manager.",
        file=output_stream,
    )
    catalogers = _parse_csv_values(
        _prompt(
            "Syft catalogers (optional; examples python-package-cataloger, "
            "java-gradle-lockfile-cataloger)",
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        ),
    )
    if catalogers:
        scan["syft"] = {"catalogers": catalogers}

    return scan


def _prompt_report_config(*, input_stream: TextIO, output_stream: TextIO) -> dict[str, object]:
    report: dict[str, object] = {}

    print(
        "\nreport.selection.include is optional. It controls which taxonomy categories "
        "go into report.main.*. Leave this blank to include all categories in the main "
        "report. Use it when you want a narrower shipped-product report, for example "
        "PRODUCTION,INTERNAL. Categories not listed are not dropped; third-party rows "
        "route to report.appendix.<category>.*.",
        file=output_stream,
    )
    include = _parse_csv_values(
        _prompt(
            "Main report categories (optional; examples PRODUCTION, INTERNAL)",
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        )
    )
    if include:
        report["selection"] = {"include": include}

    print(
        "\nreport.header.org_name and report.header.legal_text are optional docx cover text. "
        f"Default legal_text: {_DEFAULT_REPORT_LEGAL_TEXT}",
        file=output_stream,
    )
    if _confirm(
        "Add report header text?",
        input_stream=input_stream,
        output_stream=output_stream,
    ):
        org_name = _prompt(
            "Report header org_name",
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        )
        legal_text = _prompt(
            "Report header legal_text",
            default=_DEFAULT_REPORT_LEGAL_TEXT,
            input_stream=input_stream,
            output_stream=output_stream,
        )
        report["header"] = {"org_name": org_name, "legal_text": legal_text}

    return report


def _prompt(
    label: str,
    *,
    default: str,
    input_stream: TextIO,
    output_stream: TextIO,
) -> str:
    print(f"{label} [{default}]: ", end="", file=output_stream, flush=True)
    raw = input_stream.readline()
    if raw == "":
        raise InputError("config init needs interactive input or piped answers")
    value = raw.strip()
    return value if value else default


def _confirm(label: str, *, input_stream: TextIO, output_stream: TextIO) -> bool:
    print(f"{label} [y/N]: ", end="", file=output_stream, flush=True)
    raw = input_stream.readline()
    if raw == "":
        raise InputError("config init needs interactive input or piped answers")
    return raw.strip().lower() in {"y", "yes"}


def _prompt_parsed(
    label: str,
    *,
    parser: Callable[[str], _ParsedPromptValue],
    retry_hint: str,
    input_stream: TextIO,
    output_stream: TextIO,
) -> _ParsedPromptValue:
    while True:
        value = _prompt(
            label,
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        )
        try:
            return parser(value)
        except InputError as exc:
            print(f"Invalid input: {exc}", file=output_stream)
            print(f"Try again. {retry_hint}", file=output_stream)


def _prompt_dead_repos(*, input_stream: TextIO, output_stream: TextIO) -> dict[str, str]:
    while True:
        value = _prompt(
            "Dead repos (examples owner/repo=retired or repo-a,repo-b then one reason)",
            default="",
            input_stream=input_stream,
            output_stream=output_stream,
        )
        try:
            return _parse_mapping(value, label="dead repo")
        except InputError as exc:
            repos = _parse_csv_values(value)
            if repos and all("=" not in repo for repo in repos):
                print(
                    "Dead repos need a visible reason. You entered repo names without reasons.",
                    file=output_stream,
                )
                reason = _prompt(
                    "Reason to apply to all listed dead repos (blank retries the list)",
                    default="",
                    input_stream=input_stream,
                    output_stream=output_stream,
                )
                if reason:
                    return {repo: reason for repo in repos}
            print(f"Invalid input: {exc}", file=output_stream)
            print(
                "Try again. Use owner/repo=reason pairs such as owner/repo=retired, "
                "or enter repo-a,repo-b and then provide one reason. Press Enter to skip.",
                file=output_stream,
            )


def _parse_csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_mapping(value: str, *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _parse_csv_values(value):
        key, sep, child = item.partition("=")
        if not sep or not key.strip() or not child.strip():
            raise InputError(f"{label} entries must use key=value")
        result[key.strip()] = child.strip()
    return result


def _parse_patterns(value: str) -> list[dict[str, str]]:
    return [
        {"glob": glob, "category": category}
        for glob, category in _parse_mapping(value, label="pattern category").items()
    ]


def _parse_exclude_patterns(value: str) -> list[dict[str, str]]:
    return [
        {"glob": glob, "reason": reason}
        for glob, reason in _parse_mapping(value, label="exclude pattern").items()
    ]


def _parse_optional_positive_timeout(value: str) -> int | float | None:
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError as exc:
        raise InputError("scan.clone_timeout_seconds must be a positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise InputError("scan.clone_timeout_seconds must be a positive number")
    return int(parsed) if parsed.is_integer() else parsed


def _discover_command(args: argparse.Namespace) -> CommandResult:
    _print_config_summary(args, label="discover")
    repos = parse_repos_option(args.repos) if args.repos is not None else None
    if args.force:
        print(
            "Warning: --force regenerates repos.candidate.md and discards prior "
            "checkbox/tick edits.",
            file=sys.stderr,
        )
    result = run_discover(
        owner=args.owner,
        work_root=args.work_root,
        config=args.runtime_config,
        limit=args.limit,
        repos=repos,
        force_candidate=args.force,
    )
    # Remember the chosen work-root so the next step is copy-pasteable after
    # the candidate checklist has been reviewed.
    work_root = Path(args.work_root)
    bootstrap_command = f"repolens bootstrap --work-root {shlex.quote(str(work_root))}"
    scan_command = f"repolens scan --work-root {shlex.quote(str(work_root))}"
    return CommandResult(
        CommandStatus.SUCCESS,
        (
            f"Discovered {result.repository_count} repositories: "
            f"{result.candidate_count} candidates, {result.hard_exclusion_count} hard exclusions.\n"
            f"Created {result.discovered_path} and {result.candidate_path}.\n"
            f"Manual step: open {result.candidate_path}, untick any repos you want "
            "to exclude, and leave checked repos ready for scan.\n"
            f"Next: prepare work-root tools: {bootstrap_command}\n"
            f"Next CLI stage: {scan_command}"
        ),
    )


def _run_command(args: argparse.Namespace) -> CommandResult:
    _validate_positive_timeout("--timeout", args.timeout)
    _validate_positive_timeout("--clone-timeout", args.clone_timeout)

    work_root = Path(args.work_root)
    out_dir = _resolve_report_out_dir(work_root, args.out_dir)
    _print_run_header(args, out_dir)
    summary = RunSummary(reports_dir=out_dir)
    interactive = _run_interactive(args)

    persisted_failures = _persisted_scan_failures(work_root)
    resolved_refs = _resolved_repo_refs(work_root)
    if _report_resume_complete(work_root, out_dir, resolved_refs, args.runtime_config):
        _load_existing_report_summary(summary, out_dir)
        summary.repo_refs.update(resolved_refs)
        summary.failures.extend(persisted_failures)
        status = CommandStatus.FINDINGS_OPEN if summary.has_failures else CommandStatus.SUCCESS
        return CommandResult(status, _run_done_message(summary))

    if not _has_scan_artifacts(work_root):
        if not _discover_artifacts_exist(work_root):
            repos = parse_repos_option(args.repos) if args.repos is not None else None
            _run_banner(args, "discover", "starting")
            result = run_discover(
                owner=args.owner,
                work_root=work_root,
                config=args.runtime_config,
                repos=repos,
                force_candidate=False,
            )
            _run_banner(
                args,
                "discover",
                f"{result.repository_count} repos, {result.candidate_count} checked",
            )
        else:
            _run_banner(args, "discover", "using existing candidate review")
        if interactive:
            _run_pause(
                f"Review {work_root / 'repos.candidate.md'} (untick to exclude), "
                "then press Enter to continue.",
                interactive=True,
            )
    else:
        _run_banner(args, "discover", "skipped (scan artifacts exist)")
    _run_step_pause(args, "discover")

    scan_report = _run_scan_stage(args)
    if scan_report is not None:
        summary.repo_refs.update(outcome.repo_ref for outcome in scan_report.scanned)
        summary.repo_refs.update(outcome.repo_ref for outcome in scan_report.skipped)
        for outcome in scan_report.failed:
            summary.failures.append(
                RunFailure(
                    "scan",
                    outcome.repo_ref,
                    _sanitize(str(outcome.error or "unknown error"), redact_paths=True),
                )
            )
    else:
        summary.failures.extend(persisted_failures)
    summary.repo_refs.update(_sbom_repo_refs(work_root))
    _run_step_pause(args, "scan")

    resolved_refs = _run_resolve_stage(args, summary)
    if not resolved_refs:
        return CommandResult(CommandStatus.FINDINGS_OPEN, _run_done_message(summary))
    _run_step_pause(args, "resolve")

    if _flag_outputs_current(work_root, resolved_refs):
        _run_banner(args, "flag", "skipped (inventory/shortlist current)")
    else:
        flag_result = _flag_stage(_stage_args(args, work_root=work_root))
        _run_banner(args, "flag", _first_line(flag_result.message))
    _run_step_pause(args, "flag")

    shortlist_result = _run_shortlist_loop(args, work_root, interactive=interactive)
    if shortlist_result is not None:
        return shortlist_result

    _run_step_pause(args, "shortlist")

    report_root = _report_work_root(work_root, resolved_refs, summary)
    report_result = _report(_stage_args(args, work_root=report_root, out_dir=out_dir))
    if report_result.status is CommandStatus.FINDINGS_OPEN:
        return report_result
    if isinstance(report_result.metadata, ReportResult):
        _apply_report_result(summary, report_result.metadata)
    else:
        _load_existing_report_summary(summary, out_dir)
    _run_banner(args, "report", f"{summary.report_rows} rows")

    status = CommandStatus.FINDINGS_OPEN if summary.has_failures else CommandStatus.SUCCESS
    return CommandResult(status, _run_done_message(summary))


def _run_scan_stage(args: argparse.Namespace) -> ScanReport | None:
    work_root = Path(args.work_root)
    if _scan_complete_or_failed(work_root):
        _run_banner(args, "scan", "skipped (artifacts already exist)")
        return None

    from repolens.githost import resolve_clone_credential_result
    from repolens.scan import runner as scan_runner
    from repolens.scan.inputs import load_discover_approved_repo_specs

    repos = load_discover_approved_repo_specs(work_root, scan_runner.RepoSpec)
    scan_args = _stage_args(args, work_root=work_root)
    syft_path = _ensure_syft_for_scan(scan_args)
    progress = _ScanProgressPrinter(quiet=args.quiet, stream=sys.stderr)
    extra = _scan_timeout_kwargs(args, scan_runner)
    try:
        report = scan_runner.scan_repos(
            work_root,
            repos,
            syft_path=syft_path,
            credential_provider=resolve_clone_credential_result,
            progress=progress,
            exclude_paths=scan_runner.configured_exclude_paths(args.runtime_config.values),
            syft_catalogers=scan_runner.configured_syft_catalogers(args.runtime_config.values),
            **extra,
        )
    except scan_runner.ScanBatchError as exc:
        report = exc.report
    progress.finish(report)
    _run_banner(
        args,
        "scan",
        (
            f"{len(report.outcomes)} repos, {len(report.scanned)} scanned, "
            f"{len(report.skipped)} skipped, {len(report.failed)} failed"
        ),
    )
    return report


def _run_resolve_stage(args: argparse.Namespace, summary: RunSummary) -> set[str]:
    from repolens.resolve import run_resolve
    from repolens.resolve.stage import ResolveCacheStats

    work_root = Path(args.work_root)
    resolved_refs = set(_resolved_repo_refs(work_root))
    for repo_ref in sorted(_sbom_repo_refs(work_root), key=str.casefold):
        if repo_ref in resolved_refs:
            summary.skipped += 1
            summary.repo_refs.add(repo_ref)
            continue
        try:
            _run_banner(args, "resolve", f"{repo_ref} starting")
            cache_stats = ResolveCacheStats()
            run_resolve(work_root, repo_ref, cache_stats=cache_stats)
        except Exception as exc:
            summary.failures.append(
                RunFailure("resolve", repo_ref, _sanitize(str(exc), redact_paths=True))
            )
            continue
        resolved_refs.add(repo_ref)
        summary.repo_refs.add(repo_ref)
        detail = f"{repo_ref} done"
        if cache_stats.cache_hits:
            detail = f"{detail}; reused {cache_stats.cache_hits} cached resolution(s)"
        _run_banner(args, "resolve", detail)
    _run_scancode_retry_notice(args, work_root, tuple(sorted(resolved_refs, key=str.casefold)))
    return resolved_refs


def _stage_args(
    source: argparse.Namespace,
    *,
    work_root: Path,
    out_dir: Path | None = None,
    emit_contexts_path: Path | None = None,
    proposals_path: Path | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        work_root=work_root,
        out_dir=out_dir,
        runtime_config=source.runtime_config,
        quiet=getattr(source, "quiet", False),
        yes=getattr(source, "yes", False),
        owner=getattr(source, "owner", None),
        timeout=getattr(source, "timeout", None),
        clone_timeout=getattr(source, "clone_timeout", None),
        repos=None,
        offline=False,
        repo_ref=None,
        source_root=None,
        enable_mobile_native=False,
        identity=None,
        emit_contexts=emit_contexts_path,
        proposals=proposals_path,
        in_run=True,
    )


def _run_interactive(args: argparse.Namespace) -> bool:
    # ``getattr(..., "yes", False)`` keeps this safe for the standalone ``report``
    # parser, which has no ``--yes`` flag (no new flags per scope).
    return (
        not getattr(args, "yes", False)
        and bool(getattr(sys.stdin, "isatty", lambda: False)())
        and bool(getattr(sys.stderr, "isatty", lambda: False)())
    )


def _print_run_header(args: argparse.Namespace, out_dir: Path) -> None:
    if getattr(args, "quiet", False):
        return
    print(
        "\n".join(
            (
                "== RepoLens run ==",
                f"Work root: {args.work_root}",
                f"Owner: {args.owner}",
                f"Reports: {out_dir}",
                "Config:",
                *(f"  {line}" for line in config_discovery_lines(args.runtime_config)),
            )
        ),
        file=sys.stderr,
    )


def _print_config_summary(args: argparse.Namespace, *, label: str) -> None:
    if getattr(args, "quiet", False) or getattr(args, "in_run", False):
        return
    print(
        "\n".join(
            (
                f"== {label} config ==",
                *(f"  {line}" for line in config_discovery_lines(args.runtime_config)),
            )
        ),
        file=sys.stderr,
    )


def _run_banner(args: argparse.Namespace, stage: str, detail: str) -> None:
    if args.quiet:
        return
    if getattr(args, "_last_banner_stage", None) != stage:
        print(f"\n== {stage.title()} ==", file=sys.stderr)
        args._last_banner_stage = stage
    print(f"Status: {detail}", file=sys.stderr)


def _run_scancode_retry_notice(
    args: argparse.Namespace, work_root: Path, repo_refs: tuple[str, ...]
) -> None:
    if args.quiet:
        return
    advisory = _scancode_retry_advisory(work_root, repo_refs, after_retry=False)
    if advisory is None:
        return
    print("\n== Resolve Follow-Up ==", file=sys.stderr)
    print(advisory, file=sys.stderr)


def _run_pause(message: str, *, interactive: bool) -> None:
    print(message, file=sys.stderr)
    if interactive:
        sys.stdin.readline()


def _run_step_pause(args: argparse.Namespace, stage: str) -> None:
    if not args.step or not _run_interactive(args):
        return
    _run_pause(f"Review artifacts after {stage}, then press Enter to continue.", interactive=True)


def _run_shortlist_loop(
    args: argparse.Namespace,
    work_root: Path,
    *,
    interactive: bool,
) -> CommandResult | None:
    contexts_path = work_root / "shortlist.contexts.json"
    proposals_path = work_root / "shortlist.proposals.json"

    while True:
        _shortlist_stage(_stage_args(args, work_root=work_root, emit_contexts_path=contexts_path))
        open_count = _shortlist_open_count(work_root)
        _run_banner(args, "shortlist", f"{open_count} open item(s); contexts at {contexts_path}")
        if open_count == 0:
            return None

        if not interactive:
            if proposals_path.exists():
                _shortlist_stage(
                    _stage_args(args, work_root=work_root, proposals_path=proposals_path)
                )
                open_count = _shortlist_open_count(work_root)
                _run_banner(args, "shortlist", f"{open_count} open item(s) after proposals")
                if open_count == 0:
                    return None
            instruction = _shortlist_artifact_instruction(
                open_count,
                work_root,
                contexts_path,
                proposals_path,
            )
            return CommandResult(CommandStatus.FINDINGS_OPEN, instruction)

        _run_pause(
            "External proposal step: use the `.skills/repolens` runbook to review "
            f"{contexts_path} and write optional proposals to {proposals_path}, then "
            "press Enter.",
            interactive=True,
        )
        if proposals_path.exists():
            _shortlist_stage(_stage_args(args, work_root=work_root, proposals_path=proposals_path))
            open_count = _shortlist_open_count(work_root)
            _run_banner(args, "shortlist", f"{open_count} open item(s) after proposals")
            if open_count == 0:
                return None

        _run_pause(
            f"Review grouped decisions in {work_root / 'shortlist.md'} "
            "([x] approve / [r] reject available groups or items), then press Enter.",
            interactive=True,
        )
        _shortlist_stage(_stage_args(args, work_root=work_root))
        open_count = _shortlist_open_count(work_root)
        _run_banner(args, "shortlist", f"{open_count} open item(s) after human decisions")
        if open_count == 0:
            return None


def _shortlist_artifact_instruction(
    open_count: int,
    work_root: Path,
    contexts_path: Path,
    proposals_path: Path,
) -> str:
    return (
        f"Open shipped-license findings: {open_count}; report is halted before disclosure.\n"
        f"Contexts: {contexts_path}\n"
        f"Optional proposals: {proposals_path}\n"
        f"Grouped human review: {work_root / 'shortlist.md'}\n"
        "Next: create proposals outside RepoLens if useful, then ingest them with "
        f"`repolens shortlist --work-root {shlex.quote(str(work_root))} "
        f"--proposals {shlex.quote(str(proposals_path))}` and approve/reject groups "
        "or items in shortlist.md. Rerun `repolens run` after human approval."
    )


def _discover_artifacts_exist(work_root: Path) -> bool:
    root = Path(work_root)
    return (root / "discovered.json").exists() and (root / "repos.candidate.md").exists()


def _has_scan_artifacts(work_root: Path) -> bool:
    work_dir = Path(work_root) / "work"
    if not work_dir.is_dir():
        return False
    return any(
        path.is_dir()
        and ((path / "sbom.syft.json").exists() or (path / "scan.status.json").exists())
        for path in work_dir.iterdir()
    )


def _scan_complete_or_failed(work_root: Path) -> bool:
    from repolens.scan import runner as scan_runner
    from repolens.scan.inputs import load_discover_approved_repo_specs

    if not _discover_artifacts_exist(work_root):
        return False
    try:
        repos = load_discover_approved_repo_specs(Path(work_root), scan_runner.RepoSpec)
    except InputError:
        return False
    if not repos:
        return False
    return all(_repo_scan_terminal(work_root, spec.repo_ref) for spec in repos)


def _repo_scan_terminal(work_root: Path, repo_ref: str) -> bool:
    directory = _repo_artifact_dir(work_root, repo_ref)
    return (directory / "sbom.syft.json").exists() or _failed_scan_status(directory)


def _failed_scan_status(repo_directory: Path) -> bool:
    status_path = repo_directory / "scan.status.json"
    if not status_path.exists():
        return False
    try:
        import json

        raw = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(raw, dict) and raw.get("status") == "failed"


def _persisted_scan_failures(work_root: Path) -> list[RunFailure]:
    work_dir = Path(work_root) / "work"
    if not work_dir.is_dir():
        return []
    failures: list[RunFailure] = []
    for path in sorted(
        (item for item in work_dir.iterdir() if item.is_dir()),
        key=lambda item: item.name.casefold(),
    ):
        status_path = path / "scan.status.json"
        if not status_path.exists():
            continue
        try:
            import json

            raw = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(raw, dict) or raw.get("status") != "failed":
            continue
        failures.append(
            RunFailure(
                "scan",
                unquote(path.name),
                _sanitize(str(raw.get("error") or "unknown error"), redact_paths=True),
            )
        )
    return failures


def _sbom_repo_refs(work_root: Path) -> set[str]:
    return _repo_refs_with_artifact(work_root, "sbom.syft.json")


def _resolved_repo_refs(work_root: Path) -> set[str]:
    return _repo_refs_with_artifact(work_root, "resolved.ndjson")


def _repo_refs_with_artifact(work_root: Path, artifact_name: str) -> set[str]:
    work_dir = Path(work_root) / "work"
    if not work_dir.is_dir():
        return set()
    return {
        unquote(path.name)
        for path in work_dir.iterdir()
        if path.is_dir() and (path / artifact_name).exists()
    }


def _shortlist_open_count(work_root: Path) -> int:
    from repolens.data.store import read_shortlist

    try:
        value = read_shortlist(work_root)
    except FileNotFoundError:
        return 0
    open_count = value.get("open_count", 0)
    return open_count if isinstance(open_count, int) else 0


def _report_work_root(work_root: Path, resolved_refs: set[str], summary: RunSummary) -> Path:
    if not summary.has_failures:
        return work_root
    target = Path(work_root) / ".run-report-view"
    if target.exists():
        shutil.rmtree(target)
    (target / "work").mkdir(parents=True)
    for filename in ("discovered.json", "shortlist.json"):
        source = Path(work_root) / filename
        if source.exists():
            shutil.copy2(source, target / filename)
    for repo_ref in sorted(resolved_refs, key=str.casefold):
        source_dir = _repo_artifact_dir(work_root, repo_ref)
        target_dir = _repo_artifact_dir(target, repo_ref)
        target_dir.mkdir(parents=True, exist_ok=True)
        source = source_dir / "resolved.ndjson"
        if source.exists():
            shutil.copy2(source, target_dir / "resolved.ndjson")
    return target


def _resolve_report_out_dir(work_root: Path, out_dir: Path | None) -> Path:
    if out_dir is not None:
        return Path(out_dir)
    return Path(work_root) / "reports"


def _repo_artifact_dir(work_root: Path, repo_ref: str) -> Path:
    from repolens.data.store import repo_dir

    return repo_dir(work_root, repo_ref)


def _report_resume_complete(
    work_root: Path,
    out_dir: Path,
    resolved_refs: set[str] | None = None,
    config: Config | None = None,
) -> bool:
    refs = resolved_refs if resolved_refs is not None else _resolved_repo_refs(work_root)
    return (
        bool(refs)
        and _shortlist_complete(work_root)
        and _report_outputs_current(
            out_dir,
            _report_input_paths(work_root, refs),
            require_docx=_report_header_configured(config),
        )
    )


def _report_header_configured(config: Config | None) -> bool:
    """Whether ``report.header`` config is present (docx is then expected)."""

    values = getattr(config, "values", {})
    report = values.get("report") if isinstance(values, dict) else None
    return isinstance(report, dict) and report.get("header") is not None


def _shortlist_complete(work_root: Path) -> bool:
    root = Path(work_root)
    return (
        (root / "inventory.json").exists()
        and (root / "shortlist.json").exists()
        and (root / "shortlist.md").exists()
        and _shortlist_open_count(root) == 0
    )


def _flag_outputs_current(work_root: Path, resolved_refs: set[str]) -> bool:
    return _artifacts_current(
        _flag_output_paths(work_root), _resolved_artifact_paths(work_root, resolved_refs)
    )


def _report_outputs_current(
    out_dir: Path, input_paths: Sequence[Path], *, require_docx: bool = True
) -> bool:
    # When no header is configured the docx is legitimately skipped, so resume
    # currency keys off the always-produced md/csv only. Once a header is added,
    # the docx becomes required again so a previously skipped run re-renders it.
    filenames = REPORT_MAIN_FILENAMES if require_docx else REPORT_MAIN_DATA_FILENAMES
    output_paths = tuple(Path(out_dir) / filename for filename in filenames)
    return _artifacts_current(output_paths, input_paths)


def _flag_output_paths(work_root: Path) -> tuple[Path, Path, Path]:
    root = Path(work_root)
    return root / "inventory.json", root / "shortlist.json", root / "shortlist.md"


def _report_input_paths(work_root: Path, resolved_refs: set[str]) -> tuple[Path, ...]:
    return (*_resolved_artifact_paths(work_root, resolved_refs), *_flag_output_paths(work_root))


def _resolved_artifact_paths(work_root: Path, resolved_refs: set[str]) -> tuple[Path, ...]:
    return tuple(
        _repo_artifact_dir(work_root, repo_ref) / "resolved.ndjson"
        for repo_ref in sorted(resolved_refs, key=str.casefold)
    )


def _artifacts_current(output_paths: Sequence[Path], input_paths: Sequence[Path]) -> bool:
    if not output_paths or not input_paths:
        return False
    try:
        output_mtime = min(path.stat().st_mtime for path in output_paths)
        input_mtime = max(path.stat().st_mtime for path in input_paths)
    except FileNotFoundError:
        return False
    return output_mtime >= input_mtime


def _report_row_count(out_dir: Path) -> int:
    csv_path = Path(out_dir) / "report.main.csv"
    if not csv_path.exists():
        return 0
    text = csv_path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    return max(0, len(lines) - 1)


def _run_done_message(summary: RunSummary) -> str:
    reports = summary.reports_dir if summary.reports_dir is not None else Path("reports")
    lines = [
        "Done.",
        f"Repos included: {len(summary.repo_refs)}",
        f"Main report rows: {summary.report_rows}",
        f"Appendix rows: {_format_counts(summary.appendix_rows_by_label)}",
        f"Resume skips: {summary.skipped}",
        f"Failures: {len(summary.failures)}",
        f"Reports directory: {_resolved_path(reports)}",
        *_review_guidance(summary),
    ]
    if not summary.failures:
        return "\n".join(lines)
    details = "\n".join(
        f"  - {failure.stage}"
        f"{f' {failure.repo_ref}' if failure.repo_ref else ''}: {failure.message}"
        for failure in summary.failures
    )
    return "\n".join((*lines, "Failure details:", details))


def _apply_report_result(summary: RunSummary, result: ReportResult) -> None:
    paths = [result.markdown_path, result.csv_path]
    if result.docx_path is not None:
        paths.append(result.docx_path)
    summary.report_rows = result.row_count
    summary.report_paths = tuple(paths)
    summary.docx_skipped = result.docx_skipped
    summary.coverage_gaps_by_label = {"main": dict(result.coverage_gaps)}
    summary.appendix_rows_by_label = {
        appendix.label: appendix.row_count for appendix in result.appendices
    }
    summary.appendix_paths_by_label = {
        appendix.label: (appendix.markdown_path, appendix.csv_path)
        for appendix in result.appendices
    }
    for appendix in result.appendices:
        summary.coverage_gaps_by_label[appendix.label] = dict(appendix.coverage_gaps)


def _load_existing_report_summary(summary: RunSummary, out_dir: Path) -> None:
    summary.report_rows = _report_row_count(out_dir)
    paths: list[Path] = []
    for filename in REPORT_MAIN_FILENAMES:
        path = Path(out_dir) / filename
        if path.exists():
            paths.append(path)
    summary.report_paths = tuple(paths)
    summary.docx_skipped = not (Path(out_dir) / REPORT_MAIN_DOCX_FILENAME).exists()
    summary.coverage_gaps_by_label = {}
    main_gaps = _coverage_gaps_from_csv(Path(out_dir) / "report.main.csv")
    if main_gaps:
        summary.coverage_gaps_by_label["main"] = main_gaps
    summary.appendix_rows_by_label = {}
    summary.appendix_paths_by_label = {}
    for csv_path in sorted(
        Path(out_dir).glob("report.appendix.*.csv"),
        key=lambda path: (path.name.casefold(), path.name),
    ):
        label = unquote(csv_path.name.removeprefix("report.appendix.").removesuffix(".csv"))
        markdown_path = csv_path.with_suffix(".md")
        summary.appendix_rows_by_label[label] = _csv_data_row_count(csv_path)
        summary.appendix_paths_by_label[label] = (markdown_path, csv_path)
        gaps = _coverage_gaps_from_csv(csv_path)
        if gaps:
            summary.coverage_gaps_by_label[label] = gaps


def _csv_data_row_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", newline="") as handle:
        return max(0, sum(1 for _row in csv.reader(handle)) - 1)


def _coverage_gaps_from_csv(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    gaps: dict[str, int] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            for gap in str(row.get("coverage_gaps", "")).split(";"):
                normalized = gap.strip()
                if not normalized or normalized == "none":
                    continue
                gaps[normalized] = gaps.get(normalized, 0) + 1
    return gaps


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{label}={count}" for label, count in sorted(counts.items()))


def _format_gap_counts(gaps_by_label: dict[str, dict[str, int]]) -> str:
    chunks: list[str] = []
    for label, gaps in sorted(gaps_by_label.items()):
        if not gaps:
            continue
        chunks.append(
            f"{label}: " + ", ".join(f"{gap}={count}" for gap, count in sorted(gaps.items()))
        )
    return "; ".join(chunks)


def _review_guidance(summary: RunSummary) -> list[str]:
    lines = ["Review checklist:"]
    existing_main_paths = [path for path in summary.report_paths if path.exists()]
    if existing_main_paths:
        lines.append(
            "  - Main report: "
            + ", ".join(str(_resolved_path(path)) for path in existing_main_paths)
        )
    if summary.appendix_paths_by_label:
        appendix_parts = []
        for label, paths in sorted(summary.appendix_paths_by_label.items()):
            existing = [path for path in paths if path.exists()]
            if existing:
                appendix_parts.append(
                    f"{label}: " + ", ".join(str(_resolved_path(path)) for path in existing)
                )
        if appendix_parts:
            lines.append("  - Appendices: " + "; ".join(appendix_parts))
    gaps = _format_gap_counts(summary.coverage_gaps_by_label)
    if gaps:
        lines.append(f"  - Coverage gaps to double-check: {gaps}")
    else:
        lines.append("  - Coverage gaps: none reported in main or appendices")
    lines.append(
        "  - Shortlist: clear (0 open shipped-license findings). "
        "This does not mean appendix coverage is gap-free."
    )
    if summary.docx_skipped:
        lines.append(
            "  - Docx skipped: add report.header config or rerun report interactively "
            "to generate it."
        )
    return lines


def _resolved_path(path: Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _first_line(value: str) -> str:
    return value.splitlines()[0] if value else "done"


def _handle_scan(args: argparse.Namespace) -> CommandResult:
    # Imported here so the rest of the CLI does not pull the scan/store stack
    # (and jsonschema) unless `scan` actually runs.
    from repolens.githost import resolve_clone_credential_result
    from repolens.scan import runner as scan_runner
    from repolens.scan.inputs import load_discover_approved_repo_specs, load_explicit_repo_specs

    _print_config_summary(args, label="scan")
    if args.offline and args.yes:
        raise InputError("--offline cannot be combined with --yes")
    _validate_positive_timeout("--timeout", args.timeout)
    _validate_positive_timeout("--clone-timeout", args.clone_timeout)
    if args.repos is not None:
        repos = load_explicit_repo_specs(args.repos, scan_runner.RepoSpec)
    else:
        repos = load_discover_approved_repo_specs(args.work_root, scan_runner.RepoSpec)
    syft_path = _ensure_syft_for_scan(args)
    # scan_repos persists successful SBOMs and raises ScanBatchError only after
    # finishing the batch when expected per-repo failures occurred. The credential
    # provider resolves a read-only GitHub token lazily, only when a private repo
    # is encountered. A None timeout uses the default per-repo budget.
    extra = _scan_timeout_kwargs(args, scan_runner)
    progress = _ScanProgressPrinter(quiet=args.quiet, stream=sys.stderr)
    try:
        report = scan_runner.scan_repos(
            args.work_root,
            repos,
            syft_path=syft_path,
            credential_provider=resolve_clone_credential_result,
            progress=progress,
            exclude_paths=scan_runner.configured_exclude_paths(args.runtime_config.values),
            syft_catalogers=scan_runner.configured_syft_catalogers(args.runtime_config.values),
            **extra,
        )
    except scan_runner.ScanBatchError as exc:
        report = exc.report
    progress.finish(report)
    return _scan_command_result(report, args.work_root)


def _validate_positive_timeout(name: str, value: float | None) -> None:
    if value is not None and (not math.isfinite(value) or value <= 0):
        raise InputError(f"{name} must be a positive number of seconds")


def _scan_timeout_kwargs(args: argparse.Namespace, scan_runner: object) -> dict[str, float]:
    kwargs: dict[str, float] = {}
    if args.timeout is not None:
        kwargs["timeout_seconds"] = args.timeout
    clone_timeout = getattr(args, "clone_timeout", None)
    if clone_timeout is None:
        clone_timeout = scan_runner.configured_clone_timeout_seconds(args.runtime_config.values)
    if clone_timeout is not None:
        kwargs["clone_timeout_seconds"] = clone_timeout
    return kwargs


class _ScanProgressPrinter:
    def __init__(
        self,
        *,
        quiet: bool,
        stream: TextIO,
        heartbeat_interval: float = 30.0,
        heartbeat_factory: Callable[[float, Callable[[float], None]], _HeartbeatHandle]
        | None = None,
    ) -> None:
        self._quiet = quiet
        self._stream = stream
        self._tty = bool(getattr(stream, "isatty", lambda: False)())
        self._started_at = time.monotonic()
        self._last_line_length = 0
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_factory = heartbeat_factory or _make_heartbeat
        self._clone_heartbeat: _HeartbeatHandle | None = None

    def __call__(self, event: ScanProgressEvent) -> None:
        if self._quiet:
            return
        if event.kind == "start":
            self._stop_clone_heartbeat()
            self._write_progress_line(_scan_start_line(event), newline=not self._tty)
            self._clone_heartbeat = self._heartbeat_factory(
                self._heartbeat_interval,
                lambda elapsed: self._write_progress_line(
                    f"still cloning {event.repo_ref} ({int(elapsed)}s)…",
                    newline=True,
                ),
            )
            self._clone_heartbeat.start()
            return
        if event.kind == "outcome":
            self._stop_clone_heartbeat()
            self._write_progress_line(_scan_outcome_line(event), newline=True)

    def finish(self, report: ScanReport) -> None:
        if self._quiet:
            return
        self._stop_clone_heartbeat()
        total = len(report.outcomes)
        elapsed = _format_seconds(time.monotonic() - self._started_at)
        line = (
            f"Done: {total} repos — {len(report.scanned)} scanned, "
            f"{len(report.skipped)} skipped, {len(report.failed)} "
            f"failed in {elapsed}."
        )
        self._write_progress_line(line, newline=True)

    def _write_progress_line(self, line: str, *, newline: bool) -> None:
        if self._tty:
            padding = " " * max(0, self._last_line_length - len(line))
            text = f"\r{line}{padding}"
            self._last_line_length = len(line)
            if newline:
                text += "\n"
                self._last_line_length = 0
        else:
            text = f"{line}\n"
        print(text, end="", file=self._stream, flush=True)

    def _stop_clone_heartbeat(self) -> None:
        if self._clone_heartbeat is not None:
            self._clone_heartbeat.stop()
            self._clone_heartbeat = None


class _Heartbeat:
    def __init__(self, *, interval_seconds: float, write: Callable[[float], None]) -> None:
        self._interval_seconds = interval_seconds
        self._write = write
        self._started_at = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if self._interval_seconds > 0:
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=0.2)

    def _run(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            self._write(time.monotonic() - self._started_at)


class _HeartbeatHandle(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...


def _make_heartbeat(
    interval_seconds: float,
    write: Callable[[float], None],
) -> _HeartbeatHandle:
    return _Heartbeat(interval_seconds=interval_seconds, write=write)


def _scan_start_line(event: ScanProgressEvent) -> str:
    return f"[{event.index}/{event.total}] {event.repo_ref} — cloning…"


def _scan_outcome_line(event: ScanProgressEvent) -> str:
    prefix = f"[{event.index}/{event.total}] {event.repo_ref}"
    status = event.status
    if status == "scanned":
        deps_count = event.deps_count
        deps_count = 0 if deps_count is None else deps_count
        deps_label = f"{deps_count} deps"
        if event.raw_deps_count is not None and event.raw_deps_count > deps_count:
            deps_label = f"{deps_label} (deduped from {event.raw_deps_count} raw)"
        elapsed = _format_seconds(event.elapsed_seconds)
        return f"{prefix} ✓ {deps_label} ({elapsed})"
    if status == "skipped":
        return f"{prefix} ↻ skipped (cached)"
    reason = _sanitize(str(event.error or "unknown error"), redact_paths=True)
    return f"{prefix} ✗ failed: {reason}"


def _format_seconds(value: float | None) -> str:
    seconds = 0.0 if value is None else float(value)
    if seconds >= 60.0:
        total_seconds = int(seconds)
        minutes, remaining_seconds = divmod(total_seconds, 60)
        return f"{minutes}m{remaining_seconds:02d}s"
    return f"{seconds:.1f}s"


def _scan_command_result(report: ScanReport, work_root: Path) -> CommandResult:
    summary = (
        f"{len(report.outcomes)} repos - {len(report.scanned)} scanned, "
        f"{len(report.skipped)} skipped, {len(report.failed)} failed"
    )
    if report.failed:
        # Expected per-repo failures are user-actionable: print the summary + each
        # redacted reason to stderr and exit 1. `Internal error` is reserved for
        # genuine crashes (brief §2) and never appears here.
        print(summary, file=sys.stderr)
        for outcome in report.failed:
            reason = _sanitize(str(outcome.error or "unknown error"), redact_paths=True)
            print(f"  - {outcome.repo_ref}: {reason}", file=sys.stderr)
        return CommandResult(CommandStatus.FINDINGS_OPEN)
    next_message = _scan_next_step_message(report, work_root)
    return CommandResult(CommandStatus.SUCCESS, next_message)


def _scan_next_step_message(report: ScanReport, work_root: Path) -> str:
    resolvable = tuple(
        outcome for outcome in report.outcomes if outcome.status in {"scanned", "skipped"}
    )
    if not resolvable:
        return ""
    command = f"repolens resolve --work-root {shlex.quote(str(work_root))}"
    return f"Next CLI stage: {command}"


def _ensure_syft_for_scan(args: argparse.Namespace) -> Path:
    pin = load_syft_pin()
    cached = cached_syft_path(pin)
    if cached is not None:
        return cached

    if args.offline:
        try:
            result = ensure_syft_cached(offline=True)
        except UsageError as exc:
            raise InputError(str(exc)) from exc
        return result.path

    interactive = sys.stdin.isatty() and sys.stderr.isatty()
    if not args.yes:
        if interactive:
            print(_syft_not_installed_message(pin), file=sys.stderr)
            print(
                "Download and install RepoLens's validated Syft now? [y/N] ",
                end="",
                file=sys.stderr,
                flush=True,
            )
            answer = sys.stdin.readline().strip().lower()
            if answer not in {"y", "yes"}:
                raise InputError(_syft_declined_message(pin, interactive=True))
        else:
            raise InputError(_syft_declined_message(pin, interactive=False))

    progress = _SyftAcquireProgressPrinter(quiet=args.quiet, stream=sys.stderr)
    progress.notice(pin)
    try:
        result = ensure_syft_cached(progress=progress)
    except UsageError as exc:
        raise InputError(str(exc)) from exc
    except IntegrityError as exc:
        raise InternalError(f"Syft bootstrap integrity failure: {exc}") from exc
    progress.finish(result)
    return result.path


class _SyftAcquireProgressPrinter:
    _PHASE_LABELS = {
        "download_syft": lambda pin: f"downloading syft {pin.version}",
        "download_cosign": lambda pin: "downloading cosign",
        "verify_signature": lambda pin: "verifying signature",
        "cache": lambda pin: "caching",
    }

    def __init__(self, *, quiet: bool, stream: TextIO, heartbeat_interval: float = 10.0) -> None:
        self._quiet = quiet
        self._stream = stream
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat: _Heartbeat | None = None
        self._phase_label: str | None = None
        self._ready_printed = False

    def notice(self, pin: SyftPinSummary) -> None:
        if self._quiet:
            return
        print(
            "First run: fetching RepoLens's pinned Syft "
            f"v{pin.version} — one-time, ~a minute, cached afterward.",
            file=self._stream,
            flush=True,
        )

    def __call__(self, phase: str, pin: SyftPinSummary) -> None:
        if self._quiet:
            return
        if phase == "ready":
            self._stop_heartbeat()
            print(f"✓ Syft {pin.version} ready", file=self._stream, flush=True)
            self._ready_printed = True
            return
        label_factory = self._PHASE_LABELS.get(phase)
        if label_factory is None:
            return
        self._stop_heartbeat()
        self._phase_label = label_factory(pin)
        print(f"• {self._phase_label}…", file=self._stream, flush=True)
        self._heartbeat = _Heartbeat(
            interval_seconds=self._heartbeat_interval,
            write=lambda elapsed: self._write_still(elapsed),
        )
        self._heartbeat.start()

    def finish(self, result: SyftCacheResult) -> None:
        self._stop_heartbeat()
        if not self._quiet and not self._ready_printed:
            print(f"✓ Syft {result.pin.version} ready", file=self._stream, flush=True)

    def _write_still(self, elapsed: float) -> None:
        if self._phase_label is None:
            return
        print(f"still {self._phase_label} ({int(elapsed)}s)…", file=self._stream, flush=True)

    def _stop_heartbeat(self) -> None:
        if self._heartbeat is not None:
            self._heartbeat.stop()
            self._heartbeat = None


def _syft_not_installed_message(pin: SyftPinSummary) -> str:
    return (
        f"RepoLens's validated Syft is not installed in the shared cache.\n"
        f"Tool: Syft {pin.version} (sha256 {pin.short_sha256}...)\n"
        f"Verification: {pin.cosign_note}\n"
        f"Docs: {DOC_LINK}"
    )


def _syft_declined_message(pin: SyftPinSummary, *, interactive: bool) -> str:
    mode_hint = (
        "Rerun and answer yes, pass --yes, or run `repolens bootstrap`."
        if interactive
        else "Pass --yes for automation or run `repolens bootstrap` before scanning."
    )
    return (
        f"RepoLens's validated Syft {pin.version} (sha256 {pin.short_sha256}...) is required. "
        f"Nothing was downloaded. See {DOC_LINK}. {mode_hint}"
    )


def _resolve_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.resolve import run_resolve
    from repolens.resolve.stage import ResolveCacheStats

    repo_refs = _resolve_repo_refs(args.work_root, args.repo_ref)
    if args.source_root is not None and len(repo_refs) > 1:
        raise InputError("resolve --source-root supports exactly one repo; pass one --repo-ref")
    retry_scancode = bool(getattr(args, "retry_scancode", False))
    if retry_scancode:
        repo_refs = _repo_refs_needing_scancode_retry(args.work_root, repo_refs)
        if not repo_refs:
            flag_command = f"repolens flag --work-root {shlex.quote(str(args.work_root))}"
            return CommandResult(
                CommandStatus.SUCCESS,
                (
                    "No repos need ScanCode retry: no existing resolved.ndjson contains "
                    "unresolved:scancode_tool_unavailable.\n"
                    f"Next CLI stage: {flag_command}"
                ),
            )
        _ensure_scancode_ready_for_retry(Path(args.work_root))
    paths = []
    total = len(repo_refs)
    progress = _ResolveProgressPrinter(stream=sys.stderr)
    total_cache_hits = 0
    for index, repo_ref in enumerate(repo_refs, start=1):
        repo_started_at = time.monotonic()
        progress.start_repo(index, total, repo_ref)
        cache_stats = ResolveCacheStats()

        def package_progress(
            package_index: int,
            package_total: int,
            package_name: str,
            *,
            repo_index: int = index,
            repo_total: int = total,
            current_repo_ref: str = repo_ref,
            started_at: float = repo_started_at,
        ) -> None:
            progress.package(
                repo_index,
                repo_total,
                current_repo_ref,
                package_index,
                package_total,
                package_name,
                time.monotonic() - started_at,
            )

        path = run_resolve(
            args.work_root,
            repo_ref,
            source_root=args.source_root,
            enable_mobile_native=args.enable_mobile_native,
            detect_conflicts=args.detect_conflicts,
            progress=package_progress,
            cache_stats=cache_stats,
        )
        total_cache_hits += cache_stats.cache_hits
        progress.repo_done(
            index,
            total,
            repo_ref,
            path.name,
            time.monotonic() - repo_started_at,
            cache_hits=cache_stats.cache_hits,
        )
        paths.append(path)
    progress.finish(total, cache_hits=total_cache_hits)
    flag_command = f"repolens flag --work-root {shlex.quote(str(args.work_root))}"
    if len(paths) == 1:
        write_summary = f"{'retried ScanCode; ' if retry_scancode else ''}wrote {paths[0].name}"
    else:
        preview = ", ".join(repo_refs[:5])
        suffix = "" if len(repo_refs) <= 5 else ", ..."
        action = "retried ScanCode for" if retry_scancode else "resolved"
        write_summary = f"{action} {len(repo_refs)} repos: {preview}{suffix}"
    retry_advisory = _scancode_retry_advisory(
        args.work_root,
        repo_refs,
        after_retry=retry_scancode,
    )
    if retry_advisory is not None:
        return CommandResult(
            CommandStatus.SUCCESS,
            f"{write_summary}{_resolve_cache_summary(total_cache_hits)}\n{retry_advisory}",
        )
    return CommandResult(
        CommandStatus.SUCCESS,
        (
            f"{write_summary}{_resolve_cache_summary(total_cache_hits)}\n"
            f"Next CLI stage: {flag_command}"
        ),
    )


def _resolve_cache_summary(cache_hits: int) -> str:
    if cache_hits <= 0:
        return ""
    return f"; reused {cache_hits} cached resolution(s)"


def _ensure_scancode_ready_for_retry(work_root: Path) -> None:
    from repolens.resolve.scancode import resolve_scancode_path

    try:
        resolve_scancode_path(work_root)
    except InputError as exc:
        raise InputError(
            f"ScanCode is not ready for retry: {exc}\n"
            f"Fix: repolens bootstrap --work-root {shlex.quote(str(work_root))}"
        ) from exc


class _ResolveProgressPrinter:
    def __init__(
        self,
        *,
        stream: TextIO,
        non_tty_package_interval: int = 25,
        non_tty_seconds_interval: float = 30.0,
    ) -> None:
        self._stream = stream
        self._tty = bool(getattr(stream, "isatty", lambda: False)())
        self._last_line_length = 0
        self._started_at = time.monotonic()
        self._non_tty_package_interval = non_tty_package_interval
        self._non_tty_seconds_interval = non_tty_seconds_interval
        self._last_non_tty_report = self._started_at

    def start_repo(self, index: int, total: int, repo_ref: str) -> None:
        self._write_progress_line(
            f"[{index}/{total}] {repo_ref} — resolving...",
            newline=not self._tty,
        )

    def package(
        self,
        repo_index: int,
        repo_total: int,
        repo_ref: str,
        package_index: int,
        package_total: int,
        package_name: str,
        elapsed_seconds: float,
    ) -> None:
        now = time.monotonic()
        if not self._tty and not self._should_report_non_tty(package_index, package_total, now):
            return
        elapsed = _format_seconds(elapsed_seconds)
        line = (
            f"[{repo_index}/{repo_total}] {repo_ref} — "
            f"{package_index}/{package_total} resolved… ({elapsed})"
        )
        if package_name:
            line = f"{line} {package_name}"
        self._write_progress_line(line, newline=not self._tty)
        self._last_non_tty_report = now

    def repo_done(
        self,
        index: int,
        total: int,
        repo_ref: str,
        path_name: str,
        elapsed_seconds: float,
        *,
        cache_hits: int = 0,
    ) -> None:
        elapsed = _format_seconds(elapsed_seconds)
        reused = f"; reused {cache_hits} cached resolution(s)" if cache_hits else ""
        self._write_progress_line(
            f"[{index}/{total}] {repo_ref} ✓ wrote {path_name} ({elapsed}){reused}",
            newline=True,
        )

    def finish(self, repo_count: int, *, cache_hits: int = 0) -> None:
        elapsed = _format_seconds(time.monotonic() - self._started_at)
        reused = f"; reused {cache_hits} cached resolution(s)" if cache_hits else ""
        self._write_progress_line(
            f"Done: {repo_count} repos resolved in {elapsed}{reused}.",
            newline=True,
        )

    def _should_report_non_tty(self, package_index: int, package_total: int, now: float) -> bool:
        return (
            package_index == package_total
            or package_index % self._non_tty_package_interval == 0
            or now - self._last_non_tty_report >= self._non_tty_seconds_interval
        )

    def _write_progress_line(self, line: str, *, newline: bool) -> None:
        if self._tty:
            padding = " " * max(0, self._last_line_length - len(line))
            text = f"\r{line}{padding}"
            self._last_line_length = len(line)
            if newline:
                text += "\n"
                self._last_line_length = 0
        else:
            text = f"{line}\n"
        print(text, end="", file=self._stream, flush=True)


def _resolve_repo_refs(work_root: Path, repo_ref: str | Sequence[str] | None) -> tuple[str, ...]:
    requested_refs = _requested_repo_refs(repo_ref)
    if requested_refs:
        return requested_refs
    work_dir = Path(work_root) / "work"
    command = f"repolens scan --work-root {shlex.quote(str(work_root))}"
    approval_error = None
    try:
        approved_refs = _approved_resolve_repo_refs(work_root)
    except InputError as exc:
        approved_refs = ()
        approval_error = exc
    if approved_refs:
        from repolens.data.store import repo_dir

        available = tuple(
            candidate
            for candidate in approved_refs
            if (repo_dir(work_root, candidate) / "sbom.syft.json").is_file()
        )
        available_set = set(available)
        missing = tuple(candidate for candidate in approved_refs if candidate not in available_set)
        if available:
            if missing:
                _warn_missing_checked_sboms(missing, command)
            return available
        if missing and not work_dir.is_dir():
            preview = ", ".join(missing[:5])
            suffix = "" if len(missing) <= 5 else ", ..."
            raise InputError(
                f"resolve is missing SBOMs for checked repos: {preview}{suffix}; "
                f"run `{command}` first."
            )
        if missing:
            _warn_missing_checked_sboms(missing, command)
    if not work_dir.is_dir():
        if approval_error is not None:
            raise approval_error
        raise InputError(f"resolve found no scanned repos under {work_dir}; run `{command}` first.")
    repo_refs = tuple(
        unquote(path.name)
        for path in sorted(work_dir.iterdir(), key=lambda item: item.name.casefold())
        if path.is_dir() and (path / "sbom.syft.json").is_file()
    )
    if not repo_refs:
        if approval_error is not None:
            raise approval_error
        raise InputError(f"resolve found no SBOMs under {work_dir}; run `{command}` first.")
    if approval_error is not None:
        _warn_ignored_discover_approval_error(approval_error)
    return repo_refs


def _requested_repo_refs(repo_ref: str | Sequence[str] | None) -> tuple[str, ...]:
    if repo_ref is None:
        return ()
    if isinstance(repo_ref, str):
        return (repo_ref,)
    return tuple(str(ref) for ref in repo_ref if str(ref))


_SCANCODE_TOOL_UNAVAILABLE_ANCHOR = "unresolved:scancode_tool_unavailable"


def _repo_refs_needing_scancode_retry(
    work_root: Path, repo_refs: tuple[str, ...]
) -> tuple[str, ...]:
    from repolens.data import store

    retry_refs: list[str] = []
    for repo_ref in repo_refs:
        path = store.repo_dir(work_root, repo_ref) / "resolved.ndjson"
        if not path.is_file():
            continue
        for record in store.iter_resolved(path):
            evidence = record.get("evidence")
            if (
                isinstance(evidence, dict)
                and evidence.get("anchor") == _SCANCODE_TOOL_UNAVAILABLE_ANCHOR
            ):
                retry_refs.append(repo_ref)
                break
    return tuple(retry_refs)


def _scancode_retry_advisory(
    work_root: Path,
    repo_refs: tuple[str, ...],
    *,
    after_retry: bool,
) -> str | None:
    retry_refs = _repo_refs_needing_scancode_retry(work_root, repo_refs)
    if not retry_refs:
        return None
    retry_command = f"repolens resolve --work-root {shlex.quote(str(work_root))} --retry-scancode"
    flag_command = f"repolens flag --work-root {shlex.quote(str(work_root))}"
    preview = ", ".join(retry_refs[:5])
    suffix = "" if len(retry_refs) <= 5 else ", ..."
    intro = (
        "ScanCode is still unavailable"
        if after_retry
        else "ScanCode was unavailable during resolve"
    )
    return "\n".join(
        (
            "ScanCode follow-up:",
            (
                f"  {intro}: {len(retry_refs)} repo(s) still contain "
                f"{_SCANCODE_TOOL_UNAVAILABLE_ANCHOR}."
            ),
            f"  Affected repos: {preview}{suffix}",
            "",
            "Prepare ScanCode for this work root:",
            f"  repolens bootstrap --work-root {shlex.quote(str(work_root))}",
            "",
            "Then retry ScanCode:",
            f"  {retry_command}",
            "",
            "Then rebuild the shortlist inputs:",
            f"  {flag_command}",
        )
    )


def _warn_ignored_discover_approval_error(error: InputError) -> None:
    print(
        f"Warning: resolve could not use checked discover approvals ({error}); "
        "resolving available scanned SBOMs instead.",
        file=sys.stderr,
    )


def _warn_missing_checked_sboms(missing: tuple[str, ...], command: str) -> None:
    preview = ", ".join(missing[:5])
    suffix = "" if len(missing) <= 5 else ", ..."
    print(
        f"Warning: resolve skipped checked repos without SBOMs: {preview}{suffix}; "
        f"run `{command}` to scan them.",
        file=sys.stderr,
    )


def _approved_resolve_repo_refs(work_root: Path) -> tuple[str, ...]:
    root = Path(work_root)
    if not (root / "discovered.json").exists() or not (root / "repos.candidate.md").exists():
        return ()
    from repolens.scan import runner as scan_runner
    from repolens.scan.inputs import load_discover_approved_repo_specs

    specs = load_discover_approved_repo_specs(root, scan_runner.RepoSpec)
    return tuple(spec.repo_ref for spec in specs)


def _flag_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.flag import run_flag

    result = run_flag(args.work_root)
    summary = (
        f"flagged {result.open_count} open item(s) across {result.component_count} "
        f"component(s); wrote {result.inventory_path.name}, "
        f"{result.shortlist_json_path.name}, {result.shortlist_md_path.name}"
    )
    if result.preserved_decision_count:
        summary = f"{summary}; preserved {result.preserved_decision_count} prior decision(s)"
    shortlist_command = f"repolens shortlist --work-root {shlex.quote(str(args.work_root))}"
    summary = f"{summary}\nNext CLI stage: {shortlist_command}"
    if result.open_count > 0:
        return CommandResult(CommandStatus.FINDINGS_OPEN, summary)
    return CommandResult(CommandStatus.SUCCESS, summary)


def _shortlist_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.shortlist import run_shortlist
    from repolens.shortlist.agent import AgentRequest, AgentResponse

    # The default offline agent abstains. RepoLens itself never invokes a model; artifact
    # proposal workflows run outside RepoLens, then this stage re-fetches and verifies
    # citations before recording candidates.
    class _AbstainingAgent:
        def resolve(self, request: AgentRequest) -> AgentResponse:
            from repolens.shortlist.agent import Abstain

            del request
            return Abstain(reason="no_offline_agent")

    result = run_shortlist(
        args.work_root,
        agent_client=_AbstainingAgent(),
        identity=args.identity,
        emit_contexts_path=args.emit_contexts,
        proposals_path=args.proposals,
    )
    summary = (
        f"settled shortlist: {result.open_count} open item(s) of {result.item_count}; "
        f"wrote {result.shortlist_json_path.name}, {result.shortlist_md_path.name}"
    )
    contexts_path = getattr(result, "contexts_path", None)
    if contexts_path is not None:
        summary = f"{summary}; emitted contexts {contexts_path}"
    if args.proposals is not None:
        summary = f"{summary}; ingested proposals {args.proposals}"
    if result.open_count > 0:
        return CommandResult(
            CommandStatus.FINDINGS_OPEN,
            f"{summary}\n{_shortlist_open_guidance(args, result.shortlist_md_path, contexts_path)}",
        )
    report_command = f"repolens report --work-root {shlex.quote(str(args.work_root))}"
    return CommandResult(CommandStatus.SUCCESS, f"{summary}\nNext CLI stage: {report_command}")


def _shortlist_open_guidance(
    args: argparse.Namespace,
    shortlist_md_path: Path,
    contexts_path: Path | None,
) -> str:
    work_root = Path(args.work_root)
    work_root_arg = shlex.quote(str(work_root))
    contexts = contexts_path or work_root / "shortlist.contexts.json"
    proposals = work_root / "shortlist.proposals.json"
    review_notes = work_root / "shortlist.review.md"
    emit_command = (
        f"repolens shortlist --work-root {work_root_arg} "
        f"--emit-contexts {shlex.quote(str(contexts))}"
    )
    ingest_command = (
        f"repolens shortlist --work-root {work_root_arg} --proposals {shlex.quote(str(proposals))}"
    )
    rerun_command = f"repolens shortlist --work-root {work_root_arg}"
    bucket_hint = _shortlist_unresolved_bucket_hint(work_root)
    scancode_retry_hint = _shortlist_scancode_retry_hint(work_root)

    if args.proposals is not None:
        sections = [
            "Manual step: proposals were ingested, but some items remain open.",
            "",
        ]
        if bucket_hint:
            sections.extend((bucket_hint, ""))
        if scancode_retry_hint:
            sections.extend((scancode_retry_hint, ""))
        sections.extend(_shortlist_review_notes_guidance(work_root, args.proposals))
        sections.extend(
            (
                "Human review:",
                f"  Open and edit decisions: {shortlist_md_path}",
                "  Mark remaining rows or groups with [x] to accept or [r] to reject.",
                "",
                "Then rerun:",
                f"  {rerun_command}",
            )
        )
        return "\n".join(sections)
    if contexts_path is not None:
        sections = [
            "Manual step: contexts are ready for AI-assisted shortlist review.",
            "",
        ]
        if bucket_hint:
            sections.extend((bucket_hint, ""))
        if scancode_retry_hint:
            sections.extend((scancode_retry_hint, ""))
        sections.extend(
            (
                "Ask Codex/Claude:",
                "  $repolens review every row in:",
                f"    {contexts}",
                "  Write:",
                f"    proposals: {proposals}",
                f"    review notes: {review_notes}",
                "",
                "Then ingest verified proposals:",
                f"  {ingest_command}",
                "",
                "Evidence notes:",
                f"  Review notes will be written to: {review_notes}",
                "  Use them as supporting evidence after proposal ingestion.",
                "",
                "Human review:",
                f"  Open and edit decisions: {shortlist_md_path}",
                "  Approve/reject remaining items, then rerun:",
                f"  {rerun_command}",
            )
        )
        return "\n".join(sections)
    sections = [
        "Manual step: resolve open shortlist items before report.",
        "",
    ]
    if bucket_hint:
        sections.extend((bucket_hint, ""))
    if scancode_retry_hint:
        sections.extend((scancode_retry_hint, ""))
    sections.extend(_shortlist_review_notes_guidance(work_root, None))
    sections.extend(
        (
            "AI-assisted pass for UNKNOWNs/stale evidence:",
            "  Emit contexts:",
            f"    {emit_command}",
            "",
            "  Ask Codex/Claude:",
            "    $repolens review every row in:",
            f"      {contexts}",
            "    Write:",
            f"      proposals: {proposals}",
            f"      review notes: {review_notes}",
            "",
            "  Ingest verified proposals:",
            f"    {ingest_command}",
            "",
            "Human review:",
            f"  Open and edit decisions: {shortlist_md_path}",
            "  Mark remaining rows or groups with [x] to accept or [r] to reject.",
            "",
            "Then rerun:",
            f"  {rerun_command}",
        )
    )
    return "\n".join(sections)


def _shortlist_review_notes_guidance(
    work_root: Path, proposals_arg: object | None
) -> tuple[str, ...]:
    review_notes = _shortlist_existing_review_notes_path(work_root, proposals_arg)
    if review_notes is None:
        return ()
    return (
        "Evidence notes:",
        f"  Read supporting evidence: {review_notes}",
        "  Use this for proposal rationale and browser-evidence breadcrumbs; edit decisions "
        "only in shortlist.md.",
        "",
    )


def _shortlist_existing_review_notes_path(
    work_root: Path, proposals_arg: object | None
) -> Path | None:
    candidates: list[Path] = []
    if proposals_arg is not None:
        proposals_path = Path(proposals_arg)
        name = proposals_path.name
        if name.endswith(".proposals.json"):
            candidates.append(
                proposals_path.with_name(f"{name.removesuffix('.proposals.json')}.review.md")
            )
    candidates.append(Path(work_root) / "shortlist.review.md")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _shortlist_unresolved_bucket_hint(work_root: Path) -> str:
    path = Path(work_root) / "shortlist.json"
    if not path.is_file():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    items = payload.get("items")
    if not isinstance(items, list):
        return ""
    counts: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict) or item.get("status") != "open":
            continue
        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            continue
        anchor = evidence.get("anchor")
        if isinstance(anchor, str):
            counts[anchor] = counts.get(anchor, 0) + 1
    sections: list[str] = []
    no_target = counts.get("unresolved:scancode_no_target", 0)
    if no_target:
        sections.append(
            f"  {no_target} open row(s) have unresolved:scancode_no_target: RepoLens found "
            "no safe package-local source target, often because the SBOM points only at a "
            "lockfile. Bootstrapping ScanCode or --retry-scancode does not change this selector."
        )
    no_api = counts.get("unresolved:no_supported_catalog_license_api", 0)
    if no_api:
        sections.append(
            f"  {no_api} open row(s) have unresolved:no_supported_catalog_license_api: "
            "RepoLens did not find exact supported public metadata for those package "
            "identities and versions."
        )
    if not sections:
        return ""
    return "\n".join(("Open UNKNOWN bucket summary:", *sections))


def _shortlist_scancode_retry_hint(work_root: Path) -> str:
    retry_refs = _repo_refs_with_scancode_unavailable(work_root)
    if not retry_refs:
        return ""
    work_root_arg = shlex.quote(str(work_root))
    preview = ", ".join(retry_refs[:5])
    suffix = "" if len(retry_refs) <= 5 else ", ..."
    selected_args = " ".join(f"--repo-ref {shlex.quote(repo_ref)}" for repo_ref in retry_refs[:2])
    return "\n".join(
        (
            "Tool retry for ScanCode-backed UNKNOWNs:",
            (
                f"  {len(retry_refs)} repo(s) still contain "
                f"{_SCANCODE_TOOL_UNAVAILABLE_ANCHOR}: {preview}{suffix}"
            ),
            "  Prepare ScanCode for this work root:",
            f"    repolens bootstrap --work-root {work_root_arg}",
            "  Then retry all affected repos:",
            f"    repolens resolve --work-root {work_root_arg} --retry-scancode",
            "  Or retry only selected repos; repeat --repo-ref for several:",
            (f"    repolens resolve --work-root {work_root_arg} --retry-scancode {selected_args}"),
            f"    repolens flag --work-root {work_root_arg}",
            (
                "  `flag` preserves matching approved/rejected shortlist decisions and "
                "keeps changed findings open."
            ),
        )
    )


def _repo_refs_with_scancode_unavailable(work_root: Path) -> tuple[str, ...]:
    work_dir = Path(work_root) / "work"
    if not work_dir.is_dir():
        return ()
    repo_refs = tuple(
        unquote(path.name)
        for path in sorted(work_dir.iterdir(), key=lambda item: item.name.casefold())
        if path.is_dir() and (path / "resolved.ndjson").is_file()
    )
    return _repo_refs_needing_scancode_retry(Path(work_root), repo_refs)


def _report(args: argparse.Namespace) -> CommandResult:
    _print_config_summary(args, label="report")
    out_dir = _resolve_report_out_dir(Path(args.work_root), args.out_dir)
    try:
        result = render_main_report(
            args.work_root,
            out_dir,
            args.runtime_config,
            interactive=_run_interactive(args),
            owner=getattr(args, "owner", None),
        )
    except ReportGateOpen as exc:
        return CommandResult(CommandStatus.FINDINGS_OPEN, str(exc))
    summary = RunSummary(reports_dir=out_dir)
    _apply_report_result(summary, result)
    return CommandResult(
        CommandStatus.SUCCESS,
        _report_done_message(summary),
        metadata=result,
    )


def _report_done_message(summary: RunSummary) -> str:
    reports = summary.reports_dir if summary.reports_dir is not None else Path("reports")
    return "\n".join(
        (
            "Report written.",
            f"Main report rows: {summary.report_rows}",
            f"Appendix rows: {_format_counts(summary.appendix_rows_by_label)}",
            f"Reports directory: {_resolved_path(reports)}",
            *_review_guidance(summary),
        )
    )


def _exit_code_for_result(result: CommandResult) -> int:
    if result.status is CommandStatus.SUCCESS:
        return int(ExitCode.SUCCESS)
    if result.status is CommandStatus.FINDINGS_OPEN:
        return int(ExitCode.FINDINGS_OPEN)
    raise InputError("Unknown command result")


def _sanitize(message: str, *, redact_paths: bool = True) -> str:
    redacted = redact_tokens(message)
    if not redact_paths:
        return redacted
    return PATH_PATTERN.sub("[REDACTED_PATH]", redacted)
