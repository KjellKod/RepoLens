"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
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
from typing import TYPE_CHECKING, Protocol, TextIO
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
from repolens.report import ReportGateOpen, render_main_report
from repolens.security.redaction import redact_tokens

from .config import load_config
from .data.errors import ArtifactError
from .discovery.gh import DEFAULT_GH_LIMIT, MAX_GH_LIMIT, parse_repos_option
from .discovery.pipeline import run_discover
from .exit_codes import ExitCode, InputError, InternalError

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


CommandHandler = Callable[[argparse.Namespace], CommandResult]


STAGE_COMMANDS = ("discover", "scan", "resolve", "flag", "shortlist", "report")
REPORT_MAIN_FILENAMES = ("report.main.md", "report.main.csv", "report.main.docx")


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
            "`repolens scan --work-root <WORK>`.",
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
        epilog=_stage_epilog(
            "Syft SBOMs from scan at <WORK>/work/*/sbom.syft.json. By default, "
            "resolve uses checked discover repos with SBOMs, then falls back to "
            "available scanned SBOMs when no checked SBOM is present; --repo-ref "
            "narrows resolve to one repo artifact directory; "
            "--source-root may point at a read-only checkout for mobile markers and "
            "package-local ScanCode fallback.",
            "repolens resolve --work-root <WORK>",
            "<WORK>/work/<repo_ref>/resolved.ndjson (license + evidence + tags per "
            "dependency; unresolved records stay schema-valid).",
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
        description=("Stage 5/6 — settle flagged items with anchored evidence and your approval."),
        epilog=_stage_epilog(
            "shortlist.json + shortlist.md from flag under <WORK>.",
            "repolens shortlist --work-root work [--identity <REVIEWER>]",
            "shortlist.json + shortlist.md rewritten with settled statuses, candidate "
            "evidence, and your recorded approvals; exits 1 while any item is still open.",
            "once nothing is open, `repolens report`.",
        ),
    ),
    "report": StageHelp(
        help="Assemble gated main, appendix, and docx disclosure reports.",
        description=("Stage 6/6 — assemble gated disclosure reports from resolved artifacts."),
        epilog=_stage_epilog(
            "resolved.ndjson files from resolve, discovered.json categories when present, "
            "a clear shortlist.json when present, and report.header config for docx.",
            "repolens report --work-root <WORK> --out-dir reports",
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

_EPILOG = (
    "global options:\n"
    "  Put global options before the stage name, e.g.\n"
    "    repolens --config ./repolens.local.toml discover --owner <OWNER>\n"
    "  Config files hold local taxonomy, policy, and report settings; owner is\n"
    "  still supplied at runtime with --owner.\n"
    "  Use stage options such as --work-root for output directories; --config is\n"
    "  only for local config files.\n"
    "\n"
    "recommended:\n"
    "  repolens run --work-root work --owner <OWNER> --out-dir reports\n"
    "\n"
    "step it yourself:\n"
    "  1. repolens discover --owner <OWNER>                     find + approve the repos\n"
    "  2. repolens scan --work-root work                        inventory approved dependencies\n"
    "  3. repolens resolve --work-root work                     resolve scanned repos\n"
    "  4. repolens flag --work-root work                        flag risk / unknowns\n"
    "  5. repolens shortlist --work-root work                   settle the flags + approve\n"
    "  6. repolens report --work-root work --out-dir reports    build the main disclosure\n"
    "\n"
    "Scan auto-acquires and verifies RepoLens's pinned Syft into a shared cache on\n"
    "first use; `repolens bootstrap` pre-seeds it for offline runs. Run\n"
    "`repolens <stage> --help` for one stage. Full guide: docs/usage.md."
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

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="Pre-seed RepoLens's verified shared tool cache for offline scans.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Pre-seed RepoLens's verified shared Syft cache for offline scans.",
        epilog=(
            "Before: nothing, or an empty shared cache.\n"
            "Example: repolens bootstrap\n"
            "Output: ~/.cache/repolens/tools/<version>-<sha256>/syft (or XDG_CACHE_HOME).\n"
            "Next: `repolens scan --work-root <WORK> --offline`."
        ),
    )
    bootstrap_parser.set_defaults(handler=_bootstrap_command)

    run_parser = subparsers.add_parser(
        "run",
        help="Recommended: run the full pipeline with inline pauses and resume.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Recommended entry point — discover, scan, resolve, flag, shortlist, and report "
            "with human pauses only where review is required."
        ),
        epilog=(
            "Example: repolens run --work-root work --owner <OWNER> --out-dir reports\n"
            "Automation: repolens run --work-root work --owner <OWNER> --out-dir reports --yes\n"
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
        help="Per-repo wall-clock budget for the Syft scan (default: clone timeout).",
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
        default=Path("reports"),
        metavar="PATH",
        help="Directory for report.main.{md,csv,docx} and appendix artifacts.",
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
        help="Per-repo wall-clock budget for the Syft scan (default: clone timeout).",
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
        metavar="REPO_REF",
        help=(
            "Optional runtime repository reference used for one work/<repo-ref>/ "
            "artifact dir; omit to resolve checked scan output."
        ),
    )
    subparser.add_argument(
        "--source-root",
        type=Path,
        metavar="PATH",
        help=(
            "Optional read-only source checkout for mobile marker detection and scoped "
            "ScanCode fallback."
        ),
    )
    subparser.add_argument(
        "--enable-mobile-native",
        action="store_true",
        help="Opt in to sandboxed native mobile license enrichment when mobile markers exist.",
    )
    subparser.add_argument(
        "--detect-conflicts",
        action="store_true",
        help=(
            "Cross-check all API adapters and write CONFLICT when verified sources disagree "
            "(slower; default stops at the first verified API source)."
        ),
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
            "Runtime reviewer identity recorded as decided_by on approved/rejected items; "
            "never an owner/repo literal."
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            parser.print_help()
            return int(ExitCode.SUCCESS)

        config_path = getattr(args, "run_config", None) or args.config
        args.runtime_config = load_config(Path.cwd(), config_path)
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


def _stage_stub(args: argparse.Namespace) -> CommandResult:
    if args.findings_open:
        return CommandResult(CommandStatus.FINDINGS_OPEN, "findings remain open")
    return CommandResult(CommandStatus.SUCCESS, "skeleton command completed")


def _bootstrap_command(args: argparse.Namespace) -> CommandResult:
    del args
    try:
        result = ensure_syft_cached()
    except UsageError as exc:
        raise InputError(str(exc)) from exc
    except IntegrityError as exc:
        raise InternalError(f"Syft bootstrap integrity failure: {exc}") from exc

    status = "acquired and verified" if result.acquired else "already verified"
    return CommandResult(
        CommandStatus.SUCCESS,
        f"Syft {result.pin.version} ({result.pin.short_sha256}...) {status}: {result.path}",
    )


def _discover_command(args: argparse.Namespace) -> CommandResult:
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
    scan_command = f"repolens scan --work-root {shlex.quote(str(work_root))}"
    return CommandResult(
        CommandStatus.SUCCESS,
        (
            f"Discovered {result.repository_count} repositories: "
            f"{result.candidate_count} candidates, {result.hard_exclusion_count} hard exclusions.\n"
            f"Created {result.discovered_path} and {result.candidate_path}.\n"
            f"Manual step: open {result.candidate_path}, untick any repos you want "
            "to exclude, and leave checked repos ready for scan.\n"
            f"Next CLI stage: {scan_command}"
        ),
    )


def _run_command(args: argparse.Namespace) -> CommandResult:
    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        raise InputError("--timeout must be a positive number of seconds")

    work_root = Path(args.work_root)
    out_dir = Path(args.out_dir)
    summary = RunSummary(reports_dir=out_dir)
    interactive = _run_interactive(args)

    persisted_failures = _persisted_scan_failures(work_root)
    resolved_refs = _resolved_repo_refs(work_root)
    if _report_resume_complete(work_root, out_dir, resolved_refs):
        summary.report_rows = _report_row_count(out_dir)
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

    while True:
        _shortlist_stage(_stage_args(args, work_root=work_root))
        open_count = _shortlist_open_count(work_root)
        _run_banner(args, "shortlist", f"{open_count} open item(s)")
        if open_count == 0:
            break
        instruction = (
            f"{open_count} items need a decision in {work_root / 'shortlist.md'} "
            "([x] approve / [r] reject), then press Enter."
        )
        if not interactive:
            print(
                f"{open_count} items still need review in {work_root / 'shortlist.md'}",
                file=sys.stderr,
            )
            return CommandResult(CommandStatus.FINDINGS_OPEN, instruction)
        _run_pause(instruction, interactive=True)

    _run_step_pause(args, "shortlist")

    report_root = _report_work_root(work_root, resolved_refs, summary)
    report_result = _report(_stage_args(args, work_root=report_root, out_dir=out_dir))
    if report_result.status is CommandStatus.FINDINGS_OPEN:
        return report_result
    summary.report_rows = _report_row_count(out_dir)
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
    extra = {"timeout_seconds": args.timeout} if args.timeout is not None else {}
    try:
        report = scan_runner.scan_repos(
            work_root,
            repos,
            syft_path=syft_path,
            credential_provider=resolve_clone_credential_result,
            progress=progress,
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

    work_root = Path(args.work_root)
    resolved_refs = set(_resolved_repo_refs(work_root))
    for repo_ref in sorted(_sbom_repo_refs(work_root), key=str.casefold):
        if repo_ref in resolved_refs:
            summary.skipped += 1
            summary.repo_refs.add(repo_ref)
            continue
        try:
            _run_banner(args, "resolve", f"{repo_ref} starting")
            run_resolve(work_root, repo_ref)
        except Exception as exc:
            summary.failures.append(
                RunFailure("resolve", repo_ref, _sanitize(str(exc), redact_paths=True))
            )
            continue
        resolved_refs.add(repo_ref)
        summary.repo_refs.add(repo_ref)
        _run_banner(args, "resolve", f"{repo_ref} done")
    return resolved_refs


def _stage_args(
    source: argparse.Namespace,
    *,
    work_root: Path,
    out_dir: Path | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        work_root=work_root,
        out_dir=out_dir,
        runtime_config=source.runtime_config,
        quiet=getattr(source, "quiet", False),
        yes=getattr(source, "yes", False),
        timeout=getattr(source, "timeout", None),
        repos=None,
        offline=False,
        repo_ref=None,
        source_root=None,
        enable_mobile_native=False,
        identity=None,
    )


def _run_interactive(args: argparse.Namespace) -> bool:
    return (
        not args.yes
        and bool(getattr(sys.stdin, "isatty", lambda: False)())
        and bool(getattr(sys.stderr, "isatty", lambda: False)())
    )


def _run_banner(args: argparse.Namespace, stage: str, detail: str) -> None:
    if args.quiet:
        return
    print(f"> {stage} ... {detail}", file=sys.stderr)


def _run_pause(message: str, *, interactive: bool) -> None:
    print(message, file=sys.stderr)
    if interactive:
        sys.stdin.readline()


def _run_step_pause(args: argparse.Namespace, stage: str) -> None:
    if not args.step or not _run_interactive(args):
        return
    _run_pause(f"Review artifacts after {stage}, then press Enter to continue.", interactive=True)


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


def _repo_artifact_dir(work_root: Path, repo_ref: str) -> Path:
    from repolens.data.store import repo_dir

    return repo_dir(work_root, repo_ref)


def _report_resume_complete(
    work_root: Path, out_dir: Path, resolved_refs: set[str] | None = None
) -> bool:
    refs = resolved_refs if resolved_refs is not None else _resolved_repo_refs(work_root)
    return (
        bool(refs)
        and _shortlist_complete(work_root)
        and _report_outputs_current(out_dir, _report_input_paths(work_root, refs))
    )


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


def _report_outputs_current(out_dir: Path, input_paths: Sequence[Path]) -> bool:
    output_paths = tuple(Path(out_dir) / filename for filename in REPORT_MAIN_FILENAMES)
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
    failed = len(summary.failures)
    skipped_failed = summary.skipped + failed
    reports = summary.reports_dir if summary.reports_dir is not None else Path("reports")
    prefix = (
        f"Done - {len(summary.repo_refs)} repos, {summary.report_rows} in report, "
        f"{skipped_failed} skipped/failed; {reports}/ written."
    )
    if not summary.failures:
        return prefix
    details = "\n".join(
        f"  - {failure.stage}"
        f"{f' {failure.repo_ref}' if failure.repo_ref else ''}: {failure.message}"
        for failure in summary.failures
    )
    return f"{prefix}\nFailures:\n{details}"


def _first_line(value: str) -> str:
    return value.splitlines()[0] if value else "done"


def _handle_scan(args: argparse.Namespace) -> CommandResult:
    # Imported here so the rest of the CLI does not pull the scan/store stack
    # (and jsonschema) unless `scan` actually runs.
    from repolens.githost import resolve_clone_credential_result
    from repolens.scan import runner as scan_runner
    from repolens.scan.inputs import load_discover_approved_repo_specs, load_explicit_repo_specs

    if args.offline and args.yes:
        raise InputError("--offline cannot be combined with --yes")
    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        raise InputError("--timeout must be a positive number of seconds")
    if args.repos is not None:
        repos = load_explicit_repo_specs(args.repos, scan_runner.RepoSpec)
    else:
        repos = load_discover_approved_repo_specs(args.work_root, scan_runner.RepoSpec)
    syft_path = _ensure_syft_for_scan(args)
    # scan_repos persists successful SBOMs and raises ScanBatchError only after
    # finishing the batch when expected per-repo failures occurred. The credential
    # provider resolves a read-only GitHub token lazily, only when a private repo
    # is encountered. A None timeout uses the default per-repo budget.
    extra = {"timeout_seconds": args.timeout} if args.timeout is not None else {}
    progress = _ScanProgressPrinter(quiet=args.quiet, stream=sys.stderr)
    try:
        report = scan_runner.scan_repos(
            args.work_root,
            repos,
            syft_path=syft_path,
            credential_provider=resolve_clone_credential_result,
            progress=progress,
            **extra,
        )
    except scan_runner.ScanBatchError as exc:
        report = exc.report
    progress.finish(report)
    return _scan_command_result(report, args.work_root)


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
        elapsed = _format_seconds(event.elapsed_seconds)
        return f"{prefix} ✓ {deps_count} deps ({elapsed})"
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

    repo_refs = _resolve_repo_refs(args.work_root, args.repo_ref)
    if args.source_root is not None and args.repo_ref is None and len(repo_refs) > 1:
        raise InputError(
            "resolve --source-root requires --repo-ref when multiple scanned repos exist"
        )
    paths = []
    total = len(repo_refs)
    progress = _ResolveProgressPrinter(stream=sys.stderr)
    for index, repo_ref in enumerate(repo_refs, start=1):
        repo_started_at = time.monotonic()
        progress.start_repo(index, total, repo_ref)

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
        )
        progress.repo_done(index, total, repo_ref, path.name, time.monotonic() - repo_started_at)
        paths.append(path)
    progress.finish(total)
    flag_command = f"repolens flag --work-root {shlex.quote(str(args.work_root))}"
    if len(paths) == 1:
        write_summary = f"wrote {paths[0].name}"
    else:
        preview = ", ".join(repo_refs[:5])
        suffix = "" if len(repo_refs) <= 5 else ", ..."
        write_summary = f"resolved {len(repo_refs)} repos: {preview}{suffix}"
    return CommandResult(
        CommandStatus.SUCCESS,
        f"{write_summary}\nNext CLI stage: {flag_command}",
    )


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
    ) -> None:
        elapsed = _format_seconds(elapsed_seconds)
        self._write_progress_line(
            f"[{index}/{total}] {repo_ref} ✓ wrote {path_name} ({elapsed})",
            newline=True,
        )

    def finish(self, repo_count: int) -> None:
        elapsed = _format_seconds(time.monotonic() - self._started_at)
        self._write_progress_line(
            f"Done: {repo_count} repos resolved in {elapsed}.",
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


def _resolve_repo_refs(work_root: Path, repo_ref: str | None) -> tuple[str, ...]:
    if repo_ref:
        return (repo_ref,)
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
    shortlist_command = f"repolens shortlist --work-root {shlex.quote(str(args.work_root))}"
    summary = f"{summary}\nNext CLI stage: {shortlist_command}"
    if result.open_count > 0:
        return CommandResult(CommandStatus.FINDINGS_OPEN, summary)
    return CommandResult(CommandStatus.SUCCESS, summary)


def _shortlist_stage(args: argparse.Namespace) -> CommandResult:
    from repolens.shortlist import run_shortlist
    from repolens.shortlist.agent import AgentRequest, AgentResponse

    # The default offline agent abstains: the production model is wired behind the
    # AgentClient boundary and exercised only by the scheduled live-smoke lane (plan A1).
    # Abstaining keeps the offline CLI from reaching any model while still exercising the
    # pre-screen / decision-ingest / write-back paths.
    class _AbstainingAgent:
        def resolve(self, request: AgentRequest) -> AgentResponse:
            from repolens.shortlist.agent import Abstain

            del request
            return Abstain(reason="no_offline_agent")

    result = run_shortlist(
        args.work_root,
        agent_client=_AbstainingAgent(),
        identity=args.identity,
    )
    summary = (
        f"settled shortlist: {result.open_count} open item(s) of {result.item_count}; "
        f"wrote {result.shortlist_json_path.name}, {result.shortlist_md_path.name}"
    )
    if result.open_count > 0:
        rerun_command = f"repolens shortlist --work-root {shlex.quote(str(args.work_root))}"
        return CommandResult(
            CommandStatus.FINDINGS_OPEN,
            (
                f"{summary}\n"
                f"Manual step: resolve open items in {result.shortlist_md_path}, then rerun "
                f"`{rerun_command}`."
            ),
        )
    report_command = (
        f"repolens report --work-root {shlex.quote(str(args.work_root))} --out-dir reports"
    )
    return CommandResult(CommandStatus.SUCCESS, f"{summary}\nNext CLI stage: {report_command}")


def _report(args: argparse.Namespace) -> CommandResult:
    try:
        result = render_main_report(args.work_root, args.out_dir, args.runtime_config)
    except ReportGateOpen as exc:
        return CommandResult(CommandStatus.FINDINGS_OPEN, str(exc))
    written = [result.markdown_path, result.csv_path, result.docx_path, *result.appendix_paths]
    return CommandResult(
        CommandStatus.SUCCESS,
        "wrote " + ", ".join(str(path) for path in written),
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
