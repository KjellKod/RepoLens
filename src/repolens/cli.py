"""CLI skeleton and routing for RepoLens."""

from __future__ import annotations

import argparse
import math
import re
import shlex
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from repolens.bootstrap.cache import (
    DOC_LINK,
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

PATH_PATTERN = re.compile(r"(/[^\s:]+)+")

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
            "`repolens resolve --work-root <WORK> --repo-ref <REPO_REF>`.",
        ),
    ),
    "resolve": StageHelp(
        help="Resolve every dependency's license with APIs, mobile opt-in, and scoped ScanCode.",
        description=(
            "Stage 3/6 — determine each dependency's license, cheapest trusted source first."
        ),
        epilog=_stage_epilog(
            "a Syft SBOM from scan at <WORK>/work/<REPO_REF>/sbom.syft.json; "
            "--source-root may point at a read-only checkout for mobile markers and "
            "package-local ScanCode fallback.",
            "repolens resolve --work-root <WORK> --repo-ref <REPO_REF> "
            "--source-root <CHECKOUT> [--enable-mobile-native]",
            "<WORK>/work/<REPO_REF>/resolved.ndjson (license + evidence + tags per "
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
    "  2. repolens scan --work-root work                        inventory approved dependencies\n"
    "  3. repolens resolve --work-root work --repo-ref <REPO_REF>\n"
    "                                                           resolve licenses\n"
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

        args.runtime_config = load_config(Path.cwd(), args.config)
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


def _handle_scan(args: argparse.Namespace) -> CommandResult:
    # Imported here so the rest of the CLI does not pull the scan/store stack
    # (and jsonschema) unless `scan` actually runs.
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
    # scan_repos persists every successful SBOM and raises InternalError (exit 1)
    # if any repository fails; a clean run returns a report (exit 0). A None
    # timeout lets the runner apply its default per-repo budget.
    extra = {"timeout_seconds": args.timeout} if args.timeout is not None else {}
    progress = _ScanProgressPrinter(quiet=args.quiet, stream=sys.stderr)
    try:
        report = scan_runner.scan_repos(
            args.work_root,
            repos,
            syft_path=syft_path,
            progress=progress,
            **extra,
        )
    except scan_runner.ScanBatchError as exc:
        report = exc.report
    progress.finish(report)
    if report.failed:
        return CommandResult(CommandStatus.FINDINGS_OPEN)
    return CommandResult(CommandStatus.SUCCESS)


class _ScanProgressPrinter:
    def __init__(self, *, quiet: bool, stream: TextIO) -> None:
        self._quiet = quiet
        self._stream = stream
        self._tty = bool(getattr(stream, "isatty", lambda: False)())
        self._started_at = time.monotonic()
        self._last_line_length = 0

    def __call__(self, event: ScanProgressEvent) -> None:
        if self._quiet:
            return
        if event.kind == "start":
            self._write_progress_line(_scan_start_line(event), newline=not self._tty)
            return
        if event.kind == "outcome":
            self._write_progress_line(_scan_outcome_line(event), newline=True)

    def finish(self, report: ScanReport) -> None:
        if self._quiet:
            return
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
    if status == "skipped" and event.error == "private":
        return f"{prefix} 🔒 skipped (private, needs auth)"
    if status == "skipped":
        return f"{prefix} ↻ skipped (cached)"
    reason = str(event.error or "unknown error")
    return f"{prefix} ✗ failed: {reason}"


def _format_seconds(value: float | None) -> str:
    seconds = 0.0 if value is None else float(value)
    return f"{seconds:.1f}s"


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

    print(
        f"Acquiring and verifying RepoLens Syft {pin.version} (sha256 {pin.short_sha256}...) ... ",
        end="",
        file=sys.stderr,
        flush=True,
    )
    try:
        result = ensure_syft_cached()
    except UsageError as exc:
        raise InputError(str(exc)) from exc
    except IntegrityError as exc:
        raise InternalError(f"Syft bootstrap integrity failure: {exc}") from exc
    print("ok", file=sys.stderr)
    return result.path


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

    path = run_resolve(
        args.work_root,
        args.repo_ref,
        source_root=args.source_root,
        enable_mobile_native=args.enable_mobile_native,
    )
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
        return CommandResult(CommandStatus.FINDINGS_OPEN, summary)
    return CommandResult(CommandStatus.SUCCESS, summary)


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
