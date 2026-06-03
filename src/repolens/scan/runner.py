"""P2 scan orchestration: hardened clone -> Syft -> per-repo SBOM.

This module is an orchestration layer over existing primitives. It never
reimplements clone hardening or SBOM/license detection: cloning goes through
``repolens.security.clone.hardened_clone`` and inventory through the pinned,
already-verified Syft binary (a path resolved by the CLI handler; this module is
acquisition-free).

Import discipline (security-canary gate): the module top-level imports nothing
that pulls ``jsonschema``. The on-disk store
(``repolens.data.store`` -> ``repolens.data.validation`` -> ``jsonschema``) is
imported lazily inside :func:`scan_repos`, and only when a store-backed default
seam is actually needed. Canaries inject all store seams, so importing the runner
under the lock-only ``security-canaries.yml`` env stays free of ``jsonschema``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.data.errors import ArtifactError
from repolens.exit_codes import InputError, InternalError, RepoLensError
from repolens.githost import (
    CloneCredentialResolution,
    access_denied_message,
    private_repo_needs_auth_message,
    rate_limited_message,
)
from repolens.security.clone import CloneCredential, CloneOptions, hardened_clone
from repolens.security.errors import (
    CloneAccessDenied,
    CloneAuthRequired,
    CloneRateLimited,
    CloneSecurityError,
    CloneTransient,
)
from repolens.security.limits import DEFAULT_LIMITS
from repolens.security.redaction import redact_tokens, redact_tokens_from_structure
from repolens.security.retry import DEFAULT_BASE_DELAY, retry_with_backoff

SCHEMA_VERSION = "1.0"
SYFT_OUTPUT_FORMAT = "syft-json"
#: Environment keys preserved when invoking Syft. Mirrors the clone env scrub:
#: the GitHub token (and every other secret) is never placed in the child env.
_SAFE_ENV_KEYS = ("HOME", "PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "USERPROFILE")

#: Injected boundary for invoking Syft, kept thin so tests stay offline.
CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]
#: Injected boundary for performing the hardened clone.
CloneFn = Callable[[CloneOptions], Path]
#: Injected progress sink. The CLI maps these events to stderr; tests can collect them.
ProgressFn = Callable[["ScanProgressEvent"], None]
#: Resolves a read-only credential once per run (lazily, on first private repo).
CredentialProvider = Callable[[], "CloneCredential | CloneCredentialResolution | None"]

#: Clone-retry bounds. The attempt cap is the primary wall-clock bound: each
#: attempt is itself capped at ``clone_timeout_seconds`` by the hardened clone
#: primitive, so two attempts bound a hung repo at roughly ``2 * clone_timeout``.
#: The elapsed budget is retained only as a guard against pathological clock or
#: subprocess timeout overshoot.
CLONE_RETRY_MAX_ATTEMPTS = 2
_CLONE_ELAPSED_BUDGET_FACTOR = float(CLONE_RETRY_MAX_ATTEMPTS)


@dataclass(frozen=True)
class RepoSpec:
    """One repository to scan. ``clone_url`` is the runtime https remote."""

    repo_ref: str
    clone_url: str
    #: Whether discovery saw this repo as private. Drives credential resolution;
    #: defaults False so legacy ``--repos`` JSON without the field clones public.
    private: bool = False


@dataclass(frozen=True)
class RepoScanOutcome:
    """The redacted result of scanning a single repository."""

    repo_ref: str
    status: str  # "scanned" | "skipped" | "failed"
    tool_version: str | None = None
    error: str | None = None
    skipped_reason: str | None = None


@dataclass(frozen=True)
class ScanProgressEvent:
    """A per-repository scan progress event."""

    kind: str  # "start" | "outcome"
    index: int
    total: int
    repo_ref: str
    status: str | None = None
    deps_count: int | None = None
    elapsed_seconds: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class ScanReport:
    """Aggregate result across all repositories in a run."""

    outcomes: tuple[RepoScanOutcome, ...]

    @property
    def scanned(self) -> tuple[RepoScanOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "scanned")

    @property
    def skipped(self) -> tuple[RepoScanOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "skipped")

    @property
    def failed(self) -> tuple[RepoScanOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "failed")


class SyftScanError(RepoLensError):
    """Raised when the Syft invocation fails or its output is unusable."""


class ScanBatchError(InternalError):
    """Raised after all repos finish when one or more repo scans failed."""

    def __init__(self, report: ScanReport) -> None:
        self.report = report
        super().__init__(f"{len(report.failed)} repository scan(s) failed")


def resolve_syft_path(work_root: str | Path) -> Path:
    """Return RepoLens's verified shared-cache Syft path.

    The CLI performs consent-gated acquisition before calling :func:`scan_repos`.
    This resolver is cache-only and intentionally ignores ``work_root`` so a
    caller cannot supply a local Syft binary.
    """

    del work_root
    from repolens.bootstrap.cache import cached_syft_path, load_syft_pin

    path = cached_syft_path(load_syft_pin())
    if path is None:
        raise InputError(
            "RepoLens's validated Syft is not in the shared cache; run "
            "`repolens scan --yes` to acquire and verify it, or run "
            "`repolens bootstrap` before offline use. See docs/usage.md#tool-bootstrap."
        )
    return path


def _utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


def _scrubbed_tool_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}


def _default_command_runner(
    argv: Sequence[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    # argv is fully constructed (no shell); Syft runs over an already-cloned local path.
    return subprocess.run(
        list(argv),
        env=_scrubbed_tool_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _licenses_from(entry: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for lic in entry.get("licenses") or []:
        if isinstance(lic, str):
            value = lic
        elif isinstance(lic, dict):
            value = lic.get("spdxExpression") or lic.get("value") or ""
        else:
            value = ""
        value = str(value).strip()
        if value:
            out.append(value)
    return out


def _locations_from(entry: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for loc in entry.get("locations") or []:
        if isinstance(loc, str):
            path = loc
        elif isinstance(loc, dict):
            path = loc.get("path") or ""
        else:
            path = ""
        path = str(path).strip()
        if path:
            out.append(path)
    return out


def _map_syft_to_sbom(
    syft_doc: dict[str, Any],
    *,
    repo_ref: str,
    source: str,
    generated_at: str,
) -> tuple[dict[str, Any], str]:
    """Map a Syft JSON document onto the frozen ``sbom.schema.json`` shape.

    Returns the artifact dict plus the resolved tool version (also surfaced on the
    per-repo status). Generation/license detection is Syft's; this only reshapes.
    """

    descriptor = syft_doc.get("descriptor") or {}
    tool_name = str(descriptor.get("name") or "syft").strip() or "syft"
    tool_version = str(descriptor.get("version") or "").strip() or "unknown"

    artifacts: list[dict[str, Any]] = []
    for entry in syft_doc.get("artifacts") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        artifact_type = str(entry.get("type") or "").strip()
        if not name or not artifact_type:
            # The frozen schema requires both; skip malformed Syft entries rather
            # than emitting an artifact the store would reject.
            continue
        mapped: dict[str, Any] = {"name": name, "type": artifact_type}
        version = entry.get("version")
        mapped["version"] = str(version) if version else None
        purl = str(entry.get("purl") or "").strip()
        if purl:
            mapped["purl"] = purl
        licenses = _licenses_from(entry)
        if licenses:
            mapped["licenses"] = licenses
        locations = _locations_from(entry)
        if locations:
            mapped["locations"] = locations
        artifacts.append(mapped)

    sbom = {
        "schema_version": SCHEMA_VERSION,
        "repo": repo_ref,
        "generated_at": generated_at,
        "tool": {"name": tool_name, "version": tool_version},
        "source": source,
        "artifacts": artifacts,
    }
    return sbom, tool_version


def _run_syft(
    command_runner: CommandRunner,
    *,
    syft_path: Path,
    target: Path,
    timeout: float,
) -> dict[str, Any]:
    argv = [str(syft_path), "scan", f"dir:{target}", "-o", SYFT_OUTPUT_FORMAT]
    try:
        completed = command_runner(argv, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SyftScanError("Syft scan exceeded the per-repo time budget") from exc
    if completed.returncode != 0:
        raise SyftScanError(redact_tokens((completed.stderr or "syft scan failed").strip())[:500])
    try:
        document = json.loads(completed.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SyftScanError("Syft produced output that is not valid JSON") from exc
    if not isinstance(document, dict):
        raise SyftScanError("Syft output is not a JSON object")
    return document


def _scan_one(
    repo: RepoSpec,
    *,
    work_root: str | Path,
    syft_path: Path,
    timeout_seconds: float,
    clone: CloneFn,
    command_runner: CommandRunner,
    clock: Callable[[], str],
    repo_dir_fn: Callable[..., Path],
    write_sbom_fn: Callable[..., Path],
    write_status_fn: Callable[[str | Path, Any], None],
    get_credential: CredentialProvider,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> tuple[RepoScanOutcome, int | None]:
    repo_dir = repo_dir_fn(work_root, repo.repo_ref)
    repo_dir.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix=".scan-", dir=repo_dir))
    try:
        credential_resolution = get_credential() if repo.private else None
        credential, credential_miss_message = _coerce_credential_resolution(credential_resolution)
        if repo.private and credential is None:
            # No credential resolvable for a private repo: do not attempt clone.
            # Prefer the resolver's precise gh-not-installed / gh-not-authed /
            # rate-limit reason; otherwise use the generic private-repo needs-auth
            # message for the no-token-anywhere case.
            return (
                _record_failure(
                    repo,
                    repo_dir,
                    write_status_fn,
                    clock,
                    message=credential_miss_message
                    or private_repo_needs_auth_message(repo.repo_ref),
                ),
                None,
            )

        clone_path = _clone_with_retry(
            repo,
            workdir=workdir,
            clone=clone,
            credential=credential,
            sleep=sleep,
            monotonic=monotonic,
        )
        document = _run_syft(
            command_runner,
            syft_path=syft_path,
            target=clone_path,
            timeout=timeout_seconds,
        )
        sbom, tool_version = _map_syft_to_sbom(
            document,
            repo_ref=repo.repo_ref,
            source=repo.clone_url,
            generated_at=clock(),
        )
        # Redact before persisting. write_sbom redacts + schema-validates; the
        # status file is written via atomic_write_json, which does NOT redact, so
        # we apply the single redaction discipline here for both paths.
        write_sbom_fn(work_root, repo.repo_ref, redact_tokens_from_structure(sbom))
        _write_status(
            repo_dir,
            write_status_fn,
            repo_ref=repo.repo_ref,
            status="scanned",
            tool_version=tool_version,
            error=None,
            generated_at=sbom["generated_at"],
        )
        return (
            RepoScanOutcome(repo.repo_ref, "scanned", tool_version=tool_version),
            len(sbom["artifacts"]),
        )
    except (CloneSecurityError, SyftScanError, ArtifactError) as exc:
        # Per-repo isolation boundary for EXPECTED failures only. One untrusted
        # repository must never abort the batch; the CLI maps a non-empty failed
        # set to exit 1 with a clear message. Genuine crashes (programming bugs)
        # are NOT caught here — they propagate and surface as `Internal error`
        # (brief §2). Typed clone failures get their distinct, actionable wording.
        return (
            _record_failure(
                repo,
                repo_dir,
                write_status_fn,
                clock,
                message=_failure_message(repo, exc),
            ),
            None,
        )
    finally:
        # Guaranteed cleanup of the scan-owned ephemeral workdir (rpl_security §7).
        shutil.rmtree(workdir, ignore_errors=True)


def _clone_with_retry(
    repo: RepoSpec,
    *,
    workdir: Path,
    clone: CloneFn,
    credential: CloneCredential | None,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> Path:
    """Clone with bounded retry on transient/rate-limit failures only.

    ``CloneAuthRequired``/``CloneAccessDenied`` are never retried; they propagate
    immediately to the caller's typed-failure mapping.
    """

    options = CloneOptions(
        remote_url=repo.clone_url,
        destination=workdir / "repo",
        limits=DEFAULT_LIMITS,
        credential=credential,
    )
    return retry_with_backoff(
        lambda: clone(options),
        is_transient=lambda exc: isinstance(exc, CloneRateLimited | CloneTransient),
        max_attempts=CLONE_RETRY_MAX_ATTEMPTS,
        base_delay=DEFAULT_BASE_DELAY,
        sleep=sleep,
        max_elapsed=DEFAULT_LIMITS.clone_timeout_seconds * _CLONE_ELAPSED_BUDGET_FACTOR,
        monotonic=monotonic,
    )


def _coerce_credential_resolution(
    value: CloneCredential | CloneCredentialResolution | None,
) -> tuple[CloneCredential | None, str | None]:
    if isinstance(value, CloneCredentialResolution):
        return value.credential, value.unavailable_message
    return value, None


def _failure_message(repo: RepoSpec, exc: Exception) -> str:
    """Map an expected per-repo failure onto its redacted, actionable message."""

    if isinstance(exc, CloneAuthRequired):
        return private_repo_needs_auth_message(repo.repo_ref)
    if isinstance(exc, CloneAccessDenied):
        return access_denied_message(repo.repo_ref)
    if isinstance(exc, CloneRateLimited | CloneTransient):
        return rate_limited_message(CLONE_RETRY_MAX_ATTEMPTS)
    return redact_tokens(str(exc))[:500]


def _record_failure(
    repo: RepoSpec,
    repo_dir: Path,
    write_status_fn: Callable[[str | Path, Any], None],
    clock: Callable[[], str],
    *,
    message: str,
) -> RepoScanOutcome:
    _write_status(
        repo_dir,
        write_status_fn,
        repo_ref=repo.repo_ref,
        status="failed",
        tool_version=None,
        error=message,
        generated_at=clock(),
    )
    return RepoScanOutcome(repo.repo_ref, "failed", error=message)


def _write_status(
    repo_dir: Path,
    write_status_fn: Callable[[str | Path, Any], None],
    *,
    repo_ref: str,
    status: str,
    tool_version: str | None,
    error: str | None,
    generated_at: str,
) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "repo": repo_ref,
        "status": status,
        "generated_at": generated_at,
        "tool_version": tool_version,
        "error": error,
    }
    # Defence in depth: redact again at the boundary even though callers pass
    # pre-redacted values, because atomic_write_json never redacts.
    write_status_fn(repo_dir / "scan.status.json", redact_tokens_from_structure(payload))


def scan_repos(
    work_root: str | Path,
    repos: Sequence[RepoSpec],
    *,
    syft_path: str | Path,
    timeout_seconds: float = DEFAULT_LIMITS.clone_timeout_seconds,
    clone: CloneFn | None = None,
    command_runner: CommandRunner | None = None,
    clock: Callable[[], str] | None = None,
    credential_provider: CredentialProvider | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    is_scanned_fn: Callable[..., bool] | None = None,
    repo_dir_fn: Callable[..., Path] | None = None,
    write_sbom_fn: Callable[..., Path] | None = None,
    write_status_fn: Callable[[str | Path, Any], None] | None = None,
    progress: ProgressFn | None = None,
) -> ScanReport:
    """Scan each repository: resume-skip, hardened clone, Syft, persist, status.

    Returns the full :class:`ScanReport` on clean runs. Expected per-repo
    failures are collected across the batch and then raised as
    :class:`ScanBatchError` so the CLI can still print progress, final counts,
    and actionable reasons while exiting 1. Genuine crashes propagate.
    ``credential_provider`` is resolved lazily and at most once, the first time
    a private repo is encountered (the result, including ``None``, is memoized);
    public repos never trigger resolution.

    Every store-backed seam (``is_scanned_fn``/``repo_dir_fn``/``write_sbom_fn``/
    ``write_status_fn``) is injectable. They default to the on-disk store, which is
    imported lazily so that merely importing this module — or calling it with all
    store seams injected, as the security canaries do — does not pull ``jsonschema``.
    """

    clone = clone or hardened_clone
    command_runner = command_runner or _default_command_runner
    clock = clock or _utc_now
    sleep = sleep or time.sleep
    monotonic = monotonic or time.monotonic

    if None in (is_scanned_fn, repo_dir_fn, write_sbom_fn, write_status_fn):
        # Lazy: importing the store pulls jsonschema (absent from the lock-only
        # security-canaries env). Canaries inject all four seams to avoid this.
        from repolens.data.store import (
            atomic_write_json,
            is_repo_scanned,
            repo_dir,
            write_sbom,
        )

        is_scanned_fn = is_scanned_fn or is_repo_scanned
        repo_dir_fn = repo_dir_fn or repo_dir
        write_sbom_fn = write_sbom_fn or write_sbom
        write_status_fn = write_status_fn or atomic_write_json

    get_credential = _memoized_credential_provider(credential_provider)

    syft = Path(syft_path)
    outcomes: list[RepoScanOutcome] = []
    total = len(repos)
    for index, repo in enumerate(repos, start=1):
        progress_start = _dt.datetime.now(_dt.UTC)
        if progress is not None:
            progress(ScanProgressEvent("start", index, total, repo.repo_ref))
        if is_scanned_fn(work_root, repo.repo_ref):
            outcome = RepoScanOutcome(repo.repo_ref, "skipped", skipped_reason="cached")
            outcomes.append(outcome)
            if progress is not None:
                progress(
                    ScanProgressEvent(
                        "outcome",
                        index,
                        total,
                        repo.repo_ref,
                        status=outcome.status,
                        elapsed_seconds=_elapsed_seconds(progress_start),
                    )
                )
            continue
        outcome, deps_count = _scan_one(
            repo,
            work_root=work_root,
            syft_path=syft,
            timeout_seconds=timeout_seconds,
            clone=clone,
            command_runner=command_runner,
            clock=clock,
            repo_dir_fn=repo_dir_fn,
            write_sbom_fn=write_sbom_fn,
            write_status_fn=write_status_fn,
            get_credential=get_credential,
            sleep=sleep,
            monotonic=monotonic,
        )
        outcomes.append(outcome)
        if progress is not None:
            progress(
                ScanProgressEvent(
                    "outcome",
                    index,
                    total,
                    repo.repo_ref,
                    status=outcome.status,
                    deps_count=deps_count,
                    elapsed_seconds=_elapsed_seconds(progress_start),
                    error=outcome.error,
                )
            )

    report = ScanReport(tuple(outcomes))
    if report.failed:
        # Mixed-run rule: successes are already persisted; a hard failure makes the
        # process exit 1. The report is attached so the CLI can still print final counts.
        raise ScanBatchError(report)
    return report


def _elapsed_seconds(started_at: _dt.datetime) -> float:
    return (_dt.datetime.now(_dt.UTC) - started_at).total_seconds()


def _memoized_credential_provider(
    credential_provider: CredentialProvider | None,
) -> CredentialProvider:
    """Resolve the credential at most once per run, caching the result (incl. None)."""

    cache: dict[str, CloneCredential | CloneCredentialResolution | None] = {}

    def get_credential() -> CloneCredential | CloneCredentialResolution | None:
        if "value" not in cache:
            cache["value"] = credential_provider() if credential_provider is not None else None
        return cache["value"]

    return get_credential
