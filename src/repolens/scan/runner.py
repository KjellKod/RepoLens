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
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from repolens.data.errors import ArtifactError
from repolens.exit_codes import InputError, InternalError, RepoLensError
from repolens.githost import (
    CloneCredentialResolution,
    access_denied_message,
    private_repo_needs_auth_message,
    rate_limited_message,
)
from repolens.resolve.purl import package_identity
from repolens.scan.first_party import collect_first_party_names
from repolens.security.clone import (
    CloneCredential,
    CloneOptions,
    hardened_clone,
    is_sparse_manifest_path,
)
from repolens.security.errors import (
    CloneAccessDenied,
    CloneAuthRequired,
    CloneRateLimited,
    CloneSecurityError,
    CloneTimeout,
    CloneTransient,
)
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.redaction import (
    committed_token_patterns,
    redact_tokens,
    redact_tokens_from_structure,
)
from repolens.security.retry import DEFAULT_BASE_DELAY, retry_with_backoff

SCHEMA_VERSION = "1.0"
SYFT_OUTPUT_FORMAT = "syft-json"
#: Environment keys preserved when invoking Syft. Mirrors the clone env scrub:
#: the GitHub token (and every other secret) is never placed in the child env.
_SAFE_ENV_KEYS = ("HOME", "PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "USERPROFILE")
DEFAULT_EXCLUDE_PATHS = (
    "tests/fixtures/",
    "test/fixtures/",
    "tests/bootstrap/fixtures/",
    ".git/",
)
MOBILE_RESTRICTED_CATALOGERS = (
    "java-gradle-lockfile-cataloger",
    "cocoapods-cataloger",
    "swift-package-manager-cataloger",
)
DECLARED_UNPINNED_STATUS = "declared-unpinned"
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXACT_VERSION_RE = re.compile(r"(?<![<>=!~])={2,3}\s*([^,;\s]+)")

#: Injected boundary for invoking Syft, kept thin so tests stay offline.
CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]
#: Injected boundary for performing the hardened clone.
CloneFn = Callable[[CloneOptions], Path]
#: Injected progress sink. The CLI maps these events to stderr; tests can collect them.
ProgressFn = Callable[["ScanProgressEvent"], None]
#: Resolves a read-only credential once per run (lazily, on first private repo).
CredentialProvider = Callable[[], "CloneCredential | CloneCredentialResolution | None"]
#: Replaces the scan-owned bounded source sidecar.
SourceSnapshotWriter = Callable[[str | Path, str, str | Path | None], Path | None]

#: Clone-retry bounds. The attempt cap is the primary wall-clock bound: each
#: attempt is itself capped at ``clone_timeout_seconds`` by the hardened clone
#: primitive, so two attempts bound a hung repo at roughly ``2 * clone_timeout``.
#: The elapsed budget is retained only as a guard against pathological clock or
#: subprocess timeout overshoot.
CLONE_RETRY_MAX_ATTEMPTS = 2
_CLONE_ELAPSED_BUDGET_FACTOR = float(CLONE_RETRY_MAX_ATTEMPTS)
_MAX_SOURCE_SNAPSHOT_FILES = 256
_MAX_SOURCE_SNAPSHOT_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_SNAPSHOT_FILE_BYTES = 512 * 1024
_DEPENDENCY_GRAPH_FILENAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "cargo.lock",
        "go.sum",
        "gradle.lockfile",
        "build.gradle",
        "build.gradle.kts",
        "pom.xml",
        "gemfile.lock",
        "packages.lock.json",
        "package.resolved",
        "podfile.lock",
    }
)
_PACKAGE_LOCAL_ROOTS = frozenset(
    {
        ".git",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "packages",
        "site-packages",
        "src",
        "source",
        "target",
        "vendor",
    }
)


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
    deps_count: int | None = None
    raw_deps_count: int | None = None


@dataclass(frozen=True)
class ScanProgressEvent:
    """A per-repository scan progress event."""

    kind: str  # "start" | "outcome"
    index: int
    total: int
    repo_ref: str
    status: str | None = None
    deps_count: int | None = None
    raw_deps_count: int | None = None
    elapsed_seconds: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class SbomDedupeStats:
    """Counts from post-Syft SBOM dedupe."""

    raw_artifact_count: int
    persisted_artifact_count: int

    @property
    def deduped(self) -> bool:
        return self.raw_artifact_count > self.persisted_artifact_count


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

    The CLI auto-acquires RepoLens's pinned Syft before calling :func:`scan_repos`.
    This resolver is cache-only and intentionally ignores ``work_root`` so a caller
    cannot supply a local Syft binary.
    """

    del work_root
    from repolens.bootstrap.cache import cached_syft_path, load_syft_pin

    path = cached_syft_path(load_syft_pin())
    if path is None:
        raise InputError(
            "RepoLens's validated Syft is not in the shared cache; run "
            "`repolens scan` to acquire and verify it, or run "
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


def configured_exclude_paths(config_values: dict[str, Any]) -> tuple[str, ...]:
    """Return scan exclusion prefixes from runtime config, replacing defaults when set."""

    raw = _nested_config(config_values, ("scan", "exclude_paths"))
    if raw is None:
        return DEFAULT_EXCLUDE_PATHS
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise InputError("scan.exclude_paths must be an array of path prefixes")
    return _normalized_exclude_prefixes(raw)


def configured_syft_catalogers(config_values: dict[str, Any]) -> tuple[str, ...] | None:
    """Return optional restricted Syft catalogers from runtime config."""

    raw = _nested_config(config_values, ("scan", "syft", "catalogers"))
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise InputError("scan.syft.catalogers must be an array of cataloger names")
    catalogers = tuple(item.strip() for item in raw if item.strip())
    if not catalogers:
        raise InputError("scan.syft.catalogers must contain at least one cataloger")
    return catalogers


def configured_clone_timeout_seconds(config_values: dict[str, Any]) -> float | None:
    """Return optional scan clone timeout from runtime config."""

    raw = _nested_config(config_values, ("scan", "clone_timeout_seconds"))
    if raw is None:
        return None
    if not isinstance(raw, int | float) or not math.isfinite(float(raw)) or float(raw) <= 0:
        raise InputError("scan.clone_timeout_seconds must be a positive number of seconds")
    return float(raw)


def _nested_config(config_values: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = config_values
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _syft_argv(
    syft_path: Path,
    target: Path,
    *,
    catalogers: Sequence[str] | None,
) -> list[str]:
    argv = [str(syft_path), "scan", f"dir:{target}", "-o", SYFT_OUTPUT_FORMAT]
    if catalogers is not None:
        argv.extend(["--select-catalogers", ",".join(_catalogers_with_mobile(catalogers))])
    return argv


def _catalogers_with_mobile(catalogers: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for cataloger in (*catalogers, *MOBILE_RESTRICTED_CATALOGERS):
        value = cataloger.strip()
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return tuple(out)


def _augment_with_pyproject_dependencies(sbom: dict[str, Any], source_root: Path) -> None:
    pyproject_path = source_root / "pyproject.toml"
    if not pyproject_path.is_file():
        return
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return
    project = data.get("project")
    if not isinstance(project, dict):
        return

    artifacts = sbom["artifacts"]
    dependencies = project.get("dependencies")
    if isinstance(dependencies, list):
        _append_new_artifacts(artifacts, _pyproject_artifacts(dependencies, "pyproject.toml"))
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group, values in optional.items():
            if isinstance(values, list):
                location = f"pyproject.toml#project.optional-dependencies.{group}"
                _append_new_artifacts(artifacts, _pyproject_artifacts(values, location))


def _append_new_artifacts(
    artifacts: list[dict[str, Any]],
    candidates: Sequence[dict[str, Any]],
) -> None:
    seen = {_artifact_identity(artifact): artifact for artifact in artifacts}
    for candidate in candidates:
        identity = _artifact_identity(candidate)
        existing = seen.get(identity)
        if existing is not None:
            _merge_artifact_metadata(existing, candidate)
            continue
        artifacts.append(candidate)
        seen[identity] = candidate


def _dedupe_registry_dependency_artifacts(
    artifacts: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], SbomDedupeStats]:
    """Collapse exact registry dependency graph duplicates conservatively."""

    out: list[dict[str, Any]] = []
    eligible_by_key: dict[tuple[str, str, str | None, str, tuple[str, ...]], dict[str, Any]] = {}
    occurrence_counts: dict[int, int] = {}

    for artifact in artifacts:
        key = _registry_dependency_dedupe_key(artifact)
        if key is None:
            out.append(dict(artifact))
            continue
        existing = eligible_by_key.get(key)
        if existing is None:
            copy = dict(artifact)
            out.append(copy)
            eligible_by_key[key] = copy
            occurrence_counts[id(copy)] = _artifact_occurrence_count(artifact)
            continue
        _merge_registry_duplicate(existing, artifact)
        occurrence_counts[id(existing)] += _artifact_occurrence_count(artifact)

    for artifact in out:
        occurrence_count = occurrence_counts.get(id(artifact), _artifact_occurrence_count(artifact))
        if occurrence_count > 1:
            artifact["repolens_occurrence_count"] = occurrence_count
        else:
            artifact.pop("repolens_occurrence_count", None)

    return out, SbomDedupeStats(
        raw_artifact_count=len(artifacts),
        persisted_artifact_count=len(out),
    )


def _registry_dependency_dedupe_key(
    artifact: dict[str, Any],
) -> tuple[str, str, str | None, str, tuple[str, ...]] | None:
    purl = str(artifact.get("purl") or "").strip()
    if not purl:
        return None
    locations = artifact.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    if not all(_is_dependency_graph_location(location) for location in locations):
        return None

    artifact_type = str(artifact.get("type") or "").strip()
    name = str(artifact.get("name") or "").strip()
    if not artifact_type or not name:
        return None
    ecosystem, identity = package_identity(artifact_type, name, purl)
    ecosystem = ecosystem.strip().lower()
    identity = _normalize_registry_identity(ecosystem, identity)
    if not ecosystem or not identity:
        return None
    version = artifact.get("version")
    normalized_version = str(version).strip() if version is not None else None
    normalized_purl = purl.strip()
    licenses = artifact.get("licenses")
    declared_license_tuple: tuple[str, ...] = ()
    if isinstance(licenses, list):
        declared_license_tuple = tuple(
            sorted(
                str(license_value).strip()
                for license_value in licenses
                if str(license_value).strip()
            )
        )
    return ecosystem, identity, normalized_version, normalized_purl, declared_license_tuple


def _normalize_registry_identity(ecosystem: str, identity: str) -> str:
    value = identity.strip()
    if ecosystem in {"python", "pypi"}:
        return _normalize_pypi_name(value)
    return value.lower()


def _is_dependency_graph_location(location: object) -> bool:
    normalized = _normalized_location_for_dedupe(location)
    if normalized is None:
        return False
    parts = normalized.parts
    lowered_parts = tuple(part.lower() for part in parts)
    filename = lowered_parts[-1]
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return True
    if filename == "package.json":
        if any(part in _PACKAGE_LOCAL_ROOTS for part in lowered_parts[:-1]):
            return False
        return len(parts) <= 2 and lowered_parts[0] not in _PACKAGE_LOCAL_ROOTS
    if filename not in _DEPENDENCY_GRAPH_FILENAMES:
        return False
    return not any(part in _PACKAGE_LOCAL_ROOTS - {"packages"} for part in lowered_parts[:-1])


def _normalized_location_for_dedupe(location: object) -> PurePosixPath | None:
    normalized = _normalized_location(location)
    if normalized is None:
        return None
    path_text = normalized.split("#", 1)[0]
    if not path_text:
        return None
    return PurePosixPath(path_text)


def _merge_registry_duplicate(target: dict[str, Any], source: dict[str, Any]) -> None:
    target["locations"] = _sorted_unique_locations(
        [
            *list(target.get("locations") if isinstance(target.get("locations"), list) else []),
            *list(source.get("locations") if isinstance(source.get("locations"), list) else []),
        ]
    )
    _merge_description_if_missing(target, source)


def _sorted_unique_locations(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    by_normalized: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str) or not item.strip():
            continue
        normalized = _normalized_location(item) or item.strip()
        by_normalized.setdefault(normalized, item.strip())
    return [by_normalized[key] for key in sorted(by_normalized)]


def _artifact_occurrence_count(artifact: dict[str, Any]) -> int:
    value = artifact.get("repolens_occurrence_count")
    if isinstance(value, int) and value > 0:
        return value
    return 1


def _merge_artifact_metadata(target: dict[str, Any], source: dict[str, Any]) -> None:
    locations = target.setdefault("locations", [])
    if not isinstance(locations, list):
        locations = []
        target["locations"] = locations
    for location in source.get("locations", []):
        if isinstance(location, str) and location not in locations:
            locations.append(location)
    if source.get("declared_version_status") == DECLARED_UNPINNED_STATUS:
        target["declared_version_status"] = DECLARED_UNPINNED_STATUS
    _merge_description_if_missing(target, source)


def _merge_description_if_missing(target: dict[str, Any], source: dict[str, Any]) -> None:
    if target.get("description"):
        return
    description = source.get("description")
    if isinstance(description, str) and description.strip():
        target["description"] = description


def _artifact_identity(artifact: dict[str, Any]) -> tuple[str, str, str | None, str | None]:
    name = str(artifact.get("name") or "")
    artifact_type = str(artifact.get("type") or "")
    version = artifact.get("version")
    purl = artifact.get("purl")
    return (
        _normalize_pypi_name(name) if artifact_type == "python" else name,
        artifact_type,
        str(version) if version is not None else None,
        str(purl) if purl is not None else None,
    )


def _pyproject_artifacts(requirements: Sequence[object], location: str) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for raw in requirements:
        if not isinstance(raw, str):
            continue
        parsed = _parse_pyproject_requirement(raw)
        if parsed is None:
            continue
        name, version = parsed
        artifact: dict[str, Any] = {
            "name": name,
            "type": "python",
            "version": version,
            "purl": f"pkg:pypi/{name}" + (f"@{version}" if version is not None else ""),
            "locations": [location],
        }
        if version is None:
            artifact["declared_version_status"] = DECLARED_UNPINNED_STATUS
        artifacts.append(artifact)
    return artifacts


def _parse_pyproject_requirement(value: str) -> tuple[str, str | None] | None:
    requirement = value.strip()
    if (
        not requirement
        or " @ " in requirement
        or requirement.startswith((".", "/", "file:", "git+"))
    ):
        return None
    match = _REQ_NAME_RE.match(requirement)
    if match is None:
        return None
    remainder = requirement[match.end() :].lstrip()
    if remainder and not remainder.startswith(("[", ";", "<", ">", "=", "!", "~", ",")):
        return None
    name = _normalize_pypi_name(match.group(1))
    version = _exact_version(requirement)
    return name, version


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _exact_version(requirement: str) -> str | None:
    before_marker = requirement.split(";", 1)[0]
    match = _EXACT_VERSION_RE.search(before_marker)
    if match is None:
        return None
    version = match.group(1).strip()
    if not version or "*" in version:
        return None
    return version


def _filter_artifacts_by_exclusions(
    artifacts: Sequence[dict[str, Any]],
    exclude_paths: Sequence[str],
) -> list[dict[str, Any]]:
    prefixes = _normalized_exclude_prefixes(exclude_paths)
    if not prefixes:
        return list(artifacts)
    return [
        artifact
        for artifact in artifacts
        if not _artifact_locations_all_excluded(artifact, prefixes)
    ]


def _artifact_locations_all_excluded(
    artifact: dict[str, Any],
    exclude_prefixes: Sequence[str],
) -> bool:
    locations = artifact.get("locations")
    if not isinstance(locations, list) or not locations:
        return False
    normalized = [_normalized_location(location) for location in locations]
    valid_locations = [location for location in normalized if location is not None]
    if not valid_locations:
        return False
    return all(_path_is_excluded(location, exclude_prefixes) for location in valid_locations)


def _normalized_location(location: object) -> str | None:
    if not isinstance(location, str) or not location.strip():
        return None
    text = location.strip().replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute():
        # Syft reports repository-root-relative locations with a leading slash.
        # Treat those as relative while still leaving host absolute paths outside
        # configured prefixes unless their repo-relative tail matches exactly.
        path = PurePosixPath(text.lstrip("/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _path_is_excluded(path: str, exclude_prefixes: Sequence[str]) -> bool:
    normalized = _normalize_exclude_prefix(path)
    return any(
        prefix and (normalized == prefix or normalized.startswith(f"{prefix}/"))
        for prefix in exclude_prefixes
    )


def _normalized_exclude_prefixes(values: Sequence[str]) -> tuple[str, ...]:
    prefixes: list[str] = []
    for value in values:
        if not value.strip():
            continue
        normalized = _normalize_exclude_prefix(value)
        if normalized:
            prefixes.append(normalized)
    return tuple(prefixes)


def _normalize_exclude_prefix(value: str) -> str:
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text:
        return ""
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        return ""
    normalized = path.as_posix().rstrip("/")
    return normalized


def _run_syft(
    command_runner: CommandRunner,
    *,
    syft_path: Path,
    target: Path,
    timeout: float,
    catalogers: Sequence[str] | None,
) -> dict[str, Any]:
    argv = _syft_argv(syft_path, target, catalogers=catalogers)
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
    exclude_paths: Sequence[str],
    syft_catalogers: Sequence[str] | None,
    clock: Callable[[], str],
    repo_dir_fn: Callable[..., Path],
    write_sbom_fn: Callable[..., Path],
    write_status_fn: Callable[[str | Path, Any], None],
    write_first_party_fn: Callable[..., Path],
    write_source_snapshot_fn: SourceSnapshotWriter,
    get_credential: CredentialProvider,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    clone_limits: SecurityLimits,
) -> tuple[RepoScanOutcome, int | None, int | None]:
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
                None,
            )

        clone_path = _clone_with_retry(
            repo,
            workdir=workdir,
            clone=clone,
            credential=credential,
            sleep=sleep,
            monotonic=monotonic,
            clone_limits=clone_limits,
        )
        document = _run_syft(
            command_runner,
            syft_path=syft_path,
            target=clone_path,
            timeout=timeout_seconds,
            catalogers=syft_catalogers,
        )
        sbom, tool_version = _map_syft_to_sbom(
            document,
            repo_ref=repo.repo_ref,
            source=repo.clone_url,
            generated_at=clock(),
        )
        _augment_with_pyproject_dependencies(sbom, clone_path)
        sbom["artifacts"] = _filter_artifacts_by_exclusions(
            sbom["artifacts"],
            exclude_paths,
        )
        sbom["artifacts"], dedupe_stats = _dedupe_registry_dependency_artifacts(sbom["artifacts"])
        # Redact before persisting. write_sbom redacts + schema-validates; the
        # status file is written via atomic_write_json, which does NOT redact, so
        # we apply the single redaction discipline here for both paths.
        write_sbom_fn(work_root, repo.repo_ref, redact_tokens_from_structure(sbom))
        # Detect the repo's own workspace members while the checkout still exists
        # (this is the only stage with one) and persist them to a work-root sidecar
        # that survives the `finally` rmtree of the ephemeral workdir. Persisted
        # under repo_dir, not workdir, so later checkout-free stages can read it.
        write_first_party_fn(work_root, repo.repo_ref, _detect_first_party(clone_path))
        _persist_source_snapshot(
            work_root,
            repo.repo_ref,
            clone_path,
            repo_dir=repo_dir,
            write_source_snapshot_fn=write_source_snapshot_fn,
        )
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
            RepoScanOutcome(
                repo.repo_ref,
                "scanned",
                tool_version=tool_version,
                deps_count=dedupe_stats.persisted_artifact_count,
                raw_deps_count=dedupe_stats.raw_artifact_count,
            ),
            dedupe_stats.persisted_artifact_count,
            dedupe_stats.raw_artifact_count,
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
            None,
        )
    finally:
        # Guaranteed cleanup of the scan-owned ephemeral workdir (rpl_security §7).
        shutil.rmtree(workdir, ignore_errors=True)


def _detect_first_party(clone_path: Path) -> list[str]:
    """Best-effort first-party detection over the untrusted clone.

    The detector is already internally guarded (bounded reads, tolerant parses),
    but detection must *never* abort a scan batch — a broad guard here keeps a
    pathological repo from turning a detection edge case into a failed scan. An
    empty list is treated exactly like an absent sidecar by the resolve reader.
    """

    try:
        return collect_first_party_names(clone_path)
    except Exception:
        return []


def _persist_source_snapshot(
    work_root: str | Path,
    repo_ref: str,
    clone_path: Path,
    *,
    repo_dir: Path,
    write_source_snapshot_fn: SourceSnapshotWriter,
) -> None:
    staged_parent = Path(tempfile.mkdtemp(prefix=".source-snapshot-", dir=repo_dir))
    staged = staged_parent / "source.snapshot"
    staged.mkdir()
    copied = 0
    total_bytes = 0
    try:
        for source, relative_path in _iter_snapshot_candidates(clone_path):
            try:
                stat = source.stat()
            except OSError:
                continue
            if stat.st_size > _MAX_SOURCE_SNAPSHOT_FILE_BYTES:
                continue
            if copied >= _MAX_SOURCE_SNAPSHOT_FILES:
                continue
            if total_bytes + stat.st_size > _MAX_SOURCE_SNAPSHOT_TOTAL_BYTES:
                continue
            try:
                data = source.read_bytes()
            except OSError:
                continue
            if _contains_token_sentinel(data):
                continue
            destination = staged / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            copied += 1
            total_bytes += stat.st_size
        write_source_snapshot_fn(work_root, repo_ref, staged if copied else None)
        staged = Path()
    finally:
        if staged_parent.exists():
            shutil.rmtree(staged_parent, ignore_errors=True)


def _iter_snapshot_candidates(clone_path: Path) -> Sequence[tuple[Path, PurePosixPath]]:
    candidates: list[tuple[Path, PurePosixPath]] = []
    root = clone_path.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            name for name in dirnames if name != ".git" and not (Path(dirpath) / name).is_symlink()
        ]
        current = Path(dirpath)
        for filename in filenames:
            source = current / filename
            if source.is_symlink() or not source.is_file():
                continue
            try:
                relative = source.relative_to(root)
            except ValueError:
                continue
            relative_posix = PurePosixPath(relative.as_posix())
            if is_sparse_manifest_path(relative_posix.as_posix()):
                candidates.append((source, relative_posix))
    return tuple(candidates)


def _contains_token_sentinel(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore")
    return any(pattern.search(text) for pattern in committed_token_patterns())


def _skip_source_snapshot(*_args: object) -> Path | None:
    return None


def _clone_with_retry(
    repo: RepoSpec,
    *,
    workdir: Path,
    clone: CloneFn,
    credential: CloneCredential | None,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    clone_limits: SecurityLimits,
) -> Path:
    """Clone with bounded retry on transient/rate-limit failures only.

    ``CloneAuthRequired``/``CloneAccessDenied`` are never retried; they propagate
    immediately to the caller's typed-failure mapping.
    """

    options = CloneOptions(
        remote_url=repo.clone_url,
        destination=workdir / "repo",
        limits=clone_limits,
        credential=credential,
    )
    return retry_with_backoff(
        lambda: clone(options),
        is_transient=lambda exc: isinstance(exc, CloneRateLimited | CloneTransient),
        max_attempts=CLONE_RETRY_MAX_ATTEMPTS,
        base_delay=DEFAULT_BASE_DELAY,
        sleep=sleep,
        max_elapsed=clone_limits.clone_timeout_seconds * _CLONE_ELAPSED_BUDGET_FACTOR,
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
    if isinstance(exc, CloneTimeout):
        return str(exc)
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
    clone_timeout_seconds: float = DEFAULT_LIMITS.clone_timeout_seconds,
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
    write_first_party_fn: Callable[..., Path] | None = None,
    write_source_snapshot_fn: SourceSnapshotWriter | None = None,
    progress: ProgressFn | None = None,
    exclude_paths: Sequence[str] = DEFAULT_EXCLUDE_PATHS,
    syft_catalogers: Sequence[str] | None = None,
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

    store_needed = None in (
        is_scanned_fn,
        repo_dir_fn,
        write_sbom_fn,
        write_status_fn,
        write_first_party_fn,
    )
    if store_needed:
        # Lazy: importing the store pulls jsonschema (absent from the lock-only
        # security-canaries env). Canaries inject all store seams to avoid this.
        from repolens.data.store import (
            atomic_write_json,
            is_repo_scanned,
            replace_source_snapshot,
            repo_dir,
            write_first_party,
            write_sbom,
        )

        is_scanned_fn = is_scanned_fn or is_repo_scanned
        repo_dir_fn = repo_dir_fn or repo_dir
        write_sbom_fn = write_sbom_fn or write_sbom
        write_status_fn = write_status_fn or atomic_write_json
        write_first_party_fn = write_first_party_fn or write_first_party
        write_source_snapshot_fn = write_source_snapshot_fn or replace_source_snapshot
    else:
        write_source_snapshot_fn = write_source_snapshot_fn or _skip_source_snapshot

    get_credential = _memoized_credential_provider(credential_provider)

    syft = Path(syft_path)
    if not math.isfinite(clone_timeout_seconds) or clone_timeout_seconds <= 0:
        raise InputError("clone_timeout_seconds must be a positive number of seconds")
    clone_limits = replace(DEFAULT_LIMITS, clone_timeout_seconds=clone_timeout_seconds)
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
        outcome, deps_count, raw_deps_count = _scan_one(
            repo,
            work_root=work_root,
            syft_path=syft,
            timeout_seconds=timeout_seconds,
            clone=clone,
            command_runner=command_runner,
            exclude_paths=exclude_paths,
            syft_catalogers=syft_catalogers,
            clock=clock,
            repo_dir_fn=repo_dir_fn,
            write_sbom_fn=write_sbom_fn,
            write_status_fn=write_status_fn,
            write_first_party_fn=write_first_party_fn,
            write_source_snapshot_fn=write_source_snapshot_fn,
            get_credential=get_credential,
            sleep=sleep,
            monotonic=monotonic,
            clone_limits=clone_limits,
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
                    raw_deps_count=raw_deps_count,
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
