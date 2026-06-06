"""Stage orchestration for API-only license resolution."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from repolens.data.limits import SCHEMA_VERSION
from repolens.data.models import ResolvedItem
from repolens.policy.config import Policy, load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.adapters import (
    API_ALLOWED_HOSTS,
    build_default_adapters,
    package_description,
)
from repolens.resolve.descriptions import first_brief_description
from repolens.resolve.ecosystems import is_cataloging_only_package, is_ci_only_package
from repolens.resolve.evidence import (
    UNKNOWN_VERSION,
    has_exact_license_evidence,
    should_attempt_api_resolution,
)
from repolens.resolve.license_expression import license_resolution_id, license_resolution_key
from repolens.resolve.mobile import (
    MobileDetection,
    MobileEnrichmentOutcome,
    detect_mobile,
    enrich_mobile_native,
)
from repolens.resolve.mobile_metadata import resolve_mobile_metadata
from repolens.resolve.models import (
    ApiCandidate,
    FetchFunction,
    PackageFact,
    ResolveAdapter,
    ScancodeExecutableProvider,
)
from repolens.resolve.purl import package_identity
from repolens.resolve.scancode import CommandRunner, resolve_scancode_path, run_scancode_fallback
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import (
    HttpFetchOptions,
    Resolver,
    fetch_url,
    validate_url_for_fetch,
)
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.sandbox import SandboxRunner

DEFAULT_TAGS = {
    "origin": "third-party-oss",
    "scope": "runtime",
    "distribution": "server",
}
_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
DECLARED_UNPINNED_STATUS = "declared-unpinned"
CI_ONLY_TAGS = {
    "origin": "third-party-oss",
    "scope": "build",
    "distribution": "not-distributed",
}

SbomReader = Callable[[str | Path, str], dict[str, object]]
ResolvedWriter = Callable[[str | Path, str, Sequence[dict[str, object]]], Path]
FirstPartyReader = Callable[[str | Path, str], frozenset[str]]
SourceSnapshotReader = Callable[[str | Path, str], Path | None]
ResolveProgress = Callable[[int, int, str], None]


@dataclass
class ResolveCacheStats:
    """Per-run reuse counters for operator visibility."""

    declared_hits: int = 0
    api_hits: int = 0

    @property
    def cache_hits(self) -> int:
        return self.declared_hits + self.api_hits


@dataclass(frozen=True, slots=True)
class _ResolutionOutcome:
    spdx_id: str | None
    source_layer: str
    anchor: str
    url: str | None = None
    description: str | None = None


@dataclass
class _ResolveCache:
    stats: ResolveCacheStats
    declared: dict[str, str | None]
    api: dict[
        tuple[str, str, str, str | None, str | None, bool, bool]
        | tuple[str, str, str, str | None, str | None, bool, bool, tuple[str, ...]],
        _ResolutionOutcome | None,
    ]
    descriptions: dict[tuple[str, str, str, str | None], str | None]


def run_resolve(
    work_root: str | Path,
    repo_ref: str,
    *,
    source_root: str | Path | None = None,
    enable_mobile_native: bool = False,
    adapters: Iterable[ResolveAdapter] | None = None,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
    detect_conflicts: bool = False,
    progress: ResolveProgress | None = None,
    mobile_enricher: (
        Callable[
            [PackageFact, MobileDetection, Path, SandboxRunner | None, SecurityLimits],
            MobileEnrichmentOutcome,
        ]
        | None
    ) = None,
    sandbox_runner: SandboxRunner | None = None,
    scancode_runner: CommandRunner | None = None,
    scancode_executable_provider: ScancodeExecutableProvider | None = None,
    sbom_reader: SbomReader | None = None,
    resolved_writer: ResolvedWriter | None = None,
    first_party_reader: FirstPartyReader | None = None,
    source_snapshot_reader: SourceSnapshotReader | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
    cache_stats: ResolveCacheStats | None = None,
) -> Path:
    """Resolve a Syft SBOM into frozen-schema ``resolved.ndjson`` records."""

    read, write = _storage_functions(sbom_reader, resolved_writer)
    read_first_party = _first_party_reader(first_party_reader)
    sbom = read(work_root, repo_ref)
    # Read the repo's own workspace-member names once (empty for old work-roots
    # with no first_party.json — the fresh-scan-only caveat). Stamping in this
    # loop, after _resolved_dict builds the record, covers every resolution path
    # (declared, api, scancode, mobile, unresolved) with a single touch-point.
    first_party_names = read_first_party(work_root, repo_ref)
    resolved_source_root = _effective_source_root(
        work_root,
        repo_ref,
        source_root=source_root,
        source_snapshot_reader=source_snapshot_reader,
    )
    detection = detect_mobile(resolved_source_root, limits=limits)
    packages = _package_facts(sbom, repo_ref)
    records: list[dict[str, object]] = []
    total = len(packages)
    cache = _ResolveCache(
        stats=cache_stats or ResolveCacheStats(),
        declared={},
        api={},
        descriptions={},
    )
    for index, package in enumerate(packages, start=1):
        package = _package_with_description(
            package,
            fetcher=fetcher,
            cache=cache,
            lookup_enabled=adapters is None,
        )
        record = _resolved_dict(
            _resolve_package(
                package,
                work_root=work_root,
                source_root=resolved_source_root,
                mobile_detection=detection,
                enable_mobile_native=enable_mobile_native,
                adapters=adapters,
                fetcher=fetcher,
                evidence_resolver=evidence_resolver,
                detect_conflicts=detect_conflicts,
                mobile_enricher=mobile_enricher,
                sandbox_runner=sandbox_runner,
                scancode_runner=scancode_runner,
                scancode_executable_provider=scancode_executable_provider,
                limits=limits,
                cache=cache,
            )
        )
        tags = record["tags"]
        if package.name in first_party_names and isinstance(tags, dict):
            tags["origin"] = "first-party"
        if (
            package.declared_version_status == DECLARED_UNPINNED_STATUS
            and record["version"] == UNKNOWN_VERSION
        ):
            record["declared_version_status"] = DECLARED_UNPINNED_STATUS
        records.append(record)
        if progress is not None:
            progress(index, total, package.name)
    return write(work_root, repo_ref, records)


def _storage_functions(
    sbom_reader: SbomReader | None,
    resolved_writer: ResolvedWriter | None,
) -> tuple[SbomReader, ResolvedWriter]:
    if sbom_reader is not None and resolved_writer is not None:
        return sbom_reader, resolved_writer

    from repolens.data.store import read_sbom, write_resolved

    return sbom_reader or read_sbom, resolved_writer or write_resolved


def _first_party_reader(reader: FirstPartyReader | None) -> FirstPartyReader:
    if reader is not None:
        return reader

    from repolens.data.store import read_first_party

    return read_first_party


def _source_snapshot_reader(reader: SourceSnapshotReader | None) -> SourceSnapshotReader:
    if reader is not None:
        return reader

    from repolens.data.store import read_source_snapshot

    return read_source_snapshot


def _resolved_dict(item: ResolvedItem) -> dict[str, object]:
    record = item.to_dict()
    if item.spdx_id is None:
        record["spdx_id"] = None
    return record


def _package_facts(sbom: dict[str, object], repo_ref: str) -> tuple[PackageFact, ...]:
    repo = _string_or_default(sbom.get("repo"), repo_ref)
    artifacts = sbom.get("artifacts")
    if not isinstance(artifacts, list):
        return ()

    facts: list[PackageFact] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        name = _string_or_default(artifact.get("name"), "")
        package_type = _string_or_default(artifact.get("type"), "")
        if not name or not package_type:
            continue
        facts.append(
            PackageFact(
                name=name,
                version=_version_or_unknown(artifact.get("version")),
                package_type=package_type,
                repo=repo,
                purl=_optional_string(artifact.get("purl")),
                declared_license_raw=_declared_license(artifact.get("licenses")),
                locations=_locations(artifact.get("locations")),
                declared_version_status=_declared_version_status(
                    artifact.get("declared_version_status")
                ),
                description=_description_from_artifact(artifact),
            )
        )
    return tuple(facts)


def _resolve_package(
    package: PackageFact,
    *,
    work_root: str | Path,
    source_root: Path | None,
    mobile_detection: MobileDetection,
    enable_mobile_native: bool,
    adapters: Iterable[ResolveAdapter] | None,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
    detect_conflicts: bool,
    mobile_enricher: (
        Callable[
            [PackageFact, MobileDetection, Path, SandboxRunner | None, SecurityLimits],
            MobileEnrichmentOutcome,
        ]
        | None
    ),
    sandbox_runner: SandboxRunner | None,
    scancode_runner: CommandRunner | None,
    scancode_executable_provider: ScancodeExecutableProvider | None,
    limits: SecurityLimits,
    cache: _ResolveCache,
) -> ResolvedItem:
    declared = _resolve_declared(package, cache=cache)
    if declared is not None:
        return _record(package, spdx_id=declared, source_layer="syft", anchor=declared)
    cataloging_only = is_cataloging_only_package(package)
    if cataloging_only:
        metadata_item = _resolve_mobile_metadata_package(
            package,
            source_root=source_root,
            fetcher=fetcher,
            evidence_resolver=evidence_resolver,
            limits=limits,
            cache=cache,
        )
        if metadata_item is not None:
            return metadata_item
    if (
        cataloging_only
        and enable_mobile_native
        and mobile_detection.detected
        and source_root is not None
    ):
        mobile = _resolve_mobile_package(
            package,
            detection=mobile_detection,
            source_root=source_root,
            mobile_enricher=mobile_enricher,
            sandbox_runner=sandbox_runner,
            limits=limits,
        )
        if mobile.candidate is not None:
            return _record(
                package,
                spdx_id=mobile.candidate.spdx_id,
                source_layer="mobile",
                url=mobile.candidate.evidence_url,
                anchor=mobile.candidate.evidence_anchor,
            )
        if mobile.unresolved_anchor is not None:
            return _record(
                package,
                spdx_id=None,
                source_layer="mobile",
                anchor=mobile.unresolved_anchor,
            )
    if cataloging_only:
        return _record(
            package,
            spdx_id=None,
            source_layer="api",
            anchor="unresolved:no_supported_catalog_license_api",
        )

    mobile_anchor: str | None = None
    if not should_attempt_api_resolution(package) and source_root is None:
        return _record(
            package, spdx_id=None, source_layer="syft", anchor="unresolved:missing_version"
        )
    api_item = _resolve_api_package(
        package,
        adapters=adapters,
        fetcher=fetcher,
        evidence_resolver=evidence_resolver,
        detect_conflicts=detect_conflicts,
        lower_unresolved=source_root is None,
        cache=cache,
    )
    if api_item is not None:
        return api_item
    if enable_mobile_native and mobile_detection.detected and source_root is not None:
        mobile = _resolve_mobile_package(
            package,
            detection=mobile_detection,
            source_root=source_root,
            mobile_enricher=mobile_enricher,
            sandbox_runner=sandbox_runner,
            limits=limits,
        )
        if mobile.candidate is not None:
            return _record(
                package,
                spdx_id=mobile.candidate.spdx_id,
                source_layer="mobile",
                url=mobile.candidate.evidence_url,
                anchor=mobile.candidate.evidence_anchor,
            )
        mobile_anchor = mobile.unresolved_anchor

    scancode = run_scancode_fallback(
        package,
        work_root=work_root,
        source_root=source_root,
        command_runner=scancode_runner,
        executable_provider=scancode_executable_provider or resolve_scancode_path,
        limits=limits,
    )
    if scancode.spdx_id is not None:
        return _record(
            package,
            spdx_id=scancode.spdx_id,
            source_layer="scancode",
            anchor=scancode.anchor,
        )
    if mobile_anchor is not None:
        return _record(package, spdx_id=None, source_layer="mobile", anchor=mobile_anchor)
    return _record(package, spdx_id=None, source_layer="scancode", anchor=scancode.anchor)


def _resolve_api_package(
    package: PackageFact,
    *,
    adapters: Iterable[ResolveAdapter] | None,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
    detect_conflicts: bool,
    lower_unresolved: bool,
    cache: _ResolveCache,
) -> ResolvedItem | None:
    if not should_attempt_api_resolution(package):
        return None

    cache_key = _api_cache_key(
        package,
        detect_conflicts=detect_conflicts,
        lower_unresolved=lower_unresolved,
    )
    if cache_key in cache.api:
        cache.stats.api_hits += 1
        return _record_from_outcome(package, cache.api[cache_key])

    unresolved_anchor = "unresolved:no_candidate"
    verified_candidates: list[ApiCandidate] = []
    for adapter in adapters if adapters is not None else build_default_adapters(fetcher):
        candidate = adapter.resolve(package)
        if candidate is None:
            continue
        verified = _verify_api_candidate(candidate, fetcher=fetcher, resolver=evidence_resolver)
        if verified is not None:
            if not detect_conflicts:
                return _record_cached_api(
                    cache,
                    cache_key,
                    _ResolutionOutcome(
                        spdx_id=verified.spdx_id,
                        source_layer="api",
                        url=verified.evidence_url,
                        anchor=verified.evidence_anchor,
                        description=verified.description,
                    ),
                    package,
                )
            verified_candidates.append(verified)
        unresolved_anchor = "unresolved:evidence_mismatch"

    if not verified_candidates:
        if lower_unresolved:
            return _record_cached_api(
                cache,
                cache_key,
                _ResolutionOutcome(None, "api", unresolved_anchor),
                package,
            )
        cache.api[cache_key] = None
        return None
    license_keys = {
        license_resolution_key(candidate.spdx_id, load_default_policy())
        for candidate in verified_candidates
    }
    if len(license_keys) > 1:
        return _record_cached_api(
            cache,
            cache_key,
            _ResolutionOutcome("CONFLICT", "api", "conflict:api_disagreement"),
            package,
        )
    verified = verified_candidates[0]
    return _record_cached_api(
        cache,
        cache_key,
        _ResolutionOutcome(
            spdx_id=verified.spdx_id,
            source_layer="api",
            url=verified.evidence_url,
            anchor=verified.evidence_anchor,
            description=verified.description,
        ),
        package,
    )


def _resolve_mobile_metadata_package(
    package: PackageFact,
    *,
    source_root: Path | None,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
    limits: SecurityLimits,
    cache: _ResolveCache,
) -> ResolvedItem | None:
    cache_key = _mobile_metadata_cache_key(package)
    if cache_key in cache.api:
        cache.stats.api_hits += 1
        return _record_from_outcome(package, cache.api[cache_key])

    candidate = resolve_mobile_metadata(
        package,
        source_root=source_root,
        fetcher=fetcher,
        limits=limits,
    )
    if candidate is None:
        cache.api[cache_key] = None
        return None
    verified = _verify_api_candidate(candidate, fetcher=fetcher, resolver=evidence_resolver)
    if verified is None:
        return _record_cached_api(
            cache,
            cache_key,
            _ResolutionOutcome(None, "api", "unresolved:evidence_mismatch"),
            package,
        )
    return _record_cached_api(
        cache,
        cache_key,
        _ResolutionOutcome(
            spdx_id=verified.spdx_id,
            source_layer="api",
            url=verified.evidence_url,
            anchor=verified.evidence_anchor,
            description=verified.description,
        ),
        package,
    )


def _resolve_mobile_package(
    package: PackageFact,
    *,
    detection: MobileDetection,
    source_root: Path,
    mobile_enricher: (
        Callable[
            [PackageFact, MobileDetection, Path, SandboxRunner | None, SecurityLimits],
            MobileEnrichmentOutcome,
        ]
        | None
    ),
    sandbox_runner: SandboxRunner | None,
    limits: SecurityLimits,
) -> MobileEnrichmentOutcome:
    if mobile_enricher is not None:
        return mobile_enricher(package, detection, source_root, sandbox_runner, limits)
    if sandbox_runner is None:
        return MobileEnrichmentOutcome(unresolved_anchor="unresolved:mobile_sandbox_unavailable")
    return enrich_mobile_native(
        package,
        detection=detection,
        source_root=source_root,
        sandbox_runner=sandbox_runner,
        limits=limits,
    )


def _resolve_declared(package: PackageFact, *, cache: _ResolveCache) -> str | None:
    if package.declared_license_raw is None:
        return None
    key = package.declared_license_raw.strip()
    if key in cache.declared:
        cache.stats.declared_hits += 1
        return cache.declared[key]
    normalized = normalize_license(package.declared_license_raw, load_default_policy())
    cache.declared[key] = normalized.spdx_id
    return normalized.spdx_id


def _api_cache_key(
    package: PackageFact,
    *,
    detect_conflicts: bool,
    lower_unresolved: bool,
) -> tuple[str, str, str, str | None, str | None, bool, bool]:
    ecosystem, identity = package_identity(package.package_type, package.name, package.purl)
    return (
        ecosystem.lower(),
        identity.lower(),
        package.version,
        package.purl,
        package.declared_license_raw,
        detect_conflicts,
        lower_unresolved,
    )


def _mobile_metadata_cache_key(
    package: PackageFact,
) -> tuple[str, str, str, str | None, str | None, bool, bool, tuple[str, ...]]:
    return (
        *_api_cache_key(package, detect_conflicts=False, lower_unresolved=True),
        package.locations,
    )


def _description_cache_key(package: PackageFact) -> tuple[str, str, str, str | None]:
    ecosystem, identity = package_identity(package.package_type, package.name, package.purl)
    return (
        ecosystem.lower(),
        identity.lower(),
        package.version,
        package.purl,
    )


def _package_with_description(
    package: PackageFact,
    *,
    fetcher: FetchFunction,
    cache: _ResolveCache,
    lookup_enabled: bool,
) -> PackageFact:
    if package.description is not None or not lookup_enabled:
        return package
    cache_key = _description_cache_key(package)
    if cache_key not in cache.descriptions:
        cache.descriptions[cache_key] = package_description(package, fetcher=fetcher)
    description = cache.descriptions[cache_key]
    if description is None:
        return package
    return replace(package, description=description)


def _record_cached_api(
    cache: _ResolveCache,
    cache_key: tuple[str, str, str, str | None, str | None, bool, bool]
    | tuple[str, str, str, str | None, str | None, bool, bool, tuple[str, ...]],
    outcome: _ResolutionOutcome,
    package: PackageFact,
) -> ResolvedItem:
    cache.api[cache_key] = outcome
    record = _record_from_outcome(package, outcome)
    if record is None:
        raise AssertionError("API outcome must be record-producing")
    return record


def _record_from_outcome(
    package: PackageFact,
    outcome: _ResolutionOutcome | None,
) -> ResolvedItem | None:
    if outcome is None:
        return None
    return _record(
        package,
        spdx_id=outcome.spdx_id,
        source_layer=outcome.source_layer,
        url=outcome.url,
        anchor=outcome.anchor,
        description=outcome.description,
    )


def _verify_api_candidate(
    candidate: ApiCandidate,
    *,
    fetcher: FetchFunction,
    resolver: Resolver | None,
) -> ApiCandidate | None:
    policy = load_default_policy()
    spdx_id = _api_candidate_license_id(candidate.spdx_id, policy)
    if spdx_id is None or not candidate.evidence_anchor:
        return None

    options = _api_evidence_fetch_options(candidate.evidence_url)
    try:
        validate_url_for_fetch(candidate.evidence_url, options, resolver=resolver)
        result = fetcher(candidate.evidence_url, options)
    except FetchSecurityError:
        return None

    if not has_exact_license_evidence(result.body, candidate, spdx_id):
        return None
    return ApiCandidate(
        spdx_id=spdx_id,
        evidence_url=result.url,
        evidence_anchor=candidate.evidence_anchor,
        description=candidate.description,
    )


def _api_evidence_fetch_options(url: str) -> HttpFetchOptions:
    headers = _GITHUB_API_HEADERS if urlparse(url).hostname == "api.github.com" else {}
    return HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers=headers)


def _api_candidate_license_id(raw_license: str, policy: Policy) -> str | None:
    return license_resolution_id(raw_license, policy)


def _record(
    package: PackageFact,
    *,
    spdx_id: str | None,
    source_layer: str,
    anchor: str,
    url: str | None = None,
    description: str | None = None,
) -> ResolvedItem:
    evidence = {
        "source_layer": source_layer,
        "anchor": anchor,
        "fetched_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if url is not None:
        evidence["url"] = url
    return ResolvedItem(
        schema_version=SCHEMA_VERSION,
        name=package.name,
        version=package.version,
        repo=package.repo,
        purl=package.purl,
        description=description or package.description,
        declared_license_raw=package.declared_license_raw,
        spdx_id=spdx_id,
        evidence=evidence,
        tags=_default_tags_for(package),
        modified="unknown",
    )


def _default_tags_for(package: PackageFact) -> dict[str, str]:
    if is_ci_only_package(package):
        return dict(CI_ONLY_TAGS)
    return dict(DEFAULT_TAGS)


def _declared_license(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def _locations(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return tuple(out)


def _declared_version_status(value: object) -> str | None:
    if value == DECLARED_UNPINNED_STATUS:
        return DECLARED_UNPINNED_STATUS
    return None


def _description_from_artifact(artifact: dict[str, object]) -> str | None:
    candidates: list[object] = [artifact.get("description")]
    metadata = artifact.get("metadata")
    if isinstance(metadata, dict):
        candidates.extend(
            (
                metadata.get("description"),
                metadata.get("summary"),
                metadata.get("packageDescription"),
            )
        )
    return first_brief_description(candidates)


def _validated_source_root(source_root: str | Path | None) -> Path | None:
    if source_root is None:
        return None
    root = Path(source_root).resolve()
    if not root.is_dir():
        return None
    return root


def _effective_source_root(
    work_root: str | Path,
    repo_ref: str,
    *,
    source_root: str | Path | None,
    source_snapshot_reader: SourceSnapshotReader | None,
) -> Path | None:
    if source_root is not None:
        return _validated_source_root(source_root)
    return _source_snapshot_reader(source_snapshot_reader)(work_root, repo_ref)


def _version_or_unknown(value: object) -> str:
    if not isinstance(value, str):
        return UNKNOWN_VERSION
    return value.strip() or UNKNOWN_VERSION


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _string_or_default(value: object, default: str) -> str:
    if isinstance(value, str) and value:
        return value
    return default
