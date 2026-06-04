"""Stage orchestration for API-only license resolution."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from repolens.data.limits import SCHEMA_VERSION
from repolens.data.models import ResolvedItem
from repolens.policy.config import Policy, load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.adapters import (
    API_ALLOWED_HOSTS,
    build_default_adapters,
)
from repolens.resolve.evidence import (
    UNKNOWN_VERSION,
    has_exact_license_evidence,
    should_attempt_api_resolution,
)
from repolens.resolve.license_expression import license_resolution_id
from repolens.resolve.mobile import (
    MobileDetection,
    MobileEnrichmentOutcome,
    detect_mobile,
    enrich_mobile_native,
)
from repolens.resolve.models import (
    ApiCandidate,
    FetchFunction,
    PackageFact,
    ResolveAdapter,
    ScancodeExecutableProvider,
)
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

SbomReader = Callable[[str | Path, str], dict[str, object]]
ResolvedWriter = Callable[[str | Path, str, Sequence[dict[str, object]]], Path]
ResolveProgress = Callable[[int, int, str], None]


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
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> Path:
    """Resolve a Syft SBOM into frozen-schema ``resolved.ndjson`` records."""

    read, write = _storage_functions(sbom_reader, resolved_writer)
    sbom = read(work_root, repo_ref)
    resolved_source_root = _validated_source_root(source_root)
    detection = detect_mobile(resolved_source_root, limits=limits)
    packages = _package_facts(sbom, repo_ref)
    records: list[dict[str, object]] = []
    total = len(packages)
    for index, package in enumerate(packages, start=1):
        records.append(
            _resolved_dict(
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
                )
            )
        )
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
) -> ResolvedItem:
    declared = _resolve_declared(package)
    if declared is not None:
        return _record(package, spdx_id=declared, source_layer="syft", anchor=declared)

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
) -> ResolvedItem | None:
    if not should_attempt_api_resolution(package):
        return None

    unresolved_anchor = "unresolved:no_candidate"
    verified_candidates: list[ApiCandidate] = []
    for adapter in adapters if adapters is not None else build_default_adapters(fetcher):
        candidate = adapter.resolve(package)
        if candidate is None:
            continue
        verified = _verify_api_candidate(candidate, fetcher=fetcher, resolver=evidence_resolver)
        if verified is not None:
            if not detect_conflicts:
                return _record(
                    package,
                    spdx_id=verified.spdx_id,
                    source_layer="api",
                    url=verified.evidence_url,
                    anchor=verified.evidence_anchor,
                )
            verified_candidates.append(verified)
        unresolved_anchor = "unresolved:evidence_mismatch"

    if not verified_candidates:
        if lower_unresolved:
            return _record(package, spdx_id=None, source_layer="api", anchor=unresolved_anchor)
        return None
    spdx_ids = {candidate.spdx_id for candidate in verified_candidates}
    if len(spdx_ids) > 1:
        return _record(
            package, spdx_id="CONFLICT", source_layer="api", anchor="conflict:api_disagreement"
        )
    verified = verified_candidates[0]
    return _record(
        package,
        spdx_id=verified.spdx_id,
        source_layer="api",
        url=verified.evidence_url,
        anchor=verified.evidence_anchor,
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


def _resolve_declared(package: PackageFact) -> str | None:
    if package.declared_license_raw is None:
        return None
    normalized = normalize_license(package.declared_license_raw, load_default_policy())
    return normalized.spdx_id


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

    options = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
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
    )


def _api_candidate_license_id(raw_license: str, policy: Policy) -> str | None:
    return license_resolution_id(raw_license, policy)


def _record(
    package: PackageFact,
    *,
    spdx_id: str | None,
    source_layer: str,
    anchor: str,
    url: str | None = None,
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
        declared_license_raw=package.declared_license_raw,
        spdx_id=spdx_id,
        evidence=evidence,
        tags=DEFAULT_TAGS,
        modified="unknown",
    )


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


def _validated_source_root(source_root: str | Path | None) -> Path | None:
    if source_root is None:
        return None
    root = Path(source_root).resolve()
    if not root.is_dir():
        return None
    return root


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
