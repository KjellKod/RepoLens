"""Stage orchestration for API-only license resolution."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from repolens.data.limits import SCHEMA_VERSION
from repolens.data.models import ResolvedItem
from repolens.data.store import read_sbom, write_resolved
from repolens.policy.config import load_default_policy
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
from repolens.resolve.models import ApiCandidate, FetchFunction, PackageFact, ResolveAdapter
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import (
    HttpFetchOptions,
    Resolver,
    fetch_url,
    validate_url_for_fetch,
)

DEFAULT_TAGS = {
    "origin": "third-party-oss",
    "scope": "runtime",
    "distribution": "server",
}


def run_resolve(
    work_root: str | Path,
    repo_ref: str,
    *,
    adapters: Iterable[ResolveAdapter] | None = None,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
) -> Path:
    """Resolve a Syft SBOM into frozen-schema ``resolved.ndjson`` records."""

    sbom = read_sbom(work_root, repo_ref)
    records = [
        _resolved_dict(
            _resolve_package(
                package,
                adapters=adapters,
                fetcher=fetcher,
                evidence_resolver=evidence_resolver,
            )
        )
        for package in _package_facts(sbom, repo_ref)
    ]
    return write_resolved(work_root, repo_ref, records)


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
            )
        )
    return tuple(facts)


def _resolve_package(
    package: PackageFact,
    *,
    adapters: Iterable[ResolveAdapter] | None,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
) -> ResolvedItem:
    declared = _resolve_declared(package)
    if declared is not None:
        return _record(package, spdx_id=declared, source_layer="syft", anchor=declared)

    if not should_attempt_api_resolution(package):
        return _record(
            package, spdx_id=None, source_layer="syft", anchor="unresolved:missing_version"
        )

    unresolved_anchor = "unresolved:no_candidate"
    for adapter in adapters if adapters is not None else build_default_adapters(fetcher):
        candidate = adapter.resolve(package)
        if candidate is None:
            continue
        verified = _verify_api_candidate(candidate, fetcher=fetcher, resolver=evidence_resolver)
        if verified is not None:
            return _record(
                package,
                spdx_id=verified.spdx_id,
                source_layer="api",
                url=verified.evidence_url,
                anchor=verified.evidence_anchor,
            )
        unresolved_anchor = "unresolved:evidence_mismatch"

    return _record(
        package,
        spdx_id=None,
        source_layer="api",
        anchor=unresolved_anchor,
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
    normalized = normalize_license(candidate.spdx_id, load_default_policy())
    if normalized.spdx_id is None or not candidate.evidence_anchor:
        return None

    options = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
    try:
        validate_url_for_fetch(candidate.evidence_url, options, resolver=resolver)
        result = fetcher(candidate.evidence_url, options)
    except FetchSecurityError:
        return None

    if not has_exact_license_evidence(result.body, candidate, normalized.spdx_id):
        return None
    return ApiCandidate(
        spdx_id=normalized.spdx_id,
        evidence_url=result.url,
        evidence_anchor=candidate.evidence_anchor,
    )


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
