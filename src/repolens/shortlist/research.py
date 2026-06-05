"""Deterministic shortlist research artifact generation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from repolens.data import store
from repolens.data.limits import max_bytes_for
from repolens.policy import PolicyTier, classify_license_input
from repolens.policy.config import load_default_policy
from repolens.resolve.adapters import API_ALLOWED_HOSTS, target_license_candidates
from repolens.resolve.license_expression import license_resolution_id
from repolens.resolve.models import FetchFunction
from repolens.resolve.purl import parse_purl
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, fetch_url
from repolens.shortlist.evidence import (
    BrowserEvidence,
    ConflictEvidence,
    EvidenceIdentity,
    EvidenceRecord,
    SourceRepoEvidence,
    identity_for_context,
)

_FETCH_OPTIONS = HttpFetchOptions(
    allowed_hosts=API_ALLOWED_HOSTS | frozenset({"trunk.cocoapods.org"}),
    headers={},
)
_UNKNOWN_VERSION = "unknown"
_LOOKUP_LABELS = {
    "pypi": "PyPI metadata",
    "clearlydefined": "ClearlyDefined",
    "github_license_api": "GitHub license API",
    "github_raw_license": "LICENSE",
    "cocoapods": "CocoaPods podspec",
    "swiftpm": "SwiftPM tag license",
}
_GITHUB_HOST = "github.com"
_GITHUB_API_HOST = "api.github.com"
_RAW_GITHUB_HOST = "raw.githubusercontent.com"
_CONTROLLED_LICENSE_PATHS = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md")
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_MUTABLE_REFS = frozenset({"main", "master", "develop", "development", "trunk", "default"})


@dataclass(frozen=True, slots=True)
class ResearchResult:
    """Paths and counts written by the research command."""

    proposals_path: Path
    evidence_path: Path
    review_path: Path
    row_count: int
    proposal_count: int


@dataclass(frozen=True, slots=True)
class LookupResult:
    """One deterministic license lookup result."""

    source: str
    label: str
    url: str
    spdx_id: str
    anchor: str
    machine_verifiable: bool
    ref: str | None = None
    display_url: str | None = None
    source_repo: SourceRepoEvidence | None = None

    def browser_evidence(self) -> BrowserEvidence:
        return BrowserEvidence(
            label=self.label,
            url=self.display_url or self.url,
            source_type=self.source,
            anchor=self.anchor,
            ref=self.ref,
        )


def run_research(
    *,
    contexts_path: Path,
    proposals_path: Path,
    evidence_path: Path,
    review_path: Path,
    fetcher: FetchFunction = fetch_url,
) -> ResearchResult:
    """Research emitted contexts and write proposals, evidence, and review notes."""

    rows = load_context_rows(contexts_path)
    evidence_records: list[EvidenceRecord] = []
    proposals: list[dict[str, Any]] = []
    for row in rows:
        record, proposal = research_context(row, fetcher=fetcher)
        evidence_records.append(record)
        if proposal is not None:
            proposals.append(proposal)

    store.atomic_write_json(proposals_path, proposals)
    store.atomic_write_json(
        evidence_path,
        [record.to_shortlist_metadata() for record in evidence_records],
    )
    review_path.parent.mkdir(parents=True, exist_ok=True)
    store.atomic_write_bytes(
        review_path,
        render_review_markdown(evidence_records).encode("utf-8"),
    )
    return ResearchResult(
        proposals_path=proposals_path,
        evidence_path=evidence_path,
        review_path=review_path,
        row_count=len(evidence_records),
        proposal_count=len(proposals),
    )


def load_context_rows(path: Path) -> tuple[Mapping[str, Any], ...]:
    """Load model-free shortlist context rows."""

    raw = store.load_json_capped(path, max_bytes=max_bytes_for("shortlist"))
    if not isinstance(raw, list):
        raise ValueError("shortlist contexts must be a JSON array")
    rows: list[Mapping[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"shortlist contexts[{index}] must be an object")
        rows.append(entry)
    return tuple(rows)


def research_context(
    row: Mapping[str, Any],
    *,
    fetcher: FetchFunction = fetch_url,
) -> tuple[EvidenceRecord, dict[str, Any] | None]:
    """Research one context row and return evidence plus an optional verified proposal."""

    identity = identity_for_context(row)
    lookup_results: list[LookupResult] = []
    attempted: list[str] = []
    for lookup in _lookup_urls(row, identity):
        attempted.append(lookup.label)
        result = _fetch_lookup(lookup, fetcher)
        if result is not None:
            lookup_results.append(result)
            if lookup.source_repo is not None:
                break

    if not attempted:
        attempted.append("deterministic metadata lookup")

    spdx_values = {result.spdx_id for result in lookup_results}
    if len(spdx_values) > 1:
        conflicts = tuple(
            ConflictEvidence(
                spdx_id=result.spdx_id,
                label=result.label,
                url=result.url,
                anchor=result.anchor,
            )
            for result in lookup_results
        )
        return (
            _record(
                identity,
                outcome="conflict",
                machine_verification="conflict",
                lookups_attempted=attempted,
                conflicts=conflicts,
                review_note="Deterministic sources disagreed; human review required.",
            ),
            None,
        )

    if not lookup_results:
        return (
            _record(
                identity,
                outcome="no_public_evidence",
                machine_verification="no_public_evidence",
                lookups_attempted=attempted,
                review_note="No public deterministic evidence found.",
            ),
            None,
        )

    result = lookup_results[0]
    decision = classify_license_input(result.spdx_id)
    evidence = (result.browser_evidence(),)
    if decision.tier != PolicyTier.ALLOW:
        return (
            _record(
                identity,
                outcome="legal_or_vendor_review",
                machine_verification="legal_or_vendor_review",
                lookups_attempted=attempted,
                likely_spdx=result.spdx_id,
                browser_evidence=evidence,
                review_note="Deterministic evidence confirms a license requiring human judgment.",
            ),
            None,
        )

    if result.machine_verifiable:
        proposal = _proposal_for_result(identity, result)
        return (
            _record(
                identity,
                outcome="machine_verified",
                machine_verification="verified",
                lookups_attempted=attempted,
                likely_spdx=result.spdx_id,
                browser_evidence=evidence,
                source_repo=result.source_repo,
                review_note="Machine-verifiable allow candidate awaiting human approval.",
            ),
            proposal,
        )

    human_candidate_spdx = (
        result.spdx_id
        if result.source_repo is not None
        and result.source_repo.provenance == "external_candidate"
        else None
    )
    return (
        _record(
            identity,
            outcome="pending_verifier_support",
            machine_verification="pending_verifier_support",
            lookups_attempted=attempted,
            likely_spdx=result.spdx_id,
            browser_evidence=evidence,
            human_candidate_spdx=human_candidate_spdx,
            source_repo=result.source_repo,
            review_note="Browser evidence found; verifier support pending.",
        ),
        None,
    )


def render_review_markdown(records: Sequence[EvidenceRecord]) -> str:
    """Render a compact review surface with one row per researched context."""

    counts: dict[str, int] = {}
    for record in records:
        counts[record.outcome] = counts.get(record.outcome, 0) + 1
    lines = [
        "# RepoLens Shortlist Research",
        "",
        "RepoLens research is deterministic and model-free. Machine verification status is "
        "separate from browser evidence.",
        "",
        "## Summary",
        "",
    ]
    if counts:
        for outcome in sorted(counts):
            lines.append(f"- {outcome}: {counts[outcome]}")
    else:
        lines.append("- no rows")
    lines.extend(
        [
            "",
            "## Rows",
            "",
            "| component_ref | outcome | machine verification | evidence or lookups | note |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for record in records:
        lines.append(
            "| "
            f"`{_escape_pipe(record.identity.component_ref)}` | "
            f"{record.outcome} | "
            f"{record.machine_verification} | "
            f"{_review_evidence_cell(record)} | "
            f"{_escape_pipe(record.review_note or record.rationale or '')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


@dataclass(frozen=True, slots=True)
class _Lookup:
    source: str
    label: str
    url: str
    machine_verifiable: bool
    ref: str | None = None
    display_url: str | None = None
    source_repo: SourceRepoEvidence | None = None


@dataclass(frozen=True, slots=True)
class _GitHubRepo:
    owner: str
    repo: str
    ref: str | None = None


@dataclass(frozen=True, slots=True)
class _SourceRepoIdentity:
    component_ref: str
    ecosystem: str | None
    package: str | None
    version: str | None
    source_repo_host: str
    owner: str
    repo: str
    acceptable_refs: tuple[str, ...]
    provenance: str
    provenance_detail: str
    ref: str | None = None
    ref_kind: str | None = None

    @property
    def bound_to_package(self) -> bool:
        return self.provenance == "package_metadata"

    def evidence(
        self,
        *,
        ref: str | None,
        fetch_url: str,
        display_url: str | None = None,
    ) -> SourceRepoEvidence:
        return SourceRepoEvidence(
            host=self.source_repo_host,
            owner=self.owner,
            repo=self.repo,
            ref=ref,
            ref_kind=_ref_kind(ref, self.version),
            provenance=self.provenance,
            provenance_detail=self.provenance_detail,
            bound_to_package=self.bound_to_package,
            fetch_url=fetch_url,
            display_url=display_url,
        )


def _lookup_urls(row: Mapping[str, Any], identity: EvidenceIdentity) -> tuple[_Lookup, ...]:
    package = identity.package
    version = identity.version or _UNKNOWN_VERSION
    ecosystem = (identity.ecosystem or "").casefold()
    urls: list[_Lookup] = []
    if package and ecosystem in {"python", "pypi"}:
        package_part = quote(package, safe="")
        if version != _UNKNOWN_VERSION:
            url = f"https://pypi.org/pypi/{package_part}/{quote(version, safe='')}/json"
        else:
            url = f"https://pypi.org/pypi/{package_part}/json"
        urls.append(_Lookup("pypi", _LOOKUP_LABELS["pypi"], url, True))
    clearly_defined_ecosystems = {"python", "pypi", "npm", "maven", "cargo"}
    if package and version != _UNKNOWN_VERSION and ecosystem in clearly_defined_ecosystems:
        source = "registry" if ecosystem != "golang" else "git"
        url = (
            "https://api.clearlydefined.io/definitions/"
            f"{source}/{quote(ecosystem, safe='')}/-/{quote(package, safe='')}/"
            f"{quote(version, safe='')}"
        )
        urls.append(_Lookup("clearlydefined", _LOOKUP_LABELS["clearlydefined"], url, True))
    if package and version != _UNKNOWN_VERSION and ecosystem in {"cocoapods", "pod"}:
        url = (
            "https://trunk.cocoapods.org/api/v1/pods/"
            f"{quote(package, safe='')}/specs/{quote(version, safe='')}"
        )
        urls.append(_Lookup("cocoapods", "podspec", url, True, ref=version))
    for source_repo in _source_repos_from_row(row, identity):
        urls.extend(_github_source_repo_lookups(source_repo))
    return tuple(dict.fromkeys(urls))


def _github_license_lookup(url: str | None, version: str) -> _Lookup | None:
    if url is None:
        return None
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname == "api.github.com" and len(parts) >= 4 and parts[:1] == ["repos"]:
        owner = quote(parts[1], safe="")
        repo = quote(parts[2], safe="")
        base = f"https://api.github.com/repos/{owner}/{repo}/license"
    elif parsed.hostname == "github.com" and len(parts) >= 2:
        owner = quote(parts[0], safe="")
        repo = quote(parts[1], safe="")
        base = f"https://api.github.com/repos/{owner}/{repo}/license"
    else:
        return None
    ref = None if version == _UNKNOWN_VERSION else version
    query = f"?{urlencode({'ref': ref})}" if ref is not None else ""
    return _Lookup(
        "github_license_api",
        "GitHub license API",
        f"{base}{query}",
        ref is not None,
        ref=ref,
    )


def _source_repos_from_row(
    row: Mapping[str, Any],
    identity: EvidenceIdentity,
) -> tuple[_SourceRepoIdentity, ...]:
    triage = row.get("triage") if isinstance(row.get("triage"), Mapping) else {}
    version = _clean_version(identity.version)
    trusted_values = (
        ("purl", _optional_text(row.get("purl"))),
        ("source_url", _optional_text(row.get("source_url"))),
        ("package", _optional_text(row.get("package"))),
    )
    repos: list[_SourceRepoIdentity] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for detail, value in trusted_values:
        repo = _github_repo_from_value(value, version, package_metadata=True)
        if repo is None:
            continue
        identity_repo = _source_identity(identity, repo, "package_metadata", detail, version)
        key = _source_key(identity_repo)
        if key not in seen:
            seen.add(key)
            repos.append(identity_repo)

    evidence_url = _optional_text(triage.get("evidence_url"))
    external_repo = _github_repo_from_value(evidence_url, version, package_metadata=False)
    if external_repo is not None:
        candidate = _source_identity(
            identity,
            external_repo,
            "external_candidate",
            "triage_evidence_url",
            version,
        )
        key = _source_key(candidate)
        if key not in seen:
            seen.add(key)
            repos.append(candidate)
    return tuple(repos)


def _source_identity(
    identity: EvidenceIdentity,
    repo: _GitHubRepo,
    provenance: str,
    provenance_detail: str,
    version: str | None,
) -> _SourceRepoIdentity:
    accepted_refs = _acceptable_refs(version, repo.ref, trusted=provenance == "package_metadata")
    ref = repo.ref if repo.ref in accepted_refs else None
    return _SourceRepoIdentity(
        component_ref=identity.component_ref,
        ecosystem=identity.ecosystem,
        package=identity.package,
        version=identity.version,
        source_repo_host=_GITHUB_HOST,
        owner=repo.owner,
        repo=repo.repo,
        acceptable_refs=accepted_refs,
        provenance=provenance,
        provenance_detail=provenance_detail,
        ref=ref,
        ref_kind=_ref_kind(ref, version),
    )


def _source_key(source_repo: _SourceRepoIdentity) -> tuple[str, str, tuple[str, ...]]:
    return (
        source_repo.owner.casefold(),
        source_repo.repo.casefold(),
        source_repo.acceptable_refs,
    )


def _github_repo_from_value(
    value: str | None,
    fallback_version: str | None,
    *,
    package_metadata: bool,
) -> _GitHubRepo | None:
    return (
        _github_repo_from_purl(value, fallback_version)
        or _github_repo_from_http_url(value, fallback_version, package_metadata=package_metadata)
        or _github_repo_from_package(value, fallback_version)
    )


def _github_repo_from_purl(value: str | None, fallback_version: str | None) -> _GitHubRepo | None:
    parsed = parse_purl(value)
    if parsed is None or parsed.package_type not in {"swift", "swiftpm"}:
        return None
    segments = [
        segment for segment in ((parsed.namespace or "").split("/") + [parsed.name]) if segment
    ]
    if len(segments) < 3 or segments[0].casefold() != _GITHUB_HOST:
        return None
    owner = _valid_segment(segments[1])
    repo = _valid_repo_segment(segments[2])
    if owner is None or repo is None:
        return None
    return _GitHubRepo(owner=owner, repo=repo, ref=_clean_ref(parsed.version or fallback_version))


def _github_repo_from_package(
    value: str | None,
    fallback_version: str | None,
) -> _GitHubRepo | None:
    if value is None:
        return None
    text = value.strip()
    if not text.startswith(f"{_GITHUB_HOST}/"):
        return None
    if any(char in text for char in "?#") or "\\" in text:
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) < 3 or parts[0].casefold() != _GITHUB_HOST:
        return None
    if any(part in {".", ".."} for part in parts[:3]):
        return None
    owner = _valid_segment(parts[1])
    repo = _valid_repo_segment(parts[2])
    if owner is None or repo is None:
        return None
    return _GitHubRepo(owner=owner, repo=repo, ref=_clean_ref(fallback_version))


def _github_repo_from_http_url(
    value: str | None,
    fallback_version: str | None,
    *,
    package_metadata: bool,
) -> _GitHubRepo | None:
    if value is None:
        return None
    text = value.strip()
    if text.startswith("git@github.com:"):
        suffix = text.removeprefix("git@github.com:")
        if "/" not in suffix or suffix.count("/") != 1:
            return None
        owner_text, repo_text = suffix.split("/", 1)
        owner = _valid_segment(owner_text)
        repo = _valid_repo_segment(repo_text)
        if owner is None or repo is None:
            return None
        return _GitHubRepo(owner=owner, repo=repo, ref=_clean_ref(fallback_version))
    if text.startswith(f"{_GITHUB_HOST}/"):
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    host = parsed.hostname.casefold()
    if host not in {_GITHUB_HOST, _GITHUB_API_HOST, _RAW_GITHUB_HOST}:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    if parsed.query and host != _GITHUB_API_HOST:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if host == _GITHUB_API_HOST:
        if len(parts) < 4 or parts[0] != "repos" or parts[3] != "license":
            return None
        owner_part, repo_part = parts[1], parts[2]
        ref = _clean_ref(_query_ref(parsed.query) or fallback_version)
    elif host == _RAW_GITHUB_HOST:
        if len(parts) < 4 or parts[3] not in _CONTROLLED_LICENSE_PATHS:
            return None
        owner_part, repo_part, ref = parts[0], parts[1], parts[2]
    else:
        if len(parts) < 2:
            return None
        owner_part, repo_part = parts[0], parts[1]
        ref = _clean_ref(fallback_version)
        if len(parts) > 2:
            if package_metadata and len(parts) == 3:
                pass
            elif (
                len(parts) == 5
                and parts[2] in {"blob", "tree"}
                and parts[4] in _CONTROLLED_LICENSE_PATHS
            ):
                if parts[3] in _MUTABLE_REFS:
                    return None
                ref = _clean_ref(parts[3])
            else:
                return None
    owner = _valid_segment(owner_part)
    repo = _valid_repo_segment(repo_part)
    if owner is None or repo is None:
        return None
    return _GitHubRepo(owner=owner, repo=repo, ref=ref)


def _query_ref(query: str) -> str | None:
    for part in query.split("&"):
        key, separator, value = part.partition("=")
        if separator and key == "ref":
            return value
    return None


def _github_source_repo_lookups(source_repo: _SourceRepoIdentity) -> tuple[_Lookup, ...]:
    lookups: list[_Lookup] = []
    refs = source_repo.acceptable_refs
    if refs:
        for ref in refs:
            api_url = _github_license_api_url(source_repo.owner, source_repo.repo, ref)
            lookups.append(
                _Lookup(
                    "github_license_api",
                    "GitHub license API",
                    api_url,
                    source_repo.provenance == "package_metadata",
                    ref=ref,
                    source_repo=source_repo.evidence(ref=ref, fetch_url=api_url),
                )
            )
        for ref in refs:
            for path in _CONTROLLED_LICENSE_PATHS:
                raw_url = (
                    f"https://{_RAW_GITHUB_HOST}/{quote(source_repo.owner, safe='')}/"
                    f"{quote(source_repo.repo, safe='')}/{quote(ref, safe='')}/{path}"
                )
                display_url = (
                    f"https://{_GITHUB_HOST}/{quote(source_repo.owner, safe='')}/"
                    f"{quote(source_repo.repo, safe='')}/blob/{quote(ref, safe='')}/{path}"
                )
                lookups.append(
                    _Lookup(
                        "github_raw_license",
                        "LICENSE",
                        raw_url,
                        False,
                        ref=ref,
                        display_url=display_url,
                        source_repo=source_repo.evidence(
                            ref=ref,
                            fetch_url=raw_url,
                            display_url=display_url,
                        ),
                    )
                )
    else:
        api_url = _github_license_api_url(source_repo.owner, source_repo.repo, None)
        lookups.append(
            _Lookup(
                "github_license_api",
                "GitHub license API",
                api_url,
                False,
                source_repo=source_repo.evidence(ref=None, fetch_url=api_url),
            )
        )
    return tuple(lookups)


def _github_license_api_url(owner: str, repo: str, ref: str | None) -> str:
    base = (
        f"https://{_GITHUB_API_HOST}/repos/"
        f"{quote(owner, safe='')}/{quote(repo, safe='')}/license"
    )
    if ref is None:
        return base
    return f"{base}?{urlencode({'ref': ref})}"


def _fetch_lookup(lookup: _Lookup, fetcher: FetchFunction) -> LookupResult | None:
    try:
        result = fetcher(lookup.url, _FETCH_OPTIONS)
    except FetchSecurityError:
        return None
    candidates = list(target_license_candidates(result.body))
    if lookup.source == "github_raw_license":
        candidates.extend(_raw_license_candidates(result.body))
    for license_text in tuple(dict.fromkeys(candidates)):
        spdx_id = license_resolution_id(license_text, load_default_policy())
        if spdx_id is None:
            continue
        return LookupResult(
            source=lookup.source,
            label=lookup.label,
            url=result.url,
            spdx_id=spdx_id,
            anchor=license_text,
            machine_verifiable=lookup.machine_verifiable,
            ref=lookup.ref,
            display_url=lookup.display_url,
            source_repo=lookup.source_repo,
        )
    return None


def _raw_license_candidates(body: bytes) -> tuple[str, ...]:
    text = body.decode("utf-8", errors="replace")
    normalized = " ".join(text.split()).casefold()
    if (
        normalized.startswith("mit license")
        and "permission is hereby granted" in normalized
        and "the software is provided" in normalized
    ):
        return ("MIT",)
    return ()


def _valid_segment(value: str) -> str | None:
    if not value or value in {".", ".."}:
        return None
    if value.strip() != value or not value.isascii() or not _SAFE_SEGMENT_RE.fullmatch(value):
        return None
    return value


def _valid_repo_segment(value: str) -> str | None:
    text = value[:-4] if value.endswith(".git") else value
    return _valid_segment(text)


def _clean_version(value: str | None) -> str | None:
    text = _clean_ref(value)
    if text is None or text.casefold() in {_UNKNOWN_VERSION, "declared-unpinned"}:
        return None
    return text


def _clean_ref(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text or not text.isascii():
        return None
    if any(char in text for char in "\\?#@") or "/" in text or ":" in text:
        return None
    if text in {".", ".."}:
        return None
    return text


def _acceptable_refs(
    version: str | None,
    source_ref: str | None,
    *,
    trusted: bool,
) -> tuple[str, ...]:
    refs: list[str] = []
    if version is not None and version.casefold() not in _MUTABLE_REFS:
        refs.extend(_bounded_version_refs(version))
    clean_source_ref = _clean_ref(source_ref)
    if trusted and clean_source_ref is not None and _SHA_RE.fullmatch(clean_source_ref):
        refs.append(clean_source_ref)
    return tuple(dict.fromkeys(refs))


def _bounded_version_refs(version: str) -> tuple[str, ...]:
    if version.startswith("v") and len(version) > 1:
        return (version, version[1:])
    return (version, f"v{version}")


def _ref_kind(ref: str | None, version: str | None) -> str | None:
    if ref is None:
        return None
    if _SHA_RE.fullmatch(ref):
        return "commit"
    if version is not None and ref in _bounded_version_refs(version):
        return "version"
    if ref.casefold() in _MUTABLE_REFS:
        return "default_branch"
    return "unknown"


def _record(
    identity: EvidenceIdentity,
    *,
    outcome: str,
    machine_verification: str,
    lookups_attempted: Sequence[str],
    likely_spdx: str | None = None,
    browser_evidence: Sequence[BrowserEvidence] = (),
    conflicts: Sequence[ConflictEvidence] = (),
    human_candidate_spdx: str | None = None,
    source_repo: SourceRepoEvidence | None = None,
    review_note: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        identity=identity,
        context_fingerprint=identity.context_fingerprint,
        outcome=outcome,
        machine_verification=machine_verification,
        lookups_attempted=tuple(dict.fromkeys(lookups_attempted)),
        likely_spdx=likely_spdx,
        human_candidate_spdx=human_candidate_spdx,
        confidence="high" if likely_spdx else None,
        browser_evidence=tuple(browser_evidence),
        conflicts=tuple(conflicts),
        source_repo=source_repo,
        rationale=review_note,
        review_note=review_note,
    )


def _proposal_for_result(identity: EvidenceIdentity, result: LookupResult) -> dict[str, Any]:
    proposal: dict[str, Any] = {
        "component_ref": identity.component_ref,
        "spdx_id": result.spdx_id,
        "evidence_url": result.url,
        "evidence_anchor": result.anchor,
        "disposition": "allow",
        "confidence": 0.9,
        "rationale": f"{result.label} anchors {result.spdx_id}.",
        "sanity_check": "Deterministic public metadata only; no model invocation.",
    }
    if result.source_repo is not None and result.source_repo.provenance == "package_metadata":
        proposal["evidence_kind"] = "github_source_repo"
        proposal["source_repo"] = {
            "host": result.source_repo.host,
            "owner": result.source_repo.owner,
            "repo": result.source_repo.repo,
            "ref": result.source_repo.ref,
            "ref_kind": result.source_repo.ref_kind,
            "provenance": result.source_repo.provenance,
            "provenance_detail": result.source_repo.provenance_detail,
            "bound_to_package": result.source_repo.bound_to_package,
        }
    return proposal


def _review_evidence_cell(record: EvidenceRecord) -> str:
    if record.browser_evidence:
        return ", ".join(
            f"[{_escape_pipe(entry.label)}]({_escape_pipe(entry.url)})"
            for entry in record.browser_evidence
        )
    if record.conflicts:
        return ", ".join(
            f"[{_escape_pipe(entry.label)}]({_escape_pipe(entry.url)}) "
            f"`{_escape_pipe(entry.spdx_id)}`"
            for entry in record.conflicts
        )
    if record.lookups_attempted:
        return "looked up: " + ", ".join(_escape_pipe(value) for value in record.lookups_attempted)
    return ""


def _escape_pipe(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = [
    "ResearchResult",
    "load_context_rows",
    "render_review_markdown",
    "research_context",
    "run_research",
]
