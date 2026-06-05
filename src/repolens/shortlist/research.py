"""Deterministic shortlist research artifact generation."""

from __future__ import annotations

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
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, fetch_url
from repolens.shortlist.evidence import (
    BrowserEvidence,
    ConflictEvidence,
    EvidenceIdentity,
    EvidenceRecord,
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
    "cocoapods": "CocoaPods podspec",
    "swiftpm": "SwiftPM tag license",
}


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

    def browser_evidence(self) -> BrowserEvidence:
        return BrowserEvidence(
            label=self.label,
            url=self.url,
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
                review_note="Machine-verifiable allow candidate awaiting human approval.",
            ),
            proposal,
        )

    return (
        _record(
            identity,
            outcome="pending_verifier_support",
            machine_verification="pending_verifier_support",
            lookups_attempted=attempted,
            likely_spdx=result.spdx_id,
            browser_evidence=evidence,
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


def _lookup_urls(row: Mapping[str, Any], identity: EvidenceIdentity) -> tuple[_Lookup, ...]:
    package = identity.package
    version = identity.version or _UNKNOWN_VERSION
    ecosystem = (identity.ecosystem or "").casefold()
    triage = row.get("triage") if isinstance(row.get("triage"), Mapping) else {}
    evidence_url = _optional_text(triage.get("evidence_url"))
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
    github_license = _github_license_lookup(evidence_url, version)
    if github_license is not None:
        urls.append(github_license)
    if ecosystem in {"swift", "swiftpm"} and evidence_url:
        swiftpm_lookup = _github_license_lookup(evidence_url, version)
        if swiftpm_lookup is not None:
            urls.append(
                _Lookup(
                    "swiftpm",
                    "LICENSE",
                    swiftpm_lookup.url,
                    swiftpm_lookup.machine_verifiable,
                    ref=swiftpm_lookup.ref,
                )
            )
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


def _fetch_lookup(lookup: _Lookup, fetcher: FetchFunction) -> LookupResult | None:
    try:
        result = fetcher(lookup.url, _FETCH_OPTIONS)
    except FetchSecurityError:
        return None
    for license_text in target_license_candidates(result.body):
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
        )
    return None


def _record(
    identity: EvidenceIdentity,
    *,
    outcome: str,
    machine_verification: str,
    lookups_attempted: Sequence[str],
    likely_spdx: str | None = None,
    browser_evidence: Sequence[BrowserEvidence] = (),
    conflicts: Sequence[ConflictEvidence] = (),
    review_note: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        identity=identity,
        context_fingerprint=identity.context_fingerprint,
        outcome=outcome,
        machine_verification=machine_verification,
        lookups_attempted=tuple(dict.fromkeys(lookups_attempted)),
        likely_spdx=likely_spdx,
        confidence="high" if likely_spdx else None,
        browser_evidence=tuple(browser_evidence),
        conflicts=tuple(conflicts),
        rationale=review_note,
        review_note=review_note,
    )


def _proposal_for_result(identity: EvidenceIdentity, result: LookupResult) -> dict[str, Any]:
    return {
        "component_ref": identity.component_ref,
        "spdx_id": result.spdx_id,
        "evidence_url": result.url,
        "evidence_anchor": result.anchor,
        "disposition": "allow",
        "confidence": 0.9,
        "rationale": f"{result.label} anchors {result.spdx_id}.",
        "sanity_check": "Deterministic public metadata only; no model invocation.",
    }


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
