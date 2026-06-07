"""Research evidence artifact loading, validation, and shortlist merge helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.data.limits import max_bytes_for
from repolens.data.validation import validate_artifact
from repolens.shortlist.contexts import ShortlistMetadata, package_for_item, triage_for_item

_HTTP_SCHEMES = frozenset({"http", "https"})
_PLACEHOLDER_LABELS = frozenset({"placeholder", "todo", "tbd", "link", "url"})
_PLACEHOLDER_HOSTS = frozenset({"example.com", "example.org", "example.net"})
_SEARCH_HOST_FRAGMENTS = ("google.", "bing.", "duckduckgo.", "search.yahoo.")
_EVIDENCE_OUTCOMES = frozenset(
    {
        "machine_verified",
        "pending_verifier_support",
        "no_public_evidence",
        "conflict",
        "legal_or_vendor_review",
    }
)
_SOURCE_REPO_PROVENANCE = frozenset({"package_metadata", "external_candidate"})
_SOURCE_REPO_REF_KINDS = frozenset({"version", "commit", "default_branch", "unknown"})


@dataclass(frozen=True, slots=True)
class BrowserEvidence:
    """One direct human-clickable evidence link."""

    label: str
    url: str
    source_type: str
    anchor: str | None = None
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "label": self.label,
            "url": self.url,
            "source_type": self.source_type,
        }
        if self.anchor is not None:
            value["anchor"] = self.anchor
        if self.ref is not None:
            value["ref"] = self.ref
        return value


@dataclass(frozen=True, slots=True)
class ConflictEvidence:
    """One conflicting evidence source."""

    spdx_id: str
    label: str
    url: str
    anchor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "spdx_id": self.spdx_id,
            "label": self.label,
            "url": self.url,
        }
        if self.anchor is not None:
            value["anchor"] = self.anchor
        return value


@dataclass(frozen=True, slots=True)
class SourceRepoEvidence:
    """Structured GitHub source-repo provenance for researched evidence."""

    host: str
    owner: str
    repo: str
    provenance: str
    provenance_detail: str
    bound_to_package: bool
    ref: str | None = None
    ref_kind: str | None = None
    fetch_url: str | None = None
    display_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "host": self.host,
            "owner": self.owner,
            "repo": self.repo,
            "provenance": self.provenance,
            "provenance_detail": self.provenance_detail,
            "bound_to_package": self.bound_to_package,
        }
        if self.ref is not None:
            value["ref"] = self.ref
        if self.ref_kind is not None:
            value["ref_kind"] = self.ref_kind
        if self.fetch_url is not None:
            value["fetch_url"] = self.fetch_url
        if self.display_url is not None:
            value["display_url"] = self.display_url
        return value


@dataclass(frozen=True, slots=True)
class EvidenceIdentity:
    """Stable facts used to prevent stale research rows from attaching."""

    component_ref: str
    package: str | None
    version: str | None
    ecosystem: str | None
    found_in: tuple[str, ...]

    @property
    def context_fingerprint(self) -> str:
        payload = {
            "component_ref": self.component_ref,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "found_in": list(self.found_in),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One validated evidence artifact row."""

    identity: EvidenceIdentity
    context_fingerprint: str
    outcome: str
    machine_verification: str
    lookups_attempted: tuple[str, ...]
    likely_spdx: str | None
    human_candidate_spdx: str | None
    confidence: str | int | float | None
    browser_evidence: tuple[BrowserEvidence, ...]
    conflicts: tuple[ConflictEvidence, ...]
    source_repo: SourceRepoEvidence | None
    rationale: str | None
    review_note: str | None

    def to_shortlist_metadata(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "component_ref": self.identity.component_ref,
            "context_fingerprint": self.context_fingerprint,
            "package": self.identity.package,
            "version": self.identity.version,
            "ecosystem": self.identity.ecosystem,
            "found_in": list(self.identity.found_in),
            "outcome": self.outcome,
            "machine_verification": self.machine_verification,
            "lookups_attempted": list(self.lookups_attempted),
        }
        if self.likely_spdx is not None:
            value["likely_spdx"] = self.likely_spdx
        if self.human_candidate_spdx is not None:
            value["human_candidate_spdx"] = self.human_candidate_spdx
        if self.confidence is not None:
            value["confidence"] = self.confidence
        if self.browser_evidence:
            value["browser_evidence"] = [entry.to_dict() for entry in self.browser_evidence]
        if self.conflicts:
            value["conflicts"] = [entry.to_dict() for entry in self.conflicts]
        if self.source_repo is not None:
            value["source_repo"] = self.source_repo.to_dict()
        if self.rationale is not None:
            value["rationale"] = self.rationale
        if self.review_note is not None:
            value["review_note"] = self.review_note
        return value


def load_evidence(path: Path) -> tuple[EvidenceRecord, ...]:
    """Read and validate a shortlist evidence artifact."""

    raw = store.load_json_capped(path, max_bytes=max_bytes_for("shortlist"))
    validate_artifact(raw, "shortlist_evidence")
    if not isinstance(raw, list):
        raise SchemaValidationError("shortlist_evidence: expected array")

    seen: set[tuple[str, str]] = set()
    records: list[EvidenceRecord] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise SchemaValidationError(f"shortlist_evidence.{index}: expected object")
        record = _parse_record(entry, index)
        key = (record.identity.component_ref, record.context_fingerprint)
        if key in seen:
            raise SchemaValidationError(f"shortlist_evidence.{index}: duplicate context identity")
        seen.add(key)
        records.append(record)
    return tuple(records)


def apply_evidence(
    items: Sequence[Mapping[str, Any]],
    evidence_path: Path,
    *,
    metadata: ShortlistMetadata,
) -> list[dict[str, Any]]:
    """Merge matching research evidence into open shortlist items without deciding them."""

    records = load_evidence(evidence_path)
    by_identity = {
        (record.identity.component_ref, record.context_fingerprint): record for record in records
    }
    updated: list[dict[str, Any]] = []
    for item in items:
        record = dict(item)
        if record.get("status") == "open":
            identity = identity_for_item(record, metadata)
            evidence = by_identity.get((identity.component_ref, identity.context_fingerprint))
            # Precedence invariant: a proposal that passed the verify-don't-trust closure is
            # authoritative. Its verifier-produced research_evidence (the
            # verify:exact_anchor[_default_branch] outcome) must not be overwritten by researched
            # evidence, whose stricter schema cannot re-express the verifier outcome. Stating
            # this here keeps correctness explicit rather than dependent on run_shortlist's
            # stage order. The guard is scoped to verifier-owned outcomes only, so an
            # evidence-ingested record stays refreshable by a newer evidence artifact.
            if evidence is not None and not _is_verifier_owned(record.get("research_evidence")):
                record["research_evidence"] = evidence.to_shortlist_metadata()
        updated.append(record)
    return updated


#: Outcomes produced exclusively by the proposals verifier (verify.py). Used to scope the
#: apply_evidence precedence guard so it protects verifier-owned blocks without freezing
#: evidence-ingested records (which may legitimately downgrade to conflict/no_public_evidence).
_VERIFIER_OWNED_OUTCOMES = frozenset({"verify:exact_anchor", "verify:exact_anchor_default_branch"})


def _is_verifier_owned(research_evidence: object) -> bool:
    return (
        isinstance(research_evidence, Mapping)
        and research_evidence.get("machine_verification") == "verified"
        and research_evidence.get("outcome") in _VERIFIER_OWNED_OUTCOMES
    )


def identity_for_item(item: Mapping[str, Any], metadata: ShortlistMetadata) -> EvidenceIdentity:
    """Build the current item identity from shortlist and inventory metadata."""

    component_ref = _required_text(item.get("component_ref"), "component_ref")
    triage = triage_for_item(item, metadata)
    package_metadata = package_for_item(item, metadata)
    return EvidenceIdentity(
        component_ref=component_ref,
        package=package_metadata.package,
        version=package_metadata.version,
        ecosystem=package_metadata.ecosystem,
        found_in=triage.found_in,
    )


def identity_for_context(row: Mapping[str, Any]) -> EvidenceIdentity:
    """Build the stable identity for an emitted context row."""

    component_ref = _required_text(row.get("component_ref"), "component_ref")
    package, _current_spdx = _split_component_ref(component_ref)
    triage = row.get("triage") if isinstance(row.get("triage"), Mapping) else {}
    found_in = _str_tuple(triage.get("found_in"))
    return EvidenceIdentity(
        component_ref=component_ref,
        package=_optional_text(row.get("package")) or package,
        version=_optional_text(row.get("version")),
        ecosystem=_optional_text(row.get("ecosystem") or row.get("package_type")),
        found_in=found_in,
    )


def _parse_record(entry: Mapping[str, object], index: int) -> EvidenceRecord:
    identity = EvidenceIdentity(
        component_ref=_required_text(entry.get("component_ref"), "component_ref"),
        package=_optional_text(entry.get("package")),
        version=_optional_text(entry.get("version")),
        ecosystem=_optional_text(entry.get("ecosystem")),
        found_in=_str_tuple(entry.get("found_in")),
    )
    fingerprint = _required_text(entry.get("context_fingerprint"), "context_fingerprint")
    if fingerprint != identity.context_fingerprint:
        raise SchemaValidationError(
            f"shortlist_evidence.{index}.context_fingerprint: does not match identity facts"
        )
    outcome = _required_text(entry.get("outcome"), "outcome")
    if outcome not in _EVIDENCE_OUTCOMES:
        raise SchemaValidationError(f"shortlist_evidence.{index}.outcome: unsupported value")
    machine_verification = _required_text(entry.get("machine_verification"), "machine_verification")
    lookups_attempted = _str_tuple(entry.get("lookups_attempted"))
    browser_evidence = tuple(
        _parse_browser_evidence(value, index)
        for value in _mapping_sequence(entry.get("browser_evidence"))
    )
    conflicts = tuple(
        _parse_conflict_evidence(value, index)
        for value in _mapping_sequence(entry.get("conflicts"))
    )
    record = EvidenceRecord(
        identity=identity,
        context_fingerprint=fingerprint,
        outcome=outcome,
        machine_verification=machine_verification,
        lookups_attempted=lookups_attempted,
        likely_spdx=_optional_text(entry.get("likely_spdx")),
        human_candidate_spdx=_optional_text(entry.get("human_candidate_spdx")),
        confidence=_confidence(entry.get("confidence")),
        browser_evidence=browser_evidence,
        conflicts=conflicts,
        source_repo=_parse_source_repo(entry.get("source_repo"), index),
        rationale=_optional_text(entry.get("rationale")),
        review_note=_optional_text(entry.get("review_note")),
    )
    _validate_outcome(record, index)
    return record


def _validate_outcome(record: EvidenceRecord, index: int) -> None:
    if record.outcome == "machine_verified":
        if record.machine_verification != "verified" or record.likely_spdx is None:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: machine_verified requires verified likely_spdx"
            )
        if not record.browser_evidence:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: machine_verified requires browser_evidence"
            )
    elif record.outcome == "pending_verifier_support":
        if record.machine_verification not in {
            "pending_verifier_support",
            "unsupported_evidence_source",
        }:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: pending outcome has wrong verifier status"
            )
        if record.likely_spdx is None or not record.browser_evidence:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: pending outcome requires likely_spdx and links"
            )
        if record.human_candidate_spdx is not None and not _is_external_candidate(record):
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: human candidate requires external source_repo"
            )
    elif record.outcome == "no_public_evidence":
        if record.machine_verification != "no_public_evidence" or not record.lookups_attempted:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: no_public_evidence requires lookup attempts"
            )
        if record.browser_evidence:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: no_public_evidence cannot include links"
            )
    elif record.outcome == "conflict":
        if record.machine_verification != "conflict" or len(record.conflicts) < 2:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: conflict requires conflicting URLs"
            )
    elif record.outcome == "legal_or_vendor_review":
        if record.machine_verification != "legal_or_vendor_review" or record.review_note is None:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: legal review requires review_note"
            )
        if not record.browser_evidence and not record.lookups_attempted:
            raise SchemaValidationError(
                f"shortlist_evidence.{index}: legal review requires links or lookups"
            )
    if (
        record.source_repo is not None
        and record.source_repo.provenance == "external_candidate"
        and record.source_repo.bound_to_package
    ):
        raise SchemaValidationError(
            f"shortlist_evidence.{index}: external candidate cannot be package-bound"
        )
    if (
        record.human_candidate_spdx is not None
        and record.likely_spdx != record.human_candidate_spdx
    ):
        raise SchemaValidationError(
            f"shortlist_evidence.{index}: human_candidate_spdx must match likely_spdx"
        )


def _parse_browser_evidence(value: Mapping[str, object], index: int) -> BrowserEvidence:
    label = _required_text(value.get("label"), "label")
    url = _required_text(value.get("url"), "url")
    _validate_direct_link(label, url, f"shortlist_evidence.{index}.browser_evidence")
    return BrowserEvidence(
        label=label,
        url=url,
        source_type=_required_text(value.get("source_type"), "source_type"),
        anchor=_optional_text(value.get("anchor")),
        ref=_optional_text(value.get("ref")),
    )


def _parse_conflict_evidence(value: Mapping[str, object], index: int) -> ConflictEvidence:
    label = _required_text(value.get("label"), "label")
    url = _required_text(value.get("url"), "url")
    _validate_direct_link(label, url, f"shortlist_evidence.{index}.conflicts")
    return ConflictEvidence(
        spdx_id=_required_text(value.get("spdx_id"), "spdx_id"),
        label=label,
        url=url,
        anchor=_optional_text(value.get("anchor")),
    )


def _parse_source_repo(value: object, index: int) -> SourceRepoEvidence | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise SchemaValidationError(f"shortlist_evidence.{index}.source_repo: expected object")
    host = _required_text(value.get("host"), "source_repo.host").casefold()
    if host != "github.com":
        raise SchemaValidationError(f"shortlist_evidence.{index}.source_repo.host: unsupported")
    provenance = _required_text(value.get("provenance"), "source_repo.provenance")
    if provenance not in _SOURCE_REPO_PROVENANCE:
        raise SchemaValidationError(
            f"shortlist_evidence.{index}.source_repo.provenance: unsupported"
        )
    ref_kind = _optional_text(value.get("ref_kind"))
    if ref_kind is not None and ref_kind not in _SOURCE_REPO_REF_KINDS:
        raise SchemaValidationError(f"shortlist_evidence.{index}.source_repo.ref_kind: unsupported")
    source_repo = SourceRepoEvidence(
        host=host,
        owner=_required_text(value.get("owner"), "source_repo.owner"),
        repo=_required_text(value.get("repo"), "source_repo.repo"),
        ref=_optional_text(value.get("ref")),
        ref_kind=ref_kind,
        provenance=provenance,
        provenance_detail=_required_text(
            value.get("provenance_detail"), "source_repo.provenance_detail"
        ),
        bound_to_package=bool(value.get("bound_to_package")),
        fetch_url=_optional_text(value.get("fetch_url")),
        display_url=_optional_text(value.get("display_url")),
    )
    if source_repo.fetch_url is not None:
        _validate_direct_link("fetch_url", source_repo.fetch_url, "source_repo.fetch_url")
    if source_repo.display_url is not None:
        _validate_direct_link("display_url", source_repo.display_url, "source_repo.display_url")
    return source_repo


def _is_external_candidate(record: EvidenceRecord) -> bool:
    return (
        record.source_repo is not None
        and record.source_repo.provenance == "external_candidate"
        and not record.source_repo.bound_to_package
    )


def _validate_direct_link(label: str, url: str, prefix: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.netloc:
        raise SchemaValidationError(f"{prefix}: evidence URL must be direct HTTP(S)")
    host = parsed.hostname or ""
    if host.casefold() in _PLACEHOLDER_HOSTS or any(
        part in host for part in _SEARCH_HOST_FRAGMENTS
    ):
        raise SchemaValidationError(f"{prefix}: placeholder or search-result URL rejected")
    normalized_label = label.strip().casefold()
    if not normalized_label or normalized_label in _PLACEHOLDER_LABELS:
        raise SchemaValidationError(f"{prefix}: evidence label must be meaningful")


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _required_text(value: object, field: str) -> str:
    text = _optional_text(value)
    if text is None:
        raise SchemaValidationError(f"shortlist_evidence.{field}: required")
    return text


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted(str(item).strip() for item in value if str(item).strip()))


def _split_component_ref(component_ref: str) -> tuple[str | None, str | None]:
    name, separator, spdx_id = component_ref.rpartition("|")
    if not separator:
        return (_optional_text(component_ref), None)
    return (_optional_text(name), _optional_text(spdx_id))


def _confidence(value: object) -> str | int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    return _optional_text(value)


__all__ = [
    "BrowserEvidence",
    "ConflictEvidence",
    "EvidenceIdentity",
    "EvidenceRecord",
    "SourceRepoEvidence",
    "apply_evidence",
    "identity_for_context",
    "identity_for_item",
    "load_evidence",
]
