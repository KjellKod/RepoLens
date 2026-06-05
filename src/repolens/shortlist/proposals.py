"""External proposal artifact parsing and verify-don't-trust ingestion."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.data.limits import max_bytes_for
from repolens.resolve.models import FetchFunction
from repolens.resolve.purl import parse_purl
from repolens.security.http_client import Resolver, fetch_url
from repolens.shortlist.agent import MAX_FETCHES_PER_ITEM, Resolution
from repolens.shortlist.contexts import ShortlistMetadata, package_for_item
from repolens.shortlist.verify import verify_agent_resolution


@dataclass(frozen=True, slots=True)
class ProposalRecord:
    """One untrusted external proposal or abstention for a shortlist item."""

    component_ref: str
    spdx_id: str | None
    evidence_url: str | None
    evidence_anchor: str | None
    disposition: str | None
    confidence: str | int | float | None
    rationale: str | None
    sanity_check: str | None
    evidence_kind: str | None
    source_repo: Mapping[str, Any] | None
    abstain: bool
    reason: str | None
    invalid_reason: str | None = None

    @property
    def valid_resolution(self) -> bool:
        return (
            self.invalid_reason is None
            and not self.abstain
            and self.spdx_id is not None
            and self.evidence_url is not None
            and self.evidence_anchor is not None
        )

    def ai_suggestion(self) -> dict[str, Any]:
        source_repo = (
            dict(self.source_repo)
            if self.source_repo is not None
            and _optional_str(self.source_repo.get("provenance")) == "package_metadata"
            else None
        )
        return {
            "component_ref": self.component_ref,
            "spdx_id": self.spdx_id,
            "evidence_url": self.evidence_url,
            "evidence_anchor": self.evidence_anchor,
            "disposition": self.disposition,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "sanity_check": self.sanity_check,
            "evidence_kind": self.evidence_kind,
            "source_repo": source_repo,
            "abstain": self.abstain,
            "reason": self.reason,
            "invalid_reason": self.invalid_reason,
        }


@dataclass(frozen=True, slots=True)
class ProposalIngestSummary:
    """Structured proposal-ref summary for the current shortlist state."""

    total_records: int
    matched_open_refs: tuple[str, ...]
    skipped_missing_refs: tuple[str, ...]
    skipped_settled_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProposalApplyResult:
    """Updated items plus proposal-ingest diagnostics."""

    items: list[dict[str, Any]]
    summary: ProposalIngestSummary


def load_proposals(path: Path) -> tuple[ProposalRecord, ...]:
    """Read an external proposal JSON array and return fail-closed typed records."""

    raw = store.load_json_capped(path, max_bytes=max_bytes_for("shortlist"))
    if not isinstance(raw, list):
        raise SchemaValidationError("proposal artifact must be a JSON array")
    _validate_proposal_artifact_shape(raw)
    records: list[ProposalRecord] = []
    for entry in raw:
        records.append(_parse_entry(entry))
    return tuple(records)


def apply_proposals(
    items: Sequence[Mapping[str, Any]],
    proposals_path: Path,
    *,
    metadata: ShortlistMetadata | None = None,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
) -> list[dict[str, Any]]:
    """Apply proposals and return updated items.

    Use :func:`apply_proposals_with_summary` when callers need diagnostics about stale or
    already-settled proposal refs.
    """

    return apply_proposals_with_summary(
        items,
        proposals_path,
        metadata=metadata,
        fetcher=fetcher,
        evidence_resolver=evidence_resolver,
    ).items


def apply_proposals_with_summary(
    items: Sequence[Mapping[str, Any]],
    proposals_path: Path,
    *,
    metadata: ShortlistMetadata | None = None,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
) -> ProposalApplyResult:
    """Apply proposal metadata to matching open items after independent verification.

    Verified proposals record candidate evidence and AI-suggested metadata, but they do
    not approve or reject the item. Failed, abstained, malformed, and off-allowlist
    proposals leave the item open with an explicit fail-closed reason. Proposal refs that
    do not match current open rows are returned in the summary rather than silently
    disappearing from the operator workflow.
    """

    records = load_proposals(proposals_path)
    proposals = _group_by_ref(records)
    summary = _proposal_ingest_summary(items, proposals, total_records=len(records))
    updated: list[dict[str, Any]] = []
    for item in items:
        record = dict(item)
        if record.get("status") == "open":
            _apply_item_proposals(
                record,
                proposals.get(str(record.get("component_ref")), ()),
                metadata=metadata,
                fetcher=fetcher,
                evidence_resolver=evidence_resolver,
            )
        updated.append(record)
    return ProposalApplyResult(items=updated, summary=summary)


def _proposal_ingest_summary(
    items: Sequence[Mapping[str, Any]],
    proposals: Mapping[str, Sequence[ProposalRecord]],
    *,
    total_records: int,
) -> ProposalIngestSummary:
    open_refs: set[str] = set()
    settled_refs: set[str] = set()
    for item in items:
        component_ref = str(item.get("component_ref"))
        if item.get("status") == "open":
            open_refs.add(component_ref)
        else:
            settled_refs.add(component_ref)

    proposal_refs = set(proposals)
    current_refs = open_refs | settled_refs
    return ProposalIngestSummary(
        total_records=total_records,
        matched_open_refs=tuple(sorted(proposal_refs & open_refs)),
        skipped_missing_refs=tuple(sorted(proposal_refs - current_refs)),
        skipped_settled_refs=tuple(sorted(proposal_refs & (settled_refs - open_refs))),
    )


def _apply_item_proposals(
    record: dict[str, Any],
    proposals: Sequence[ProposalRecord],
    *,
    metadata: ShortlistMetadata | None,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
) -> None:
    for proposal in proposals[:MAX_FETCHES_PER_ITEM]:
        record["ai_suggestion"] = proposal.ai_suggestion()
        if proposal.abstain:
            record["note"] = "agent:abstained"
            record["verify_reason"] = "agent:abstained"
            return
        if not proposal.valid_resolution:
            reason = proposal.invalid_reason or "proposal:invalid"
            record["note"] = reason
            record["verify_reason"] = reason
            return

        assert proposal.spdx_id is not None
        assert proposal.evidence_url is not None
        assert proposal.evidence_anchor is not None
        source_repo_reason = _github_source_repo_proposal_mismatch(
            proposal,
            record,
            metadata,
        )
        if source_repo_reason is not None:
            record["note"] = f"verify_failed:{source_repo_reason}"
            record["verify_reason"] = source_repo_reason
            continue
        verified = verify_agent_resolution(
            Resolution(
                spdx_id=proposal.spdx_id,
                evidence_url=proposal.evidence_url,
                evidence_anchor=proposal.evidence_anchor,
            ),
            expected_ref=_expected_ref_for_item(record, metadata),
            fetcher=fetcher,
            resolver=evidence_resolver,
        )
        if not verified.verified:
            record["note"] = f"verify_failed:{verified.reason}"
            record["verify_reason"] = verified.reason
            continue

        record["candidate_spdx"] = verified.spdx_id
        evidence = dict(record.get("evidence") or {})
        evidence["source_layer"] = "agent"
        if verified.evidence_url:
            evidence["url"] = verified.evidence_url
        if verified.evidence_anchor:
            evidence["anchor"] = verified.evidence_anchor
        record["evidence"] = evidence
        record["note"] = "agent:verified_awaiting_human"
        record["verify_reason"] = verified.reason
        return

    if proposals:
        record.setdefault("verify_reason", "verify_failed:no_verified_proposal")
        record.setdefault("note", "verify_failed:no_verified_proposal")


def _expected_ref_for_item(
    record: Mapping[str, Any],
    metadata: ShortlistMetadata | None,
) -> str | None:
    if metadata is not None:
        package_metadata = package_for_item(record, metadata)
        if package_metadata.version is not None:
            return package_metadata.version
    version = record.get("version")
    if version is None:
        return None
    text = str(version).strip()
    return text or None


def _github_source_repo_proposal_mismatch(
    proposal: ProposalRecord,
    record: Mapping[str, Any],
    metadata: ShortlistMetadata | None,
) -> str | None:
    parsed = urlparse(proposal.evidence_url or "")
    if parsed.hostname != "api.github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[0] != "repos" or parts[3] != "license":
        return None
    if proposal.evidence_kind != "github_source_repo" or proposal.source_repo is None:
        return "verify:source_repo_provenance_required"
    source_repo = proposal.source_repo
    if _optional_str(source_repo.get("provenance")) != "package_metadata":
        return "verify:source_repo_provenance_required"
    if source_repo.get("bound_to_package") is not True:
        return "verify:source_repo_provenance_required"
    owner = _optional_str(source_repo.get("owner"))
    repo = _optional_str(source_repo.get("repo"))
    ref = _optional_str(source_repo.get("ref"))
    if owner is None or repo is None or ref is None:
        return "verify:source_repo_provenance_required"
    if parts[1] != owner or parts[2] != repo:
        return "verify:source_repo_mismatch"
    refs = [value.strip() for value in parse_qs(parsed.query).get("ref", []) if value.strip()]
    if not refs or refs[0] != ref:
        return "verify:source_repo_ref_mismatch"
    current = _current_package_source_repos(record, metadata)
    if (owner, repo) not in current:
        return "verify:source_repo_mismatch"
    expected_ref = _expected_ref_for_item(record, metadata)
    if not _proposal_ref_allowed(ref, expected_ref, current[(owner, repo)]):
        return "verify:source_repo_ref_mismatch"
    return None


def _current_package_source_repos(
    record: Mapping[str, Any],
    metadata: ShortlistMetadata | None,
) -> dict[tuple[str, str], set[str]]:
    if metadata is None:
        return {}
    package_metadata = package_for_item(record, metadata)
    refs: dict[tuple[str, str], set[str]] = {}
    for value in (package_metadata.purl, package_metadata.source_url, package_metadata.package):
        parsed = _github_repo_from_metadata(value)
        if parsed is None:
            continue
        owner, repo, ref = parsed
        refs.setdefault((owner, repo), set())
        if ref is not None:
            refs[(owner, repo)].add(ref)
    return refs


def _github_repo_from_metadata(value: str | None) -> tuple[str, str, str | None] | None:
    if not value:
        return None
    parsed_purl = parse_purl(value)
    if parsed_purl is not None and parsed_purl.package_type in {"swift", "swiftpm"}:
        segments = [
            segment
            for segment in ((parsed_purl.namespace or "").split("/") + [parsed_purl.name])
            if segment
        ]
        if len(segments) >= 3 and segments[0].casefold() == "github.com":
            return (segments[1], _strip_git(segments[2]), parsed_purl.version)
    text = value.strip()
    plain_github = text.startswith("github.com/")
    if text.startswith("github.com/"):
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.hostname not in {"github.com", "raw.githubusercontent.com"}:
        return None
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname == "raw.githubusercontent.com":
        if len(parts) != 4 or parts[3] not in _CONTROLLED_LICENSE_PATHS:
            return None
        owner, repo, ref = parts[0], _strip_git(parts[1]), parts[2]
    elif len(parts) == 2 or (plain_github and len(parts) == 3):
        owner, repo, ref = parts[0], _strip_git(parts[1]), None
    elif len(parts) == 5 and parts[2] in {"blob", "tree"} and parts[4] in _CONTROLLED_LICENSE_PATHS:
        owner, repo, ref = parts[0], _strip_git(parts[1]), parts[3]
    else:
        return None
    if (
        not _safe_segment(owner)
        or not _safe_segment(repo)
        or (ref is not None and not _safe_ref(ref))
    ):
        return None
    return (owner, repo, ref)


def _strip_git(value: str) -> str:
    return value[:-4] if value.endswith(".git") else value


_CONTROLLED_LICENSE_PATHS = frozenset(
    {"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md"}
)


def _safe_segment(value: str) -> bool:
    if not value or value in {".", ".."} or not value.isascii():
        return False
    return all(char.isalnum() or char in "._-" for char in value)


def _safe_ref(value: str) -> bool:
    if not value or value in {".", ".."} or not value.isascii():
        return False
    return not any(char in value for char in "/\\?#@:")


def _proposal_ref_allowed(ref: str, expected_ref: str | None, source_refs: set[str]) -> bool:
    if ref in source_refs and _is_sha(ref):
        return True
    if expected_ref is None:
        return False
    refs = {expected_ref}
    if expected_ref.startswith("v") and len(expected_ref) > 1:
        refs.add(expected_ref[1:])
    else:
        refs.add(f"v{expected_ref}")
    return ref in refs


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdefABCDEF" for char in value)


def _group_by_ref(records: Sequence[ProposalRecord]) -> dict[str, tuple[ProposalRecord, ...]]:
    grouped: dict[str, list[ProposalRecord]] = {}
    for record in records:
        grouped.setdefault(record.component_ref, []).append(record)
    return {key: tuple(value) for key, value in grouped.items()}


@lru_cache
def _proposal_schema_properties() -> dict[str, set[str]]:
    schema_path = resources.files("repolens.data").joinpath(
        "schemas/shortlist_proposals.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    items = schema.get("items", {})
    properties = items.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaValidationError("shortlist_proposals schema properties must be an object")
    parsed: dict[str, set[str]] = {}
    for field, spec in properties.items():
        if not isinstance(field, str) or not isinstance(spec, dict):
            continue
        raw_type = spec.get("type")
        if isinstance(raw_type, str):
            parsed[field] = {raw_type}
        elif isinstance(raw_type, list):
            parsed[field] = {item for item in raw_type if isinstance(item, str)}
    return parsed


def _validate_proposal_artifact_shape(raw: list[object]) -> None:
    properties = _proposal_schema_properties()
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise SchemaValidationError(f"shortlist_proposals.{index}: expected object")
        for field, value in entry.items():
            expected = properties.get(str(field))
            if expected is None:
                raise SchemaValidationError(
                    f"shortlist_proposals.{index}: unexpected field {field!r}"
                )
            if not _matches_schema_type(value, expected):
                expected_text = " or ".join(sorted(expected))
                raise SchemaValidationError(
                    f"shortlist_proposals.{index}.{field}: expected {expected_text}"
                )


def _matches_schema_type(value: object, expected: set[str]) -> bool:
    if "boolean" in expected and isinstance(value, bool):
        return True
    if "object" in expected and isinstance(value, Mapping):
        return True
    if "string" in expected and isinstance(value, str):
        return True
    return "number" in expected and isinstance(value, int | float) and not isinstance(value, bool)


def _parse_entry(entry: object) -> ProposalRecord:
    if not isinstance(entry, Mapping):
        return ProposalRecord(
            component_ref="",
            spdx_id=None,
            evidence_url=None,
            evidence_anchor=None,
            disposition=None,
            confidence=None,
            rationale=None,
            sanity_check=None,
            evidence_kind=None,
            source_repo=None,
            abstain=True,
            reason=None,
            invalid_reason="proposal:invalid_non_object",
        )

    component_ref = _required_str(entry, "component_ref")
    invalid_reason = None
    if component_ref is None or "|" not in component_ref:
        component_ref = component_ref or ""
        invalid_reason = "proposal:invalid_component_ref"

    abstain = bool(entry.get("abstain"))
    reason = _optional_str(entry.get("reason"))
    if abstain:
        return ProposalRecord(
            component_ref=component_ref,
            spdx_id=None,
            evidence_url=None,
            evidence_anchor=None,
            disposition=None,
            confidence=_confidence(entry.get("confidence")),
            rationale=_optional_str(entry.get("rationale")),
            sanity_check=_optional_str(entry.get("sanity_check")),
            evidence_kind=_optional_str(entry.get("evidence_kind")),
            source_repo=(
                entry.get("source_repo") if isinstance(entry.get("source_repo"), Mapping) else None
            ),
            abstain=True,
            reason=reason,
            invalid_reason=invalid_reason,
        )

    spdx_id = _required_str(entry, "spdx_id")
    evidence_url = _required_str(entry, "evidence_url")
    evidence_anchor = _required_str(entry, "evidence_anchor")
    disposition = _required_str(entry, "disposition")
    confidence = _confidence(entry.get("confidence"))
    rationale = _required_str(entry, "rationale")
    sanity_check = _required_str(entry, "sanity_check")
    evidence_kind = _optional_str(entry.get("evidence_kind"))
    source_repo = (
        entry.get("source_repo") if isinstance(entry.get("source_repo"), Mapping) else None
    )
    if invalid_reason is None:
        for field, value in (
            ("spdx_id", spdx_id),
            ("evidence_url", evidence_url),
            ("evidence_anchor", evidence_anchor),
            ("disposition", disposition),
            ("rationale", rationale),
            ("sanity_check", sanity_check),
        ):
            if value is None:
                invalid_reason = f"proposal:invalid_{field}"
                break
    if invalid_reason is None and confidence is None:
        invalid_reason = "proposal:invalid_confidence"

    return ProposalRecord(
        component_ref=component_ref,
        spdx_id=spdx_id,
        evidence_url=evidence_url,
        evidence_anchor=evidence_anchor,
        disposition=disposition,
        confidence=confidence,
        rationale=rationale,
        sanity_check=sanity_check,
        evidence_kind=evidence_kind,
        source_repo=source_repo,
        abstain=False,
        reason=reason,
        invalid_reason=invalid_reason,
    )


def _required_str(entry: Mapping[str, object], field: str) -> str | None:
    value = entry.get(field)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    return text or None


def _confidence(value: object) -> str | int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


__all__ = [
    "ProposalApplyResult",
    "ProposalIngestSummary",
    "ProposalRecord",
    "apply_proposals",
    "apply_proposals_with_summary",
    "load_proposals",
]
