"""External proposal artifact parsing and verify-don't-trust ingestion."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.data.limits import max_bytes_for
from repolens.resolve.models import FetchFunction
from repolens.security.http_client import Resolver, fetch_url
from repolens.shortlist.agent import MAX_FETCHES_PER_ITEM, Resolution
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
        return {
            "component_ref": self.component_ref,
            "spdx_id": self.spdx_id,
            "evidence_url": self.evidence_url,
            "evidence_anchor": self.evidence_anchor,
            "disposition": self.disposition,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "sanity_check": self.sanity_check,
            "abstain": self.abstain,
            "reason": self.reason,
            "invalid_reason": self.invalid_reason,
        }


def load_proposals(path: Path) -> tuple[ProposalRecord, ...]:
    """Read an external proposal JSON array and return fail-closed typed records."""

    raw = store.load_json_capped(path, max_bytes=max_bytes_for("shortlist"))
    if not isinstance(raw, list):
        raise SchemaValidationError("proposal artifact must be a JSON array")
    records: list[ProposalRecord] = []
    for entry in raw:
        records.append(_parse_entry(entry))
    return tuple(records)


def apply_proposals(
    items: Sequence[Mapping[str, Any]],
    proposals_path: Path,
    *,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
) -> list[dict[str, Any]]:
    """Apply proposal metadata to matching open items after independent verification.

    Verified proposals record candidate evidence and AI-suggested metadata, but they do
    not approve or reject the item. Failed, abstained, malformed, and off-allowlist
    proposals leave the item open with an explicit fail-closed reason.
    """

    proposals = _group_by_ref(load_proposals(proposals_path))
    updated: list[dict[str, Any]] = []
    for item in items:
        record = dict(item)
        if record.get("status") == "open":
            _apply_item_proposals(
                record,
                proposals.get(str(record.get("component_ref")), ()),
                fetcher=fetcher,
                evidence_resolver=evidence_resolver,
            )
        updated.append(record)
    return updated


def _apply_item_proposals(
    record: dict[str, Any],
    proposals: Sequence[ProposalRecord],
    *,
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
        verified = verify_agent_resolution(
            Resolution(
                spdx_id=proposal.spdx_id,
                evidence_url=proposal.evidence_url,
                evidence_anchor=proposal.evidence_anchor,
            ),
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


def _group_by_ref(records: Sequence[ProposalRecord]) -> dict[str, tuple[ProposalRecord, ...]]:
    grouped: dict[str, list[ProposalRecord]] = {}
    for record in records:
        grouped.setdefault(record.component_ref, []).append(record)
    return {key: tuple(value) for key, value in grouped.items()}


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


__all__ = ["ProposalRecord", "apply_proposals", "load_proposals"]
