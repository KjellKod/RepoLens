"""Human license override loading, validation, and shortlist merge helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.data.limits import max_bytes_for
from repolens.data.validation import validate_artifact
from repolens.policy import PolicyTier, classify_license_input, load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.shortlist.contexts import ShortlistMetadata
from repolens.shortlist.evidence import EvidenceIdentity, _validate_direct_link, identity_for_item

HUMAN_OVERRIDE_OUTCOME = "human_override"
HUMAN_OVERRIDE_MACHINE_VERIFICATION = "human_override_unverified"
HUMAN_OVERRIDE_SOURCE_TYPE = "human_override"
DEFAULT_OVERRIDES_FILENAME = "shortlist.overrides.json"


@dataclass(frozen=True, slots=True)
class OverrideRecord:
    """One validated local human license override."""

    component_ref: str
    spdx_id: str
    reason: str
    decided_by: str
    evidence_url: str | None = None
    evidence_note: str | None = None
    expires_at: str | None = None
    policy_tier: PolicyTier = PolicyTier.UNKNOWN


def resolve_overrides_path(work_root: Path, path: Path) -> Path:
    """Resolve an override artifact path under ``work_root``.

    Overrides are local operator assertions. Keep the CLI contract anchored to the work
    root so a relative typo cannot silently ingest an artifact from another checkout.
    """

    raw_path = Path(path)
    if raw_path.is_absolute():
        raise SchemaValidationError("shortlist_overrides path must be relative to --work-root")
    candidate = (Path(work_root) / raw_path).resolve()
    root = Path(work_root).resolve()
    if candidate != root and root not in candidate.parents:
        raise SchemaValidationError("shortlist_overrides path must stay under --work-root")
    return candidate


def load_overrides(
    path: Path,
    *,
    items: Sequence[Mapping[str, Any]],
    today: date | None = None,
) -> tuple[OverrideRecord, ...]:
    """Read and validate a human override artifact against current shortlist items."""

    raw = store.load_json_capped(path, max_bytes=max_bytes_for("shortlist"))
    if not isinstance(raw, list):
        raise SchemaValidationError("shortlist_overrides: expected array")
    validate_artifact(raw, "shortlist_overrides")

    item_refs = {
        str(item.get("component_ref"))
        for item in items
        if isinstance(item, Mapping) and isinstance(item.get("component_ref"), str)
    }
    seen: set[str] = set()
    records: list[OverrideRecord] = []
    active_today = today or datetime.now(UTC).date()
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise SchemaValidationError(f"shortlist_overrides.{index}: expected object")
        record = _parse_override(entry, index, today=active_today)
        if record.component_ref in seen:
            raise SchemaValidationError(
                f"shortlist_overrides.{index}.component_ref: duplicate entry"
            )
        if record.component_ref not in item_refs:
            raise SchemaValidationError(
                f"shortlist_overrides.{index}.component_ref: does not match shortlist item"
            )
        seen.add(record.component_ref)
        records.append(record)
    return tuple(records)


def apply_overrides(
    items: Sequence[Mapping[str, Any]],
    overrides_path: Path,
    *,
    metadata: ShortlistMetadata | None = None,
    today: date | None = None,
) -> list[dict[str, Any]]:
    """Apply validated overrides without approving any item."""

    overrides = {
        record.component_ref: record
        for record in load_overrides(overrides_path, items=items, today=today)
    }
    updated: list[dict[str, Any]] = []
    for item in items:
        record = dict(item)
        override = overrides.get(str(record.get("component_ref")))
        if override is not None:
            identity = identity_for_item(record, metadata) if metadata is not None else None
            _apply_override(record, override, identity=identity)
        updated.append(record)
    return updated


def _parse_override(
    entry: Mapping[str, object],
    index: int,
    *,
    today: date,
) -> OverrideRecord:
    component_ref = _required_text(entry.get("component_ref"), index, "component_ref")
    spdx_raw = _required_text(entry.get("spdx_id"), index, "spdx_id")
    normalized_spdx, tier = _normalize_spdx(spdx_raw, index)
    reason = _required_text(entry.get("reason"), index, "reason")
    decided_by = _required_text(entry.get("decided_by"), index, "decided_by")
    evidence_url = _optional_text(entry.get("evidence_url"))
    evidence_note = _optional_text(entry.get("evidence_note"))
    if evidence_url is not None:
        _validate_direct_link(
            evidence_note or "Human override evidence",
            evidence_url,
            f"shortlist_overrides.{index}.evidence_url",
        )
    expires_at = _optional_text(entry.get("expires_at"))
    if expires_at is not None:
        _validate_expiry(expires_at, index, today=today)
    return OverrideRecord(
        component_ref=component_ref,
        spdx_id=normalized_spdx,
        evidence_url=evidence_url,
        evidence_note=evidence_note,
        reason=reason,
        decided_by=decided_by,
        expires_at=expires_at,
        policy_tier=tier,
    )


def _normalize_spdx(value: str, index: int) -> tuple[str, PolicyTier]:
    policy = load_default_policy()
    normalized = normalize_license(value, policy)
    if normalized.spdx_id is None:
        raise SchemaValidationError(f"shortlist_overrides.{index}.spdx_id: unsupported SPDX value")
    decision = classify_license_input(normalized.spdx_id, policy)
    if decision.tier == PolicyTier.UNKNOWN:
        raise SchemaValidationError(f"shortlist_overrides.{index}.spdx_id: unsupported SPDX value")
    return normalized.spdx_id, decision.tier


def _validate_expiry(value: str, index: int, *, today: date) -> None:
    try:
        expires = date.fromisoformat(value)
    except ValueError as exc:
        raise SchemaValidationError(
            f"shortlist_overrides.{index}.expires_at: expected YYYY-MM-DD"
        ) from exc
    if expires < today:
        raise SchemaValidationError(f"shortlist_overrides.{index}.expires_at: override is expired")


def _apply_override(
    record: dict[str, Any],
    override: OverrideRecord,
    *,
    identity: EvidenceIdentity | None,
) -> None:
    if record.get("status") in {"approved", "rejected"}:
        _reopen(record)

    record["candidate_spdx"] = override.spdx_id
    record["note"] = "human_override:awaiting_human_decision"
    record["research_evidence"] = _research_evidence_for_override(
        record,
        override,
        identity=identity,
    )


def _reopen(record: dict[str, Any]) -> None:
    record["status"] = "open"
    for field in ("decided_by", "decided_at"):
        record[field] = None
    for field in ("decided_via", "decision_provenance"):
        record.pop(field, None)


def _research_evidence_for_override(
    item: Mapping[str, Any],
    override: OverrideRecord,
    *,
    identity: EvidenceIdentity | None,
) -> dict[str, Any]:
    research: dict[str, Any] = {
        "component_ref": override.component_ref,
        "outcome": HUMAN_OVERRIDE_OUTCOME,
        "machine_verification": HUMAN_OVERRIDE_MACHINE_VERIFICATION,
        "likely_spdx": override.spdx_id,
        "human_candidate_spdx": override.spdx_id,
        "override_reason": override.reason,
        "override_decided_by": override.decided_by,
        "override_evidence_verified": False,
        "override_policy_tier": override.policy_tier.value,
    }
    if override.expires_at is not None:
        research["override_expires_at"] = override.expires_at

    if identity is not None:
        research["context_fingerprint"] = identity.context_fingerprint
        research["package"] = identity.package
        research["version"] = identity.version
        research["ecosystem"] = identity.ecosystem
        research["found_in"] = list(identity.found_in)
    else:
        prior = (
            item.get("research_evidence")
            if isinstance(item.get("research_evidence"), Mapping)
            else {}
        )
        found_in = prior.get("found_in")
        if isinstance(found_in, list):
            research["found_in"] = [str(value) for value in found_in if str(value).strip()]

    browser_evidence = _browser_evidence_for_override(override)
    if browser_evidence is not None:
        research["browser_evidence"] = [browser_evidence]
    if override.evidence_note is not None:
        research["review_note"] = override.evidence_note
    return research


def _browser_evidence_for_override(override: OverrideRecord) -> dict[str, Any] | None:
    if override.evidence_url is None:
        return None
    label = override.evidence_note or f"Human override evidence ({override.spdx_id})"
    return {
        "label": label,
        "url": override.evidence_url,
        "source_type": HUMAN_OVERRIDE_SOURCE_TYPE,
        "anchor": override.spdx_id,
    }


def _required_text(value: object, index: int, field: str) -> str:
    text = _optional_text(value)
    if text is None:
        raise SchemaValidationError(f"shortlist_overrides.{index}.{field}: required")
    return text


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


__all__ = [
    "DEFAULT_OVERRIDES_FILENAME",
    "HUMAN_OVERRIDE_MACHINE_VERIFICATION",
    "HUMAN_OVERRIDE_OUTCOME",
    "HUMAN_OVERRIDE_SOURCE_TYPE",
    "OverrideRecord",
    "apply_overrides",
    "load_overrides",
    "resolve_overrides_path",
]
