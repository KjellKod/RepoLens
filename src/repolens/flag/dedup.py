"""Grouping, tag folds, and ``InventoryComponent`` construction for the flag stage.

The dedup group key is ``(name, spdx_key or "UNKNOWN")`` where ``spdx_key`` is strip-only
with a ``None`` guard — byte-for-byte the behavior of ``report._normalized_spdx``. This is
deliberate: do **not** add case-folding or SPDX canonicalization here, or the key would
diverge from the frozen dedup contract that P6b consolidation depends on (plan §5).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from repolens.data.models import InventoryComponent, Modified
from repolens.flag.tagging import fold_distribution, fold_modified, fold_origin, fold_scope
from repolens.policy import Policy, PolicyDecision, classify_license_input

_UNKNOWN = "UNKNOWN"
_NOASSERTION = "NOASSERTION"


@dataclass(frozen=True)
class CollectedRecord:
    """A resolved record plus the file context needed to build evidence refs."""

    data: dict[str, Any]
    repo_dir: str
    ordinal: int


@dataclass(frozen=True)
class GroupOutcome:
    """A deduplicated component plus its policy decision and shortlist material."""

    component: InventoryComponent
    decision: PolicyDecision
    component_ref: str
    candidate_spdx: str | None
    evidence: dict[str, str]
    reason_note: str


@dataclass
class _GroupAccumulator:
    name: str
    spdx_key: str
    records: list[CollectedRecord] = field(default_factory=list)


def build_group_outcomes(
    records: Iterable[CollectedRecord], policy: Policy
) -> list[GroupOutcome]:
    """Group records by ``(name, spdx_key or "UNKNOWN")`` and build one outcome per group."""

    groups: dict[tuple[str, str], _GroupAccumulator] = {}
    for record in records:
        name = str(record.data["name"])
        spdx_key = _spdx_key(record.data.get("spdx_id"))
        key = (name, spdx_key or _UNKNOWN)
        group = groups.setdefault(key, _GroupAccumulator(name=name, spdx_key=spdx_key))
        group.records.append(record)

    outcomes = [_build_outcome(group, policy) for group in groups.values()]
    return sorted(outcomes, key=_outcome_sort_key)


def _build_outcome(group: _GroupAccumulator, policy: Policy) -> GroupOutcome:
    # spdx_key is the empty string when the id was null, so the engine returns
    # tier=UNKNOWN (via normalize_license -> empty_input) — never the truthy "None".
    decision = classify_license_input(group.spdx_key, policy)
    group_license = group.spdx_key or _UNKNOWN

    versions = {str(record.data["version"]) for record in group.records}
    found_in = {str(record.data["repo"]) for record in group.records}
    evidence_refs = {
        f"{record.repo_dir}/resolved.ndjson:{record.ordinal}" for record in group.records
    }

    origins = [str(_tags(record)["origin"]) for record in group.records]
    scopes = [str(_tags(record)["scope"]) for record in group.records]
    distributions = [str(_tags(record)["distribution"]) for record in group.records]
    modified_values: list[Modified] = [
        _modified(record.data["modified"]) for record in group.records
    ]

    representative = min(group.records, key=_record_sort_key)
    evidence = _trim_evidence(representative.data["evidence"])
    source_url = _source_url(representative)

    component = InventoryComponent(
        name=group.name,
        license=group_license,
        origin=fold_origin(origins),
        scope=fold_scope(scopes),
        distribution=fold_distribution(distributions),
        versions=_sorted(versions),
        source_url=source_url,
        modified=fold_modified(modified_values),
        found_in=_sorted(found_in),
        policy_tier=decision.tier.value,
        evidence_refs=_sorted(evidence_refs),
    )

    candidate_spdx = group.spdx_key or None
    component_ref = f"{group.name}|{group_license}"
    reason_note = f"{decision.tier.value}: {'; '.join(decision.reasons)}"
    return GroupOutcome(
        component=component,
        decision=decision,
        component_ref=component_ref,
        candidate_spdx=candidate_spdx,
        evidence=evidence,
        reason_note=reason_note,
    )


def _spdx_key(value: object) -> str:
    """Strip-only normalization with a ``None`` guard (mirrors ``report._normalized_spdx``)."""

    return "" if value is None else str(value).strip()


def _tags(record: CollectedRecord) -> dict[str, Any]:
    return record.data["tags"]


def _modified(value: object) -> Modified:
    if value is True or value is False:
        return value
    return "unknown"


def _trim_evidence(evidence: dict[str, Any]) -> dict[str, str]:
    """Keep only the shortlist-schema-allowed evidence keys; drop ``fetched_at``."""

    trimmed = {"source_layer": str(evidence["source_layer"])}
    for key in ("url", "anchor"):
        value = evidence.get(key)
        if value is not None:
            trimmed[key] = str(value)
    return trimmed


def _source_url(record: CollectedRecord) -> str:
    """Fallback chain ``evidence.url -> purl -> "NOASSERTION"`` (first non-empty)."""

    url = _non_empty(record.data["evidence"].get("url"))
    if url is not None:
        return url
    purl = _non_empty(record.data.get("purl"))
    if purl is not None:
        return purl
    return _NOASSERTION


def _non_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _sorted(values: Iterable[str]) -> list[str]:
    return sorted(values, key=lambda value: (value.casefold(), value))


def _record_sort_key(record: CollectedRecord) -> tuple[str, str, int]:
    return (str(record.data["repo"]), str(record.data["version"]), record.ordinal)


def _outcome_sort_key(outcome: GroupOutcome) -> tuple[str, str, str, str]:
    name = outcome.component.name
    license_id = outcome.component.license
    return (name.casefold(), license_id.casefold(), name, license_id)
