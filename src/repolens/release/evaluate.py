"""Release disclosure gate evaluation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.policy.config import Policy, load_default_policy
from repolens.policy.disclosure import (
    DisclosureActions,
    DisclosureBlocked,
    DisclosurePolicy,
    context_for,
    evaluate_disclosure,
    load_default_disclosure_policy,
)
from repolens.policy.engine import classify_license_input
from repolens.policy.spdx import normalize_license
from repolens.presence.defaults import build_presence
from repolens.presence.models import DeliveryArtifact, Presence
from repolens.presence.sections import (
    DELIVERED_SECTION,
    LOCKFILE_MONITOR_SECTION,
    section_for_presence,
)
from repolens.shortlist.identity import build_decision_ref, decision_ref_for_item


@dataclass(frozen=True, slots=True)
class ReleaseBlocker:
    code: str
    message: str
    name: str = ""
    expression: str = ""
    context: str = ""


@dataclass(frozen=True, slots=True)
class ReleaseEntry:
    record: Mapping[str, Any]
    actions: DisclosureActions
    context: str
    tier: str
    chosen_branch: str | None


@dataclass(frozen=True, slots=True)
class ReleaseEvaluation:
    result: str
    delivered: tuple[ReleaseEntry, ...]
    blockers: tuple[ReleaseBlocker, ...]
    warnings: tuple[str, ...]
    monitored: tuple[Mapping[str, Any], ...]
    not_scanned: tuple[Mapping[str, Any], ...]
    policy_version: str
    disclosure_policy_version: str
    target: str | None = None
    artifact: DeliveryArtifact | None = None


def evaluate_release(
    records: Sequence[Mapping[str, Any]],
    *,
    disclosure_policy: DisclosurePolicy | None = None,
    tier_policy: Policy | None = None,
    approved_decision_refs: frozenset[str] = frozenset(),
    target: str | None = None,
    artifact: DeliveryArtifact | None = None,
) -> ReleaseEvaluation:
    active_disclosure = disclosure_policy or load_default_disclosure_policy()
    active_tier = tier_policy or load_default_policy()
    delivered: list[ReleaseEntry] = []
    blockers: list[ReleaseBlocker] = []
    warnings: list[str] = []
    monitored: list[Mapping[str, Any]] = []
    not_scanned: list[Mapping[str, Any]] = []

    if target:
        target_context = context_for(target, "delivered", active_disclosure)
        if isinstance(target_context, DisclosureBlocked):
            blockers.append(_blocker_from_disclosure(target_context, target=target))

    for record in records:
        presence = _presence_for_record(record)
        section = section_for_presence(presence)
        if section == DELIVERED_SECTION:
            entry = _evaluate_delivered_record(
                record,
                presence=presence,
                target=target,
                disclosure_policy=active_disclosure,
                tier_policy=active_tier,
                approved_decision_refs=approved_decision_refs,
            )
            if isinstance(entry, ReleaseBlocker):
                blockers.append(entry)
            else:
                delivered.append(entry)
        elif section == LOCKFILE_MONITOR_SECTION:
            monitored.append(record)
        else:
            not_scanned.append(record)

    if not_scanned:
        message = (
            f"{len(not_scanned)} dependency records have no delivered-artifact evidence "
            "for this release run"
        )
        if active_disclosure.unscanned_delivery_gate == "block":
            blockers.append(ReleaseBlocker("unscanned_delivery_block", message))
        else:
            warnings.append(message)

    return ReleaseEvaluation(
        result="blocked" if blockers else "pass",
        delivered=tuple(delivered),
        blockers=tuple(blockers),
        warnings=tuple(warnings),
        monitored=tuple(monitored),
        not_scanned=tuple(not_scanned),
        policy_version=active_tier.policy_version,
        disclosure_policy_version=active_disclosure.version,
        target=target,
        artifact=artifact,
    )


def load_approved_decision_refs(work_root: Path) -> frozenset[str]:
    shortlist_path = Path(work_root) / "shortlist.json"
    if not shortlist_path.exists():
        return frozenset()
    document = store.read_shortlist(work_root)
    refs: set[str] = set()
    raw_items = document.get("items", [])
    if not isinstance(raw_items, list):
        return frozenset()
    for item in raw_items:
        if isinstance(item, Mapping) and item.get("status") == "approved":
            refs.add(decision_ref_for_item(item))
    return frozenset(refs)


def _evaluate_delivered_record(
    record: Mapping[str, Any],
    *,
    presence: Presence,
    target: str | None,
    disclosure_policy: DisclosurePolicy,
    tier_policy: Policy,
    approved_decision_refs: frozenset[str],
) -> ReleaseEntry | ReleaseBlocker:
    expression = _expression_for_record(record)
    resolved_context = context_for(target, presence.delivery_state, disclosure_policy)
    if isinstance(resolved_context, DisclosureBlocked):
        return _blocker_from_disclosure(resolved_context, record=record)
    actions = evaluate_disclosure(expression, resolved_context, disclosure_policy, tier_policy)
    if isinstance(actions, DisclosureBlocked):
        return _blocker_from_disclosure(actions, record=record)

    decision = classify_license_input(expression, tier_policy)
    if actions.release_gate == "block":
        return ReleaseBlocker(
            code="release_gate_block",
            message=f"{_record_name(record)} is blocked for release by disclosure policy",
            name=_record_name(record),
            expression=expression,
            context=resolved_context,
        )
    if actions.release_gate == "review":
        decision_ref = build_decision_ref(_component_ref(record, tier_policy), DELIVERED_SECTION)
        if decision_ref not in approved_decision_refs:
            return ReleaseBlocker(
                code="release_gate_review_unapproved",
                message=(
                    f"{_record_name(record)} requires an approved delivered-section "
                    "shortlist decision before release"
                ),
                name=_record_name(record),
                expression=expression,
                context=resolved_context,
            )
    return ReleaseEntry(
        record=record,
        actions=actions,
        context=resolved_context,
        tier=decision.effective_tier.name,
        chosen_branch=decision.chosen_branch,
    )


def _presence_for_record(record: Mapping[str, Any]) -> Presence:
    presence = Presence.from_dict(record.get("presence"))
    if presence is not None:
        return presence
    tags = record.get("tags")
    return build_presence(
        tags=tags if isinstance(tags, Mapping) else None,
        source="syft",
    )


def _expression_for_record(record: Mapping[str, Any]) -> str:
    spdx = record.get("spdx_id")
    declared = record.get("declared_license_raw")
    return str(spdx if spdx is not None else declared if declared is not None else "UNKNOWN")


def _component_ref(record: Mapping[str, Any], policy: Policy) -> str:
    expression = _expression_for_record(record)
    normalized = normalize_license(expression, policy)
    spdx = normalized.spdx_id or expression
    return f"{_record_name(record)}|{spdx}"


def _record_name(record: Mapping[str, Any]) -> str:
    return str(record.get("name") or "unknown")


def _blocker_from_disclosure(
    blocked: DisclosureBlocked,
    *,
    record: Mapping[str, Any] | None = None,
    target: str | None = None,
) -> ReleaseBlocker:
    return ReleaseBlocker(
        code=blocked.reason_code,
        message=blocked.message,
        name=_record_name(record) if record is not None else "",
        expression=blocked.expression,
        context=blocked.context or (target or ""),
    )
