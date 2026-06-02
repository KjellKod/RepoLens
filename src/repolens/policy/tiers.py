"""Tier mapping and action derivation."""

from __future__ import annotations

from repolens.policy.config import Policy
from repolens.policy.types import Action, PolicyTier

# Conservative ordering: UNKNOWN is treated as highest risk.
RISK_ORDER = {
    PolicyTier.ALLOW: 0,
    PolicyTier.REVIEW: 1,
    PolicyTier.BLOCK: 2,
    PolicyTier.UNKNOWN: 3,
}


def risk_rank(tier: PolicyTier) -> int:
    return RISK_ORDER[tier]


def choose_lower_risk(left: PolicyTier, right: PolicyTier) -> PolicyTier:
    return left if risk_rank(left) <= risk_rank(right) else right


def choose_higher_risk(left: PolicyTier, right: PolicyTier) -> PolicyTier:
    return left if risk_rank(left) >= risk_rank(right) else right


def map_license_to_tier(
    license_id: str | None,
    policy: Policy,
    *,
    exception_id: str | None = None,
) -> PolicyTier:
    if license_id is None:
        return PolicyTier.UNKNOWN

    if exception_id is not None:
        exact_key = (license_id, exception_id)
        if exact_key in policy.exception_tiers:
            return policy.exception_tiers[exact_key]
        fallback_key = (None, exception_id)
        if fallback_key in policy.exception_tiers:
            return policy.exception_tiers[fallback_key]
        return PolicyTier.UNKNOWN

    if license_id in policy.allow_ids:
        return PolicyTier.ALLOW
    if license_id in policy.review_ids:
        return PolicyTier.REVIEW
    if license_id in policy.block_ids:
        return PolicyTier.BLOCK

    if license_id.endswith("+"):
        plus_base = license_id[:-1]
        if plus_base in policy.block_ids:
            return PolicyTier.BLOCK
        maybe_or_later = f"{plus_base}-or-later"
        if maybe_or_later in policy.block_ids:
            return PolicyTier.BLOCK
        if maybe_or_later in policy.review_ids:
            return PolicyTier.REVIEW
        if maybe_or_later in policy.allow_ids:
            return PolicyTier.ALLOW

    return PolicyTier.UNKNOWN


def coerce_effective_tier(tier: PolicyTier, default_unknown_action: PolicyTier) -> PolicyTier:
    if tier == PolicyTier.UNKNOWN:
        return default_unknown_action
    return tier


def action_for_tier(tier: PolicyTier) -> Action:
    if tier == PolicyTier.ALLOW:
        return Action.PASS
    if tier == PolicyTier.REVIEW:
        return Action.FLAG
    return Action.FLAG_HARD


def caveats_for_license(license_id: str | None, policy: Policy) -> tuple[str, ...]:
    if not license_id:
        return tuple()

    caveats: list[str] = []
    if license_id.startswith("BUSL-"):
        note = policy.caveats.get("BUSL")
        if note:
            caveats.append(note)

    if license_id.startswith("LGPL-"):
        note = policy.caveats.get("LGPL")
        if note:
            caveats.append(note)

    return tuple(caveats)
