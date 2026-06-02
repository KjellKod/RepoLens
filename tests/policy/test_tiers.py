"""Tier mapping and action mapping tests."""

from repolens.policy import load_default_policy
from repolens.policy.tiers import (
    action_for_tier,
    choose_higher_risk,
    choose_lower_risk,
    coerce_effective_tier,
    map_license_to_tier,
)
from repolens.policy.types import Action, PolicyTier


def test_representative_tier_mappings() -> None:
    policy = load_default_policy()

    assert map_license_to_tier("MIT", policy) == PolicyTier.ALLOW
    assert map_license_to_tier("MPL-2.0", policy) == PolicyTier.REVIEW
    assert map_license_to_tier("AGPL-3.0-only", policy) == PolicyTier.BLOCK
    assert map_license_to_tier("LicenseRef-Custom", policy) == PolicyTier.UNKNOWN


def test_unknown_is_highest_risk() -> None:
    assert choose_higher_risk(PolicyTier.BLOCK, PolicyTier.UNKNOWN) == PolicyTier.UNKNOWN
    assert choose_lower_risk(PolicyTier.UNKNOWN, PolicyTier.REVIEW) == PolicyTier.REVIEW


def test_unknown_coercion_and_action_mapping() -> None:
    effective = coerce_effective_tier(PolicyTier.UNKNOWN, PolicyTier.BLOCK)
    assert effective == PolicyTier.BLOCK
    assert action_for_tier(effective) == Action.FLAG_HARD
