"""Offline canaries tied to F5 roadmap/security requirements."""

from repolens.policy import classify_license_input, load_default_policy
from repolens.policy.types import PolicyTier


def test_canary_agpl_is_blocked() -> None:
    decision = classify_license_input("AGPL-3.0-only", policy=load_default_policy())
    assert decision.tier == PolicyTier.BLOCK


def test_canary_missing_license_is_unknown_and_effective_block() -> None:
    decision = classify_license_input("", policy=load_default_policy())
    assert decision.tier == PolicyTier.UNKNOWN
    assert decision.effective_tier == PolicyTier.BLOCK


def test_canary_compound_is_deterministic() -> None:
    expression = "MIT OR (GPL-3.0-only AND Apache-2.0)"
    baseline = classify_license_input(expression, policy=load_default_policy())

    for _ in range(10):
        current = classify_license_input(expression, policy=load_default_policy())
        assert current.tier == baseline.tier
        assert current.chosen_branch == baseline.chosen_branch
        assert current.policy_version == baseline.policy_version


def test_canary_policy_version_is_present() -> None:
    decision = classify_license_input("BSD-3-Clause", policy=load_default_policy())
    assert decision.policy_version == "2026.06.05-mobile-metadata"
