"""Compound SPDX expression tests."""

from repolens.policy import classify_license_input, load_default_policy
from repolens.policy.types import PolicyTier


def test_or_uses_lower_risk_and_records_branch() -> None:
    decision = classify_license_input("MIT OR GPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.dual_license_detected is True
    assert decision.caveats == ()


def test_and_uses_higher_risk() -> None:
    decision = classify_license_input("MIT AND GPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.BLOCK


def test_or_does_not_leak_caveats_from_unchosen_branch() -> None:
    decision = classify_license_input("MIT OR LGPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.caveats == ()


def test_parentheses_precedence_and_determinism() -> None:
    expression = "MIT OR (GPL-3.0-only AND Apache-2.0)"
    first = classify_license_input(expression, policy=load_default_policy())
    second = classify_license_input(expression, policy=load_default_policy())

    assert first.tier == PolicyTier.ALLOW
    assert second.tier == first.tier
    assert second.chosen_branch == first.chosen_branch


def test_with_exception_downgrades_to_explicit_target_tier() -> None:
    classpath = classify_license_input(
        "GPL-2.0-only WITH Classpath-exception-2.0",
        policy=load_default_policy(),
    )
    autoconf = classify_license_input(
        "GPL-3.0-only WITH Autoconf-exception-3.0",
        policy=load_default_policy(),
    )

    assert classpath.tier == PolicyTier.REVIEW
    assert autoconf.tier == PolicyTier.ALLOW


def test_with_without_exception_match_is_unknown() -> None:
    decision = classify_license_input(
        "GPL-3.0-only WITH Unknown-exception",
        policy=load_default_policy(),
    )

    assert decision.tier == PolicyTier.UNKNOWN


def test_unknown_with_restrictive_exception_does_not_allow_base_tier() -> None:
    decision = classify_license_input(
        "MIT WITH Commons-Clause",
        policy=load_default_policy(),
    )

    assert decision.tier == PolicyTier.UNKNOWN
    assert decision.effective_tier == PolicyTier.BLOCK


def test_plus_suffix_is_supported_for_compound_paths() -> None:
    decision = classify_license_input("GPL-2.0+ OR MIT", policy=load_default_policy())
    assert decision.tier == PolicyTier.ALLOW


def test_malformed_expression_is_unknown() -> None:
    decision = classify_license_input("MIT OR (GPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.UNKNOWN
    assert "parse_error" in decision.reasons
