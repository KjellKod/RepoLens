"""Compound SPDX expression tests."""

from repolens.policy import classify_license_input, load_default_policy
from repolens.policy.expression import equivalent_expressions, pure_or_leaf_options
from repolens.policy.spdx import normalize_license
from repolens.policy.types import PolicyTier


def _normalize_leaf(raw: str) -> str | None:
    return normalize_license(raw, load_default_policy()).spdx_id


def test_apache_mit_or_uses_lower_risk_allow_tier() -> None:
    decision = classify_license_input("Apache-2.0 OR MIT", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "Apache-2.0"
    assert decision.dual_license_detected is True
    assert "compound_expression" in decision.reasons


def test_or_uses_lower_risk_and_records_branch() -> None:
    decision = classify_license_input("MIT OR GPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.dual_license_detected is True
    assert decision.caveats == ()


def test_and_uses_higher_risk() -> None:
    decision = classify_license_input("MIT AND GPL-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.BLOCK


def test_lowercase_compound_operators_are_parsed() -> None:
    decision = classify_license_input("mit or gpl-3.0-only", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.dual_license_detected is True


def test_or_with_restrictive_unknown_branch_chooses_lower_risk_branch() -> None:
    decision = classify_license_input("MIT OR non-commercial", policy=load_default_policy())

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.dual_license_detected is True


def test_nested_or_choice_survives_and_expression() -> None:
    decision = classify_license_input(
        "(MIT OR GPL-3.0-only) AND Apache-2.0",
        policy=load_default_policy(),
    )

    assert decision.tier == PolicyTier.ALLOW
    assert decision.chosen_branch == "MIT"
    assert decision.dual_license_detected is True


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


def test_apache_with_llvm_exception_uses_explicit_exception_table() -> None:
    decision = classify_license_input(
        "Apache-2.0 WITH LLVM-exception",
        policy=load_default_policy(),
    )

    assert decision.tier == PolicyTier.ALLOW
    assert decision.effective_tier == PolicyTier.ALLOW
    assert "compound_expression" in decision.reasons


def test_expression_equivalence_tolerates_or_operand_order() -> None:
    assert equivalent_expressions(
        "Apache-2.0 OR MIT",
        "MIT OR Apache-2.0",
        leaf_normalizer=_normalize_leaf,
    )


def test_pure_or_leaf_options_rejects_parenthesized_nested_or() -> None:
    assert pure_or_leaf_options("MIT OR Apache-2.0") == ("MIT", "Apache-2.0")
    assert pure_or_leaf_options("MIT OR (Apache-2.0 OR BSD-3-Clause)") is None


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

    assert decision.tier == PolicyTier.BLOCK
    assert decision.effective_tier == PolicyTier.BLOCK


def test_exception_override_does_not_apply_to_unlisted_block_license() -> None:
    decision = classify_license_input(
        "AGPL-3.0-only WITH Autoconf-exception-3.0",
        policy=load_default_policy(),
    )

    assert decision.tier == PolicyTier.UNKNOWN
    assert decision.effective_tier == PolicyTier.BLOCK


def test_llvm_exception_does_not_apply_to_unlisted_block_license() -> None:
    decision = classify_license_input(
        "GPL-3.0-only WITH LLVM-exception",
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
