"""End-to-end policy engine tests."""

from repolens.policy import classify_license_input, load_default_policy
from repolens.policy.types import Action, PolicyTier


def test_classify_agpl_as_block() -> None:
    decision = classify_license_input("AGPL-3.0-only", policy=load_default_policy())
    assert decision.tier == PolicyTier.BLOCK


def test_classify_action_for_unknown_is_block() -> None:
    decision = classify_license_input("NOASSERTION", policy=load_default_policy())

    assert decision.tier == PolicyTier.UNKNOWN
    assert decision.effective_tier == PolicyTier.BLOCK
    assert decision.action == Action.FLAG_HARD


def test_busl_has_change_date_caveat() -> None:
    decision = classify_license_input("BUSL-1.1", policy=load_default_policy())
    assert decision.tier == PolicyTier.BLOCK
    assert any("Change Date" in note for note in decision.caveats)


def test_lgpl_has_linking_caveat() -> None:
    decision = classify_license_input("LGPL-3.0-only", policy=load_default_policy())
    assert decision.tier == PolicyTier.REVIEW
    assert any("static versus dynamic linking" in note for note in decision.caveats)


def test_legacy_plus_form_normalizes_before_tier_mapping() -> None:
    decision = classify_license_input("LGPL-3.0+", policy=load_default_policy())

    assert decision.tier == PolicyTier.REVIEW
    assert "legacy_plus" in decision.reasons
    assert any("static versus dynamic linking" in note for note in decision.caveats)


def test_policy_version_is_populated() -> None:
    decision = classify_license_input("MIT", policy=load_default_policy())
    assert decision.policy_version
    assert decision.dual_license_detected is False
