"""Normalization tests for SPDX and non-SPDX inputs."""

from repolens.policy import classify_license_input, load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.policy.types import Action, PolicyTier


def test_normalize_canonical_and_alias_ids() -> None:
    policy = load_default_policy()

    mit = normalize_license("MIT", policy)
    apache_alias = normalize_license("apache 2.0", policy)

    assert mit.spdx_id == "MIT"
    assert mit.reason == "canonical_id"
    assert apache_alias.spdx_id == "Apache-2.0"
    assert apache_alias.reason == "alias_hit"


def test_deprecated_id_is_not_treated_as_normalized_spdx() -> None:
    policy = load_default_policy()
    normalized = normalize_license("GPL-2.0", policy)

    assert normalized.spdx_id is None
    assert normalized.reason == "deprecated_id"


def test_unknown_literals_and_empty_stay_unknown() -> None:
    policy = load_default_policy()
    for value in ("NOASSERTION", "NONE", "", "Proprietary", "Commercial", "TotallyCustom"):
        decision = classify_license_input(value, policy=policy)
        assert decision.tier == PolicyTier.UNKNOWN
        assert decision.effective_tier == PolicyTier.BLOCK
        assert decision.action == Action.FLAG_HARD


def test_non_spdx_nc_and_commons_clause_block() -> None:
    policy = load_default_policy()

    nc = classify_license_input("custom non-commercial usage license", policy=policy)
    commons = classify_license_input("MIT with Commons-Clause addendum", policy=policy)

    assert nc.tier == PolicyTier.BLOCK
    assert "non_spdx:NC" in nc.reasons
    assert commons.tier == PolicyTier.BLOCK
    assert "non_spdx:commons-clause" in commons.reasons


def test_valid_but_unrecognized_spdx_leaf_is_unknown() -> None:
    policy = load_default_policy()
    decision = classify_license_input("LicenseRef-NotInPolicy", policy=policy)

    assert decision.tier == PolicyTier.UNKNOWN
    assert decision.effective_tier == PolicyTier.BLOCK
