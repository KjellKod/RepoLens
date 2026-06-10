from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repolens.data.errors import SchemaValidationError
from repolens.data.validation import validate_artifact
from repolens.policy.config import load_default_policy
from repolens.policy.disclosure import (
    DisclosureActions,
    DisclosureBlocked,
    disclosure_policy_from_dict,
    evaluate_disclosure,
    load_default_disclosure_policy,
)


def test_loader_happy_path_and_mit_actions() -> None:
    policy = load_default_disclosure_policy()

    result = evaluate_disclosure("MIT", "delivered_distribution", policy)

    assert isinstance(result, DisclosureActions)
    assert result.public_notice == "not_required_by_default"
    assert result.bundled_notice == "required"
    assert result.release_gate == "pass"


def test_schema_rejects_missing_rationale() -> None:
    raw = _raw_policy()
    del raw["action_profiles"]["permissive_notice"]["delivered_distribution"]["rationale"]

    with pytest.raises(SchemaValidationError):
        validate_artifact(raw, "disclosure_policy")


def test_schema_rejects_unknown_top_level_key() -> None:
    raw = _raw_policy()
    raw["surprise"] = True

    with pytest.raises(SchemaValidationError):
        validate_artifact(raw, "disclosure_policy")


def test_unknown_license_blocks() -> None:
    result = evaluate_disclosure("WEIRD-1.0", "delivered_distribution")

    assert isinstance(result, DisclosureBlocked)
    assert result.reason_code == "unknown_license_action"


def test_known_license_unknown_context_blocks() -> None:
    result = evaluate_disclosure("MIT", "desktop_app")

    assert isinstance(result, DisclosureBlocked)
    assert result.reason_code == "unknown_context"


def test_or_uses_risk_chosen_branch_for_disclosure() -> None:
    result = evaluate_disclosure("(AFL-2.1 OR BSD-3-Clause)", "delivered_distribution")

    assert isinstance(result, DisclosureActions)
    assert result.release_gate == "pass"
    assert result.bundled_notice == "required"


def test_and_with_unmodeled_leaf_blocks() -> None:
    result = evaluate_disclosure("WEIRD-1.0 AND MIT", "delivered_distribution")

    assert isinstance(result, DisclosureBlocked)
    assert result.reason_code == "unknown_license_action"


def test_with_expression_resolves_exact_match() -> None:
    result = evaluate_disclosure(
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "delivered_distribution",
    )

    assert isinstance(result, DisclosureActions)
    assert result.release_gate == "review"


def test_parse_garbage_blocks() -> None:
    result = evaluate_disclosure("MIT AND", "delivered_distribution")

    assert isinstance(result, DisclosureBlocked)
    assert result.reason_code == "irreducible_expression"


def test_unknown_action_value_blocks() -> None:
    raw = _raw_policy()
    action = copy.deepcopy(raw["action_profiles"]["permissive_notice"])
    action["delivered_distribution"]["public_notice"] = "unknown"
    raw["entries"]["MIT"] = {"contexts": action}
    policy = disclosure_policy_from_dict(raw)

    result = evaluate_disclosure("MIT", "delivered_distribution", policy)

    assert isinstance(result, DisclosureBlocked)
    assert result.reason_code == "unknown_action_value"


def test_tier_policy_ids_and_exceptions_have_disclosure_entries_for_every_context() -> None:
    disclosure = load_default_disclosure_policy()
    tier = load_default_policy()
    expected = set(tier.allow_ids | tier.review_ids | tier.block_ids)
    expected.update(
        f"{license_id} WITH {exception_id}"
        for (license_id, exception_id) in tier.exception_tiers
        if license_id is not None
    )

    missing = sorted(expected.difference(disclosure.entries))
    assert missing == []
    for expression in sorted(expected):
        assert set(disclosure.entries[expression]) == set(disclosure.contexts)


def _raw_policy() -> dict[str, object]:
    path = Path("src/repolens/policy/data/disclosure-policy.default.json")
    return json.loads(path.read_text(encoding="utf-8"))
