from __future__ import annotations

from repolens.flag.dedup import build_group_outcomes
from repolens.policy import load_default_policy


def _outcome(collected_records):
    outcomes = build_group_outcomes(collected_records, load_default_policy())
    assert len(outcomes) == 1
    return outcomes[0]


def test_agpl_routes_block(make_record, collected) -> None:
    outcome = _outcome(collected([make_record(spdx_id="AGPL-3.0-only")]))

    assert outcome.decision.tier.value == "BLOCK"
    assert outcome.component.policy_tier == "BLOCK"


def test_null_spdx_routes_unknown(make_record, collected) -> None:
    # The empty string is exactly the classification input the dedup code uses for null ids.
    outcome = _outcome(collected([make_record(spdx_id=None)]))

    assert outcome.decision.tier.value == "UNKNOWN"
    # The coerced effective tier is BLOCK, but the queue must use decision.tier (R1).
    assert outcome.decision.effective_tier.value == "BLOCK"


def test_lgpl_or_mpl_routes_review(make_record, collected) -> None:
    lgpl = _outcome(collected([make_record(spdx_id="LGPL-3.0-only")]))
    mpl = _outcome(collected([make_record(spdx_id="MPL-2.0")]))

    assert lgpl.decision.tier.value == "REVIEW"
    assert mpl.decision.tier.value == "REVIEW"


def test_mit_not_flagged(make_record, collected) -> None:
    outcome = _outcome(collected([make_record(spdx_id="MIT")]))

    assert outcome.decision.tier.value == "ALLOW"


def test_compound_apache_mit_expression_routes_allow(make_record, collected) -> None:
    outcome = _outcome(collected([make_record(spdx_id="Apache-2.0 OR MIT")]))

    assert outcome.decision.tier.value == "ALLOW"
    assert outcome.component.policy_tier == "ALLOW"
    assert outcome.component.license == "Apache-2.0 OR MIT"
    assert "compound_expression" in outcome.reason_note


def test_stated_reason_text_present(make_record, collected) -> None:
    block = _outcome(collected([make_record(spdx_id="AGPL-3.0-only")]))
    unknown = _outcome(collected([make_record(spdx_id=None)]))

    assert block.reason_note == "BLOCK: canonical_id"
    assert "non_spdx_restrictive" not in block.reason_note
    assert unknown.reason_note == "UNKNOWN: empty_input"
