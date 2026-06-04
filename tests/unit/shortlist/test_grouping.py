from __future__ import annotations

from repolens.shortlist.contexts import ShortlistMetadata, TriageMetadata
from repolens.shortlist.grouping import (
    ACCEPT_RECOMMENDED,
    LOW_CONFIDENCE,
    NEEDS_JUDGMENT,
    build_groups,
    spdx_family,
)


def _item(component_ref: str, **overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "component_ref": component_ref,
        "reason": "REVIEW",
        "evidence": {"source_layer": "agent", "url": "https://api.deps.dev/x", "anchor": "MIT"},
        "candidate_spdx": "MIT",
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": "agent:verified_awaiting_human",
        "ai_suggestion": {"disposition": "allow", "confidence": 0.95},
    }
    item.update(overrides)
    return item


def _metadata(
    *,
    license_id: str = "MIT",
    distribution: str = "server",
    scope: str = "runtime",
) -> ShortlistMetadata:
    return ShortlistMetadata(
        triage_by_ref={
            f"acme-lib|{license_id}": TriageMetadata(
                spdx_id=license_id,
                tier="REVIEW",
                origin="third-party-oss",
                scope=scope,
                distribution=distribution,
                evidence_url="https://api.deps.dev/x",
                evidence_anchor=license_id,
                found_in=("acme-alpha",),
            )
        }
    )


def test_accept_recommended_requires_all_verified_low_risk_allow() -> None:
    groups = build_groups([_item("acme-lib|MIT")], _metadata(distribution="server"))

    assert len(groups) == 1
    assert groups[0].tier == ACCEPT_RECOMMENDED
    assert groups[0].bulk_decision


def test_conservative_demotes_mixed_or_failed_group() -> None:
    groups = build_groups(
        [
            _item("acme-lib|MIT", note="agent:verified_awaiting_human"),
            _item("acme-lib|MIT", note="verify_failed:verify:anchor_mismatch"),
        ],
        _metadata(distribution="server"),
    )

    assert groups[0].tier == LOW_CONFIDENCE
    assert not groups[0].bulk_decision


def test_block_distributed_never_accept_recommended() -> None:
    groups = build_groups(
        [
            _item(
                "acme-lib|GPL-3.0-only",
                candidate_spdx="GPL-3.0-only",
                reason="BLOCK",
            )
        ],
        _metadata(license_id="GPL-3.0-only", distribution="server"),
    )

    assert groups[0].tier == NEEDS_JUDGMENT
    assert not groups[0].bulk_decision


def test_non_allow_proposal_disposition_is_not_accept_recommended() -> None:
    groups = build_groups(
        [
            _item(
                "acme-lib|MIT",
                ai_suggestion={"disposition": "block", "confidence": 0.95},
            )
        ],
        _metadata(distribution="server"),
    )

    assert groups[0].tier == NEEDS_JUDGMENT
    assert not groups[0].bulk_decision


def test_stringified_low_confidence_is_low_confidence() -> None:
    groups = build_groups(
        [
            _item(
                "acme-lib|MIT",
                ai_suggestion={"disposition": "allow", "confidence": "0.42"},
            )
        ],
        _metadata(distribution="server"),
    )

    assert groups[0].tier == LOW_CONFIDENCE
    assert not groups[0].bulk_decision


def test_spdx_family_keeps_legally_distinct_families_apart() -> None:
    assert spdx_family("GPL-3.0-only") == "GPL-3.0"
    assert spdx_family("GPL-3.0-or-later") == "GPL-3.0"
    assert spdx_family("GPL-2.0-only") == "GPL-2.0"
    assert spdx_family("LGPL-3.0-only") == "LGPL-3.0"
    assert spdx_family("AGPL-3.0-only") == "AGPL-3.0"
    assert spdx_family("Apache-2.0") == "Apache"
