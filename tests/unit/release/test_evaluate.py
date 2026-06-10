from __future__ import annotations

from repolens.policy.disclosure import load_default_disclosure_policy
from repolens.presence.models import Presence
from repolens.presence.sections import DELIVERED_SECTION, LOCKFILE_MONITOR_SECTION
from repolens.release.evaluate import evaluate_release
from repolens.shortlist.identity import build_decision_ref


def test_delivered_mit_passes() -> None:
    result = evaluate_release([_record("acme-mit", "MIT", _presence("delivered"))])

    assert result.result == "pass"
    assert len(result.delivered) == 1


def test_delivered_block_licenses_fail_release() -> None:
    result = evaluate_release(
        [
            _record("acme-gpl", "GPL-3.0-only", _presence("delivered")),
            _record(
                "acme-poly",
                "PolyForm-Noncommercial-1.0.0",
                _presence("delivered"),
            ),
        ]
    )

    assert result.result == "blocked"
    assert {blocker.code for blocker in result.blockers} == {"release_gate_block"}


def test_unknown_license_blocks() -> None:
    result = evaluate_release([_record("acme-weird", "WEIRD-1.0", _presence("delivered"))])

    assert result.result == "blocked"
    assert result.blockers[0].code == "unknown_license_action"


def test_unmapped_target_blocks_via_policy() -> None:
    result = evaluate_release(
        [_record("acme-mit", "MIT", _presence("delivered"))],
        target="desktop-app",
    )

    assert result.result == "blocked"
    assert result.blockers[0].code == "unknown_context"


def test_review_gate_requires_delivered_section_approval() -> None:
    component_ref = "acme-lgpl|LGPL-3.0-only"
    approved = build_decision_ref(component_ref, DELIVERED_SECTION)

    blocked = evaluate_release([_record("acme-lgpl", "LGPL-3.0-only", _presence("delivered"))])
    passed = evaluate_release(
        [_record("acme-lgpl", "LGPL-3.0-only", _presence("delivered"))],
        approved_decision_refs=frozenset({approved}),
    )

    assert blocked.result == "blocked"
    assert blocked.blockers[0].code == "release_gate_review_unapproved"
    assert passed.result == "pass"


def test_lockfile_section_approval_does_not_satisfy_delivered_review_gate() -> None:
    component_ref = "acme-lgpl|LGPL-3.0-only"
    wrong_section = build_decision_ref(component_ref, LOCKFILE_MONITOR_SECTION)

    result = evaluate_release(
        [_record("acme-lgpl", "LGPL-3.0-only", _presence("delivered"))],
        approved_decision_refs=frozenset({wrong_section}),
    )

    assert result.result == "blocked"


def test_lockfile_optional_lgpl_is_monitored_not_blocked() -> None:
    result = evaluate_release(
        [
            _record(
                "acme-native-optional",
                "LGPL-3.0-only",
                _presence("not_scanned", install_state="lockfile_only", relation="optional"),
            )
        ]
    )

    assert result.result == "pass"
    assert len(result.monitored) == 1
    assert result.delivered == ()


def test_not_scanned_count_warns_by_default() -> None:
    policy = load_default_disclosure_policy()

    result = evaluate_release(
        [_record("acme-mit", "MIT", _presence("not_scanned"))],
        disclosure_policy=policy,
    )

    assert result.result == "pass"
    assert len(result.not_scanned) == 1
    assert result.warnings


def _record(name: str, spdx_id: str, presence: dict[str, object]) -> dict[str, object]:
    return {
        "name": name,
        "version": "1.0.0",
        "repo": "acme-alpha",
        "purl": f"pkg:npm/{name}@1.0.0",
        "spdx_id": spdx_id,
        "evidence": {"source_layer": "syft"},
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "presence": presence,
        "modified": "unknown",
    }


def _presence(
    delivery_state: str,
    *,
    install_state: str = "installed",
    relation: str = "direct",
) -> dict[str, object]:
    return Presence(
        install_state=install_state,  # type: ignore[arg-type]
        delivery_state=delivery_state,  # type: ignore[arg-type]
        relation=relation,  # type: ignore[arg-type]
        source="syft",
    ).to_dict()
