from __future__ import annotations

from repolens.data import store
from repolens.flag.dedup import build_group_outcomes
from repolens.flag.stage import run_flag
from repolens.policy import load_default_policy
from repolens.shortlist.render import render_shortlist_markdown


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


def test_build_not_distributed_stays_in_inventory_without_open_shortlist_item(
    tmp_path,
    make_record,
) -> None:
    store.write_resolved(
        tmp_path,
        "sentinel-ci",
        [
            make_record(
                name="sentinel-ci-action",
                spdx_id=None,
                declared_license_raw=None,
                scope="build",
                distribution="not-distributed",
                purl="pkg:githubactions/sentinel-ci-owner/sentinel-ci-action@v1",
            )
        ],
    )

    result = run_flag(tmp_path)

    inventory = store.read_inventory(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    assert result.component_count == 1
    assert inventory["components"][0]["name"] == "sentinel-ci-action"
    assert inventory["components"][0]["scope"] == "build"
    assert inventory["components"][0]["distribution"] == "not-distributed"
    assert shortlist["open_count"] == 0
    assert shortlist["items"] == []


def test_first_party_component_not_in_open_shortlist(tmp_path, make_record) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            # A first-party member with an UNKNOWN license must NOT produce a shortlist
            # item; an identical third-party UNKNOWN record still does.
            make_record(
                name="diffly-app",
                spdx_id=None,
                declared_license_raw=None,
                origin="first-party",
            ),
            make_record(
                name="third-party-lib",
                spdx_id=None,
                declared_license_raw=None,
                origin="third-party-oss",
            ),
        ],
    )

    run_flag(tmp_path)

    inventory = store.read_inventory(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    names = {component["name"] for component in inventory["components"]}
    # Both components stay in the inventory; only the third-party one is flagged.
    assert names == {"diffly-app", "third-party-lib"}
    item_refs = [item["component_ref"] for item in shortlist["items"]]
    assert item_refs == ["third-party-lib|UNKNOWN"]
    assert shortlist["open_count"] == 1


def test_mixed_runtime_and_build_group_remains_visible_for_review(make_record, collected) -> None:
    outcome = _outcome(
        collected(
            [
                make_record(spdx_id=None),
                make_record(spdx_id=None, scope="build", distribution="not-distributed"),
            ]
        )
    )

    assert outcome.component.scope == "unknown"
    assert outcome.component.distribution == "unknown"
    assert outcome.decision.tier.value == "UNKNOWN"


def test_flag_rerun_carries_forward_ingested_human_decisions(tmp_path, make_record) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="acme-unknown",
                spdx_id=None,
                declared_license_raw=None,
                url=None,
                anchor="unresolved:no_candidate",
            )
        ],
    )
    run_flag(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    item = dict(shortlist["items"][0])
    item["status"] = "approved"
    item["decided_by"] = "reviewer-sentinel"
    item["decided_at"] = "2026-06-05T12:00:00Z"
    item["decided_via"] = "item"
    store.write_shortlist(
        tmp_path,
        {
            **shortlist,
            "open_count": 0,
            "items": [item],
        },
    )

    result = run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    assert result.open_count == 0
    assert result.preserved_decision_count == 1
    assert rerun["open_count"] == 0
    assert rerun["items"][0]["component_ref"] == "acme-unknown|UNKNOWN"
    assert rerun["items"][0]["status"] == "approved"
    assert rerun["items"][0]["decided_by"] == "reviewer-sentinel"
    assert rerun["items"][0]["decided_at"] == "2026-06-05T12:00:00Z"


def test_flag_rerun_carries_forward_legacy_bare_ref_decision_for_non_delivered_row(
    tmp_path,
    make_record,
) -> None:
    record = make_record(
        name="copyleft-lib",
        spdx_id="GPL-3.0-only",
        scope="runtime",
        distribution="server",
    )
    record.pop("presence")
    store.write_resolved(tmp_path, "acme-alpha", [record])
    store.write_shortlist(
        tmp_path,
        {
            "schema_version": "1.0",
            "generated_at": "2026-06-05T12:00:00Z",
            "open_count": 0,
            "items": [
                {
                    "component_ref": "copyleft-lib|GPL-3.0-only",
                    "reason": "BLOCK",
                    "evidence": {"source_layer": "syft"},
                    "candidate_spdx": "GPL-3.0-only",
                    "status": "approved",
                    "decided_by": "reviewer-sentinel",
                    "decided_at": "2026-06-05T12:00:00Z",
                    "decided_via": "item",
                    "note": "legacy approval",
                }
            ],
        },
    )

    result = run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    item = rerun["items"][0]
    assert result.open_count == 0
    assert result.preserved_decision_count == 1
    assert item["component_ref"] == "copyleft-lib|GPL-3.0-only"
    assert item["decision_ref"] != item["component_ref"]
    assert item["status"] == "approved"
    assert item["decided_by"] == "reviewer-sentinel"
    assert item["note"] == "legacy approval"


def test_flag_rerun_ingests_pending_shortlist_markdown_ticks(
    tmp_path, make_record, monkeypatch
) -> None:
    monkeypatch.setattr(
        "repolens.shortlist.decisions.getpass.getuser",
        lambda: "reviewer-local",
    )
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="acme-unknown",
                spdx_id=None,
                declared_license_raw=None,
                url=None,
                anchor="unresolved:no_candidate",
            )
        ],
    )
    run_flag(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    markdown = render_shortlist_markdown(shortlist["items"]).replace(
        "- [ ] `acme-unknown|UNKNOWN`",
        "- [x] `acme-unknown|UNKNOWN`",
        1,
    )
    (tmp_path / "shortlist.md").write_text(markdown, encoding="utf-8")

    result = run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    assert result.preserved_decision_count == 1
    assert rerun["open_count"] == 0
    assert rerun["items"][0]["status"] == "approved"
    assert rerun["items"][0]["decided_by"] == "reviewer-local"
    assert rerun["items"][0]["decided_at"]
    rendered = (tmp_path / "shortlist.md").read_text(encoding="utf-8")
    assert "- [x] `acme-unknown|UNKNOWN`" in rendered
    assert "rpl:ref=" in rendered


def test_flag_writes_checkbox_shortlist_view(tmp_path, make_record) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="acme-unknown",
                spdx_id=None,
                declared_license_raw=None,
                url=None,
                anchor="unresolved:no_candidate",
            )
        ],
    )

    run_flag(tmp_path)

    rendered = (tmp_path / "shortlist.md").read_text(encoding="utf-8")
    assert "Tick an available group checkbox" in rendered
    assert "- [ ] `acme-unknown|UNKNOWN`" in rendered
    assert "rpl:ref=" in rendered
    assert "- `acme-unknown|UNKNOWN`" not in rendered


def test_flag_rerun_does_not_carry_decision_to_changed_component_ref(tmp_path, make_record) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="acme-lib",
                spdx_id=None,
                declared_license_raw=None,
                url=None,
                anchor="unresolved:no_candidate",
            )
        ],
    )
    run_flag(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    item = dict(shortlist["items"][0])
    item["status"] = "approved"
    item["decided_by"] = "reviewer-sentinel"
    item["decided_at"] = "2026-06-05T12:00:00Z"
    item["decided_via"] = "item"
    store.write_shortlist(tmp_path, {**shortlist, "open_count": 0, "items": [item]})
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [make_record(name="acme-lib", spdx_id="GPL-3.0-only", anchor="GPL-3.0-only")],
    )

    run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    assert rerun["open_count"] == 1
    assert rerun["items"][0]["component_ref"] == "acme-lib|GPL-3.0-only"
    assert rerun["items"][0]["status"] == "open"
    assert rerun["items"][0]["decided_by"] is None


def test_flag_rerun_reopens_approved_item_when_delivery_becomes_delivered(
    tmp_path,
    make_record,
) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                delivery_state="not_scanned",
            )
        ],
    )
    run_flag(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    item = dict(shortlist["items"][0])
    item["status"] = "approved"
    item["decided_by"] = "reviewer-sentinel"
    item["decided_at"] = "2026-06-05T12:00:00Z"
    item["decided_via"] = "item"
    store.write_shortlist(tmp_path, {**shortlist, "open_count": 0, "items": [item]})
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                delivery_state="delivered",
            )
        ],
    )

    result = run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    assert result.open_count == 1
    assert rerun["items"][0]["status"] == "open"
    assert rerun["items"][0]["decided_by"] is None
    assert rerun["items"][0]["presence_section"] == "DELIVERED / SHIPPED - ACTION REQUIRED"
    assert str(rerun["items"][0]["note"]).startswith("reopened:")


def test_flag_rerun_keeps_presence_split_decisions_independent(
    tmp_path,
    make_record,
) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                install_state="installed",
                delivery_state="not_scanned",
                relation="direct",
            ),
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                install_state="lockfile_only",
                delivery_state="not_scanned",
                relation="optional",
                version="2.0.0",
            ),
        ],
    )
    run_flag(tmp_path)
    shortlist = store.read_shortlist(tmp_path)
    approved_items = []
    for item in shortlist["items"]:
        approved = dict(item)
        approved["status"] = "approved"
        approved["decided_by"] = "reviewer-sentinel"
        approved["decided_at"] = "2026-06-05T12:00:00Z"
        approved["decided_via"] = "item"
        approved_items.append(approved)
    store.write_shortlist(tmp_path, {**shortlist, "open_count": 0, "items": approved_items})
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                install_state="installed",
                delivery_state="delivered",
                relation="direct",
            ),
            make_record(
                name="copyleft-lib",
                spdx_id="GPL-3.0-only",
                install_state="lockfile_only",
                delivery_state="not_scanned",
                relation="optional",
                version="2.0.0",
            ),
        ],
    )

    result = run_flag(tmp_path)

    rerun = store.read_shortlist(tmp_path)
    by_section = {str(item["presence_section"]): item for item in rerun["items"]}
    delivered = by_section["DELIVERED / SHIPPED - ACTION REQUIRED"]
    monitor = by_section["LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR"]
    assert result.open_count == 1
    assert delivered["component_ref"] == monitor["component_ref"] == "copyleft-lib|GPL-3.0-only"
    assert delivered["decision_ref"] != monitor["decision_ref"]
    assert delivered["status"] == "open"
    assert str(delivered["note"]).startswith("reopened:")
    assert monitor["status"] == "approved"
    assert monitor["decided_by"] == "reviewer-sentinel"
