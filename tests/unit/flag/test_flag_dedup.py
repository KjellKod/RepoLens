from __future__ import annotations

from repolens.flag.dedup import build_group_outcomes
from repolens.policy import load_default_policy


def _outcomes(collected_records):
    return build_group_outcomes(collected_records, load_default_policy())


def test_groups_by_name_and_normalized_spdx(make_record, collected) -> None:
    records = collected(
        [
            make_record(name="acme-lib", spdx_id="MIT", version="1.0"),
            make_record(name="acme-lib", spdx_id=" MIT ", version="2.0"),
        ]
    )

    outcomes = _outcomes(records)

    assert len(outcomes) == 1
    assert outcomes[0].component.license == "MIT"
    assert outcomes[0].component.versions == ["1.0", "2.0"]


def test_unions_versions_and_found_in(make_record, collected) -> None:
    records = collected(
        [make_record(name="acme-lib", spdx_id="MIT", version="1.0", repo="acme-alpha")]
    ) + collected(
        [make_record(name="acme-lib", spdx_id="MIT", version="2.0", repo="acme-beta")],
        repo_dir="acme-beta",
    )

    outcomes = _outcomes(records)

    assert len(outcomes) == 1
    component = outcomes[0].component
    assert component.versions == ["1.0", "2.0"]
    assert component.found_in == ["acme-alpha", "acme-beta"]
    assert component.evidence_refs == [
        "acme-alpha/resolved.ndjson:1",
        "acme-beta/resolved.ndjson:1",
    ]


def test_separates_distinct_spdx(make_record, collected) -> None:
    records = collected(
        [
            make_record(name="acme-lib", spdx_id="MIT", version="1.0"),
            make_record(name="acme-lib", spdx_id="Apache-2.0", version="1.0"),
        ]
    )

    outcomes = _outcomes(records)

    assert {outcome.component.license for outcome in outcomes} == {"MIT", "Apache-2.0"}


def test_tier_is_stable_within_group(make_record, collected) -> None:
    # Two spdx_id=null records with different raw text land in one (name, "UNKNOWN") group
    # and classify to a single tier — classification is a pure function of the group key.
    records = collected(
        [
            make_record(name="acme-lib", spdx_id=None, declared_license_raw="AGPL-3.0-only"),
            make_record(name="acme-lib", spdx_id=None, declared_license_raw="MIT", version="2.0"),
        ]
    )

    outcomes = _outcomes(records)

    assert len(outcomes) == 1
    assert outcomes[0].component.policy_tier == "UNKNOWN"
    assert outcomes[0].decision.tier.value == "UNKNOWN"


def test_null_spdx_keys_unknown_not_none(make_record, collected) -> None:
    records = collected([make_record(name="acme-lib", spdx_id=None, anchor="NONE")])

    outcome = _outcomes(records)[0]

    assert outcome.component.license == "UNKNOWN"
    assert outcome.component_ref == "acme-lib|UNKNOWN"
    assert outcome.component_ref.endswith("|UNKNOWN")
    assert "None" not in outcome.component_ref
    assert outcome.candidate_spdx is None


def test_component_has_min_one_version_and_found_in(make_record, collected) -> None:
    outcome = _outcomes(collected([make_record()]))[0]

    assert len(outcome.component.versions) >= 1
    assert len(outcome.component.found_in) >= 1


def test_modified_fold(make_record, collected) -> None:
    any_true = collected(
        [
            make_record(version="1.0", modified=False),
            make_record(version="2.0", modified=True),
        ]
    )
    any_unknown = collected(
        [
            make_record(version="1.0", modified=False),
            make_record(version="2.0", modified="unknown"),
        ]
    )
    all_false = collected(
        [
            make_record(version="1.0", modified=False),
            make_record(version="2.0", modified=False),
        ]
    )

    assert _outcomes(any_true)[0].component.modified is True
    assert _outcomes(any_unknown)[0].component.modified == "unknown"
    assert _outcomes(all_false)[0].component.modified is False


def test_source_url_falls_back_to_purl_then_noassertion(make_record, collected) -> None:
    with_url = collected([make_record(url="https://example.invalid/a")])
    with_purl = collected([make_record(url=None, purl="pkg:pypi/acme-lib@1.2.3")])
    with_neither = collected([make_record(url=None, purl=None)])

    assert _outcomes(with_url)[0].component.source_url == "https://example.invalid/a"
    assert _outcomes(with_purl)[0].component.source_url == "pkg:pypi/acme-lib@1.2.3"
    assert _outcomes(with_neither)[0].component.source_url == "NOASSERTION"


def test_evidence_trimmed_drops_fetched_at(make_record, collected) -> None:
    outcome = _outcomes(collected([make_record()]))[0]

    assert "fetched_at" not in outcome.evidence
    assert set(outcome.evidence) <= {"source_layer", "url", "anchor"}
    assert outcome.evidence["source_layer"] == "syft"


def test_mixed_presence_same_component_survives_dedup_split(make_record, collected) -> None:
    records = collected(
        [
            make_record(
                name="sharp",
                spdx_id="LGPL-3.0-only",
                install_state="installed",
                delivery_state="not_scanned",
                relation="direct",
            ),
            make_record(
                name="sharp",
                spdx_id="LGPL-3.0-only",
                install_state="lockfile_only",
                delivery_state="not_scanned",
                relation="optional",
                version="1.0.1",
            ),
        ]
    )

    outcomes = _outcomes(records)

    assert len(outcomes) == 2
    sections = {
        outcome.component.presence.install_state: outcome.component.presence.relation
        for outcome in outcomes
        if outcome.component.presence is not None
    }
    assert sections == {"installed": "direct", "lockfile_only": "optional"}
