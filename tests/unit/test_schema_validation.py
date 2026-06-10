from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repolens.data.errors import SchemaValidationError
from repolens.data.validation import validate_artifact


@pytest.mark.parametrize(
    ("artifact", "fixture_name"),
    [
        ("sbom", "sbom"),
        ("resolved", "resolved_record"),
        ("inventory", "inventory"),
        ("shortlist", "shortlist"),
        ("shortlist_proposals", "shortlist_proposals"),
        ("shortlist_evidence", "shortlist_evidence"),
    ],
)
def test_valid_fixture_passes(
    request: pytest.FixtureRequest, artifact: str, fixture_name: str
) -> None:
    validate_artifact(request.getfixturevalue(fixture_name), artifact)


@pytest.mark.parametrize(
    ("artifact", "fixture_name", "field"),
    [
        ("sbom", "sbom", "repo"),
        ("resolved", "resolved_record", "repo"),
        ("inventory", "inventory", "components"),
        ("shortlist", "shortlist", "items"),
    ],
)
def test_missing_required_field_rejected(
    request: pytest.FixtureRequest, artifact: str, fixture_name: str, field: str
) -> None:
    value = copy.deepcopy(request.getfixturevalue(fixture_name))
    del value[field]

    with pytest.raises(SchemaValidationError, match=field):
        validate_artifact(value, artifact)


def test_wrong_type_rejected(sbom: dict[str, object]) -> None:
    sbom["artifacts"] = "not-an-array"

    with pytest.raises(SchemaValidationError, match="artifacts"):
        validate_artifact(sbom, "sbom")


def test_inventory_rejects_empty_version(inventory: dict[str, object]) -> None:
    components = inventory["components"]
    assert isinstance(components, list)
    components[0]["versions"] = [""]

    with pytest.raises(SchemaValidationError, match="versions"):
        validate_artifact(inventory, "inventory")


def test_sbom_allows_unversioned_artifact(sbom: dict[str, object]) -> None:
    artifacts = sbom["artifacts"]
    assert isinstance(artifacts, list)
    del artifacts[0]["version"]

    validate_artifact(sbom, "sbom")


def test_resolved_accepts_declared_unpinned_status(
    resolved_record: dict[str, object],
) -> None:
    resolved_record["version"] = "unknown"
    resolved_record["declared_version_status"] = "declared-unpinned"

    validate_artifact(resolved_record, "resolved")


def test_resolved_accepts_brief_description(
    resolved_record: dict[str, object],
) -> None:
    resolved_record["description"] = "Brief package summary"

    validate_artifact(resolved_record, "resolved")


def test_resolved_rejects_unknown_declared_version_status(
    resolved_record: dict[str, object],
) -> None:
    resolved_record["version"] = "unknown"
    resolved_record["declared_version_status"] = "not-a-known-status"

    with pytest.raises(SchemaValidationError, match="declared_version_status"):
        validate_artifact(resolved_record, "resolved")


def test_shortlist_open_count_must_match_open_items(shortlist: dict[str, object]) -> None:
    shortlist["open_count"] = 0

    with pytest.raises(SchemaValidationError, match="open_count"):
        validate_artifact(shortlist, "shortlist")


def test_shortlist_proposals_reject_unknown_fields(
    shortlist_proposals: list[dict[str, object]],
) -> None:
    shortlist_proposals[0]["unexpected"] = "drift"

    with pytest.raises(SchemaValidationError, match="unexpected"):
        validate_artifact(shortlist_proposals, "shortlist_proposals")


def test_shortlist_overrides_reject_unknown_fields() -> None:
    overrides = [
        {
            "component_ref": "zope.site|UNKNOWN",
            "spdx_id": "ZPL-2.1",
            "reason": "manual correction",
            "decided_by": "kjell",
            "unexpected": "drift",
        }
    ]

    with pytest.raises(SchemaValidationError, match="unexpected"):
        validate_artifact(overrides, "shortlist_overrides")


def test_shortlist_accepts_research_evidence_field(shortlist: dict[str, object]) -> None:
    items = shortlist["items"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    item["research_evidence"] = {
        "component_ref": item["component_ref"],
        "context_fingerprint": "abc123def456",
        "package": "acme-lib",
        "version": None,
        "ecosystem": None,
        "found_in": ["sentinel-alpha"],
        "outcome": "pending_verifier_support",
        "machine_verification": "pending_verifier_support",
        "lookups_attempted": ["PyPI metadata"],
        "likely_spdx": "MIT",
        "browser_evidence": [
            {
                "label": "PyPI metadata",
                "url": "https://pypi.org/pypi/acme-lib/1.2.3/json",
                "source_type": "pypi",
            }
        ],
    }

    validate_artifact(shortlist, "shortlist")


def test_presence_schema_copies_stay_identical(repo_root: Path) -> None:
    schema_dir = repo_root / "src" / "repolens" / "data" / "schemas"
    resolved = json.loads((schema_dir / "resolved.schema.json").read_text(encoding="utf-8"))
    inventory = json.loads((schema_dir / "inventory.schema.json").read_text(encoding="utf-8"))
    shortlist = json.loads((schema_dir / "shortlist.schema.json").read_text(encoding="utf-8"))

    assert (
        resolved["properties"]["presence"]
        == inventory["properties"]["components"]["items"]["properties"]["presence"]
    )
    assert (
        resolved["properties"]["presence"]
        == shortlist["properties"]["items"]["items"]["properties"]["presence"]
    )


def test_presence_blocks_are_valid_when_present(
    resolved_record: dict[str, object],
    inventory: dict[str, object],
    shortlist: dict[str, object],
) -> None:
    presence = {
        "install_state": "installed",
        "delivery_state": "not_scanned",
        "relation": "direct",
        "path": ["root", "acme-lib"],
        "platform_match": "unknown",
        "source": "syft",
        "target": "unknown",
        "reopen_on_delivery_change": True,
    }
    resolved_record["presence"] = presence
    components = inventory["components"]
    assert isinstance(components, list)
    components[0]["presence"] = presence
    items = shortlist["items"]
    assert isinstance(items, list)
    items[0]["presence"] = presence
    items[0]["presence_section"] = "INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW"

    validate_artifact(resolved_record, "resolved")
    validate_artifact(inventory, "inventory")
    validate_artifact(shortlist, "shortlist")
