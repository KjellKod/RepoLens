from __future__ import annotations

import copy

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


def test_shortlist_open_count_must_match_open_items(shortlist: dict[str, object]) -> None:
    shortlist["open_count"] = 0

    with pytest.raises(SchemaValidationError, match="open_count"):
        validate_artifact(shortlist, "shortlist")
