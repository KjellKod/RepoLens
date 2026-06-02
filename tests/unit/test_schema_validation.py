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
