"""Schema loading and validation for frozen F3 artifacts."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from repolens.data.errors import SchemaValidationError

SCHEMA_NAMES = frozenset(
    {
        "sbom",
        "resolved",
        "discovered",
        "inventory",
        "shortlist",
        "shortlist_proposals",
        "local_config",
    }
)


@lru_cache
def load_schema(artifact_name: str) -> dict[str, Any]:
    """Load a packaged, self-contained schema by artifact name."""

    if artifact_name not in SCHEMA_NAMES:
        raise ValueError(f"unknown artifact schema: {artifact_name}")
    schema_path = resources.files("repolens.data").joinpath(f"schemas/{artifact_name}.schema.json")
    value = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"schema {artifact_name} must be a JSON object")
    return value


@lru_cache
def _validator(artifact_name: str) -> Draft202012Validator:
    schema = load_schema(artifact_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_artifact(value: Any, artifact_name: str) -> None:
    """Validate ``value`` against a frozen schema."""

    validator = _validator(artifact_name)
    try:
        validator.validate(value)
    except ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path)
        prefix = f"{artifact_name}"
        if path:
            prefix = f"{prefix}.{path}"
        raise SchemaValidationError(f"{prefix}: {exc.message}") from exc
    if artifact_name == "discovered":
        _validate_discovered_counts(value)
    if artifact_name == "shortlist":
        _validate_shortlist_open_count(value)


def _validate_discovered_counts(value: Any) -> None:
    if not isinstance(value, dict):
        return
    repositories = value.get("repositories", [])
    if not isinstance(repositories, list):
        return
    candidate_count = sum(
        1 for item in repositories if isinstance(item, dict) and not item.get("hard_excluded")
    )
    hard_exclusion_count = sum(
        1 for item in repositories if isinstance(item, dict) and item.get("hard_excluded")
    )
    if value.get("repository_count") != len(repositories):
        raise SchemaValidationError("discovered.repository_count: must match repositories length")
    if value.get("candidate_count") != candidate_count:
        raise SchemaValidationError("discovered.candidate_count: must match candidate count")
    if value.get("hard_exclusion_count") != hard_exclusion_count:
        raise SchemaValidationError(
            "discovered.hard_exclusion_count: must match hard exclusion count"
        )


def _validate_shortlist_open_count(value: Any) -> None:
    if not isinstance(value, dict):
        return
    items = value.get("items", [])
    if not isinstance(items, list):
        return
    open_count = sum(1 for item in items if isinstance(item, dict) and item.get("status") == "open")
    if value.get("open_count") != open_count:
        raise SchemaValidationError("shortlist.open_count: must match open item count")
