"""Synthetic fixture watermark canary."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.testing.fixtures import DEFAULT_FIXTURE_MANIFEST, load_fixture_manifest

WATERMARK_ID = "repolens-x1-synthetic-fixtures-v1"
SCHEMA_VERSION = 1
REQUIRED_COMPONENT_FIELDS = frozenset({"name", "version", "declared_license", "scope"})


@dataclass(frozen=True)
class WatermarkResult:
    """Structured result for fixture watermark checks."""

    ok: bool
    manifest_path: Path
    synthetic_owner: str | None
    watermark_id: str | None
    failures: tuple[str, ...]


def validate_fixture_watermark(
    manifest_path: str | Path = DEFAULT_FIXTURE_MANIFEST,
    *,
    runtime_owner_repo: str | None = None,
) -> WatermarkResult:
    """Validate synthetic fixture traceability without using runtime owner/repo input.

    ``runtime_owner_repo`` exists only to make isolation directly testable. The canary
    deliberately ignores it, and never reads owner or repository values from the
    environment, argv, or default runtime configuration.
    """
    del runtime_owner_repo

    path = Path(manifest_path)
    failures: list[str] = []
    manifest = load_fixture_manifest(path)

    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must equal {SCHEMA_VERSION}")

    watermark_id = manifest.get("watermark_id")
    if watermark_id != WATERMARK_ID:
        failures.append(f"watermark_id must equal {WATERMARK_ID}")

    synthetic_owner = manifest.get("synthetic_owner")
    if not isinstance(synthetic_owner, str) or not synthetic_owner:
        failures.append("synthetic_owner must be a non-empty string")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        failures.append("fixtures must be a non-empty list")
        fixtures = []

    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict):
            failures.append(f"fixtures[{index}] must be an object")
            continue

        fixture_id = _display_id(fixture, index)
        expected_components = fixture.get("expected_components")
        if not isinstance(expected_components, list) or not expected_components:
            failures.append(f"{fixture_id} must declare at least one expected component")
            continue

        for component_index, component in enumerate(expected_components):
            if not isinstance(component, dict):
                failures.append(
                    f"{fixture_id}.expected_components[{component_index}] must be an object"
                )
                continue

            missing = sorted(REQUIRED_COMPONENT_FIELDS.difference(component))
            if missing:
                joined = ", ".join(missing)
                failures.append(
                    f"{fixture_id}.expected_components[{component_index}] missing fields: {joined}"
                )

    return WatermarkResult(
        ok=not failures,
        manifest_path=path,
        synthetic_owner=synthetic_owner if isinstance(synthetic_owner, str) else None,
        watermark_id=watermark_id if isinstance(watermark_id, str) else None,
        failures=tuple(failures),
    )


def _display_id(fixture: dict[str, Any], index: int) -> str:
    fixture_id = fixture.get("id")
    if isinstance(fixture_id, str) and fixture_id:
        return fixture_id
    return f"fixtures[{index}]"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate synthetic fixture watermark metadata.")
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_FIXTURE_MANIFEST),
        help="Path to the synthetic fixture manifest.",
    )
    parser.add_argument(
        "--runtime-owner-repo",
        default=None,
        help="Ignored owner/repo-shaped input used by isolation canaries.",
    )
    args = parser.parse_args(argv)

    result = validate_fixture_watermark(
        args.manifest,
        runtime_owner_repo=args.runtime_owner_repo,
    )
    if result.ok:
        print(f"watermark ok: {result.watermark_id}")
        return 0

    for failure in result.failures:
        print(f"watermark failure: {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
