"""Helpers for loading the synthetic fixture contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_FIXTURE_MANIFEST = Path("tests/fixtures/synthetic/fixture_manifest.json")


def load_fixture_manifest(path: str | Path = DEFAULT_FIXTURE_MANIFEST) -> dict[str, Any]:
    """Load a fixture manifest from a caller-provided path."""
    manifest_path = Path(path)
    with manifest_path.open(encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)

    if not isinstance(manifest, dict):
        msg = f"{manifest_path} must contain a JSON object"
        raise ValueError(msg)
    return manifest


def synthetic_fixture_root(manifest_path: str | Path = DEFAULT_FIXTURE_MANIFEST) -> Path:
    """Return the directory containing the synthetic fixture manifest."""
    return Path(manifest_path).resolve().parent
