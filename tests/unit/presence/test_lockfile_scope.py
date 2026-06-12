"""Tests for lockfile-based delivery + declared-license signals."""

from __future__ import annotations

import json
from pathlib import Path

from repolens.presence.lockfile_scope import (
    load_lockfile_licenses,
    load_lockfile_scopes,
)


def _write_lockfile(tmp_path: Path, packages: dict[str, dict[str, object]]) -> Path:
    snapshot = tmp_path / "source.snapshot"
    snapshot.mkdir()
    (snapshot / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8"
    )
    return snapshot


def test_classifies_prod_dev_optional(tmp_path: Path) -> None:
    snapshot = _write_lockfile(
        tmp_path,
        {
            "": {"name": "root"},
            "node_modules/react": {"version": "19.0.0"},
            "node_modules/eslint": {"version": "9.0.0", "dev": True},
            "node_modules/@img/sharp-libvips-linux-x64": {
                "version": "1.2.0",
                "optional": True,
            },
            "node_modules/fsevents": {"version": "2.3.3", "devOptional": True},
        },
    )
    scopes = load_lockfile_scopes(snapshot)
    assert scopes["react"] == "prod"
    assert scopes["eslint"] == "dev"
    assert scopes["@img/sharp-libvips-linux-x64"] == "optional"
    assert scopes["fsevents"] == "devOptional"


def test_nested_and_scoped_names_resolve(tmp_path: Path) -> None:
    snapshot = _write_lockfile(
        tmp_path,
        {
            "node_modules/a/node_modules/@img/sharp": {"version": "0.34.0"},
        },
    )
    assert load_lockfile_scopes(snapshot) == {"@img/sharp": "prod"}


def test_production_observation_wins_over_dev(tmp_path: Path) -> None:
    # Same package hoisted as prod and nested as dev: production wins.
    snapshot = _write_lockfile(
        tmp_path,
        {
            "node_modules/dual": {"version": "1.0.0"},
            "node_modules/tool/node_modules/dual": {"version": "1.0.0", "dev": True},
        },
    )
    assert load_lockfile_scopes(snapshot)["dual"] == "prod"


def test_declared_licenses_extracted(tmp_path: Path) -> None:
    snapshot = _write_lockfile(
        tmp_path,
        {
            "node_modules/json-schema": {
                "version": "0.4.0",
                "license": "(AFL-2.1 OR BSD-3-Clause)",
            },
            "node_modules/no-license": {"version": "1.0.0"},
        },
    )
    licenses = load_lockfile_licenses(snapshot)
    assert licenses == {"json-schema": "(AFL-2.1 OR BSD-3-Clause)"}


def test_missing_lockfile_is_empty(tmp_path: Path) -> None:
    assert load_lockfile_scopes(tmp_path / "nope") == {}
    assert load_lockfile_licenses(tmp_path / "nope") == {}


def test_lockfile_v1_without_packages_is_empty(tmp_path: Path) -> None:
    snapshot = tmp_path / "source.snapshot"
    snapshot.mkdir()
    (snapshot / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 1, "dependencies": {"react": {}}}),
        encoding="utf-8",
    )
    assert load_lockfile_scopes(snapshot) == {}
