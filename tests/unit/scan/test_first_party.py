"""Unit tests for first-party workspace-member detection (scan/first_party.py).

All cases write manifests under a ``tmp_path`` clone root and call the pure
detector directly — no clone, no Syft, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from repolens.scan.first_party import MAX_WORKSPACE_MEMBERS, collect_first_party_names


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_cargo_workspace_members_resolve_to_package_names(tmp_path: Path) -> None:
    # Virtual root manifest (no [package]); members via a glob and a direct path.
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["crates/*", "xtask"]\n',
    )
    _write(tmp_path / "crates" / "app" / "Cargo.toml", '[package]\nname = "diffly-app"\n')
    _write(tmp_path / "crates" / "core" / "Cargo.toml", '[package]\nname = "diffly-core"\n')
    _write(tmp_path / "xtask" / "Cargo.toml", '[package]\nname = "xtask"\n')

    assert collect_first_party_names(tmp_path) == ["diffly-app", "diffly-core", "xtask"]


def test_cargo_root_package_name_included_when_root_is_a_package(tmp_path: Path) -> None:
    _write(
        tmp_path / "Cargo.toml",
        '[package]\nname = "duck"\n\n[workspace]\nmembers = ["sub"]\n',
    )
    _write(tmp_path / "sub" / "Cargo.toml", '[package]\nname = "duck-sub"\n')

    assert collect_first_party_names(tmp_path) == ["duck", "duck-sub"]


def test_npm_workspaces_array_glob_resolves_to_names(tmp_path: Path) -> None:
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "doc2md", "workspaces": ["packages/*"]}),
    )
    _write(
        tmp_path / "packages" / "core" / "package.json",
        json.dumps({"name": "@doc2md/core"}),
    )
    _write(
        tmp_path / "packages" / "cli" / "package.json",
        json.dumps({"name": "doc2md-cli"}),
    )

    # Scoped names are preserved; the root name is included.
    assert collect_first_party_names(tmp_path) == ["@doc2md/core", "doc2md", "doc2md-cli"]


def test_npm_workspaces_object_packages_form_resolves_to_names(tmp_path: Path) -> None:
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "root-pkg", "workspaces": {"packages": ["libs/*"]}}),
    )
    _write(tmp_path / "libs" / "a" / "package.json", json.dumps({"name": "@scope/lib-a"}))

    assert collect_first_party_names(tmp_path) == ["@scope/lib-a", "root-pkg"]


def test_python_project_name_included(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", '[project]\nname = "repolens"\n')

    assert collect_first_party_names(tmp_path) == ["repolens"]


def test_no_workspace_manifests_yields_empty(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "nothing to see\n")

    assert collect_first_party_names(tmp_path) == []


def test_malformed_manifests_are_best_effort_and_never_raise(tmp_path: Path) -> None:
    _write(tmp_path / "Cargo.toml", "this is { not valid toml")
    _write(tmp_path / "package.json", "{ not json")
    _write(tmp_path / "pyproject.toml", "::: broken :::")

    assert collect_first_party_names(tmp_path) == []


def test_members_escaping_the_root_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    # A sibling package outside the clone root must never be treated first-party.
    _write(tmp_path / "outside" / "Cargo.toml", '[package]\nname = "evil-outside"\n')
    _write(
        root / "Cargo.toml",
        '[workspace]\nmembers = ["../outside", "inside"]\n',
    )
    _write(root / "inside" / "Cargo.toml", '[package]\nname = "good-inside"\n')

    assert collect_first_party_names(root) == ["good-inside"]


def test_member_count_is_capped(tmp_path: Path) -> None:
    _write(tmp_path / "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n')
    for index in range(MAX_WORKSPACE_MEMBERS + 5):
        _write(
            tmp_path / "crates" / f"c{index}" / "Cargo.toml",
            f'[package]\nname = "crate-{index}"\n',
        )

    # The cap bounds detection on a hostile/huge workspace; we never read all of them.
    assert len(collect_first_party_names(tmp_path)) <= MAX_WORKSPACE_MEMBERS
