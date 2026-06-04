from __future__ import annotations

import json

import pytest

from repolens.testing.watermark import REQUIRED_COMPONENT_FIELDS, SCHEMA_VERSION, WATERMARK_ID

pytestmark = [pytest.mark.offline, pytest.mark.fixtures]


def test_fixture_manifest_contract(fixture_manifest_path):
    manifest = json.loads(fixture_manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["watermark_id"] == WATERMARK_ID
    assert manifest["synthetic_owner"] == "acme-synthetic-owner"
    assert {fixture["ecosystem"] for fixture in manifest["fixtures"]} == {
        "android",
        "go",
        "ios",
        "jvm",
        "node",
        "python",
        "rust",
    }

    for fixture in manifest["fixtures"]:
        if fixture["ecosystem"] in {"android", "ios"}:
            assert fixture["id"].startswith("sentinel_")
        else:
            assert fixture["id"]
        assert fixture["path"] == fixture["id"]
        assert fixture["expected_components"]
        for component in fixture["expected_components"]:
            assert REQUIRED_COMPONENT_FIELDS.issubset(component)


def test_fixture_manifest_paths_exist(fixture_manifest_path, synthetic_fixture_root):
    manifest = json.loads(fixture_manifest_path.read_text(encoding="utf-8"))

    missing_paths = [
        fixture["path"]
        for fixture in manifest["fixtures"]
        if not (synthetic_fixture_root / fixture["path"]).is_dir()
    ]

    assert missing_paths == []


def test_ios_fixture_includes_swiftpm_and_cocoapods_lockfiles(synthetic_fixture_root):
    fixture_root = synthetic_fixture_root / "sentinel_ios_client"

    assert (fixture_root / "Package.swift").is_file()
    assert (fixture_root / "Package.resolved").is_file()
    assert (fixture_root / "Podfile").is_file()
    assert (fixture_root / "Podfile.lock").is_file()


def test_android_fixture_includes_gradle_lockfile(synthetic_fixture_root):
    fixture_root = synthetic_fixture_root / "sentinel_android_app"

    lockfile = fixture_root / "gradle.lockfile"
    assert (fixture_root / "settings.gradle").is_file()
    assert (fixture_root / "build.gradle").is_file()
    assert lockfile.is_file()
    assert "invalid.sentinel:sentinel-android-runtime:3.1.4" in lockfile.read_text(encoding="utf-8")
