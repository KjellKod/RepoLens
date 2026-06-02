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
        "go",
        "jvm",
        "node",
        "python",
        "rust",
    }

    for fixture in manifest["fixtures"]:
        assert fixture["id"].startswith("acme_")
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
