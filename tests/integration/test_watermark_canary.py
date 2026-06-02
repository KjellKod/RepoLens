from __future__ import annotations

import json

import pytest

from repolens.testing.watermark import WATERMARK_ID, validate_fixture_watermark

pytestmark = [pytest.mark.offline, pytest.mark.security]

RUNTIME_OWNER_REPO = "input-scope/input-target"


def test_watermark_canary_accepts_synthetic_fixture_manifest(fixture_manifest_path):
    result = validate_fixture_watermark(fixture_manifest_path)

    assert result.ok
    assert result.synthetic_owner == "acme-synthetic-owner"
    assert result.watermark_id == WATERMARK_ID
    assert result.failures == ()


def test_watermark_canary_fails_when_watermark_removed(fixture_manifest_path, tmp_path):
    manifest = json.loads(fixture_manifest_path.read_text(encoding="utf-8"))
    manifest.pop("watermark_id")
    mutated_manifest_path = tmp_path / "fixture_manifest.json"
    mutated_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_fixture_watermark(mutated_manifest_path)

    assert not result.ok
    assert result.failures == (f"watermark_id must equal {WATERMARK_ID}",)


def test_watermark_canary_fails_when_expected_components_empty(fixture_manifest_path, tmp_path):
    manifest = json.loads(fixture_manifest_path.read_text(encoding="utf-8"))
    manifest["fixtures"][0]["expected_components"] = []
    mutated_manifest_path = tmp_path / "fixture_manifest.json"
    mutated_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_fixture_watermark(mutated_manifest_path)

    assert not result.ok
    assert result.failures == ("acme_python_service must declare at least one expected component",)


def test_watermark_canary_ignores_runtime_owner_repo_inputs(
    fixture_manifest_path,
    monkeypatch,
):
    monkeypatch.setenv("REPOLENS_OWNER", "input-scope")
    monkeypatch.setenv("GITHUB_OWNER", "input-scope")

    result = validate_fixture_watermark(
        fixture_manifest_path,
        runtime_owner_repo=RUNTIME_OWNER_REPO,
    )

    assert result.ok
    assert result.synthetic_owner == "acme-synthetic-owner"
    assert result.watermark_id == WATERMARK_ID
    assert RUNTIME_OWNER_REPO not in _failure_text(result.failures)


def test_watermark_failures_do_not_echo_runtime_owner_repo_inputs(
    fixture_manifest_path,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("REPOLENS_OWNER", "input-scope")
    monkeypatch.setenv("GITHUB_OWNER", "input-scope")
    manifest = json.loads(fixture_manifest_path.read_text(encoding="utf-8"))
    manifest.pop("watermark_id")
    mutated_manifest_path = tmp_path / "fixture_manifest.json"
    mutated_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_fixture_watermark(
        mutated_manifest_path,
        runtime_owner_repo=RUNTIME_OWNER_REPO,
    )

    failures = _failure_text(result.failures)
    assert not result.ok
    assert "input-scope" not in failures
    assert "input-target" not in failures


def _failure_text(failures: tuple[str, ...]) -> str:
    return "\n".join(failures)
