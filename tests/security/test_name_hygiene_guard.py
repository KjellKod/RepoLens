from __future__ import annotations

import pytest

from repolens.testing.name_hygiene import scan_paths

pytestmark = [pytest.mark.offline, pytest.mark.security]


def test_name_hygiene_guard_fails_on_forbidden_token(tmp_path):
    fixture_file = tmp_path / "bad.txt"
    forbidden_token = "GITHUB" + "_OWNER="
    fixture_file.write_text(f"{forbidden_token}input-scope\n", encoding="utf-8")

    findings = scan_paths(tmp_path)

    assert len(findings) == 1
    assert findings[0].token == forbidden_token


def test_name_hygiene_guard_allows_synthetic_fixtures(synthetic_fixture_root):
    findings = scan_paths(synthetic_fixture_root)

    assert findings == []


def test_name_hygiene_guard_skips_generated_or_ignored_directories(tmp_path):
    skipped_dir = tmp_path / ".pytest_cache"
    skipped_dir.mkdir()
    skipped_file = skipped_dir / "cached.txt"
    skipped_file.write_text("REPOLENS" + "_OWNER=input-scope\n", encoding="utf-8")

    findings = scan_paths(tmp_path)

    assert findings == []


def test_name_hygiene_guard_fails_closed_when_root_is_missing(tmp_path):
    missing_root = tmp_path / "missing"

    with pytest.raises(FileNotFoundError, match="name hygiene root does not exist"):
        scan_paths(missing_root)
