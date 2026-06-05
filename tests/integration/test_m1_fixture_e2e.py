from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.offline, pytest.mark.fixtures]


def test_m1_fixture_e2e_harness_writes_valid_deduped_report(
    tmp_path: Path, repo_root: Path
) -> None:
    work_root = tmp_path / "work-root"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/m1_fixture_e2e.py",
            "--work-root",
            str(work_root),
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)

    assert summary["approved_repos"] == 8
    assert summary["sbom_artifacts"] == 12
    assert summary["raw_synthetic_sbom_artifacts"] == 13
    assert summary["resolved_rows"] == 12
    assert summary["report_rows"] == 4
    assert summary["appendix_rows"] == 6
    assert summary["report_union_rows"] == 10
    assert summary["report_rows_with_license"] == 4
    assert summary["report_rows_with_source_url"] == 4
    assert summary["deduped_shared_component_rows"] == 1
    assert summary["monorepo_sbom_artifacts"] == 2
    assert summary["monorepo_raw_artifacts"] == 3
    assert summary["monorepo_occurrence_count"] == 2
    assert summary["monorepo_locations"] == [
        "apps/api/package-lock.json",
        "apps/web/package-lock.json",
    ]
    assert summary["monorepo_shared_component_report_rows"] == 1
    assert summary["report_md_exists"] is True
    assert summary["report_csv_exists"] is True
    assert summary["report_docx_exists"] is True
    assert summary["appendix_csv_exists"] is True
    assert summary["appendix_md_exists"] is True

    ios_sbom = json.loads(
        (work_root / "work" / "sentinel_ios_client" / "sbom.syft.json").read_text(encoding="utf-8")
    )
    locations_by_name = {
        artifact["name"]: artifact["locations"] for artifact in ios_sbom["artifacts"]
    }
    assert locations_by_name["sentinel-swift-runtime"] == ["sentinel_ios_client/Package.resolved"]
    assert locations_by_name["SentinelPodRuntime"] == ["sentinel_ios_client/Podfile.lock"]

    android_sbom = json.loads(
        (work_root / "work" / "sentinel_android_app" / "sbom.syft.json").read_text(encoding="utf-8")
    )
    android_locations_by_name = {
        artifact["name"]: artifact["locations"] for artifact in android_sbom["artifacts"]
    }
    assert android_locations_by_name["invalid.sentinel:sentinel-android-runtime"] == [
        "sentinel_android_app/gradle.lockfile"
    ]
