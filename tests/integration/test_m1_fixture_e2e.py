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
    result = subprocess.run(
        [
            sys.executable,
            "scripts/m1_fixture_e2e.py",
            "--work-root",
            str(tmp_path / "work-root"),
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)

    assert summary["approved_repos"] == 5
    assert summary["sbom_artifacts"] == 7
    assert summary["resolved_rows"] == 7
    assert summary["report_rows"] == 3
    assert summary["appendix_rows"] == 3
    assert summary["report_union_rows"] == 6
    assert summary["report_rows_with_license"] == 3
    assert summary["report_rows_with_source_url"] == 3
    assert summary["deduped_shared_component_rows"] == 1
    assert summary["report_md_exists"] is True
    assert summary["report_csv_exists"] is True
    assert summary["report_docx_exists"] is True
    assert summary["appendix_csv_exists"] is True
    assert summary["appendix_md_exists"] is True
