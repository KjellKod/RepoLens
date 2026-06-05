from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

import pytest

from repolens.data import store
from repolens.report.dependency_boundaries import (
    DEPENDABOT_COVERED,
    DEPENDABOT_UNCOVERED,
    DEPENDABOT_UNKNOWN,
    build_dependency_boundary_summary,
    render_dependency_boundaries_csv,
    render_dependency_boundaries_markdown,
    write_dependency_boundary_artifacts,
)


def test_builds_boundary_summary_with_repeats_drift_helper_paths_and_dependabot(
    tmp_path: Path,
) -> None:
    repo_ref = "acme-monorepo"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [
                _artifact(
                    "shared-core",
                    "1.0.0",
                    "pkg:npm/shared-core@1.0.0",
                    ["apps/api/package-lock.json", "apps/web/package-lock.json"],
                ),
                _artifact(
                    "drift-lib",
                    "1.0.0",
                    "pkg:npm/drift-lib@1.0.0",
                    ["apps/api/package-lock.json"],
                ),
                _artifact(
                    "drift-lib",
                    "2.0.0",
                    "pkg:npm/drift-lib@2.0.0",
                    ["apps/web/package-lock.json"],
                ),
                _artifact(
                    "script-tool",
                    "3.0.0",
                    "pkg:npm/script-tool@3.0.0",
                    ["ops/scripts/package-lock.json"],
                ),
                _artifact(
                    "host-leak",
                    "1.0.0",
                    "pkg:npm/host-leak@1.0.0",
                    ["/Users/acme/private/package-lock.json"],
                ),
            ],
        ),
    )
    _write_dependabot_snapshot(
        tmp_path,
        repo_ref,
        """
version: 2
updates:
  - package-ecosystem: npm
    directory: /apps/api/
  - package-ecosystem: npm
    directory: /ops/scripts
""",
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert summary.total_component_rows == 5
    assert summary.boundary_attributed_row_count == 5
    assert summary.unique_purl_count == 5
    assert summary.unique_package_name_count == 4
    assert summary.unique_manifest_path_count == 3
    assert summary.helper_path_row_count == 1
    assert summary.dependabot_covered_manifest_count == 2
    assert summary.dependabot_uncovered_manifest_count == 1
    assert summary.dependabot_unknown_manifest_count == 0
    assert summary.dropped_path_count == 1
    assert dict(summary.dropped_path_reasons) == {"absolute_path": 1}

    rows_by_path = {row.manifest_path: row for row in summary.boundaries}
    assert rows_by_path["apps/api/package-lock.json"].row_count == 2
    assert rows_by_path["apps/api/package-lock.json"].dependabot_status == DEPENDABOT_COVERED
    assert rows_by_path["apps/web/package-lock.json"].row_count == 2
    assert rows_by_path["apps/web/package-lock.json"].dependabot_status == DEPENDABOT_UNCOVERED
    assert rows_by_path["ops/scripts/package-lock.json"].helper_path is True
    assert rows_by_path["ops/scripts/package-lock.json"].dependabot_status == DEPENDABOT_COVERED

    assert summary.top_repeated_packages[0].purl == "pkg:npm/shared-core@1.0.0"
    assert summary.top_repeated_packages[0].manifest_path_count == 2
    assert summary.version_drift[0].package_name == "drift-lib"
    assert summary.version_drift[0].versions == ("1.0.0", "2.0.0")


def test_boundary_attributed_rows_can_exceed_raw_component_rows(tmp_path: Path) -> None:
    repo_ref = "acme-monorepo"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [
                _artifact(
                    "shared-core",
                    "1.0.0",
                    "pkg:npm/shared-core@1.0.0",
                    [
                        "apps/api/package-lock.json",
                        "apps/web/package-lock.json",
                        "apps/admin/package-lock.json",
                    ],
                )
            ],
        ),
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert summary.total_component_rows == 1
    assert summary.boundary_attributed_row_count == 3
    assert sum(row.row_count for row in summary.boundaries) == 3


def test_repo_root_relative_locations_with_leading_slash_are_allowed(tmp_path: Path) -> None:
    repo_ref = "acme-root-relative"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [
                _artifact(
                    "root-relative-lib",
                    "1.0.0",
                    "pkg:npm/root-relative-lib@1.0.0",
                    ["/apps/api/package-lock.json", "/package-lock.json"],
                )
            ],
        ),
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert summary.dropped_path_count == 0
    assert {row.manifest_path for row in summary.boundaries} == {
        "apps/api/package-lock.json",
        "package-lock.json",
    }


def test_decodes_repo_ref_directory_names_before_reading_sbom(tmp_path: Path) -> None:
    repo_ref = "acme/encoded"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [_artifact("acme-lib", "1.0.0", "pkg:pypi/acme-lib@1.0.0", ["requirements.txt"])],
        ),
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert summary.total_component_rows == 1
    assert summary.boundaries[0].repo == repo_ref


def test_dependabot_root_directory_covers_all_boundaries(tmp_path: Path) -> None:
    repo_ref = "acme-root"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [
                _artifact("root-lib", "1.0.0", "pkg:pypi/root-lib@1.0.0", ["requirements.txt"]),
                _artifact(
                    "nested-lib",
                    "1.0.0",
                    "pkg:npm/nested-lib@1.0.0",
                    ["apps/web/package-lock.json"],
                ),
            ],
        ),
    )
    _write_dependabot_snapshot(
        tmp_path,
        repo_ref,
        """
version: 2
updates:
  - package-ecosystem: pip
    directory: /
""",
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert {row.dependabot_status for row in summary.boundaries} == {DEPENDABOT_COVERED}


def test_missing_or_invalid_dependabot_config_is_unknown(tmp_path: Path) -> None:
    missing_repo = "acme-missing"
    invalid_repo = "acme-invalid"
    for repo_ref in (missing_repo, invalid_repo):
        store.write_sbom(
            tmp_path,
            repo_ref,
            _sbom(
                repo_ref,
                [_artifact("acme-lib", "1.0.0", "pkg:pypi/acme-lib@1.0.0", ["requirements.txt"])],
            ),
        )
    _write_dependabot_snapshot(tmp_path, invalid_repo, "updates: [")

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    statuses = {row.repo: row.dependabot_status for row in summary.boundaries}
    assert statuses[missing_repo] == DEPENDABOT_UNKNOWN
    assert statuses[invalid_repo] == DEPENDABOT_UNKNOWN


def test_markdown_csv_and_json_outputs_keep_paths_inert(tmp_path: Path) -> None:
    repo_ref = "acme-output"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [
                _artifact(
                    "formula-lib",
                    "1.0.0",
                    "pkg:npm/formula-lib@1.0.0",
                    ["=cmd/package-lock.json", "../private/package-lock.json"],
                )
            ],
        ),
    )

    summary = build_dependency_boundary_summary(tmp_path)
    assert summary is not None
    assert summary.dropped_path_count == 1
    assert "../private/package-lock.json" not in json.dumps(summary.to_dict())

    csv_text = render_dependency_boundaries_csv(summary)
    csv_rows = list(csv.DictReader(csv_text.splitlines()))
    assert csv_rows[0]["manifest_path"] == "\t=cmd/package-lock.json"

    markdown = render_dependency_boundaries_markdown(summary)
    assert "`=cmd/package-lock.json`" in markdown
    assert "../private/package-lock.json" not in markdown

    json_path, csv_path, markdown_path = write_dependency_boundary_artifacts(
        tmp_path / "reports",
        summary,
    )
    assert json_path.exists()
    assert csv_path.exists()
    assert markdown_path.exists()


def test_boundary_generation_does_not_invoke_native_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"native tool execution is not allowed: {args} {kwargs}")

    monkeypatch.setattr(subprocess, "run", fail_run)
    repo_ref = "acme-offline"
    store.write_sbom(
        tmp_path,
        repo_ref,
        _sbom(
            repo_ref,
            [_artifact("acme-lib", "1.0.0", "pkg:pypi/acme-lib@1.0.0", ["requirements.txt"])],
        ),
    )

    summary = build_dependency_boundary_summary(tmp_path)

    assert summary is not None
    assert summary.total_component_rows == 1


def _write_dependabot_snapshot(tmp_path: Path, repo_ref: str, text: str) -> None:
    staged = tmp_path / f"{repo_ref}-snapshot"
    (staged / ".github").mkdir(parents=True)
    (staged / ".github" / "dependabot.yml").write_text(text.strip() + "\n", encoding="utf-8")
    store.replace_source_snapshot(tmp_path, repo_ref, staged)


def _sbom(repo_ref: str, artifacts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "repo": repo_ref,
        "generated_at": "2026-01-01T00:00:00Z",
        "tool": {"name": "syft", "version": "1.0.0"},
        "source": f"https://example.invalid/{repo_ref}",
        "artifacts": artifacts,
    }


def _artifact(
    name: str,
    version: str,
    purl: str,
    locations: list[str],
    *,
    ecosystem: str = "npm",
) -> dict[str, object]:
    return {
        "name": name,
        "version": version,
        "type": ecosystem,
        "purl": purl,
        "licenses": ["MIT"],
        "locations": locations,
    }
