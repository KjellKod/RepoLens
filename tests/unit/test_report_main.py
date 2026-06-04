from __future__ import annotations

import csv
import zipfile
from pathlib import Path
from typing import Any

import pytest

from repolens.config import Config
from repolens.data import store
from repolens.exit_codes import InputError
from repolens.report import COLUMNS, aggregate_rows, render_main_report


def test_render_main_report_writes_md_and_csv_from_resolved_records(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    assert result.row_count == 1
    assert result.markdown_path.exists()
    assert result.csv_path.exists()
    assert result.docx_path.exists()
    assert tuple(_csv_rows(result.csv_path)[0]) == COLUMNS
    markdown = result.markdown_path.read_text(encoding="utf-8")
    for column in ("version", "source_url", "modified?", "origin", "scope", "distribution"):
        assert column in markdown


def test_deduplicates_by_name_and_spdx_id_across_repos(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    store.write_resolved(
        tmp_path,
        "acme-beta",
        [
            {
                **resolved_record,
                "repo": "acme-beta",
                "version": "1.2.4",
                "evidence": {
                    **resolved_record["evidence"],
                    "url": "https://example.invalid/licenses/mit-2",
                },
            }
        ],
    )

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert len(rows) == 1
    assert rows[0]["name"] == "acme-lib"
    assert rows[0]["spdx_id"] == "MIT"
    assert rows[0]["version"] == "1.2.3; 1.2.4"
    assert rows[0]["found_in"] == "acme-alpha; acme-beta"


def test_deduplicates_same_component_seen_from_multiple_package_types(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            {
                **resolved_record,
                "purl": "pkg:pypi/acme-lib@1.2.3",
            },
            {
                **resolved_record,
                "purl": "pkg:npm/acme-lib@1.2.3",
                "evidence": {
                    **resolved_record["evidence"],
                    "source_layer": "api",
                    "url": "https://example.invalid/licenses/mit-api",
                },
            },
        ],
    )

    rows = aggregate_rows(store.iter_resolved(tmp_path / "work" / "acme-alpha" / "resolved.ndjson"))

    assert len(rows) == 1
    assert rows[0].evidence_source_layers == ("api", "syft")
    assert rows[0].source_urls == (
        "https://example.invalid/licenses/mit",
        "https://example.invalid/licenses/mit-api",
    )


def test_aggregates_versions_source_urls_and_provenance_deterministically(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    records = [
        {
            **resolved_record,
            "version": "2.0.0",
            "repo": "acme-zeta",
            "evidence": {
                **resolved_record["evidence"],
                "url": "https://example.invalid/z",
                "source_layer": "api",
            },
        },
        {
            **resolved_record,
            "version": "1.0.0",
            "repo": "acme-alpha",
            "evidence": {
                **resolved_record["evidence"],
                "url": "https://example.invalid/a",
            },
        },
    ]
    store.write_resolved(tmp_path, "acme-zeta", [records[0]])
    store.write_resolved(tmp_path, "acme-alpha", [records[1]])

    row = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)[0]

    assert row["version"] == "1.0.0; 2.0.0"
    assert row["source_url"] == "https://example.invalid/a; https://example.invalid/z"
    assert row["found_in"] == "acme-alpha; acme-zeta"
    assert row["evidence_source_layer"] == "api; syft"


def test_coverage_gaps_are_rendered_without_dropping_rows(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    no_url = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    blank_url = {
        **resolved_record,
        "version": "1.2.4",
        "spdx_id": None,
        "evidence": {"source_layer": "syft", "url": "  "},
    }
    store.write_resolved(tmp_path, "acme-alpha", [no_url, blank_url])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert len(rows) == 1
    assert rows[0]["spdx_id"] == "UNKNOWN"
    assert rows[0]["version"] == "1.2.3; 1.2.4"
    assert rows[0]["source_url"] == ""
    assert rows[0]["coverage_gaps"] == "missing_category; missing_source_url; missing_spdx_id"


def test_unknown_version_adds_missing_version_coverage_gap(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    unknown_version = {**resolved_record, "version": "unknown"}
    store.write_resolved(tmp_path, "acme-alpha", [unknown_version])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert rows[0]["version"] == "unknown"
    assert rows[0]["coverage_gaps"] == "missing_category; missing_version"


def test_mixed_tags_and_modified_are_preserved_and_flagged(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    records = [
        {
            **resolved_record,
            "modified": True,
            "tags": {
                "origin": "third-party-oss",
                "scope": "runtime",
                "distribution": "server",
            },
        },
        {
            **resolved_record,
            "version": "1.2.4",
            "modified": False,
            "tags": {
                "origin": "first-party",
                "scope": "dev",
                "distribution": "not-distributed",
            },
        },
    ]

    row = aggregate_rows(records)[0]

    assert row.origins == ("first-party", "third-party-oss")
    assert row.scopes == ("dev", "runtime")
    assert row.distributions == ("not-distributed", "server")
    assert row.modified == ("false", "true")
    assert row.coverage_gaps == (
        "mixed_distribution",
        "mixed_modified",
        "mixed_origin",
        "mixed_scope",
    )


def test_report_uses_resolved_ndjson_not_inventory_json(
    tmp_path: Path, resolved_record: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    (tmp_path / "inventory.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(store, "read_inventory", lambda *_args, **_kwargs: pytest.fail("inventory"))

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    assert result.row_count == 1


def test_pipe_characters_are_escaped_in_markdown_table(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            {
                **resolved_record,
                "name": "acme|widget",
                "evidence": {
                    **resolved_record["evidence"],
                    "url": "https://example.invalid/licenses/acme|widget",
                },
            }
        ],
    )

    markdown = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(),
    ).markdown_path.read_text(encoding="utf-8")

    assert "`acme\\|widget`" in markdown
    assert "https://example.invalid/licenses/acme\\|widget" in markdown


def test_empty_resolved_file_renders_file_gap(tmp_path: Path) -> None:
    repo_dir = tmp_path / "work" / "acme-alpha"
    repo_dir.mkdir(parents=True)
    (repo_dir / "resolved.ndjson").write_text("", encoding="utf-8")

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    assert result.row_count == 0
    assert result.file_gaps == ("empty_resolved_file: work/acme-alpha/resolved.ndjson",)
    assert "Coverage Gaps" in result.markdown_path.read_text(encoding="utf-8")


def test_missing_work_root_raises_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        render_main_report(tmp_path, tmp_path / "out", _report_config())


def test_report_requires_docx_header(tmp_path: Path, resolved_record: dict[str, Any]) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    with pytest.raises(InputError, match="report.header"):
        render_main_report(tmp_path, tmp_path / "out")


def test_same_component_can_split_between_main_and_appendix(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    _write_discovered(
        tmp_path,
        [
            {"name": "acme-alpha", "name_with_owner": "acme/acme-alpha", "category": "runtime"},
            {"name": "acme-beta", "name_with_owner": "acme/acme-beta", "category": "tools"},
        ],
    )
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    store.write_resolved(
        tmp_path,
        "acme-beta",
        [
            {
                **resolved_record,
                "repo": "acme-beta",
                "version": "2.0.0",
            }
        ],
    )

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(include=("runtime",)),
    )

    main_rows = _csv_records(result.csv_path)
    appendix_rows = _csv_records(tmp_path / "out" / "report.appendix.tools.csv")
    assert main_rows[0]["found_in"] == "acme-alpha"
    assert main_rows[0]["version"] == "1.2.3"
    assert appendix_rows[0]["found_in"] == "acme-beta"
    assert appendix_rows[0]["version"] == "2.0.0"


def test_first_party_occurrence_never_enters_main(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    _write_discovered(
        tmp_path,
        [{"name": "acme-alpha", "name_with_owner": "acme/acme-alpha", "category": "runtime"}],
    )
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            resolved_record,
            {
                **resolved_record,
                "version": "2.0.0",
                "tags": {
                    **resolved_record["tags"],
                    "origin": "first-party",
                },
            },
        ],
    )

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(include=("runtime",)),
    )

    main_rows = _csv_records(result.csv_path)
    appendix_rows = _csv_records(tmp_path / "out" / "report.appendix.first-party.csv")
    assert main_rows[0]["origin"] == "third-party-oss"
    assert main_rows[0]["version"] == "1.2.3"
    assert appendix_rows[0]["origin"] == "first-party"
    assert appendix_rows[0]["version"] == "2.0.0"


def test_report_main_md_csv_docx_share_main_row_set_without_build_ci_gap(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    _write_discovered(
        tmp_path,
        [
            {
                "name": "sentinel-report-app",
                "name_with_owner": "sentinel-owner/sentinel-report-app",
                "category": "runtime",
            }
        ],
    )
    ci_name = "sentinel-ci-action"
    store.write_resolved(
        tmp_path,
        "sentinel-report-app",
        [
            {**resolved_record, "repo": "sentinel-report-app"},
            {
                **resolved_record,
                "repo": "sentinel-report-app",
                "name": ci_name,
                "version": "v1",
                "spdx_id": None,
                "declared_license_raw": None,
                "purl": "pkg:githubactions/sentinel-ci-owner/sentinel-ci-action@v1",
                "evidence": {"source_layer": "api", "anchor": "unresolved:no_candidate"},
                "tags": {
                    "origin": "third-party-oss",
                    "scope": "build",
                    "distribution": "not-distributed",
                },
            },
        ],
    )

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(include=("runtime",)),
    )

    main_rows = _csv_records(result.csv_path)
    appendix_rows = _csv_records(tmp_path / "out" / "report.appendix.build-ci.csv")
    markdown = result.markdown_path.read_text(encoding="utf-8")
    docx_xml = zipfile.ZipFile(result.docx_path).read("word/document.xml").decode("utf-8")
    assert [row["name"] for row in main_rows] == [resolved_record["name"]]
    assert appendix_rows[0]["name"] == ci_name
    assert ci_name not in markdown
    assert ci_name not in docx_xml


def _csv_records(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _csv_rows(path: Path) -> list[list[str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


def _report_config(include: tuple[str, ...] | None = None) -> Config:
    report: dict[str, object] = {
        "header": {
            "org_name": "Example Org",
            "legal_text": "Example legal notice.",
        }
    }
    if include is not None:
        report["selection"] = {"include": list(include)}
    return Config(values={"report": report}, sources=())


def _write_discovered(tmp_path: Path, repositories: list[dict[str, str]]) -> None:
    payload = {
        "schema_version": "1.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "owner": "acme",
        "repository_count": len(repositories),
        "candidate_count": len(repositories),
        "hard_exclusion_count": 0,
        "repositories": [
            {
                "url": f"https://example.invalid/{repo['name_with_owner']}",
                "description": "",
                "topics": [],
                "archived": False,
                "private": False,
                "category_source": "test",
                "hard_excluded": False,
                "exclusion_reason": None,
                **repo,
            }
            for repo in repositories
        ],
    }
    store.write_discovered(tmp_path, payload)
