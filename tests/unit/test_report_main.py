from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from repolens.config import Config
from repolens.data import store
from repolens.exit_codes import InputError
from repolens.report import (
    COLUMNS,
    DEFAULT_LEGAL_TEXT,
    DOCX_SKIPPED_NOTICE,
    aggregate_rows,
    render_main_report,
)
from repolens.shortlist.evidence import EvidenceIdentity


def test_render_main_report_writes_md_and_csv_from_resolved_records(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    assert result.row_count == 1
    assert result.markdown_path.exists()
    assert result.csv_path.exists()
    assert result.html_path.exists()
    assert result.docx_path.exists()
    assert result.presentation_markdown_path == tmp_path / "out" / "report.presentation.md"
    assert result.presentation_csv_path == tmp_path / "out" / "report.presentation.csv"
    assert result.presentation_html_path == tmp_path / "out" / "report.presentation.html"
    assert result.presentation_docx_path == tmp_path / "out" / "report.presentation.docx"
    assert result.presentation_markdown_path.exists()
    assert result.presentation_csv_path.exists()
    assert result.presentation_html_path.exists()
    assert result.presentation_docx_path.exists()
    assert tuple(_csv_rows(result.csv_path)[0]) == COLUMNS
    markdown = result.markdown_path.read_text(encoding="utf-8")
    for column in ("version", "source_url", "modified?", "origin", "scope", "distribution"):
        assert column in markdown


def test_render_main_report_defaults_out_dir_under_work_root(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    result = render_main_report(tmp_path, config=_report_config())

    assert result.markdown_path == tmp_path / "reports" / "report.main.md"
    assert result.csv_path == tmp_path / "reports" / "report.main.csv"
    assert result.html_path == tmp_path / "reports" / "report.main.html"
    assert result.docx_path == tmp_path / "reports" / "report.main.docx"
    assert result.presentation_markdown_path == tmp_path / "reports" / "report.presentation.md"
    assert result.presentation_csv_path == tmp_path / "reports" / "report.presentation.csv"
    assert result.presentation_html_path == tmp_path / "reports" / "report.presentation.html"
    assert result.presentation_docx_path == tmp_path / "reports" / "report.presentation.docx"


def test_aggregate_rows_filters_badge_descriptions_from_stale_resolved_records() -> None:
    def record(description: str, version: str) -> dict[str, Any]:
        return {
            "name": "@smithy/middleware-retry",
            "version": version,
            "repo": "web",
            "spdx_id": "Apache-2.0",
            "modified": "unknown",
            "description": description,
            "purl": f"pkg:npm/%40smithy/middleware-retry@{version}",
            "evidence": {"source_layer": "syft"},
            "tags": {
                "origin": "third-party-oss",
                "scope": "runtime",
                "distribution": "server",
            },
        }

    rows = aggregate_rows(
        [
            record(
                "[![NPM version](https://img.shields.io/npm/v/@smithy/middleware-retry/"
                "latest.svg)](https://www.npmjs.com/package/@smithy/middleware-retry)",
                "4.4.29",
            ),
            record("Shared retry utilities to be used in middleware packages.", "4.0.6"),
        ]
    )

    assert rows[0].descriptions == ("Shared retry utilities to be used in middleware packages.",)


def test_render_main_report_writes_dependency_boundary_artifacts(
    tmp_path: Path, resolved_record: dict[str, Any], sbom: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    store.write_sbom(
        tmp_path,
        "acme-alpha",
        {
            **sbom,
            "artifacts": [
                {
                    **sbom["artifacts"][0],
                    "locations": ["apps/api/package-lock.json", "apps/web/package-lock.json"],
                }
            ],
        },
    )

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    assert result.dependency_boundary_paths == (
        tmp_path / "out" / "dependency-boundaries.json",
        tmp_path / "out" / "report.dependency-boundaries.csv",
        tmp_path / "out" / "report.dependency-boundaries.md",
    )
    markdown = result.markdown_path.read_text(encoding="utf-8")
    assert "## Dependency Boundaries" in markdown
    payload = json.loads(result.dependency_boundary_paths[0].read_text(encoding="utf-8"))
    assert payload["total_component_rows"] == 1
    assert payload["boundary_attributed_row_count"] == 2
    assert payload["unique_manifest_path_count"] == 2


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
    assert rows[0]["source_url"] == "pkg:pypi/acme-lib@1.2.3"
    assert rows[0]["coverage_gaps"] == "missing_category; missing_source_url; missing_spdx_id"


def test_report_excludes_rejected_shortlist_components(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(tmp_path, [_shortlist_item("acme-lib|UNKNOWN", status="rejected")])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert rows == []
    assert "acme-lib" not in (tmp_path / "out" / "report.main.html").read_text(encoding="utf-8")


def test_report_keeps_approved_shortlist_components(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(tmp_path, [_shortlist_item("acme-lib|UNKNOWN", status="approved")])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert len(rows) == 1
    assert rows[0]["name"] == "acme-lib"
    assert rows[0]["spdx_id"] == "UNKNOWN"


def test_report_projects_approved_human_override_with_unverified_provenance(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(
        tmp_path,
        [
            _shortlist_item(
                "acme-lib|UNKNOWN",
                status="approved",
                candidate_spdx="ZPL-2.1",
                research_evidence={
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": _override_fingerprint("acme-lib|UNKNOWN"),
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": [],
                    "outcome": "human_override",
                    "machine_verification": "human_override_unverified",
                    "likely_spdx": "ZPL-2.1",
                    "human_candidate_spdx": "ZPL-2.1",
                    "override_reason": "manual review",
                    "override_decided_by": "kjell",
                    "override_evidence_verified": False,
                    "browser_evidence": [
                        {
                            "label": "PyPI project page",
                            "url": "https://pypi.org/project/acme-lib/",
                            "source_type": "human_override",
                            "anchor": "ZPL-2.1",
                        }
                    ],
                },
            )
        ],
    )

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())
    rows = _csv_records(result.csv_path)
    markdown = result.markdown_path.read_text(encoding="utf-8")
    html = result.html_path.read_text(encoding="utf-8")

    assert rows[0]["spdx_id"] == "ZPL-2.1"
    assert rows[0]["evidence_source_layer"] == "human_override_unverified"
    assert rows[0]["source_url"] == "https://pypi.org/project/acme-lib/"
    assert "human_override_unverified" in markdown
    assert "human_override_unverified" in html


def test_report_rejects_mismatched_human_override_spdx_provenance(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(
        tmp_path,
        [
            _shortlist_item(
                "acme-lib|UNKNOWN",
                status="approved",
                candidate_spdx="MIT",
                research_evidence={
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": _override_fingerprint("acme-lib|UNKNOWN"),
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": [],
                    "outcome": "human_override",
                    "machine_verification": "human_override_unverified",
                    "likely_spdx": "ZPL-2.1",
                    "human_candidate_spdx": "ZPL-2.1",
                    "override_reason": "manual review",
                    "override_decided_by": "kjell",
                    "override_evidence_verified": False,
                },
            )
        ],
    )

    with pytest.raises(InputError, match="mismatched"):
        render_main_report(tmp_path, tmp_path / "out", _report_config())


def test_report_clears_inherited_source_url_when_human_override_has_no_evidence_url(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    stale_url = "https://deps.dev/stale/verifier-evidence"
    unknown = {
        **resolved_record,
        "spdx_id": None,
        "evidence": {"source_layer": "syft", "url": stale_url, "anchor": "MIT"},
    }
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(
        tmp_path,
        [
            _shortlist_item(
                "acme-lib|UNKNOWN",
                status="approved",
                candidate_spdx="ZPL-2.1",
                research_evidence={
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": _override_fingerprint("acme-lib|UNKNOWN"),
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": [],
                    "outcome": "human_override",
                    "machine_verification": "human_override_unverified",
                    "likely_spdx": "ZPL-2.1",
                    "human_candidate_spdx": "ZPL-2.1",
                    "override_reason": "manual review",
                    "override_decided_by": "kjell",
                    "override_evidence_verified": False,
                },
            )
        ],
    )

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert rows[0]["spdx_id"] == "ZPL-2.1"
    assert rows[0]["evidence_source_layer"] == "human_override_unverified"
    assert rows[0]["source_url"] != stale_url
    assert rows[0]["source_url"] == "pkg:pypi/acme-lib@1.2.3"


def test_report_rejects_expired_approved_human_override(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(
        tmp_path,
        [
            _shortlist_item(
                "acme-lib|UNKNOWN",
                status="approved",
                candidate_spdx="ZPL-2.1",
                research_evidence={
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": _override_fingerprint("acme-lib|UNKNOWN"),
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": [],
                    "outcome": "human_override",
                    "machine_verification": "human_override_unverified",
                    "likely_spdx": "ZPL-2.1",
                    "human_candidate_spdx": "ZPL-2.1",
                    "override_reason": "manual review",
                    "override_decided_by": "kjell",
                    "override_evidence_verified": False,
                    "override_expires_at": "2000-01-01",
                },
            )
        ],
    )

    with pytest.raises(InputError, match="expired"):
        render_main_report(tmp_path, tmp_path / "out", _report_config())


def test_report_rejects_stale_approved_human_override_context(
    tmp_path: Path,
    resolved_record: dict[str, Any],
) -> None:
    unknown = {**resolved_record, "spdx_id": None, "evidence": {"source_layer": "syft"}}
    store.write_resolved(tmp_path, "acme-alpha", [unknown])
    _write_shortlist(
        tmp_path,
        [
            _shortlist_item(
                "acme-lib|UNKNOWN",
                status="approved",
                candidate_spdx="ZPL-2.1",
                research_evidence={
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": _override_fingerprint(
                        "acme-lib|UNKNOWN",
                        version="1.2.3",
                    ),
                    "package": "acme-lib",
                    "version": "1.2.3",
                    "ecosystem": None,
                    "found_in": [],
                    "outcome": "human_override",
                    "machine_verification": "human_override_unverified",
                    "likely_spdx": "ZPL-2.1",
                    "human_candidate_spdx": "ZPL-2.1",
                    "override_reason": "manual review",
                    "override_decided_by": "kjell",
                    "override_evidence_verified": False,
                },
            )
        ],
    )

    with pytest.raises(InputError, match="stale"):
        render_main_report(tmp_path, tmp_path / "out", _report_config())


def test_report_rejected_shortlist_ref_does_not_drop_other_spdx_for_same_name(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    unknown = {
        **resolved_record,
        "spdx_id": None,
        "version": "2.0.0",
        "evidence": {"source_layer": "syft"},
    }
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record, unknown])
    _write_shortlist(tmp_path, [_shortlist_item("acme-lib|UNKNOWN", status="rejected")])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

    assert [row["spdx_id"] for row in rows] == ["MIT"]
    assert rows[0]["version"] == "1.2.3"


def test_missing_evidence_url_without_purl_still_renders_empty_source_url(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    no_url = {
        **resolved_record,
        "spdx_id": None,
        "evidence": {"source_layer": "syft"},
    }
    no_url.pop("purl")
    store.write_resolved(tmp_path, "acme-alpha", [no_url])

    rows = _csv_records(render_main_report(tmp_path, tmp_path / "out", _report_config()).csv_path)

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


def test_declared_unpinned_version_renders_status_without_missing_version_gap(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    declared_unpinned = {
        **resolved_record,
        "version": "unknown",
        "declared_version_status": "declared-unpinned",
    }
    store.write_resolved(tmp_path, "acme-alpha", [declared_unpinned])

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())
    rows = _csv_records(result.csv_path)
    markdown = result.markdown_path.read_text(encoding="utf-8")

    assert rows[0]["version"] == "declared-unpinned"
    assert rows[0]["coverage_gaps"] == "missing_category"
    assert "declared-unpinned" in markdown
    assert "missing_version" not in rows[0]["coverage_gaps"]


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


def test_report_ignores_unchecked_stale_scan_artifacts(
    tmp_path: Path, resolved_record: dict[str, Any], sbom: dict[str, Any]
) -> None:
    _write_discovered(
        tmp_path,
        [
            {"name": "acme-alpha", "name_with_owner": "acme/acme-alpha", "category": "runtime"},
            {
                "name": "internal-datadog-mcp",
                "name_with_owner": "acme/internal-datadog-mcp",
                "category": "internal",
            },
        ],
    )
    _write_candidates(
        tmp_path,
        [
            "- [x] `acme/acme-alpha` - category `runtime` (`test`)",
            "- [ ] `acme/internal-datadog-mcp` - category `internal` (`test`)",
        ],
    )
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    store.write_sbom(tmp_path, "internal-datadog-mcp", sbom)

    result = render_main_report(tmp_path, tmp_path / "out", _report_config(include=("runtime",)))

    rows = _csv_records(result.csv_path)
    assert result.row_count == 1
    assert rows[0]["found_in"] == "acme-alpha"


def test_report_lists_missing_checked_resolved_inputs(tmp_path: Path, sbom: dict[str, Any]) -> None:
    _write_discovered(
        tmp_path,
        [
            {"name": "acme-alpha", "name_with_owner": "acme/acme-alpha", "category": "runtime"},
            {"name": "acme-beta", "name_with_owner": "acme/acme-beta", "category": "runtime"},
        ],
    )
    _write_candidates(
        tmp_path,
        [
            "- [x] `acme/acme-alpha` - category `runtime` (`test`)",
            "- [x] `acme/acme-beta` - category `runtime` (`test`)",
        ],
    )
    store.write_sbom(tmp_path, "acme-alpha", sbom)
    store.write_sbom(tmp_path, "acme-beta", sbom)

    with pytest.raises(
        InputError,
        match=(
            r"incomplete R1 input: missing work/acme-alpha/resolved\.ndjson, "
            r"work/acme-beta/resolved\.ndjson"
        ),
    ):
        render_main_report(tmp_path, tmp_path / "out", _report_config(include=("runtime",)))


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


def test_main_markdown_safe_source_url_label_is_not_double_escaped(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    url = (
        "https://api.deps.dev/v3alpha/systems/npm/packages/"
        "@aashutoshrathi%2Fword-wrap/versions/1.2.6"
    )
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [{**resolved_record, "evidence": {**resolved_record["evidence"], "url": url}}],
    )

    markdown = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(),
    ).markdown_path.read_text(encoding="utf-8")

    assert f"[{url}]({url})" in markdown
    assert "api\\." not in markdown
    assert "word\\-wrap" not in markdown


def test_html_report_uses_wide_landscape_layout_and_inert_unsafe_urls(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            {
                **resolved_record,
                "name": "acme <widget>",
                "evidence": {
                    **resolved_record["evidence"],
                    "url": "javascript:alert(1)",
                },
            }
        ],
    )

    html = render_main_report(
        tmp_path,
        tmp_path / "out",
        _report_config(),
    ).html_path.read_text(encoding="utf-8")

    assert "@page { size: letter landscape;" in html
    assert "table-layout: fixed" in html
    assert "word-break: break-word" in html
    assert 'style="width: 25%"' in html
    assert "overflow-x: auto" not in html
    assert "acme &lt;widget&gt;" in html
    assert "javascript:" not in html
    assert "javascript&#58;alert(1)" in html
    assert 'href="javascript' not in html


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


def test_report_renders_md_csv_without_header_config(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    result = render_main_report(tmp_path, tmp_path / "out", _no_header_config())

    assert result.row_count == 1
    assert result.markdown_path.exists()
    assert result.csv_path.exists()
    assert result.html_path.exists()
    assert result.docx_path is None
    assert result.docx_skipped is True
    assert result.presentation_markdown_path is not None
    assert result.presentation_csv_path is not None
    assert result.presentation_html_path is not None
    assert result.presentation_markdown_path.exists()
    assert result.presentation_csv_path.exists()
    assert result.presentation_html_path.exists()
    assert result.presentation_docx_path is None
    assert result.presentation_docx_skipped is True
    assert not (tmp_path / "out" / "report.main.docx").exists()
    assert not (tmp_path / "out" / "report.presentation.docx").exists()


def test_report_skips_docx_when_header_absent_non_interactive(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    output = io.StringIO()

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _no_header_config(),
        output_stream=output,
    )

    assert output.getvalue().strip() == DOCX_SKIPPED_NOTICE
    assert result.docx_path is None
    assert result.docx_skipped is True
    assert result.presentation_docx_path is None
    assert result.presentation_docx_skipped is True
    assert not (tmp_path / "out" / "report.main.docx").exists()
    assert not (tmp_path / "out" / "report.presentation.docx").exists()
    assert result.csv_path.exists()
    assert result.markdown_path.exists()
    assert result.html_path.exists()
    assert result.presentation_csv_path is not None
    assert result.presentation_markdown_path is not None
    assert result.presentation_html_path is not None
    assert result.presentation_csv_path.exists()
    assert result.presentation_markdown_path.exists()
    assert result.presentation_html_path.exists()


def test_report_header_present_but_empty_still_raises(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    config = Config(values={"report": {"header": {"org_name": "", "legal_text": ""}}}, sources=())

    with pytest.raises(InputError, match="report.header"):
        render_main_report(tmp_path, tmp_path / "out", config)


def test_report_prompts_and_renders_docx_with_entered_header(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    input_stream = io.StringIO("Acme Inc\nConfidential - internal only\n")

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _no_header_config(),
        interactive=True,
        owner=None,
        input_stream=input_stream,
        output_stream=io.StringIO(),
    )

    assert result.docx_path is not None
    assert result.presentation_docx_path is not None
    assert result.docx_skipped is False
    document_xml = zipfile.ZipFile(result.docx_path).read("word/document.xml").decode("utf-8")
    presentation_xml = (
        zipfile.ZipFile(result.presentation_docx_path).read("word/document.xml").decode("utf-8")
    )
    assert "Acme Inc" in document_xml
    assert "Confidential - internal only" in document_xml
    assert "RepoLens Presentation Report" in presentation_xml
    assert "Acme Inc" in presentation_xml


def test_report_prompt_defaults_use_owner_and_default_legal(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    input_stream = io.StringIO("\n\n")

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _no_header_config(),
        interactive=True,
        owner="acme",
        input_stream=input_stream,
        output_stream=io.StringIO(),
    )

    assert result.docx_path is not None
    document_xml = zipfile.ZipFile(result.docx_path).read("word/document.xml").decode("utf-8")
    assert "acme" in document_xml
    assert DEFAULT_LEGAL_TEXT in document_xml


def test_report_prompt_eof_without_owner_skips_docx(
    tmp_path: Path, resolved_record: dict[str, Any]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])
    output = io.StringIO()

    result = render_main_report(
        tmp_path,
        tmp_path / "out",
        _no_header_config(),
        interactive=True,
        owner=None,
        input_stream=io.StringIO(""),
        output_stream=output,
    )

    assert result.docx_path is None
    assert result.presentation_docx_path is None
    assert result.docx_skipped is True
    assert result.presentation_docx_skipped is True
    assert DOCX_SKIPPED_NOTICE in output.getvalue()
    assert not (tmp_path / "out" / "report.main.docx").exists()
    assert not (tmp_path / "out" / "report.presentation.docx").exists()


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
    assert (
        appendix_rows[0]["source_url"]
        == "pkg:githubactions/sentinel-ci-owner/sentinel-ci-action@v1"
    )
    assert ci_name not in markdown
    assert ci_name not in docx_xml
    assert result.appendices[0].label == "build-ci"
    assert result.appendices[0].row_count == 1
    assert dict(result.appendices[0].coverage_gaps) == {
        "missing_source_url": 1,
        "missing_spdx_id": 1,
    }


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


def _no_header_config(include: tuple[str, ...] | None = None) -> Config:
    report: dict[str, object] = {}
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


def _write_candidates(tmp_path: Path, rows: list[str]) -> None:
    (tmp_path / "repos.candidate.md").write_text(
        "\n".join(
            [
                "# Repository candidates",
                "",
                "## Candidates",
                "",
                *rows,
                "",
                "## Hard exclusions",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_shortlist(tmp_path: Path, items: list[dict[str, object]]) -> None:
    store.write_shortlist(
        tmp_path,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 0,
            "items": items,
        },
    )


def _shortlist_item(
    component_ref: str,
    *,
    status: str,
    candidate_spdx: str | None = None,
    research_evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "component_ref": component_ref,
        "reason": "UNKNOWN",
        "evidence": {"source_layer": "syft"},
        "candidate_spdx": candidate_spdx,
        "status": status,
        "decided_by": "reviewer",
        "decided_at": "2026-01-01T00:00:00Z",
    }
    if research_evidence is not None:
        item["research_evidence"] = research_evidence
    return item


def _override_fingerprint(
    component_ref: str,
    *,
    package: str | None = "acme-lib",
    version: str | None = None,
    ecosystem: str | None = None,
    found_in: tuple[str, ...] = (),
) -> str:
    return EvidenceIdentity(
        component_ref=component_ref,
        package=package,
        version=version,
        ecosystem=ecosystem,
        found_in=found_in,
    ).context_fingerprint
