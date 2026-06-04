from __future__ import annotations

from pathlib import Path

from repolens import cli
from repolens.data.store import iter_resolved, write_sbom


def test_resolve_cli_reads_sbom_and_writes_resolved_ndjson(tmp_path: Path, repo_ref: str) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/acme-alpha",
            "artifacts": [
                {
                    "name": "acme-lib",
                    "version": "1.2.3",
                    "type": "python",
                    "purl": "pkg:pypi/acme-lib@1.2.3",
                    "licenses": ["MIT"],
                }
            ],
        },
    )

    code = cli.main(["resolve", "--work-root", str(tmp_path), "--repo-ref", repo_ref])

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["name"] == "acme-lib"
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"


def test_resolve_cli_without_repo_ref_resolves_all_scanned_repos(tmp_path: Path) -> None:
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        write_sbom(
            tmp_path,
            repo_ref,
            {
                "schema_version": "1.0",
                "repo": repo_ref,
                "generated_at": "2026-01-01T00:00:00Z",
                "tool": {"name": "syft", "version": "1.0.0"},
                "source": f"https://example.invalid/{repo_ref}",
                "artifacts": [
                    {
                        "name": f"{repo_ref}-lib",
                        "version": "1.2.3",
                        "type": "python",
                        "purl": f"pkg:pypi/{repo_ref}-lib@1.2.3",
                        "licenses": ["MIT"],
                    }
                ],
            },
        )

    code = cli.main(["resolve", "--work-root", str(tmp_path)])

    assert code == 0
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
        assert records[0]["name"] == f"{repo_ref}-lib"
        assert records[0]["spdx_id"] == "MIT"


def test_resolve_cli_accepts_source_root_and_preserves_p3a_shape(
    tmp_path: Path, repo_ref: str
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Package.swift").write_text("// fixture", encoding="utf-8")
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/fixture",
            "artifacts": [
                {
                    "name": "fixture-lib",
                    "version": "1.2.3",
                    "type": "python",
                    "licenses": ["MIT"],
                    "locations": ["Package.swift"],
                }
            ],
        },
    )

    code = cli.main(
        [
            "resolve",
            "--work-root",
            str(tmp_path),
            "--repo-ref",
            repo_ref,
            "--source-root",
            str(source_root),
        ]
    )

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"


def test_resolve_cli_mobile_native_missing_sandbox_is_non_fatal(
    tmp_path: Path, repo_ref: str
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "build.gradle").write_text(
        "plugins { id 'com.android.application' }", encoding="utf-8"
    )
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/fixture",
            "artifacts": [
                {
                    "name": "fixture-lib",
                    "version": None,
                    "type": "python",
                    "licenses": [],
                    "locations": [],
                }
            ],
        },
    )

    code = cli.main(
        [
            "resolve",
            "--work-root",
            str(tmp_path),
            "--repo-ref",
            repo_ref,
            "--source-root",
            str(source_root),
            "--enable-mobile-native",
        ]
    )

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] is None
    assert records[0]["evidence"]["source_layer"] == "mobile"
    assert records[0]["evidence"]["anchor"] == "unresolved:mobile_sandbox_unavailable"
