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
