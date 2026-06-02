from __future__ import annotations

from pathlib import Path

from repolens.data.store import (
    iter_resolved,
    read_inventory,
    read_sbom,
    read_shortlist,
    write_inventory,
    write_resolved,
    write_sbom,
    write_shortlist,
)


def test_write_then_read_all_artifacts(
    tmp_path: Path,
    repo_ref: str,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
    inventory: dict[str, object],
    shortlist: dict[str, object],
) -> None:
    write_sbom(tmp_path, repo_ref, sbom)
    resolved_path = write_resolved(tmp_path, repo_ref, [resolved_record])
    write_inventory(tmp_path, inventory)
    write_shortlist(tmp_path, shortlist)

    assert read_sbom(tmp_path, repo_ref)["repo"] == repo_ref
    assert list(iter_resolved(resolved_path))[0]["name"] == "acme-lib"
    assert read_inventory(tmp_path)["components"][0]["source_url"].startswith("https://example")
    assert read_shortlist(tmp_path)["open_count"] == 1
