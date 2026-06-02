from __future__ import annotations

from pathlib import Path

from repolens.data.store import (
    is_repo_scanned,
    iter_resolved,
    read_inventory,
    write_inventory,
    write_resolved,
    write_sbom,
)


def test_round_trip_and_resume(
    tmp_path: Path,
    repo_ref: str,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
    inventory: dict[str, object],
) -> None:
    write_sbom(tmp_path, repo_ref, sbom)
    resolved_path = write_resolved(tmp_path, repo_ref, [resolved_record])
    write_inventory(tmp_path, inventory)

    assert is_repo_scanned(tmp_path, repo_ref)
    assert list(iter_resolved(resolved_path))[0]["repo"] == repo_ref
    assert read_inventory(tmp_path)["components"][0]["found_in"] == [repo_ref]
