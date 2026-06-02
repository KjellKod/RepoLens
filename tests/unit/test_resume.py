from __future__ import annotations

from pathlib import Path

from repolens.data.store import is_repo_scanned, repo_dir, write_sbom


def test_complete_artifact_is_skipped(
    tmp_path: Path, repo_ref: str, sbom: dict[str, object]
) -> None:
    write_sbom(tmp_path, repo_ref, sbom)

    assert is_repo_scanned(tmp_path, repo_ref) is True


def test_orphan_temp_not_skipped(tmp_path: Path, repo_ref: str) -> None:
    directory = repo_dir(tmp_path, repo_ref)
    directory.mkdir(parents=True)
    (directory / ".sbom.syft.json.partial").write_text("{}", encoding="utf-8")

    assert is_repo_scanned(tmp_path, repo_ref) is False


def test_corrupt_artifact_not_skipped(tmp_path: Path, repo_ref: str) -> None:
    directory = repo_dir(tmp_path, repo_ref)
    directory.mkdir(parents=True)
    (directory / "sbom.syft.json").write_text("{not-json", encoding="utf-8")

    assert is_repo_scanned(tmp_path, repo_ref) is False
