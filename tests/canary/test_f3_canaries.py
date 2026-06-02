from __future__ import annotations

from pathlib import Path

import pytest

from repolens.data.errors import LimitExceeded, SchemaValidationError
from repolens.data.redact import REDACTION
from repolens.data.store import is_repo_scanned, load_json_capped, read_sbom, write_sbom


def test_untrusted_malformed_sbom_rejected(
    tmp_path: Path, repo_ref: str, sbom: dict[str, object]
) -> None:
    del sbom["repo"]
    work = tmp_path / "work" / repo_ref
    work.mkdir(parents=True)
    (work / "sbom.syft.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SchemaValidationError):
        read_sbom(tmp_path, repo_ref)


def test_untrusted_oversize_rejected(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    with pytest.raises(LimitExceeded):
        load_json_capped(path, max_bytes=1)


def test_untrusted_overdeep_rejected_with_typed_error(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_text("[" * 70 + "0" + "]" * 70, encoding="utf-8")

    with pytest.raises(LimitExceeded):
        load_json_capped(path, max_bytes=10_000, max_depth=64)


def test_token_absent_from_artifacts(
    tmp_path: Path, repo_ref: str, sbom: dict[str, object]
) -> None:
    token = "ghp_" + "1234567890abcdef"
    sbom["source"] = f"https://example.invalid/{token}"

    path = write_sbom(tmp_path, repo_ref, sbom)

    text = path.read_text(encoding="utf-8")
    assert token not in text
    assert REDACTION in text


def test_resume_does_not_skip_partial(tmp_path: Path, repo_ref: str) -> None:
    work = tmp_path / "work" / repo_ref
    work.mkdir(parents=True)
    (work / ".sbom.syft.json.tmp").write_text("{}", encoding="utf-8")

    assert is_repo_scanned(tmp_path, repo_ref) is False
