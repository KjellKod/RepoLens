from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data.errors import CorruptArtifactError, LimitExceeded, SchemaValidationError
from repolens.data.store import iter_resolved, write_resolved


def test_per_record_stamped_line_accepted(
    tmp_path: Path, repo_ref: str, resolved_record: dict[str, object]
) -> None:
    path = write_resolved(tmp_path, repo_ref, [resolved_record])

    assert list(iter_resolved(path))[0]["schema_version"] == "1.0"


def test_header_shaped_line_rejected(tmp_path: Path) -> None:
    path = tmp_path / "resolved.ndjson"
    path.write_text(
        json.dumps({"kind": "resolved-header", "schema_version": "1.0"}),
        encoding="utf-8",
    )

    with pytest.raises(SchemaValidationError):
        list(iter_resolved(path))


def test_missing_schema_version_rejected(
    tmp_path: Path, resolved_record: dict[str, object]
) -> None:
    path = tmp_path / "resolved.ndjson"
    record = dict(resolved_record)
    del record["schema_version"]
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(SchemaValidationError, match="schema_version"):
        list(iter_resolved(path))


def test_overdeep_resolved_line_rejected_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "resolved.ndjson"
    path.write_text("[" * 70 + "0" + "]" * 70, encoding="utf-8")

    def fail_parse(_: bytes) -> object:
        raise AssertionError("parser should not run")

    monkeypatch.setattr("repolens.data.store.json.loads", fail_parse)

    with pytest.raises(LimitExceeded):
        list(iter_resolved(path))


def test_invalid_utf8_resolved_line_raises_corrupt_artifact(tmp_path: Path) -> None:
    path = tmp_path / "resolved.ndjson"
    path.write_bytes(b'{"name":"\xff"}\n')

    with pytest.raises(CorruptArtifactError):
        list(iter_resolved(path))


def test_explicit_zero_byte_cap_rejected(
    tmp_path: Path, resolved_record: dict[str, object]
) -> None:
    path = tmp_path / "resolved.ndjson"
    path.write_text(json.dumps(resolved_record), encoding="utf-8")

    with pytest.raises(LimitExceeded):
        list(iter_resolved(path, max_bytes=0))
