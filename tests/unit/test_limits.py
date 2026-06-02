from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data.errors import CorruptArtifactError, LimitExceeded
from repolens.data.store import load_json_capped, write_inventory, write_resolved


def test_oversize_file_rejected_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    def fail_stat(_: Path) -> object:
        raise AssertionError("size guard should not rely on a separate stat")

    def fail_parse(_: bytes) -> object:
        raise AssertionError("parser should not run")

    monkeypatch.setattr(Path, "stat", fail_stat)
    monkeypatch.setattr("repolens.data.store.json.loads", fail_parse)

    with pytest.raises(LimitExceeded):
        load_json_capped(path, max_bytes=1)


def test_overdeep_json_rejected_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text("[" * 70 + "0" + "]" * 70, encoding="utf-8")

    def fail_parse(_: bytes) -> object:
        raise AssertionError("parser should not run")

    monkeypatch.setattr("repolens.data.store.json.loads", fail_parse)

    with pytest.raises(LimitExceeded):
        load_json_capped(path, max_bytes=10_000, max_depth=64)


def test_within_caps_passes(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps({"items": [{"name": "acme-lib"}]}), encoding="utf-8")

    assert load_json_capped(path, max_bytes=10_000, max_depth=64)["items"][0]["name"] == "acme-lib"


def test_invalid_utf8_json_raises_corrupt_artifact(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"name":"\xff"}')

    with pytest.raises(CorruptArtifactError):
        load_json_capped(path, max_bytes=10_000, max_depth=64)


def test_write_json_artifact_enforces_caps(
    tmp_path: Path, inventory: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("repolens.data.store.max_bytes_for", lambda _: 8)

    with pytest.raises(LimitExceeded):
        write_inventory(tmp_path, inventory)


def test_write_resolved_enforces_caps(
    tmp_path: Path,
    repo_ref: str,
    resolved_record: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("repolens.data.store.max_bytes_for", lambda _: 8)

    with pytest.raises(LimitExceeded):
        write_resolved(tmp_path, repo_ref, [resolved_record])
