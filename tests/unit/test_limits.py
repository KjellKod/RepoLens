from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data.errors import LimitExceeded
from repolens.data.store import load_json_capped


def test_oversize_file_rejected_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    def fail_parse(_: bytes) -> object:
        raise AssertionError("parser should not run")

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
