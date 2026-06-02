"""Tests for the tool_versions.json artifact (AC #5)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from repolens.bootstrap.record import VERSIONS_SCHEMA, write_tool_versions
from repolens.bootstrap.syft import ResolvedTool

from .conftest import PLATFORM


def test_records_all_tools_with_required_fields(test_pins, tmp_path):
    resolved = [
        ResolvedTool(
            name="syft",
            version="1.18.1",
            digest=test_pins.tool("syft").artifact_for(PLATFORM).sha256,
            path=Path("/w/syft"),
            source="https://example/syft",
        ),
        ResolvedTool(
            name="cosign",
            version="2.4.1",
            digest=test_pins.tool("cosign").artifact_for(PLATFORM).sha256,
            path=Path("/w/cosign"),
            source=None,
        ),
    ]
    out = tmp_path / "tool_versions.json"
    write_tool_versions(test_pins, resolved, out, now=dt.datetime(2026, 6, 1, tzinfo=dt.UTC))

    payload = json.loads(out.read_text())
    assert payload["schema"] == VERSIONS_SCHEMA
    assert payload["generated_at"].startswith("2026-06-01")
    assert "@sha256:" in payload["base_image"]

    # Every pinned tool appears with {version, digest, source}.
    for name in ("syft", "cosign", "scancode", "git", "gh"):
        entry = payload["tools"][name]
        assert set(entry) == {"version", "digest", "source"}
        assert entry["version"]

    # Resolved tools carry the measured digest.
    assert payload["tools"]["syft"]["digest"] == resolved[0].digest


def test_pinned_only_tools_fall_back_to_manifest_digest(test_pins, tmp_path):
    out = tmp_path / "tv.json"
    write_tool_versions(test_pins, [], out)
    payload = json.loads(out.read_text())
    # git/gh were not "resolved" but still have a recorded pinned digest.
    assert payload["tools"]["git"]["digest"] == "a" * 64
    assert payload["tools"]["gh"]["digest"] == "b" * 64
