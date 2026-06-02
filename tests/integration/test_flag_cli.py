from __future__ import annotations

from pathlib import Path
from typing import Any

from repolens import cli
from repolens.data import store


def _record(
    *,
    name: str,
    spdx_id: str | None,
    repo: str,
    version: str = "1.0",
    url: str | None = "https://example.invalid/license",
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"source_layer": "syft", "anchor": spdx_id or "NONE"}
    if url is not None:
        evidence["url"] = url
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "name": name,
        "version": version,
        "repo": repo,
        "evidence": evidence,
        "tags": {"origin": "third-party-oss", "scope": "runtime", "distribution": "server"},
        "modified": "unknown",
    }
    record["spdx_id"] = spdx_id
    return record


def test_flag_over_fixture_workdir(tmp_path: Path) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [
            _record(name="acme-agpl", spdx_id="AGPL-3.0-only", repo="acme-alpha", version="1.0"),
            _record(name="acme-mit", spdx_id="MIT", repo="acme-alpha"),
            _record(name="acme-none", spdx_id=None, repo="acme-alpha", url=None),
        ],
    )
    store.write_resolved(
        tmp_path,
        "acme-beta",
        [
            _record(name="acme-agpl", spdx_id="AGPL-3.0-only", repo="acme-beta", version="2.0"),
            _record(name="acme-lgpl", spdx_id="LGPL-3.0-only", repo="acme-beta"),
        ],
    )

    code = cli.main(["flag", "--work-root", str(tmp_path)])

    assert code == 1
    inventory = store.read_inventory(tmp_path)
    shortlist = store.read_shortlist(tmp_path)

    components = {component["name"]: component for component in inventory["components"]}
    # acme-agpl is deduplicated across both repos into one component.
    assert components["acme-agpl"]["versions"] == ["1.0", "2.0"]
    assert components["acme-agpl"]["found_in"] == ["acme-alpha", "acme-beta"]
    assert components["acme-agpl"]["policy_tier"] == "BLOCK"
    assert components["acme-mit"]["policy_tier"] == "ALLOW"

    items = {item["component_ref"]: item for item in shortlist["items"]}
    assert items["acme-agpl|AGPL-3.0-only"]["reason"] == "BLOCK"
    assert items["acme-lgpl|LGPL-3.0-only"]["reason"] == "REVIEW"
    unknown = items["acme-none|UNKNOWN"]
    assert unknown["reason"] == "UNKNOWN"
    assert unknown["candidate_spdx"] is None
    # MIT (ALLOW) is not flagged; the other three are open.
    assert "acme-mit|MIT" not in items
    assert shortlist["open_count"] == 3
    assert (tmp_path / "shortlist.md").exists()


def test_flag_all_allow_exits_zero(tmp_path: Path) -> None:
    store.write_resolved(
        tmp_path,
        "acme-alpha",
        [_record(name="acme-mit", spdx_id="MIT", repo="acme-alpha")],
    )

    code = cli.main(["flag", "--work-root", str(tmp_path)])

    assert code == 0
    shortlist = store.read_shortlist(tmp_path)
    assert shortlist["open_count"] == 0
    assert shortlist["items"] == []
    assert len(store.read_inventory(tmp_path)["components"]) == 1


def test_flag_empty_workdir_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()

    code = cli.main(["flag", "--work-root", str(tmp_path)])

    assert code == 0
    assert store.read_inventory(tmp_path)["components"] == []
    assert store.read_shortlist(tmp_path)["open_count"] == 0
    assert (tmp_path / "shortlist.md").exists()


def test_flag_missing_workdir_exits_zero(tmp_path: Path) -> None:
    # No work/ directory at all — flag must write empty artifacts and exit 0, unlike report.
    code = cli.main(["flag", "--work-root", str(tmp_path)])

    assert code == 0
    assert store.read_inventory(tmp_path)["components"] == []
    assert store.read_shortlist(tmp_path)["items"] == []
