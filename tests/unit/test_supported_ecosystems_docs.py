from __future__ import annotations

from pathlib import Path

from repolens.resolve.ecosystems import (
    CATALOGING_ONLY_ECOSYSTEMS,
    CI_ONLY_ECOSYSTEMS,
    DEPS_DEV_SYSTEM_TO_PUBLIC_ECOSYSTEM,
    ECOSYSTEM_TO_DEPS_DEV,
    MOBILE_METADATA_ECOSYSTEMS,
    RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS,
    SUPPORTED_ECOSYSTEMS,
)


def test_supported_ecosystem_matrix_matches_resolver_mapping(repo_root: Path) -> None:
    docs = repo_root / "docs" / "usage.md"
    rows = _parse_supported_ecosystem_rows(docs.read_text(encoding="utf-8"))

    expected = {
        item.key: {
            "cataloged": item.cataloged,
            "api_resolved": item.api_resolved,
        }
        for item in SUPPORTED_ECOSYSTEMS
    }
    assert rows == expected


def test_supported_ecosystem_contract_is_derived_from_resolver_mapping() -> None:
    deps_dev_systems = frozenset(ECOSYSTEM_TO_DEPS_DEV.values())
    supported = {item.key: item for item in SUPPORTED_ECOSYSTEMS}
    resolver_supported = frozenset(
        DEPS_DEV_SYSTEM_TO_PUBLIC_ECOSYSTEM[system] for system in deps_dev_systems
    )

    assert frozenset(DEPS_DEV_SYSTEM_TO_PUBLIC_ECOSYSTEM) == deps_dev_systems
    assert resolver_supported == RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS
    assert frozenset(supported) == (
        RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS | CATALOGING_ONLY_ECOSYSTEMS | CI_ONLY_ECOSYSTEMS
    )
    assert {
        key for key, item in supported.items() if item.api_resolved
    } == RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS | MOBILE_METADATA_ECOSYSTEMS
    assert all(supported[key].cataloged for key in supported)
    assert all(supported[key].api_resolved for key in MOBILE_METADATA_ECOSYSTEMS)
    assert all(not supported[key].api_resolved for key in CI_ONLY_ECOSYSTEMS)


def _parse_supported_ecosystem_rows(text: str) -> dict[str, dict[str, bool]]:
    start = "<!-- repolens-supported-ecosystems:start -->"
    end = "<!-- repolens-supported-ecosystems:end -->"
    block = text.split(start, 1)[1].split(end, 1)[0]
    rows: dict[str, dict[str, bool]] = {}
    for line in block.splitlines():
        if not line.startswith("| ") or "---" in line or "ecosystem" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows[cells[0]] = {
            "cataloged": _yes_no(cells[1]),
            "api_resolved": _yes_no(cells[2]),
        }
    return rows


def _yes_no(value: str) -> bool:
    if value == "yes":
        return True
    if value == "no":
        return False
    raise AssertionError(f"expected yes/no value, got {value!r}")
