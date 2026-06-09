from __future__ import annotations

import json
from pathlib import Path

from repolens.presence.enrich_npm import enrich
from repolens.resolve.models import PackageFact


def test_real_sharp_fixture_lockfile_only(repo_root: Path) -> None:
    fixture = repo_root / "tests" / "fixtures" / "resolve" / "resolver_coverage" / "sbom.syft.json"
    sbom = json.loads(fixture.read_text(encoding="utf-8"))
    artifact = next(
        item for item in sbom["artifacts"] if item["purl"].startswith("pkg:npm/%40img/sharp")
    )

    enrichment = enrich(_fact(artifact))

    assert artifact["locations"] == ["package-lock.json"]
    assert enrichment.install_state == "lockfile_only"
    assert enrichment.relation == "unknown"


def test_node_modules_location_is_installed_and_path_is_parsed() -> None:
    enrichment = enrich(
        PackageFact(
            name="sharp",
            version="1.0.0",
            package_type="npm",
            repo="acme",
            purl="pkg:npm/sharp@1.0.0",
            declared_license_raw=None,
            locations=("node_modules/next/node_modules/sharp/package.json",),
        )
    )

    assert enrichment.install_state == "installed"
    assert enrichment.relation == "transitive"
    assert enrichment.path == ("next", "sharp")


def test_optional_qualifier_sets_relation_without_lockfile_parser() -> None:
    enrichment = enrich(
        PackageFact(
            name="sharp",
            version="1.0.0",
            package_type="npm",
            repo="acme",
            purl="pkg:npm/sharp@1.0.0?dependency=optional",
            declared_license_raw=None,
            locations=("package-lock.json",),
        )
    )

    assert enrichment.install_state == "lockfile_only"
    assert enrichment.relation == "optional"


def test_non_npm_degrades_to_unknown() -> None:
    enrichment = enrich(
        PackageFact(
            name="acme",
            version="1.0.0",
            package_type="python",
            repo="acme",
            purl="pkg:pypi/acme@1.0.0",
            declared_license_raw=None,
            locations=("requirements.txt",),
        )
    )

    assert enrichment.install_state == "unknown"
    assert enrichment.relation == "unknown"
    assert enrichment.path == ()


def _fact(artifact: dict[str, object]) -> PackageFact:
    return PackageFact(
        name=str(artifact["name"]),
        version=str(artifact["version"]),
        package_type=str(artifact["type"]),
        repo="fixture",
        purl=str(artifact["purl"]),
        declared_license_raw=None,
        locations=tuple(str(location) for location in artifact["locations"]),
    )
