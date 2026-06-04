"""Supported ecosystem mapping for resolver behavior and documentation sync."""

from __future__ import annotations

from dataclasses import dataclass

from repolens.resolve.models import PackageFact
from repolens.resolve.purl import package_identity

ECOSYSTEM_TO_DEPS_DEV = {
    "cargo": "cargo",
    "golang": "go",
    "gomod": "go",
    "go-module": "go",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "python": "pypi",
    "pypi": "pypi",
    "gem": "rubygems",
    "ruby": "rubygems",
    "rubygems": "rubygems",
    "rust": "cargo",
}

RESOLVER_SUPPORTED_ECOSYSTEMS = frozenset(ECOSYSTEM_TO_DEPS_DEV)
DEPS_DEV_SYSTEM_TO_PUBLIC_ECOSYSTEM = {
    "cargo": "cargo",
    "go": "go-module",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pypi": "pypi",
    "rubygems": "rubygems",
}
RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS = frozenset(
    DEPS_DEV_SYSTEM_TO_PUBLIC_ECOSYSTEM[system]
    for system in frozenset(ECOSYSTEM_TO_DEPS_DEV.values())
)
CATALOGING_ONLY_ECOSYSTEMS = frozenset({"swift", "cocoapods"})
CI_ONLY_ECOSYSTEMS = frozenset({"githubactions"})
CI_ONLY_PACKAGE_TYPES = frozenset({"github-action", "githubactions"})
BUILD_TOOL_LOCATION_PREFIXES = frozenset(
    {
        ".github/",
        "pyproject.toml#project.optional-dependencies.build",
        "pyproject.toml#project.optional-dependencies.ci",
        "pyproject.toml#project.optional-dependencies.dev",
        "pyproject.toml#project.optional-dependencies.docs",
        "pyproject.toml#project.optional-dependencies.lint",
        "pyproject.toml#project.optional-dependencies.test",
        "pyproject.toml#project.optional-dependencies.tests",
        "requirements-dev.txt",
        "src/repolens/bootstrap/scancode.requirements.txt",
        "tests/bootstrap/fixtures",
        "tests/fixtures",
    }
)


@dataclass(frozen=True, slots=True)
class EcosystemSupport:
    key: str
    cataloged: bool
    api_resolved: bool
    notes: str


_ECOSYSTEM_NOTES = {
    "cargo": "Rust crates resolve through deps.dev/Crates.",
    "cocoapods": "Cataloged only; unresolved without SBOM license.",
    "githubactions": "Build/CI inventory; excluded from shipped main.",
    "go-module": "Go modules resolve through deps.dev/proxy data.",
    "maven": "Maven purls include Gradle-originated dependencies.",
    "npm": "npm packages resolve through deps.dev/npm registry data.",
    "nuget": "NuGet packages resolve through deps.dev.",
    "pypi": "Python packages include Syft and pyproject facts.",
    "rubygems": "Ruby gems resolve through deps.dev.",
    "swift": "Cataloged only; unresolved without SBOM license.",
}


def _supported_ecosystems() -> tuple[EcosystemSupport, ...]:
    keys = RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS | CATALOGING_ONLY_ECOSYSTEMS | CI_ONLY_ECOSYSTEMS
    return tuple(
        EcosystemSupport(
            key,
            cataloged=True,
            api_resolved=key in RESOLVER_SUPPORTED_PUBLIC_ECOSYSTEMS,
            notes=_ECOSYSTEM_NOTES[key],
        )
        for key in sorted(keys)
    )


SUPPORTED_ECOSYSTEMS = _supported_ecosystems()


def is_cataloging_only_package(package: PackageFact) -> bool:
    ecosystem, _package_name = package_identity(package.package_type, package.name, package.purl)
    return ecosystem in CATALOGING_ONLY_ECOSYSTEMS


def is_ci_only_package(package: PackageFact) -> bool:
    ecosystem, _package_name = package_identity(package.package_type, package.name, package.purl)
    if ecosystem in CI_ONLY_ECOSYSTEMS or package.package_type.lower() in CI_ONLY_PACKAGE_TYPES:
        return True
    locations = tuple(location for location in package.locations if location.strip())
    return bool(locations) and all(
        _location_matches_prefix(location, BUILD_TOOL_LOCATION_PREFIXES) for location in locations
    )


def _location_matches_prefix(location: str, prefixes: frozenset[str]) -> bool:
    normalized = location.strip().replace("\\", "/").lstrip("/")
    normalized_prefixes = tuple(prefix.strip().replace("\\", "/").strip("/") for prefix in prefixes)
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}/")
        for prefix in normalized_prefixes
        if prefix
    )
