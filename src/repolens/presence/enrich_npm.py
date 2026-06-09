"""Bounded npm/package-manager presence enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urlsplit

from repolens.presence.models import InstallState, PlatformMatch, Relation
from repolens.resolve.models import PackageFact

_LOCKFILES = frozenset({"package-lock.json", "pnpm-lock.yaml", "yarn.lock"})


@dataclass(frozen=True, slots=True)
class NpmPresenceEnrichment:
    install_state: InstallState = "unknown"
    relation: Relation = "unknown"
    path: tuple[str, ...] = ()
    platform_match: PlatformMatch = "unknown"


def enrich(package: PackageFact, *, target: str = "unknown") -> NpmPresenceEnrichment:
    """Derive npm presence metadata from the already-parsed SBOM package fact."""

    if package.package_type.casefold() != "npm":
        return NpmPresenceEnrichment()
    locations = tuple(location.strip() for location in package.locations if location.strip())
    path = _node_modules_path(locations)
    return NpmPresenceEnrichment(
        install_state=_install_state(locations),
        relation=_relation(package.purl, locations, path),
        path=path,
        platform_match=_platform_match(package.purl, target=target),
    )


def _install_state(locations: tuple[str, ...]) -> InstallState:
    if any(_is_node_modules_path(location) for location in locations):
        return "installed"
    if locations and all(_is_lockfile(location) for location in locations):
        return "lockfile_only"
    return "unknown"


def _relation(purl: str | None, locations: tuple[str, ...], path: tuple[str, ...]) -> Relation:
    qualifier = _dependency_qualifier(purl)
    if qualifier is not None:
        return qualifier
    if len(path) > 1:
        return "transitive"
    if path:
        return "direct"
    if any(_is_top_level_package_json(location) for location in locations):
        return "direct"
    return "unknown"


def _dependency_qualifier(purl: str | None) -> Relation | None:
    if not purl:
        return None
    for key, value in parse_qsl(urlsplit(purl).query):
        if key.casefold() not in {"dependency", "dependency_type", "dependency-type"}:
            continue
        if value in {"optional", "dev", "peer", "devOptional"}:
            return value
    return None


def _node_modules_path(locations: tuple[str, ...]) -> tuple[str, ...]:
    for location in locations:
        if not _is_node_modules_path(location):
            continue
        parts = PurePosixPath(location).parts
        packages: list[str] = []
        index = 0
        while index < len(parts):
            if parts[index] != "node_modules":
                index += 1
                continue
            index += 1
            if index >= len(parts):
                break
            package = parts[index]
            if package.startswith("@") and index + 1 < len(parts):
                package = f"{package}/{parts[index + 1]}"
                index += 1
            packages.append(package)
            index += 1
        if packages:
            return tuple(packages)
    return ()


def _platform_match(purl: str | None, *, target: str) -> PlatformMatch:
    if not purl or target == "unknown":
        return "unknown"
    qualifiers = {key: value for key, value in parse_qsl(urlsplit(purl).query)}
    if not any(key in qualifiers for key in ("os", "cpu", "libc")):
        return "unknown"
    target_text = target.casefold()
    values = {value.casefold() for value in qualifiers.values()}
    if target_text in values:
        return "target"
    return "cross_platform"


def _is_node_modules_path(location: str) -> bool:
    return "node_modules" in PurePosixPath(location).parts


def _is_lockfile(location: str) -> bool:
    return PurePosixPath(location).name in _LOCKFILES


def _is_top_level_package_json(location: str) -> bool:
    path = PurePosixPath(location)
    return path.name == "package.json" and "node_modules" not in path.parts
