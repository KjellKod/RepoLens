"""Unauthenticated package metadata adapters for the resolve stage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from repolens.policy.config import load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.models import ApiCandidate, FetchFunction, PackageFact, ResolveAdapter
from repolens.resolve.purl import package_identity
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, fetch_url

API_ALLOWED_HOSTS = frozenset(
    {
        "api.deps.dev",
        "registry.npmjs.org",
        "pypi.org",
        "repo.maven.apache.org",
        "crates.io",
        "proxy.golang.org",
        "api.github.com",
        "api.clearlydefined.io",
        "api.ecosyste.ms",
    }
)

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

_FETCH_OPTIONS = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})


def build_default_adapters(fetcher: FetchFunction = fetch_url) -> tuple[ResolveAdapter, ...]:
    """Return the deterministic API adapter chain."""

    return (
        DepsDevAdapter(fetcher),
        NativeRegistryAdapter(fetcher),
        ClearlyDefinedAdapter(fetcher),
        EcosysteMsAdapter(fetcher),
    )


@dataclass(frozen=True, slots=True)
class DepsDevAdapter:
    fetcher: FetchFunction

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        system = ECOSYSTEM_TO_DEPS_DEV.get(ecosystem)
        if system is None:
            return None
        url = (
            "https://api.deps.dev/v3alpha/systems/"
            f"{quote(system, safe='')}/packages/{quote(package_name, safe='')}"
            f"/versions/{quote(package.version, safe='')}"
        )
        return _candidate_from_url(self.fetcher, url)


@dataclass(frozen=True, slots=True)
class NativeRegistryAdapter:
    fetcher: FetchFunction

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        url = _native_registry_url(ecosystem, package_name, package.version)
        if url is None:
            return None
        return _candidate_from_url(self.fetcher, url)


@dataclass(frozen=True, slots=True)
class ClearlyDefinedAdapter:
    fetcher: FetchFunction

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        source = _clearly_defined_source(ecosystem)
        if source is None:
            return None
        url = (
            "https://api.clearlydefined.io/definitions/"
            f"{source}/{quote(ecosystem, safe='')}/-/{quote(package_name, safe='')}/"
            f"{quote(package.version, safe='')}"
        )
        return _candidate_from_url(self.fetcher, url)


@dataclass(frozen=True, slots=True)
class EcosysteMsAdapter:
    fetcher: FetchFunction

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        url = (
            "https://api.ecosyste.ms/packages/lookup"
            f"?ecosystem={quote(ecosystem, safe='')}&name={quote(package_name, safe='')}"
        )
        return _candidate_from_url(self.fetcher, url)


def _native_registry_url(ecosystem: str, package_name: str, version: str) -> str | None:
    if ecosystem in {"python", "pypi"}:
        return (
            f"https://pypi.org/pypi/{quote(package_name, safe='')}/{quote(version, safe='')}/json"
        )
    if ecosystem == "npm":
        return (
            f"https://registry.npmjs.org/{quote(package_name, safe='')}/{quote(version, safe='')}"
        )
    if ecosystem in {"cargo", "rust"}:
        name = quote(package_name, safe="")
        package_version = quote(version, safe="")
        return f"https://crates.io/api/v1/crates/{name}/{package_version}"
    if ecosystem in {"golang", "gomod", "go-module"}:
        name = quote(package_name, safe="")
        package_version = quote(version, safe="")
        return f"https://proxy.golang.org/{name}/@v/{package_version}.info"
    if ecosystem == "maven":
        return (
            "https://repo.maven.apache.org/maven2/"
            f"{quote(package_name.replace('.', '/'), safe='/')}/{quote(version, safe='')}/"
        )
    return None


def _clearly_defined_source(ecosystem: str) -> str | None:
    if ecosystem in {"npm", "pypi", "maven", "cargo"}:
        return "registry"
    if ecosystem in {"golang", "gomod", "go-module"}:
        return "git"
    return None


def _candidate_from_url(fetcher: FetchFunction, url: str) -> ApiCandidate | None:
    try:
        result = fetcher(url, _FETCH_OPTIONS)
    except FetchSecurityError:
        return None
    policy = load_default_policy()
    for license_text in target_license_candidates(result.body):
        normalized = normalize_license(license_text, policy)
        if normalized.spdx_id is not None:
            return ApiCandidate(
                spdx_id=normalized.spdx_id,
                evidence_url=result.url,
                evidence_anchor=license_text,
            )
    return None


def target_license_candidates(body: bytes) -> tuple[str, ...]:
    """Return license strings from known target-package fields only."""

    text = body.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return (text,)
    if not isinstance(payload, dict):
        return ()

    found: list[str] = []
    for path in _TARGET_LICENSE_PATHS:
        found.extend(_strings_at_path(payload, path))
    return tuple(dict.fromkeys(found))


_TARGET_LICENSE_PATHS = (
    ("license",),
    ("licenses",),
    ("normalized_licenses",),
    ("info", "license"),
    ("info", "licenses"),
    ("version", "license"),
    ("version", "licenses"),
    ("crate", "license"),
    ("licensed", "declared"),
    ("licensed", "facets", "core", "attribution", "parties", "0", "license"),
)


def _strings_at_path(payload: dict[str, object], path: tuple[str, ...]) -> tuple[str, ...]:
    current: object = payload
    for segment in path:
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            current = current[index] if index < len(current) else None
        else:
            return ()
    return _license_strings(current)


def _license_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        stripped = value.strip()
        return (stripped,) if stripped else ()
    if isinstance(value, dict):
        for key in ("id", "type", "name"):
            child = value.get(key)
            if isinstance(child, str) and child.strip():
                return (child.strip(),)
        return ()
    if isinstance(value, list):
        found: list[str] = []
        for item in value:
            found.extend(_license_strings(item))
        return tuple(found)
    return ()
