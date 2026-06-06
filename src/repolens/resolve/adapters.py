"""Unauthenticated package metadata adapters for the resolve stage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from repolens.policy.config import Policy, load_default_policy
from repolens.resolve.descriptions import first_brief_description
from repolens.resolve.ecosystems import ECOSYSTEM_TO_DEPS_DEV, RESOLVER_SUPPORTED_ECOSYSTEMS
from repolens.resolve.license_expression import license_resolution_id
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
        "rubygems.org",
        "trunk.cocoapods.org",
        "raw.githubusercontent.com",
    }
)

_FETCH_OPTIONS = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
_UNKNOWN_VERSION = "unknown"


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
        if package.version == _UNKNOWN_VERSION:
            return None
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        system = ECOSYSTEM_TO_DEPS_DEV.get(ecosystem)
        if system is None:
            return None
        url = (
            "https://api.deps.dev/v3alpha/systems/"
            f"{quote(system, safe='')}/packages/{_quote_deps_dev_package(system, package_name)}"
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
        coordinates = _clearly_defined_coordinates(ecosystem)
        if coordinates is None:
            return None
        source, provider = coordinates
        url = (
            "https://api.clearlydefined.io/definitions/"
            f"{source}/{quote(provider, safe='')}/-/{quote(package_name, safe='')}/"
            f"{quote(package.version, safe='')}"
        )
        return _candidate_from_url(self.fetcher, url)


@dataclass(frozen=True, slots=True)
class EcosysteMsAdapter:
    fetcher: FetchFunction

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
        if ecosystem not in RESOLVER_SUPPORTED_ECOSYSTEMS:
            return None
        url = (
            "https://api.ecosyste.ms/packages/lookup"
            f"?ecosystem={quote(ecosystem, safe='')}&name={quote(package_name, safe='')}"
        )
        return _candidate_from_url(self.fetcher, url)


def _native_registry_url(ecosystem: str, package_name: str, version: str) -> str | None:
    if ecosystem in {"python", "pypi"}:
        if version == _UNKNOWN_VERSION:
            return f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"
        return (
            f"https://pypi.org/pypi/{quote(package_name, safe='')}/{quote(version, safe='')}/json"
        )
    if ecosystem == "npm":
        return (
            f"https://registry.npmjs.org/{_quote_npm_package(package_name)}/"
            f"{quote(version, safe='')}"
        )
    if ecosystem in {"cargo", "rust"}:
        name = quote(package_name, safe="")
        package_version = quote(version, safe="")
        return f"https://crates.io/api/v1/crates/{name}/{package_version}"
    if ecosystem in {"golang", "gomod", "go-module"}:
        name = quote(package_name, safe="")
        package_version = quote(version, safe="")
        return f"https://proxy.golang.org/{name}/@v/{package_version}.info"
    if ecosystem in {"gem", "ruby", "rubygems"}:
        if version == _UNKNOWN_VERSION:
            return None
        return (
            f"https://rubygems.org/api/v2/rubygems/{quote(package_name, safe='')}"
            f"/versions/{quote(version, safe='')}.json"
        )
    if ecosystem == "maven":
        return (
            "https://repo.maven.apache.org/maven2/"
            f"{quote(package_name.replace('.', '/'), safe='/')}/{quote(version, safe='')}/"
        )
    return None


def package_description(package: PackageFact, fetcher: FetchFunction = fetch_url) -> str | None:
    """Return a brief package description from official registry metadata."""

    ecosystem, package_name = package_identity(package.package_type, package.name, package.purl)
    url = _description_registry_url(ecosystem, package_name, package.version)
    if url is None:
        return None
    try:
        result = fetcher(url, _FETCH_OPTIONS)
    except Exception:
        return None
    return _description_from_body(result.body)


def _description_registry_url(ecosystem: str, package_name: str, version: str) -> str | None:
    if ecosystem in {"python", "pypi"}:
        if version == _UNKNOWN_VERSION:
            return f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"
        return (
            f"https://pypi.org/pypi/{quote(package_name, safe='')}/{quote(version, safe='')}/json"
        )
    if ecosystem == "npm":
        if version == _UNKNOWN_VERSION:
            return f"https://registry.npmjs.org/{_quote_npm_package(package_name)}"
        return (
            f"https://registry.npmjs.org/{_quote_npm_package(package_name)}/"
            f"{quote(version, safe='')}"
        )
    if ecosystem in {"cargo", "rust"}:
        return f"https://crates.io/api/v1/crates/{quote(package_name, safe='')}"
    if ecosystem in {"gem", "ruby", "rubygems"}:
        return f"https://rubygems.org/api/v1/gems/{quote(package_name, safe='')}.json"
    return None


def _clearly_defined_coordinates(ecosystem: str) -> tuple[str, str] | None:
    if ecosystem == "npm":
        return ("npm", "npm")
    if ecosystem in {"pypi", "python"}:
        return ("pypi", "pypi")
    if ecosystem in {"gem", "ruby", "rubygems"}:
        return ("gem", "rubygems")
    if ecosystem in {"cargo", "rust"}:
        return ("crate", "cratesio")
    if ecosystem == "maven":
        return ("registry", "maven")
    if ecosystem in {"golang", "gomod", "go-module"}:
        return ("git", ecosystem)
    return None


def _candidate_from_url(fetcher: FetchFunction, url: str) -> ApiCandidate | None:
    try:
        result = fetcher(url, _FETCH_OPTIONS)
    except FetchSecurityError:
        return None
    policy = load_default_policy()
    description = _description_from_body(result.body)
    for license_text in target_license_candidates(result.body):
        spdx_id = _license_resolution_id(license_text, policy)
        if spdx_id is not None:
            return ApiCandidate(
                spdx_id=spdx_id,
                evidence_url=result.url,
                evidence_anchor=license_text,
                description=description,
            )
    return None


def _quote_deps_dev_package(system: str, package_name: str) -> str:
    if system == "npm":
        return _quote_npm_package(package_name)
    return quote(package_name, safe="")


def _quote_npm_package(package_name: str) -> str:
    return quote(package_name, safe="@")


def _license_resolution_id(license_text: str, policy: Policy) -> str | None:
    return license_resolution_id(license_text, policy)


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


def target_description_candidates(body: bytes) -> tuple[str, ...]:
    """Return target-package description strings from known metadata fields."""

    text = body.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, dict):
        return ()

    found: list[str] = []
    for path in _TARGET_DESCRIPTION_PATHS:
        found.extend(_description_strings_at_path(payload, path))
    return tuple(dict.fromkeys(found))


def _description_from_body(body: bytes) -> str | None:
    return first_brief_description(target_description_candidates(body))


_TARGET_LICENSE_PATHS = (
    ("license",),
    ("license", "spdx_id"),
    ("licenses",),
    ("normalized_licenses",),
    ("info", "license"),
    ("info", "license_expression"),
    ("info", "licenses"),
    ("version", "license"),
    ("version", "licenses"),
    ("crate", "license"),
    ("license", "spdx_id"),
    ("licensed", "declared"),
    ("licensed", "facets", "core", "attribution", "parties", "0", "license"),
)

_TARGET_DESCRIPTION_PATHS = (
    ("description",),
    ("summary",),
    ("info",),
    ("info", "summary"),
    ("info", "description"),
    ("version", "description"),
    ("crate", "description"),
    ("package", "description"),
)


def _description_strings_at_path(
    payload: dict[str, object], path: tuple[str, ...]
) -> tuple[str, ...]:
    current: object = payload
    for segment in path:
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            current = current[index] if index < len(current) else None
        else:
            return ()
    if isinstance(current, str) and current.strip():
        return (current.strip(),)
    return ()


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
