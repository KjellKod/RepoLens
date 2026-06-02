from __future__ import annotations

import pytest

from repolens.resolve.adapters import API_ALLOWED_HOSTS, build_default_adapters
from repolens.resolve.models import PackageFact
from repolens.resolve.purl import package_identity, parse_purl
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import FetchResult, HttpFetchOptions


def test_parse_purl_extracts_supported_identity() -> None:
    parsed = parse_purl("pkg:npm/%40acme/widget@1.2.3")

    assert parsed is not None
    assert parsed.package_type == "npm"
    assert parsed.namespace == "@acme"
    assert parsed.name == "widget"
    assert parsed.version == "1.2.3"
    assert package_identity("javascript", "widget", "pkg:npm/%40acme/widget@1.2.3") == (
        "npm",
        "@acme/widget",
    )


def test_parse_purl_rejects_malformed_values() -> None:
    assert parse_purl(None) is None
    assert parse_purl("not-a-purl") is None
    assert parse_purl("pkg:npm") is None


def test_adapters_use_fixed_allowlist_and_no_auth_headers() -> None:
    seen: list[tuple[str, HttpFetchOptions]] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        seen.append((url, options))
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="acme-lib",
            version="1.2.3",
            package_type="python",
            repo="acme-alpha",
            purl="pkg:pypi/acme-lib@1.2.3",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "MIT"
    assert seen[0][0].startswith("https://api.deps.dev/")
    assert seen[0][1].allowed_hosts == API_ALLOWED_HOSTS
    assert seen[0][1].headers == {}


@pytest.mark.parametrize(
    ("purl", "expected_url"),
    [
        (
            "pkg:nuget/acme-widget@1.2.3",
            "https://api.deps.dev/v3alpha/systems/nuget/packages/acme-widget/versions/1.2.3",
        ),
        (
            "pkg:gem/acme_gem@1.2.3",
            "https://api.deps.dev/v3alpha/systems/rubygems/packages/acme_gem/versions/1.2.3",
        ),
    ],
)
def test_deps_dev_adapter_covers_locked_ecosystems(purl: str, expected_url: str) -> None:
    seen: list[tuple[str, HttpFetchOptions]] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        seen.append((url, options))
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    package_type = purl.split("/", 1)[0].removeprefix("pkg:")
    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="fallback-name",
            version=purl.rsplit("@", 1)[1],
            package_type=package_type,
            repo="acme-alpha",
            purl=purl,
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "MIT"
    assert seen == [(expected_url, HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={}))]


def test_adapter_order_is_deps_dev_then_targeted_fallbacks() -> None:
    names = [type(adapter).__name__ for adapter in build_default_adapters()]

    assert names == [
        "DepsDevAdapter",
        "NativeRegistryAdapter",
        "ClearlyDefinedAdapter",
        "EcosysteMsAdapter",
    ]


def test_fetch_security_failure_returns_no_candidate() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del url, options
        raise FetchSecurityError("response body exceeds size cap")

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact("acme-lib", "1.2.3", "python", "acme-alpha", None, None)
    )

    assert candidate is None


def test_adapters_ignore_unrelated_nested_license_fields() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"dependencies":[{"name":"nested","license":"MIT"}]}',
        )

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact("acme-lib", "1.2.3", "python", "acme-alpha", None, None)
    )

    assert candidate is None


@pytest.mark.parametrize(
    ("package_type", "expected_host"),
    [
        ("python", "https://pypi.org/"),
        ("npm", "https://registry.npmjs.org/"),
        ("cargo", "https://crates.io/"),
    ],
)
def test_native_registry_adapter_targets_allowlisted_hosts(
    package_type: str, expected_host: str
) -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    adapter = build_default_adapters(fetcher)[1]
    assert adapter.resolve(PackageFact("acme-lib", "1.2.3", package_type, "acme-alpha", None, None))
    assert seen[0].startswith(expected_host)
