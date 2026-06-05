from __future__ import annotations

import pytest

from repolens.policy import load_default_policy
from repolens.resolve.adapters import (
    API_ALLOWED_HOSTS,
    build_default_adapters,
    target_license_candidates,
)
from repolens.resolve.license_expression import license_resolution_id
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


def test_adapter_carries_compound_spdx_expression_candidate() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"Apache-2.0 OR MIT"}')

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="anyhow",
            version="1.0.98",
            package_type="cargo",
            repo="acme-alpha",
            purl="pkg:cargo/anyhow@1.0.98",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "Apache-2.0 OR MIT"
    assert candidate.evidence_anchor == "Apache-2.0 OR MIT"


def test_license_resolution_id_accepts_apache_with_llvm_exception() -> None:
    expression = "Apache-2.0 WITH LLVM-exception"

    assert license_resolution_id(expression, load_default_policy()) == expression


def test_license_resolution_id_accepts_zope_public_license() -> None:
    policy = load_default_policy()

    assert license_resolution_id("ZPL-2.1", policy) == "ZPL-2.1"
    assert license_resolution_id("Zope Public License", policy) == "ZPL-2.1"


def test_deep_compound_expression_fails_closed() -> None:
    expression = ("(" * 2_000) + "MIT" + (")" * 2_000)

    assert license_resolution_id(expression, load_default_policy()) is None


@pytest.mark.parametrize(
    "expression",
    [
        "GPL-3.0-only WITH Unknown-exception",
        "AGPL-3.0-only WITH Autoconf-exception-3.0",
    ],
)
def test_adapter_rejects_unsupported_with_exception_candidate(expression: str) -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=f'{{"license":"{expression}"}}'.encode(),
        )

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="acme-lib",
            version="1.2.3",
            package_type="cargo",
            repo="acme-alpha",
            purl="pkg:cargo/acme-lib@1.2.3",
            declared_license_raw=None,
        )
    )

    assert candidate is None


def test_python_adapter_resolves_zpl_from_pypi_metadata() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=b'{"info":{"license":"ZPL-2.1"}}')

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(
            name="zope.site",
            version="6.0",
            package_type="python",
            repo="acme-alpha",
            purl="pkg:pypi/zope.site@6.0",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "ZPL-2.1"
    assert candidate.evidence_anchor == "ZPL-2.1"


def test_adapter_reads_structured_github_license_spdx_id() -> None:
    assert target_license_candidates(b'{"license":{"spdx_id":"Apache-2.0"}}') == ("Apache-2.0",)


def test_python_adapter_reads_exact_license_expression_field() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"info":{"license_expression":"MIT OR Apache-2.0"}}',
        )

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(
            name="sentinel-runtime",
            version="1.0.0",
            package_type="python",
            repo="acme-alpha",
            purl="pkg:pypi/sentinel-runtime@1.0.0",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "MIT OR Apache-2.0"
    assert candidate.evidence_anchor == "MIT OR Apache-2.0"


def test_adapter_carries_known_with_exception_candidate() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"license":"GPL-3.0-only WITH Autoconf-exception-3.0"}',
        )

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="acme-lib",
            version="1.2.3",
            package_type="cargo",
            repo="acme-alpha",
            purl="pkg:cargo/acme-lib@1.2.3",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "GPL-3.0-only WITH Autoconf-exception-3.0"
    assert candidate.evidence_anchor == "GPL-3.0-only WITH Autoconf-exception-3.0"


def test_adapter_carries_apache_with_llvm_exception_candidate() -> None:
    expression = "Apache-2.0 WITH LLVM-exception"

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"license":"Apache-2.0 WITH LLVM-exception"}',
        )

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="acme-lib",
            version="1.2.3",
            package_type="cargo",
            repo="acme-alpha",
            purl="pkg:cargo/acme-lib@1.2.3",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == expression
    assert candidate.evidence_anchor == expression


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


@pytest.mark.parametrize(
    ("name", "version", "purl", "expected_url"),
    [
        (
            "@img/sharp-win32-x64",
            "0.33.5",
            "pkg:npm/%40img/sharp-win32-x64@0.33.5",
            "https://api.deps.dev/v3alpha/systems/npm/packages/"
            "@img%2Fsharp-win32-x64/versions/0.33.5",
        ),
        (
            "left-pad",
            "1.3.0",
            "pkg:npm/left-pad@1.3.0",
            "https://api.deps.dev/v3alpha/systems/npm/packages/left-pad/versions/1.3.0",
        ),
    ],
)
def test_deps_dev_npm_url_preserves_scoped_at_and_encodes_slash(
    name: str, version: str, purl: str, expected_url: str
) -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(name, version, "npm", "acme-alpha", purl, None)
    )

    assert candidate is not None
    assert seen == [expected_url]


@pytest.mark.parametrize(
    ("name", "version", "purl", "expected_url"),
    [
        (
            "@img/sharp-win32-x64",
            "0.33.5",
            "pkg:npm/%40img/sharp-win32-x64@0.33.5",
            "https://registry.npmjs.org/@img%2Fsharp-win32-x64/0.33.5",
        ),
        (
            "left-pad",
            "1.3.0",
            "pkg:npm/left-pad@1.3.0",
            "https://registry.npmjs.org/left-pad/1.3.0",
        ),
    ],
)
def test_native_npm_url_preserves_scoped_at_and_encodes_slash(
    name: str, version: str, purl: str, expected_url: str
) -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(name, version, "npm", "acme-alpha", purl, None)
    )

    assert candidate is not None
    assert seen == [expected_url]


def test_gradle_maven_purl_routes_to_maven() -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"Apache-2.0"}')

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="ignored-gradle-name",
            version="3.4.5",
            package_type="gradle",
            repo="sentinel-repo",
            purl="pkg:maven/invalid.sentinel/sentinel-gradle-runtime@3.4.5",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "Apache-2.0"
    assert seen == [
        (
            "https://api.deps.dev/v3alpha/systems/maven/packages/"
            "invalid.sentinel%2Fsentinel-gradle-runtime/versions/3.4.5"
        )
    ]


def test_unversioned_pypi_package_uses_package_metadata_endpoint() -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"info":{"license":"MIT"}}')

    package = PackageFact(
        name="sentinel-runtime",
        version="unknown",
        package_type="python",
        repo="sentinel-repo",
        purl="pkg:pypi/sentinel-runtime",
        declared_license_raw=None,
    )

    adapters = build_default_adapters(fetcher)
    assert adapters[0].resolve(package) is None
    candidate = adapters[1].resolve(package)

    assert candidate is not None
    assert candidate.spdx_id == "MIT"
    assert seen == ["https://pypi.org/pypi/sentinel-runtime/json"]


def test_rubygems_exact_version_adapter_reads_non_empty_licenses() -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"licenses":["MIT"]}')

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(
            name="babosa",
            version="1.0.4",
            package_type="gem",
            repo="acme-alpha",
            purl="pkg:gem/babosa@1.0.4",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "MIT"
    assert seen == ["https://rubygems.org/api/v2/rubygems/babosa/versions/1.0.4.json"]


def test_rubygems_empty_license_array_remains_unresolved() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=b'{"licenses":[]}')

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(
            name="babosa",
            version="1.0.4",
            package_type="gem",
            repo="acme-alpha",
            purl="pkg:gem/babosa@1.0.4",
            declared_license_raw=None,
        )
    )

    assert candidate is None


@pytest.mark.parametrize(
    ("package", "expected_url", "body", "expected_spdx"),
    [
        (
            PackageFact("click", "8.1.8", "python", "acme-alpha", "pkg:pypi/click@8.1.8", None),
            "https://api.clearlydefined.io/definitions/pypi/pypi/-/click/8.1.8",
            b'{"licensed":{"declared":"BSD-2-Clause AND BSD-3-Clause"}}',
            "BSD-2-Clause AND BSD-3-Clause",
        ),
        (
            PackageFact("babosa", "1.0.4", "gem", "acme-alpha", "pkg:gem/babosa@1.0.4", None),
            "https://api.clearlydefined.io/definitions/gem/rubygems/-/babosa/1.0.4",
            b'{"licensed":{"declared":"MIT"}}',
            "MIT",
        ),
    ],
)
def test_clearlydefined_adapter_uses_exact_ecosystem_coordinates(
    package: PackageFact,
    expected_url: str,
    body: bytes,
    expected_spdx: str,
) -> None:
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=body)

    candidate = build_default_adapters(fetcher)[2].resolve(package)

    assert candidate is not None
    assert candidate.spdx_id == expected_spdx
    assert candidate.evidence_url == expected_url
    assert seen == [expected_url]


def test_npm_caniuse_lite_cc_by_4_resolves_as_review_candidate() -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"CC-BY-4.0"}')

    candidate = build_default_adapters(fetcher)[0].resolve(
        PackageFact(
            name="caniuse-lite",
            version="1.0.30001712",
            package_type="npm",
            repo="acme-alpha",
            purl="pkg:npm/caniuse-lite@1.0.30001712",
            declared_license_raw=None,
        )
    )

    assert candidate is not None
    assert candidate.spdx_id == "CC-BY-4.0"


@pytest.mark.parametrize("license_text", ["BSD", "BSD License", "Public Domain"])
def test_ambiguous_public_metadata_labels_remain_unresolved(license_text: str) -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=f'{{"info":{{"license":"{license_text}"}}}}'.encode(),
        )

    candidate = build_default_adapters(fetcher)[1].resolve(
        PackageFact(
            name="click",
            version="8.1.8",
            package_type="python",
            repo="acme-alpha",
            purl="pkg:pypi/click@8.1.8",
            declared_license_raw=None,
        )
    )

    assert candidate is None


@pytest.mark.parametrize(
    "package",
    [
        PackageFact(
            "sentinel-swift-runtime",
            "1.0.0",
            "swift",
            "sentinel-repo",
            "pkg:swift/sentinel-swift-runtime@1.0.0",
            None,
        ),
        PackageFact(
            "SentinelPodRuntime",
            "2.0.0",
            "cocoapods",
            "sentinel-repo",
            "pkg:cocoapods/SentinelPodRuntime@2.0.0",
            None,
        ),
    ],
)
def test_mobile_cataloging_only_ecosystems_do_not_fetch(package: PackageFact) -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del url, options
        raise AssertionError("cataloging-only mobile packages should not hit API adapters")

    assert [adapter.resolve(package) for adapter in build_default_adapters(fetcher)] == [
        None,
        None,
        None,
        None,
    ]


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
