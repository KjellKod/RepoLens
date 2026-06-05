from __future__ import annotations

import json
from pathlib import Path

from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.resolve.mobile_metadata import resolve_mobile_metadata
from repolens.resolve.models import PackageFact
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.security.limits import SecurityLimits

GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def test_swiftpm_resolves_github_license_api_at_locked_revision(tmp_path: Path) -> None:
    _write_package_resolved(
        tmp_path,
        location="https://github.com/apple/swift-collections.git",
        version="1.4.0",
        revision="abc123def456",
    )
    seen: list[tuple[str, HttpFetchOptions]] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        seen.append((url, options))
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"license":{"spdx_id":"Apache-2.0"}}',
        )

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="swift-collections",
            version="1.4.0",
            package_type="swift",
            repo="ios-app",
            purl="pkg:swift/swift-collections@1.4.0",
            declared_license_raw=None,
            locations=("Package.resolved",),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is not None
    assert candidate.spdx_id == "Apache-2.0"
    assert candidate.evidence_url == (
        "https://api.github.com/repos/apple/swift-collections/license?ref=abc123def456"
    )
    assert candidate.evidence_anchor == "Apache-2.0"
    assert seen == [
        (
            "https://api.github.com/repos/apple/swift-collections/license?ref=abc123def456",
            HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers=GITHUB_API_HEADERS),
        )
    ]


def test_swiftpm_ignores_version_mismatch_and_non_github(tmp_path: Path) -> None:
    _write_package_resolved(
        tmp_path,
        location="https://example.invalid/swift-collections.git",
        version="1.5.0",
        revision="abc123",
    )

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        raise AssertionError(f"unexpected fetch: {url} {options}")

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="swift-collections",
            version="1.4.0",
            package_type="swift",
            repo="ios-app",
            purl="pkg:swift/swift-collections@1.4.0",
            declared_license_raw=None,
            locations=("Package.resolved",),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is None


def test_swiftpm_refuses_symlinked_package_resolved(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    _write_package_resolved(
        outside,
        location="https://github.com/apple/swift-collections.git",
        version="1.4.0",
        revision="abc123",
    )
    (tmp_path / "Package.resolved").symlink_to(outside / "Package.resolved")

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        raise AssertionError(f"unexpected fetch: {url} {options}")

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="swift-collections",
            version="1.4.0",
            package_type="swift",
            repo="ios-app",
            purl="pkg:swift/swift-collections@1.4.0",
            declared_license_raw=None,
            locations=("Package.resolved",),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is None


def test_swiftpm_discovery_fails_closed_when_candidate_cap_exceeded(tmp_path: Path) -> None:
    for index in range(17):
        package_dir = tmp_path / f"Package{index}"
        package_dir.mkdir()
        _write_package_resolved(
            package_dir,
            location="https://github.com/apple/swift-collections.git",
            version="1.4.0",
            revision=f"abc{index}",
        )

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        raise AssertionError(f"unexpected fetch: {url} {options}")

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="swift-collections",
            version="1.4.0",
            package_type="swift",
            repo="ios-app",
            purl="pkg:swift/swift-collections@1.4.0",
            declared_license_raw=None,
            locations=(),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is None


def test_cocoapods_resolves_exact_trunk_spec_from_purl_version(tmp_path: Path) -> None:
    seen: list[tuple[str, HttpFetchOptions]] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        seen.append((url, options))
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":{"type":"MIT"}}')

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="Charts/Core",
            version="4.1.8",
            package_type="cocoapods",
            repo="ios-app",
            purl="pkg:cocoapods/Charts/Core@4.1.8",
            declared_license_raw=None,
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is not None
    assert candidate.spdx_id == "MIT"
    assert candidate.evidence_url == "https://trunk.cocoapods.org/api/v1/pods/Charts/specs/4.1.8"
    assert candidate.evidence_anchor == "MIT"
    assert seen == [
        (
            "https://trunk.cocoapods.org/api/v1/pods/Charts/specs/4.1.8",
            HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, max_redirects=1, headers={}),
        )
    ]


def test_cocoapods_recovers_version_from_podfile_lock(tmp_path: Path) -> None:
    (tmp_path / "Podfile.lock").write_text(
        "PODS:\n  - SentinelPodRuntime (2.0.0)\n", encoding="utf-8"
    )
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.headers == {}
        assert options.max_redirects == 1
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"Apache-2.0"}')

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="SentinelPodRuntime",
            version="unknown",
            package_type="cocoapods",
            repo="ios-app",
            purl="pkg:cocoapods/SentinelPodRuntime",
            declared_license_raw=None,
            locations=("Podfile.lock",),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is not None
    assert candidate.spdx_id == "Apache-2.0"
    assert seen == ["https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0"]


def test_cocoapods_ambiguous_license_metadata_stays_unresolved(tmp_path: Path) -> None:
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"BSD"}')

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="AmbiguousPod",
            version="1.0.0",
            package_type="cocoapods",
            repo="ios-app",
            purl="pkg:cocoapods/AmbiguousPod@1.0.0",
            declared_license_raw=None,
        ),
        source_root=tmp_path,
        fetcher=fetcher,
    )

    assert candidate is None


def test_over_limit_package_resolved_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "Package.resolved").write_text(" " * 128, encoding="utf-8")

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        raise AssertionError(f"unexpected fetch: {url} {options}")

    candidate = resolve_mobile_metadata(
        PackageFact(
            name="swift-collections",
            version="1.4.0",
            package_type="swift",
            repo="ios-app",
            purl="pkg:swift/swift-collections@1.4.0",
            declared_license_raw=None,
            locations=("Package.resolved",),
        ),
        source_root=tmp_path,
        fetcher=fetcher,
        limits=SecurityLimits(max_parse_bytes=16),
    )

    assert candidate is None


def _write_package_resolved(
    root: Path,
    *,
    location: str,
    version: str,
    revision: str,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Package.resolved").write_text(
        json.dumps(
            {
                "pins": [
                    {
                        "identity": "swift-collections",
                        "kind": "remoteSourceControl",
                        "location": location,
                        "state": {"version": version, "revision": revision},
                    }
                ],
                "version": 3,
            }
        ),
        encoding="utf-8",
    )
