from __future__ import annotations

import pytest

from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import FetchResult, HttpFetchOptions, validate_url_for_fetch
from repolens.shortlist.agent import Resolution
from repolens.shortlist.verify import verify_agent_resolution

_DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3"


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def _private_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("169.254.169.254",)


def _fetcher_returning(body: bytes):
    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=body)

    return fetcher


def test_exact_anchor_passes() -> None:
    resolution = Resolution("MIT", _DEPS_DEV_URL, "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":"MIT"}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.spdx_id == "MIT"
    assert outcome.evidence_anchor == "MIT"


def test_mismatched_anchor_fails() -> None:
    resolution = Resolution("MIT", _DEPS_DEV_URL, "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":"GPL-3.0-only"}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"


def test_off_allowlist_url_fails_closed() -> None:
    # github.com / raw.githubusercontent.com are NOT in API_ALLOWED_HOSTS; an off-allowlist
    # evidence URL fails closed to the human queue rather than forking the allowlist (AC 15).
    assert "raw.githubusercontent.com" not in API_ALLOWED_HOSTS
    resolution = Resolution("MIT", "https://attacker.example.invalid/license?token=ghp_x", "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":"MIT"}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:fetch_blocked_or_failed"


def test_private_ip_resolution_blocked() -> None:
    resolution = Resolution("MIT", _DEPS_DEV_URL, "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":"MIT"}'),
        resolver=_private_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:fetch_blocked_or_failed"


def test_unrecognized_spdx_abstains_without_fetch() -> None:
    fetched: list[str] = []

    def counting_fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        fetched.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b"{}")

    resolution = Resolution("not-an-spdx-id", _DEPS_DEV_URL, "anchor")
    outcome = verify_agent_resolution(
        resolution, fetcher=counting_fetcher, resolver=_public_resolver
    )

    assert not outcome.verified
    assert outcome.reason == "verify:unrecognized_spdx"
    assert fetched == []  # never re-fetches on an unrecognized claim


def test_off_allowlist_host_raises_at_validate() -> None:
    options = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
    with pytest.raises(FetchSecurityError, match="host is not allowlisted"):
        validate_url_for_fetch(
            "https://raw.githubusercontent.com/acme/acme/main/LICENSE",
            options,
            resolver=_public_resolver,
        )
