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
    assert "github.com" not in API_ALLOWED_HOSTS
    resolution = Resolution("MIT", "https://attacker.example.invalid/license?token=ghp_x", "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":"MIT"}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:fetch_blocked_or_failed"


def test_raw_github_evidence_host_can_verify_exact_anchor() -> None:
    assert "raw.githubusercontent.com" in API_ALLOWED_HOSTS
    resolution = Resolution(
        "MIT",
        "https://raw.githubusercontent.com/CocoaPods/Specs/abc123/"
        "Specs/a/7/6/Analytics/4.1.8/Analytics.podspec.json",
        "MIT",
    )

    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":{"type":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.evidence_url == resolution.evidence_url
    assert outcome.evidence_anchor == "MIT"


def test_arbitrary_raw_github_evidence_fails_closed() -> None:
    resolution = Resolution(
        "MIT",
        "https://raw.githubusercontent.com/attacker/not-the-package/main/package.json",
        "MIT",
    )

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


def test_compound_expression_claim_verifies_against_exact_anchor() -> None:
    expression = "PSF-2.0 AND ZPL-2.1"
    resolution = Resolution(expression, _DEPS_DEV_URL, expression)
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"licensed":{"declared":"PSF-2.0 AND ZPL-2.1"}}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.spdx_id == expression
    assert outcome.evidence_anchor == expression


def test_github_license_api_ref_verifies() -> None:
    url = "https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3"
    resolution = Resolution("MIT", url, "MIT")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor"


def test_github_default_branch_rejected_for_versioned_package() -> None:
    resolution = Resolution("MIT", "https://api.github.com/repos/sentinel/acme-lib/license", "MIT")
    outcome = verify_agent_resolution(
        resolution,
        expected_ref="1.2.3",
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:missing_ref"


def test_github_license_api_main_ref_rejected_for_versioned_package() -> None:
    resolution = Resolution(
        "MIT",
        "https://api.github.com/repos/sentinel/acme-lib/license?ref=main",
        "MIT",
    )
    outcome = verify_agent_resolution(
        resolution,
        expected_ref="1.2.3",
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:default_branch_rejected"


def test_github_license_api_wrong_tag_rejected_for_versioned_package() -> None:
    resolution = Resolution(
        "MIT",
        "https://api.github.com/repos/sentinel/acme-lib/license?ref=2.0.0",
        "MIT",
    )
    outcome = verify_agent_resolution(
        resolution,
        expected_ref="1.2.3",
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:ref_mismatch"


def test_github_license_api_sha_ref_allowed_for_versioned_package() -> None:
    resolution = Resolution(
        "MIT",
        "https://api.github.com/repos/sentinel/acme-lib/license?ref=" + ("a" * 40),
        "MIT",
    )
    outcome = verify_agent_resolution(
        resolution,
        expected_ref="1.2.3",
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor"


def test_cocoapods_podspec_license_verifies() -> None:
    resolution = Resolution(
        "MIT",
        "https://trunk.cocoapods.org/api/v1/pods/acme-lib/specs/1.2.3",
        "MIT",
    )
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"license":{"type":"MIT"}}'),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor"


def test_partial_claim_against_compound_expression_fails_anchor_match() -> None:
    resolution = Resolution("ZPL-2.1", _DEPS_DEV_URL, "ZPL-2.1")
    outcome = verify_agent_resolution(
        resolution,
        fetcher=_fetcher_returning(b'{"licensed":{"declared":"PSF-2.0 AND ZPL-2.1"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"


_GITHUB_LICENSE_BODY = (
    b'{"license":{"spdx_id":"MIT"},'
    b'"html_url":"https://github.com/o/r/blob/v1.2.3/LICENSE",'
    b'"download_url":"https://raw.githubusercontent.com/o/r/v1.2.3/LICENSE"}'
)


def test_github_license_api_pinned_ref_verifies_with_urls() -> None:
    """#1 — pinned ref verifies, ref_pinned True, URLs lifted, reason exact_anchor."""

    url = "https://api.github.com/repos/o/r/license?ref=1.2.3"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        expected_ref="1.2.3",
        allow_default_branch=False,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor"
    assert outcome.ref_pinned is True
    assert outcome.html_url == "https://github.com/o/r/blob/v1.2.3/LICENSE"
    assert outcome.download_url == "https://raw.githubusercontent.com/o/r/v1.2.3/LICENSE"


def test_github_license_api_bare_url_verifies_default_branch_with_urls() -> None:
    """#2 — bare /license with the flag verifies as unpinned default branch."""

    url = "https://api.github.com/repos/o/r/license"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor_default_branch"
    assert outcome.ref_pinned is False
    assert outcome.html_url == "https://github.com/o/r/blob/v1.2.3/LICENSE"
    assert outcome.download_url == "https://raw.githubusercontent.com/o/r/v1.2.3/LICENSE"


def test_github_license_api_master_ref_verifies_default_branch() -> None:
    """#3 — ?ref=master with the flag verifies as unpinned default branch."""

    url = "https://api.github.com/repos/o/r/license?ref=master"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor_default_branch"
    assert outcome.ref_pinned is False


def test_github_license_api_bare_url_without_flag_still_missing_ref() -> None:
    """#4 — without the flag, a bare /license still fails verify:missing_ref."""

    url = "https://api.github.com/repos/o/r/license"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=False,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:missing_ref"


def test_github_license_api_master_ref_without_flag_still_rejected() -> None:
    """#5 — without the flag, ?ref=master still fails default_branch_rejected."""

    url = "https://api.github.com/repos/o/r/license?ref=master"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        expected_ref="1.2.3",
        allow_default_branch=False,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:default_branch_rejected"


def test_github_license_api_noassertion_fails_closed() -> None:
    """#6 — NOASSERTION fails closed even with the flag on."""

    url = "https://api.github.com/repos/o/r/license"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"NOASSERTION"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"


def test_github_license_api_null_spdx_fails_closed() -> None:
    """#7 — null spdx_id fails closed."""

    url = "https://api.github.com/repos/o/r/license"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":null}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"


def test_github_license_api_spdx_mismatch_fails_closed() -> None:
    """#8 — SPDX mismatch fails closed (never downgraded)."""

    url = "https://api.github.com/repos/o/r/license"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(b'{"license":{"spdx_id":"GPL-3.0-only"}}'),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"


def test_github_license_api_pinned_but_wrong_ref_still_ref_mismatch() -> None:
    """#9 — a pinned-but-wrong ref fails verify:ref_mismatch even with the flag on."""

    url = "https://api.github.com/repos/o/r/license?ref=2.0.0"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        expected_ref="1.2.3",
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:ref_mismatch"


def test_github_license_api_sha_ref_stays_pinned() -> None:
    """#10 — a 40-char SHA ref stays pinned even with the flag on."""

    url = "https://api.github.com/repos/o/r/license?ref=" + ("a" * 40)
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert outcome.verified
    assert outcome.reason == "verify:exact_anchor"
    assert outcome.ref_pinned is True


def test_raw_download_url_as_primary_evidence_blocked() -> None:
    """#11 — a raw githubusercontent URL that is not a CocoaPods podspec is blocked."""

    url = "https://raw.githubusercontent.com/o/r/master/LICENSE"
    outcome = verify_agent_resolution(
        Resolution("MIT", url, "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert not outcome.verified
    assert outcome.reason == "verify:fetch_blocked_or_failed"


def test_verifier_reason_set_not_asserted_exhaustively() -> None:
    """#26 — grounding guard: no consumer enumerates the verifier reason-set.

    A repo-wide search (``rg "verify:exact_anchor" tests/ src/``) confirmed no test or
    consumer asserts the reason-set exhaustively (no set-membership / all-reasons
    enumeration), so adding ``verify:exact_anchor_default_branch`` is purely additive. If a
    future exhaustive assertion is introduced, EXTEND it to include the new reason rather
    than letting it silently reject the value. Both reasons are produced by the verifier
    and are distinct.
    """

    pinned = verify_agent_resolution(
        Resolution("MIT", "https://api.github.com/repos/o/r/license?ref=1.2.3", "MIT"),
        expected_ref="1.2.3",
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )
    default_branch = verify_agent_resolution(
        Resolution("MIT", "https://api.github.com/repos/o/r/license", "MIT"),
        allow_default_branch=True,
        fetcher=_fetcher_returning(_GITHUB_LICENSE_BODY),
        resolver=_public_resolver,
    )

    assert pinned.reason == "verify:exact_anchor"
    assert default_branch.reason == "verify:exact_anchor_default_branch"
    assert pinned.reason != default_branch.reason


def test_off_allowlist_host_raises_at_validate() -> None:
    options = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
    with pytest.raises(FetchSecurityError, match="host is not allowlisted"):
        validate_url_for_fetch(
            "https://github.com/acme/acme/blob/main/LICENSE",
            options,
            resolver=_public_resolver,
        )
