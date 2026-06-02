from __future__ import annotations

import pytest

from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.resolve.evidence import (
    UNKNOWN_VERSION,
    has_exact_license_evidence,
    should_attempt_api_resolution,
)
from repolens.resolve.models import ApiCandidate, PackageFact
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, validate_url_for_fetch
from repolens.security.redaction import REDACTION, redact_tokens

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def metadata_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("169.254.169.254",)


def evidence_options() -> HttpFetchOptions:
    return HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})


def test_p3a_resolve_blocks_off_allowlist_evidence() -> None:
    with pytest.raises(FetchSecurityError, match="host is not allowlisted"):
        validate_url_for_fetch(
            "https://offlist.example.invalid/licenses/acme-lib",
            evidence_options(),
            resolver=public_resolver,
        )


def test_p3a_resolve_rejects_mismatched_evidence_anchor() -> None:
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        "MIT",
    )

    assert not has_exact_license_evidence(b'{"licenses":["Apache-2.0"]}', candidate, "MIT")


def test_p3a_resolve_rejects_similar_spdx_evidence() -> None:
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        "MIT",
    )

    assert not has_exact_license_evidence(b'{"license":"MIT-0"}', candidate, "MIT")


def test_p3a_resolve_blocks_allowlisted_host_resolving_private_ip() -> None:
    with pytest.raises(FetchSecurityError, match="blocked IP"):
        validate_url_for_fetch(
            "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_options(),
            resolver=metadata_resolver,
        )


def test_p3a_resolve_does_not_fetch_unversioned_package() -> None:
    package = PackageFact("acme-lib", UNKNOWN_VERSION, "python", "fixture-repo", None, None)

    assert not should_attempt_api_resolution(package)


def test_p3a_resolve_redacts_token_shaped_api_payload() -> None:
    token = "ghp_" + "A" * 24
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        f"MIT {token}",
    )

    assert not has_exact_license_evidence(f'{{"license":"MIT {token}"}}'.encode(), candidate, "MIT")
    redacted = redact_tokens(candidate.evidence_anchor)
    assert token not in redacted
    assert REDACTION in redacted


def test_p3a_resolve_drops_rejected_credential_evidence_url() -> None:
    with pytest.raises(FetchSecurityError, match="must not embed credentials"):
        validate_url_for_fetch(
            "https://user:plainsecret@api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_options(),
            resolver=public_resolver,
        )
