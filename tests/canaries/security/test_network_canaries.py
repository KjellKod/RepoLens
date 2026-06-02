import pytest

from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, validate_url_for_fetch

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_ssrf_resolve_validate_blocks() -> None:
    options = HttpFetchOptions(
        allowed_hosts=frozenset({"metadata.example.invalid", "safe.example.invalid"})
    )

    def resolver(addresses):
        return lambda host, port: addresses

    with pytest.raises(FetchSecurityError, match="blocked IP"):
        validate_url_for_fetch(
            "https://metadata.example.invalid/license",
            options,
            resolver=resolver(("169.254.169.254",)),
        )
    with pytest.raises(FetchSecurityError, match="blocked IP"):
        validate_url_for_fetch(
            "https://metadata.example.invalid/license",
            options,
            resolver=resolver(("100.64.0.1",)),
        )

    with pytest.raises(FetchSecurityError, match="https"):
        validate_url_for_fetch(
            "file:///tmp/secret",
            options,
            resolver=resolver(("198.51.100.4",)),
        )

    with pytest.raises(FetchSecurityError, match="allowlisted"):
        validate_url_for_fetch(
            "https://offlist.example.invalid/license",
            options,
            resolver=resolver(("198.51.100.4",)),
        )
    with pytest.raises(FetchSecurityError, match="credentials"):
        validate_url_for_fetch(
            "https://token@safe.example.invalid/license",
            options,
            resolver=resolver(("8.8.8.8",)),
        )

    assert validate_url_for_fetch(
        "https://safe.example.invalid/license",
        options,
        resolver=resolver(("8.8.8.8",)),
    ) == ("safe.example.invalid", 443, "8.8.8.8")
