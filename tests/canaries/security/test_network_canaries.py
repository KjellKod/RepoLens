import pytest

from repolens.security.network import validate_fetch_target


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_ssrf_resolve_validate_blocks() -> None:
    allowed_hosts = {"metadata.example.invalid", "safe.example.invalid"}

    with pytest.raises(ValueError, match="blocked address"):
        validate_fetch_target(
            "https://metadata.example.invalid/license",
            allowed_hosts=allowed_hosts,
            resolver=lambda host: ("169.254.169.254",),
        )
    with pytest.raises(ValueError, match="blocked address"):
        validate_fetch_target(
            "https://metadata.example.invalid/license",
            allowed_hosts=allowed_hosts,
            resolver=lambda host: ("100.64.0.1",),
        )

    with pytest.raises(ValueError, match="https"):
        validate_fetch_target(
            "file:///tmp/secret",
            allowed_hosts=allowed_hosts,
            resolver=lambda host: ("198.51.100.4",),
        )

    with pytest.raises(ValueError, match="allowlisted"):
        validate_fetch_target(
            "https://offlist.example.invalid/license",
            allowed_hosts=allowed_hosts,
            resolver=lambda host: ("198.51.100.4",),
        )

    assert validate_fetch_target(
        "https://safe.example.invalid/license",
        allowed_hosts=allowed_hosts,
        resolver=lambda host: ("8.8.8.8",),
    ) == "https://safe.example.invalid/license"
