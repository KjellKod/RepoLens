"""URL and resolved-address validation for outbound fetches."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from ipaddress import ip_address
from urllib.parse import urlparse


Resolver = Callable[[str], Iterable[str]]

_BLOCKED_HOSTS = {"169.254.169.254"}


def validate_fetch_target(
    url: str,
    *,
    allowed_hosts: set[str],
    resolver: Resolver,
) -> str:
    """Return the normalized URL when it is safe to fetch."""

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("fetch target must use https")
    if not parsed.hostname:
        raise ValueError("fetch target must include a host")

    host = parsed.hostname.lower().rstrip(".")
    allowed = {entry.lower().rstrip(".") for entry in allowed_hosts}
    if host not in allowed:
        raise ValueError("fetch target host is not allowlisted")
    if host in _BLOCKED_HOSTS:
        raise ValueError("fetch target host is blocked")

    resolved = tuple(resolver(host))
    if not resolved:
        raise ValueError("fetch target did not resolve")

    for raw_ip in resolved:
        address = ip_address(raw_ip)
        if not address.is_global:
            raise ValueError("fetch target resolved to a blocked address")

    return parsed.geturl()


def validate_redirect_target(
    current_url: str,
    redirect_url: str,
    *,
    allowed_hosts: set[str],
    resolver: Resolver,
) -> str:
    """Validate a redirect by applying the same target rules to the new URL."""

    del current_url
    return validate_fetch_target(redirect_url, allowed_hosts=allowed_hosts, resolver=resolver)
