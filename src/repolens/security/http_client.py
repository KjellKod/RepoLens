"""Allowlisted HTTPS client with SSRF defenses."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from repolens.security.errors import FetchSecurityError
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits

_NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_IPV4_COMPAT_NETWORK = ipaddress.ip_network("::/96")
_SITE_LOCAL_IPV6_NETWORK = ipaddress.ip_network("fec0::/10")
_BLOCKED_IPV4_HOSTS = {ipaddress.ip_address("169.254.169.254")}
_AUTH_HEADER_NAMES = {"authorization", "proxy-authorization"}


@dataclass(frozen=True, slots=True)
class HttpFetchOptions:
    """Options for a guarded fetch."""

    allowed_hosts: frozenset[str]
    limits: SecurityLimits = DEFAULT_LIMITS
    max_redirects: int = 0
    headers: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Minimal fetch result with eager body bytes."""

    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        *,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._tls_hostname = hostname

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self._tls_hostname)


def fetch_url(url: str, options: HttpFetchOptions) -> FetchResult:
    """Fetch a URL after allowlist and resolve-then-connect validation."""

    return _fetch_url(url, options, redirects_remaining=options.max_redirects)


def validate_url_for_fetch(url: str, options: HttpFetchOptions) -> tuple[str, int, str]:
    """Validate a URL and return host, port, and a pinned IP address."""

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise FetchSecurityError("only https URLs are allowed")
    if not parsed.hostname:
        raise FetchSecurityError("URL must include a host")
    host = parsed.hostname.lower()
    if not _host_allowed(host, options.allowed_hosts):
        raise FetchSecurityError("host is not allowlisted")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise FetchSecurityError("invalid URL port") from exc
    port = 443 if parsed_port is None else parsed_port
    if port <= 0:
        raise FetchSecurityError("invalid URL port")
    addresses = _resolve_host(host, port)
    if not addresses:
        raise FetchSecurityError("host did not resolve")
    unsafe = [ip for ip in addresses if _is_blocked_ip(ip)]
    if unsafe:
        raise FetchSecurityError("resolved host includes a blocked IP")
    return host, port, addresses[0]


def _fetch_url(
    url: str,
    options: HttpFetchOptions,
    *,
    redirects_remaining: int,
) -> FetchResult:
    host, port, pinned_ip = validate_url_for_fetch(url, options)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = _safe_headers(options.headers or {})
    host_header = host if port == 443 else f"{host}:{port}"
    conn = _PinnedHTTPSConnection(
        host,
        pinned_ip,
        port=port,
        timeout=options.limits.fetch_timeout_seconds,
        context=ssl.create_default_context(),
    )
    try:
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host_header)
        conn.putheader("Accept", "*/*")
        conn.putheader("User-Agent", "repolens-security-fetch/0")
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.endheaders()
        response = conn.getresponse()
        status = response.status
        if status in {301, 302, 303, 307, 308}:
            location = response.getheader("Location")
            if redirects_remaining <= 0 or not location:
                raise FetchSecurityError("redirects are disabled")
            redirected = urljoin(url, location)
            return _fetch_url(redirected, options, redirects_remaining=redirects_remaining - 1)
        if status >= 400:
            raise FetchSecurityError(f"unexpected HTTP status {status}")
        body = _read_capped(response, options.limits.max_fetch_bytes)
        return FetchResult(
            url=url,
            status=status,
            headers=tuple(response.getheaders()),
            body=body,
        )
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        raise FetchSecurityError("fetch failed") from exc
    finally:
        conn.close()


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in _AUTH_HEADER_NAMES}


def _read_capped(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchSecurityError("response body exceeds size cap")
        chunks.append(chunk)
    return b"".join(chunks)


def _resolve_host(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchSecurityError("host resolution failed") from exc
    addresses: list[str] = []
    seen: set[str] = set()
    for info in infos:
        raw_ip = info[4][0]
        parsed = str(ipaddress.ip_address(raw_ip))
        if parsed not in seen:
            addresses.append(parsed)
            seen.add(parsed)
    return addresses


def _host_allowed(host: str, allowed_hosts: frozenset[str]) -> bool:
    for allowed in allowed_hosts:
        candidate = allowed.lower()
        if candidate.startswith(".") and host.endswith(candidate):
            return True
        if host == candidate:
            return True
    return False


def _is_blocked_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_blocked_ip(str(ip.ipv4_mapped))
        if ip in _IPV4_COMPAT_NETWORK:
            return True
        if ip in _SITE_LOCAL_IPV6_NETWORK:
            return True
        if any(ip in network for network in _NAT64_NETWORKS):
            return True
    if ip in _BLOCKED_IPV4_HOSTS:
        return True
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_unspecified,
            ip.is_reserved,
        )
    )
