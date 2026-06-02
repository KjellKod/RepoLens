from __future__ import annotations

import socket

import pytest

from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import (
    HttpFetchOptions,
    _is_blocked_ip,
    fetch_url,
    validate_url_for_fetch,
)
from repolens.security.limits import SecurityLimits


class FakeResponse:
    status = 200

    def __init__(self, chunks: list[bytes], location: str | None = None) -> None:
        self._chunks = chunks
        self._location = location

    def read(self, size: int) -> bytes:
        del size
        return self._chunks.pop(0) if self._chunks else b""

    def getheaders(self):
        return [("content-type", "text/plain")]

    def getheader(self, name: str):
        return self._location if name.lower() == "location" else None


class FakeConnection:
    instances: list[FakeConnection] = []

    def __init__(self, hostname, pinned_ip, *, port, timeout, context):
        del context
        self.hostname = hostname
        self.pinned_ip = pinned_ip
        self.port = port
        self.timeout = timeout
        self.headers: dict[str, str] = {}
        FakeConnection.instances.append(self)

    def putrequest(self, method, path, **kwargs):
        self.method = method
        self.path = path

    def putheader(self, key, value):
        self.headers[key.lower()] = value

    def endheaders(self):
        pass

    def getresponse(self):
        return FakeResponse([b"ok"])

    def close(self):
        pass


def options(**kwargs) -> HttpFetchOptions:
    return HttpFetchOptions(allowed_hosts=frozenset({"allowed.example"}), **kwargs)


def patch_dns(monkeypatch: pytest.MonkeyPatch, *ips: str) -> None:
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_rejects_non_https_scheme() -> None:
    with pytest.raises(FetchSecurityError):
        validate_url_for_fetch("file:///tmp/acme", options())


def test_rejects_host_not_on_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_dns(monkeypatch, "93.184.216.34")
    with pytest.raises(FetchSecurityError):
        validate_url_for_fetch("https://other.example/path", options())


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
    ],
)
def test_rejects_private_ipv4_and_ipv6_after_resolution(
    monkeypatch: pytest.MonkeyPatch, ip: str
) -> None:
    patch_dns(monkeypatch, ip)
    with pytest.raises(FetchSecurityError):
        validate_url_for_fetch("https://allowed.example/path", options())


def test_allows_public_allowlisted_host(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_dns(monkeypatch, "93.184.216.34")
    assert validate_url_for_fetch("https://allowed.example/path", options()) == (
        "allowed.example",
        443,
        "93.184.216.34",
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://allowed.example:abc/path",
        "https://allowed.example:-1/path",
        "https://allowed.example:0/path",
        "https://allowed.example:99999/path",
    ],
)
def test_invalid_url_ports_raise_fetch_security_error(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "repolens.security.http_client._resolve_host", lambda host, port: ["93.184.216.34"]
    )
    with pytest.raises(FetchSecurityError, match="invalid URL port"):
        validate_url_for_fetch(url, options())


def test_fetch_drops_authorization_header_and_uses_pinned_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_calls = 0

    def fake_getaddrinfo(host, port, **kwargs):
        nonlocal dns_calls
        dns_calls += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("repolens.security.http_client._PinnedHTTPSConnection", FakeConnection)
    FakeConnection.instances = []
    result = fetch_url(
        "https://allowed.example/acme",
        HttpFetchOptions(
            allowed_hosts=frozenset({"allowed.example"}),
            headers={"Authorization": "secret", "X-Acme": "ok"},
        ),
    )
    conn = FakeConnection.instances[0]
    assert result.body == b"ok"
    assert conn.pinned_ip == "93.184.216.34"
    assert conn.hostname == "allowed.example"
    assert "authorization" not in conn.headers
    assert conn.headers["x-acme"] == "ok"
    assert dns_calls == 1


def test_enforces_body_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    class LargeConnection(FakeConnection):
        def getresponse(self):
            return FakeResponse([b"abc", b"def"])

    patch_dns(monkeypatch, "93.184.216.34")
    monkeypatch.setattr("repolens.security.http_client._PinnedHTTPSConnection", LargeConnection)
    with pytest.raises(FetchSecurityError, match="size cap"):
        fetch_url(
            "https://allowed.example/acme",
            HttpFetchOptions(
                allowed_hosts=frozenset({"allowed.example"}),
                limits=SecurityLimits(max_fetch_bytes=4),
            ),
        )


def test_redirect_is_denied_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedirectConnection(FakeConnection):
        def getresponse(self):
            response = FakeResponse([])
            response.status = 302
            response._location = "https://allowed.example/next"
            return response

    patch_dns(monkeypatch, "93.184.216.34")
    monkeypatch.setattr("repolens.security.http_client._PinnedHTTPSConnection", RedirectConnection)
    with pytest.raises(FetchSecurityError, match="redirects are disabled"):
        fetch_url("https://allowed.example/acme", options())


def test_ip_blocklist_helper_catches_ipv4_mapped() -> None:
    assert _is_blocked_ip("::ffff:169.254.169.254")
