from __future__ import annotations

import csv
import io
import socket
from html import unescape

import pytest

from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, validate_url_for_fetch
from repolens.security.output import neutralize_csv_cell, sanitize_markdown_href
from repolens.security.redaction import redact_tokens, redact_tokens_from_structure
from repolens.security.sanitize import sanitize_markdown, serialize_csv_row


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_csv_formula_neutralizes() -> None:
    assert neutralize_csv_cell("=1+2").startswith("\t")
    assert neutralize_csv_cell("  +cmd").startswith("\t")
    assert neutralize_csv_cell("＝1+2").startswith("\t")
    assert neutralize_csv_cell("plain text") == "plain text"


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_markdown_href_sanitizes() -> None:
    markdown = (
        "[x](javascript:alert(1)) "
        "[encoded](jav&#x61;script:alert(1)) "
        "![](https://tracker.example.invalid/pixel) "
        '<a href="data:text/html,abc">raw</a> '
        '<a href=" javascript:alert(1)">spaced</a> '
        '<a href="jav&#x61;script:alert(1)">encoded</a> '
        "<javascript:alert(1)>"
    )

    sanitized = sanitize_markdown_href(markdown)

    decoded = unescape(sanitized)
    assert "javascript:" not in decoded
    assert "data:text/html" not in decoded
    assert "tracker.example.invalid" not in sanitized
    assert "`x`" in sanitized
    assert "`raw`" in sanitized
    assert "`spaced`" in sanitized
    assert "`encoded`" in sanitized
    assert "`unsafe-link`" in sanitized


def test_csv_formula_cells_are_neutralized() -> None:
    for value in ("=1+2", "＝1+2"):
        output = serialize_csv_row([value])
        assert output.startswith('"\t')
        parsed = next(csv.reader(io.StringIO(output)))[0]
        assert parsed.startswith("\t")
        assert not parsed.startswith(("=", "+", "-", "@"))


def test_markdown_unsafe_hrefs_and_images_are_neutralized() -> None:
    output = sanitize_markdown(
        "[x](javascript:alert(1)) ![](https://allowed.example/pixel) "
        "<javascript:alert(1)> [y][ref]\n\n[ref]: data:text/plain,acme"
    )
    assert "javascript:" not in output
    assert "data:" not in output
    assert "![]" not in output
    assert "https://allowed.example/pixel" not in output


def test_supported_tokens_are_redacted_from_text_and_structures() -> None:
    token = "ghp_" + "a" * 20
    assert token not in redact_tokens(f"value={token}")
    assert token not in repr(redact_tokens_from_structure({"token": token}))


@pytest.mark.parametrize(
    "url,ip",
    [
        ("file:///tmp/acme", "93.184.216.34"),
        ("https://allowed.example/acme", "169.254.169.254"),
        ("https://allowed.example/acme", "10.0.0.1"),
        ("https://allowed.example/acme", "::ffff:169.254.169.254"),
        ("https://allowed.example/acme", "64:ff9b::a9fe:a9fe"),
        ("https://allowed.example/acme", "fc00::1"),
    ],
)
def test_ssrf_metadata_private_file_and_ipv6_traps_blocked(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    ip: str,
) -> None:
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(FetchSecurityError):
        validate_url_for_fetch(url, HttpFetchOptions(allowed_hosts=frozenset({"allowed.example"})))


def test_ssrf_allowlisted_public_host_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert (
        validate_url_for_fetch(
            "https://allowed.example/acme",
            HttpFetchOptions(allowed_hosts=frozenset({"allowed.example"})),
        )[2]
        == "93.184.216.34"
    )
