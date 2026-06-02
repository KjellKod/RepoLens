from __future__ import annotations

import csv
import io
import socket
from pathlib import Path

import pytest

from repolens.report import main as report_main
from repolens.report import render_main_report
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, validate_url_for_fetch
from repolens.security.redaction import redact_tokens, redact_tokens_from_structure
from repolens.security.sanitize import neutralize_csv_cell, sanitize_markdown, serialize_csv_row


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
        "[ref-link][bad]\n\n[bad]: data:text/html,abc"
    )

    sanitized = sanitize_markdown(markdown)

    assert "javascript:" not in sanitized
    assert "data:text/html" not in sanitized
    assert "tracker.example.invalid" not in sanitized
    assert "![" not in sanitized


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p6a_report_csv_artifact_neutralizes_formula_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_records(
        tmp_path,
        monkeypatch,
        [
            _resolved_record(name="=acme-one", version="＝acme-two"),
            _resolved_record(name="\t=acme-three", version="\r=acme-four"),
        ],
    )

    csv_path = render_main_report(tmp_path, tmp_path / "out").csv_path
    data = csv_path.read_bytes()
    parsed = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))

    assert b'"\t=acme-one"' in data
    assert b'"\t=acme-two"' in data
    assert b'"\t\t=acme-three"' in data
    assert b'"\t\r=acme-four"' in data
    for row in parsed:
        assert row["name"].startswith("\t")
        assert row["version"].startswith("\t")


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p6a_report_markdown_artifact_sanitizes_hrefs_and_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_records(
        tmp_path,
        monkeypatch,
        [
            _resolved_record(
                name="acme-markdown|name",
                evidence_url="javascript:alert(1)",
            )
        ],
    )

    data = render_main_report(tmp_path, tmp_path / "out").markdown_path.read_bytes()
    markdown = data.decode("utf-8")

    assert "`acme-markdown\\|name`" in markdown
    assert "javascript:" not in markdown
    assert "javascript&#58;alert\\(1\\)" in markdown
    assert "](javascript" not in markdown


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p4_flag_markdown_artifact_sanitizes_hrefs_and_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolens.flag import run_flag
    from repolens.flag import stage as flag_stage

    record = {
        "schema_version": "1.0",
        "name": "acme-markdown|name",
        "version": "1.2.3",
        "repo": "acme-alpha",
        # BLOCK tier so the item lands in shortlist.md where the href/name are rendered.
        "spdx_id": "AGPL-3.0-only",
        "evidence": {
            "source_layer": "syft",
            "url": "javascript:alert(1)",
            "anchor": "AGPL-3.0-only",
        },
        "tags": {"origin": "third-party-oss", "scope": "runtime", "distribution": "server"},
        "modified": "unknown",
    }
    resolved_path = tmp_path / "work" / "acme-alpha" / "resolved.ndjson"
    resolved_path.parent.mkdir(parents=True)
    resolved_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(flag_stage.store, "iter_resolved", lambda path: iter([record]))

    markdown = run_flag(tmp_path).shortlist_md_path.read_text(encoding="utf-8")

    # The untrusted name is wrapped in an inert code span; the javascript: href is neutralized.
    assert "`acme-markdown|name|AGPL-3.0-only`" in markdown
    assert "javascript:" not in markdown
    assert "javascript&#58;alert\\(1\\)" in markdown
    assert "](javascript" not in markdown


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


def _resolved_record(
    *,
    name: str = "acme-lib",
    version: str = "1.2.3",
    evidence_url: str = "https://example.invalid/licenses/mit",
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "name": name,
        "version": version,
        "repo": "acme-alpha",
        "purl": f"pkg:pypi/{name}@{version}",
        "declared_license_raw": "MIT",
        "spdx_id": "MIT",
        "evidence": {
            "source_layer": "syft",
            "url": evidence_url,
        },
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "modified": "unknown",
    }


def _stub_report_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict[str, object]],
) -> None:
    resolved_path = tmp_path / "work" / "acme-alpha" / "resolved.ndjson"
    resolved_path.parent.mkdir(parents=True)
    resolved_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(report_main.store, "iter_resolved", lambda path: iter(records))
