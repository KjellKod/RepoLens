from __future__ import annotations

import csv
import io

import pytest

from repolens.security.sanitize import (
    markdown_link,
    neutralize_csv_cell,
    render_code_span,
    sanitize_markdown,
    serialize_csv_row,
)


@pytest.mark.parametrize("value", ["=1+2", "  +1", "＝1+2", "\t=1", "\r=1", "@cmd"])
def test_neutralize_csv_cell_prefixes_tab_after_normalization(value: str) -> None:
    assert neutralize_csv_cell(value).startswith("\t")


def test_serialize_csv_row_quotes_tab_prefixed_formula() -> None:
    output = serialize_csv_row(["=1+2"])
    assert output == '"\t=1+2"\n'
    parsed = next(csv.reader(io.StringIO(output)))[0]
    assert parsed.startswith("\t")
    assert not parsed.lstrip(" ").startswith(("=", "+", "-", "@"))


def test_markdown_unsafe_links_are_neutralized() -> None:
    assert sanitize_markdown("[x](javascript:alert(1))") == "x)"
    assert sanitize_markdown("[x](data:text/plain,acme)") == "x"


def test_markdown_images_are_neutralized() -> None:
    output = sanitize_markdown("before ![pixel](https://allowed.example/pixel) after")
    assert "![" not in output
    assert "https://allowed.example/pixel" not in output
    assert "pixel" in output


def test_markdown_raw_html_is_escaped() -> None:
    output = sanitize_markdown('<a href="javascript:alert(1)">x</a> <script>bad()</script>')
    assert "<a" not in output
    assert "<script" not in output
    assert "javascript:" not in output
    assert "&lt;a" in output


def test_markdown_autolink_unsafe_href_is_escaped() -> None:
    output = sanitize_markdown("<javascript:alert(1)>")
    assert "<javascript:" not in output
    assert "&lt;javascript&#58;" in output


def test_markdown_reference_style_unsafe_link_is_neutralized() -> None:
    output = sanitize_markdown("[x][ref]\n\n[ref]: javascript:alert(1)")
    assert "javascript:" not in output
    assert "[x][ref]" not in output
    assert "x" in output


def test_markdown_safe_link_survives() -> None:
    assert (
        markdown_link("acme", "https://allowed.example/path")
        == "[acme](https://allowed.example/path)"
    )


def test_sanitize_markdown_preserves_safe_link_label_without_double_escape() -> None:
    url = (
        "https://api.deps.dev/v3alpha/systems/npm/packages/"
        "@aashutoshrathi%2Fword-wrap/versions/1.2.6"
    )

    output = sanitize_markdown(markdown_link(url, url))

    assert output == f"[{url}]({url})"
    assert "api\\." not in output
    assert "word\\-wrap" not in output


def test_markdown_link_escapes_self_url_label_delimiters_without_overescaping() -> None:
    url = "https://allowed.example/path[ref]name"

    output = markdown_link(url, url)

    assert output == f"[https://allowed.example/path\\[ref\\]name]({url})"
    assert "allowed\\.example" not in output
    assert sanitize_markdown(output) == output


@pytest.mark.parametrize(
    "url",
    [
        "https://allowed.example/license#section",
        "https://allowed.example/license(foo)",
        "https://allowed.example/a_b!c",
    ],
)
def test_markdown_link_keeps_common_self_url_punctuation_readable(url: str) -> None:
    output = markdown_link(url, url)

    assert output == f"[{url}]({url})"
    assert sanitize_markdown(output) == output


def test_malformed_markdown_url_is_neutralized() -> None:
    assert sanitize_markdown("[x](http://[::1)") == "x"


def test_empty_markdown_url_rejected() -> None:
    assert markdown_link("acme", "") == "acme"


def test_render_code_span_handles_backticks_and_controls() -> None:
    assert render_code_span("acme`name\x00").startswith("``")
    assert "\n" not in render_code_span("acme\n## injected")
