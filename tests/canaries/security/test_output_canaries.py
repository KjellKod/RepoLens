from html import unescape

import pytest

from repolens.security.output import neutralize_csv_cell, sanitize_markdown_href

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_csv_formula_neutralizes() -> None:
    assert neutralize_csv_cell("=1+2").startswith("\t")
    assert neutralize_csv_cell("  +cmd").startswith("\t")
    assert neutralize_csv_cell("＝1+2").startswith("\t")
    assert neutralize_csv_cell("plain text") == "plain text"


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
