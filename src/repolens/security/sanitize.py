"""Output sanitizers for CSV, Markdown, and untrusted names."""

from __future__ import annotations

import csv
import html
import io
import re
import unicodedata
from urllib.parse import urlparse

_DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_LEADING_WHITESPACE = " \t\r\n\f\v\ufeff"
_MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)]*)\)")
_MARKDOWN_REFERENCE_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\[([^\]]*)\]")
_MARKDOWN_REFERENCE_DEF_RE = re.compile(r"(?m)^(\s*)\[([^\]]+)\]:\s*(\S+)(.*)$")
_DANGEROUS_MARKDOWN_SCHEME_TEXT_RE = re.compile(
    r"\b(javascript|data|vbscript|file)\s*:", re.IGNORECASE
)


def neutralize_csv_cell(value: object) -> str:
    """Return a CSV cell value that cannot open as a live formula."""

    text = unicodedata.normalize("NFKC", "" if value is None else str(value))
    probe = text.lstrip(_LEADING_WHITESPACE)
    if probe.startswith(_DANGEROUS_CSV_PREFIXES):
        return f"\t{text}"
    return text


def serialize_csv_row(values: list[object] | tuple[object, ...]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow([neutralize_csv_cell(value) for value in values])
    return output.getvalue()


def serialize_csv_rows(rows: list[list[object] | tuple[object, ...]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
    for row in rows:
        writer.writerow([neutralize_csv_cell(value) for value in row])
    return output.getvalue()


def markdown_link(label: str, url: str) -> str:
    """Render a safe Markdown link or inert label for unsafe hrefs."""

    if not _safe_markdown_url(url):
        return _escape_markdown_text(label)
    safe_label = _escape_markdown_url_label(label) if label == url else _escape_markdown_text(label)
    return f"[{safe_label}]({html.escape(url, quote=True)})"


def sanitize_markdown(markdown: str) -> str:
    """Neutralize unsafe Markdown links, raw HTML, autolinks, and image sources."""

    unsafe_refs = _unsafe_reference_labels(markdown)

    def replace_image(match: re.Match[str]) -> str:
        return _escape_markdown_text(match.group(1))

    def replace_link(match: re.Match[str]) -> str:
        label = match.group(1)
        url = match.group(2)
        if not _safe_markdown_url(url):
            return _escape_markdown_text(label)
        return f"[{label}]({html.escape(url, quote=True)})"

    def replace_reference_link(match: re.Match[str]) -> str:
        label = match.group(1)
        reference = (match.group(2) or label).strip().lower()
        if reference in unsafe_refs:
            return _escape_markdown_text(label)
        return match.group(0)

    def replace_reference_def(match: re.Match[str]) -> str:
        label = match.group(2)
        reference = label.strip().lower()
        if reference in unsafe_refs:
            return f"{match.group(1)}{_escape_markdown_text(label)}"
        return match.group(0)

    without_images = _MARKDOWN_IMAGE_RE.sub(replace_image, markdown)
    without_links = _MARKDOWN_LINK_RE.sub(replace_link, without_images)
    without_ref_links = _MARKDOWN_REFERENCE_LINK_RE.sub(replace_reference_link, without_links)
    without_unsafe_defs = _MARKDOWN_REFERENCE_DEF_RE.sub(replace_reference_def, without_ref_links)
    return _escape_raw_html(without_unsafe_defs)


def render_code_span(value: object) -> str:
    """Render untrusted text as an inert Markdown code span."""

    text = "" if value is None else str(value)
    text = re.sub(r"[\r\n]+", " ", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    if text.startswith("`") or text.endswith("`"):
        text = f" {text} "
    return f"{fence}{text}{fence}"


def _safe_markdown_url(url: str) -> bool:
    stripped = unicodedata.normalize("NFKC", url).strip()
    if not stripped:
        return False
    try:
        parsed = urlparse(stripped)
        scheme = parsed.scheme.lower()
    except ValueError:
        return False
    if scheme in {"javascript", "data", "vbscript", "file"}:
        return False
    return not (scheme and scheme not in {"https", "http", "mailto"})


def _unsafe_reference_labels(markdown: str) -> set[str]:
    unsafe: set[str] = set()
    for match in _MARKDOWN_REFERENCE_DEF_RE.finditer(markdown):
        label = match.group(2).strip().lower()
        url = match.group(3).strip("<>")
        if not _safe_markdown_url(url):
            unsafe.add(label)
    return unsafe


def _escape_raw_html(text: str) -> str:
    escaped = text.replace("<", "&lt;").replace(">", "&gt;")
    return _DANGEROUS_MARKDOWN_SCHEME_TEXT_RE.sub(lambda match: f"{match.group(1)}&#58;", escaped)


def _escape_markdown_text(text: str) -> str:
    escaped = html.escape(text, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|-])", r"\\\1", escaped)


def _escape_markdown_url_label(text: str) -> str:
    escaped = html.escape(text, quote=False)
    return re.sub(r"([\\\[\]])", r"\\\1", escaped)
