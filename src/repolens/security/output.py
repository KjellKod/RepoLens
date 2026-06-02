"""Output sanitizers for generated reports."""

from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import urlparse


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_HTML_HREF_RE = re.compile(
    r"<a\b[^>]*\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^'\"\s>]+))[^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_AUTOLINK_RE = re.compile(r"<([a-z][a-z0-9+.-]*:[^<>\s]*)>", re.IGNORECASE)
_IMAGE_LINK_RE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_TEXT_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)]*)\)")
_TRACKING_HINTS = ("pixel", "tracking", "beacon")
_SAFE_HREF_SCHEMES = {"https", "http"}


def neutralize_csv_cell(value: object) -> str:
    """Normalize and neutralize a cell that could be interpreted as a formula."""

    normalized = unicodedata.normalize("NFKC", str(value))
    stripped = normalized.lstrip()
    if stripped.startswith(_FORMULA_PREFIXES):
        return "\t" + stripped
    return normalized


def sanitize_markdown_href(markdown: str) -> str:
    """Sanitize unsafe markdown links and remove tracking-pixel image links."""

    def is_unsafe_href(href: str) -> bool:
        decoded_href = html.unescape(href).strip()
        parsed = urlparse(decoded_href)
        return bool(parsed.scheme and parsed.scheme not in _SAFE_HREF_SCHEMES)

    def replacement_text(label: str, fallback: str = "unsafe-link") -> str:
        clean_label = _HTML_TAG_RE.sub("", label).strip()
        escaped = html.escape(clean_label or fallback, quote=False)
        return f"`{escaped}`"

    def replace_html_href(match: re.Match[str]) -> str:
        href = next(group for group in match.group(1, 2, 3) if group is not None)
        if is_unsafe_href(href):
            return replacement_text(match.group(4))
        return match.group(0)

    def replace_autolink(match: re.Match[str]) -> str:
        href = match.group(1)
        if is_unsafe_href(href):
            return replacement_text("", fallback="unsafe-link")
        return match.group(0)

    def replace_image(match: re.Match[str]) -> str:
        alt_text = html.escape(match.group(1), quote=False)
        href = match.group(2).strip()
        if any(hint in href.lower() for hint in _TRACKING_HINTS):
            return f"`{alt_text}`" if alt_text else ""
        if is_unsafe_href(href):
            return f"`{alt_text}`" if alt_text else ""
        return match.group(0)

    def replace_link(match: re.Match[str]) -> str:
        label = match.group(1)
        href = match.group(2).strip()
        if is_unsafe_href(href):
            return f"`{html.escape(label, quote=False)}`"
        return match.group(0)

    without_html_hrefs = _HTML_HREF_RE.sub(replace_html_href, markdown)
    without_autolinks = _AUTOLINK_RE.sub(replace_autolink, without_html_hrefs)
    without_pixels = _IMAGE_LINK_RE.sub(replace_image, without_autolinks)
    return _TEXT_LINK_RE.sub(replace_link, without_pixels)
