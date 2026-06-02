"""Helpers for untrusted text caps, screening, and delimiter wrapping."""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass

from repolens.security.errors import ContentSecurityError
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DIRECTIONAL_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_BOUNDARY_RE = re.compile(
    r"</?untrusted_content\b[^>]*>|\[/?system\]|\[/?developer\]|\[/?assistant\]",
    re.IGNORECASE,
)
_MARKER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("role_play", re.compile(r"\byou are now\b|\bact as\b", re.IGNORECASE)),
    ("output_override", re.compile(r"\bignore (all )?(previous|above) instructions\b", re.IGNORECASE)),
    ("container_escape", _BOUNDARY_RE),
    ("imperative", re.compile(r"\b(output|return|print)\b.{0,32}\b(json|mit|license)\b", re.IGNORECASE)),
    ("directional_unicode", _DIRECTIONAL_RE),
)


@dataclass(frozen=True, slots=True)
class ContentScreen:
    """Result of F2 injection-marker detection and stripping."""

    text: str
    markers: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return bool(self.markers)


def normalize_untrusted_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = value
    text = unicodedata.normalize("NFC", text)
    text = _DIRECTIONAL_RE.sub("", text)
    return _CONTROL_RE.sub("", text)


def cap_text(value: bytes | str, cap_bytes: int) -> str:
    if cap_bytes < 0:
        raise ContentSecurityError("cap must be non-negative")
    text = normalize_untrusted_text(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= cap_bytes:
        return text
    return encoded[:cap_bytes].decode("utf-8", errors="ignore")


def strip_boundary_tokens(value: bytes | str) -> str:
    text = normalize_untrusted_text(value)
    return _BOUNDARY_RE.sub("", text)


def screen_untrusted_content(value: bytes | str) -> ContentScreen:
    normalized = normalize_untrusted_text(value)
    markers = tuple(name for name, pattern in _MARKER_PATTERNS if pattern.search(normalized))
    return ContentScreen(text=strip_boundary_tokens(normalized), markers=markers)


def wrap_untrusted_content(
    value: bytes | str,
    *,
    source: str,
    path: str,
    cap_bytes: int | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> str:
    cap = limits.license_text_bytes if cap_bytes is None else cap_bytes
    screened = screen_untrusted_content(cap_text(value, cap))
    source_attr = html.escape(source, quote=True)
    path_attr = html.escape(path, quote=True)
    body = html.escape(screened.text, quote=False)
    return f'<untrusted_content source="{source_attr}" path="{path_attr}">\n{body}\n</untrusted_content>'
