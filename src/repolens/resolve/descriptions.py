"""Brief package-description normalization for resolved records."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

MAX_DESCRIPTION_CHARS = 160
_WHITESPACE = re.compile(r"\s+")
_MARKDOWN_LINKED_IMAGE = re.compile(r"\[!\[[^\]]*]\([^)]*\)]\([^)]*\)")
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*]\([^)]*\)")
_HTML_IMAGE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)]\(([^)]+)\)")
_BADGE_FRAGMENT_MARKERS = (
    "![",
    "[![",
    "img.shields.io",
    "npm version",
    "npm downloads",
)


def brief_description(value: object) -> str | None:
    """Return a short, single-line package description or ``None``."""

    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", value)
    text = "".join(
        character for character in text if not unicodedata.category(character).startswith("C")
    )
    text = _strip_badge_markup(text)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text or _looks_like_badge_fragment(text):
        return None
    if len(text) <= MAX_DESCRIPTION_CHARS:
        return text
    return text[: MAX_DESCRIPTION_CHARS - 3].rstrip() + "..."


def first_brief_description(values: Iterable[object]) -> str | None:
    """Return the first usable brief description from candidate values."""

    for value in values:
        description = brief_description(value)
        if description is not None:
            return description
    return None


def _strip_badge_markup(text: str) -> str:
    text = _MARKDOWN_LINKED_IMAGE.sub(" ", text)
    text = _MARKDOWN_IMAGE.sub(" ", text)
    text = _HTML_IMAGE.sub(" ", text)
    return _MARKDOWN_LINK.sub(lambda match: match.group(1), text)


def _looks_like_badge_fragment(text: str) -> bool:
    lowered = text.casefold()
    return any(marker in lowered for marker in _BADGE_FRAGMENT_MARKERS)
