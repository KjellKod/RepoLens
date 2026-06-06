"""Brief package-description normalization for resolved records."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

MAX_DESCRIPTION_CHARS = 160
_WHITESPACE = re.compile(r"\s+")


def brief_description(value: object) -> str | None:
    """Return a short, single-line package description or ``None``."""

    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", value)
    text = "".join(
        character for character in text if not unicodedata.category(character).startswith("C")
    )
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
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
