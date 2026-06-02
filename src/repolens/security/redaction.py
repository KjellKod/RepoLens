"""Token redaction helpers for logs and structured artifacts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

_TOKEN_RE = re.compile(
    r"(?:ghp_[A-Za-z0-9_]{20,}|ghs_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"
)
_REDACTION = "[REDACTED_TOKEN]"


def redact_tokens(text: object) -> str:
    return _TOKEN_RE.sub(_REDACTION, "" if text is None else str(text))


def redact_tokens_from_structure(value):
    """Recursively redact supported token families from JSON-like structures."""

    if isinstance(value, str):
        return redact_tokens(value)
    if isinstance(value, Mapping):
        return {
            redact_tokens(key) if isinstance(key, str) else key: redact_tokens_from_structure(child)
            for key, child in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_tokens_from_structure(child) for child in value)
    if isinstance(value, list):
        return [redact_tokens_from_structure(child) for child in value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return type(value)(redact_tokens_from_structure(child) for child in value)
    return value
