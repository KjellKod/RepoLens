"""Output redaction helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTION = "***REDACTED***"
TOKEN_RE = re.compile(
    r"(ghp_[A-Za-z0-9_]{12,}|gho_[A-Za-z0-9_]{12,}|ghs_[A-Za-z0-9_]{12,}|"
    r"github_pat_[A-Za-z0-9_]{20,})"
)


def redact_tokens(value: Any) -> Any:
    """Return ``value`` with GitHub token-looking strings replaced."""

    if isinstance(value, str):
        return TOKEN_RE.sub(REDACTION, value)
    if isinstance(value, Mapping):
        return {key: redact_tokens(inner) for key, inner in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return [redact_tokens(inner) for inner in value]
    return value
