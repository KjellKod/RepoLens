"""Secret redaction for logs and artifacts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


TOKEN_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"gho_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghu_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghr_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"ghs_[A-Za-z0-9_]{20,}"),
)


def redact_text(text: str) -> str:
    redacted = text
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_mapping(values: Mapping[str, object]) -> dict[str, object]:
    return {key: _redact_value(value) for key, value in values.items()}


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {key: _redact_value(nested) for key, nested in value.items()}
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [_redact_value(item) for item in value]
    return value
