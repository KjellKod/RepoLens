"""Canonical token redaction for logs and structured artifacts.

This is the single home for token redaction (see ``docs/roadmap/rpl_execution.md`` →
*Where things live*). It covers every GitHub token family RepoLens cares about and uses a
single redaction string. Callers that previously imported ``data.redact`` or
``security.secrets`` should import from here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

#: The single redaction replacement used everywhere a token is scrubbed.
REDACTION = "[REDACTED_TOKEN]"

# Individual token families. The gh-prefixed families allow short bodies so that
# token-shaped strings are scrubbed even when truncated in an error message; the
# fine-grained PAT keeps its longer minimum because its prefix is less distinctive.
_TOKEN_FAMILY_SOURCES = (
    r"ghp_[A-Za-z0-9_]{6,}",
    r"gho_[A-Za-z0-9_]{6,}",
    r"ghu_[A-Za-z0-9_]{6,}",
    r"ghr_[A-Za-z0-9_]{6,}",
    r"ghs_[A-Za-z0-9_]{6,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
)
_TOKEN_RE = re.compile("|".join(f"(?:{source})" for source in _TOKEN_FAMILY_SOURCES))

# Stricter, anchored patterns for the committed-surface name-hygiene scan, where a
# generous minimum length avoids matching ordinary prose.
_COMMITTED_TOKEN_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"gho_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghu_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghr_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"ghs_[A-Za-z0-9_]{20,}"),
)


def committed_token_patterns() -> tuple[re.Pattern[str], ...]:
    """Return the token patterns used by the committed-surface name-hygiene scan."""

    return _COMMITTED_TOKEN_PATTERNS


def redact_tokens(text: object) -> str:
    """Scrub every supported token family from ``text`` (coerced to ``str``)."""

    return _TOKEN_RE.sub(REDACTION, "" if text is None else str(text))


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
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [redact_tokens_from_structure(child) for child in value]
    return value
