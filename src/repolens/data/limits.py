"""Safety limits for on-disk RepoLens artifacts."""

from __future__ import annotations

from repolens.data.errors import LimitExceeded
from repolens.security.limits import DEFAULT_LIMITS

SCHEMA_VERSION = "1.0"

MAX_ARTIFACT_BYTES = {
    "sbom": 64 * 1024 * 1024,
    "resolved": 16 * 1024 * 1024,
    "inventory": 16 * 1024 * 1024,
    "shortlist": 4 * 1024 * 1024,
}
#: Single source for the JSON structural-depth cap: the security-primitive default.
MAX_JSON_DEPTH = DEFAULT_LIMITS.max_structure_depth
MAX_NDJSON_RECORDS = 1_000_000
MAX_NDJSON_LINE_BYTES = 1 * 1024 * 1024


def max_bytes_for(artifact_name: str) -> int:
    """Return the byte cap for a known artifact type."""

    try:
        return MAX_ARTIFACT_BYTES[artifact_name]
    except KeyError as exc:
        raise ValueError(f"unknown artifact type: {artifact_name}") from exc


def scan_depth(raw: bytes, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Reject over-deep JSON before handing bytes to the parser.

    The scanner only tracks structural brackets outside JSON strings. It is not a
    replacement parser; it is a cheap pre-parser guard that keeps recursion-heavy
    inputs away from ``json.loads``.
    """

    depth = 0
    in_string = False
    escaped = False

    for byte in raw:
        char = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise LimitExceeded(f"JSON depth exceeds limit {max_depth}")
        elif char in "]}":
            depth = max(0, depth - 1)
