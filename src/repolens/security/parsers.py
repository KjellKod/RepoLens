"""Safe parsing helpers for untrusted metadata."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from xml.etree import ElementTree


class UnsafeArchiveError(ValueError):
    """Raised when an archive exceeds configured safety limits."""


def load_yaml_safe(text: str) -> object:
    """Load a small YAML subset without anchors, tags, or object construction."""

    forbidden = ("!!", "&", "*", "<<:")
    if any(token in text for token in forbidden):
        raise ValueError("unsafe yaml feature rejected")

    result: dict[str, object] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            raise ValueError("unsupported yaml syntax")
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError("yaml key is required")
        result[key] = _parse_scalar(value)
    return result


def parse_xml_safe(text: str) -> ElementTree.Element:
    """Reject XML declarations that can enable entity expansion before parsing."""

    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("unsafe xml declaration rejected")
    return ElementTree.fromstring(text)


def validate_archive_limits(
    data: bytes,
    *,
    max_compression_ratio: float = 100.0,
    max_uncompressed_bytes: int = 500 * 1024 * 1024,
) -> None:
    """Reject zip archives that exceed ratio or uncompressed-size caps."""

    with zipfile.ZipFile(BytesIO(data)) as archive:
        total_uncompressed = 0
        for member in archive.infolist():
            total_uncompressed += member.file_size
            compressed = max(member.compress_size, 1)
            ratio = member.file_size / compressed
            if ratio > max_compression_ratio:
                raise UnsafeArchiveError("archive compression ratio exceeds limit")
            if total_uncompressed > max_uncompressed_bytes:
                raise UnsafeArchiveError("archive uncompressed size exceeds limit")


def _parse_scalar(value: str) -> object:
    if value in {"", "null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if value.startswith("[") or value.startswith("{"):
        return json.loads(value)
    if value.isdecimal():
        return int(value)
    return value.strip("\"'")
