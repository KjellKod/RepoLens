"""Safe parsers for untrusted structured data and archives."""

from __future__ import annotations

import io
import json
import re
import signal
import stat
import tarfile
import threading
import time
import zipfile
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
from typing import TypeVar
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError as XmlParseError

import yaml
from defusedxml import ElementTree as DefusedElementTree

from repolens.security.errors import ParseSecurityError
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits

T = TypeVar("T")
_YAML_ALIAS_TOKEN_RE = re.compile(r"(?<![\w-])[&*][A-Za-z0-9_-]+")


class UnsafeArchiveError(ValueError):
    """Raised when an archive exceeds configured safety limits."""


@dataclass(frozen=True, slots=True)
class ArchiveInspection:
    """Metadata summary for an archive inspected without extraction."""

    entries: int
    total_uncompressed_bytes: int


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


def parse_yaml_bytes(data: bytes, limits: SecurityLimits = DEFAULT_LIMITS) -> object:
    _enforce_byte_cap(data, limits)
    text = _decode_utf8(data)
    if _yaml_alias_token_count(text) > limits.max_yaml_alias_tokens:
        raise ParseSecurityError("YAML alias or anchor token cap exceeded")

    def parse() -> object:
        try:
            return yaml.safe_load(text)
        except RecursionError as exc:
            raise ParseSecurityError("YAML nesting exceeds parser safety limits") from exc
        except yaml.YAMLError as exc:
            raise ParseSecurityError("invalid YAML") from exc

    result = _run_with_timeout(parse, limits)
    _validate_structure(result, limits)
    return result


def parse_xml_bytes(data: bytes, limits: SecurityLimits = DEFAULT_LIMITS):
    _enforce_byte_cap(data, limits)
    text = _decode_utf8(data)
    if "<!doctype" in text.lower():
        raise ParseSecurityError("XML DOCTYPE is blocked")

    def parse():
        try:
            return DefusedElementTree.fromstring(data)
        except XmlParseError as exc:
            raise ParseSecurityError("invalid XML") from exc

    root = _run_with_timeout(parse, limits)
    _validate_xml_tree(root, limits)
    return root


def parse_json_bytes(data: bytes, limits: SecurityLimits = DEFAULT_LIMITS) -> object:
    _enforce_byte_cap(data, limits)
    text = _decode_utf8(data)

    def parse() -> object:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseSecurityError("invalid JSON") from exc

    result = _run_with_timeout(parse, limits)
    _validate_structure(result, limits)
    return result


def inspect_archive(data: bytes, limits: SecurityLimits = DEFAULT_LIMITS) -> ArchiveInspection:
    _enforce_byte_cap(data, limits)

    def inspect() -> ArchiveInspection:
        raw = io.BytesIO(data)
        if zipfile.is_zipfile(raw):
            raw.seek(0)
            return _inspect_zip(raw, limits)
        raw.seek(0)
        try:
            return _inspect_tar(raw, limits)
        except tarfile.TarError as exc:
            raise ParseSecurityError("unsupported archive format") from exc

    return _run_with_timeout(inspect, limits)


def _inspect_zip(raw: io.BytesIO, limits: SecurityLimits) -> ArchiveInspection:
    total = 0
    with zipfile.ZipFile(raw) as archive:
        infos = archive.infolist()
        _check_entry_count(len(infos), limits)
        for info in infos:
            _validate_archive_path(info.filename)
            if _zip_entry_is_symlink(info):
                raise ParseSecurityError("archive links are blocked")
            if info.is_dir():
                continue
            _check_entry_size(info.file_size, limits)
            _check_ratio(info.file_size, info.compress_size, limits)
            total += info.file_size
            _check_total_size(total, limits)
    return ArchiveInspection(entries=len(infos), total_uncompressed_bytes=total)


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def _inspect_tar(raw: io.BytesIO, limits: SecurityLimits) -> ArchiveInspection:
    total = 0
    with tarfile.open(fileobj=raw) as archive:
        members = archive.getmembers()
        _check_entry_count(len(members), limits)
        for member in members:
            _validate_archive_path(member.name)
            if member.issym() or member.islnk():
                raise ParseSecurityError("archive links are blocked")
            if member.isdir():
                continue
            _check_entry_size(member.size, limits)
            total += member.size
            _check_total_size(total, limits)
    return ArchiveInspection(entries=len(members), total_uncompressed_bytes=total)


def _enforce_byte_cap(data: bytes, limits: SecurityLimits) -> None:
    if len(data) > limits.max_parse_bytes:
        raise ParseSecurityError("input exceeds parse byte cap")


def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseSecurityError("input is not valid UTF-8") from exc


def _yaml_alias_token_count(text: str) -> int:
    return len(_YAML_ALIAS_TOKEN_RE.findall(text))


def _validate_structure(value: object, limits: SecurityLimits) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_structure_nodes:
            raise ParseSecurityError("parsed node cap exceeded")
        if depth > limits.max_structure_depth:
            raise ParseSecurityError("parsed depth cap exceeded")
        if isinstance(item, dict):
            stack.extend((key, depth + 1) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list | tuple | set):
            stack.extend((child, depth + 1) for child in item)


def _validate_xml_tree(root, limits: SecurityLimits) -> None:
    stack = [(root, 0)]
    nodes = 0
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_structure_nodes:
            raise ParseSecurityError("XML node cap exceeded")
        if depth > limits.max_structure_depth:
            raise ParseSecurityError("XML depth cap exceeded")
        stack.extend((child, depth + 1) for child in list(element))


def _validate_archive_path(name: str) -> None:
    if "\\" in name:
        raise ParseSecurityError("archive path traversal is blocked")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ParseSecurityError("archive path traversal is blocked")


def _check_entry_count(count: int, limits: SecurityLimits) -> None:
    if count > limits.max_archive_entries:
        raise ParseSecurityError("archive entry count cap exceeded")


def _check_entry_size(size: int, limits: SecurityLimits) -> None:
    if size > limits.max_archive_entry_uncompressed_bytes:
        raise ParseSecurityError("archive entry size cap exceeded")


def _check_total_size(total: int, limits: SecurityLimits) -> None:
    if total > limits.max_archive_total_uncompressed_bytes:
        raise ParseSecurityError("archive total size cap exceeded")


def _check_ratio(size: int, compressed: int, limits: SecurityLimits) -> None:
    if size <= 0:
        return
    if compressed <= 0:
        raise ParseSecurityError("archive compression ratio cap exceeded")
    if (size / compressed) > limits.max_archive_compression_ratio:
        raise ParseSecurityError("archive compression ratio cap exceeded")


def _run_with_timeout(func: Callable[[], T], limits: SecurityLimits) -> T:
    timeout = limits.parse_timeout_seconds
    if timeout <= 0:
        raise ParseSecurityError("parse timeout must be positive")
    started = time.monotonic()
    try:
        with _deadline(timeout):
            return func()
    except TimeoutError as exc:
        raise ParseSecurityError("parse timed out") from exc
    finally:
        if time.monotonic() - started > timeout:
            raise ParseSecurityError("parse timed out")


@contextmanager
def _deadline(seconds: float):
    if threading.current_thread() is not threading.main_thread():
        raise ParseSecurityError("parse timeout requires main-thread parsing")
    if not hasattr(signal, "setitimer"):
        raise ParseSecurityError("parse timeout is not supported on this platform")

    previous_handler = signal.getsignal(signal.SIGALRM)

    def _raise_timeout(signum, frame) -> None:
        del signum, frame
        raise TimeoutError("parse timed out")

    signal.signal(signal.SIGALRM, _raise_timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


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
