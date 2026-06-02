"""On-disk RepoLens artifact store."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from repolens.data.errors import CorruptArtifactError, LimitExceeded, SchemaValidationError
from repolens.data.limits import (
    MAX_JSON_DEPTH,
    MAX_NDJSON_LINE_BYTES,
    MAX_NDJSON_RECORDS,
    SCHEMA_VERSION,
    max_bytes_for,
    scan_depth,
)
from repolens.data.redact import redact_tokens
from repolens.data.validation import validate_artifact


def repo_dir(work_root: str | Path, repo_ref: str) -> Path:
    """Return the per-repository artifact directory."""

    return Path(work_root) / "work" / _repo_ref_dirname(repo_ref)


def _repo_ref_dirname(repo_ref: str) -> str:
    if repo_ref in {"", ".", ".."}:
        raise ValueError("repo_ref must not be empty, '.' or '..'")
    encoded = quote(repo_ref, safe="")
    return encoded


def _artifact_path(work_root: str | Path, artifact_name: str, repo_ref: str | None = None) -> Path:
    root = Path(work_root)
    if artifact_name == "sbom":
        if repo_ref is None:
            raise ValueError("repo_ref is required for sbom artifacts")
        return repo_dir(root, repo_ref) / "sbom.syft.json"
    if artifact_name == "resolved":
        if repo_ref is None:
            raise ValueError("repo_ref is required for resolved artifacts")
        return repo_dir(root, repo_ref) / "resolved.ndjson"
    if artifact_name == "inventory":
        return root / "inventory.json"
    if artifact_name == "shortlist":
        return root / "shortlist.json"
    raise ValueError(f"unknown artifact type: {artifact_name}")


def atomic_write_bytes(path: str | Path, data: bytes) -> None:
    """Write bytes atomically using a same-directory temporary file."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        ) as handle:
            temp_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
        temp_name = None
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temp_name is not None:
            try:
                Path(temp_name).unlink()
            except FileNotFoundError:
                pass


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def atomic_write_json(path: str | Path, value: Any) -> None:
    atomic_write_bytes(path, _json_bytes(value))


def atomic_write_ndjson(path: str | Path, records: Iterable[dict[str, Any]]) -> None:
    lines = [_json_bytes(record).rstrip(b"\n") for record in records]
    atomic_write_bytes(path, b"\n".join(lines) + (b"\n" if lines else b""))


def load_json_capped(
    path: str | Path,
    *,
    max_bytes: int,
    max_depth: int = MAX_JSON_DEPTH,
) -> Any:
    """Read JSON with size and depth guards before full parser trust."""

    artifact = Path(path)
    raw = _read_capped_bytes(artifact, max_bytes)
    scan_depth(raw, max_depth)
    try:
        return json.loads(raw)
    except RecursionError as exc:
        raise LimitExceeded(f"{artifact} exceeds JSON depth limit {max_depth}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = f"{artifact} is not valid JSON: {_parse_error_message(exc)}"
        raise CorruptArtifactError(message) from exc


def write_sbom(work_root: str | Path, repo_ref: str, value: dict[str, Any]) -> Path:
    return _write_json_artifact(work_root, "sbom", value, repo_ref=repo_ref)


def write_inventory(work_root: str | Path, value: dict[str, Any]) -> Path:
    return _write_json_artifact(work_root, "inventory", value)


def write_shortlist(work_root: str | Path, value: dict[str, Any]) -> Path:
    return _write_json_artifact(work_root, "shortlist", value)


def _write_json_artifact(
    work_root: str | Path,
    artifact_name: str,
    value: dict[str, Any],
    *,
    repo_ref: str | None = None,
) -> Path:
    redacted = redact_tokens(value)
    validate_artifact(redacted, artifact_name)
    path = _artifact_path(work_root, artifact_name, repo_ref)
    data = _json_bytes(redacted)
    _check_bytes(data, max_bytes_for(artifact_name), path)
    scan_depth(data, MAX_JSON_DEPTH)
    atomic_write_bytes(path, data)
    return path


def write_resolved(
    work_root: str | Path,
    repo_ref: str,
    records: Iterable[dict[str, Any]],
) -> Path:
    stamped = []
    for record in records:
        redacted = redact_tokens(
            {**record, "schema_version": record.get("schema_version", SCHEMA_VERSION)}
        )
        validate_artifact(redacted, "resolved")
        stamped.append(redacted)
    path = _artifact_path(work_root, "resolved", repo_ref)
    data = _checked_ndjson_bytes(path, stamped)
    atomic_write_bytes(path, data)
    return path


def read_sbom(work_root: str | Path, repo_ref: str) -> dict[str, Any]:
    return _read_json_artifact(work_root, "sbom", repo_ref=repo_ref)


def read_inventory(work_root: str | Path) -> dict[str, Any]:
    return _read_json_artifact(work_root, "inventory")


def read_shortlist(work_root: str | Path) -> dict[str, Any]:
    return _read_json_artifact(work_root, "shortlist")


def _read_json_artifact(
    work_root: str | Path,
    artifact_name: str,
    *,
    repo_ref: str | None = None,
) -> dict[str, Any]:
    path = _artifact_path(work_root, artifact_name, repo_ref)
    value = load_json_capped(path, max_bytes=max_bytes_for(artifact_name))
    validate_artifact(value, artifact_name)
    if not isinstance(value, dict):
        raise SchemaValidationError(f"{artifact_name}: expected object")
    return value


def iter_resolved(
    path: str | Path,
    *,
    max_bytes: int | None = None,
    max_records: int = MAX_NDJSON_RECORDS,
    max_line_bytes: int = MAX_NDJSON_LINE_BYTES,
) -> Iterable[dict[str, Any]]:
    """Yield validated resolved records from an NDJSON file."""

    artifact = Path(path)
    byte_cap = max_bytes if max_bytes is not None else max_bytes_for("resolved")
    total_bytes = 0
    with artifact.open("rb") as handle:
        for index, line in enumerate(handle, start=1):
            total_bytes += len(line)
            if total_bytes > byte_cap:
                raise LimitExceeded(f"{artifact} exceeds {byte_cap} bytes")
            if index > max_records:
                raise LimitExceeded(f"{artifact} exceeds {max_records} records")
            if len(line) > max_line_bytes:
                raise LimitExceeded(f"{artifact}:{index} exceeds {max_line_bytes} bytes")
            if not line.strip():
                continue
            scan_depth(line, MAX_JSON_DEPTH)
            try:
                record = json.loads(line)
            except RecursionError as exc:
                raise LimitExceeded(f"{artifact}:{index} exceeds JSON depth limit") from exc
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                message = f"{artifact}:{index} is not valid JSON: {_parse_error_message(exc)}"
                raise CorruptArtifactError(message) from exc
            validate_artifact(record, "resolved")
            if not isinstance(record, dict):
                raise SchemaValidationError(f"resolved:{index}: expected object")
            yield record


def is_repo_scanned(work_root: str | Path, repo_ref: str) -> bool:
    """Return true only when the final SBOM artifact is present and valid."""

    path = _artifact_path(work_root, "sbom", repo_ref)
    if not path.exists():
        return False
    try:
        read_sbom(work_root, repo_ref)
    except (CorruptArtifactError, LimitExceeded, SchemaValidationError, OSError):
        return False
    return True


def _parse_error_message(exc: UnicodeDecodeError | json.JSONDecodeError) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return exc.msg
    return exc.reason


def _read_capped_bytes(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    _check_bytes(data, max_bytes, path)
    return data


def _checked_ndjson_bytes(path: Path, records: list[dict[str, Any]]) -> bytes:
    if len(records) > MAX_NDJSON_RECORDS:
        raise LimitExceeded(f"{path} exceeds {MAX_NDJSON_RECORDS} records")
    lines: list[bytes] = []
    for index, record in enumerate(records, start=1):
        line = _json_bytes(record).rstrip(b"\n")
        if len(line) > MAX_NDJSON_LINE_BYTES:
            raise LimitExceeded(f"{path}:{index} exceeds {MAX_NDJSON_LINE_BYTES} bytes")
        scan_depth(line, MAX_JSON_DEPTH)
        lines.append(line)
    data = b"\n".join(lines) + (b"\n" if lines else b"")
    _check_bytes(data, max_bytes_for("resolved"), path)
    return data


def _check_bytes(data: bytes, max_bytes: int, path: Path) -> None:
    if len(data) > max_bytes:
        raise LimitExceeded(f"{path} exceeds {max_bytes} bytes")
