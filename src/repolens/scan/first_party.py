"""Detect a repository's own first-party / workspace-member package names.

The scan stage is the only place with a checkout, so first-party detection lives
here: parse the repo's *own* workspace manifests (Cargo, npm, and the root Python
project) and collect the set of package names it declares for itself. Later stages
consume the persisted set by name (the SBOM identity for an unpublished member is
just its name, e.g. ``pkg:cargo/diffly-app@…``).

Parsing runs over an **untrusted** clone, so every read is bounded and best-effort:
globs resolve only *under* the clone root, escaping paths (``..``, absolute, or
symlink-out) are rejected, the expanded member count and per-file read size are
capped, and any parse/IO error contributes nothing rather than aborting detection.
The module imports nothing that pulls ``jsonschema`` so it stays usable under the
scan import-discipline (security-canary) gate.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterator
from pathlib import Path

from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits

#: Upper bound on workspace members expanded from a single repo's manifests. A
#: hostile repo could declare pathological globs (``**/*``); this caps the file
#: I/O detection performs while comfortably exceeding any real workspace size.
MAX_WORKSPACE_MEMBERS = 2_000

_GLOB_METACHARS = ("*", "?", "[")


def collect_first_party_names(
    source_root: Path, *, limits: SecurityLimits = DEFAULT_LIMITS
) -> list[str]:
    """Return the sorted, deduped set of the repo's own declared package names.

    Union of Cargo workspace members, npm workspace members, and the root Python
    project name (each including the root package name when present). Pure file
    reads under ``source_root`` only; unreadable or malformed manifests simply
    contribute nothing.
    """

    root = source_root.resolve()
    names: set[str] = set()
    names.update(_cargo_workspace_names(root, limits))
    names.update(_npm_workspace_names(root, limits))
    python_name = _python_project_name(root, limits)
    if python_name is not None:
        names.add(python_name)
    return sorted(names)


def _cargo_workspace_names(root: Path, limits: SecurityLimits) -> set[str]:
    data = _read_toml_capped(root / "Cargo.toml", limits)
    if data is None:
        return set()

    names: set[str] = set()
    root_name = _cargo_package_name(data)
    if root_name is not None:
        names.add(root_name)

    workspace = data.get("workspace")
    if not isinstance(workspace, dict):
        return names
    patterns = _string_list(workspace.get("members"))
    for member_dir in _safe_member_dirs(root, patterns, limits):
        member_data = _read_toml_capped(member_dir / "Cargo.toml", limits)
        if member_data is None:
            continue
        member_name = _cargo_package_name(member_data)
        if member_name is not None:
            names.add(member_name)
    return names


def _cargo_package_name(data: dict[str, object]) -> str | None:
    package = data.get("package")
    if not isinstance(package, dict):
        return None
    return _non_empty_str(package.get("name"))


def _npm_workspace_names(root: Path, limits: SecurityLimits) -> set[str]:
    data = _read_json_capped(root / "package.json", limits)
    if not isinstance(data, dict):
        return set()

    names: set[str] = set()
    root_name = _non_empty_str(data.get("name"))
    if root_name is not None:
        names.add(root_name)

    for member_dir in _safe_member_dirs(root, _npm_workspace_patterns(data), limits):
        member_data = _read_json_capped(member_dir / "package.json", limits)
        if not isinstance(member_data, dict):
            continue
        member_name = _non_empty_str(member_data.get("name"))
        if member_name is not None:
            names.add(member_name)
    return names


def _npm_workspace_patterns(data: dict[str, object]) -> list[str]:
    """Accept both the array form ``["pkgs/*"]`` and the ``{"packages": [...]}`` form."""

    workspaces = data.get("workspaces")
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages")
    return _string_list(workspaces)


def _python_project_name(root: Path, limits: SecurityLimits) -> str | None:
    """Return the repo's own ``[project].name`` from root ``pyproject.toml``.

    Best-effort and stored as declared: a repo rarely lists itself as its own
    dependency, so PyPI-style normalization mismatches are low-impact (see Risks).
    """

    data = _read_toml_capped(root / "pyproject.toml", limits)
    if data is None:
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    return _non_empty_str(project.get("name"))


def _safe_member_dirs(root: Path, patterns: list[str], limits: SecurityLimits) -> list[Path]:
    """Resolve member path/glob patterns to directories strictly under ``root``.

    Patterns with glob metacharacters are expanded lazily with ``Path.glob`` and
    capped at :data:`MAX_WORKSPACE_MEMBERS`; others are treated as direct
    subdirectories. Any resolved path that escapes ``root`` — via ``..``, an
    absolute pattern, or a symlink pointing out — is rejected.
    """

    del limits  # bounds come from the member cap; no per-pattern byte budget here
    dirs: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for candidate_count, candidate in enumerate(_expand_pattern(root, pattern), start=1):
            if candidate_count > MAX_WORKSPACE_MEMBERS:
                break
            if len(seen) >= MAX_WORKSPACE_MEMBERS:
                return dirs
            resolved = _under_root(root, candidate)
            if resolved is None or resolved in seen:
                continue
            if not resolved.is_dir():
                continue
            seen.add(resolved)
            dirs.append(resolved)
    return dirs


def _expand_pattern(root: Path, pattern: str) -> Iterator[Path]:
    normalized = pattern.strip().replace("\\", "/")
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return
    if any(char in normalized for char in _GLOB_METACHARS):
        try:
            yield from root.glob(normalized)
        except (OSError, ValueError):
            return
    else:
        yield root / normalized


def _under_root(root: Path, candidate: Path) -> Path | None:
    """Resolve ``candidate`` and return it only when it is a path strictly under ``root``."""

    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    if resolved == root:
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def _read_text_capped(path: Path, limits: SecurityLimits) -> str | None:
    try:
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            data = handle.read(limits.max_parse_bytes + 1)
    except OSError:
        return None
    if len(data) > limits.max_parse_bytes:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_toml_capped(path: Path, limits: SecurityLimits) -> dict[str, object] | None:
    text = _read_text_capped(path, limits)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_json_capped(path: Path, limits: SecurityLimits) -> object:
    text = _read_text_capped(path, limits)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _non_empty_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
