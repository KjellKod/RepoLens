"""Offline and protected name-hygiene checks."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from repolens.security.secrets import TOKEN_PATTERNS


_SYNTHETIC_SENTINEL_PARTS = ("x2", "synthetic", "forbidden", "name")
SYNTHETIC_SENTINEL = "-".join(_SYNTHETIC_SENTINEL_PARTS)
_SENTINEL_PATTERN = re.compile(re.escape(SYNTHETIC_SENTINEL), re.IGNORECASE)
_ENV_DENYLIST_FILE = "REPOLENS_NAME_HYGIENE_DENYLIST_FILE"
_ENV_FORBIDDEN_NAMES = "REPOLENS_FORBIDDEN_NAMES"
_ENV_MODE = "REPOLENS_NAME_HYGIENE_MODE"
_ALLOWED_ALLOWLIST_GLOB = "tests/fixtures/security/**"
_DEFAULT_SCAN_ROOTS = (
    "src",
    "scripts",
    "tests",
    ".github",
    ".ai",
    ".skills",
    "docs",
    "README.md",
    "CONTRIBUTING.md",
)
_EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".git", ".quest"}
_FORBIDDEN_ALLOWLIST_PREFIXES = (
    "src/",
    "docs/",
    ".github/",
    "tests/security/",
    "tests/canaries/security/",
)


@dataclass(frozen=True)
class AllowlistEntry:
    path_glob: str
    pattern: str
    reason: str


@dataclass(frozen=True)
class NameHygieneViolation:
    path: str
    pattern: str


def committed_patterns() -> tuple[re.Pattern[str], ...]:
    return (*TOKEN_PATTERNS, _SENTINEL_PATTERN)


def load_forbidden_patterns(mode: str | None = None) -> tuple[re.Pattern[str], ...]:
    selected_mode = (mode or os.environ.get(_ENV_MODE) or "offline").strip().lower()
    patterns = list(committed_patterns())

    if selected_mode == "offline":
        return tuple(patterns)
    if selected_mode != "protected":
        raise ValueError("unsupported name hygiene mode")

    denied_names = _load_protected_names()
    patterns.extend(re.compile(re.escape(name), re.IGNORECASE) for name in denied_names)
    return tuple(patterns)


def scan_paths(
    root: Path,
    paths: list[Path],
    *,
    patterns: tuple[re.Pattern[str], ...],
    allowlist: tuple[AllowlistEntry, ...] = (),
) -> list[NameHygieneViolation]:
    validate_allowlist(allowlist)
    violations: list[NameHygieneViolation] = []
    for path in paths:
        rel_path = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            if pattern.search(text) and not _is_allowed(rel_path, pattern.pattern, allowlist):
                violations.append(NameHygieneViolation(path=rel_path, pattern=pattern.pattern))
    return violations


def scan_repository(
    root: Path,
    *,
    patterns: tuple[re.Pattern[str], ...],
    allowlist: tuple[AllowlistEntry, ...] = (),
    scan_roots: tuple[str, ...] = _DEFAULT_SCAN_ROOTS,
) -> list[NameHygieneViolation]:
    """Scan committed text surfaces that are part of the offline security gate."""

    paths = list(_iter_text_paths(root, scan_roots))
    return scan_paths(root, paths, patterns=patterns, allowlist=allowlist)


def validate_allowlist(entries: tuple[AllowlistEntry, ...]) -> None:
    for entry in entries:
        if not entry.path_glob or not entry.pattern or not entry.reason:
            raise ValueError("allowlist entries require path_glob, pattern, and reason")
        normalized = entry.path_glob.removeprefix("./")
        if not fnmatch.fnmatch(normalized, _ALLOWED_ALLOWLIST_GLOB):
            raise ValueError("allowlist entries must be bounded to synthetic fixtures")
        if normalized.startswith(_FORBIDDEN_ALLOWLIST_PREFIXES):
            raise ValueError("allowlist cannot cover protected source or test paths")


def _load_protected_names() -> list[str]:
    names: list[str] = []
    denylist_path = os.environ.get(_ENV_DENYLIST_FILE)
    if denylist_path:
        path = Path(denylist_path)
        if not path.is_file():
            raise RuntimeError("protected denylist file is missing")
        names.extend(line.strip() for line in path.read_text(encoding="utf-8").splitlines())

    env_names = os.environ.get(_ENV_FORBIDDEN_NAMES, "")
    names.extend(name.strip() for name in env_names.split(","))
    filtered = [name for name in names if name]
    if not filtered:
        raise RuntimeError("protected denylist is required")
    return filtered


def _is_allowed(
    rel_path: str,
    pattern_text: str,
    allowlist: tuple[AllowlistEntry, ...],
) -> bool:
    return any(
        fnmatch.fnmatch(rel_path, entry.path_glob) and pattern_text == entry.pattern
        for entry in allowlist
    )


def _iter_text_paths(root: Path, scan_roots: tuple[str, ...]) -> list[Path]:
    paths: list[Path] = []
    for rel_root in scan_roots:
        candidate = root / rel_root
        if candidate.is_file():
            paths.append(candidate)
            continue
        if not candidate.is_dir():
            continue
        for path in candidate.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _EXCLUDED_DIRS for part in path.parts):
                continue
            try:
                path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            paths.append(path)
    return paths
