"""Offline, protected, and runtime-configured name-hygiene checks."""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from repolens.security.errors import NameHygieneError
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

ENV_FORBIDDEN_TERMS = "NAME_HYGIENE_FORBIDDEN_TERMS"
_BINARY_SAMPLE_BYTES = 4096


@dataclass(frozen=True)
class AllowlistEntry:
    path_glob: str
    pattern: str
    reason: str


@dataclass(frozen=True)
class NameHygieneViolation:
    path: str
    pattern: str


@dataclass(frozen=True, slots=True)
class NameHygieneFinding:
    path: Path
    line: int
    term: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: forbidden runtime term matched"


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


def scan_tracked_files(
    root: Path,
    forbidden_terms: list[str],
) -> list[NameHygieneFinding]:
    root = Path(root)
    terms = _normalize_terms(forbidden_terms)
    if not terms:
        return []
    findings: list[NameHygieneFinding] = []
    for relative in _tracked_files(root):
        path = root / relative
        if _is_binary(path):
            continue
        findings.extend(_scan_file(path, relative, terms))
    return findings


def assert_clean(root: Path, forbidden_terms: list[str]) -> None:
    findings = scan_tracked_files(root, forbidden_terms)
    if findings:
        rendered = "\n".join(finding.render() for finding in findings)
        raise NameHygieneError(rendered)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--forbidden", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    terms = _normalize_terms([*args.forbidden, *_terms_from_env()])
    if not terms:
        print(f"no forbidden terms supplied; configure {ENV_FORBIDDEN_TERMS}", file=sys.stderr)
        return 2
    findings = scan_tracked_files(args.root, terms)
    for finding in findings:
        print(finding.render(), file=sys.stderr)
    return 1 if findings else 0


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


def _self_test() -> int:
    sentinel = "acme-runtime-forbidden-sentinel"
    with tempfile.TemporaryDirectory(prefix="name-hygiene-") as raw:
        root = Path(raw)
        _git(root, "init")
        _git(root, "config", "user.email", "acme@example.invalid")
        _git(root, "config", "user.name", "Acme Tester")
        target = root / "tracked.txt"
        target.write_text(f"contains {sentinel}\n", encoding="utf-8")
        _git(root, "add", "tracked.txt")
        findings = scan_tracked_files(root, [sentinel])
        if not findings:
            print("self-test did not detect seeded tracked violation", file=sys.stderr)
            return 1
    return 0


def _tracked_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise NameHygieneError("git ls-files failed")
    return [Path(line) for line in completed.stdout.splitlines() if line.strip()]


def _scan_file(path: Path, relative: Path, terms: list[str]) -> list[NameHygieneFinding]:
    findings: list[NameHygieneFinding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return findings
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        for term in terms:
            if term.lower() in lowered:
                findings.append(NameHygieneFinding(relative, line_number, term))
    return findings


def _normalize_terms(terms: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for term in terms:
        stripped = term.strip()
        if not stripped:
            continue
        folded = stripped.lower()
        if folded not in seen:
            normalized.append(stripped)
            seen.add(folded)
    return normalized


def _terms_from_env() -> list[str]:
    raw = os.environ.get(ENV_FORBIDDEN_TERMS, "")
    terms: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        if chunk.strip():
            terms.append(chunk.strip())
    return terms


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:_BINARY_SAMPLE_BYTES]
    except OSError:
        return True
    return b"\x00" in sample


def _git(root: Path, *args: str) -> None:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise NameHygieneError(f"git {' '.join(args)} failed")


if __name__ == "__main__":
    raise SystemExit(main())
