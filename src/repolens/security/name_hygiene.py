"""Canonical name-hygiene guard for RepoLens.

This is the single home for every name-hygiene concern (see
``docs/roadmap/rpl_execution.md`` → *Where things live*). It is invoked as::

    python -m repolens.security.name_hygiene [--root PATH] [--forbidden-name NAME ...]
                                             [--local-config PATH] [--require-denylist]
                                             [--self-test]

It folds together what used to be six parallel implementations:

* **Offline committed-surface scan** — token + synthetic-sentinel patterns over the
  committed text surfaces that the security canary gate anchors on
  (:func:`committed_patterns`, :func:`scan_repository`, :func:`load_forbidden_patterns`).
* **Runtime forbidden-name scan** — fail-closed denylist matching over the tracked /
  scannable tree, with hashed token ids so a real name never lands in CI logs
  (:func:`run`, :func:`main`). The denylist is supplied at runtime only, via the single
  env var ``REPOLENS_FORBIDDEN_NAMES`` (comma/newline-separated), ``--forbidden-name``,
  or a discovered ``*.local.*`` config (:func:`discover_local_config`).
* **Structural leak checks** — token literals and non-neutral URLs/domains in
  structural surfaces (:func:`structural_findings`).

The forbidden-names denylist is NEVER committed. Real owner/repo/company names live in a
gitignored ``.name-hygiene.local.json`` (or a CI variable) — the repo holds only the
matcher logic.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from repolens.security.errors import NameHygieneError
from repolens.security.redaction import committed_token_patterns

_SYNTHETIC_SENTINEL_PARTS = ("x2", "synthetic", "forbidden", "name")
SYNTHETIC_SENTINEL = "-".join(_SYNTHETIC_SENTINEL_PARTS)
_SENTINEL_PATTERN = re.compile(re.escape(SYNTHETIC_SENTINEL), re.IGNORECASE)

_ENV_DENYLIST_FILE = "REPOLENS_NAME_HYGIENE_DENYLIST_FILE"
#: The single canonical env var for the runtime forbidden-names denylist.
ENV_FORBIDDEN_NAMES = "REPOLENS_FORBIDDEN_NAMES"
#: Deprecated aliases kept only so existing callers keep working. Prefer
#: ``REPOLENS_FORBIDDEN_NAMES`` everywhere.
_DEPRECATED_FORBIDDEN_NAME_ALIASES = (
    "NAME_HYGIENE_FORBIDDEN_TERMS",
    "REPOLENS_NAME_DENYLIST",
)
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

_BINARY_SAMPLE_BYTES = 4096

DEFAULT_LOCAL_CONFIG = ".name-hygiene.local.json"
SKIPPED_SEGMENTS = {
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".quest",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".worktrees",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "venv",
}

# Structural checks (migrated from the former scripts/check_name_hygiene.py).
_STRUCTURAL_TEXT_EXTENSIONS = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".rst",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_STRUCTURAL_TEXT_FILENAMES = {".gitignore", "Dockerfile", "LICENSE", "Makefile"}
_STRUCTURAL_SEGMENTS = {"docs", "schemas", "schema", "fixtures", "fixture"}
_NEUTRAL_HOSTS = {
    "127.0.0.1",
    "::1",
    "example.com",
    "example.net",
    "example.org",
    "json-schema.org",
    "localhost",
}
_NEUTRAL_SUFFIXES = (".example", ".invalid", ".localhost", ".test")
_CLASSIC_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_FINE_GRAINED_GITHUB_TOKEN_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s<>)\"']+", re.IGNORECASE)
_KEYED_DOMAIN_RE = re.compile(
    r"['\"]?\b(?:domain|host|hostname|homepage|site|url|uri|website)\b['\"]?"
    r"\s*[:=]\s*['\"]?(?P<value>(?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
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


@dataclass(frozen=True, slots=True)
class NameHygieneFinding:
    path: Path
    line: int
    term: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: forbidden runtime term matched"


@dataclass(frozen=True)
class StructuralFinding:
    path: Path
    line: int
    check: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.check}: {self.detail}"


@dataclass(frozen=True)
class RuntimeFinding:
    """A runtime forbidden-name match, reported only via a non-reversible token id."""

    path: str
    token: str

    def to_public_dict(self) -> dict[str, str]:
        token_hash = hashlib.sha256(self.token.encode("utf-8")).hexdigest()
        return {"path": self.path, "token_id": f"sha256:{token_hash[:16]}"}


# --------------------------------------------------------------------------------------
# Offline committed-surface scan (token families + synthetic sentinel)
# --------------------------------------------------------------------------------------


def committed_patterns() -> tuple[re.Pattern[str], ...]:
    return (*committed_token_patterns(), _SENTINEL_PATTERN)


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


# --------------------------------------------------------------------------------------
# Runtime tracked-tree scan (fail-closed denylist matching, hashed reporting)
# --------------------------------------------------------------------------------------


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


def run(root: Path, tokens: list[str], require_denylist: bool) -> tuple[int, dict[str, object]]:
    """Scan ``root`` for the case-folded ``tokens``; fail-closed when configured.

    Returns ``(exit_code, public_result)`` where ``public_result`` is JSON-safe and never
    contains the forbidden literals — only ``sha256:`` token ids.
    """

    if not tokens:
        result = {
            "denylist_status": "absent",
            "files_scanned": 0,
            "findings": [],
            "passed": not require_denylist,
        }
        return (1 if require_denylist else 0), result

    findings: list[RuntimeFinding] = []
    files = iter_candidate_files(root)
    display_root = root if root.is_dir() else root.parent
    for path in files:
        findings.extend(_scan_runtime_file(path, display_root, tokens))

    result = {
        "denylist_status": "present",
        "files_scanned": len(files),
        "findings": [finding.to_public_dict() for finding in findings],
        "passed": not findings,
    }
    return (1 if findings else 0), result


# --------------------------------------------------------------------------------------
# Structural leak checks (token literals + non-neutral URLs/domains)
# --------------------------------------------------------------------------------------


def structural_findings(path: Path, text: str) -> list[StructuralFinding]:
    findings: list[StructuralFinding] = []
    for regex in (_CLASSIC_GITHUB_TOKEN_RE, _FINE_GRAINED_GITHUB_TOKEN_RE):
        for match in regex.finditer(text):
            findings.append(
                StructuralFinding(
                    path, _line_number(text, match.start()), "github-token", "redacted-token"
                )
            )

    if not _is_structural_candidate(path):
        return findings

    for match in _URL_RE.finditer(text):
        host = urlsplit(match.group(0)).hostname or ""
        if host and not _neutral_host(host):
            findings.append(
                StructuralFinding(path, _line_number(text, match.start()), "non-neutral-url", host)
            )

    for match in _KEYED_DOMAIN_RE.finditer(text):
        host = _host_from_domain_value(match.group("value"))
        if host and not _neutral_host(host):
            findings.append(
                StructuralFinding(
                    path, _line_number(text, match.start()), "non-neutral-domain", host
                )
            )

    return findings


_LITERAL_TEXT_EXTENSIONS = frozenset(
    {
        "",
        ".cfg",
        ".ini",
        ".json",
        ".md",
        ".mod",
        ".py",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)


def scan_literal_paths(root: Path, forbidden_tokens: list[str]) -> list[NameHygieneFinding]:
    """Scan text files under ``root`` for case-sensitive forbidden literal tokens.

    Fails closed: a missing root raises ``FileNotFoundError``. Used by the X1 test
    harness for its fixed owner/repo token set.
    """

    if not root.exists():
        raise FileNotFoundError(f"name hygiene root does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise NotADirectoryError(f"name hygiene root is not a file or directory: {root}")

    findings: list[NameHygieneFinding] = []
    for path in _iter_literal_text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        display_path = _literal_display_path(path, root)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for token in forbidden_tokens:
                if token and token in line:
                    findings.append(NameHygieneFinding(display_path, line_number, token))
    return findings


def _iter_literal_text_files(root: Path):
    if root.is_file():
        if _should_scan_literal(root):
            yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not _should_scan_literal(path):
            continue
        yield path


def _should_scan_literal(path: Path) -> bool:
    if set(path.parts).intersection(SKIPPED_SEGMENTS):
        return False
    if path.is_symlink():
        return False
    return path.suffix.lower() in _LITERAL_TEXT_EXTENSIONS


def _literal_display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def check_structural(paths: list[Path]) -> list[StructuralFinding]:
    findings: list[StructuralFinding] = []
    for path in paths:
        text = _read_structural_text(path)
        if text is None:
            continue
        findings.extend(structural_findings(path, text))
    return findings


# --------------------------------------------------------------------------------------
# Local-config discovery + denylist loading
# --------------------------------------------------------------------------------------


def parse_env_tokens(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace(",", "\n")
    return [line.strip() for line in normalized.splitlines() if line.strip()]


def forbidden_names_from_env() -> list[str]:
    """Collect runtime denylist tokens from the canonical env var (+ deprecated aliases)."""

    tokens: list[str] = list(parse_env_tokens(os.environ.get(ENV_FORBIDDEN_NAMES)))
    for alias in _DEPRECATED_FORBIDDEN_NAME_ALIASES:
        tokens.extend(parse_env_tokens(os.environ.get(alias)))
    return tokens


def load_local_config(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not fnmatch.fnmatch(path.name.lower(), "*.local.*"):
        raise ValueError("local denylist config path must match '*.local.*'")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        normalized = {str(key).lower(): value for key, value in payload.items()}
        values = normalized.get("forbidden_names", [])
    else:
        raise ValueError("local denylist config must be a JSON list or object")
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError("forbidden_names must be a list of strings")
    return [item.strip() for item in values if item.strip()]


def discover_local_config(root: Path) -> Path | None:
    for candidate_root in _candidate_config_roots(root):
        candidate = candidate_root / DEFAULT_LOCAL_CONFIG
        if candidate.exists():
            return candidate
        try:
            for child in candidate_root.iterdir():
                if child.name.casefold() == DEFAULT_LOCAL_CONFIG:
                    return child
        except OSError:
            continue
    return None


def normalize_tokens(tokens: list[str]) -> list[str]:
    return sorted({token.strip().casefold() for token in tokens if token.strip()})


def iter_candidate_files(root: Path) -> list[Path]:
    if not root.exists():
        raise FileNotFoundError(f"name hygiene root does not exist: {root}")
    if root.is_file():
        return [root]
    git_files = _git_files(root)
    if git_files:
        return [
            path
            for path, tracked in git_files
            if _should_scan_runtime(path.relative_to(root), tracked=tracked)
        ]
    return _walk_files(root)


def should_scan(relative_path: Path, *, tracked: bool = False) -> bool:
    # Retained as a public name for back-compat with the former scripts/ci entrypoint.
    return _should_scan_runtime(relative_path, tracked=tracked)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Canonical RepoLens name-hygiene guard.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--forbidden-name", action="append", default=[])
    parser.add_argument("--local-config", type=Path)
    parser.add_argument("--require-denylist", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.self_test:
        return _self_test()

    root = args.root.resolve()
    try:
        local_config = args.local_config or discover_local_config(root)
        tokens = [
            *args.forbidden_name,
            *forbidden_names_from_env(),
            *load_local_config(local_config),
        ]
        # run() is inside the try so a scan-time error (e.g. a missing --root
        # raising FileNotFoundError, an OSError subclass) becomes the clean JSON
        # error path below instead of an uncaught traceback.
        exit_code, result = run(
            root=root, tokens=normalize_tokens(tokens), require_denylist=args.require_denylist
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True))
        return 1

    print(json.dumps(result, sort_keys=True))
    return exit_code


# --------------------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------------------


def _load_protected_names() -> list[str]:
    names: list[str] = []
    denylist_path = os.environ.get(_ENV_DENYLIST_FILE)
    if denylist_path:
        path = Path(denylist_path)
        if not path.is_file():
            raise RuntimeError("protected denylist file is missing")
        names.extend(line.strip() for line in path.read_text(encoding="utf-8").splitlines())

    names.extend(forbidden_names_from_env())
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
        capture_output=True,
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


def _scan_runtime_file(path: Path, root: Path, tokens: list[str]) -> list[RuntimeFinding]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    normalized_content = content.casefold()
    relative = path.relative_to(root).as_posix()
    return [RuntimeFinding(relative, token) for token in tokens if token in normalized_content]


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
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise NameHygieneError(f"git {' '.join(args)} failed")


def _candidate_config_roots(root: Path) -> list[Path]:
    roots: list[Path] = []

    def add_root(path: Path) -> None:
        resolved = path.resolve()
        if resolved not in roots:
            roots.append(resolved)

    for candidate in (root, *root.parents):
        add_root(candidate)

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return roots

    common_dir = Path(proc.stdout.strip()).resolve()
    if common_dir.name == ".git":
        mother_root = common_dir.parent
        for candidate in (mother_root, *mother_root.parents):
            add_root(candidate)
    return roots


def _git_ls_files(root: Path, args: list[str]) -> list[Path]:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", *args],
            cwd=root,
            check=True,
            capture_output=True,
            text=False,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [root / item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]


def _git_files(root: Path) -> list[tuple[Path, bool]]:
    candidates: list[tuple[Path, bool]] = []
    seen: set[Path] = set()
    for path in _git_ls_files(root, ["--cached"]):
        if path not in seen:
            candidates.append((path, True))
            seen.add(path)
    for path in _git_ls_files(root, ["--others", "--exclude-standard"]):
        if path not in seen:
            candidates.append((path, False))
            seen.add(path)
    return candidates


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        rel_root = Path(current_root).relative_to(root)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in SKIPPED_SEGMENTS and not fnmatch.fnmatch(dirname.lower(), "*.local.*")
        ]
        for filename in filenames:
            path = rel_root / filename
            if _should_scan_runtime(path):
                files.append(root / path)
    return files


def _should_scan_runtime(relative_path: Path, *, tracked: bool = False) -> bool:
    if any(part in SKIPPED_SEGMENTS for part in relative_path.parts):
        return False
    if tracked:
        return True
    return not fnmatch.fnmatch(relative_path.name.lower(), "*.local.*")


def _read_structural_text(path: Path) -> str | None:
    is_text = path.suffix.lower() in _STRUCTURAL_TEXT_EXTENSIONS or path.name in (
        _STRUCTURAL_TEXT_FILENAMES
    )
    if not is_text or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _is_structural_candidate(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return bool(parts & _STRUCTURAL_SEGMENTS)


def _neutral_host(host: str) -> bool:
    normalized = host.strip("[]").rstrip(".").lower()
    return normalized in _NEUTRAL_HOSTS or normalized.endswith(_NEUTRAL_SUFFIXES)


def _host_from_domain_value(value: str) -> str:
    if value.lower().startswith(("http://", "https://")):
        return urlsplit(value).hostname or ""
    return value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# Re-exported names that downstream tooling may import.
__all__ = [
    "AllowlistEntry",
    "ENV_FORBIDDEN_NAMES",
    "NameHygieneFinding",
    "NameHygieneViolation",
    "RuntimeFinding",
    "StructuralFinding",
    "SYNTHETIC_SENTINEL",
    "assert_clean",
    "check_structural",
    "committed_patterns",
    "discover_local_config",
    "forbidden_names_from_env",
    "iter_candidate_files",
    "load_forbidden_patterns",
    "load_local_config",
    "main",
    "normalize_tokens",
    "parse_env_tokens",
    "run",
    "scan_literal_paths",
    "scan_paths",
    "scan_repository",
    "scan_tracked_files",
    "structural_findings",
    "validate_allowlist",
]


if __name__ == "__main__":
    raise SystemExit(main())
