"""Offline repository name-hygiene guard."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_FORBIDDEN_TOKENS = (
    "GITHUB" + "_OWNER=",
    "REPOLENS" + "_OWNER=",
    "--owner " + "real",
)
ALLOWED_SYNTHETIC_TERMS = ("acme-", "example.invalid", "invalid.acme")
SKIPPED_PATH_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".quest",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "venv",
    }
)
TEXT_EXTENSIONS = frozenset(
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


@dataclass(frozen=True)
class NameHygieneFinding:
    path: Path
    line: int
    token: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: forbidden token {self.token!r}"


def scan_paths(
    root: str | Path,
    *,
    forbidden_tokens: Sequence[str] = DEFAULT_FORBIDDEN_TOKENS,
) -> list[NameHygieneFinding]:
    """Scan text files under root for forbidden owner/repo tokens."""
    root_path = Path(root)
    validate_root(root_path)
    findings: list[NameHygieneFinding] = []
    for path in iter_text_files(root_path):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        display_path = _display_path(path, root_path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for token in forbidden_tokens:
                if token and token in line:
                    findings.append(NameHygieneFinding(display_path, line_number, token))
    return findings


def validate_root(root: Path) -> None:
    if not root.exists():
        raise FileNotFoundError(f"name hygiene root does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise NotADirectoryError(f"name hygiene root is not a file or directory: {root}")


def iter_text_files(root: Path) -> Iterator[Path]:
    """Yield likely text files while skipping generated and ignored directories."""
    if root.is_file():
        if _should_scan(root):
            yield root
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file() or not _should_scan(path):
            continue
        yield path


def _should_scan(path: Path) -> bool:
    parts = set(path.parts)
    if parts.intersection(SKIPPED_PATH_PARTS):
        return False
    if path.is_symlink():
        return False
    return path.suffix.lower() in TEXT_EXTENSIONS


def _display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def format_findings(findings: Iterable[NameHygieneFinding]) -> str:
    return "\n".join(finding.format() for finding in findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan repository text for forbidden name tokens.")
    parser.add_argument("--root", default=".", help="Root path to scan.")
    parser.add_argument(
        "--forbid",
        action="append",
        default=[],
        help="Additional forbidden token. May be supplied more than once.",
    )
    args = parser.parse_args(argv)

    tokens = tuple(DEFAULT_FORBIDDEN_TOKENS) + tuple(args.forbid)
    try:
        findings = scan_paths(args.root, forbidden_tokens=tokens)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(exc)
        return 2
    if not findings:
        print("name hygiene ok")
        return 0

    print(format_findings(findings))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
