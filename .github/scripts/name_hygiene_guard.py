#!/usr/bin/env python3
"""Fail when configured forbidden names appear in scanned files."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator
from pathlib import Path

ENV_DENYLIST = "REPOLENS_NAME_DENYLIST"
ENV_DENYLIST_FILE = "REPOLENS_NAME_DENYLIST_FILE"
ENV_FORBIDDEN_NAMES = "REPOLENS_FORBIDDEN_NAMES"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=["."])
    args = parser.parse_args(argv)

    terms = _load_terms()
    if not terms:
        return 0

    violations: list[str] = []
    for root in [Path(path) for path in args.paths]:
        for file_path in _iter_files(root):
            text = _read_text(file_path)
            if text is None:
                continue
            for term in terms:
                if term in text:
                    violations.append(f"{file_path}:denylist-entry")

    if violations:
        for violation in violations:
            print(f"forbidden name: {violation}", file=sys.stderr)
        return 1
    return 0


def _load_terms() -> list[str]:
    raw = "\n".join(
        value
        for value in (
            os.environ.get(ENV_DENYLIST, ""),
            os.environ.get(ENV_FORBIDDEN_NAMES, ""),
        )
        if value
    )
    file_path = os.environ.get(ENV_DENYLIST_FILE)
    if file_path:
        raw = f"{raw}\n{Path(file_path).read_text(encoding='utf-8')}"
    return [term.strip() for term in raw.replace(",", "\n").splitlines() if term.strip()]


def _iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    ignored_dirs = {".git", ".quest", ".venv", "__pycache__", ".pytest_cache"}
    for file_path in root.rglob("*"):
        if any(part in ignored_dirs for part in file_path.parts):
            continue
        if file_path.is_file():
            yield file_path


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
