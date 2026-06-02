"""Offline repository name-hygiene guard for the X1 test harness.

This is a thin reuse of the canonical guard in
:mod:`repolens.security.name_hygiene`. It carries only the X1-specific default
owner/repo token set; all scanning, finding representation, and skip rules come
from the canonical module so there is a single name-hygiene implementation.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from repolens.security.name_hygiene import (
    SKIPPED_SEGMENTS,
    NameHygieneFinding,
    scan_literal_paths,
)

DEFAULT_FORBIDDEN_TOKENS = (
    "GITHUB" + "_OWNER=",
    "REPOLENS" + "_OWNER=",
    "--owner " + "real",
)

__all__ = ["DEFAULT_FORBIDDEN_TOKENS", "NameHygieneFinding", "main", "scan_paths"]


def scan_paths(
    root: str | Path,
    *,
    forbidden_tokens: Sequence[str] = DEFAULT_FORBIDDEN_TOKENS,
) -> list[NameHygieneFinding]:
    """Scan text files under ``root`` for forbidden owner/repo tokens."""

    return scan_literal_paths(Path(root), list(forbidden_tokens))


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

    print("\n".join(finding.render() for finding in findings))
    return 1


# Re-export skip set so callers that introspect it keep working.
_SKIPPED_SEGMENTS = SKIPPED_SEGMENTS


if __name__ == "__main__":
    raise SystemExit(main())
